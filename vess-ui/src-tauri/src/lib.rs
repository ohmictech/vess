use std::sync::Mutex;
use std::sync::Arc;
use std::process::{Child, Command};
use tauri::Manager;

struct NodeProcess {
    child: Mutex<Option<Child>>,
    rpc_port: u16,
    ready: Arc<Mutex<bool>>,
    state_dir: String,
}

fn find_free_port() -> Option<u16> {
    use std::net::TcpListener;
    // Use a wider range and try random offset to avoid collisions
    // when two instances start simultaneously.
    let base = 9821u16;
    for offset in 0..50 {
        let port = base + (offset % 50) as u16;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Some(port);
        }
    }
    None
}

fn artery_binary_path() -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let name = if cfg!(windows) { "vess-artery.exe" } else { "vess-artery" };
    // Check same directory, then resources subdirectory, then workspace target.
    for dir in [exe_dir.clone(), exe_dir.join("resources")] {
        let path = dir.join(&name);
        if path.exists() { return path; }
    }
    let workspace_target = exe_dir.join("../../target/release").join(&name);
    if let Ok(canon) = workspace_target.canonicalize() { return canon; }
    std::path::PathBuf::from(name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_log::Builder::default().build())
        .setup(|app| {
            let port = find_free_port().ok_or_else(|| {
                log::error!("no free RPC ports (9821–9851)");
                std::io::Error::new(std::io::ErrorKind::AddrInUse, "all RPC ports in use")
            })?;

            let bin = artery_binary_path();
            log::info!("spawning Vess node: {} on port {}", bin.display(), port);

            // Each instance needs its own state directory so nodes get unique
            // mesh identities — otherwise two nodes with the same node_id
            // can't discover each other on the P2P mesh.
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| ".".to_string());
            let state_dir = std::path::PathBuf::from(&home).join(format!(".vess-artery-{port}"));

            // Remove any stale state from a previous run so we don't
            // read an old rpc-token (which would cause auth rejection).
            let _ = std::fs::remove_dir_all(&state_dir);
            std::fs::create_dir_all(&state_dir).map_err(|e| {
                log::error!("failed to create state dir {}: {e}", state_dir.display());
                std::io::Error::new(std::io::ErrorKind::Other, format!("state dir: {e}"))
            })?;

            let child = Command::new(&bin)
                .env("VESS_RPC_PORT", port.to_string())
                .env("VESS_TESTNET", "1")
                .env("VESS_STATE_DIR", state_dir.to_string_lossy().to_string())
                .spawn()
                .map_err(|e| {
                    log::error!("failed to spawn node: {e}");
                    std::io::Error::new(std::io::ErrorKind::Other, format!("spawn failed: {e}"))
                })?;

            app.manage(NodeProcess {
                child: Mutex::new(Some(child)),
                rpc_port: port,
                ready: Arc::new(Mutex::new(false)),
                state_dir: state_dir.to_string_lossy().to_string(),
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_rpc_port, is_node_ready, rpc_proxy])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn get_rpc_port(state: tauri::State<NodeProcess>) -> u16 {
    state.rpc_port
}

#[tauri::command]
async fn is_node_ready(app: tauri::AppHandle) -> bool {
    let state = app.state::<NodeProcess>();
    let ready = state.ready.clone();
    let port = state.rpc_port;
    // Fast path: cached flag.
    if *ready.lock().unwrap() {
        return true;
    }
    // Try a quick TCP connect — just check the port is open, then
    // close cleanly so the node doesn't log "bad auth token".
    let addr = format!("127.0.0.1:{port}");
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(&addr),
    ).await {
        Ok(Ok(stream)) => {
            drop(stream); // clean FIN, no data sent
            log::info!("node ready on port {port}");
            *ready.lock().unwrap() = true;
            true
        }
        Ok(Err(e)) => {
            log::info!("node not ready on port {port}: {e}");
            false
        }
        Err(_) => {
            log::info!("node connect timeout on port {port}");
            false
        }
    }
}

#[tauri::command]
async fn rpc_proxy(state: tauri::State<'_, NodeProcess>, method: String, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let port = state.rpc_port;
    let body = if let serde_json::Value::Object(ref map) = params {
        let mut m: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        m.insert("method".to_string(), serde_json::Value::String(method.clone()));
        m.extend(map.clone());
        serde_json::Value::Object(m)
    } else {
        serde_json::json!({ "method": method })
    };

    // Read auth token from disk (node writes it before RPC server starts).
    let token_path = std::path::PathBuf::from(&state.state_dir).join("rpc-token");
    let addr = format!("127.0.0.1:{port}");

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    for attempt in 0u32..8 {
        let token = match std::fs::read_to_string(&token_path) {
            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => {
                log::info!("rpc_proxy[{method}]: token file not ready (attempt {attempt})");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        log::info!("rpc_proxy[{method}]: connecting to {addr} (attempt {attempt})");
        let mut stream = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        ).await {
            Ok(Ok(s)) => s,
            _ => {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        // Native protocol: {token}\n{json}\n
        let req_bytes = serde_json::to_vec(&body).map_err(|e| format!("json: {e}"))?;
        if stream.write_all(token.as_bytes()).await.is_err() { continue; }
        if stream.write_all(b"\n").await.is_err() { continue; }
        if stream.write_all(&req_bytes).await.is_err() { continue; }
        if stream.write_all(b"\n").await.is_err() { continue; }

        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reader.read_line(&mut line),
        ).await {
            Ok(Ok(n)) if n > 0 => {
                let trimmed = line.trim();
                log::info!("rpc_proxy[{method}]: response len={}", trimmed.len());
                return serde_json::from_str(trimmed).map_err(|e| format!("parse: {e}"));
            }
            _ => {
                // Empty response = bad token. Delete stale token file so node regenerates it.
                log::warn!("rpc_proxy[{method}]: bad/empty response (stale token?)");
                let _ = std::fs::remove_file(&token_path);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
    Err("RPC unavailable — node not ready".to_string())
}

impl Drop for NodeProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
        }
    }
}
