use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::CommandChild;
use tauri_plugin_shell::process::CommandEvent;
use std::sync::Mutex;

struct NodeProcess {
    child: Mutex<Option<CommandChild>>,
    rpc_port: u16,
}

/// Find a free port in range 9821–9851.
fn find_free_port() -> Option<u16> {
    use std::net::TcpListener;
    for port in 9821..=9851 {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Some(port);
        }
    }
    None
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Always spawn a fresh node on a free port.
            let port = find_free_port().ok_or_else(|| {
                log::error!("no free RPC ports (9821–9851)");
                std::io::Error::new(std::io::ErrorKind::AddrInUse, "all RPC ports in use")
            })?;

            log::info!("spawning Vess node on port {port}");
            app.manage(NodeProcess { child: Mutex::new(None), rpc_port: port });

            let shell = app.shell();
            let (mut rx, child) = shell
                .sidecar("vess-artery")
                .expect("failed to create vess-artery sidecar")
                .env("VESS_RPC_PORT", port.to_string())
                .spawn()
                .expect("failed to spawn vess-artery node");

            app.state::<NodeProcess>()
                .child.lock().unwrap()
                .replace(child);

            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => log::info!("[node] {}", String::from_utf8_lossy(&line)),
                        CommandEvent::Stderr(line) => log::error!("[node] {}", String::from_utf8_lossy(&line)),
                        CommandEvent::Terminated(_) => {
                            log::warn!("[node] exited");
                            break;
                        }
                        _ => {}
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_rpc_port])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn get_rpc_port(state: tauri::State<NodeProcess>) -> u16 {
    state.rpc_port
}
