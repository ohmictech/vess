use tauri::Manager;
use std::sync::Mutex;

struct NodeProcess(Mutex<Option<tauri::api::process::CommandChild>>);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_shell::init())
        .manage(NodeProcess(Mutex::new(None)))
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Auto-start the Vess node on app launch
            let shell = app.shell();
            let (mut rx, child) = shell
                .sidecar("vess-artery")
                .expect("failed to create vess-artery sidecar")
                .spawn()
                .expect("failed to spawn vess-artery node");

            // Store the child process handle so it stays alive
            let state = app.state::<NodeProcess>();
            *state.0.lock().unwrap() = Some(child);

            // Log node output in background
            tauri::async_runtime::spawn(async move {
                use tauri::api::process::CommandEvent;
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => log::info!("[node] {}", String::from_utf8_lossy(&line)),
                        CommandEvent::Stderr(line) => log::error!("[node] {}", String::from_utf8_lossy(&line)),
                        CommandEvent::Terminated(status) => {
                            log::warn!("[node] exited with {:?}", status.code());
                            break;
                        }
                        _ => {}
                    }
                }
            });

            log::info!("Vess node started successfully");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
