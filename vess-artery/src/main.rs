//! Vess artery node — standalone binary.
//!
//! This binary is spawned as a sidecar by the Tauri desktop wallet
//! and can also be run directly for headless node operation.
//!
//! Environment variables:
//!   VESS_STATE_DIR   — path to state directory (default: ~/.vess-artery)
//!   VESS_RPC_PORT    — JSON-RPC port (default: 9821)
//!   VESS_BIND_ADDR   — UDP bind address (default: 0.0.0.0:0)
//!   VESS_TESTNET     — set to "1" for testnet mode
//!   VESS_WALLET_PATH — path to wallet file for auto-load

use std::path::PathBuf;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let state_dir = std::env::var("VESS_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs_next::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".vess-artery")
        });

    std::fs::create_dir_all(&state_dir).expect("create state directory");

    let rpc_port: u16 = std::env::var("VESS_RPC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9821);

    let bind_addr: Option<std::net::SocketAddr> = std::env::var("VESS_BIND_ADDR")
        .ok()
        .and_then(|s| s.parse().ok());

    let is_testnet = std::env::var("VESS_TESTNET")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    let wallet_path = std::env::var("VESS_WALLET_PATH")
        .ok()
        .map(PathBuf::from);

            let config = vess_artery::node_runner::NodeConfig {
        state_dir,
        wallet_path,
        wallet_password: None,
        rpc_port: Some(rpc_port),
        bind_addr,
        k_neighbors: if is_testnet { 4 } else { 20 },
        max_hops: 6,
        bootstrap: vec![],
        enable_local_discovery: true,
        test: is_testnet,
    };

    tracing::info!(
        port = rpc_port,
        testnet = is_testnet,
        "vess-artery node starting"
    );

    match vess_artery::node_runner::run_node(config).await {
        Ok(node_id) => {
            tracing::info!(%node_id, "vess-artery node stopped");
        }
        Err(e) => {
            tracing::error!(error = %e, "vess-artery node crashed");
            std::process::exit(1);
        }
    }
}
