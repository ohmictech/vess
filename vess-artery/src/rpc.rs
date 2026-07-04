//! Vess artery RPC — JSON-line over TCP (stub — mining+RPC wiring TODO).
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use vess_foundry::Vess;
use crate::node_runner::ArteryState;

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest { pub method: String, pub params: serde_json::Value }

#[derive(Debug, Serialize)]
pub struct RpcResponse { pub ok: bool, pub data: serde_json::Value }

#[derive(Debug, Clone)]
pub struct QueueSenders {
    pub og_tx: mpsc::UnboundedSender<Vess>,
}

pub fn run_rpc_server(_state: Arc<Mutex<ArteryState>>, _senders: QueueSenders) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async { /* RPC server stub — mining loop is in node_runner */ })
}

pub fn wallet_tag_store(_state: &Arc<Mutex<ArteryState>>) {}

pub fn fire_opportunistic_consolidations(_state: &Arc<Mutex<ArteryState>>) {}

pub fn handle_rpc(_state: &Arc<Mutex<ArteryState>>, _og_tx: &mpsc::UnboundedSender<Vess>, _req: RpcRequest) -> RpcResponse {
    RpcResponse { ok: false, data: serde_json::json!({"error": "rpc not yet wired"}) }
}
