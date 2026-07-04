//! Vess artery node — validates and stores Vess, runs mining loop.
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use vess_foundry::{self, Vess};
use crate::vess_store::VessStore;

pub struct NodeState {
    pub store: VessStore,
    pub current_epoch: u64,
    pub mining: Option<MiningState>,
    pub wallet_vk: Option<Vec<u8>>,
    pub wallet_sk: Option<Vec<u8>>,
}

pub struct MiningState {
    pub stop_tx: tokio::sync::oneshot::Sender<()>,
    pub amount: u64,
    pub started_at: u64,
}

impl NodeState {
    pub fn new() -> Self {
        Self { store: VessStore::default(), current_epoch: current_epoch(), mining: None, wallet_vk: None, wallet_sk: None }
    }
}

pub fn current_epoch() -> u64 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    now.saturating_sub(1735689600) / 86400
}

pub fn validate_vess(v: &Vess, store: &VessStore, current_epoch: u64) -> Result<(), String> {
    let id = v.compute_vess_id();
    if store.is_consumed(&id) { return Err("already consumed".into()); }
    if let Some(existing) = store.get(&id) {
        if v.chain_depth <= existing.chain_depth { return Err("stale chain".into()); }
    }
    if v.is_mined() { return vess_foundry::mine::verify_mined(&v.initial_pk, v.epoch, v.nonce, v.amount, current_epoch); }
    if v.is_changed() { return validate_changed(v, store); }
    Err("neither mined nor changed".into())
}

fn validate_changed(v: &Vess, store: &VessStore) -> Result<(), String> {
    let mut input_sum: u64 = 0;
    for cid in &v.consumed {
        let input = store.get(cid).ok_or_else(|| format!("input not found"))?;
        input_sum += input.amount;
    }
    if v.amount > input_sum { return Err("value overflow".into()); }
    if !v.change_sig.is_empty() {
        let commitment = Vess::change_commitment(&v.consumed, &[v.clone()]);
        if !vess_foundry::spend_auth::verify_spend(&v.owner_vk, &commitment, &v.change_sig).unwrap_or(false) {
            return Err("invalid change sig".into());
        }
    }
    Ok(())
}
// ── Legacy compatibility stubs ──

pub struct NodeConfig {
    pub k_neighbors: usize,
    pub max_hops: u8,
    pub state_dir: std::path::PathBuf,
    pub bootstrap: Vec<String>,
    pub ready_tx: Option<tokio::sync::oneshot::Sender<[u8; 32]>>,
    pub wallet_path: Option<std::path::PathBuf>,
    pub rpc_port: Option<u16>,
    pub wallet_password: Option<String>,
    pub bind_addr: Option<std::net::SocketAddr>,
    pub enable_local_discovery: bool,
    pub reset_transient_peer_state: bool,
    pub test: bool,
    pub bootstrap_dns: Vec<String>,
}

pub async fn run_node(_config: NodeConfig) -> anyhow::Result<String> {
    tracing::info!("Vess artery v3 node stub running");
    loop { tokio::time::sleep(std::time::Duration::from_secs(3600)).await; }
}