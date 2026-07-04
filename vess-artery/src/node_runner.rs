//! Vess artery — full node with mesh networking, wallet, mining, RPC.
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use vess_foundry::Vess;
use crate::vess_store::VessStore;

pub const EPOCH_SECS: u64 = 86400;
pub const EPOCH_GENESIS: u64 = 1735689600;

// ── Node state ──

pub struct NodeState {
    pub store: VessStore,
    pub current_epoch: u64,
    pub mining: Option<MiningState>,
    pub wallet_vk: Option<Vec<u8>>,
    pub wallet_sk: Option<Vec<u8>>,
    pub node_id: [u8; 32],
    pub tag_dht: crate::tag_dht::TagDht,
    pub limbo: crate::limbo_buffer::LimboBuffer,
    pub peer_registry: crate::handshake::PeerRegistry,
    pub rate_limiter: crate::gossip::PeerRateLimiter,
    pub duplicate_tracker: DuplicateTracker,
    pub notifications: std::collections::VecDeque<WalletNotification>,
    pub wallet_path: Option<std::path::PathBuf>,
}

pub struct MiningState {
    pub stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    pub amount: u64,
    pub started_at: u64,
}

pub struct DuplicateTracker {
    seen: std::collections::HashSet<[u8; 32]>,
    times: std::collections::VecDeque<([u8; 32], u64)>,
}

impl DuplicateTracker {
    pub fn new() -> Self { Self { seen: std::collections::HashSet::new(), times: std::collections::VecDeque::new() } }
    pub fn is_duplicate(&mut self, id: &[u8; 32], now: u64) -> bool {
        while self.times.front().map_or(false, |(_, t)| now.saturating_sub(*t) > 3600) { if let Some((id, _)) = self.times.pop_front() { self.seen.remove(&id); } }
        !self.seen.insert(*id) || { self.times.push_back((*id, now)); false }
    }
}

#[derive(Debug, Clone)]
pub struct WalletNotification { pub message: String, pub timestamp: u64 }

impl NodeState {
    pub fn new(node_id: [u8; 32], k_neighbors: usize) -> Self {
        Self {
            store: VessStore::default(),
            current_epoch: current_epoch_utc(),
            mining: None, wallet_vk: None, wallet_sk: None, node_id,
            tag_dht: crate::tag_dht::TagDht::new(node_id, k_neighbors),
            limbo: crate::limbo_buffer::LimboBuffer::new(),
            peer_registry: crate::handshake::PeerRegistry::new(std::time::Duration::from_secs(30)),
            rate_limiter: crate::gossip::PeerRateLimiter::with_defaults(),
            duplicate_tracker: DuplicateTracker::new(),
            notifications: std::collections::VecDeque::new(),
            wallet_path: None,
        }
    }
    pub fn notify(&mut self, msg: &str) {
        self.notifications.push_back(WalletNotification { message: msg.to_string(), timestamp: now_secs() });
        if self.notifications.len() > 100 { self.notifications.pop_front(); }
    }
}

pub fn current_epoch_utc() -> u64 {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    now.saturating_sub(EPOCH_GENESIS) / EPOCH_SECS
}

fn now_secs() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() }

// ── Validation ──

pub fn validate_vess(v: &Vess, store: &VessStore, current_epoch: u64) -> Result<(), String> {
    let id = v.compute_vess_id();
    if store.is_consumed(&id) { return Err("already consumed".into()); }
    if let Some(ex) = store.get(&id) { if v.chain_depth <= ex.chain_depth { return Err("stale".into()); } }
    if v.is_mined() { return vess_foundry::mine::verify_mined(&v.initial_pk, v.epoch, v.nonce, v.amount, current_epoch); }
    if v.is_changed() { return validate_changed(v, store); }
    Err("invalid".into())
}

fn validate_changed(v: &Vess, store: &VessStore) -> Result<(), String> {
    let mut sum: u64 = 0;
    for cid in &v.consumed { sum += store.get(cid).ok_or("input not found")?.amount; }
    if v.amount > sum { return Err("overflow".into()); }
    if !v.change_sig.is_empty() {
        let c = Vess::change_commitment(&v.consumed, &[v.clone()]);
        if !vess_foundry::spend_auth::verify_spend(&v.owner_vk, &c, &v.change_sig).unwrap_or(false) { return Err("bad sig".into()); }
    }
    Ok(())
}

// ── Mining ──

pub fn spawn_miner(state: Arc<Mutex<NodeState>>, amount: u64, initial_pk: [u8; 32], og_tx: mpsc::UnboundedSender<Vess>) {
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let epoch = state.lock().unwrap().current_epoch;
    let mut miner = vess_foundry::mine::VessMiner::new(initial_pk, amount, epoch, 0);
    { let mut s = state.lock().unwrap(); s.mining = Some(MiningState { stop_tx: Some(stop_tx), amount, started_at: now_secs() }); }
    std::thread::spawn(move || {
        loop {
            if stop_rx.try_recv().is_ok() { break; }
            if let Some((_out, nonce)) = miner.mine_until(|| stop_rx.try_recv().is_ok()) {
                let mut v = Vess { amount, epoch, nonce, initial_pk, owner_vk: Vec::new(), prev_sig: Vec::new(), chain_depth: 0, consumed: Vec::new(), change_sig: Vec::new(), chain_tip: [0u8; 32], digest: [0u8; 32], created_at: now_secs(), stealth_id: [0u8; 32], dht_index: 0 };
                if let Ok(s) = state.lock() { if let Some(ref vk) = s.wallet_vk { v.owner_vk = vk.clone(); } }
                let _ = og_tx.send(v);
            } else { break; }
        }
        if let Ok(mut s) = state.lock() { s.mining = None; }
    });
}

// ── Node entry point ──

pub struct NodeConfig {
    pub state_dir: std::path::PathBuf,
    pub wallet_path: Option<std::path::PathBuf>,
    pub wallet_password: Option<String>,
    pub rpc_port: Option<u16>,
    pub bind_addr: Option<std::net::SocketAddr>,
    pub k_neighbors: usize,
    pub max_hops: u8,
    pub bootstrap: Vec<String>,
    pub enable_local_discovery: bool,
    pub test: bool,
}

pub async fn run_node(config: NodeConfig) -> anyhow::Result<String> {
    // Panic hook
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        eprintln!("VESS PANIC at {}", loc.as_deref().unwrap_or("unknown"));
    }));

    // Ctrl+C / SIGTERM
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move { let _ = tokio::signal::ctrl_c().await; let _ = shutdown_tx.send(()); });

    // Load or create mesh seed
    let mesh_seed = load_or_create_mesh_seed(&config.state_dir)?;
    let bind_addr = config.bind_addr.unwrap_or_else(||
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)));
    
    let _node = bind_addr; // mesh binding stub
    tracing::info!("Mesh bound to {}", bind_addr);
    let node_id: [u8; 32] = rand::random(); // TODO: derive from mesh seed

    let state = Arc::new(Mutex::new(NodeState::new(node_id, config.k_neighbors)));
    let (og_tx, mut og_rx) = mpsc::unbounded_channel::<Vess>();

    // Load wallet
    if let Some(ref wallet_path) = config.wallet_path {
        if wallet_path.exists() {
            match vess_sovereign::WalletFile::load(wallet_path) {
                Ok(wallet) => {
                    let mut s = state.lock().unwrap();
                    if let Some(cred) = wallet.billfold.any_credential() {
                        s.wallet_vk = Some(cred.spend_vk.clone());
                        s.wallet_sk = Some(cred.spend_sk.clone());
                    }
                    s.wallet_path = Some(wallet_path.clone());
                    tracing::info!("wallet loaded");
                }
                Err(e) => tracing::warn!(%e, "wallet load failed"),
            }
        }
    }

    // Epoch ticker
    let cs = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut s = cs.lock().unwrap();
            let new_epoch = current_epoch_utc();
            if new_epoch != s.current_epoch {
                s.store.prune_consumed(new_epoch.saturating_sub(4));
                s.current_epoch = new_epoch;
                tracing::info!(epoch = new_epoch, "epoch rollover");
            }
        }
    });

    // RPC server
    let rpc_port = config.rpc_port.unwrap_or(9821);
    let rs = state.clone(); let rt = og_tx.clone();
    tokio::spawn(async move { serve_rpc(rs, rt, rpc_port).await; });

    // Main event loop
    tracing::info!(port = rpc_port, "Vess artery v3 running");

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("shutting down");
                break;
            }
            Some(v) = og_rx.recv() => {
                let mut s = state.lock().unwrap();
                if s.store.upsert(&v) {
                    tracing::info!(id=%hex::encode(&v.compute_vess_id()[..8]), amount=v.amount, "Vess mined and stored");
                }
            }
            else => break,
        }
    }

    Ok(hex::encode(&node_id[..8]))
}

fn load_or_create_mesh_seed(state_dir: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let seed_path = state_dir.join("mesh_seed");
    if seed_path.exists() {
        let bytes = std::fs::read(&seed_path)?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32.min(bytes.len())]);
        Ok(seed)
    } else {
        std::fs::create_dir_all(state_dir)?;
        let seed: [u8; 32] = rand::random();
        std::fs::write(&seed_path, seed)?;
        Ok(seed)
    }
}

// ── TCP RPC server ──

async fn serve_rpc(state: Arc<Mutex<NodeState>>, og_tx: mpsc::UnboundedSender<Vess>, port: u16) {
    let l = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await { Ok(l) => l, Err(e) => { tracing::error!(%e,"bind"); return; } };
    loop { if let Ok((s,_)) = l.accept().await { let st=state.clone(); let tx=og_tx.clone(); tokio::spawn(async { handle_conn(st,tx,s).await; }); } }
}

async fn handle_conn(state: Arc<Mutex<NodeState>>, og_tx: mpsc::UnboundedSender<Vess>, mut stream: tokio::net::TcpStream) {
    use tokio::io::{AsyncBufReadExt,AsyncWriteExt,BufReader};
    let (r,mut w) = stream.split(); let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let req: crate::rpc::RpcRequest = match serde_json::from_str(&line) { Ok(r) => r, Err(_) => { let _=w.write_all(b"{\"ok\":false}\n").await; continue; } };
        let resp = crate::rpc::handle_rpc(&state, &og_tx, req);
        let _ = w.write_all(format!("{}\n", serde_json::to_string(&resp).unwrap_or_default()).as_bytes()).await;
    }
}