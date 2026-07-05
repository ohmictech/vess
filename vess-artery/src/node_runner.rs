//! Vess artery — full node with mesh networking, wallet, mining, RPC.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use vess_foundry::Vess;
use vess_foundry::clock;
use crate::vess_store::VessStore;

// ── Node state ──

pub struct ArteryState {
    pub store: VessStore,
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
    /// Channel to push wallet manifests to the DHT.
    pub manifest_tx: Option<mpsc::UnboundedSender<vess_protocol::ManifestStore>>,
    /// Blake3 hash of the wallet's seed phrase (for DHT lookup).
    pub wallet_seed_hash: Option<[u8; 32]>,
    /// Known peer node IDs (from bootstrap, discovery, or persisted snapshot).
    pub known_peers: HashSet<[u8; 32]>,
    /// Node ID → contact string (for dialing).
    pub peer_endpoints: HashMap<[u8; 32], String>,
    /// Banned node IDs.
    pub banned_peers: HashSet<[u8; 32]>,
    /// Channel to dynamically add peers at runtime.
    pub add_peer_tx: Option<mpsc::UnboundedSender<String>>,
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

impl ArteryState {
    pub fn new(node_id: [u8; 32], k_neighbors: usize) -> Self {
        Self {
            store: VessStore::default(),
            mining: None, wallet_vk: None, wallet_sk: None, node_id,
            tag_dht: crate::tag_dht::TagDht::new(node_id, k_neighbors),
            limbo: crate::limbo_buffer::LimboBuffer::new(),
            peer_registry: crate::handshake::PeerRegistry::new(std::time::Duration::from_secs(30)),
            rate_limiter: crate::gossip::PeerRateLimiter::with_defaults(),
            duplicate_tracker: DuplicateTracker::new(),
            notifications: std::collections::VecDeque::new(),
            wallet_path: None,
            manifest_tx: None,
            wallet_seed_hash: None,
            known_peers: HashSet::new(),
            peer_endpoints: HashMap::new(),
            banned_peers: HashSet::new(),
            add_peer_tx: None,
        }
    }
    pub fn notify(&mut self, msg: &str) {
        self.notifications.push_back(WalletNotification { message: msg.to_string(), timestamp: now_secs() });
        if self.notifications.len() > 100 { self.notifications.pop_front(); }
    }

    /// Push an already-encrypted wallet manifest to the DHT.
    /// The caller handles encryption (wallet layer has the keys).
    pub fn push_wallet_manifest(&self, encrypted_blob: Vec<u8>) {
        let seed_hash = match self.wallet_seed_hash {
            Some(h) => h,
            None => return,
        };
        let tx = match &self.manifest_tx {
            Some(tx) => tx,
            None => return,
        };

        let dht_key = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-wallet-manifest-v1");
            h.update(&seed_hash);
            *h.finalize().as_bytes()
        };

        let manifest = vess_protocol::ManifestStore {
            dht_key,
            encrypted_manifest: encrypted_blob,
            hops_remaining: 0,
        };

        let _ = tx.send(manifest);
        tracing::debug!("wallet manifest pushed to DHT");
    }
}

pub fn now_secs() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() }

// ── Validation ──

pub fn validate_vess(v: &Vess, store: &VessStore, _current_epoch: u64) -> Result<(), String> {
    let id = v.compute_vess_id();
    if store.is_consumed(&id) { return Err("already consumed".into()); }
    if let Some(ex) = store.get(&id) { if v.chain_depth <= ex.chain_depth { return Err("stale".into()); } }
    if v.is_mined() { return Err("mining validation not yet wired for MintProof model".into()); }
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

pub fn spawn_miner(state: Arc<Mutex<ArteryState>>, amount: u64, initial_pk: [u8; 32], og_tx: mpsc::UnboundedSender<Vess>) {
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let epoch = vess_foundry::clock::current_epoch();
    {
        let mut s = state.lock().unwrap();
        s.mining = Some(MiningState { stop_tx: Some(stop_tx), amount, started_at: now_secs() });
    }

    let cs = state.clone();
    std::thread::spawn(move || {
        let mut nonce: u64 = 0;
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }

            // Try nonce
            let hash = vess_foundry::mine::mine_argon2d(&initial_pk, epoch, nonce, amount);
            let bits = vess_foundry::mine::leading_zero_bits(&hash);

            let required_bits = vess_foundry::mine::amount_to_bits(amount);
            if bits >= required_bits {
                // Found a valid proof!
                let owner_vk = {
                    let s = cs.lock().unwrap();
                    s.wallet_vk.clone()
                };
                if let Some(vk) = owner_vk {
                    let v = Vess {
                        amount,
                        epoch,
                        nonce,
                        initial_pk,
                        owner_vk: vk,
                        prev_sig: Vec::new(),
                        chain_depth: 0,
                        consumed: Vec::new(),
                        change_sig: Vec::new(),
                        chain_tip: [0u8; 32],
                        digest: hash,
                        created_at: now_secs(),
                        stealth_id: [0u8; 32],
                        dht_index: 0,
                    };
                    let _ = og_tx.send(v);
                    break;
                }
            }

            nonce = nonce.wrapping_add(1);
            // Yield every 1000 attempts
            if nonce % 1000 == 0 {
                std::thread::yield_now();
            }
        }
        let _ = cs.lock().map(|mut s| s.mining = None);
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

    // Load or create mesh seed, extend to 64 bytes for key derivation
    let mesh_seed32 = load_or_create_mesh_seed(&config.state_dir)?;
    let mut mesh_seed = [0u8; 64];
    mesh_seed[..32].copy_from_slice(&mesh_seed32);
    let bind_addr = config.bind_addr.unwrap_or_else(||
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)));

    // Derive node ID from mesh seed
    let (_, mesh_address) = vess_mesh::generate_mesh_keys_from_seed(&mesh_seed, 0);
    let node_id = *mesh_address.node_id.as_bytes();

    // Load persisted snapshot
    let storage = crate::persistence::NodeStorage::open(&config.state_dir)?;
    let snapshot = storage.load().unwrap_or_else(|_| crate::persistence::ArterySnapshot {
        node_id, peer_list: vec![], known_peers: vec![], peer_endpoints: vec![], banned_peers: vec![],
    });

    let state = Arc::new(Mutex::new(ArteryState::new(node_id, config.k_neighbors)));

    // Restore persisted peers
    {
        let mut s = state.lock().unwrap();
        for &pid in &snapshot.known_peers { s.known_peers.insert(pid); }
        for ep in &snapshot.peer_endpoints {
            if let Ok(contact) = vess_mesh::decode_mesh_contact_string(ep) {
                if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                    s.peer_endpoints.insert(id, ep.clone());
                    s.known_peers.insert(id);
                }
            }
        }
        for &pid in &snapshot.banned_peers { s.banned_peers.insert(pid); }
    }

    let (og_tx, mut og_rx) = mpsc::unbounded_channel::<Vess>();

    // ── Dynamic peer-add channel ──
    let (add_peer_tx, mut add_peer_rx) = mpsc::unbounded_channel::<String>();
    {
        let mut s = state.lock().unwrap();
        s.add_peer_tx = Some(add_peer_tx);
    }

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
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let mut s = cs.lock().unwrap();
            let epoch = clock::current_epoch();
            s.store.prune_deep_buried(epoch);
            tracing::debug!(epoch, "epochly prune");
        }
    });

    // ── Local discovery (LAN broadcast + mDNS) ──
    let discovery_state = state.clone();
    let discovery_node_id = node_id;
    let discovery_mesh_address = mesh_address.clone();
    let discovery_bind = bind_addr;
    tokio::spawn(async move {
        run_local_discovery(discovery_state, discovery_node_id, &discovery_mesh_address, discovery_bind).await;
    });

    // ── Process bootstrap peers ──
    for bs in &config.bootstrap {
        let bs = bs.trim().to_string();
        if bs.is_empty() { continue; }
        if let Ok(contact) = vess_mesh::decode_mesh_contact_string(&bs) {
            if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                if id != node_id {
                    let mut s = state.lock().unwrap();
                    s.known_peers.insert(id);
                    s.peer_endpoints.insert(id, bs.clone());
                    tracing::info!(peer=%hex::encode(&id[..8]), "bootstrap peer added");
                }
            }
        } else {
            // Try parsing as ip:port and create a contact string
            tracing::warn!(bootstrap=%bs, "unrecognized bootstrap format, skipping");
        }
    }

    // ── Periodic snapshot persistence ──
    let persist_state = state.clone();
    let persist_dir = config.state_dir.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let s = persist_state.lock().unwrap();
            let snap = crate::persistence::ArterySnapshot {
                node_id: s.node_id,
                peer_list: s.known_peers.iter().copied().collect(),
                known_peers: s.known_peers.iter().copied().collect(),
                peer_endpoints: s.peer_endpoints.values().cloned().collect(),
                banned_peers: s.banned_peers.iter().copied().collect(),
            };
            if let Ok(storage) = crate::persistence::NodeStorage::open(&persist_dir) {
                if let Err(e) = storage.save(&snap) {
                    tracing::warn!(%e, "failed to persist snapshot");
                }
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
                // Final persistence
                let s = state.lock().unwrap();
                let snap = crate::persistence::ArterySnapshot {
                    node_id: s.node_id,
                    peer_list: s.known_peers.iter().copied().collect(),
                    known_peers: s.known_peers.iter().copied().collect(),
                    peer_endpoints: s.peer_endpoints.values().cloned().collect(),
                    banned_peers: s.banned_peers.iter().copied().collect(),
                };
                if let Ok(storage) = crate::persistence::NodeStorage::open(&config.state_dir) {
                    let _ = storage.save(&snap);
                }
                break;
            }
            Some(contact_str) = add_peer_rx.recv() => {
                // Dynamic peer add at runtime
                if let Ok(contact) = vess_mesh::decode_mesh_contact_string(&contact_str) {
                    if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                        let mut s = state.lock().unwrap();
                        if id != s.node_id && !s.banned_peers.contains(&id) {
                            s.known_peers.insert(id);
                            s.peer_endpoints.insert(id, contact_str);
                            tracing::info!(peer=%hex::encode(&id[..8]), "peer added at runtime");
                        }
                    }
                }
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

/// Background task: LAN broadcast + mDNS discovery loop.
async fn run_local_discovery(
    state: Arc<Mutex<ArteryState>>,
    node_id: [u8; 32],
    mesh_address: &vess_mesh::MeshAddress,
    bind_addr: std::net::SocketAddr,
) {
    // Build our own contact for announcements
    let our_contact = vess_mesh::MeshCarrierContact::UdpSocket {
        addr: bind_addr.to_string(),
        mesh_address: mesh_address.clone(),
    };

    // Initial discovery sweep
    let discovered = crate::local_discovery::discover_lan_peer_contacts(
        std::time::Duration::from_secs(5),
        Some(node_id),
    ).await;

    {
        let mut s = state.lock().unwrap();
        for contact in &discovered {
            if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                if id != node_id && !s.banned_peers.contains(&id) {
                    if let Ok(contact_str) = vess_mesh::encode_mesh_contact_string(contact) {
                        s.known_peers.insert(id);
                        s.peer_endpoints.insert(id, contact_str);
                        tracing::debug!(peer=%hex::encode(&id[..8]), "discovered peer");
                    }
                }
            }
        }
    }

    // Periodic re-discovery + announcement
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tick.tick().await;

        // Announce ourselves on LAN
        if let Ok(socket) = crate::local_discovery::bind_lan_discovery_socket(0) {
            let _ = crate::local_discovery::send_lan_announcement(&socket, &our_contact).await;
        }

        // mDNS: query for other Vess nodes
        if let Ok(mdns_socket) = crate::local_discovery::bind_mdns_socket() {
            let _ = crate::local_discovery::send_mdns_query(&mdns_socket).await;
            // Listen briefly for responses
            let mut buf = vec![0u8; 2048];
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { break; }
                let recv = tokio::time::timeout(remaining, mdns_socket.recv_from(&mut buf)).await;
                if let Ok(Ok((len, _src))) = recv {
                    if let Some(contact_str) = crate::local_discovery::extract_contact_from_mdns_response(&buf[..len]) {
                        if let Ok(contact) = vess_mesh::decode_mesh_contact_string(&contact_str) {
                            if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                                let mut s = state.lock().unwrap();
                                if id != node_id && !s.banned_peers.contains(&id) {
                                    s.known_peers.insert(id);
                                    s.peer_endpoints.insert(id, contact_str);
                                    tracing::debug!(peer=%hex::encode(&id[..8]), "discovered via mDNS");
                                }
                            }
                        }
                    }
                }
            }
        }

        // Re-probe LAN for new peers
        let discovered = crate::local_discovery::discover_lan_peer_contacts(
            std::time::Duration::from_secs(3),
            Some(node_id),
        ).await;

        let mut s = state.lock().unwrap();
        for contact in &discovered {
            if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                if id != node_id && !s.banned_peers.contains(&id) {
                    if let Ok(contact_str) = vess_mesh::encode_mesh_contact_string(contact) {
                        s.known_peers.insert(id);
                        s.peer_endpoints.insert(id, contact_str);
                    }
                }
            }
        }
    }
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

async fn serve_rpc(state: Arc<Mutex<ArteryState>>, og_tx: mpsc::UnboundedSender<Vess>, port: u16) {
    let l = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await { Ok(l) => l, Err(e) => { tracing::error!(%e,"bind"); return; } };
    loop { if let Ok((s,_)) = l.accept().await { let st=state.clone(); let tx=og_tx.clone(); tokio::spawn(async { handle_conn(st,tx,s).await; }); } }
}

async fn handle_conn(state: Arc<Mutex<ArteryState>>, og_tx: mpsc::UnboundedSender<Vess>, mut stream: tokio::net::TcpStream) {
    use tokio::io::{AsyncBufReadExt,AsyncWriteExt,BufReader};
    let (r,mut w) = stream.split(); let mut lines = BufReader::new(r).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let req: crate::rpc::RpcRequest = match serde_json::from_str(&line) { Ok(r) => r, Err(_) => { let _=w.write_all(b"{\"ok\":false}\n").await; continue; } };
        let resp = crate::rpc::handle_rpc(&state, &og_tx, req);
        let _ = w.write_all(format!("{}\n", serde_json::to_string(&resp).unwrap_or_default()).as_bytes()).await;
    }
}