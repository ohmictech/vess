//! Vess artery — full node with mesh networking, wallet, mining, RPC.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use anyhow::Context;
use tokio::sync::mpsc;
use vess_foundry::Vess;
use vess_foundry::clock;
use crate::vess_store::VessStore;

// ── Node state ──

pub struct ArteryState {
    pub store: VessStore,
    pub minting: Option<MintingState>,
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
    /// Node's mesh contact for sharing with peers.
    pub mesh_contact: Option<vess_mesh::MeshCarrierContact>,
    /// Spend credentials for bills we own (mint_id → (vk, sk)).
    pub spend_credentials: HashMap<[u8; 32], (Vec<u8>, Vec<u8>)>,
    /// Outbox channel for sending mesh messages (for onion forwarding, etc.).
    pub mesh_outbox: Option<mpsc::UnboundedSender<(vess_mesh::MeshCarrierContact, vess_protocol::PulseMessage)>>,
    /// Kademlia routing table for DHT operations (mailbox, tag, Vess sharding).
    pub routing_table: crate::kademlia::RoutingTable,
    /// Last epoch the wallet swept its mailbox (for catch-up after offline).
    pub last_sweep_epoch: Option<u64>,
    /// Pending DHT queries awaiting responses (query_id → response sender).
    pub pending_queries: HashMap<[u8; 16], tokio::sync::mpsc::UnboundedSender<vess_protocol::DhtQueryResponse>>,
    /// Encrypted wallet manifests cached from DHT replication (dht_key → manifest).
    pub manifest_cache: HashMap<[u8; 32], vess_protocol::ManifestStore>,
    /// Track which peers sent us which DHT stores to avoid echo loops.
    pub dht_store_seen: HashSet<[u8; 32]>,
    /// Per-peer NAT traversal hints (node_id → observed_addr etc.).
    pub peer_hints: HashMap<[u8; 32], PeerHints>,
    /// Mesh node handle for dial cascade (relay/rendezvous).
    pub mesh_node: Option<Arc<vess_mesh::MeshPulseNode>>,
    /// Configured relay server address for NAT fallback.
    pub relay_addr: Option<std::net::SocketAddr>,
    /// Configured rendezvous server address for hole punching.
    pub rendezvous_addr: Option<std::net::SocketAddr>,
}

pub struct MintingState {
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
            minting: None, wallet_vk: None, wallet_sk: None, node_id,
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
            mesh_contact: None,
            spend_credentials: HashMap::new(),
            mesh_outbox: None,
            routing_table: crate::kademlia::RoutingTable::new(node_id),
            last_sweep_epoch: None,
            pending_queries: HashMap::new(),
            manifest_cache: HashMap::new(),
            dht_store_seen: HashSet::new(),
            peer_hints: HashMap::new(),
            mesh_node: None,
            relay_addr: None,
            rendezvous_addr: None,
        }
    }
    pub fn notify(&mut self, msg: &str) {
        self.notifications.push_back(WalletNotification { message: msg.to_string(), timestamp: now_secs() });
        if self.notifications.len() > 100 { self.notifications.pop_front(); }
    }

    /// DHT replication factor: max(50, sqrt(known_peers)).
    pub fn dht_replication(&self) -> usize {
        crate::ownership_registry::dht_replication_factor(self.known_peers.len().max(1))
    }

    /// Push an already-encrypted wallet manifest to the DHT.
    /// The caller handles encryption (wallet layer has the keys).
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

pub fn validate_vess(v: &Vess, store: &VessStore, current_epoch: u64) -> Result<(), String> {
    let id = v.compute_vess_id();
    if store.is_consumed(&id) { return Err("already consumed".into()); }
    if let Some(ex) = store.get(&id) { if v.chain_depth <= ex.chain_depth { return Err("stale".into()); } }

    // Validate minted Vess (Argon2d proof-of-work)
    if v.is_minted() {
        return vess_foundry::mint::verify_minted_vess(v, current_epoch);
    }

    // Validate faucet Vess (dev signature)
    if v.is_faucet() {
        return vess_foundry::mint::verify_faucet_vess(v, current_epoch, &vess_protocol::DEV_VK);
    }

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
    let start_epoch = vess_foundry::clock::current_epoch();
    {
        let mut s = state.lock().unwrap();
        s.minting = Some(MintingState { stop_tx: Some(stop_tx), amount, started_at: now_secs() });
    }

    let cs = state.clone();
    std::thread::spawn(move || {
        let mut nonce: u64 = 0;
        let mut current_epoch = start_epoch;
        let mut bills_minted: u64 = 0;

        loop {
            // Check for stop signal
            if stop_rx.try_recv().is_ok() {
                tracing::info!(bills_minted, "miner stopped");
                break;
            }

            // Check if epoch changed — reset nonce, continue with new epoch
            let now_epoch = vess_foundry::clock::current_epoch();
            if now_epoch != current_epoch {
                current_epoch = now_epoch;
                nonce = 0;
                tracing::debug!(epoch = current_epoch, "miner advanced to new epoch");
            }

            // Try nonce
            let hash = vess_foundry::mint::mint_argon2d(&initial_pk, current_epoch, nonce, amount);
            let bits = vess_foundry::mint::leading_zero_bits(&hash);
            let required_bits = vess_foundry::mint::amount_to_bits(amount);

            if bits >= required_bits {
                let owner_vk = {
                    let s = cs.lock().unwrap();
                    s.wallet_vk.clone()
                };
                if let Some(vk) = owner_vk {
                    let v = Vess {
                        amount,
                        epoch: current_epoch,
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
                    bills_minted += 1;
                    // Reset nonce for next bill, same epoch
                    nonce = 0;
                    continue;
                }
            }

            nonce = nonce.wrapping_add(1);
            if nonce % 1000 == 0 {
                std::thread::yield_now();
            }
        }
        let _ = cs.lock().map(|mut s| s.minting = None);
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
    /// Rendezvous server address for NAT hole punching (e.g. "1.2.3.4:9445").
    pub rendezvous_addr: Option<std::net::SocketAddr>,
    /// Relay server address for NAT fallback forwarding (e.g. "1.2.3.4:9446").
    pub relay_addr: Option<std::net::SocketAddr>,
}

/// Per-peer hints for how to reach a node behind NAT.
#[derive(Debug, Clone, Default)]
pub struct PeerHints {
    /// The peer's observed external address (from rendezvous/relay).
    pub observed_addr: Option<std::net::SocketAddr>,
    /// Whether this peer is registered with our rendezvous server.
    pub rendezvous_registered: bool,
    /// Whether this peer is registered with our relay server.
    pub relay_registered: bool,
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

    // ── Bind mesh UDP socket ──
    let mesh_node = vess_mesh::MeshPulseNode::bind_from_seed(bind_addr, &mesh_seed, 0).await
        .context("bind mesh UDP socket")?;
    let mesh_contact = mesh_node.contact();
    let node_id = *mesh_node.id().as_bytes();
    tracing::info!(%bind_addr, node_id=%hex::encode(&node_id[..8]), "mesh bound");

    // Wrap in Arc for shared access
    let mesh_node = Arc::new(mesh_node);

    // ── Auto-register with relay / rendezvous servers ──
    let _observed_relay = if let Some(relay_addr) = config.relay_addr {
        match mesh_node.register_with_relay(relay_addr).await {
            Ok(observed) => {
                tracing::info!(%observed, %relay_addr, "registered with relay server, observed address");
                Some(observed)
            }
            Err(e) => {
                tracing::warn!(%e, %relay_addr, "failed to register with relay server");
                None
            }
        }
    } else { None };

    let _observed_rendezvous = if let Some(rendezvous_addr) = config.rendezvous_addr {
        match mesh_node.register_with_rendezvous(rendezvous_addr).await {
            Ok(observed) => {
                tracing::info!(%observed, %rendezvous_addr, "registered with rendezvous server, observed address");
                Some(observed)
            }
            Err(e) => {
                tracing::warn!(%e, %rendezvous_addr, "failed to register with rendezvous server");
                None
            }
        }
    } else { None };

    // ── Mesh outbox: channel for forwarding onion hops and outgoing messages ──
    let (mesh_tx, mut mesh_rx) = mpsc::unbounded_channel::<(vess_mesh::MeshCarrierContact, vess_protocol::PulseMessage)>();

    // Load persisted snapshot
    let storage = crate::persistence::NodeStorage::open(&config.state_dir)?;
    let snapshot = storage.load().unwrap_or_else(|_| crate::persistence::ArterySnapshot {
        node_id, peer_list: vec![], known_peers: vec![], peer_endpoints: vec![], banned_peers: vec![], last_sweep_epoch: None,
    });

    let state = Arc::new(Mutex::new(ArteryState::new(node_id, config.k_neighbors)));

    // Store mesh contact and outbox channel
    {
        let mut s = state.lock().unwrap();
        s.mesh_contact = Some(mesh_contact.clone());
        s.mesh_outbox = Some(mesh_tx.clone());
        s.mesh_node = Some(mesh_node.clone());
        s.relay_addr = config.relay_addr;
        s.rendezvous_addr = config.rendezvous_addr;
    }

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
        s.last_sweep_epoch = snapshot.last_sweep_epoch;
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
                Ok(mut wallet) => {
                    // Unlock with password if set
                    if let Some(ref password) = config.wallet_password {
                        let unlocked = wallet.unlock_with_password(password);
                        if let Ok(raw_seed) = unlocked {
                            let enc_key = vess_sovereign::recovery::encryption_key_from_seed(&raw_seed);
                            // Decrypt spend credentials from the encrypted blob
                            if let Some(ref blob) = wallet.encrypted_spend_credentials {
                                if let Ok(json) = blob.decrypt(&enc_key) {
                                    #[derive(serde::Deserialize)]
                                    struct StoredCred { mint_id: [u8; 32], credential: vess_sovereign::billfold::SpendCredential }
                                    if let Ok(stored) = serde_json::from_slice::<Vec<StoredCred>>(&json) {
                                        let creds: HashMap<[u8; 32], _> = stored.into_iter()
                                            .map(|c| (c.mint_id, c.credential)).collect();
                                        wallet.billfold.import_credentials(creds);
                                        tracing::info!("wallet unlocked with password");
                                    }
                                }
                            }
                        } else {
                            tracing::warn!("wallet password incorrect — wallet loaded as watch-only");
                        }
                    }

                    let mut s = state.lock().unwrap();
                    if let Some(cred) = wallet.billfold.any_credential() {
                        s.wallet_vk = Some(cred.spend_vk.clone());
                        s.wallet_sk = Some(cred.spend_sk.clone());
                    }
                    // Backfill credentials for any existing bills with wallet VK
                    let w_vk = s.wallet_vk.clone();
                    let w_sk = s.wallet_sk.clone();
                    if let (Some(vk), Some(sk)) = (w_vk, w_sk) {
                        let owned: Vec<[u8; 32]> = s.store.iter()
                            .filter(|v| v.owner_vk == vk)
                            .map(|v| v.compute_vess_id())
                            .collect();
                        for id in owned {
                            s.spend_credentials.insert(id, (vk.clone(), sk.clone()));
                        }
                    }
                    s.wallet_path = Some(wallet_path.clone());
                    tracing::info!("wallet loaded with {} spendable bills", s.spend_credentials.len());
                }
                Err(e) => tracing::warn!(%e, "wallet load failed"),
            }
        }
    }

    // Epoch ticker (also prunes store + limbo)
    let cs = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let mut s = cs.lock().unwrap();
            let epoch = clock::current_epoch();
            s.store.prune_deep_buried(epoch);
            let (evicted, _) = s.limbo.evict_expired(now_secs());
            if evicted > 0 {
                tracing::debug!(evicted, "limbo expired entries pruned");
            }
            tracing::debug!(epoch, "epochly prune");
        }
    });

    // ── Local discovery (LAN broadcast + mDNS) ──
    let discovery_state = state.clone();
    let discovery_node_id = node_id;
    let discovery_contact = mesh_contact.clone();
    let discovery_bind = bind_addr;
    tokio::spawn(async move {
        run_local_discovery(discovery_state, discovery_node_id, &discovery_contact, discovery_bind).await;
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
                last_sweep_epoch: s.last_sweep_epoch,
            };
            if let Ok(storage) = crate::persistence::NodeStorage::open(&persist_dir) {
                if let Err(e) = storage.save(&snap) {
                    tracing::warn!(%e, "failed to persist snapshot");
                }
            }
        }
    });

    // ── Mesh message listener ──
    let mesh_state = state.clone();
    let mesh_og = og_tx.clone();
    let mesh_self_contact = mesh_contact.clone();
    let mesh_node_for_listener = mesh_node.clone();
    tokio::spawn(async move {
        if let Err(e) = mesh_node_for_listener.listen_messages_with_response(move |peer, msg| {
            handle_mesh_message(&mesh_state, &mesh_og, &peer, &msg, &mesh_self_contact)
        }).await {
            tracing::error!(%e, "mesh listener crashed");
        }
    });

    // ── Mesh forwarder: reads from outbox, sends via mesh with NAT cascade ──
    let mesh_node_for_forward = mesh_node.clone();
    let fwd_state = state.clone();
    tokio::spawn(async move {
        while let Some((contact, msg)) = mesh_rx.recv().await {
            if let Err(e) = dial_and_send(&fwd_state, &mesh_node_for_forward, &contact, &msg).await {
                tracing::warn!(%e, "mesh forward failed");
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
                    last_sweep_epoch: s.last_sweep_epoch,
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
                let v_id = v.compute_vess_id();
                if s.store.upsert(&v) {
                    // Store credential if we have wallet keys
                    if let (Some(ref vk), Some(ref sk)) = (s.wallet_vk.clone(), s.wallet_sk.clone()) {
                        if v.owner_vk == *vk {
                            s.spend_credentials.insert(v_id, (vk.clone(), sk.clone()));
                        }
                    }
                    // XOR-shard Vess to K nearest DHT peers
                    if let Some(ref tx) = s.mesh_outbox {
                        let mut ranked: Vec<([u8; 32], String)> = s.peer_endpoints.iter()
                            .map(|(id, ep)| (*id, ep.clone()))
                            .collect();
                        ranked.sort_by_key(|(id, _)| crate::gossip::xor_distance(id, &v_id));
                        let msg = vess_protocol::PulseMessage::DhtStoreVess(v.clone());
                        let repl = s.dht_replication();
                        for (_, ep) in ranked.iter().take(repl) {
                            if let Ok(contact) = vess_mesh::decode_mesh_contact_string(ep) {
                                let _ = tx.send((contact, msg.clone()));
                            }
                        }
                    }
                    s.notify(&format!("minted {} Vess (epoch {})", v.amount, v.epoch));
                    tracing::info!(id=%hex::encode(&v_id[..8]), amount=v.amount, epoch=v.epoch, "Vess minted");
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
    our_contact: &vess_mesh::MeshCarrierContact,
    _bind_addr: std::net::SocketAddr,
) {

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

// ── Mesh message handler ────────────────────────────────────────────

/// Process an incoming PulseMessage from the mesh. Returns an optional response.
fn handle_mesh_message(
    state: &Arc<Mutex<ArteryState>>,
    _og_tx: &mpsc::UnboundedSender<Vess>,
    peer: &vess_mesh::MeshPeer,
    msg: &vess_protocol::PulseMessage,
    _self_contact: &vess_mesh::MeshCarrierContact,
) -> Option<vess_protocol::PulseMessage> {
    match msg {
        // ── Onion routing: try to decrypt and forward/deliver ──
        vess_protocol::PulseMessage::OnionRoute(route) => {
            let relay_key = {
                let s = state.lock().unwrap();
                blake3::hash(&s.node_id).into()
            };
            match crate::onion::process_onion_route(route, &relay_key) {
                crate::onion::OnionAction::Forward(_inner) => {
                    // Forward to all known peers (gossip-style onion relay)
                    let s = state.lock().unwrap();
                    let repl = s.dht_replication();
                    if let Some(ref tx) = s.mesh_outbox {
                        let msg = vess_protocol::PulseMessage::OnionRoute(
                            vess_protocol::OnionRoute { outer: _inner.outer }
                        );
                        for ep_str in s.peer_endpoints.values().take(repl) {
                            if let Ok(contact) = vess_mesh::decode_mesh_contact_string(ep_str) {
                                let _ = tx.send((contact, msg.clone()));
                            }
                        }
                    }
                    tracing::debug!("onion: forwarded to peers");
                    None
                }
                crate::onion::OnionAction::Deliver { payment, shard_key: _ } => {
                    // Deliver to limbo with the shard key
                    let self_node_id = state.lock().unwrap().node_id;
                    let mut s = state.lock().unwrap();
                    s.limbo.hold(
                        payment.stealth_id,
                        payment.clone(),
                        vec![payment.payment_id],
                        crate::node_runner::now_secs(),
                        self_node_id,
                        payment.mailbox_key,
                    );
                    tracing::info!("onion: delivered payment to limbo");
                    None
                }
                crate::onion::OnionAction::Drop => {
                    // Not for us — gossip to other peers
                    None
                }
            }
        }

        // ── Direct payment: deliver to limbo ──
        vess_protocol::PulseMessage::Payment(payment) => {
            let self_node_id = state.lock().unwrap().node_id;
            let mut s = state.lock().unwrap();
            s.limbo.hold(
                payment.stealth_id,
                payment.clone(),
                vec![payment.payment_id],
                crate::node_runner::now_secs(),
                self_node_id,
                payment.mailbox_key,
            );
            tracing::debug!("received direct payment, held in limbo");
            None
        }

        // ── Mailbox sweep: return buffered payloads ──
        vess_protocol::PulseMessage::MailboxSweep(sweep) => {
            let s = state.lock().unwrap();
            let key = sweep.mailbox_key.unwrap_or([0u8; 32]);
            let payloads = s.limbo.sweep_by_mailbox_key(&key, 64);
            Some(vess_protocol::PulseMessage::MailboxSweepResponse(
                vess_protocol::MailboxSweepResponse {
                    nonce: sweep.nonce,
                    payloads,
                },
            ))
        }

        // ── Mailbox collect: generic limbo sweep ──
        vess_protocol::PulseMessage::MailboxCollect(_) => {
            let s = state.lock().unwrap();
            let payloads = s.limbo.sweep_payloads(64);
            Some(vess_protocol::PulseMessage::MailboxCollectResponse(
                vess_protocol::MailboxCollectResponse {
                    stealth_id: [0u8; 32],
                    payloads,
                },
            ))
        }

        // ── Tag gossip: receive and store tag registrations from peers ──
        vess_protocol::PulseMessage::TagRegister(tag_reg) => {
            let mut s = state.lock().unwrap();
            let record = vess_tag::TagRecord {
                tag_hash: tag_reg.tag_hash,
                master_address: vess_stealth::MasterStealthAddress {
                    scan_ek: tag_reg.scan_ek.clone(),
                    spend_ek: tag_reg.spend_ek.clone(),
                },
                pow_nonce: tag_reg.pow_nonce,
                pow_hash: tag_reg.pow_hash.clone(),
                registered_at: tag_reg.timestamp,
                registrant_vk: tag_reg.registrant_vk.clone(),
                signature: tag_reg.signature.clone(),
                hardened_at: None,
                grace_until_epoch: None,
            };
            s.tag_dht.store(record);
            tracing::debug!("received tag gossip");
            None
        }

        // ── Vess DHT sharding: receive and store Vess from peers ──
        vess_protocol::PulseMessage::DhtStoreVess(v) => {
            let mut s = state.lock().unwrap();
            if s.store.upsert(&v) {
                tracing::debug!(id=%hex::encode(&v.compute_vess_id()[..8]), amount=v.amount, "received Vess from DHT shard");
            }
            None
        }

        // ── Manifest store: receive and cache wallet manifests ──
        vess_protocol::PulseMessage::DhtStoreManifest(manifest) => {
            tracing::debug!(dht_key=%hex::encode(&manifest.dht_key[..8]), "received wallet manifest from DHT shard");
            let mut s = state.lock().unwrap();
            s.manifest_cache.insert(manifest.dht_key, (*manifest).clone());
            None
        }

        // ── DHT Query: respond with local data + Vess ownership proof ──
        vess_protocol::PulseMessage::DhtQuery(query) => {
            let s = state.lock().unwrap();
            let mut tags = vec![];
            let mut payloads = vec![];
            let mut vess = vec![];
            let mut manifests = vec![];
            match &query.query_kind {
                vess_protocol::DhtQueryKind::TagLookup => {
                    if let Some(record) = s.tag_dht.lookup_by_hash(&query.dht_key) {
                        tags.push(serde_json::to_vec(record).unwrap_or_default());
                    }
                }
                vess_protocol::DhtQueryKind::MailboxSweep => {
                    payloads = s.limbo.sweep_by_mailbox_key(&query.dht_key, 64);
                }
                vess_protocol::DhtQueryKind::VessLookup => {
                    if let Some(v) = s.store.get(&query.dht_key) {
                        vess.push(serde_json::to_vec(v).unwrap_or_default());
                    }
                }
                vess_protocol::DhtQueryKind::ManifestLookup => {
                    if let Some(manifest) = s.manifest_cache.get(&query.dht_key) {
                        manifests.push(serde_json::to_vec(manifest).unwrap_or_default());
                    }
                }
            }

            // Sign with Vess ownership proof
            let proof = build_dht_proof(&s, &tags, &payloads, &vess, &manifests);

            Some(vess_protocol::PulseMessage::DhtQueryResponse(
                vess_protocol::DhtQueryResponse {
                    nonce: query.nonce,
                    query_kind: query.query_kind.clone(),
                    tags, payloads, vess, manifests,
                    proof,
                },
            ))
        }

        // ── DHT Query Response: route back to waiting query ──
        vess_protocol::PulseMessage::DhtQueryResponse(resp) => {
            let s = state.lock().unwrap();
            if let Some(tx) = s.pending_queries.get(&resp.nonce) {
                let _ = tx.send(resp.clone());
            }
            None
        }

        // ── Peer Exchange: add discovered peers to routing table ──
        vess_protocol::PulseMessage::PeerExchange(_ex) => {
            let mut s = state.lock().unwrap();
            // Add the sender to our routing table
            if let Some(id) = peer.node_id().map(|n| *n.as_bytes()) {
                if id != s.node_id && !s.banned_peers.contains(&id) {
                    s.known_peers.insert(id);
                    let contact_str = vess_mesh::encode_mesh_contact_string(&peer.contact).unwrap_or_default();
                    s.peer_endpoints.insert(id, contact_str);
                    let rp = crate::kademlia::RoutingPeer {
                        id_hash: id, id_bytes: id.to_vec(),
                        last_seen: now_secs(), first_seen: now_secs(),
                    };
                    s.routing_table.insert(rp);
                    // Track NAT traversal hints for this peer
                    s.peer_hints.entry(id).or_default();
                }
            }
            None
        }

        // ── FindNode: respond with K closest peers to target ──
        vess_protocol::PulseMessage::FindNode(fn_req) => {
            let s = state.lock().unwrap();
            let k = s.dht_replication();
            let mut peers: Vec<([u8; 32], &String)> = s.peer_endpoints.iter()
                .map(|(id, ep)| (*id, ep)).collect();
            peers.sort_by_key(|(id, _)| crate::gossip::xor_distance(id, &fn_req.target));
            let closest: Vec<Vec<u8>> = peers.iter().take(k)
                .map(|(_, ep)| ep.as_bytes().to_vec()).collect();
            Some(vess_protocol::PulseMessage::FindNodeResponse(
                vess_protocol::FindNodeResponse { peers: closest }
            ))
        }

        // ── FindNodeResponse: insert peers into routing table ──
        vess_protocol::PulseMessage::FindNodeResponse(fnr) => {
            let mut s = state.lock().unwrap();
            for contact_bytes in &fnr.peers {
                if let Ok(contact) = vess_mesh::decode_mesh_contact_string(
                    &String::from_utf8_lossy(contact_bytes)
                ) {
                    if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                        if id != s.node_id && !s.banned_peers.contains(&id) {
                            let rp = crate::kademlia::RoutingPeer {
                                id_hash: id, id_bytes: id.to_vec(),
                                last_seen: now_secs(), first_seen: now_secs(),
                            };
                            s.routing_table.insert(rp);
                        }
                    }
                }
            }
            None
        }

        // ── LimboHold: store payment in limbo for offline recipient ──
        vess_protocol::PulseMessage::LimboHold(hold) => {
            let mut s = state.lock().unwrap();
            let peer_id_bytes = peer.node_id().map(|n| *n.as_bytes()).unwrap_or([0u8; 32]);
            // Create a minimal Payment from the hold data for limbo storage
            let payment = vess_protocol::Payment {
                payment_id: [0u8; 32],
                stealth_payload: vec![],
                view_tag: 0,
                stealth_id: hold.stealth_id,
                created_at: hold.entered_at,
                bill_count: hold.bill_ids.len() as u8,
                mailbox_key: None,
                direct_receipt_tag_hash: None,
                hash_lock: None,
            };
            s.limbo.hold(hold.stealth_id, payment, hold.bill_ids.clone(), hold.entered_at, peer_id_bytes, None);
            tracing::debug!(stealth=%hex::encode(&hold.stealth_id[..8]), "limbo hold stored");
            None
        }

        // ── LimboNotify: peer announces limbo payments for a stealth_id ──
        vess_protocol::PulseMessage::LimboNotify(notify) => {
            let s = state.lock().unwrap();
            let pending = !s.limbo.peek(&notify.stealth_id).is_empty();
            drop(s);
            if pending {
                if let Some(ref tx) = state.lock().unwrap().mesh_outbox {
                    let _ = tx.send((peer.contact.clone(), vess_protocol::PulseMessage::LimboNotify(notify.clone())));
                }
            }
            None
        }

        // ── LimboDeliver: deliver buffered payment to recipient ──
        vess_protocol::PulseMessage::LimboDeliver(deliver) => {
            let s = state.lock().unwrap();
            let payment = deliver.payment.clone();
            // Store the delivered payment and notify via mailbox sweep response
            if let Some(ref tx) = s.mesh_outbox {
                let serialized = serde_json::to_vec(&payment).unwrap_or_default();
                let resp = vess_protocol::PulseMessage::MailboxSweepResponse(
                    vess_protocol::MailboxSweepResponse {
                        nonce: [0u8; 16],
                        payloads: vec![serialized],
                    }
                );
                let _ = tx.send((peer.contact.clone(), resp));
            }
            None
        }

        // ── MailboxSweep: sweep limbo for recipient (duplicate handled above) ──

        // ── ManifestRecover: return cached manifest if we have it ──
        vess_protocol::PulseMessage::ManifestRecover(req) => {
            let s = state.lock().unwrap();
            if let Some(m) = s.manifest_cache.get(&req.dht_key) {
                Some(vess_protocol::PulseMessage::ManifestRecoverResponse(
                    vess_protocol::ManifestRecoverResponse {
                        dht_key: req.dht_key,
                        encrypted_manifest: m.encrypted_manifest.clone(),
                        found: true,
                    }
                ))
            } else {
                Some(vess_protocol::PulseMessage::ManifestRecoverResponse(
                    vess_protocol::ManifestRecoverResponse {
                        dht_key: req.dht_key,
                        encrypted_manifest: vec![],
                        found: false,
                    }
                ))
            }
        }

        // ── NetworkStats: respond with peer count and uptime ──
        vess_protocol::PulseMessage::NetworkStats(req) => {
            let s = state.lock().unwrap();
            Some(vess_protocol::PulseMessage::NetworkStatsResponse(
                vess_protocol::NetworkStatsResponse {
                    nonce: req.nonce,
                    peer_count: s.known_peers.len() as u64,
                    verified_peer_count: s.peer_registry.count_in_state(crate::handshake::PeerState::Verified) as u64,
                    estimated_network_size: s.routing_table.estimated_network_size() as u64,
                    limbo_count: s.limbo.total_entries() as u64,
                    median_payment_latency_ms: 0,
                    p95_payment_latency_ms: 0,
                    latency_sample_count: 0,
                }
            ))
        }

        // ── RegistryQuery: check if we have a Vess by mint_id ──
        vess_protocol::PulseMessage::RegistryQuery(rq) => {
            let s = state.lock().unwrap();
            let active: Vec<bool> = rq.mint_ids.iter()
                .map(|id| s.store.get(id).is_some())
                .collect();
            Some(vess_protocol::PulseMessage::RegistryQueryResponse(
                vess_protocol::RegistryQueryResponse { active }
            ))
        }

        // ── Gossip / other — stubbed for now ──
        _ => {
            tracing::trace!("unhandled mesh message: {:?}", std::mem::discriminant(msg));
            None
        }
    }
}

/// Build a SignedDhtResponse proving Vess ownership for DHT response trust weighting.
fn build_dht_proof(
    s: &ArteryState,
    tags: &[Vec<u8>],
    payloads: &[Vec<u8>],
    vess: &[Vec<u8>],
    _manifests: &[Vec<u8>],
) -> Option<vess_protocol::SignedDhtResponse> {
    // Pick any Vess we have spend credentials for as proof of ownership
    let (proof_vess_id, owner_sk) = s.spend_credentials.iter().next()
        .map(|(id, (_, sk))| (*id, sk.clone()))?;

    // Serialize results for signing
    let results = serde_json::json!({
        "tags": tags.iter().map(|t| hex::encode(t)).collect::<Vec<_>>(),
        "payloads": payloads.len(),
        "vess": vess.len(),
    });
    let results_bytes = serde_json::to_vec(&results).unwrap_or_default();

    // Sign: Blake3("vess-dht-v1" || results || proof_vess_id)
    let sig_msg = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-dht-v1");
        h.update(&results_bytes);
        h.update(&proof_vess_id);
        *h.finalize().as_bytes()
    };

    let responder_sig = vess_foundry::spend_auth::sign_spend(&owner_sk, &sig_msg).ok()?;

    Some(vess_protocol::SignedDhtResponse {
        results: results_bytes,
        proof_vess_id,
        responder_sig,
    })
}

// ── NAT traversal: dial cascade ──────────────────────────────────────

/// Send a message to a peer, trying multiple paths in cascade:
/// 1. Direct UDP (fastest, works with port forwarding / UPnP)
/// 2. Rendezvous hole-punch (works for most home NATs)
/// 3. Relay forwarding (works for symmetric NATs)
async fn dial_and_send(
    state: &Arc<Mutex<ArteryState>>,
    mesh_node: &Arc<vess_mesh::MeshPulseNode>,
    contact: &vess_mesh::MeshCarrierContact,
    msg: &vess_protocol::PulseMessage,
) -> anyhow::Result<()> {
    // 1. Try direct
    match mesh_node.send_message(contact, msg).await {
        Ok(()) => return Ok(()),
        Err(e) => tracing::debug!(%e, "direct send failed, trying cascade"),
    }

    // 2. Try rendezvous hole-punch
    let rendezvous = {
        let s = state.lock().unwrap();
        s.rendezvous_addr
    };
    if let Some(rendezvous_addr) = rendezvous {
        if let Some(target_id) = contact.node_id() {
            match mesh_node.send_message_with_response_via_rendezvous(
                rendezvous_addr, target_id, msg,
            ).await {
                Ok(_) => {
                    tracing::debug!("hole-punch succeeded via rendezvous");
                    return Ok(());
                }
                Err(e) => tracing::debug!(%e, "rendezvous hole-punch failed"),
            }
        }
    }

    // 3. Try relay fallback
    let relay = {
        let s = state.lock().unwrap();
        s.relay_addr
    };
    if let Some(relay_addr) = relay {
        match mesh_node.send_message_with_response_via_relay(
            relay_addr, contact, msg,
        ).await {
            Ok(_) => {
                tracing::debug!("relay forward succeeded");
                return Ok(());
            }
            Err(e) => tracing::debug!(%e, "relay forward failed"),
        }
    }

    // All paths failed
    Err(anyhow::anyhow!("all dial paths exhausted for peer"))
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