use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use rand::Rng;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use vess_crypto::*;
use vess_network::*;

const DANDELION_MAX_STEM: u8 = 4;
const DANDELION_FLUFF_PROB: f64 = 0.10; // 10% chance per hop to switch to fluff
const DANDELION_EMBARGO_TICKS: u64 = 40; // ~200ms embargo before fluff broadcast
const HOLE_PUNCH_MAX_RETRIES: u8 = 3;
const STEM_RELAY_MAX_PER_TICK: usize = 2;
const MAX_FRAME_SIZE: usize = 20 * 1024 * 1024;  // 20 MB max UDP datagram (block + overhead)

/// NAT reachability classification.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum NatType {
    /// Haven't determined yet
    Unknown,
    /// Publicly reachable — our self-reported address matches what peers see
    Open,
    /// Behind a NAT — peers see a different address than we report
    BehindNat,
}

/// A peer we're trying to hole-punch through to.
#[derive(Clone)]
pub struct IntroducedPeer {
    pub observed_addr: SocketAddr,
    pub punch_nonce: u32,
    pub retries: u8,
}

pub struct Node {
    pub addr: SocketAddr,
    pub network: Network,
    pub peers: HashMap<SocketAddr, NodeId>,
    pub max_peers: usize,   // configurable gossip fanout cap
    pub needs_sync: bool,    // true until quorum merkle confirms we're caught up
    pub env: heed::Env,
    pub vess_index: heed::Database<heed::types::Bytes, heed::types::Unit>,
    ban_list: heed::Database<heed::types::Bytes, heed::types::Unit>,
    meta: heed::Database<heed::types::Str, heed::types::Bytes>,
    mined_keys: heed::Database<heed::types::Bytes, heed::types::Bytes>, // owner_hash → pubkey||spend_key
    peers_db: heed::Database<heed::types::Bytes, heed::types::Unit>,   // persisted peer addresses
    limbo: HashMap<PaymentId, (VessPayment, u64)>,       // payment → (data, entry_tick)
    limbo_inputs: HashMap<VessId, Vec<PaymentId>>,       // which limbo payments claim each input
    contested: HashSet<PaymentId>,                        // payments with conflicting inputs (burn on block inclusion)
    outbox: Vec<(SocketAddr, Vec<u8>)>,
    pub stems: HashMap<PaymentId, u8>,
    pub fluff_embargo: HashMap<PaymentId, (VessPayment, u64)>, // delayed fluff: payment → (data, queued_tick)
    pub ticks: u64,
    pub fails: HashMap<SocketAddr, u32>,
    peer_msg_count: HashMap<SocketAddr, u32>,
    msg_window_start: u64,
    peer_merkle: HashMap<SocketAddr, (u64, MerkleRoot)>,
    blocks: HashMap<BlockHash, VessBlock>,    // recent blocks by hash
    pub tip_hashes: Vec<BlockHash>,               // DAG tips for parent selection
    current_tip: Option<BlockHash>,           // tip our LMDB state corresponds to
    pub mining: bool,                          // auto-mine blocks from limbo payments
    pub current_difficulty: u32,               // adjusts via DAA every DIFFICULTY_WINDOW blocks
    pub pending_blocks: Vec<VessBlock>,            // blocks waiting for gossip broadcast
    // NAT traversal
    pub nat_type: NatType,                      // our reachability classification
    pub introducer: Option<SocketAddr>,         // public peer helping us punch through
    pub introduced_peers: HashMap<NodeId, IntroducedPeer>, // peers we're hole-punching toward
    relay_queue: Vec<(NodeId, Vec<u8>)>,        // StemRelay fallback queue (target_id, gossip_bytes)
    // State sync
    sync_peer: Option<SocketAddr>,               // peer we're syncing UTXOs from
    sync_offset: u64,                             // how many UTXO IDs received so far
    sync_target_root: Option<MerkleRoot>,         // target merkle root we're aiming for
    sync_chunk_size: u32,                         // IDs per SyncReq chunk
    auto_sync_until: u64,                         // keep driving sync until this tick
    test_mode: bool,
}

impl Node {
    pub fn new(addr: SocketAddr) -> Self { Self::new_inner(addr, "vess-db", false) }
    pub fn new_test(addr: SocketAddr) -> Self { Self::new_inner(addr, "vess-db", true) }
    #[doc(hidden)]
    pub fn new_test_at(addr: SocketAddr, db_path: &str) -> Self { Self::new_inner(addr, db_path, true) }

    fn new_inner(addr: SocketAddr, db_path: &str, test_mode: bool) -> Self {
        let _ = std::fs::create_dir(db_path);
        let env = unsafe { heed::EnvOpenOptions::new().map_size(1_073_741_824).max_dbs(5).open(db_path) }.unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let db: heed::Database<heed::types::Bytes, heed::types::Unit> = env.create_database(&mut wtxn, Some("vess")).unwrap();
        let ban_list: heed::Database<heed::types::Bytes, heed::types::Unit> = env.create_database(&mut wtxn, Some("bans")).unwrap();
        let meta: heed::Database<heed::types::Str, heed::types::Bytes> = env.create_database(&mut wtxn, Some("meta")).unwrap();
        let mined_keys: heed::Database<heed::types::Bytes, heed::types::Bytes> = env.create_database(&mut wtxn, Some("keys")).unwrap();
        let peers_db: heed::Database<heed::types::Bytes, heed::types::Unit> = env.create_database(&mut wtxn, Some("peers")).unwrap();
        wtxn.commit().unwrap();

        let (saved_ticks, saved_diff) = Self::load_meta(&env, &meta);
        let mut node = Self { addr, network: Network::new(), peers: HashMap::new(), max_peers: 32, needs_sync: true, env, vess_index: db, ban_list, meta, mined_keys, peers_db,
            limbo: HashMap::new(), limbo_inputs: HashMap::new(), contested: HashSet::new(),
            outbox: Vec::new(), ticks: saved_ticks, fails: HashMap::new(),
            peer_msg_count: HashMap::new(), msg_window_start: 0, peer_merkle: HashMap::new(),
            stems: HashMap::new(), fluff_embargo: HashMap::new(),
            blocks: HashMap::new(), tip_hashes: Vec::new(), current_tip: None, mining: false,
            current_difficulty: saved_diff,
            pending_blocks: Vec::new(),
            nat_type: NatType::Unknown,
            introducer: None,
            introduced_peers: HashMap::new(),
            relay_queue: Vec::new(),
            sync_peer: None,
            sync_offset: 0,
            sync_target_root: None,
            sync_chunk_size: 10000,
            auto_sync_until: 0,
            test_mode };
        // Load persisted bans
        if let Ok(t) = node.env.read_txn() {
            if let Ok(iter) = node.ban_list.iter(&t) {
                for entry in iter {
                    if let Ok((key, _)) = entry {
                        if key.len() >= 6 {
                            let addr = SocketAddr::from(([0,0,0,0], u16::from_le_bytes([key[4], key[5]])));
                            node.fails.insert(addr, 100); // Already banned
                        }
                    }
                }
            }
            // Load persisted peers
            if let Ok(iter) = node.peers_db.iter(&t) {
                for entry in iter {
                    if let Ok((key, _)) = entry {
                        if key.len() >= 6 {
                            let port = u16::from_le_bytes([key[0], key[1]]);
                            let ip = &key[2..];
                            if ip.len() >= 4 {
                                let ip_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                    ip[0], ip[1], ip[2], ip[3]));
                                let addr = SocketAddr::new(ip_addr, port);
                                // Don't add our own address
                                if addr != node.addr {
                                    node.peers.insert(addr, [0u8; 32]);
                                }
                            }
                        }
                    }
                }
            }
        }
        node
    }

    fn load_meta(env: &heed::Env, meta: &heed::Database<heed::types::Str, heed::types::Bytes>) -> (u64, u32) {
        let t = match env.read_txn() { Ok(t) => t, Err(_) => return (0, DIFFICULTY_BASE_BITS) };
        let ticks = meta.get(&t, "ticks").ok().flatten().and_then(|b| if b.len()>=8 { Some(u64::from_le_bytes(b[..8].try_into().unwrap())) } else { None }).unwrap_or(0);
        let diff = meta.get(&t, "diff").ok().flatten().and_then(|b| if b.len()>=4 { Some(u32::from_le_bytes(b[..4].try_into().unwrap())) } else { None }).unwrap_or(DIFFICULTY_BASE_BITS);
        (ticks, diff)
    }

    fn save_meta(&self) {
        if let Ok(mut w) = self.env.write_txn() {
            let _ = self.meta.put(&mut w, "ticks", &self.ticks.to_le_bytes());
            let _ = self.meta.put(&mut w, "diff", &self.current_difficulty.to_le_bytes());
            // Best-effort commit; meta loss is recoverable
            let _ = w.commit();
        }
    }

    pub fn my_node_id(&self) -> NodeId { self.network.my_node_id() }
    pub fn get_addr(&self) -> SocketAddr { self.addr }
    pub fn get_peers(&self) -> Vec<(NodeId, SocketAddr)> {
        self.peers.iter().filter_map(|(a,id)| if *id!=[0u8;32]{Some((*id,*a))}else{None}).collect()
    }
    pub fn peer_count(&self) -> usize {
        self.peers.iter().filter(|(_,id)| **id != [0u8;32]).count()
    }
    pub fn limbo_len(&self) -> usize { self.limbo.len() }
    /// Number of UTXOs in the LMDB state index.
    pub fn utxo_count(&self) -> usize {
        self.env.read_txn().ok()
            .and_then(|t| self.vess_index.len(&t).ok())
            .unwrap_or(0) as usize
    }
    pub fn has_session_for(&self, addr: &SocketAddr) -> bool { self.network.session_by_addr(addr).is_some() }

    // ---- NAT traversal helpers ----

    /// Returns true if we believe we're behind a NAT.
    pub fn is_behind_nat(&self) -> bool { self.nat_type == NatType::BehindNat }

    /// Returns true if we're publicly reachable (observed == self-reported).
    pub fn is_public(&self) -> bool { self.nat_type == NatType::Open }

    /// Pick a public peer to act as our introducer.
    /// Returns None if we're already public or no public peers are known.
    fn select_introducer(&mut self) -> Option<SocketAddr> {
        if self.is_public() { return None; }
        // Find a peer that reports the same address we observe them at
        // (public peers have matching observed/reported addresses)
        let public: Vec<SocketAddr> = self.peers.iter()
            .filter(|(a, id)| {
                **id != [0u8; 32] && self.network.session_by_addr(a)
                    .map(|s| s.is_public_peer())
                    .unwrap_or(false)
            })
            .map(|(a, _)| *a)
            .collect();
        if public.is_empty() { return None; }
        // Pick the one we've known longest (first session)
        let chosen = public[0];
        self.introducer = Some(chosen);
        Some(chosen)
    }

    /// Send a hole-punch packet to a target address (no session needed).
    fn send_hole_punch(&mut self, addr: SocketAddr, nonce: u32) {
        let raw = GossipMessage::HolePunch(nonce).encode();
        // Hole punch goes as a raw frame — no encryption session required
        self.outbox.push((addr, raw));
    }

    /// Try to handshake with a hole-punched address (bypasses max_peers).
    pub fn try_punch_handshake(&mut self, addr: SocketAddr) {
        if !self.has_session_for(&addr) {
            let init = self.network.build_handshake_init(addr);
            self.outbox.push((addr, init));
        }
    }

    /// Manually establish a session with a known key (for testing).
    #[doc(hidden)]
    pub fn inject_session(&mut self, addr: SocketAddr, node_id: NodeId, key: [u8; 32]) {
        if self.network.session_by_addr(&addr).is_none() {
            self.network.sessions.push(vess_network::Session {
                addr, node_id: Some(node_id), session_key: key, peer_version: PROTOCOL_VERSION,
                reported_addr: Some(addr), nonce_ctr: 0,
            });
        }
        self.peers.insert(addr, node_id);
    }

    /// Send an introduce request to our introducer, asking them to connect us to target.
    #[allow(dead_code)]
    fn request_introduction(&mut self, target_id: NodeId) {
        if let Some(intro) = self.introducer {
            self.send(intro, &GossipMessage::IntroduceRequest(target_id));
        }
    }

    /// Send an Introduce message to a target peer (we're the introducer).
    pub fn send_introduce_to(&mut self, target_id: NodeId, requester_id: NodeId, requester_addr: SocketAddr) {
        // Find target peer's address
        let target_addr = self.peers.iter()
            .find(|(_, id)| **id == target_id)
            .map(|(a, _)| *a);
        if let Some(ta) = target_addr {
            self.send(ta, &GossipMessage::Introduce(requester_id, requester_addr));
        }
    }

    /// Relay a raw gossip message through our introducer to the target (stem relay fallback).
    fn relay_through_introducer(&mut self, target_id: NodeId, gossip_bytes: Vec<u8>) {
        self.relay_queue.push((target_id, gossip_bytes));
    }
    pub fn add_peer(&mut self, a: SocketAddr) -> Vec<u8> {
        if self.peer_count() >= self.max_peers { return Vec::new(); }
        let raw = self.network.build_handshake_init(a);
        let (tag, payload) = unframe(&raw).unwrap_or((HANDSHAKE_INIT, &[][..]));
        // PoW handshake puzzle: find a 6-cycle. Include the winning header + proof.
        let base = blake3_hash(&[b"vess-handshake" as &[u8], &self.network.my_node_id(), &a.to_string().as_bytes()].concat());
        let mut header = base;
        let proof = loop {
            if let Some(p) = cuckoo::solve(&header, cuckoo::HANDSHAKE_CYCLE_LENGTH, cuckoo::HANDSHAKE_EDGE_BITS) {
                break (header, p);
            }
            header = blake3_hash(&header);
        };
        let mut payload_with_pow = payload.to_vec();
        payload_with_pow.extend_from_slice(&proof.0); // 32-byte header hash
        for n in &proof.1 { payload_with_pow.extend_from_slice(&n.to_le_bytes()); }
        frame(tag, &payload_with_pow)
    }

    /// Persist a peer address so we can reconnect on restart.
    fn persist_peer(&self, addr: SocketAddr) {
        let mut key = addr.port().to_le_bytes().to_vec();
        match addr.ip() {
            std::net::IpAddr::V4(ip) => key.extend_from_slice(&ip.octets()),
            std::net::IpAddr::V6(ip) => key.extend_from_slice(&ip.octets()),
        }
        if let Ok(mut w) = self.env.write_txn() {
            let _ = self.peers_db.put(&mut w, &key, &());
            let _ = w.commit();
        }
    }

    /// Trigger auto-sync for the next ~5 seconds (1000 ticks).
    fn trigger_auto_sync(&mut self) {
        self.auto_sync_until = self.ticks.saturating_add(1000);
    }

    /// Attempt to reconnect to all known-but-unconnected peers.
    /// Returns list of (addr, handshake_init_bytes) to be sent via socket.
    pub fn reconnect_peers(&mut self) -> Vec<(std::net::SocketAddr, Vec<u8>)> {
        let unconnected: Vec<std::net::SocketAddr> = self.peers.iter()
            .filter(|(a, id)| {
                **id == [0u8; 32] &&               // not yet handshaked
                *a != &self.addr &&                 // not ourselves
                !self.has_session_for(a)            // no active session
            })
            .map(|(a, _)| *a)
            .collect();
        let mut out = Vec::new();
        for addr in unconnected {
            if self.peer_count() >= self.max_peers { break; }
            let init = self.add_peer(addr);
            if !init.is_empty() {
                out.push((addr, init));
            }
        }
        out
    }
    pub fn check_direct(&self, id: &VessId) -> bool {
        self.env.read_txn().ok()
            .and_then(|t| self.vess_index.get(&t, id).ok().flatten())
            .is_some()
    }

    pub fn check(&self, id: &VessId) -> bool {
        // Check LMDB first, then limbo outputs (pending, not yet in LMDB)
        self.env.read_txn().ok()
            .and_then(|t| self.vess_index.get(&t, id).ok().flatten())
            .is_some()
            || self.limbo.values().any(|(p, _)| p.outputs.iter().any(|v| &v.vess_id() == id))
    }

    // ---- limbo system ----

    /// Burn all inputs and outputs of conflicting payments — from limbo AND LMDB.
    /// Called when a block includes contested payments.
    #[allow(dead_code)]
    fn annihilate(&mut self, payments: &[VessPayment]) {
        let mut pids = Vec::new();
        if let Ok(mut w) = self.env.write_txn() {
            for p in payments {
                pids.push(p.payment_id);
                // Remove from limbo if still there
                self.limbo.remove(&p.payment_id);
                // Burn all inputs (from limbo tracking + LMDB)
                for v in &p.inputs {
                    self.limbo_inputs.remove(&v.vess_id());
                    let _ = self.vess_index.delete(&mut w, &v.vess_id());
                }
                // Burn all outputs (from LMDB — may have been inserted if already finalized)
                for v in &p.outputs {
                    let _ = self.vess_index.delete(&mut w, &v.vess_id());
                }
            }
            let _ = w.commit();
        }
        // Clean up limbo_inputs for any remaining references to these payments
        for claims in self.limbo_inputs.values_mut() {
            claims.retain(|pid| !pids.contains(pid));
        }
        self.limbo_inputs.retain(|_, claims| !claims.is_empty());
    }

    // ---- submit ----

    pub fn submit(&mut self, p: VessPayment) -> bool {
        // Don't accept payments while catching up; isolated nodes are always "synced"
        if self.needs_sync && self.peer_count() > 0 { return false; }
        if self.limbo.contains_key(&p.payment_id) { return false; }
        if !self.verify(&p) { return false; }

        // Check for conflicts: any input already claimed by another limbo payment?
        let mut conflicting: HashSet<PaymentId> = HashSet::new();
        for v in &p.inputs {
            if let Some(claimants) = self.limbo_inputs.get(&v.vess_id()) {
                for c in claimants { conflicting.insert(*c); }
            }
        }
        if !conflicting.is_empty() {
            // Conflict detected — mark all involved payments as contested.
            // They stay in limbo until mined; block processor annihilates them.
            conflicting.insert(p.payment_id);
            for cpid in &conflicting { self.contested.insert(*cpid); }
        }

        // Enter limbo (mempool) — payments only exit via block inclusion
        for v in &p.inputs {
            self.limbo_inputs.entry(v.vess_id()).or_default().push(p.payment_id);
        }
        self.limbo.insert(p.payment_id, (p.clone(), self.ticks));
        self.relay(&p);
        self.trigger_auto_sync();
        true
    }

    // ---- limbo maintenance ----

    /// Apply all clean (non-contested) limbo payments to LMDB.
    /// In production, this is done by block processing. For tests/standalone.
    pub fn flush_limbo(&mut self) {
        let clean: Vec<PaymentId> = self.limbo.keys()
            .filter(|pid| !self.contested.contains(*pid))
            .copied()
            .collect();
        if clean.is_empty() { return; }
        if let Ok(mut w) = self.env.write_txn() {
            for pid in &clean {
                if let Some((p, _)) = self.limbo.remove(pid) {
                    for v in &p.inputs {
                        let _ = self.vess_index.delete(&mut w, &v.vess_id());
                        self.limbo_inputs.remove(&v.vess_id());
                    }
                    for v in &p.outputs {
                        let _ = self.vess_index.put(&mut w, &v.vess_id(), &());
                    }
                }
            }
            let _ = w.commit();
        }
        self.save_meta();
    }

    // ---- block mining ----

    /// Compute what the state merkle WILL be after applying a set of payments.
    fn compute_state_merkle(&self, all_payments: &[VessPayment]) -> MerkleRoot {
        let conflicted = Self::find_conflicts(all_payments);
        let rt = match self.env.read_txn() { Ok(t) => t, Err(_) => return [0u8; 32] };
        let mut ids: Vec<VessId> = self.vess_index.iter(&rt).unwrap()
            .filter_map(|r| r.ok())
            .map(|(k, _)| { let mut a = [0u8;32]; a.copy_from_slice(&k); a })
            .collect();
        drop(rt);
        for (i, p) in all_payments.iter().enumerate() {
            if conflicted.contains(&i) {
                for inp in &p.inputs { ids.retain(|id| id != &inp.vess_id()); }
                for out in &p.outputs { ids.retain(|id| id != &out.vess_id()); }
            } else {
                for inp in &p.inputs { ids.retain(|id| id != &inp.vess_id()); }
                for out in &p.outputs { ids.push(out.vess_id()); }
            }
        }
        ids.sort(); ids.dedup();
        merkle_root(&ids)
    }

    /// Test helper: mine a block with coinbase to the given owner. Returns coinbase outputs.
    pub fn test_mine(&mut self, owner_hash: OwnerHash, pubkey: Vec<u8>, spend_key: Vec<u8>) -> Vec<Vess> {
        let diff = MINING_DIFFICULTY; // reward = 1 Vess at threshold
        let reward = block_reward(diff);
        let mut coinbase_outputs = Vec::new();
        if reward > 0 {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: reward, owner_hash,
                timestamp: 0, nonce: 0, salt: random_bytes(), pubkey, spend_key, proof: vec![], spend_condition: None });
        }
        coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: dev_reward(reward), owner_hash: DEV_PUBKEY_HASH,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: vec![], spend_key: vec![], proof: vec![], spend_condition: None });
        // Persist coinbase to treasure chest (mined_keys) for wallet import
        for v in &coinbase_outputs {
            if let Ok(mut w) = self.env.write_txn() {
                let _ = self.mined_keys.put(&mut w, &v.vess_id(), &v.encode());
                let _ = w.commit();
            }
        }
        let mut coinbase = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: coinbase_outputs.clone(), timestamp: 0, sigs: vec![], preimages: vec![] };
        coinbase.compute();

        // Collect clean payments from limbo
        let clean: Vec<VessPayment> = self.limbo.iter()
            .filter(|(pid, _)| !self.contested.contains(*pid))
            .map(|(_, (p, _))| p.clone())
            .filter(|p| !p.is_mint()) // no mints in block body
            .collect();

        let mut all_payments: Vec<VessPayment> = vec![coinbase.clone()];
        for p in &clean { all_payments.push(p.clone()); }
        let state_merkle = self.compute_state_merkle(&all_payments);
        let mut all_ids: Vec<VessId> = all_payments.iter().map(|p| p.payment_id).collect();
        all_ids.sort(); all_ids.dedup();
        let block = VessBlock {
            version: 1, parents: self.tip_hashes.clone(),
            timestamp: 0, difficulty_bits: diff, nonce: 0,
            payment_merkle: merkle_root(&all_ids), state_merkle,
            coinbase, payments: clean,
        };
        self.pending_blocks.push(block.clone());
        self.process_block(&block);
        coinbase_outputs
    }

    /// Try to mine a block. Production only (test_mode uses test_mine).
    pub fn try_mine(&mut self) -> Option<VessBlock> {
        let clean: Vec<VessPayment> = self.limbo.iter()
            .filter(|(pid, _)| !self.contested.contains(*pid))
            .map(|(_, (p, _))| p.clone())
            .filter(|p| self.verify(p))
            .collect();
        // Don't mine until we're connected to at least one peer — blocks
        // can't propagate otherwise, so mining in isolation is wasted work.
        if self.peer_count() == 0 { return None; }

        // Mine when limbo has payments, or periodically for coinbase-only blocks
        let has_work = !clean.is_empty() || !self.contested.is_empty();
        let periodic = self.ticks % 4000 == 0; // ~20s between empty-block attempts
        if !has_work && !periodic { return None; }

        let diff = self.current_difficulty;
        let reward = block_reward(diff);
        let (pk, sk) = dsa_generate();
        let miner_oh = dsa_pubkey_hash(&pk);
        let mut coinbase_outputs = Vec::new();
        if reward > 0 {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: reward, owner_hash: miner_oh,
                timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: pk.as_bytes().to_vec(), spend_key: sk.as_bytes().to_vec(), proof: vec![], spend_condition: None });
        }
        let dev_share = dev_reward(reward);
        if dev_share > 0 {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: dev_share, owner_hash: DEV_PUBKEY_HASH,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: vec![], spend_key: vec![], proof: vec![], spend_condition: None });
        }
        // Always include at least one output to carry the Cuckatoo proof
        if coinbase_outputs.is_empty() {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: 0, owner_hash: DEV_PUBKEY_HASH,
            timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: vec![], spend_key: vec![], proof: vec![], spend_condition: None });
        }
        // Persist coinbase Vess objects to treasure chest
        for v in &coinbase_outputs {
            if let Ok(mut w) = self.env.write_txn() {
                let _ = self.mined_keys.put(&mut w, &v.vess_id(), &v.encode());
                let _ = w.commit();
            }
        }
        let mut coinbase = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: coinbase_outputs, timestamp: 0, sigs: vec![], preimages: vec![] };
        coinbase.compute();

        // Build the full payment set that will be applied, then compute state merkle
        let mut all_payments: Vec<VessPayment> = vec![coinbase.clone()];
        for p in &clean { all_payments.push(p.clone()); }
        let state_merkle = self.compute_state_merkle(&all_payments);

        let mut all_ids: Vec<VessId> = vec![coinbase.payment_id];
        for p in &clean { all_ids.push(p.payment_id); }
        for pid in &self.contested { if let Some((p, _)) = self.limbo.get(pid) { all_ids.push(p.payment_id); } }
        all_ids.sort(); all_ids.dedup();

        let block = VessBlock {
            version: 1, parents: self.tip_hashes.clone(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
            difficulty_bits: diff, nonce: 0,
            payment_merkle: merkle_root(&all_ids), state_merkle,
            coinbase, payments: clean,
        };

        // Cuckatoo27 mine: header hash → solve 42-cycle → hash proof → check difficulty
        let mut b = block;
        // Cuckatoo27 PoW always required (rewards may or may not emit)
        let (target_nonce, cuckoo_proof) = {
            let mut nonce = 0u64;
            loop {
                let mut bh = b.clone(); bh.nonce = nonce;
                let header_hash = bh.header_hash();
                if let Some(proof) = cuckoo::solve(&header_hash, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
                    let pow_hash = cuckoo::proof_to_id(&proof);
                    if check_difficulty(&pow_hash, diff) {
                        break (nonce, proof);
                    }
                }
                nonce = nonce.wrapping_add(1);
            }
        };
        b.nonce = target_nonce;
        if let Some(miner_out) = b.coinbase.outputs.get_mut(0) {
            miner_out.proof = cuckoo_proof;
        }
        self.pending_blocks.push(b.clone());
        self.process_block(&b);

        let block_hash = b.header_hash();
        let hex4: String = block_hash[..4].iter().map(|b| format!("{:02x}", b)).collect();
        eprintln!("BLOCK mined id={} reward={}+{}dev diff={}", hex4, reward, dev_share, diff);
        Some(b)
    }

    /// Find conflicting payment indices in a set of payments (direct + daisy-chain).
    fn find_conflicts(payments: &[VessPayment]) -> HashSet<usize> {
        let mut conflicted: HashSet<usize> = HashSet::new();
        let mut input_owners: HashMap<VessId, Vec<usize>> = HashMap::new();
        for (i, p) in payments.iter().enumerate() {
            for v in &p.inputs { input_owners.entry(v.vess_id()).or_default().push(i); }
        }
        for owners in input_owners.values() {
            if owners.len() >= 2 { for &i in owners { conflicted.insert(i); } }
        }
        loop {
            let mut changed = false;
            let clean_outputs: HashSet<VessId> = payments.iter().enumerate()
                .filter(|(i, _)| !conflicted.contains(i))
                .flat_map(|(_, p)| p.outputs.iter().map(|v| v.vess_id()))
                .collect();
            for (i, p) in payments.iter().enumerate() {
                if conflicted.contains(&i) { continue; }
                for v in &p.inputs {
                    if clean_outputs.contains(&v.vess_id()) {
                        for (j, cp) in payments.iter().enumerate() {
                            if cp.outputs.iter().any(|o| o.vess_id() == v.vess_id()) { conflicted.insert(j); }
                        }
                        conflicted.insert(i);
                        changed = true;
                    }
                }
            }
            if !changed { break; }
        }
        conflicted
    }

    /// Process a mined/received block. Returns false if our state merkle
    /// didn't match the block's claim (we're missing UTXO entries — sync needed).
    pub fn process_block(&mut self, block: &VessBlock) -> bool {
        // Verify Cuckatoo27 PoW (skip in test mode)
        if !self.test_mode {
            let proof = block.coinbase.outputs.first()
                .map(|v| &v.proof)
                .filter(|p| !p.is_empty());
            if let Some(p) = proof {
                let header_hash = block.header_hash();
                if !cuckoo::verify(&header_hash, p, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
                    return false;
                }
                let pow_hash = cuckoo::proof_to_id(p);
                if !check_difficulty(&pow_hash, block.difficulty_bits) {
                    return false;
                }
            } else {
                return false; // No Cuckatoo proof in coinbase
            }
        }

        // Collect all payments (coinbase + block payments), verify each
        let mut all_payments: Vec<VessPayment> = vec![block.coinbase.clone()];
        for p in &block.payments {
            if self.verify(p) { all_payments.push(p.clone()); }
        }

        // Detect intra-block conflicts: direct + daisy-chain
        let conflicted = Self::find_conflicts(&all_payments);

        // Apply payments to LMDB unconditionally — PoW is the consensus rule.
        // state_merkle is a miner claim, not a validity condition. A wrong
        // state_merkle means the miner was buggy, but the block is still valid.
        if let Ok(mut w) = self.env.write_txn() {
            for (i, p) in all_payments.iter().enumerate() {
                if conflicted.contains(&i) {
                    for inp in &p.inputs { let _ = self.vess_index.delete(&mut w, &inp.vess_id()); }
                    for out in &p.outputs { let _ = self.vess_index.delete(&mut w, &out.vess_id()); }
                } else {
                    for inp in &p.inputs { let _ = self.vess_index.delete(&mut w, &inp.vess_id()); }
                    for out in &p.outputs { let _ = self.vess_index.put(&mut w, &out.vess_id(), &()); }
                }
            }
            if w.commit().is_err() {
                // LMDB commit failed (disk full, etc.) — leave limbo intact, retry later
                return false;
            }
        } else {
            return false;
        }

        // Remove all processed payments from limbo
        for p in &all_payments {
            self.limbo.remove(&p.payment_id);
            for v in &p.inputs { self.limbo_inputs.remove(&v.vess_id()); }
            self.contested.remove(&p.payment_id);
        }

        // Store block, update tips
        let block_hash = block.header_hash();
        self.blocks.insert(block_hash, block.clone());
        self.tip_hashes.retain(|h| !block.parents.contains(h));
        self.tip_hashes.push(block_hash);
        if self.current_tip.is_none() { self.current_tip = Some(block_hash); }
        self.reorg_if_needed();
        self.prune_blocks();

        // DAA: adjust difficulty every DIFFICULTY_WINDOW blocks
        if self.blocks.len() >= DIFFICULTY_WINDOW {
            let mut times: Vec<u64> = self.blocks.values().map(|b| b.timestamp).collect();
            times.sort();
            let deltas: Vec<u64> = times.windows(2).map(|w| w[1].saturating_sub(w[0])).collect();
            let recent: Vec<u64> = deltas.iter().rev().take(DIFFICULTY_WINDOW).copied().collect();
            self.current_difficulty = adjust_difficulty(self.current_difficulty, &recent, 1000);
        }

        self.save_meta();

        // Compare our post-application merkle against the block's claim.
        // Self-mined blocks use [0u8;32] → always "match" (miner trusts itself).
        if block.state_merkle == [0u8; 32] { return true; }
        self.merkle() == block.state_merkle
    }

    /// Cumulative work of a block's ancestor chain (sum of 2^difficulty_bits).
    pub fn cumulative_work(&self, hash: &BlockHash) -> u64 {
        let mut work = 0u64;
        let mut current = *hash;
        let mut visited = HashSet::new();
        loop {
            if visited.contains(&current) { break; }
            visited.insert(current);
            if let Some(b) = self.blocks.get(&current) {
                work = work.saturating_add(1u64 << b.difficulty_bits as u64);
                if let Some(parent) = b.parents.first() {
                    current = *parent;
                } else { break; }
            } else { break; }
        }
        work
    }

    /// The tip with the most cumulative work — defines canonical state.
    fn heaviest_tip(&self) -> Option<BlockHash> {
        self.tip_hashes.iter()
            .map(|h| (*h, self.cumulative_work(h)))
            .max_by_key(|(_, w)| *w)
            .map(|(h, _)| h)
    }

    fn prune_blocks(&mut self) {
        if self.blocks.len() <= 40 { return; }
        let Some(tip) = self.heaviest_tip() else { return; };
        // Walk back from heaviest tip, keep ancestors, drop the rest
        let mut keep = HashSet::new();
        let mut current = tip;
        loop {
            keep.insert(current);
            if let Some(b) = self.blocks.get(&current) {
                if let Some(parent) = b.parents.first() {
                    current = *parent;
                } else { break; }
            } else { break; }
        }
        self.blocks.retain(|h, _| keep.contains(h));
        self.tip_hashes.retain(|h| keep.contains(h));
    }

    /// If the heaviest chain disagrees with our LMDB state, rebuild from common ancestor.
    fn reorg_if_needed(&mut self) {
        let Some(heaviest) = self.heaviest_tip() else { return };
        if self.current_tip == Some(heaviest) { return; }

        // Find common ancestor
        let mut old_set: HashSet<BlockHash> = HashSet::new();
        let mut cur = self.current_tip;
        while let Some(h) = cur {
            old_set.insert(h);
            cur = self.blocks.get(&h).and_then(|b| b.parents.first().copied());
        }
        let mut common = heaviest;
        loop {
            if old_set.contains(&common) { break; }
            common = match self.blocks.get(&common).and_then(|b| b.parents.first().copied()) {
                Some(p) => p, None => { common = heaviest; break; }
            };
        }

        // Reverse old blocks back to common ancestor
        cur = self.current_tip;
        while let Some(h) = cur {
            if h == common { break; }
            let block = self.blocks.get(&h).cloned();
            if let Some(ref b) = block { self.reverse_block(b); }
            cur = block.as_ref().and_then(|b| b.parents.first().copied());
        }

        // Apply new blocks from common ancestor to heaviest
        let mut to_apply = Vec::new();
        cur = Some(heaviest);
        while let Some(h) = cur {
            if h == common { break; }
            to_apply.push(h);
            cur = self.blocks.get(&h).and_then(|b| b.parents.first().copied());
        }
        for h in to_apply.iter().rev() {
            let block = self.blocks.get(h).cloned();
            if let Some(ref b) = block { self.apply_block_state(b); }
        }

        self.current_tip = Some(heaviest);
        self.save_meta();
    }

    fn reverse_block(&mut self, block: &VessBlock) {
        if let Ok(mut w) = self.env.write_txn() {
            for p in block.payments.iter().chain(std::iter::once(&block.coinbase)) {
                for v in &p.inputs { let _ = self.vess_index.put(&mut w, &v.vess_id(), &()); }
                for v in &p.outputs { let _ = self.vess_index.delete(&mut w, &v.vess_id()); }
            }
            let _ = w.commit();
        }
    }

    fn apply_block_state(&mut self, block: &VessBlock) {
        if let Ok(mut w) = self.env.write_txn() {
            for p in block.payments.iter().chain(std::iter::once(&block.coinbase)) {
                for v in &p.inputs { let _ = self.vess_index.delete(&mut w, &v.vess_id()); }
                for v in &p.outputs { let _ = self.vess_index.put(&mut w, &v.vess_id(), &()); }
            }
            let _ = w.commit();
        }
    }

    // ---- cycle ----

    pub fn cycle(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        self.ticks = self.ticks.wrapping_add(1);
        // Reset per-second rate limiter every ~1s (200 ticks at 5ms)
        if self.ticks.saturating_sub(self.msg_window_start) >= 200 {
            self.peer_msg_count.clear();
            self.msg_window_start = self.ticks;
        }
        self.drain_embargo();
        if self.ticks % 2000 == 0 { self.gossip_roots(); } // ~10s, not every tick

        // ---- NAT traversal ----
        // Every 40 ticks (~200ms), if behind NAT, try to punch through
        if self.ticks % 40 == 0 && self.is_behind_nat() {
            self.nat_cycle();
        }
        // Drain stem relay queue through introducer (rate-limited)
        if !self.relay_queue.is_empty() && self.ticks % 20 == 0 {
            if let Some(intro) = self.introducer {
                let to_send: Vec<_> = self.relay_queue.drain(..STEM_RELAY_MAX_PER_TICK).collect();
                for (target_id, data) in to_send {
                    self.send(intro, &GossipMessage::StemRelay(target_id, data));
                }
            }
        }

        // Broadcast any pending blocks (self-mined or received) to peers
        let pending: Vec<VessBlock> = self.pending_blocks.drain(..).collect();
        for block in pending {
            let m = GossipMessage::Block(block);
            let addrs: Vec<SocketAddr> = self.peers.iter().filter(|(_,id)| **id != [0u8;32]).map(|(a,_)| *a).collect();
            for a in addrs { self.send(a, &m); }
        }
        // Try to mine a block if there are payments in limbo
        if self.mining && self.ticks % 20 == 0 { let _ = self.try_mine(); }
        if self.ticks % 100 == 0 { self.peer_announce(); } // ~0.5s
        if self.ticks % 60 == 0 { self.ping_all(); }       // ~0.3s
        if self.ticks % 30 == 0 { self.reap(); }
        if (self.needs_sync && self.ticks % 50 == 0) || (self.auto_sync_until > self.ticks && self.ticks % 50 == 0) { self.drive_sync(); }
        std::mem::take(&mut self.outbox)
    }

    /// NAT traversal tick: select introducer, retry hole punches, clean up.
    fn nat_cycle(&mut self) {
        // Ensure we have an introducer
        if self.introducer.is_none() {
            self.select_introducer();
        }
        // Collect hole-punch work (avoid borrow conflicts)
        let mut punch_tasks: Vec<(SocketAddr, u32, SocketAddr)> = Vec::new(); // (target, nonce, observed)
        let mut completed: Vec<NodeId> = Vec::new();
        for (peer_id, info) in &mut self.introduced_peers {
            if info.retries >= HOLE_PUNCH_MAX_RETRIES {
                completed.push(*peer_id);
                continue;
            }
            let has_session = self.network.session_by_addr(&info.observed_addr)
                .map(|s| s.node_id == Some(*peer_id))
                .unwrap_or(false);
            if has_session {
                completed.push(*peer_id);
            } else {
                let nonce = rand::thread_rng().gen();
                info.punch_nonce = nonce;
                info.retries += 1;
                punch_tasks.push((info.observed_addr, nonce, info.observed_addr));
            }
        }
        for pid in completed {
            self.introduced_peers.remove(&pid);
        }
        // Execute hole punches and handshake attempts
        for (observed, _nonce, addr) in punch_tasks {
            self.send_hole_punch(observed, _nonce);
            self.try_punch_handshake(addr);
        }
    }

    // ---- verify, merkle ----

    fn verify(&self, p: &VessPayment) -> bool {
        // Async minting is disabled — only block coinbases create new coins
        if p.is_mint() { return false; }
        if p.inputs.is_empty() || p.outputs.is_empty() || p.inputs.len() > MAX_INPUTS || p.outputs.len() > MAX_OUTPUTS { return false; }
        if p.input_sum() != p.output_sum() { return false; }
        if p.sigs.len() != p.inputs.len() { return false; }
        for (i, v) in p.inputs.iter().enumerate() {
            if !self.check(&v.vess_id()) { return false; }

            // Signature is always required
            if let Ok(pk) = dilithium3::PublicKey::from_bytes(&v.pubkey) {
                if !dsa_verify(&pk, &p.payment_id, &p.sigs[i]) { return false; }
            } else { return false; }

            // Spend condition: additional gates on top of signature
            if let Some(ref cond) = v.spend_condition {
                // Hashlock: must provide correct preimage (if set)
                if cond.hashlock != [0u8; 32] {
                    let preimage_ok = i < p.preimages.len()
                        && p.preimages[i].is_some()
                        && blake3_hash(&p.preimages[i].unwrap()) == cond.hashlock;
                    if !preimage_ok { return false; }
                }
                // Expiry: output expires, can't spend after (if set)
                if cond.expires_at > 0 {
                    let expired = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() >= cond.expires_at)
                        .unwrap_or(false);
                    if expired { return false; }
                }
            }
        }
        true
    }

    pub fn merkle(&self) -> MerkleRoot {
        let t = match self.env.read_txn() { Ok(t) => t, Err(_) => return [0u8; 32] };
        let iter = self.vess_index.iter(&t).unwrap().filter_map(|r| r.ok().map(|(k,_)| {
            let mut a = [0u8; 32]; a.copy_from_slice(&k); a
        }));
        // LMDB B-tree iterates in byte order → streaming merkle, O(log N) RAM
        merkle_root_stream(iter)
    }

    /// Returns (ticks, merkle_root) that a quorum of peers agree on.
    /// Requires ≥2 peers to agree — never trusts a single peer.
    fn consensus_merkle(&self) -> Option<(u64, MerkleRoot)> {
        let roots: Vec<(u64, MerkleRoot)> = self.peer_merkle.values().copied().collect();
        if roots.len() < 2 { return None; }
        // Count votes for each (ticks, root) pair; need ≥2 matching
        let mut counts: HashMap<(u64, MerkleRoot), usize> = HashMap::new();
        for &r in &roots { *counts.entry(r).or_insert(0) += 1; }
        counts.into_iter().find(|&(_, c)| c >= 2).map(|(r, _)| r)
    }

    // ---- gossip, relay ----

    fn gossip_roots(&mut self) {
        let r = self.merkle();
        let m = GossipMessage::Root(self.ticks, r);
        let addrs: Vec<SocketAddr> = self.peers.iter().filter(|(_,id)| **id != [0u8;32]).map(|(a,_)| *a).collect();
        for a in addrs { self.send(a, &m); }
    }

    fn strike(&mut self, addr: SocketAddr) {
        *self.fails.entry(addr).or_insert(0) += 1;
    }

    pub fn process(&mut self, addr: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
        // Reject banned peers immediately
        if self.fails.get(&addr).copied().unwrap_or(0) > 5 { return None; }
        // Reject oversize frames (DoS protection)
        if data.len() > MAX_FRAME_SIZE { self.strike(addr); return None; }
        if data.len() < 5 { return None; }  // minimum: tag(1) + len(4)
        let (tag, mut payload) = match unframe(data) { Some(v) => v, None => { self.strike(addr); return None; } };
        if tag == HANDSHAKE_INIT || tag == HANDSHAKE_RESP {
            // Verify PoW handshake puzzle on INIT
            if tag == HANDSHAKE_INIT {
                let proof_len = 32 + cuckoo::HANDSHAKE_CYCLE_LENGTH * 4;
                if payload.len() < proof_len { self.strike(addr); return None; }
                let split = payload.len() - proof_len;
                let pow_bytes = &payload[split..];
                let pow_header: [u8; 32] = pow_bytes[..32].try_into().unwrap();
                let mut proof = Vec::with_capacity(cuckoo::HANDSHAKE_CYCLE_LENGTH);
                for i in 0..cuckoo::HANDSHAKE_CYCLE_LENGTH {
                    proof.push(u32::from_le_bytes(pow_bytes[32+i*4..32+(i+1)*4].try_into().unwrap()));
                }
                if !cuckoo::verify(&pow_header, &proof, cuckoo::HANDSHAKE_CYCLE_LENGTH, cuckoo::HANDSHAKE_EDGE_BITS) {
                    self.strike(addr);
                    return None;
                }
                payload = &payload[..split];
            }
            let resp = self.network.handle_handshake(addr, tag, payload);
            if let Some(s) = self.network.session_by_addr(&addr) {
                if s.node_id.is_some() {
                    self.peers.insert(addr, s.node_id.unwrap());
                    self.persist_peer(addr);
                }
            }
            return resp;
        }
        // HolePunch is a raw frame — no encryption session required
        if tag == TAG_HOLE_PUNCH {
            if payload.len() >= 4 {
                let nonce = u32::from_le_bytes(payload[..4].try_into().unwrap());
                self.route(addr, &GossipMessage::HolePunch(nonce).encode());
            }
            return None;
        }
        // Rate limit: max 50 messages/sec per peer. Silently drop excess.
        let count = self.peer_msg_count.get(&addr).copied().unwrap_or(0);
        if count >= 50 {
            return None;
        }
        self.peer_msg_count.insert(addr, count + 1);

        let s = match self.network.session_by_addr_mut(&addr) { Some(s) => s, None => { self.strike(addr); return None; } };
        let plain = match s.decrypt(payload) { Some(p) => p, None => { self.strike(addr); return None; } };
        self.route(addr, &plain)
    }

    pub fn route(&mut self, addr: SocketAddr, plain: &[u8]) -> Option<Vec<u8>> {
        let (tag, payload) = match unframe(plain) { Some(v) => v, None => { self.strike(addr); return None; } };
        if (0x10..=0x19).contains(&tag) {
            let r = match self.rpc(tag, payload) { Some(r) => r, None => { self.strike(addr); return None; } };
            let s = match self.network.session_by_addr_mut(&addr) { Some(s) => s, None => { self.strike(addr); return None; } };
            return Some(s.encrypt(&r));
        }
        let m = match GossipMessage::decode(tag, payload) {
            Some(m) => m,
            None => { self.strike(addr); return None; }
        };
        match &m {
            GossipMessage::Payment(p) => {
                if !self.submit(p.clone()) {
                    *self.fails.entry(addr).or_insert(0) += 1;
                }
            }
            GossipMessage::Block(block) => {
                let matched = self.process_block(block);
                self.pending_blocks.push(block.clone());
                // Immediately relay
                let m = GossipMessage::Block(block.clone());
                let addrs: Vec<SocketAddr> = self.peers.iter().filter(|(_,id)| **id != [0u8;32]).map(|(a,_)| *a).collect();
                for a in addrs { self.send(a, &m); }
                // If our state merkle didn't match the block's claim, request sync
                if !matched {
                    self.send(addr, &GossipMessage::StateSyncReq(self.ticks, 1000));
                }
            }
            GossipMessage::Root(peer_ticks, peer_root) => {
                self.peer_merkle.insert(addr, (*peer_ticks, *peer_root));
                if let Some((consensus_ticks, consensus_root)) = self.consensus_merkle() {
                    if consensus_ticks > self.ticks.saturating_add(5) {
                        self.send(addr, &GossipMessage::StateSyncReq(self.ticks, 1000));
                    }
                    if self.needs_sync && self.merkle() == consensus_root {
                        self.needs_sync = false;
                    }
                }
            }
            GossipMessage::PeerAnnounce(pid, a) => {
                // Store the peer's self-reported address for NAT detection
                if let Some(s) = self.network.session_by_addr_mut(&addr) {
                    s.reported_addr = Some(*a);
                }
                // NAT self-detection: if someone announces OUR NodeId with a
                // different address, that address is our public face.
                if *pid == self.network.my_node_id() && *a != self.addr {
                    self.nat_type = NatType::BehindNat;
                    // The announced address is our public mapping — use it
                    // in future PeerAnnounce messages.
                }
                if self.peer_count() < self.max_peers { self.peers.entry(*a).or_insert([0u8;32]); }
            }
            GossipMessage::Ping(n) => { self.send(addr, &GossipMessage::Pong(*n)); }
            GossipMessage::StateSyncReq(s, c) => { self.sync_chunk(addr, *s, *c); }
            GossipMessage::StateSyncChunk(start, ids) => {
                self.handle_sync_chunk(addr, *start, ids);
            }
            // ---- NAT traversal messages ----
            GossipMessage::IntroduceRequest(target_id) => {
                // We're acting as introducer: tell the target about the requester.
                // The requester is the peer at `addr`.
                if let Some(requester_id) = self.network.session_by_addr(&addr).and_then(|s| s.node_id) {
                    self.send_introduce_to(*target_id, requester_id, addr);
                }
            }
            GossipMessage::Introduce(peer_id, observed_addr) => {
                // Introducer tells us: "peer_id is reachable at observed_addr"
                self.introduced_peers.insert(*peer_id, IntroducedPeer {
                    observed_addr: *observed_addr, punch_nonce: 0, retries: 0,
                });
                // Immediately send a hole-punch packet and try handshake
                let nonce = rand::thread_rng().gen();
                self.send_hole_punch(*observed_addr, nonce);
                self.try_punch_handshake(*observed_addr);
                if let Some(ip) = &mut self.introduced_peers.get_mut(peer_id) {
                    ip.punch_nonce = nonce;
                    ip.retries = 1;
                }
            }
            GossipMessage::HolePunch(nonce) => {
                // Someone is trying to punch through to us.
                // Initiate handshake if we don't have a session.
                if !self.has_session_for(&addr) {
                    self.try_punch_handshake(addr);
                }
                // Echo back with incremented nonce so the sender knows the hole is open
                self.send_hole_punch(addr, nonce.wrapping_add(1));
            }
            GossipMessage::StemRelay(target_id, data) => {
                if *target_id == self.network.my_node_id() {
                    // This relay is for us — process the inner gossip message
                    self.route(addr, data);
                } else if self.is_public() {
                    // We're the introducer — forward to target if we know them
                    let target_addr = self.peers.iter()
                        .find(|(_, id)| **id == *target_id)
                        .map(|(a, _)| *a);
                    if let Some(ta) = target_addr {
                        let m = GossipMessage::StemRelay(*target_id, data.clone());
                        self.send(ta, &m);
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn rpc(&mut self, tag: u8, payload: &[u8]) -> Option<Vec<u8>> {
        let req = RpcRequest::decode(tag, payload)?;
        Some(match req {
            RpcRequest::Check(id) => RpcResponse::Check(self.check(&id)),
            RpcRequest::Submit(p) => RpcResponse::Submit(self.submit(p)),
            RpcRequest::GetPeers => RpcResponse::GetPeers(self.get_peers()),
            RpcRequest::ConnectPeer(addr) => {
                let init = self.add_peer(addr);
                let ok = !init.is_empty();
                if ok {
                    self.outbox.push((addr, init));
                }
                RpcResponse::ConnectPeer(ok)
            }
        }.encode())
    }

    fn relay(&mut self, p: &VessPayment) {
        let h = self.stems.get(&p.payment_id).copied().unwrap_or(0);
        // Stem phase: forward to exactly 1 random peer
        let peers: Vec<SocketAddr> = self.peers.iter().filter(|(_,id)| **id != [0u8;32]).map(|(a,_)| *a).collect();
        if peers.is_empty() { return; }

        let transition = h >= DANDELION_MAX_STEM || rand::thread_rng().gen_bool(DANDELION_FLUFF_PROB);
        if transition {
            // Enter embargo: delay before broadcasting to all peers
            self.stems.remove(&p.payment_id);
            self.fluff_embargo.insert(p.payment_id, (p.clone(), self.ticks));
        } else {
            // Stay in stem: forward to two random peers for redundancy
            self.stems.insert(p.payment_id, h + 1);
            let i1 = rand::thread_rng().gen_range(0..peers.len());
            self.send(peers[i1], &GossipMessage::Payment(p.clone()));
            if peers.len() >= 2 {
                let mut i2 = rand::thread_rng().gen_range(0..peers.len());
                if i2 == i1 { i2 = (i1 + 1) % peers.len(); }
                self.send(peers[i2], &GossipMessage::Payment(p.clone()));
            }
        }
    }

    pub fn drain_embargo(&mut self) {
        let ready: Vec<PaymentId> = self.fluff_embargo.iter()
            .filter(|(_, (_, t))| self.ticks.saturating_sub(*t) >= DANDELION_EMBARGO_TICKS)
            .map(|(pid, _)| *pid)
            .collect();
        for pid in ready {
            if let Some((p, _)) = self.fluff_embargo.remove(&pid) {
                let m = GossipMessage::Payment(p);
                let addrs: Vec<SocketAddr> = self.peers.iter().filter(|(_,id)| **id != [0u8;32]).map(|(a,_)| *a).collect();
                for a in addrs { self.send(a, &m); }
            }
        }
    }

    pub fn send(&mut self, addr: SocketAddr, msg: &GossipMessage) {
        if let Some(s) = self.network.session_by_addr_mut(&addr) {
            self.outbox.push((addr, frame(ENCRYPTED_DATA, &s.encrypt(&msg.encode()))));
        } else if self.is_behind_nat() && self.introducer.is_some() {
            // No direct session — relay through introducer (stem relay fallback)
            if let Some(target_id) = self.peers.get(&addr).copied() {
                if target_id != [0u8; 32] {
                    self.relay_through_introducer(target_id, msg.encode());
                }
            }
        }
    }

    fn sync_chunk(&mut self, addr: SocketAddr, start: u64, count: u32) {
        let ids: Vec<VessId> = {
            let t = match self.env.read_txn() { Ok(t) => t, Err(_) => return };
            self.vess_index.iter(&t).unwrap().filter_map(|r| r.ok().map(|(k,_)| { let mut a=[0u8;32]; a.copy_from_slice(&k); a })).skip(start as usize).take(count as usize).collect()
        };
        self.send(addr, &GossipMessage::StateSyncChunk(start, ids));
    }

    /// Periodically drive state sync when needs_sync is true.
    fn drive_sync(&mut self) {
        // If no sync peer yet, pick the one with the highest ticks from peer_merkle
        if self.sync_peer.is_none() {
            let best = self.peer_merkle.iter()
                .filter(|(addr, _)| self.has_session_for(addr))
                .max_by_key(|(_, (ticks, _))| *ticks)
                .map(|(addr, (_, root))| (*addr, *root));
            if let Some((addr, root)) = best {
                self.sync_peer = Some(addr);
                self.sync_target_root = Some(root);
                self.sync_offset = 0;
                self.send(addr, &GossipMessage::StateSyncReq(0, self.sync_chunk_size));
            }
            return;
        }

        let peer = match self.sync_peer {
            Some(p) => p,
            None => return,
        };

        // If we've matched target merkle, we're done
        if let Some(target) = self.sync_target_root {
            if self.merkle() == target {
                self.needs_sync = false;
                self.sync_peer = None;
                self.sync_target_root = None;
                self.sync_offset = 0;
                return;
            }
        }

        // If peer disconnected, reset and pick a new one next cycle
        if !self.has_session_for(&peer) {
            self.sync_peer = None;
            self.sync_target_root = None;
            self.sync_offset = 0;
            return;
        }

        // Request the next chunk (progress is tracked by handle_sync_chunk)
        self.send(peer, &GossipMessage::StateSyncReq(self.sync_offset, self.sync_chunk_size));
    }

    /// Process an incoming StateSyncChunk from a peer.
    fn handle_sync_chunk(&mut self, addr: SocketAddr, start: u64, ids: &[VessId]) {
        let is_from_sync_peer = self.sync_peer == Some(addr);

        if !ids.is_empty() {
            // Insert only UTXO IDs we don't already have (idempotent)
            if let Ok(mut w) = self.env.write_txn() {
                let rt = self.env.read_txn().unwrap();
                for id in ids {
                    if self.vess_index.get(&rt, id).unwrap().is_none() {
                        let _ = self.vess_index.put(&mut w, id, &());
                    }
                }
                drop(rt);
                let _ = w.commit();
            }

            if is_from_sync_peer {
                self.sync_offset = start.saturating_add(ids.len() as u64);
            }

            self.save_meta();
        }

        // If chunk is smaller than requested, we've reached the end of the peer's UTXO set
        if (ids.len() as u32) < self.sync_chunk_size {
            if is_from_sync_peer {
                // Check if our merkle now matches target
                if let Some(target) = self.sync_target_root {
                    if self.merkle() == target {
                        self.needs_sync = false;
                        self.sync_peer = None;
                        self.sync_target_root = None;
                        self.sync_offset = 0;
                        return;
                    }
                }
                // Didn't match — restart sync from beginning (peer may have new state)
                self.sync_offset = 0;
            } else {
                // Unsolicited chunk from non-sync peer: if it was a response to a
                // block-triggered request, check if we're caught up now.
                if let Some(&(_, expected_root)) = self.peer_merkle.get(&addr) {
                    if self.merkle() != expected_root {
                        // Still behind — request more from this peer
                        let next_start = start.saturating_add(ids.len() as u64);
                        self.send(addr, &GossipMessage::StateSyncReq(next_start, self.sync_chunk_size));
                    }
                }
            }
        }
    }

    fn peer_announce(&mut self) {
        let m = GossipMessage::PeerAnnounce(self.my_node_id(), self.addr);
        let addrs: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for a in addrs { self.send(a, &m); }
    }

    fn ping_all(&mut self) {
        let m = GossipMessage::Ping(self.ticks as u32);
        let addrs: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for a in addrs { self.send(a, &m); }
    }

    fn reap(&mut self) {
        // Auto-ban peers with >5 rejected payments. Persist bans to LMDB.
        let to_ban: Vec<SocketAddr> = self.peers.iter()
            .filter(|(a, _)| self.fails.get(a).copied().unwrap_or(0) > 5)
            .map(|(a, _)| *a)
            .collect();

        for a in to_ban {
            self.peers.remove(&a);
            // Persist ban: key = port_bytes + ip_bytes
            let mut key = a.port().to_le_bytes().to_vec();
            match a.ip() {
                std::net::IpAddr::V4(ip) => key.extend_from_slice(&ip.octets()),
                std::net::IpAddr::V6(ip) => key.extend_from_slice(&ip.octets()),
            }
            if let Ok(mut w) = self.env.write_txn() {
                let _ = self.ban_list.put(&mut w, &key, &());
                let _ = w.commit();
            }
        }
        if self.ticks % 300 == 0 { self.fails.clear(); }
    }
}
