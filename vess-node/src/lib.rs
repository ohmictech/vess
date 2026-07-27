use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use rand::Rng;
use vess_crypto::*;
use vess_network::*;
use vess_network::data_packets::{self, PacketReassembler};

const DANDELION_MAX_STEM: u8 = 4;
const DANDELION_FLUFF_PROB: f64 = 0.10; // 10% chance per hop to switch to fluff
const DANDELION_EMBARGO_TICKS: u64 = 40; // ~200ms embargo before fluff broadcast
const HOLE_PUNCH_MAX_RETRIES: u8 = 3;
const STEM_RELAY_MAX_PER_TICK: usize = 2;
const MAX_FRAME_SIZE: usize = data_packets::MAX_MESSAGE_SIZE;
/// Maximum encoded block size.  Blocks exceeding this are rejected at
/// validation (can't enter the DAG) and skipped during prepare_block.
const MAX_BLOCK_BYTES: usize = 768 * 1024;  // 768 KB
const MAX_FUTURE_BLOCK_TIME_MS: u64 = 120_000;
const MAX_LIMBO_PAYMENTS: usize = 10_000;
const LIMBO_TTL_TICKS: u64 = 12_000;
const MAX_REASSEMBLY_PEERS: usize = 32;
const MAX_RELIABLE_MESSAGES: usize = 32;
const MAX_RELIABLE_BYTES: usize = 4 * 1024 * 1024;
const RETRANSMIT_TICKS: u64 = 200;
const MAX_RETRANSMITS: u8 = 5;
const COMPLETED_PACKET_TTL_TICKS: u64 = 6000;
const MAX_COMPLETED_PACKETS_PER_PEER: usize = 256;
const MAX_PARENTS: usize = 8;

struct ReliableMessage {
    addr: SocketAddr,
    packets: Vec<Vec<u8>>,
    last_sent: u64,
    retries: u8,
}

/// A handshake message (INIT or RESP) being retried until the session is
/// established or the retry budget is exhausted.
struct PendingHandshake {
    packets: Vec<Vec<u8>>,
    last_sent: u64,
    retries: u8,
}

pub const HANDSHAKE_RETRANSMIT_TICKS: u64 = 200; // ~1 s
pub const MAX_HANDSHAKE_RETRANSMITS: u8 = 10;    // 10 retries ≈ 10 s

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
    banned_ips: HashSet<std::net::IpAddr>,              // per-IP bans (survives port changes)
    meta: heed::Database<heed::types::Str, heed::types::Bytes>,
    mined_keys: heed::Database<heed::types::Bytes, heed::types::Bytes>, // owner_hash → pubkey||spend_key
    peers_db: heed::Database<heed::types::Bytes, heed::types::Unit>,   // persisted peer addresses
    blocks_db: heed::Database<heed::types::Bytes, heed::types::Bytes>, // block_hash → encoded block
    undo_db: heed::Database<heed::types::Bytes, heed::types::Bytes>,   // block_hash → encode(removed_ids, inserted_ids)
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
    peer_merkle: HashMap<SocketAddr, (u64, MerkleRoot, u32)>,  // height, root, difficulty_bits
    blocks: HashMap<BlockHash, VessBlock>,    // recent blocks by hash
    block_work: HashMap<BlockHash, u64>,       // cached cumulative work per block
    pub tip_hashes: Vec<BlockHash>,               // DAG tips for parent selection
    current_tip: Option<BlockHash>,           // tip our LMDB state corresponds to
    pub mining_cores: u32,                     // 0 = off, 1+ = mining with that many threads
    last_mine_tick: u64,                       // last tick we attempted mining (for periodic spacing)
    pub current_difficulty: u32,               // adjusts via DAA every DIFFICULTY_WINDOW blocks
    pub pending_blocks: Vec<(VessBlock, Option<SocketAddr>)>,  // (block, origin_sender_or_None_if_local)
    pub accepted_blocks: u64,                       // increments on every accepted block (mined or received)
    block_seen: HashSet<BlockHash>,                 // deduplicate block relay
    /// Per-peer round-trip time in ticks, updated from Ping/Pong.
    peer_rtt: HashMap<SocketAddr, u64>,
    orphans: HashMap<BlockHash, VessBlock>,          // blocks waiting for missing parents
    missing_parents: HashMap<BlockHash, Vec<BlockHash>>, // parent → children waiting for it
    // State sync buffer: accumulate chunks here, verify root, then commit.
    sync_buffer: HashSet<VessId>,
    // NAT traversal
    pub nat_type: NatType,                      // our reachability classification
    pub introducer: Option<SocketAddr>,         // public peer helping us punch through
    pub introduced_peers: HashMap<NodeId, IntroducedPeer>, // peers we're hole-punching toward
    relay_queue: Vec<(NodeId, Vec<u8>)>,        // StemRelay fallback queue (target_id, gossip_bytes)
    packet_reassembly: HashMap<SocketAddr, PacketReassembler>,
    reliable_messages: HashMap<data_packets::MessageId, ReliableMessage>,
    completed_packets: HashMap<SocketAddr, Vec<(data_packets::MessageId, u64)>>,
    // Handshake retry: keyed by peer address so a re-init replaces the old entry.
    pending_handshakes: HashMap<SocketAddr, PendingHandshake>,
    // Peers discovered via GetPeers exchange — paced connection queue.
    discovered_peers: Vec<SocketAddr>,
    // Discovered peers that need PoW solving — drained by main.rs outside
    // the node lock so the 1-3s cuckatoo solve doesn't stall the main loop.
    pub pending_discovered: Vec<SocketAddr>,
    // State sync
    sync_peer: Option<SocketAddr>,               // peer we're syncing UTXOs from
    sync_offset: u64,                             // how many UTXO IDs received so far
    sync_target_root: Option<MerkleRoot>,         // target merkle root we're aiming for
    sync_chunk_size: u32,                         // IDs per SyncReq chunk
    auto_sync_until: u64,                         // keep driving sync until this tick
    pub test_mode: bool,
    /// When true, mined blocks include the dev subsidy output.  Off by
    /// default — only the node operator with the dev key should enable it.
    pub dev_mode: bool,
    // Finality: the deepest-anchored block that cannot be reorged.
    finalized_tip: Option<BlockHash>,
    fin_work: u64,                                // cumulative work at finalized_tip (base for block_work)
    fin_root: MerkleRoot,                         // state merkle at finalized_tip
}

impl Node {
    pub fn new(addr: SocketAddr) -> Self { Self::new_inner(addr, "vess-db", false) }
    pub fn new_test(addr: SocketAddr) -> Self { Self::new_inner(addr, "vess-db", true) }
    #[doc(hidden)]
    pub fn new_test_at(addr: SocketAddr, db_path: &str) -> Self { Self::new_inner(addr, db_path, true) }

    fn new_inner(addr: SocketAddr, db_path: &str, test_mode: bool) -> Self {
        let _ = std::fs::create_dir(db_path);
        let env = unsafe { heed::EnvOpenOptions::new().map_size(1_073_741_824).max_dbs(7).open(db_path) }.unwrap();
        let mut wtxn = env.write_txn().unwrap();
        let db: heed::Database<heed::types::Bytes, heed::types::Unit> = env.create_database(&mut wtxn, Some("vess")).unwrap();
        let ban_list: heed::Database<heed::types::Bytes, heed::types::Unit> = env.create_database(&mut wtxn, Some("bans")).unwrap();
        let meta: heed::Database<heed::types::Str, heed::types::Bytes> = env.create_database(&mut wtxn, Some("meta")).unwrap();
        let mined_keys: heed::Database<heed::types::Bytes, heed::types::Bytes> = env.create_database(&mut wtxn, Some("keys")).unwrap();
        let peers_db: heed::Database<heed::types::Bytes, heed::types::Unit> = env.create_database(&mut wtxn, Some("peers")).unwrap();
        let blocks_db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env.create_database(&mut wtxn, Some("blocks")).unwrap();
        let undo_db: heed::Database<heed::types::Bytes, heed::types::Bytes> = env.create_database(&mut wtxn, Some("undo")).unwrap();
        wtxn.commit().unwrap();

        let (saved_ticks, saved_diff, saved_tip, saved_fin_tip, saved_fin_work, saved_fin_root) = Self::load_meta(&env, &meta);
        let saved_height = Self::load_accepted_blocks(&env, &meta);
        let mut node = Self { addr, network: Network::new(), peers: HashMap::new(), max_peers: 16, needs_sync: true, env, vess_index: db, ban_list, banned_ips: HashSet::new(), meta, mined_keys, peers_db,
            blocks_db, undo_db, limbo: HashMap::new(), limbo_inputs: HashMap::new(), contested: HashSet::new(),
            outbox: Vec::new(), ticks: saved_ticks, fails: HashMap::new(),
            peer_msg_count: HashMap::new(), msg_window_start: 0, peer_merkle: HashMap::new(),
            stems: HashMap::new(), fluff_embargo: HashMap::new(),
            blocks: HashMap::new(), tip_hashes: Vec::new(), current_tip: None, mining_cores: 0,
            block_work: HashMap::new(),
            last_mine_tick: 0,
            current_difficulty: saved_diff,
            pending_blocks: Vec::new(),
            accepted_blocks: saved_height,
            block_seen: HashSet::new(),
            peer_rtt: HashMap::new(),
            orphans: HashMap::new(),
            missing_parents: HashMap::new(),
            sync_buffer: HashSet::new(),
            nat_type: NatType::Unknown,
            introducer: None,
            introduced_peers: HashMap::new(),
            relay_queue: Vec::new(),
            packet_reassembly: HashMap::new(),
            reliable_messages: HashMap::new(),
            completed_packets: HashMap::new(),
            pending_handshakes: HashMap::new(),
            discovered_peers: Vec::new(),
            pending_discovered: Vec::new(),
            sync_peer: None,
            sync_offset: 0,
            sync_target_root: None,
            sync_chunk_size: 10_000,
            auto_sync_until: 0,
            test_mode,
            finalized_tip: saved_fin_tip,
            fin_work: saved_fin_work,
            fin_root: saved_fin_root,
            dev_mode: false,
        };
        // Recover the block graph before serving or mining. The UTXO index is
        // rebuilt from its canonical tip below, rather than trusted directly.
        if let Ok(t) = node.env.read_txn() {
            if let Ok(iter) = blocks_db.iter(&t) {
                for entry in iter.flatten() {
                    let (hash, bytes) = entry;
                    let Ok(hash) = <[u8; 32]>::try_from(hash) else { continue; };
                    let mut pos = 0;
                    if let Some(block) = VessBlock::decode(bytes, &mut pos) {
                        if pos == bytes.len() && block.header_hash() == hash {
                            node.blocks.insert(hash, block);
                        }
                    }
                }
            }
        }
        node.tip_hashes = node.blocks.iter()
            .filter(|(hash, _)| !node.blocks.values().any(|other| other.parents.contains(hash)))
            .map(|(hash, _)| *hash)
            .collect();
        // Rebuild cumulative work cache using the max-over-parents GHOST-lite
        // rule (matching what process_block computes on acceptance).
        // Must use topological order so parents are always cached before
        // children — timestamp sort can invert this when parent/child have
        // equal timestamps (allowed: ts >= parent) and HashMap iteration
        // order is non-deterministic.
        let order = node.ancestor_order(&node.tip_hashes).unwrap_or_else(|| {
            // Fallback: sort by timestamp (rare, only if DAG has cycles).
            let mut v: Vec<(BlockHash, VessBlock)> = node.blocks.iter()
                .map(|(h, b)| (*h, b.clone())).collect();
            v.sort_by_key(|(_, b)| b.timestamp);
            v.into_iter().map(|(h, _)| h).collect()
        });
        // Seed block_work from the finalized tip's persisted work value.
        if let Some(ft) = node.finalized_tip {
            node.block_work.insert(ft, node.fin_work);
        }
        for hash in &order {
            if let Some(block) = node.blocks.get(hash) {
                // Skip if already seeded from finalized_tip
                if node.block_work.contains_key(hash) { continue; }
                let parent_max = block.parents.iter()
                    .filter_map(|p| node.block_work.get(p))
                    .max().unwrap_or(&0);
                node.block_work.insert(*hash,
                    parent_max.saturating_add(1u64 << block.difficulty_bits as u64));
            }
        }
        // Set current_tip from saved meta — LMDB state already matches it.
        // No full replay needed; the undo log handles in-window reorgs.
        node.current_tip = saved_tip;
        // Sanity-check: if we have a tip, the live merkle should match
        // the block's own state_merkle commitment.
        if node.current_tip.is_some() && node.utxo_count() > 0 {
            let live_root = node.merkle();
            let expected = node.current_tip
                .and_then(|tip| node.blocks.get(&tip))
                .map(|b| b.state_merkle)
                .unwrap_or([0u8; 32]);
            if expected != [0u8; 32] && live_root != expected
                && live_root != [0u8; 32]
            {
                eprintln!("WARNING: live UTXO merkle mismatch — triggering sync");
                node.needs_sync = true;
            }
        }
        // Load persisted bans — key = ip bytes (4 or 16), no port.
        if let Ok(t) = node.env.read_txn() {
            if let Ok(iter) = node.ban_list.iter(&t) {
                for entry in iter {
                    if let Ok((key, _)) = entry {
                        let ip: Option<std::net::IpAddr> = if key.len() == 4 {
                            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(key[0], key[1], key[2], key[3])))
                        } else if key.len() == 16 {
                            let mut octets = [0u8; 16]; octets.copy_from_slice(key);
                            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
                        } else if key.len() >= 6 {
                            // Legacy: port_le(2) + ip
                            if key.len() >= 6 {
                                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(key[2], key[3], key[4], key[5])))
                            } else { None }
                        } else { None };
                        if let Some(ip) = ip { node.banned_ips.insert(ip); }
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

    fn load_meta(env: &heed::Env, meta: &heed::Database<heed::types::Str, heed::types::Bytes>) -> (u64, u32, Option<BlockHash>, Option<BlockHash>, u64, MerkleRoot) {
        let t = match env.read_txn() { Ok(t) => t, Err(_) => return (0, DIFFICULTY_BASE_BITS, None, None, 0, [0u8; 32]) };
        let ticks = meta.get(&t, "ticks").ok().flatten().and_then(|b| if b.len()>=8 { Some(u64::from_le_bytes(b[..8].try_into().unwrap())) } else { None }).unwrap_or(0);
        let diff = meta.get(&t, "diff").ok().flatten().and_then(|b| if b.len()>=4 { Some(u32::from_le_bytes(b[..4].try_into().unwrap())) } else { None }).unwrap_or(DIFFICULTY_BASE_BITS);
        let tip = meta.get(&t, "tip").ok().flatten().and_then(|b| if b.len()==32 { let mut a=[0u8;32]; a.copy_from_slice(b); Some(a) } else { None });
        let fin_tip = meta.get(&t, "fin_tip").ok().flatten().and_then(|b| if b.len()==32 { let mut a=[0u8;32]; a.copy_from_slice(b); Some(a) } else { None });
        let fin_work = meta.get(&t, "fin_work").ok().flatten().and_then(|b| if b.len()>=8 { Some(u64::from_le_bytes(b[..8].try_into().unwrap())) } else { None }).unwrap_or(0);
        let fin_root = meta.get(&t, "fin_root").ok().flatten().and_then(|b| if b.len()==32 { let mut a=[0u8;32]; a.copy_from_slice(b); Some(a) } else { None }).unwrap_or([0u8; 32]);
        (ticks, diff, tip, fin_tip, fin_work, fin_root)
    }

    fn load_accepted_blocks(env: &heed::Env, meta: &heed::Database<heed::types::Str, heed::types::Bytes>) -> u64 {
        let t = match env.read_txn() { Ok(t) => t, Err(_) => return 0 };
        meta.get(&t, "height").ok().flatten().and_then(|b| if b.len()>=8 { Some(u64::from_le_bytes(b[..8].try_into().unwrap())) } else { None }).unwrap_or(0)
    }

    fn save_meta(&self) {
        if let Ok(mut w) = self.env.write_txn() {
            let _ = self.meta.put(&mut w, "ticks", &self.ticks.to_le_bytes());
            let _ = self.meta.put(&mut w, "diff", &self.current_difficulty.to_le_bytes());
            let _ = self.meta.put(&mut w, "height", &self.accepted_blocks.to_le_bytes());
            if let Some(tip) = self.current_tip { let _ = self.meta.put(&mut w, "tip", &tip); }
            if let Some(ft) = self.finalized_tip { let _ = self.meta.put(&mut w, "fin_tip", &ft); }
            let _ = self.meta.put(&mut w, "fin_work", &self.fin_work.to_le_bytes());
            let _ = self.meta.put(&mut w, "fin_root", &self.fin_root);
            let _ = w.commit();
        }
    }

    /// Encode an undo record: 4-byte count of removed ids, then each 32-byte id,
    /// then 4-byte count of inserted ids, then each 32-byte id.
    fn encode_undo(removed: &HashSet<VessId>, inserted: &HashSet<VessId>) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + (removed.len() + inserted.len()) * 32);
        v.extend_from_slice(&(removed.len() as u32).to_le_bytes());
        for id in removed { v.extend_from_slice(id); }
        v.extend_from_slice(&(inserted.len() as u32).to_le_bytes());
        for id in inserted { v.extend_from_slice(id); }
        v
    }

    /// Decode an undo record → (removed, inserted).
    fn decode_undo(data: &[u8]) -> Option<(HashSet<VessId>, HashSet<VessId>)> {
        if data.len() < 8 { return None; }
        let r_count = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
        let mut pos = 4;
        if data.len() < pos + r_count * 32 + 4 { return None; }
        let mut removed = HashSet::with_capacity(r_count);
        for _ in 0..r_count {
            let mut id = [0u8; 32]; id.copy_from_slice(&data[pos..pos+32]); pos += 32;
            removed.insert(id);
        }
        let i_count = u32::from_le_bytes(data[pos..pos+4].try_into().ok()?) as usize; pos += 4;
        if data.len() < pos + i_count * 32 { return None; }
        let mut inserted = HashSet::with_capacity(i_count);
        for _ in 0..i_count {
            let mut id = [0u8; 32]; id.copy_from_slice(&data[pos..pos+32]); pos += 32;
            inserted.insert(id);
        }
        Some((removed, inserted))
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
    pub fn reliable_message_count(&self) -> usize { self.reliable_messages.len() }
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
            // Hole-punched handshakes use the full INIT with sig + PoW.
            // The PoW is lightweight (6-cycle, 14-bit edges) and prevents
            // the same INIT-spoofing attack that the sig fixes.
            let raw = self.network.build_handshake_init(addr);
            let (tag, payload) = unframe(&raw).unwrap_or((HANDSHAKE_INIT, &[][..]));
            let base = blake3_hash(&[b"vess-handshake" as &[u8], &self.network.my_node_id()].concat());
            let mut header = base;
            let proof = loop {
                if let Some(p) = cuckoo::solve(&header, cuckoo::HANDSHAKE_CYCLE_LENGTH, cuckoo::HANDSHAKE_EDGE_BITS) {
                    break (header, p);
                }
                header = blake3_hash(&header);
            };
            let mut payload_full = payload.to_vec();
            let sig_input = blake3_hash_multi(&[b"vess-hs-init", &self.network.dsa_pk, &self.network.kem_pk]);
            let init_sig = dsa_sign(&self.network.dsa_sk, &sig_input)
                .expect("DSA signing must not fail");
            write_bytes(&mut payload_full, &init_sig);
            payload_full.extend_from_slice(&proof.0);
            for n in &proof.1 { payload_full.extend_from_slice(&n.to_le_bytes()); }
            self.send_handshake(addr, frame(tag, &payload_full));
        }
    }

    /// Manually establish a session with a known key (for testing).
    #[doc(hidden)]
    pub fn inject_session(&mut self, addr: SocketAddr, node_id: NodeId, key: [u8; 32]) {
        if self.network.session_by_addr(&addr).is_none() {
            self.network.sessions.push(vess_network::Session {
                addr, node_id: Some(node_id), out_key: key, in_key: key, peer_version: PROTOCOL_VERSION,
                reported_addr: Some(addr), nonce_ctr: 0, proven_rx: true, // test-only: skip rx proof
                created_at: self.network.ticks,
            });
        }
        self.peers.insert(addr, node_id);
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
    /// Solve handshake PoW and send INIT.  Holds the lock for 1-3s while
    /// solving cuckatoo-14; prefer `add_peer_with_pow` when PoW is
    /// pre-solved outside the lock (e.g. from pending_discovered).
    pub fn add_peer(&mut self, a: SocketAddr) -> usize {
        if self.peer_count() >= self.max_peers { return 0; }
        let base = blake3_hash(&[b"vess-handshake" as &[u8], &self.network.my_node_id()].concat());
        let (proof_header, proof_cycles) = {
            let mut hdr = base;
            loop {
                if let Some(p) = cuckoo::solve(&hdr, cuckoo::HANDSHAKE_CYCLE_LENGTH, cuckoo::HANDSHAKE_EDGE_BITS) {
                    break (hdr, p);
                }
                hdr = blake3_hash(&hdr);
            }
        };
        self.add_peer_with_pow(a, proof_header, proof_cycles)
    }

    /// Send handshake INIT with a pre-solved PoW (header + cycles).
    /// Returns the framed message length, or 0 if at capacity.
    pub fn add_peer_with_pow(&mut self, a: SocketAddr, proof_header: [u8; 32], proof_cycles: Vec<u32>) -> usize {
        if self.peer_count() >= self.max_peers { return 0; }
        let raw = self.network.build_handshake_init(a);
        let (tag, payload) = unframe(&raw).unwrap_or((HANDSHAKE_INIT, &[][..]));
        let mut payload_with_pow = payload.to_vec();
        let sig_input = blake3_hash_multi(&[b"vess-hs-init", &self.network.dsa_pk, &self.network.kem_pk]);
        let init_sig = dsa_sign(&self.network.dsa_sk, &sig_input)
            .expect("DSA signing must not fail");
        write_bytes(&mut payload_with_pow, &init_sig);
        payload_with_pow.extend_from_slice(&proof_header);
        for n in &proof_cycles { payload_with_pow.extend_from_slice(&n.to_le_bytes()); }
        let framed = frame(tag, &payload_with_pow);
        let len = framed.len();
        self.send_handshake(a, framed);
        len
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
    /// Returns the number of handshakes initiated; the actual datagrams
    /// are queued in the outbox.
    pub fn reconnect_peers(&mut self) -> usize {
        let unconnected: Vec<std::net::SocketAddr> = self.peers.iter()
            .filter(|(a, id)| {
                **id == [0u8; 32] &&               // not yet handshaked
                *a != &self.addr &&                 // not ourselves
                !self.has_session_for(a)            // no active session
            })
            .map(|(a, _)| *a)
            .collect();
        let mut count = 0usize;
        for addr in unconnected {
            if self.peer_count() >= self.max_peers { break; }
            let len = self.add_peer(addr);
            if len > 0 { count += 1; }
        }
        count
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

    // ---- submit ----

    pub fn submit(&mut self, p: VessPayment) -> bool {
        self.evict_limbo();
        // Don't accept payments while catching up; isolated nodes are always "synced"
        if self.needs_sync && self.peer_count() > 0 { return false; }
        if self.limbo.len() >= MAX_LIMBO_PAYMENTS { return false; }
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

    fn evict_limbo(&mut self) {
        let expired: HashSet<PaymentId> = self.limbo.iter()
            .filter(|(_, (_, entered))| self.ticks.saturating_sub(*entered) >= LIMBO_TTL_TICKS)
            .map(|(id, _)| *id)
            .collect();
        if expired.is_empty() { return; }
        self.limbo.retain(|id, _| !expired.contains(id));
        self.contested.retain(|id| !expired.contains(id));
        for claims in self.limbo_inputs.values_mut() {
            claims.retain(|id| !expired.contains(id));
        }
        self.limbo_inputs.retain(|_, claims| !claims.is_empty());
    }

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

    /// Compute what the state merkle WILL be after applying payments on top
    /// of the merged state of `parents`. This is fork-aware: during a fork
    /// the candidate's parents may differ from the current heaviest tip, so
    /// we compute from the merged parent state rather than the live DB.
    fn compute_state_merkle(&self, parents: &[BlockHash], all_payments: &[VessPayment]) -> MerkleRoot {
        let mut state = self.state_for_roots(parents).unwrap_or_default();
        let conflicted = Self::find_conflicts(all_payments);
        // Clean payments first (same application order as validate_block).
        for (i, p) in all_payments.iter().enumerate() {
            if conflicted.contains(&i) { continue; }
            for inp in &p.inputs { state.remove(&inp.vess_id()); }
            for out in &p.outputs { state.insert(out.vess_id()); }
        }
        // Conflicted payments: inputs burn, no outputs created.
        for (i, p) in all_payments.iter().enumerate() {
            if !conflicted.contains(&i) { continue; }
            for inp in &p.inputs { state.remove(&inp.vess_id()); }
        }
        Self::state_root(&state)
    }

    /// Test helper: mine a block with coinbase to the given owner. Returns coinbase outputs.
    pub fn test_mine(&mut self, owner_hash: OwnerHash, pubkey: Vec<u8>, spend_key: Vec<u8>) -> Vec<Vess> {
        let diff = MINING_DIFFICULTY; // reward = 1 Vess at threshold
        let reward = block_reward(diff);
        let mint_timestamp = self.blocks.len() as u64 + 1;
        let mut coinbase_outputs = Vec::new();
        if reward > 0 {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: reward, owner_hash,
                timestamp: mint_timestamp, nonce: 0, salt: random_bytes(), pubkey, spend_key, spend_condition: None });
        }
        coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: dev_reward(reward), owner_hash: DEV_PUBKEY_HASH,
            timestamp: mint_timestamp, nonce: 0, salt: random_bytes(), pubkey: vec![], spend_key: vec![], spend_condition: None });
        // Treasure chest: stores miner seeds in LMDB for wallet import.
        // Dev outputs exist in the block for consensus but are only saved
        // locally when --dev is on.
        for v in &coinbase_outputs {
            if v.owner_hash == DEV_PUBKEY_HASH && !self.dev_mode { continue; }
            if let Ok(mut w) = self.env.write_txn() {
                let _ = self.mined_keys.put(&mut w, &v.vess_id(), &v.encode_with_secrets());
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
        let parents = self.block_parents();
        let state_merkle = self.compute_state_merkle(&parents, &all_payments);
        let mut all_ids: Vec<VessId> = all_payments.iter().map(|p| p.payment_id).collect();
        all_ids.sort(); all_ids.dedup();
        let block = VessBlock {
            version: 1, parents,
            timestamp: 0, difficulty_bits: diff, nonce: 0,
            payment_merkle: merkle_root(&all_ids), state_merkle,
            proof: vec![0u32; cuckoo::CYCLE_LENGTH], // test mode skips PoW verification
            coinbase, payments: clean,
        };
        self.pending_blocks.push((block.clone(), None));
        self.process_block(&block);
        coinbase_outputs
    }

    /// Prepare a block candidate (fast — reads state, no PoW). Returns None if no work.
    pub fn prepare_block(&mut self) -> Option<VessBlock> {
        // Collect candidate payments — verify already rejects outputs that
        // collide with UTXO state, but we also need to guard against
        // cross-payment collisions within the block.
        let candidates: Vec<VessPayment> = self.limbo.iter()
            .filter(|(pid, _)| !self.contested.contains(*pid))
            .map(|(_, (p, _))| p.clone())
            .filter(|p| self.verify(p))
            .collect();

        let has_work = !candidates.is_empty() || !self.contested.is_empty();
        let genesis = self.blocks.is_empty();
        let periodic = self.ticks.saturating_sub(self.last_mine_tick) >= 60;
        if !has_work && !genesis && !periodic { return None; }
        self.last_mine_tick = self.ticks;

        let diff = self.current_difficulty;
        let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as u64;
        let reward = block_reward(diff);
        let (pk, sk) = dsa_generate();
        let miner_oh = dsa_pubkey_hash(&pk);
        let mut coinbase_outputs = Vec::new();
        if reward > 0 {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: reward, owner_hash: miner_oh,
                timestamp, nonce: 0, salt: random_bytes(), pubkey: pk.clone(), spend_key: sk.clone(), spend_condition: None });
        }
        let dev_share = dev_reward(reward);
        if dev_share > 0 {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: dev_share, owner_hash: DEV_PUBKEY_HASH,
            timestamp, nonce: 0, salt: random_bytes(), pubkey: vec![], spend_key: vec![], spend_condition: None });
        }
        if coinbase_outputs.is_empty() {
            coinbase_outputs.push(Vess { variant: VessVariant::Mint, amount: 0, owner_hash: miner_oh,
            timestamp, nonce: 0, salt: random_bytes(), pubkey: pk.clone(), spend_key: sk.clone(), spend_condition: None });
        }
        // Track output IDs to prevent cross-payment collisions.
        let mut block_output_ids: HashSet<VessId> = coinbase_outputs.iter()
            .map(|v| v.vess_id()).collect();
        // Treasure chest: stores miner seeds for wallet import.
        // Dev outputs exist in the block for consensus but are only saved
        // locally when --dev is on (the operator holds the dev key).
        for v in &coinbase_outputs {
            if v.owner_hash == DEV_PUBKEY_HASH && !self.dev_mode { continue; }
            if let Ok(mut w) = self.env.write_txn() {
                let _ = self.mined_keys.put(&mut w, &v.vess_id(), &v.encode_with_secrets());
                let _ = w.commit();
            }
        }
        let mut coinbase = VessPayment { payment_id: [0u8;32], inputs: vec![], outputs: coinbase_outputs, timestamp: 0, sigs: vec![], preimages: vec![] };
        coinbase.compute();

        // Filter: drop payments whose output IDs collide with the coinbase
        // or with a previously-selected payment.
        let mut clean = Vec::new();
        for p in candidates {
            let outputs_ok = p.outputs.iter().all(|v| block_output_ids.insert(v.vess_id()));
            if outputs_ok {
                clean.push(p);
            }
        }

        // Contested payments go into the block body so the burn is committed
        // in both payment_merkle and state_merkle. Each is individually validated;
        // conflicting inputs burn deterministically, no outputs are created.
        let contested_payments: Vec<VessPayment> = self.contested.iter()
            .filter_map(|pid| self.limbo.get(pid).map(|(p, _)| p.clone()))
            .collect();

        // Select payments up to the block byte cap, skipping (not truncating!)
        // individual fat payments so a single 27KB monster doesn't underfill
        // the block — smaller payments still get in after it.
        let coinbase_encoded = coinbase.encode();
        let header_overhead = 256; // version + parents + timestamp + diff + nonce + merkle + proof (estimate)
        let mut size = coinbase_encoded.len().saturating_add(header_overhead);
        let mut sized_payments = Vec::new();
        for p in clean {
            let p_len = p.encode().len();
            if size.saturating_add(p_len) > MAX_BLOCK_BYTES { continue; }
            size = size.saturating_add(p_len);
            sized_payments.push(p);
        }
        // Add contested payments (burns) — they're small and must be committed.
        for p in contested_payments {
            let p_len = p.encode().len();
            if size.saturating_add(p_len) > MAX_BLOCK_BYTES { break; }
            size = size.saturating_add(p_len);
            sized_payments.push(p);
        }
        let mut all_ids: Vec<VessId> = vec![coinbase.payment_id];
        for p in &sized_payments { all_ids.push(p.payment_id); }
        all_ids.sort(); all_ids.dedup();

        // Hard cap at 200 payments as a safety backstop for the byte-size loop.
        if sized_payments.len() > 200 {
            sized_payments.truncate(200);
            all_ids.clear();
            all_ids.push(coinbase.payment_id);
            for p in &sized_payments { all_ids.push(p.payment_id); }
            all_ids.sort(); all_ids.dedup();
        }

        Some(VessBlock {
            version: 1, parents: self.block_parents(),
            timestamp,
            difficulty_bits: diff, nonce: 0,
            payment_merkle: merkle_root(&all_ids), state_merkle: [0u8; 32],
            proof: Vec::new(), // filled in by apply_mined_block once PoW is found
            coinbase, payments: sized_payments,
        })
    }

    /// Apply a mined block (fast — called from main loop when mining thread finishes).
    pub fn apply_mined_block(&mut self, mut block: VessBlock, nonce: u64, proof: Vec<u32>) {
        block.nonce = nonce;
        block.proof = proof;
        // Recompute state_merkle with the finalized block
        let mut all_payments: Vec<VessPayment> = vec![block.coinbase.clone()];
        for p in &block.payments { all_payments.push(p.clone()); }
        block.state_merkle = self.compute_state_merkle(&block.parents, &all_payments);

        let reward = block_reward(block.difficulty_bits);
        let dev_share = dev_reward(reward);
        self.pending_blocks.push((block.clone(), None));
        self.process_block(&block);

        let block_hash = block.header_hash();
        let hex4: String = block_hash[..4].iter().map(|b| format!("{:02x}", b)).collect();
        eprintln!("BLOCK mined id={} reward={}+{}dev diff={}", hex4, reward, dev_share, block.difficulty_bits);
    }

    /// Run the Cuckatoo27 PoW on a block candidate (slow — meant for background thread).
    /// `start_nonce` and `step` partition the nonce space across threads.
    /// Returns None if cancelled before finding a solution.
    pub fn mine_pow(block: &VessBlock, start_nonce: u64, step: u64, cancel: &std::sync::atomic::AtomicBool, counter: &std::sync::atomic::AtomicU64) -> Option<(u64, Vec<u32>)> {
        let diff = block.difficulty_bits;
        // Difficulty 0: blake3-only mining, no Cuckatoo solver. Any nonce
        // passes check_difficulty, so return immediately with a dummy proof.
        if diff == 0 {
            let mut bh = block.clone(); bh.nonce = start_nonce;
            if check_difficulty(&bh.header_hash(), diff) {
                return Some((start_nonce, vec![0u32; cuckoo::CYCLE_LENGTH]));
            }
            // Fallback: increment nonce (should never hit this — diff 0 always passes).
            let mut nonce = start_nonce.wrapping_add(step);
            loop {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) { return None; }
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut bh = block.clone(); bh.nonce = nonce;
                if check_difficulty(&bh.header_hash(), diff) {
                    return Some((nonce, vec![0u32; cuckoo::CYCLE_LENGTH]));
                }
                nonce = nonce.wrapping_add(step);
            }
        }
        let mut nonce = start_nonce;
        loop {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) { return None; }
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut bh = block.clone(); bh.nonce = nonce;
            let header_hash = bh.header_hash();
            if let Some(proof) = cuckoo::solve(&header_hash, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
                let pow_hash = cuckoo::proof_to_id(&proof);
                if check_difficulty(&pow_hash, diff) {
                    return Some((nonce, proof));
                }
            }
            nonce = nonce.wrapping_add(step);
        }
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
        // No propagation needed: chained spends are invalid by consensus (all
        // inputs must reference pre-block state), so a payment spending a
        // conflicted payment's output is rejected at the existence check —
        // conflicts are always direct, shared pre-state inputs.
        conflicted
    }

    /// Process a mined/received block. Returns false if our state merkle
    /// doesn't match the deterministic state transition.
    pub fn process_block(&mut self, block: &VessBlock) -> bool {
        let block_hash = block.header_hash();
        // A block may be received through multiple gossip paths. Never apply a
        // known block twice: state mutation must be idempotent.
        if self.blocks.contains_key(&block_hash) { return true; }

        // Orphan handling: if any parent is unknown, store the block and fetch
        // the missing parents. When all parents arrive, the orphan is retried.
        // Skip this gate when the node has no blocks at all — a state-synced
        // node has a verified UTXO set but zero history; new blocks must
        // validate against LMDB directly (state_for_roots fallback).
        let mut missing = false;
        if !self.blocks.is_empty() {
            for parent_hash in &block.parents {
                if !self.blocks.contains_key(parent_hash) {
                    missing = true;
                    self.missing_parents.entry(*parent_hash).or_default().push(block_hash);
                }
            }
        }
        if missing {
            if self.orphans.len() < 256 {
                self.orphans.insert(block_hash, block.clone());
            }
            return false;
        }

        // Finality reject rule: a block whose ancestors don't include the
        // finalized tip diverges before finality and cannot be validated
        // (pre-finality history is pruned).  Skipped in test mode — test
        // chains are shorter than FINALITY_DEPTH.
        if !self.test_mode {
            if let Some(ft) = self.finalized_tip {
                let mut reaches_finality = false;
                let mut visited = HashSet::new();
                let mut stack: Vec<BlockHash> = block.parents.clone();
                while let Some(h) = stack.pop() {
                    if h == ft { reaches_finality = true; break; }
                    if !visited.insert(h) { continue; }
                    if visited.len() > FINALITY_DEPTH { break; }
                    if let Some(b) = self.blocks.get(&h) {
                        for p in &b.parents { stack.push(*p); }
                    }
                }
                if !reaches_finality { return false; }
            }
        }

        // Gate difficulty bounds before any expensive verification.
        if block.difficulty_bits > 32 { return false; }

        // Cuckatoo27 PoW is required at difficulty ≥ 1. Difficulty 0 blocks
        // skip the solver entirely — blake3 header_hash is the only work.
        // This lets the network boot on commodity hardware; memory-hard PoW
        // kicks in as difficulty ramps up. Test mode skips all PoW.
        if !self.test_mode && block.difficulty_bits > 0 {
            if block.proof.len() != cuckoo::CYCLE_LENGTH { return false; }
            let header_hash = block.header_hash();
            if !cuckoo::verify(&header_hash, &block.proof, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
                return false;
            }
            let pow_hash = cuckoo::proof_to_id(&block.proof);
            if !check_difficulty(&pow_hash, block.difficulty_bits) {
                return false;
            }
        }

        let state = match self.validate_block(block) {
            Some(state) => state,
            None => return false,
        };
        // A non-zero state root is always a consensus commitment. Test helpers
        // may use zero while constructing synthetic blocks.
        if (!self.test_mode || block.state_merkle != [0u8; 32])
            && Self::state_root(&state) != block.state_merkle {
            return false;
        }

        // Remove all processed payments from limbo. Burns are handled
        // deterministically inside validate_block via the state transition —
        // annihilate no longer touches LMDB directly.
        for p in block.payments.iter().chain(std::iter::once(&block.coinbase)) {
            self.limbo.remove(&p.payment_id);
            for v in &p.inputs { self.limbo_inputs.remove(&v.vess_id()); }
            self.contested.remove(&p.payment_id);
        }

        // Store block, update tips
        self.blocks.insert(block_hash, block.clone());
        // Cache cumulative work — avoids O(history) DAG walk on every call.
        let work = block.parents.iter()
            .filter_map(|p| self.block_work.get(p))
            .max().unwrap_or(&0)
            .saturating_add(1u64 << block.difficulty_bits as u64);
        self.block_work.insert(block_hash, work);
        if let Ok(mut w) = self.env.write_txn() {
            if self.blocks_db.put(&mut w, &block_hash, &block.encode()).is_err() || w.commit().is_err() {
                self.blocks.remove(&block_hash);
                return false;
            }
        } else {
            self.blocks.remove(&block_hash);
            return false;
        }
        self.tip_hashes.retain(|h| !block.parents.contains(h));
        self.tip_hashes.push(block_hash);
        // Only commit state to LMDB when this block is the heaviest tip.
        // Accepting a lighter fork would revert the UTXO view to a
        // non-canonical branch — every flap rewrites the full UTXO set.
        // Non-heaviest valid blocks stay in the DAG; a child that makes
        // them heaviest triggers the commit via reorg_if_needed later.
        let is_heaviest = self.heaviest_tip() == Some(block_hash);
        if is_heaviest {
            if let Ok(mut w) = self.env.write_txn() {
                // Compute the delta: which IDs are removed/inserted relative
                // to the current live LMDB state.
                let existing: HashSet<VessId> = self.vess_index.iter(&w).ok().into_iter().flatten()
                    .filter_map(|entry| entry.ok())
                    .filter_map(|(id, _)| id.try_into().ok())
                    .collect();
                let removed: HashSet<VessId> = existing.difference(&state).copied().collect();
                let inserted: HashSet<VessId> = state.difference(&existing).copied().collect();
                // Apply the delta incrementally.
                for id in &removed { let _ = self.vess_index.delete(&mut w, id); }
                for id in &inserted { let _ = self.vess_index.put(&mut w, id, &()); }
                // Persist the undo record for in-window reorgs.
                let _ = self.undo_db.put(&mut w, &block_hash, &Self::encode_undo(&removed, &inserted));
                if w.commit().is_ok() {
                    self.current_tip = Some(block_hash);
                    self.accepted_blocks = self.accepted_blocks.saturating_add(1);
                    self.save_meta();
                }
            }
            // Advance finality and prune old history.
            self.advance_finality();
        }
        self.save_meta();

        // Resolve orphans: any block waiting for THIS block as its parent
        let canonical = self.canonical_chain(self.current_tip);
        if canonical.len() >= DIFFICULTY_WINDOW && canonical.len().is_multiple_of(DIFFICULTY_WINDOW) {
            let recent: Vec<u64> = canonical.windows(2)
                .rev()
                .take(DIFFICULTY_WINDOW - 1)
                .filter_map(|pair| {
                    let older = self.blocks.get(&pair[0])?;
                    let newer = self.blocks.get(&pair[1])?;
                    Some(newer.timestamp.saturating_sub(older.timestamp))
                })
                .collect();
            self.current_difficulty = adjust_difficulty(self.current_difficulty, &recent, 1000);
        }

        self.save_meta();

        // Resolve orphans: any block waiting for THIS block as its parent
        // can now be retried.
        if let Some(waiting) = self.missing_parents.remove(&block_hash) {
            for child_hash in waiting {
                if let Some(child) = self.orphans.remove(&child_hash) {
                    self.process_block(&child);
                }
            }
        }

        true
    }

    fn canonical_chain(&self, tip: Option<BlockHash>) -> Vec<BlockHash> {
        let mut chain = Vec::new();
        let mut current = tip;
        let mut seen = HashSet::new();
        while let Some(hash) = current {
            if !seen.insert(hash) { return Vec::new(); }
            chain.push(hash);
            current = self.blocks.get(&hash).and_then(|b| b.parents.first().copied());
        }
        chain.reverse();
        chain
    }

    /// Returns indices into `block.payments` that are intra-block conflicted
    /// (direct double-spend or daisy-chain). Coinbase (index 0 in the internal
    /// list) is excluded — it has no inputs so can never be conflicted.
    fn block_conflicted(block: &VessBlock) -> HashSet<usize> {
        let mut all = vec![block.coinbase.clone()];
        all.extend(block.payments.clone());
        let conflicted = Self::find_conflicts(&all);
        conflicted.iter().filter(|&&i| i > 0).map(|&i| i - 1).collect()
    }

    /// Build the parent list for a new block: heaviest tip first (DAA spine),
    /// then other tips (merged work), capped at MAX_PARENTS.
    fn block_parents(&self) -> Vec<BlockHash> {
        let mut parents = Vec::new();
        if let Some(h) = self.heaviest_tip() { parents.push(h); }
        for h in &self.tip_hashes { if !parents.contains(h) { parents.push(*h); } }
        parents.truncate(MAX_PARENTS);
        parents
    }

    /// Deterministic topological order over the ancestor closure of `roots`
    /// (parents before children, ready-set ties broken by block hash). Kahn's
    /// algorithm — no recursion, so long chains can't overflow the stack.
    fn ancestor_order(&self, roots: &[BlockHash]) -> Option<Vec<BlockHash>> {
        let mut set = HashSet::new();
        let mut stack: Vec<BlockHash> = roots.to_vec();
        while let Some(h) = stack.pop() {
            if !set.insert(h) { continue; }
            let b = self.blocks.get(&h)?;
            for p in &b.parents { stack.push(*p); }
        }
        let mut indeg: HashMap<BlockHash, usize> = HashMap::new();
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        for h in &set {
            let b = self.blocks.get(h)?;
            for p in &b.parents {
                if set.contains(p) {
                    *indeg.entry(*h).or_insert(0) += 1;
                    children.entry(*p).or_default().push(*h);
                }
            }
        }
        let mut ready: BTreeSet<BlockHash> =
            set.iter().copied().filter(|h| indeg.get(h).copied().unwrap_or(0) == 0).collect();
        let mut order = Vec::with_capacity(set.len());
        while let Some(h) = ready.pop_first() {
            order.push(h);
            if let Some(ch) = children.get(&h) {
                for c in ch {
                    let d = indeg.entry(*c).or_insert(0);
                    *d -= 1;
                    if *d == 0 { ready.insert(*c); }
                }
            }
        }
        if order.len() != set.len() { return None; } // cycle — impossible for valid blocks
        Some(order)
    }

    /// Three-way classification of a merged payment set (already deduped):
    /// - conflicted: shares an input with another payment → all inputs burn,
    ///   no outputs are created;
    /// - voided: spends an output of a conflicted/voided payment → contributes
    ///   nothing at all; its OTHER inputs are NOT burned. Bystanders are
    ///   unwound, never punished — the penalty rests on the double-spender.
    /// Voiding takes precedence over conflicting and propagates to a fixpoint.
    fn classify_history(payments: &[&VessPayment]) -> (HashSet<PaymentId>, HashSet<PaymentId>) {
        let mut voided: HashSet<PaymentId> = HashSet::new();
        loop {
            let mut owners: HashMap<VessId, Vec<PaymentId>> = HashMap::new();
            for p in payments {
                if voided.contains(&p.payment_id) { continue; }
                for i in &p.inputs { owners.entry(i.vess_id()).or_default().push(p.payment_id); }
            }
            let mut conflicted: HashSet<PaymentId> = HashSet::new();
            for ids in owners.values() {
                if ids.len() > 1 { for id in ids { conflicted.insert(*id); } }
            }
            let bad: HashSet<VessId> = payments.iter()
                .filter(|p| conflicted.contains(&p.payment_id) || voided.contains(&p.payment_id))
                .flat_map(|p| p.outputs.iter().map(|o| o.vess_id()))
                .collect();
            let new_void: Vec<PaymentId> = payments.iter()
                .filter(|p| !voided.contains(&p.payment_id))
                .filter(|p| p.inputs.iter().any(|i| bad.contains(&i.vess_id())))
                .map(|p| p.payment_id)
                .collect();
            if new_void.is_empty() { return (conflicted, voided); }
            for id in new_void { voided.insert(id); }
        }
    }

    /// Merged UTXO state of the full ancestor closure of `roots` — the DAG
    /// replacement for a single-parent chain replay. Every ancestor coinbase
    /// pays out (merged work is never orphaned); cross-branch conflicts
    /// vaporize; payments depending on vaporized outputs are voided.
    fn state_for_roots(&self, roots: &[BlockHash]) -> Option<HashSet<VessId>> {
        // Try to walk the block ancestor closure.
        let order = self.ancestor_order(roots);
        if let Some(order) = order {
            // Normal path: full ancestor closure available.
            let mut seen_p: HashSet<PaymentId> = HashSet::new();
            let mut payments: Vec<&VessPayment> = Vec::new();
            for h in &order {
                for p in &self.blocks[h].payments {
                    if seen_p.insert(p.payment_id) { payments.push(p); }
                }
            }
            let (conflicted, voided) = Self::classify_history(&payments);
            let mut state = HashSet::new();
            let mut applied: HashSet<PaymentId> = HashSet::new();
            for h in &order {
                let b = &self.blocks[h];
                for o in &b.coinbase.outputs { state.insert(o.vess_id()); }
                for p in &b.payments {
                    if !applied.insert(p.payment_id) { continue; }
                    if voided.contains(&p.payment_id) { continue; }
                    for input in &p.inputs { state.remove(&input.vess_id()); }
                    if !conflicted.contains(&p.payment_id) {
                        for o in &p.outputs { state.insert(o.vess_id()); }
                    }
                }
            }
            return Some(state);
        }
        // Fallback: ancestor walk failed (missing blocks — typical after
        // a state sync where history wasn't transferred).  Use the LMDB
        // UTXO set directly as the base state.
        let t = self.env.read_txn().ok()?;
        let state: HashSet<VessId> = self.vess_index.iter(&t).ok()?
            .filter_map(|r| r.ok().map(|(k,_)| {
                let mut a = [0u8; 32]; a.copy_from_slice(k); a
            }))
            .collect();
        Some(state)
    }

    fn state_root(state: &HashSet<VessId>) -> MerkleRoot {
        let mut ids: Vec<VessId> = state.iter().copied().collect();
        ids.sort();
        merkle_root(&ids)
    }

    fn validate_block(&self, block: &VessBlock) -> Option<HashSet<VessId>> {
        if block.version != 1 || block.difficulty_bits > 32 || block.parents.len() > MAX_PARENTS { return None; }
        // Reject blocks that exceed the wire size cap.  This is nearly free
        // (one encode) and prevents a malicious miner from crafting a valid
        // but undeliverable block on purpose — "valid" and "transmissible"
        // are the same set.
        if block.encode().len() > MAX_BLOCK_BYTES { return None; }
        // No alt-genesis: a block with no parents is only valid when the DAG is empty.
        if block.parents.is_empty() && !self.blocks.is_empty() { return None; }
        // Difficulty must match the DAA-determined value for the current tip.
        // Miners cannot declare arbitrary difficulty — the schedule is deterministic.
        if !self.test_mode && block.difficulty_bits != self.current_difficulty { return None; }
        let mut max_parent_ts = 0u64;
        for parent_hash in &block.parents {
            if let Some(parent_block) = self.blocks.get(parent_hash) {
                max_parent_ts = max_parent_ts.max(parent_block.timestamp);
            } else if !self.blocks.is_empty() {
                // Missing parent in a node that has block history → reject.
                // On fresh-sync nodes (no blocks yet) we allow unknown
                // parents — the synced UTXO set serves as the ancestor state.
                return None;
            }
        }
        if !self.test_mode && block.timestamp < max_parent_ts { return None; }
        if !self.test_mode {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as u64;
            if block.timestamp > now.saturating_add(MAX_FUTURE_BLOCK_TIME_MS) { return None; }
        }

        let mut payment_ids = Vec::with_capacity(block.payments.len().saturating_add(1).min(MAX_BLOCK_PAYMENTS));
        payment_ids.push(block.coinbase.payment_id);
        payment_ids.extend(block.payments.iter().map(|p| p.payment_id));
        if payment_ids.len() > MAX_BLOCK_PAYMENTS { return None; }
        payment_ids.sort();
        if payment_ids.windows(2).any(|pair| pair[0] == pair[1]) || merkle_root(&payment_ids) != block.payment_merkle {
            return None;
        }
        if !block.coinbase.inputs.is_empty() || block.coinbase.outputs.is_empty()
            || block.coinbase.outputs.len() > MAX_OUTPUTS
            || block.coinbase.outputs.iter().any(|v| v.variant != VessVariant::Mint) {
            return None;
        }
        // Coinbase amount validation: total outputs MUST equal block_reward + dev_reward.
        // Without this check, a miner could mint unlimited inflation.
        // Skipped in test mode — test helpers construct synthetic blocks for targeted scenarios.
        if !self.test_mode {
            let reward = block_reward(block.difficulty_bits);
            let dev_share = dev_reward(reward);
            let expected_total = reward.saturating_add(dev_share);
            // try_fold with checked_add: overflow → None → block rejected.
            // Prevents wrap-around inflation via crafted coinbase outputs.
            let actual_total: Amount = block.coinbase.outputs.iter()
                .try_fold(0u64, |acc, v| acc.checked_add(v.amount))?;
            if actual_total != expected_total { return None; }
            // Verify the dev output goes to the correct dev key
            let dev_output = block.coinbase.outputs.iter().find(|v| v.owner_hash == DEV_PUBKEY_HASH);
            if dev_output.map(|v| v.amount).unwrap_or(0) != dev_share { return None; }
            let miner_outputs: Amount = block.coinbase.outputs.iter()
                .filter(|v| v.owner_hash != DEV_PUBKEY_HASH)
                .try_fold(0u64, |acc, v| acc.checked_add(v.amount))?;
            if miner_outputs != reward { return None; }
        }
        let mut canonical_coinbase = block.coinbase.clone();
        canonical_coinbase.compute();
        if canonical_coinbase.payment_id != block.coinbase.payment_id { return None; }

        let mut state = self.state_for_roots(&block.parents)?;
        // Chained spends are banned by consensus: every payment input must
        // reference pre-block state — never an output created by this block
        // (including the coinbase). Checked once, before any state mutation.
        for payment in &block.payments {
            for input in &payment.inputs {
                if !state.contains(&input.vess_id()) { return None; }
            }
        }
        for output in &block.coinbase.outputs {
            if !state.insert(output.vess_id()) { return None; }
        }
        let conflicted = Self::block_conflicted(block);
        // Pass 1: validate every payment fully — canonical id, amounts, owner
        // binding, signatures, spend conditions. Conflicted payments get the
        // same cryptographic scrutiny as clean ones.
        for payment in &block.payments {
            let mut canonical = payment.clone();
            canonical.compute();
            if canonical.payment_id != payment.payment_id || payment.is_mint()
                || payment.inputs.is_empty() || payment.outputs.is_empty()
                || payment.inputs.len() > MAX_INPUTS || payment.outputs.len() > MAX_OUTPUTS
                || payment.input_sum() != payment.output_sum() || payment.sigs.len() != payment.inputs.len() {
                return None;
            }
            for (i, input) in payment.inputs.iter().enumerate() {
                // Owner binding: the pubkey must hash to the claimed owner_hash.
                // Without this, anyone can spend any UTXO by providing their own pubkey.
                if dsa_pubkey_hash(&input.pubkey) != input.owner_hash { return None; }
                if !dsa_verify(&input.pubkey, &payment.payment_id, &payment.sigs[i]) { return None; }
                if let Some(cond) = &input.spend_condition {
                    if cond.hashlock != [0u8; 32]
                        && (i >= payment.preimages.len() || payment.preimages[i]
                            .map(|preimage| blake3_hash(&preimage) != cond.hashlock).unwrap_or(true)) {
                        return None;
                    }
                    if cond.expires_at > 0 && block.timestamp / 1000 >= cond.expires_at { return None; }
                }
            }
        }
        // Pass 2: apply clean payments in block order. Conflict closure
        // guarantees clean payments never share inputs with any other payment,
        // so each input must be present exactly when spent.
        for (pi, payment) in block.payments.iter().enumerate() {
            if conflicted.contains(&pi) { continue; }
            for input in &payment.inputs {
                if !state.remove(&input.vess_id()) { return None; }
            }
            for output in &payment.outputs {
                if output.variant != VessVariant::Output || !state.insert(output.vess_id()) { return None; }
            }
        }
        // Pass 3: vaporize conflicted payments. Inputs burn, outputs are NOT
        // created — the penalty falls entirely on the double-spender. Every
        // input was already proven to exist in pre-block state above; the
        // second removal of a shared input simply no-ops — that IS the burn.
        for (pi, payment) in block.payments.iter().enumerate() {
            if !conflicted.contains(&pi) { continue; }
            for input in &payment.inputs { state.remove(&input.vess_id()); }
        }
        Some(state)
    }

    /// Cumulative work of a block's full ancestor set (sum of 2^difficulty_bits,
    /// each ancestor counted once). Multi-parent merge blocks accumulate the
    /// work of every branch they reference — fork races stop orphaning work.
    pub fn cumulative_work(&self, hash: &BlockHash) -> u64 {
        if let Some(&w) = self.block_work.get(hash) { return w; }
        // Cache miss (shouldn't happen after startup rebuild) — compute
        // using the same max-over-parents GHOST-lite rule.
        if let Some(b) = self.blocks.get(hash) {
            let parent_max = b.parents.iter()
                .filter_map(|p| self.block_work.get(p))
                .max().unwrap_or(&0);
            return parent_max.saturating_add(1u64 << b.difficulty_bits as u64);
        }
        0
    }

    /// The tip with the most cumulative work — defines canonical state.
    /// Ties are broken deterministically by lowest block hash to prevent
    /// consensus splits when two tips have equal work (common at low difficulty).
    fn heaviest_tip(&self) -> Option<BlockHash> {
        self.tip_hashes.iter()
            .map(|h| (*h, self.cumulative_work(h)))
            .max_by(|(h1, w1), (h2, w2)| w1.cmp(w2).then_with(|| h2.cmp(h1)))
            .map(|(h, _)| h)
    }

    /// Advance the finalized tip FINALITY_DEPTH blocks behind current_tip
    /// along the first-parent spine, then prune everything older.
    fn advance_finality(&mut self) {
        let Some(tip) = self.current_tip else { return };
        // Walk the first-parent spine FINALITY_DEPTH steps back.
        let mut cursor = Some(tip);
        for _ in 0..FINALITY_DEPTH {
            cursor = match cursor {
                Some(h) => self.blocks.get(&h).and_then(|b| b.parents.first().copied()),
                None => break,
            };
        }
        let new_finalized = match cursor {
            Some(h) if self.finalized_tip != Some(h) => {
                // Update fin_work and fin_root.
                // Use the block's own state_merkle — it was verified on
                // acceptance.  state_for_roots would silently fall back to
                // the live LMDB state (ancestors are already pruned at
                // finality depth), storing the current root as the
                // finalized one — indistinguishable from correct, but
                // breaks sync-from-finalized.
                self.fin_work = self.block_work.get(&h).copied().unwrap_or(self.fin_work);
                self.fin_root = self.blocks.get(&h).map(|b| b.state_merkle).unwrap_or(self.fin_root);
                self.finalized_tip = Some(h);
                self.save_meta();
                true
            }
            _ => self.finalized_tip.is_some() == cursor.is_some(),
        };
        if new_finalized || self.blocks.len() > FINALITY_DEPTH + 200 {
            self.prune_to_finality();
        }
    }

    /// Prune all blocks not in the descendant closure of finalized_tip,
    /// keeping the DAG bounded to the finality window.
    fn prune_to_finality(&mut self) {
        let Some(ft) = self.finalized_tip else { return; };
        // Walk forward from finalized_tip through all descendants.
        let mut keep = HashSet::new();
        let mut stack: Vec<BlockHash> = self.tip_hashes.clone();
        // Also include finalized_tip itself.
        stack.push(ft);
        while let Some(h) = stack.pop() {
            if !keep.insert(h) { continue; }
            // Find children (blocks whose parents include h).
            for (child_hash, child) in &self.blocks {
                if child.parents.contains(&h) && !keep.contains(child_hash) {
                    stack.push(*child_hash);
                }
            }
        }
        // Remove everything not in keep.
        self.blocks.retain(|h, _| keep.contains(h));
        self.block_work.retain(|h, _| keep.contains(h));
        self.block_seen.retain(|h| keep.contains(h));
        self.tip_hashes.retain(|h| keep.contains(h));
        // Also prune orphans/missing_parents referencing pruned blocks.
        self.orphans.retain(|h, _| keep.contains(h));
        self.missing_parents.retain(|h, _| keep.contains(h));
        if let Ok(mut w) = self.env.write_txn() {
            let persisted: Vec<BlockHash> = self.blocks_db.iter(&w).ok().into_iter().flatten()
                .filter_map(|entry| entry.ok())
                .filter_map(|(hash, _)| hash.try_into().ok())
                .collect();
            for hash in persisted.into_iter().filter(|hash| !keep.contains(hash)) {
                let _ = self.blocks_db.delete(&mut w, &hash);
                let _ = self.undo_db.delete(&mut w, &hash);
            }
            let _ = w.commit();
        }
    }

    /// If the heaviest tip disagrees with our LMDB state, rebuild using the
    /// merged DAG state. `state_for_roots` handles dedup, conflict closure,
    /// and void propagation deterministically.
    fn reorg_if_needed(&mut self) {
        let Some(heaviest) = self.heaviest_tip() else { return };
        if self.current_tip == Some(heaviest) { return; }
        let Some(state) = self.state_for_roots(&[heaviest]) else { return; };
        if let Ok(mut w) = self.env.write_txn() {
            let existing: Vec<VessId> = self.vess_index.iter(&w).ok().into_iter().flatten()
                .filter_map(|entry| entry.ok())
                .filter_map(|(id, _)| id.try_into().ok())
                .collect();
            for id in existing { let _ = self.vess_index.delete(&mut w, &id); }
            for id in &state { let _ = self.vess_index.put(&mut w, id, &()); }
            if w.commit().is_err() { return; }
            self.current_tip = Some(heaviest);
            self.save_meta();
        }
    }

    // ---- cycle ----

    pub fn cycle(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        self.ticks = self.ticks.wrapping_add(1);
        self.network.tick(); // advance network clock + reap stale half-open sessions
        self.evict_limbo();
        self.retry_reliable_messages();
        self.retry_handshakes();
        // Reset per-second rate limiter every ~1s (200 ticks at 5ms)
        if self.ticks.saturating_sub(self.msg_window_start) >= 200 {
            self.peer_msg_count.clear();
            self.msg_window_start = self.ticks;
        }
        self.drain_embargo();
        if self.ticks.is_multiple_of(2000) { self.gossip_roots(); } // ~10s, not every tick

        // ---- NAT traversal ----
        // Every 40 ticks (~200ms), if behind NAT, try to punch through
        if self.ticks.is_multiple_of(40) && self.is_behind_nat() {
            self.nat_cycle();
        }
        // Drain stem relay queue through introducer (rate-limited)
        if !self.relay_queue.is_empty() && self.ticks.is_multiple_of(20) {
            if let Some(intro) = self.introducer {
                let to_send: Vec<_> = self.relay_queue.drain(..STEM_RELAY_MAX_PER_TICK).collect();
                for (target_id, data) in to_send {
                    self.send(intro, &GossipMessage::StemRelay(target_id, data));
                }
            }
        }

        // Drain discovered peers one at a time (paced, ~0.5s between attempts).
        if self.ticks.is_multiple_of(100) {
            // Cap the queue to prevent unbounded growth from peer-list spam.
            if self.discovered_peers.len() > 500 {
                self.discovered_peers.truncate(500);
            }
            if let Some(addr) = self.discovered_peers.pop() {
                if self.peer_count() < self.max_peers && !self.has_session_for(&addr) {
                    // Defer to main.rs — PoW solving takes 1-3s and must
                    // not hold the node lock (blocks the main loop).
                    self.pending_discovered.push(addr);
                }
            }
        }

        // Two-tier block gossip: push full block to 3-4 random peers
        // (Tier 1), hash-announce to the rest (Tier 2). Peers pull via
        // BlockReq if they haven't seen the block. Excludes the origin
        // peer who already has the block.
        let pending: Vec<(VessBlock, Option<SocketAddr>)> = self.pending_blocks.drain(..).collect();
        for (block, origin) in pending {
            let hash = block.header_hash();
            let tier1 = self.select_tier1_peers(4, origin.as_ref());
            let tier1_set: HashSet<SocketAddr> = tier1.iter().copied().collect();
            let full = GossipMessage::Block(block);
            let announce = GossipMessage::BlockAnnounce(hash);
            // Collect tier-2 peers before any mutable borrow.
            let tier2: Vec<SocketAddr> = self.peers.iter()
                .filter(|(_, id)| **id != [0u8; 32])
                .map(|(a, _)| *a)
                .filter(|a| !tier1_set.contains(a) && origin.as_ref() != Some(a))
                .collect();
            for a in &tier1 { self.send_unreliable(*a, &full); }
            for a in &tier2 { self.send_unreliable(*a, &announce); }
        }
        // Mining is handled by the background mining thread in main.rs
        if self.ticks.is_multiple_of(100) { self.peer_announce(); } // ~0.5s
        if self.ticks.is_multiple_of(60) { self.ping_all(); }       // ~0.3s
        if self.ticks.is_multiple_of(30) { self.reap(); }
        if (self.needs_sync && self.ticks.is_multiple_of(50)) || (self.auto_sync_until > self.ticks && self.ticks.is_multiple_of(50)) { self.drive_sync(); }
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
            // Chained spends are banned: inputs must be confirmed UTXOs in
            // LMDB, never outputs of other in-limbo (unconfirmed) payments.
            if !self.check_direct(&v.vess_id()) { return false; }

            // Signature is always required
            if !dsa_verify(&v.pubkey, &p.payment_id, &p.sigs[i]) { return false; }
            // Owner binding: the pubkey must hash to the claimed owner_hash.
            if dsa_pubkey_hash(&v.pubkey) != v.owner_hash { return false; }

            // Spend condition: additional gates on top of signature
            if let Some(ref cond) = v.spend_condition {
                // Hashlock: must provide correct preimage (if set)
                if cond.hashlock != [0u8; 32] {
                    let preimage_ok = i < p.preimages.len()
                        && p.preimages[i].is_some()
                        && blake3_hash(&p.preimages[i].unwrap()) == cond.hashlock;
                    if !preimage_ok { return false; }
                }
                // Expiry: output expires, can't spend after (if set).
                // Use a 120 s margin below the deadline — verify() uses
                // wall clock but validate_block uses block.timestamp/1000.
                // A payment within 2 min of expiry could pass mempool but
                // fail block inclusion, creating a narrow variant of the
                // duplicate-output attack (wasted miner PoW).
                if cond.expires_at > 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    if now.saturating_add(120) >= cond.expires_at { return false; }
                }
            }
        }
        // Output collision prevention: no output may duplicate an existing
        // UTXO or collide with another output in the same payment.
        // Without this, a payment with a duplicate output passes mempool
        // checks but causes the entire block to be rejected in validate_block,
        // wasting miner PoW.
        let mut seen = HashSet::new();
        for v in &p.outputs {
            let id = v.vess_id();
            if self.check_direct(&id) || !seen.insert(id) {
                return false;
            }
        }
        true
    }

    pub fn merkle(&self) -> MerkleRoot {
        let t = match self.env.read_txn() { Ok(t) => t, Err(_) => return [0u8; 32] };
        let iter = self.vess_index.iter(&t).unwrap().filter_map(|r| r.ok().map(|(k,_)| {
            let mut a = [0u8; 32]; a.copy_from_slice(k); a
        }));
        // LMDB B-tree iterates in byte order → streaming merkle, O(log N) RAM
        merkle_root_stream(iter)
    }

    /// Returns (ticks, merkle_root) that a quorum of peers agree on.
    /// Requires ≥2 peers to agree — never trusts a single peer.
    fn consensus_merkle(&self) -> Option<(u64, MerkleRoot, u32)> {
        let roots: Vec<(u64, MerkleRoot, u32)> = self.peer_merkle.values().copied().collect();
        if roots.len() < 2 { return None; }
        // Count votes for each (ticks, root, diff) pair; need ≥2 matching
        let mut counts: HashMap<(u64, MerkleRoot, u32), usize> = HashMap::new();
        for &r in &roots { *counts.entry(r).or_insert(0) += 1; }
        counts.into_iter().find(|&(_, c)| c >= 2).map(|(r, _)| r)
    }

    // ---- gossip, relay ----

    fn gossip_roots(&mut self) {
        let r = self.merkle();
        // Use accepted_blocks, not ticks — ticks are local counters meaningless
        // across nodes. accepted_blocks is a real chain-length measure.
        let m = GossipMessage::Root(self.accepted_blocks, r, self.current_difficulty);
        let addrs: Vec<SocketAddr> = self.peers.iter().filter(|(_,id)| **id != [0u8;32]).map(|(a,_)| *a).collect();
        for a in addrs { self.send(a, &m); }
    }

    fn strike(&mut self, addr: SocketAddr) {
        // Never strike localhost — dev wallets shouldn't get banned.
        if addr.ip().is_loopback() { return; }
        // Only credit strikes against addresses whose session has proven
        // receipt of at least one valid encrypted message.  A spoofed
        // INIT creates a session immediately but the real owner of that
        // address never receives the RESP — strike accumulation would
        // otherwise get the victim IP banned network-wide.
        if self.network.session_by_addr(&addr)
            .map(|s| !s.proven_rx)
            .unwrap_or(true)
        {
            return;
        }
        *self.fails.entry(addr).or_insert(0) += 1;
    }

    pub fn process(&mut self, addr: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
        // Reject banned IPs immediately — per-IP ban survives port changes.
        if self.banned_ips.contains(&addr.ip()) && !addr.ip().is_loopback() { return None; }
        if self.fails.get(&addr).copied().unwrap_or(0) > 5 { return None; }
        let assembled;
        let completed_id;
        let data = if data_packets::is_fragment(data) {
            if !self.packet_reassembly.contains_key(&addr) && self.packet_reassembly.len() >= MAX_REASSEMBLY_PEERS {
                return None;
            }
            match self.packet_reassembly.entry(addr).or_default().push(data, self.ticks) {
                Ok(Some((id, message))) => {
                    let recent = self.completed_packets.entry(addr).or_default();
                    recent.retain(|(_, completed_at)| self.ticks.saturating_sub(*completed_at) < COMPLETED_PACKET_TTL_TICKS);
                    if recent.iter().any(|(completed_id, _)| *completed_id == id) {
                        self.send(addr, &GossipMessage::DataAck(id));
                        return None;
                    }
                    completed_id = Some(id);
                    assembled = message;
                    assembled.as_slice()
                }
                Ok(None) => return None,
                Err(()) => { self.strike(addr); return None; }
            }
        } else {
            completed_id = None;
            data
        };
        // Reject oversize frames (DoS protection)
        if data.len() > MAX_FRAME_SIZE { self.strike(addr); return None; }
        if data.len() < 5 { return None; }  // minimum: tag(1) + len(4)
        let (tag, mut payload) = match unframe(data) { Some(v) => v, None => { self.strike(addr); return None; } };
        if tag == HANDSHAKE_INIT || tag == HANDSHAKE_RESP {
            // Verify PoW handshake puzzle on INIT
            if tag == HANDSHAKE_INIT {
                // Rate-limit handshake attempts per address — handshakes
                // skip the 50 msg/s limiter and are otherwise unbounded.
                let count = self.peer_msg_count.get(&addr).copied().unwrap_or(0);
                if count >= 5 { return None; } // max 5 handshake msgs/sec per IP
                self.peer_msg_count.insert(addr, count + 1);

                let proof_len = 32 + cuckoo::HANDSHAKE_CYCLE_LENGTH * 4;
                if payload.len() < proof_len { self.strike(addr); return None; }
                let split = payload.len() - proof_len;
                let pow_bytes = &payload[split..];
                let pow_header: [u8; 32] = pow_bytes[..32].try_into().unwrap();
                // Re-derive the expected PoW header — the initiator MUST use
                // blake3("vess-handshake" || node_id).
                // Bound to the initiator's identity (authenticated by the sig
                // below): one solve per identity, not replayable across
                // identities. The target address CANNOT be used here — over
                // UDP the responder cannot know which address string the
                // initiator typed (127.0.0.1 vs 0.0.0.0 vs public IP all
                // reach the same socket), so an address binding rejects
                // every legitimate handshake.
                let expected_header = blake3_hash(
                    &[b"vess-handshake" as &[u8], &payload[..32]].concat()
                );
                // The initiator's solver retries by iterating blake3 on the
                // base header until a cycle is found, and appends the WINNING
                // header — so accept any header within a short chain of the
                // base (64 recomputations are trivially cheap).
                let mut chained = expected_header;
                let header_ok = (0..64).any(|_| {
                    if chained == pow_header { return true; }
                    chained = blake3_hash(&chained);
                    false
                });
                if !header_ok { self.strike(addr); return None; }
                let mut proof = Vec::with_capacity(cuckoo::HANDSHAKE_CYCLE_LENGTH);
                for i in 0..cuckoo::HANDSHAKE_CYCLE_LENGTH {
                    proof.push(u32::from_le_bytes(pow_bytes[32+i*4..32+(i+1)*4].try_into().unwrap()));
                }
                if !cuckoo::verify(&pow_header, &proof, cuckoo::HANDSHAKE_CYCLE_LENGTH, cuckoo::HANDSHAKE_EDGE_BITS) {
                    self.strike(addr);
                    return None;
                }
                // Cap inbound half-open sessions — MAX_SESSIONS in
                // build_handshake_init only caps outbound; inbound was
                // unbounded, letting an attacker fill session memory
                // by flooding INITs from many spoofed addresses.
                if self.network.sessions.len() >= MAX_SESSIONS {
                    return None;
                }
                payload = &payload[..split];
            }
            let resp = self.network.handle_handshake(addr, tag, payload);
            if let Some(s) = self.network.session_by_addr(&addr) {
                if s.node_id.is_some() {
                    self.peers.insert(addr, s.node_id.unwrap());
                    self.persist_peer(addr);
                    // NAT self-detection: the responder observed our source
                    // address and echoed it in HANDSHAKE_RESP. Compare the
                    // parts NAT actually changes — port (always) and IP
                    // (only when we're not bound to a wildcard).
                    // Comparing the full SocketAddr against 0.0.0.0:9876
                    // would classify every default-configured node as NAT'd.
                    if tag == HANDSHAKE_RESP && s.reported_addr.is_some() {
                        let behind = s.reported_addr.map_or(false, |oa| {
                            oa.port() != self.addr.port()
                                || (!self.addr.ip().is_unspecified() && oa.ip() != self.addr.ip())
                        });
                        if behind { self.nat_type = NatType::BehindNat; }
                    }
                    // Exchange peer lists — learn about the network through
                    // this new peer and let them learn about ours.
                    self.send_get_peers_request(addr);
                }
            }
            if let Some(handshake_data) = resp {
                self.send_handshake(addr, handshake_data);
            }
            // On RESP, our INIT arrived — stop retrying it, and exchange peers.
            if tag == HANDSHAKE_RESP {
                self.pending_handshakes.remove(&addr);
                self.send_get_peers_request(addr);
            }
            return None;
        }
        // HolePunch is a raw frame — no encryption session required.
        // Only pass through to route() if the sender is plausibly known
        // (has a session, a pending intro, or we're behind NAT).
        if tag == TAG_HOLE_PUNCH {
            if payload.len() >= 4 {
                let is_known = self.has_session_for(&addr)
                    || self.introduced_peers.values().any(|ip| ip.observed_addr == addr)
                    || self.is_behind_nat();
                if is_known {
                    let nonce = u32::from_le_bytes(payload[..4].try_into().unwrap());
                    self.route(addr, &GossipMessage::HolePunch(nonce).encode());
                } else {
                    self.strike(addr);
                }
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
        let response = self.route(addr, &plain);
        if let Some(id) = completed_id {
            let recent = self.completed_packets.entry(addr).or_default();
            if recent.len() >= MAX_COMPLETED_PACKETS_PER_PEER { recent.remove(0); }
            recent.push((id, self.ticks));
            self.send(addr, &GossipMessage::DataAck(id));
        }
        response
    }

    pub fn route(&mut self, addr: SocketAddr, plain: &[u8]) -> Option<Vec<u8>> {
        let (tag, payload) = match unframe(plain) { Some(v) => v, None => { self.strike(addr); return None; } };
        if (0x10..=0x19).contains(&tag) {
            // Even tags (0x10, 0x14, …) are requests — handle and respond.
            // Odd tags (0x11, 0x15, …) are responses to our own requests.
            if tag % 2 == 0 {
                let r = match self.rpc(tag, payload) { Some(r) => r, None => { self.strike(addr); return None; } };
                let s = match self.network.session_by_addr_mut(&addr) { Some(s) => s, None => { self.strike(addr); return None; } };
                return Some(s.encrypt(&r));
            } else {
                self.handle_rpc_response(tag, payload);
                return None;
            }
        }
        let m = match GossipMessage::decode(tag, payload) {
            Some(m) => m,
            None => { self.strike(addr); return None; }
        };
        match &m {
            GossipMessage::Payment(p) => {
                let accepted = self.submit(p.clone());
                if !accepted {
                    // Only strike for malformed/invalid payments, not for
                    // benign rejections (duplicate, limbo full, syncing).
                    if !self.needs_sync && self.limbo.len() < MAX_LIMBO_PAYMENTS
                        && !self.limbo.contains_key(&p.payment_id) {
                        *self.fails.entry(addr).or_insert(0) += 1;
                    }
                }
            }
            GossipMessage::Block(block) => {
                let hash = block.header_hash();
                // Deduplicate: only process and relay blocks we haven't seen.
                // Without this, invalid/rejected blocks circulate forever.
                if self.block_seen.contains(&hash) { return None; }
                // If parents are unknown and we have existing blocks, request them.
                for parent_hash in &block.parents {
                    if !self.blocks.contains_key(parent_hash) && !self.blocks.is_empty() {
                        self.send(addr, &GossipMessage::BlockReq(*parent_hash));
                    }
                }
                let matched = self.process_block(block);
                self.block_seen.insert(hash);
                if matched {
                    // Defer to cycle() for two-tier broadcast (push + announce).
                    self.pending_blocks.push((block.clone(), Some(addr)));
                }
                // If our state merkle didn't match the block's claim, and we're
                // actually behind, request sync (with cooldown to avoid spam).
                if !matched && self.needs_sync {
                    self.send(addr, &GossipMessage::StateSyncReq(self.ticks, 1000));
                }
            }
            GossipMessage::Root(peer_height, peer_root, peer_diff) => {
                self.peer_merkle.insert(addr, (*peer_height, *peer_root, *peer_diff));
                // Use accepted_blocks (chain height) for cross-node comparison.
                // Ticks are local counters — comparing them across nodes is meaningless.
                if let Some((consensus_height, consensus_root, _)) = self.consensus_merkle() {
                    if consensus_height > self.accepted_blocks {
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
                // Only trust this when the session's own node_id matches
                // the announced pid — otherwise any connected peer can
                // poison our NAT type by claiming to be us.
                if *pid == self.network.my_node_id() && *a != self.addr
                    && self.network.session_by_addr(&addr)
                        .map(|s| s.node_id == Some(*pid))
                        .unwrap_or(false)
                {
                    self.nat_type = NatType::BehindNat;
                    // The announced address is our public mapping — use it
                    // in future PeerAnnounce messages.
                }
                if self.peer_count() < self.max_peers && self.peers.entry(*a).or_insert([0u8;32]) == &[0u8;32] {
                    // Cap the total peer map to prevent memory exhaustion
                    // from PeerAnnounce spam.  peer_count() only counts
                    // handshaked entries; the raw map can grow unbounded.
                    if self.peers.len() >= self.max_peers * 4 { return None; }
                    // New peer — queue for connection but do NOT persist
                    // until the handshake succeeds.  Persisting unverified
                    // addresses lets an attacker flood the peer DB via
                    // PeerAnnounce spam.
                    self.discovered_peers.push(*a);
                }
            }
            GossipMessage::Ping(n) => { self.send(addr, &GossipMessage::Pong(*n)); }
            GossipMessage::Pong(n) => {
                // Track RTT in ticks for tier-1 peer selection.
                let sent = *n as u64;
                let rtt = self.ticks.saturating_sub(sent);
                self.peer_rtt.insert(addr, rtt);
            }
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
                // Gate holepunch responses: if we're public, only respond to peers
                // we're expecting (pending introductions with matching nonce).
                // Behind NAT, also require the address to be in introduced_peers
                // — otherwise any spoofed HolePunch packet triggers a 1-3s
                // locked-cpu handshake PoW solve and turns us into an unwilling
                // reflector.
                let is_introduced = self.introduced_peers.values()
                    .any(|ip| ip.observed_addr == addr && ip.punch_nonce == *nonce);
                let is_known = self.has_session_for(&addr) || is_introduced;
                if !is_known {
                    self.strike(addr);
                    return None;
                }
                // Someone is trying to punch through to us.
                // Initiate handshake if we don't have a session.
                if !self.has_session_for(&addr) {
                    self.try_punch_handshake(addr);
                }
                // Echo back with incremented nonce so the sender knows the hole is open
                self.send_hole_punch(addr, nonce.wrapping_add(1));
                // Rate-limit: don't process more than 3 holepunch echoes per tick
            }
            GossipMessage::StemRelay(target_id, data) => {
                if *target_id == self.network.my_node_id() {
                    // This relay is for us — only accept payments through
                    // the relay path.  Blocks, PeerAnnounce, and other
                    // gossip must arrive directly from an authenticated
                    // session; otherwise an attacker can route strikes
                    // onto the introducer.
                    if let Some((tag, _inner_payload)) = unframe(data) {
                        if tag == TAG_PAYMENT {
                            self.route(addr, data);
                        }
                    }
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
            GossipMessage::DataAck(id) => {
                if self.reliable_messages.get(id).map(|message| message.addr == addr).unwrap_or(false) {
                    self.reliable_messages.remove(id);
                }
            }
            GossipMessage::BlockAnnounce(hash) => {
                // Tier-2 hash announce: pull the full block if we haven't seen it.
                if !self.block_seen.contains(hash) && !self.blocks.contains_key(&hash[..]) {
                    self.send(addr, &GossipMessage::BlockReq(*hash));
                }
            }
            GossipMessage::BlockReq(hash) => {
                if let Some(block) = self.blocks.get(&hash[..]) {
                    self.send(addr, &GossipMessage::BlockResp(Some(block.clone())));
                } else {
                    self.send(addr, &GossipMessage::BlockResp(None));
                }
            }
            GossipMessage::BlockResp(Some(block)) => {
                if self.process_block(block) {
                    // Pulled blocks must propagate onward — otherwise they
                    // stop at tier-2 nodes.  Push through the same two-tier
                    // broadcast as directly-gossiped blocks.
                    self.pending_blocks.push((block.clone(), Some(addr)));
                }
            }
            GossipMessage::BlockResp(None) => {}
        }
        None
    }

    fn retry_reliable_messages(&mut self) {
        let mut retry = Vec::new();
        let mut expire = Vec::new();
        for (id, message) in &self.reliable_messages {
            if self.ticks.saturating_sub(message.last_sent) < RETRANSMIT_TICKS { continue; }
            if message.retries >= MAX_RETRANSMITS { expire.push(*id); } else { retry.push(*id); }
        }
        for id in expire { self.reliable_messages.remove(&id); }
        for id in retry {
            if let Some(message) = self.reliable_messages.get_mut(&id) {
                message.retries += 1;
                message.last_sent = self.ticks;
                for packet in &message.packets { self.outbox.push((message.addr, packet.clone())); }
            }
        }
    }

    /// Fragment and enqueue a handshake message for reliable delivery.
    /// Multi-fragment messages are tracked in `pending_handshakes` and
    /// retried until the session is established or the budget runs out.
    fn send_handshake(&mut self, addr: SocketAddr, data: Vec<u8>) {
        let Some(fragmented) = data_packets::fragment_with_id(&data) else {
            return;
        };
        if fragmented.id.is_some() {
            self.pending_handshakes.insert(addr, PendingHandshake {
                packets: fragmented.packets.clone(),
                last_sent: self.ticks,
                retries: 0,
            });
        }
        for packet in fragmented.packets {
            self.outbox.push((addr, packet));
        }
    }

    /// Retry handshake fragments that haven't been acknowledged.
    fn retry_handshakes(&mut self) {
        let mut retry = Vec::new();
        let mut done = Vec::new();
        for (addr, hs) in &self.pending_handshakes {
            if self.ticks.saturating_sub(hs.last_sent) < HANDSHAKE_RETRANSMIT_TICKS { continue; }
            if hs.retries >= MAX_HANDSHAKE_RETRANSMITS { done.push(*addr); } else { retry.push(*addr); }
        }
        for addr in done { self.pending_handshakes.remove(&addr); }
        for addr in retry {
            if let Some(hs) = self.pending_handshakes.get_mut(&addr) {
                hs.retries += 1;
                hs.last_sent = self.ticks;
                for packet in &hs.packets {
                    self.outbox.push((addr, packet.clone()));
                }
            }
        }
    }

    /// Drain the outbox without advancing ticks (for use before the main loop).
    pub fn drain_outbox(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut self.outbox)
    }

    /// Send a GetPeers RPC request through the encrypted session.
    /// Called automatically when a handshake completes so both sides
    /// discover each other's known peers.
    fn send_get_peers_request(&mut self, addr: SocketAddr) {
        let req = RpcRequest::GetPeers.encode();
        if let Some(s) = self.network.session_by_addr_mut(&addr) {
            self.outbox.push((addr, frame(ENCRYPTED_DATA, &s.encrypt(&req))));
        }
    }

    fn rpc(&mut self, tag: u8, payload: &[u8]) -> Option<Vec<u8>> {
        let req = RpcRequest::decode(tag, payload)?;
        Some(match req {
            RpcRequest::Check(id) => RpcResponse::Check(self.check(&id)),
            RpcRequest::Submit(p) => RpcResponse::Submit(self.submit(p)),
            RpcRequest::GetPeers => RpcResponse::GetPeers(self.get_peers()),
            RpcRequest::ConnectPeer(addr) => {
                let len = self.add_peer(addr);
                RpcResponse::ConnectPeer(len > 0)
            }
        }.encode())
    }

    /// Process an RPC response from a peer (e.g. GetPeers reply).
    fn handle_rpc_response(&mut self, tag: u8, payload: &[u8]) {
        if let Some(resp) = RpcResponse::decode(tag, payload) {
            match resp {
                RpcResponse::GetPeers(peers) => {
                    for (_node_id, addr) in peers {
                        if addr != self.addr && self.peer_count() < self.max_peers {
                            if self.peers.entry(addr).or_insert([0u8; 32]) == &[0u8; 32] {
                                // Queue for connection; persist only after
                                // successful handshake (not here).
                                self.discovered_peers.push(addr);
                            }
                        }
                    }
                }
                _ => {} // Check, Submit, ConnectPeer — no-op for gossip
            }
        }
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
                // Fluff to a random subset (~8 peers) instead of all peers,
                // avoiding a full-network broadcast storm per payment.
                let m = GossipMessage::Payment(p);
                let tier1 = self.select_tier1_peers(8, None);
                for a in &tier1 { self.send(*a, &m); }
            }
        }
    }

    /// Select up to `n` handshaked peers at random, preferring low-RTT peers.
    /// If `exclude` is provided, that peer is never selected.
    fn select_tier1_peers(&self, n: usize, exclude: Option<&SocketAddr>) -> Vec<SocketAddr> {
        let mut candidates: Vec<(SocketAddr, u64)> = self.peers.iter()
            .filter(|(_, id)| **id != [0u8; 32])
            .filter(|(a, _)| exclude.map_or(true, |e| *a != e))
            .map(|(a, _)| (*a, self.peer_rtt.get(a).copied().unwrap_or(u64::MAX)))
            .collect();
        // Shuffle with bias toward low RTT: score = rtt * 1000 + (random % 500).
        // Low-RTT peers get a clear advantage without determinism.
        for (_, rtt) in &mut candidates {
            let r: u64 = rand::thread_rng().gen();
            *rtt = rtt.saturating_mul(1000).saturating_add(r % 500);
        }
        candidates.sort_by_key(|(_, v)| *v);
        candidates.truncate(n.min(candidates.len()));
        candidates.into_iter().map(|(a, _)| a).collect()
    }

    /// Send a message without reliable retransmission tracking.
    /// Use for blocks (fire-and-forget — redundancy handles loss) and
    /// hash-announces (re-requested if dropped).
    pub fn send_unreliable(&mut self, addr: SocketAddr, msg: &GossipMessage) {
        let encoded = msg.encode();
        if let Some(s) = self.network.session_by_addr_mut(&addr) {
            let packet = frame(ENCRYPTED_DATA, &s.encrypt(&encoded));
            if let Some(fragmented) = data_packets::fragment_with_id(&packet) {
                for fragment in fragmented.packets { self.outbox.push((addr, fragment)); }
            } else {
                eprintln!("dropping oversized logical message ({} bytes)", encoded.len());
            }
        } else if self.is_behind_nat() && self.introducer.is_some() {
            if let Some(target_id) = self.peers.get(&addr).copied() {
                if target_id != [0u8; 32] {
                    self.relay_through_introducer(target_id, encoded);
                }
            }
        }
    }

    pub fn send(&mut self, addr: SocketAddr, msg: &GossipMessage) {
        let encoded = msg.encode();
        if let Some(s) = self.network.session_by_addr_mut(&addr) {
            let packet = frame(ENCRYPTED_DATA, &s.encrypt(&encoded));
            let Some(fragmented) = data_packets::fragment_with_id(&packet) else {
                eprintln!("dropping oversized logical message ({} bytes)", encoded.len());
                return;
            };
            if let Some(id) = fragmented.id {
                let bytes: usize = fragmented.packets.iter()
                    .fold(0usize, |acc, p| acc.saturating_add(p.len()));
                let in_flight: usize = self.reliable_messages.values().fold(0usize, |acc, m| {
                    acc.saturating_add(m.packets.iter().fold(0usize, |a, p| a.saturating_add(p.len())))
                });
                if self.reliable_messages.len() >= MAX_RELIABLE_MESSAGES
                    || in_flight.saturating_add(bytes) > MAX_RELIABLE_BYTES { return; }
                self.reliable_messages.insert(id, ReliableMessage {
                    addr,
                    packets: fragmented.packets.clone(),
                    last_sent: self.ticks,
                    retries: 0,
                });
            }
            for fragment in fragmented.packets { self.outbox.push((addr, fragment)); }
        } else if self.is_behind_nat() && self.introducer.is_some() {
            // No direct session — relay through introducer (stem relay fallback)
            if let Some(target_id) = self.peers.get(&addr).copied() {
                if target_id != [0u8; 32] {
                    self.relay_through_introducer(target_id, encoded);
                }
            }
        }
    }

    fn sync_chunk(&mut self, addr: SocketAddr, start: u64, count: u32) {
        let ids: Vec<VessId> = {
            let t = match self.env.read_txn() { Ok(t) => t, Err(_) => return };
            self.vess_index.iter(&t).unwrap().filter_map(|r| r.ok().map(|(k,_)| { let mut a=[0u8;32]; a.copy_from_slice(k); a })).skip(start as usize).take(count as usize).collect()
        };
        self.send(addr, &GossipMessage::StateSyncChunk(start, ids));
    }

    /// Periodically drive state sync when needs_sync is true.
    fn drive_sync(&mut self) {
        // If no sync peer yet, pick the one with the highest ticks from peer_merkle
        if self.sync_peer.is_none() {
            let best = self.peer_merkle.iter()
                .filter(|(addr, _)| self.has_session_for(addr))
                .max_by_key(|(_, (ticks, _, _))| *ticks)
                .map(|(addr, (_, root, _))| (*addr, *root));
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

        // If our merkle already matches the consensus root, we're done.
        if let Some((_, consensus_root, _)) = self.consensus_merkle() {
            if self.merkle() == consensus_root {
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
    /// Chunks are buffered in memory until the sync peer finishes sending;
    /// only then is the merkle root verified against quorum consensus and
    /// committed to LMDB atomically. This prevents sybil peers from poisoning
    /// the UTXO set with fabricated chunks.
    fn handle_sync_chunk(&mut self, addr: SocketAddr, start: u64, ids: &[VessId]) {
        let is_from_sync_peer = self.sync_peer == Some(addr);

        // Only accept chunks from the designated sync peer — junk chunks
        // from any other peer would permanently sabotage the sync by
        // guaranteeing a root mismatch.
        if !is_from_sync_peer { return; }

        if !ids.is_empty() {
            // Cap the sync buffer to prevent memory exhaustion from an
            // unbounded stream of chunks.
            if self.sync_buffer.len().saturating_add(ids.len()) > 50_000_000 {
                // Buffer full — abort sync, try a different peer.
                self.sync_peer = None;
                self.sync_target_root = None;
                self.sync_offset = 0;
                self.sync_buffer.clear();
                return;
            }
            // Buffer — do NOT insert into LMDB yet.
            for id in ids { self.sync_buffer.insert(*id); }

            self.sync_offset = start.saturating_add(ids.len() as u64);
        }

        // If chunk is smaller than requested, the peer finished sending.
        if (ids.len() as u32) < self.sync_chunk_size {
                // Verify buffered root against quorum consensus before committing.
                let mut sorted: Vec<VessId> = self.sync_buffer.iter().copied().collect();
                sorted.sort();
                let buffered_root = merkle_root(&sorted);

                let committed = {
                    // Require quorum: ≥2 peers must agree on the same
                    // (height, root) pair.  The sync_target_root is a
                    // hint for *which* peer to pull data from, not the
                    // source of truth — an eclipsed bootstrapping node
                    // would otherwise accept a fully fabricated UTXO set
                    // from a single attacker-controlled peer.
                    let quorum_ok = self.consensus_merkle()
                        .map(|(_, r, _)| r == buffered_root)
                        .unwrap_or(false);
                    if quorum_ok {
                        true
                    } else if self.blocks.is_empty() && self.peer_merkle.len() == 1 {
                        // Single-peer genesis fallback: only on first
                        // boot with no blocks and exactly one peer.
                        self.sync_target_root
                            .map(|r| r == buffered_root)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };

                if committed {
                    // Atomically replace LMDB with the verified buffer.
                    if let Ok(mut w) = self.env.write_txn() {
                        // Clear existing UTXOs
                        let existing: Vec<VessId> = self.vess_index.iter(&w).ok().into_iter().flatten()
                            .filter_map(|entry| entry.ok())
                            .filter_map(|(id, _)| id.try_into().ok())
                            .collect();
                        for id in existing { let _ = self.vess_index.delete(&mut w, &id); }
                        // Insert buffered
                        for id in &self.sync_buffer { let _ = self.vess_index.put(&mut w, id, &()); }
                        let _ = w.commit();
                    }
                    self.needs_sync = false;
                    self.sync_peer = None;
                    self.sync_target_root = None;
                    self.sync_offset = 0;
                    // Adopt consensus difficulty and height so new blocks
                    // pass validation. Without this, a freshly-synced node
                    // rejects every incoming block because current_difficulty
                    // is still the base/default value.
                    if let Some((height, _, diff)) = self.consensus_merkle() {
                        self.accepted_blocks = height;
                        self.current_difficulty = diff;
                        self.save_meta();
                    }
                } else {
                    // Root didn't verify — restart sync from a different peer.
                    self.sync_peer = None;
                    self.sync_target_root = None;
                    self.sync_offset = 0;
                }
                self.sync_buffer.clear();
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
        // Auto-ban peers with >5 strikes.  Ban per IP (not ip:port —
        // a new UDP source port is a new identity otherwise).
        let to_ban: Vec<SocketAddr> = self.peers.iter()
            .filter(|(a, _)| self.fails.get(a).copied().unwrap_or(0) > 5)
            .map(|(a, _)| *a)
            .collect();

        for a in to_ban {
            if a.ip().is_loopback() { continue; } // never ban localhost
            self.peers.remove(&a);
            self.banned_ips.insert(a.ip());
            // Persist ban: key = ip_bytes only (port omitted so a new
            // source port doesn't evade the ban).
            let key = match a.ip() {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            if let Ok(mut w) = self.env.write_txn() {
                let _ = self.ban_list.put(&mut w, &key, &());
                let _ = w.commit();
            }
        }
        // Decay strikes slowly — hours, not seconds.  A spammer sending
        // one invalid message every 2s would previously never be banned
        // because strikes reset at 1.5s intervals.
        if self.ticks.is_multiple_of(72_000) { // ~6 min at 5ms ticks
            for strikes in self.fails.values_mut() {
                *strikes = strikes.saturating_sub(1);
            }
            self.fails.retain(|_, s| *s > 0);
        }

        // Clean up unbounded maps.
        // missing_parents: entries for evicted orphans persist forever.
        // Prune entries whose children are no longer in the orphan cache.
        if self.ticks.is_multiple_of(6000) { // ~30 s
            self.missing_parents.retain(|_, children| {
                children.retain(|h| self.orphans.contains_key(h));
                !children.is_empty()
            });
        }
        // introduced_peers: only cleaned in nat_cycle (behind-NAT path).
        // Public nodes accumulate these forever.  Cull stale entries.
        if self.ticks.is_multiple_of(12_000) { // ~60 s
            self.introduced_peers.retain(|_, info| info.retries < HOLE_PUNCH_MAX_RETRIES);
        }
    }
}
