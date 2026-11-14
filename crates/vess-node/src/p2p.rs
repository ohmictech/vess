//! Peer sessions: inventory gossip, per-peer limits, and the in-process miner loop.
//!
//! Every peer relationship is a single long-lived TCP session. Both ends of a session announce
//! their tip with `INV` whenever it changes and relay transactions with `TX`; whichever side sees an
//! unknown tip pulls headers and blocks over the same socket. Receiving a well-formed request is
//! therefore not a special "server" mode — inbound and outbound sessions run identical code, and a
//! node that only lists peers (and is never dialled) still serves them.
//!
//! Untrusted peers are bounded three ways: a per-second frame budget, a score that is charged for
//! malformed or unsolicited traffic and ends the session when exhausted, and a short IP ban applied
//! when a session is closed for misbehaving.

use std::collections::HashSet;
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vess_net::secure::SecureStream;

use vess_core::codec::{Reader, Writer};
use vess_core::constants::{
    HANDSHAKE_TIMEOUT_MS, MAX_HEADERS_PER_MESSAGE, MAX_NETWORK_FRAME_BYTES, MAX_TRANSACTION_BYTES,
    P2P_MAGIC,
};
use vess_core::{AccountId, Hash, Transaction};
use vess_net::{
    NetError, Peer, SnapshotFrame, decode_headers, encode_headers, p2p_kind, read_frame,
    write_frame,
};

use crate::log::Level;
use crate::{Node, NodeError, log};

/// How far back a pull starts, so that a fork point is always included.
const SYNC_LOOKBACK: u64 = 32;
/// How often an idle session wakes up to announce and to notice a closed socket.
const SESSION_TICK_MS: u64 = 200;
/// Frames a peer may send per second before the session is closed.
const FRAME_BUDGET_PER_SECOND: u32 = 128;
/// Signature verifications one session may force per second.
///
/// Derived from our own relay behaviour rather than picked: a session announces at most
/// `MAX_ANNOUNCED_TRANSACTIONS` (32) per `SESSION_TICK_MS` (200 ms) tick, so an honest peer can push
/// about 160 verifications per second at peak. The budget is that plus 20% headroom, so honest relay is
/// never throttled, while a flood is. An ML-DSA-65 verification measured 370 us in release, so 192/s
/// caps one session at ~7% of a core (and the 32-session connection cap bounds the total). Frames over
/// the budget are dropped and charged to the peer's score, so a sustained flood ends the session.
const MAX_VERIFICATIONS_PER_SECOND: u32 = 192;
/// Score at which a session is closed and the address is banned.
const MAX_SCORE: u32 = 24;
/// Simultaneous inbound sessions.
const MAX_INBOUND_CONNECTIONS: usize = 32;
/// Simultaneous inbound sessions from a single address.
const MAX_INBOUND_PER_IP: usize = 4;
/// Transactions announced to one peer per wake-up.
/// Transactions announced per session tick. With `SESSION_TICK_MS = 200` this sets both the relay
/// throughput (~160 tx/s) and, via `MAX_VERIFICATIONS_PER_SECOND`, how much signature work one peer
/// can ask of us. A full 4 096-entry mempool therefore re-syncs in about 26 s.
const MAX_ANNOUNCED_TRANSACTIONS: usize = 32;
/// Seconds an address stays banned after a session was closed for misbehaviour.
const BAN_SECONDS: u64 = 60;
/// Header rounds per pull, which bounds the work a single announcement can cause.
const MAX_PULL_ROUNDS: usize = 64;
/// Blocks replayed per pull. A deep catch-up continues on the next resync tick instead of holding
/// the session for minutes.
const MAX_BLOCKS_PER_PULL: usize = 4_096;
/// Snapshot frames accepted from one peer for one snapshot.
const MAX_SNAPSHOT_FRAMES: usize = 4_096;
/// Time a request may stay unanswered before the session is dropped.
const REPLY_TIMEOUT_MS: u64 = 5_000;
/// How often a session re-checks whether the peer is still ahead of us. Announcements normally
/// trigger a pull, but this recovers from a missed or failed one on an otherwise idle chain.
const RESYNC_INTERVAL_MS: u64 = 2_000;

/// Addresses this node refuses to talk to, and until when.
///
/// Persisted to `<datadir>/bans.txt`, because a ban that a restart forgets is barely a ban: a
/// flooding peer would simply reconnect after the next `systemctl restart`. Times are stored as unix
/// seconds rather than an `Instant` so the file means something across runs.
#[derive(Default)]
pub struct Bans {
    entries: Mutex<Vec<(IpAddr, u64)>>,
    path: Mutex<Option<PathBuf>>,
}

impl Bans {
    /// Load the book from `path` if it exists, and remember where to write it back.
    pub fn load(path: PathBuf) -> Bans {
        let mut entries = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let mut parts = line.split_whitespace();
                let (Some(addr), Some(until)) = (parts.next(), parts.next()) else {
                    continue;
                };
                let (Ok(ip), Ok(until)) = (addr.parse::<IpAddr>(), until.parse::<u64>()) else {
                    continue;
                };
                if ip.is_loopback() {
                    // Never load a loopback ban: a local cluster must not be able to lock itself out,
                    // and an old file should not be able to do it either.
                    continue;
                }
                entries.push((ip, until));
            }
        }
        Bans {
            entries: Mutex::new(entries),
            path: Mutex::new(Some(path)),
        }
    }

    /// Ban `ip` for `seconds`. Loopback is never banned, and never written.
    pub fn ban(&self, ip: IpAddr, seconds: u64, now: u64) {
        if ip.is_loopback() {
            return;
        }
        let changed = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let until = now.saturating_add(seconds);
            match entries.iter_mut().find(|(known, _)| *known == ip) {
                Some(entry) => entry.1 = entry.1.max(until),
                None => entries.push((ip, until)),
            }
            true
        };
        if changed {
            self.persist();
        }
    }

    /// Is `ip` banned right now? Expired entries are dropped as a side effect.
    pub fn banned(&self, ip: IpAddr, now: u64) -> bool {
        if ip.is_loopback() {
            return false;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let before = entries.len();
        entries.retain(|(_, until)| *until > now);
        let dropped = entries.len() != before;
        let banned = entries.iter().any(|(known, _)| *known == ip);
        drop(entries);
        if dropped {
            self.persist();
        }
        banned
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the book out, temp file plus rename, so a crash cannot leave half a line.
    pub fn persist(&self) {
        let path = self.path.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(path) = path else { return };
        let body: String = {
            let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            entries
                .iter()
                .map(|(ip, until)| format!("{ip} {until}\n"))
                .collect()
        };
        let temp = path.with_extension("tmp");
        if std::fs::write(&temp, body).is_ok() {
            let _ = std::fs::rename(&temp, &path);
        }
    }
}

/// Open peer sessions and the caps on them. Owned by a `Node` rather than the process: a cap on
/// concurrent sessions is a per-node property, and two nodes in one process (the tests) must not
/// spend each other's budget.
#[derive(Default)]
pub struct Connections {
    inbound: AtomicUsize,
    outbound: AtomicUsize,
    by_ip: Mutex<Vec<(IpAddr, usize)>>,
    /// Bans live here because every path that needs them (accept, session, dial) already has the
    /// node's connection state.
    bans: Bans,
}

impl Connections {
    /// Open sessions right now, reported by `STATUS`.
    pub fn counts(&self) -> (usize, usize) {
        (
            self.inbound.load(Ordering::Relaxed),
            self.outbound.load(Ordering::Relaxed),
        )
    }

    /// Take one inbound slot, or refuse the connection when the node or the address is at its cap.
    pub fn inbound(self: &Arc<Self>, ip: Option<IpAddr>) -> Option<InboundGuard> {
        if self.inbound.fetch_add(1, Ordering::Relaxed) >= MAX_INBOUND_CONNECTIONS {
            self.inbound.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        if let Some(ip) = ip
            && !self.ip_slots(ip, 1)
        {
            self.inbound.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(InboundGuard {
            conn: self.clone(),
            ip,
        })
    }

    /// Take one outbound slot. Outbound sessions are ours, so this only counts them.
    pub fn outbound(self: &Arc<Self>) -> OutboundGuard {
        self.outbound.fetch_add(1, Ordering::Relaxed);
        OutboundGuard { conn: self.clone() }
    }

    /// Load the persisted ban list from `path`.
    pub fn load_bans(&mut self, path: PathBuf) {
        self.bans = Bans::load(path);
    }

    pub fn bans(&self) -> &Bans {
        &self.bans
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.bans.banned(ip, now_unix())
    }

    pub fn ban(&self, ip: IpAddr) {
        self.bans.ban(ip, BAN_SECONDS, now_unix());
    }

    pub fn ban_count(&self) -> usize {
        // Drop expired entries first, so the reported number is current.
        self.bans
            .banned(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), now_unix());
        self.bans.len()
    }

    /// Take (`delta = 1`) or release (`delta = -1`) one inbound slot for `ip`.
    fn ip_slots(&self, ip: IpAddr, delta: isize) -> bool {
        if ip.is_loopback() {
            // A local cluster puts every peer on one address; capping it would refuse real peers.
            return true;
        }
        let mut slots = self.by_ip.lock().unwrap_or_else(|e| e.into_inner());
        let index = slots.iter().position(|(known, _)| *known == ip);
        match (index, delta) {
            (Some(index), 1) => {
                if slots[index].1 >= MAX_INBOUND_PER_IP {
                    return false;
                }
                slots[index].1 += 1;
                true
            }
            (Some(index), _) => {
                slots[index].1 = slots[index].1.saturating_sub(1);
                if slots[index].1 == 0 {
                    slots.remove(index);
                }
                true
            }
            (None, 1) => {
                slots.push((ip, 1));
                true
            }
            (None, _) => true,
        }
    }
}

/// What handling one frame asks the session to do next.
enum Action {
    None,
    /// The peer announced a tip we do not have; pull from it.
    Pull(u64),
    /// A compact block could not be rebuilt here; fetch this block in full.
    FetchFull(Hash),
    /// The peer should be dropped, and banned when it is not a protocol-level goodbye.
    Fatal(&'static str),
}

/// Per-session bookkeeping. Reset on reconnect, so a reconnected peer is re-announced everything.
#[derive(Default)]
struct PeerState {
    announced_tip: Option<Hash>,
    sent: HashSet<Hash>,
    score: u32,
    frames: u32,
    verifications: u32,
    window: Option<Instant>,
    warned_pruned: bool,
    /// The address this peer can be dialled at, as far as we can tell.
    peer_addr: Option<String>,
    /// Whether the peer is on loopback, which decides whether its gossip may contain local addresses.
    peer_is_local: bool,
}

impl PeerState {
    /// Count one inbound frame; false when the peer is over budget.
    fn note_frame(&mut self) -> bool {
        let now = Instant::now();
        match self.window {
            Some(start) if now.duration_since(start) < Duration::from_secs(1) => {
                self.frames += 1;
                self.frames <= FRAME_BUDGET_PER_SECOND
            }
            _ => {
                self.window = Some(now);
                self.frames = 1;
                self.verifications = 0;
                true
            }
        }
    }

    /// Take one signature-verification slot from this session's per-second budget.
    fn note_verification(&mut self) -> bool {
        self.verifications += 1;
        self.verifications <= MAX_VERIFICATIONS_PER_SECOND
    }

    /// Charge the peer; false when the session must end.
    fn penalise(&mut self, points: u32) -> bool {
        self.score = self.score.saturating_add(points);
        self.score < MAX_SCORE
    }
}

pub struct InboundGuard {
    conn: Arc<Connections>,
    ip: Option<IpAddr>,
}

pub struct OutboundGuard {
    conn: Arc<Connections>,
}

impl Drop for InboundGuard {
    fn drop(&mut self) {
        self.conn.inbound.fetch_sub(1, Ordering::Relaxed);
        if let Some(ip) = self.ip {
            self.conn.ip_slots(ip, -1);
        }
    }
}

impl Drop for OutboundGuard {
    fn drop(&mut self) {
        self.conn.outbound.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Short hex, so a block id does not dominate a log record.
fn hex_short(id: &Hash) -> String {
    id[..6].iter().map(|byte| format!("{byte:02x}")).collect()
}

fn lock(node: &Arc<Mutex<Node>>) -> std::sync::MutexGuard<'_, Node> {
    match node.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn decode_hash(payload: &[u8]) -> Option<Hash> {
    payload.try_into().ok()
}

/// Bytes of a compact short id. Not consensus: it only names a transaction inside one announcement.
const SHORT_ID_BYTES: usize = 6;

/// A short transaction id, salted with the block id so ids cannot be precomputed across blocks.
fn short_id(salt: &Hash, txid: &Hash) -> [u8; SHORT_ID_BYTES] {
    let digest = vess_core::hash::tagged(b"VESS-COMPACT-BLOCK-V1", &[salt, txid]);
    let mut out = [0u8; SHORT_ID_BYTES];
    out.copy_from_slice(&digest[..SHORT_ID_BYTES]);
    out
}

fn encode_compact(
    height: u64,
    header: &vess_core::BlockHeader,
    ids: &[[u8; SHORT_ID_BYTES]],
) -> Vec<u8> {
    let mut w = Writer::with_capacity(8 + 234 + 4 + ids.len() * SHORT_ID_BYTES);
    w.u64(height);
    w.fixed(&header.canonical());
    w.u32(ids.len() as u32);
    for id in ids {
        w.fixed(id);
    }
    w.into_vec()
}

fn decode_compact(
    payload: &[u8],
) -> Result<(u64, vess_core::BlockHeader, Vec<[u8; SHORT_ID_BYTES]>), String> {
    let mut reader = Reader::new(payload);
    let height = reader
        .u64()
        .map_err(|_| "malformed CMPCTBLOCK".to_string())?;
    let header = vess_core::BlockHeader::decode(
        reader
            .bytes(vess_core::constants::BLOCK_HEADER_BYTES)
            .map_err(|_| "malformed CMPCTBLOCK".to_string())?,
    )
    .map_err(|_| "malformed CMPCTBLOCK".to_string())?;
    let count = reader
        .u32()
        .map_err(|_| "malformed CMPCTBLOCK".to_string())? as usize;
    if count > reader.remaining() / SHORT_ID_BYTES {
        return Err("malformed CMPCTBLOCK".into());
    }
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let raw = reader
            .bytes(SHORT_ID_BYTES)
            .map_err(|_| "malformed CMPCTBLOCK".to_string())?;
        let mut id = [0u8; SHORT_ID_BYTES];
        id.copy_from_slice(raw);
        ids.push(id);
    }
    Ok((height, header, ids))
}

/// Try to rebuild a block body from our own mempool.
///
/// Returns `None` when a transaction is missing, which is the normal case for a node that has not
/// seen everything the miner has.
fn reconstruct(
    node: &Arc<Mutex<Node>>,
    header: &vess_core::BlockHeader,
    ids: &[[u8; SHORT_ID_BYTES]],
) -> Option<Vec<u8>> {
    let pending = { lock(node).pending_transactions() };
    let mut by_short: std::collections::HashMap<[u8; SHORT_ID_BYTES], Transaction> =
        std::collections::HashMap::with_capacity(pending.len());
    for tx in pending {
        by_short
            .entry(short_id(&header.id(), &tx.id()))
            .or_insert(tx);
    }
    let mut transactions = Vec::with_capacity(ids.len());
    for id in ids {
        transactions.push(by_short.get(id)?.clone());
    }

    let body = vess_consensus::encode_body(&transactions).ok()?;
    let mut bytes = header.canonical().to_vec();
    bytes.extend_from_slice(&body);
    Some(bytes)
}

/// Encode as many pending transactions as fit in one frame.
///
/// A full pool can exceed `MAX_NETWORK_FRAME_BYTES`, and `write_frame` fails rather than truncating,
/// which would drop the session. The count prefix makes a prefix a well-formed reply.
fn encode_pending(transactions: &[Transaction]) -> Vec<u8> {
    let budget = MAX_NETWORK_FRAME_BYTES.saturating_sub(4);
    let mut body: Vec<u8> = Vec::new();
    let mut count = 0u32;
    for tx in transactions {
        let bytes = tx.canonical();
        if body.len() + bytes.len() > budget {
            break;
        }
        body.extend_from_slice(&bytes);
        count += 1;
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn decode_pending(payload: &[u8]) -> Vec<Transaction> {
    let mut reader = Reader::new(payload);
    let Ok(count) = reader.u32() else {
        return Vec::new();
    };
    let mut transactions = Vec::new();
    for _ in 0..count {
        match Transaction::decode_from(&mut reader, MAX_TRANSACTION_BYTES) {
            Ok(tx) => transactions.push(tx),
            Err(_) => break,
        }
    }
    transactions
}

fn submit(node: &Arc<Mutex<Node>>, tx: Transaction) -> bool {
    // Signature verification is the expensive part of admitting a transaction (~370 us) and needs
    // no node state. Doing it before the lock keeps one peer's traffic from serialising every other
    // session's verification, mining, and RPC on the node mutex.
    let network = lock(node).network_profile();
    let checked = match &tx {
        Transaction::Transfer(t) => Node::check_transfer(network, t),
        Transaction::StateUpdate(t) => Node::check_state_update(network, t),
    };
    if checked.is_err() {
        return false;
    }
    let mut guard = lock(node);
    match tx {
        Transaction::Transfer(t) => guard.apply_transfer(t).is_ok(),
        Transaction::StateUpdate(t) => guard.apply_state_update(t).is_ok(),
    }
}

/// Accept inbound sessions until the process ends.
pub fn serve(node: Arc<Mutex<Node>>, listener: TcpListener, listen_port: u16) {
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        let ip = stream.peer_addr().map(|a| a.ip()).ok();
        let conn = lock(&node).connections();
        if let Some(ip) = ip
            && conn.is_banned(ip)
        {
            continue;
        }
        let Some(guard) = conn.inbound(ip) else {
            continue;
        };
        let node = node.clone();
        std::thread::spawn(move || {
            if let Err(why) = session(node, stream, listen_port, ip, false, None, Some(guard)) {
                crate::log_debug!("p2p", "inbound session ended: {why}");
            }
        });
    }
}

/// Keep one outbound session per configured peer, forever.
pub fn poll(node: Arc<Mutex<Node>>, addrs: Vec<String>, interval: Duration, listen_port: u16) {
    let pause = interval.max(Duration::from_millis(50));
    // Configured peers are registered before the crawler starts, so it can never spend its one dial
    // on a peer the seed loops are already about to connect to.
    let connected = Arc::new(Mutex::new(addrs.clone()));
    let conn = lock(&node).connections();
    {
        let node = node.clone();
        let connected = connected.clone();
        std::thread::spawn(move || crawl(node, connected, listen_port, pause));
    }
    for addr in addrs {
        let node = node.clone();
        let conn = conn.clone();
        std::thread::spawn(move || {
            loop {
                let started = Instant::now();
                if let Ok(stream) = vess_net::connect(&addr) {
                    let ip = stream.peer_addr().map(|a| a.ip()).ok();
                    let _guard = conn.outbound();
                    if let Err(why) = session(
                        node.clone(),
                        stream,
                        listen_port,
                        ip,
                        true,
                        Some(addr.clone()),
                        None,
                    ) {
                        crate::log_debug!("p2p", "outbound session to {addr} ended: {why}");
                    }
                }
                // A session that ended immediately (refused, banned, wrong chain) is retried
                // slowly; one that lived a while reconnects at once.
                if started.elapsed() < Duration::from_secs(1) {
                    std::thread::sleep(pause);
                }
            }
        });
    }
    loop {
        std::thread::sleep(Duration::from_secs(3_600));
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Ask a fresh peer for addresses when we know too few. Fire and forget: the reply arrives whenever it
/// arrives and is handled by `dispatch`, because a separate read loop here would race with ordinary
/// traffic (an `INV` or `PING` can arrive before the `ADDR`).
fn request_addresses(node: &Arc<Mutex<Node>>, stream: &mut SecureStream) {
    let (known, verified) = lock(node).peer_book_size();
    if verified >= crate::peers::GOSSIP_THRESHOLD {
        return;
    }
    let mut w = Writer::new();
    w.u32(crate::peers::GOSSIP_FANOUT as u32);
    if write_frame(stream, P2P_MAGIC, p2p_kind::GET_ADDR, w.as_slice()).is_ok() {
        crate::log_debug!(
            "peers",
            "asked a peer for addresses ({known} known, {verified} verified)"
        );
    }
}

fn answer_addr_request(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    peer_addr: Option<&str>,
    payload: &[u8],
) -> Result<(), String> {
    let mut r = Reader::new(payload);
    let wanted = r.u32().unwrap_or(0) as usize;
    if wanted == 0 {
        return Ok(());
    }
    let entries = lock(node).gossip_peers(peer_addr.unwrap_or(""), wanted);
    write_frame(
        stream,
        P2P_MAGIC,
        p2p_kind::ADDR,
        &vess_net::encode_addresses(&entries),
    )
    .map_err(|e| e.to_string())
}

/// Run one peer session to completion.
fn session(
    node: Arc<Mutex<Node>>,
    stream: TcpStream,
    listen_port: u16,
    ip: Option<IpAddr>,
    outbound: bool,
    dialled: Option<String>,
    _inbound: Option<InboundGuard>,
) -> Result<(), String> {
    // A peer that connects and then says nothing (or speaks plaintext, whose first two bytes look
    // like a huge record length) must not hold a session slot forever, so the Noise handshake has its
    // own deadline before the ordinary session timeout takes over.
    stream
        .set_read_timeout(Some(Duration::from_millis(HANDSHAKE_TIMEOUT_MS)))
        .map_err(|e| e.to_string())?;
    // Everything from here on is inside the Noise session: the peer handshake included.
    let (secret, chain, conn) = {
        let guard = lock(&node);
        (
            *guard.identity_secret(),
            guard.chain_id(),
            guard.connections(),
        )
    };
    let (mut stream, peer_key) = if outbound {
        SecureStream::connect(stream, &secret, &chain)
    } else {
        SecureStream::accept(stream, &secret, &chain)
    }
    .map_err(|e| format!("noise handshake: {e}"))?;
    crate::log_debug!("p2p", "encrypted session with key {}", hex32(&peer_key));
    stream
        .set_read_timeout(SESSION_TICK_MS)
        .map_err(|e| e.to_string())?;
    let theirs = handshake(&node, &mut stream, listen_port, outbound)?;

    // The handshake proved this address belongs to that key, so the book may now advertise it.
    let peer_addr = match (&dialled, ip) {
        (Some(addr), _) => Some(addr.clone()),
        (None, Some(ip)) if theirs.listen_port != 0 => Some(format!("{ip}:{}", theirs.listen_port)),
        _ => None,
    };
    let ours_is_local = ip.map(|ip| ip.is_loopback()).unwrap_or(false);
    if let Some(addr) = &peer_addr {
        // Pinning: an address we have already verified has a key we proved, and a peer presenting a
        // different one is not that peer — a first-contact MITM cannot continue once we know better.
        // Dropping the session here keeps the wrong key out of the book and out of every later
        // handshake, at the cost of refusing a peer that legitimately wiped its identity file (the
        // operator deletes the record in that case).
        let pinned = lock(&node).peer_pinned(addr, &peer_key);
        if !pinned {
            crate::log_debug!(
                "p2p",
                "refusing {addr}: presented key {} does not match the pinned one",
                hex32(&peer_key)
            );
            lock(&node).record_peer_failure(addr);
            return Err("peer key does not match the pinned key".into());
        }
        let now = now_unix();
        lock(&node).record_peer_success(addr, peer_key, now);
    }
    let mut state = PeerState {
        peer_addr: peer_addr.clone(),
        peer_is_local: ours_is_local,
        ..PeerState::default()
    };
    request_addresses(&node, &mut stream);
    let mut their_height = theirs.best_height;
    let their_oldest_body = theirs.oldest_body_height;
    let mut next_resync = Instant::now() + Duration::from_millis(RESYNC_INTERVAL_MS);
    loop {
        announce(&node, &mut stream, &mut state)?;

        // Announcements usually start a pull, but a missed or failed one would otherwise leave a
        // node stuck behind a peer that has stopped producing blocks. Re-check on a timer.
        if Instant::now() >= next_resync {
            next_resync = Instant::now() + Duration::from_millis(RESYNC_INTERVAL_MS);
            if lock(&node).height() < their_height
                && pull(
                    &node,
                    &mut stream,
                    their_height,
                    their_oldest_body,
                    &mut state,
                )
                .is_err()
            {
                return Ok(());
            }
        }
        match read_frame(&mut stream, P2P_MAGIC, MAX_NETWORK_FRAME_BYTES) {
            Ok((kind, payload)) => {
                if !state.note_frame() {
                    let _ = write_frame(&mut stream, P2P_MAGIC, p2p_kind::DISCONNECT, &[]);
                    if let Some(ip) = ip {
                        conn.ban(ip);
                    }
                    return Err("peer exceeded the frame budget".into());
                }
                match dispatch(&node, &mut stream, kind, &payload, &mut state) {
                    Ok(Action::None) => {}
                    Ok(Action::Pull(height)) => {
                        their_height = their_height.max(height);
                        if pull(
                            &node,
                            &mut stream,
                            their_height,
                            their_oldest_body,
                            &mut state,
                        )
                        .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Ok(Action::FetchFull(id)) => {
                        if fetch_full(&node, &mut stream, &id, &mut state).is_err() {
                            return Ok(());
                        }
                    }
                    Ok(Action::Fatal(why)) => {
                        let _ = write_frame(&mut stream, P2P_MAGIC, p2p_kind::DISCONNECT, &[]);
                        if let Some(ip) = ip {
                            conn.ban(ip);
                        }
                        return Err(why.into());
                    }
                    Err(why) => return Err(why),
                }
            }
            Err(NetError::Timeout) => {}
            Err(_) => return Ok(()),
        }
    }
}

fn handshake(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    listen_port: u16,
    outbound: bool,
) -> Result<vess_net::Handshake, String> {
    let ours = { lock(node).handshake(listen_port) };

    if outbound {
        write_frame(stream, P2P_MAGIC, p2p_kind::HELLO, &ours.encode())
            .map_err(|e| e.to_string())?;
        let (kind, payload) =
            read_frame(stream, P2P_MAGIC, MAX_NETWORK_FRAME_BYTES).map_err(|e| e.to_string())?;
        if kind != p2p_kind::HELLO_ACK && kind != p2p_kind::HELLO {
            return Err("expected HELLO_ACK".into());
        }
        let mut reader = Reader::new(&payload);
        let theirs = vess_net::Handshake::decode(&mut reader).map_err(|e| e.to_string())?;
        vess_net::check_handshake(&ours, &theirs).map_err(|e| e.to_string())?;
        if kind == p2p_kind::HELLO {
            write_frame(stream, P2P_MAGIC, p2p_kind::HELLO_ACK, &ours.encode())
                .map_err(|e| e.to_string())?;
        }
        Ok(theirs)
    } else {
        let (kind, payload) =
            read_frame(stream, P2P_MAGIC, MAX_NETWORK_FRAME_BYTES).map_err(|e| e.to_string())?;
        if kind != p2p_kind::HELLO {
            return Err("expected HELLO".into());
        }
        let mut reader = Reader::new(&payload);
        let theirs = vess_net::Handshake::decode(&mut reader).map_err(|e| e.to_string())?;
        vess_net::check_handshake(&ours, &theirs).map_err(|e| e.to_string())?;
        write_frame(stream, P2P_MAGIC, p2p_kind::HELLO_ACK, &ours.encode())
            .map_err(|e| e.to_string())?;
        Ok(theirs)
    }
}

/// Tell the peer where our chain ends and what we have pending.
///
/// A new tip is announced as a compact block: the header plus six-byte short ids for its
/// transactions. A peer that already has those transactions in its mempool rebuilds the block from
/// them and validates it with no extra round trip; a peer that is missing any of them asks for the
/// full body instead. Six bytes is enough because the header id salts every id and a collision only
/// costs a fallback.
fn announce(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    state: &mut PeerState,
) -> Result<(), String> {
    let (height, tip) = {
        let guard = lock(node);
        (guard.height(), guard.tip().id())
    };
    if state.announced_tip != Some(tip) {
        let body = { lock(node).block_body(&tip) };
        match body {
            Some(bytes) => {
                let (header, transactions) =
                    vess_consensus::split_block(&bytes).map_err(|e| e.to_string())?;
                let ids: Vec<[u8; SHORT_ID_BYTES]> = transactions
                    .iter()
                    .map(|tx| short_id(&tip, &tx.id()))
                    .collect();
                write_frame(
                    stream,
                    P2P_MAGIC,
                    p2p_kind::CMPCTBLOCK,
                    &encode_compact(height, &header, &ids),
                )
                .map_err(|e| e.to_string())?
            }
            // A pruned or unknown body falls back to the plain announcement.
            None => {
                let mut w = Writer::new();
                w.u64(height);
                w.fixed(&tip);
                write_frame(stream, P2P_MAGIC, p2p_kind::INV, w.as_slice())
                    .map_err(|e| e.to_string())?
            }
        }
        state.announced_tip = Some(tip);
    }

    let pending = { lock(node).pending_transactions() };
    let mut sent = 0usize;
    for tx in pending {
        if sent >= MAX_ANNOUNCED_TRANSACTIONS {
            break;
        }
        let id = tx.id();
        if state.sent.contains(&id) {
            continue;
        }
        write_frame(stream, P2P_MAGIC, p2p_kind::TX, &tx.canonical()).map_err(|e| e.to_string())?;
        state.sent.insert(id);
        sent += 1;
    }

    // Forget what can never be announced again, so the set does not grow without bound.
    if state.sent.len() > MAX_ANNOUNCED_TRANSACTIONS * 8 {
        let live: HashSet<Hash> = {
            lock(node)
                .pending_transactions()
                .iter()
                .map(|t| t.id())
                .collect()
        };
        state.sent.retain(|id| live.contains(id));
    }
    Ok(())
}

/// Handle one inbound frame: serve it, or ask the session to pull, or drop the peer.
fn dispatch(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    kind: u16,
    payload: &[u8],
    state: &mut PeerState,
) -> Result<Action, String> {
    let reply = |stream: &mut SecureStream, kind: u16, payload: &[u8]| {
        write_frame(stream, P2P_MAGIC, kind, payload).map_err(|e| e.to_string())
    };

    match kind {
        p2p_kind::INV => {
            let mut reader = Reader::new(payload);
            let height = reader.u64().map_err(|_| "malformed INV".to_string())?;
            let id: Hash = reader.array().map_err(|_| "malformed INV".to_string())?;
            let ours = {
                let guard = lock(node);
                (guard.height(), guard.chain().contains(&id))
            };
            if ours.1 || height < ours.0 {
                return Ok(Action::None);
            }
            Ok(Action::Pull(height))
        }
        p2p_kind::CMPCTBLOCK => {
            let (height, header, ids) = decode_compact(payload)?;
            let id = header.id();
            {
                let guard = lock(node);
                if guard.chain().contains(&id) {
                    return Ok(Action::None);
                }
                if !guard.chain().contains(&header.previous_block_id) {
                    // We are missing history, not this block: fall back to a normal pull.
                    return Ok(Action::Pull(height));
                }
            }

            // Rebuild from the mempool. Any miss, collision, or validation failure falls back to a
            // full download, so a lying peer cannot get a bad block accepted.
            if let Some(bytes) = reconstruct(node, &header, &ids)
                && lock(node).accept_block(&bytes).is_ok()
            {
                return Ok(Action::None);
            }
            Ok(Action::FetchFull(id))
        }
        p2p_kind::GET_HEADERS => {
            let mut reader = Reader::new(payload);
            let from = reader
                .u64()
                .map_err(|_| "malformed GET_HEADERS".to_string())?;
            let max = reader
                .u32()
                .map_err(|_| "malformed GET_HEADERS".to_string())?
                .min(MAX_HEADERS_PER_MESSAGE as u32) as usize;
            let headers = { lock(node).headers_from(from, max) };
            reply(stream, p2p_kind::HEADERS, &encode_headers(&headers))?;
            Ok(Action::None)
        }
        // Only meaningful as a reply, which `recv_until` intercepts.
        p2p_kind::HEADERS | p2p_kind::PENDING => {
            if !state.penalise(1) {
                return Ok(Action::Fatal("unsolicited reply"));
            }
            Ok(Action::None)
        }
        p2p_kind::GET_BLOCK => {
            let id = decode_hash(payload).ok_or("malformed GET_BLOCK")?;
            let body = { lock(node).block_body(&id) };
            match body {
                Some(bytes) => {
                    let mut w = Writer::new();
                    let _ = w.var_bytes(&bytes);
                    reply(stream, p2p_kind::BLOCK, w.as_slice())?;
                }
                None => reply(stream, p2p_kind::NOT_FOUND, &[])?,
            }
            Ok(Action::None)
        }
        p2p_kind::BLOCK => {
            let mut reader = Reader::new(payload);
            let bytes = reader
                .var_bytes(MAX_NETWORK_FRAME_BYTES)
                .map_err(|_| "malformed BLOCK".to_string())?;
            let accepted = { lock(node).accept_block(bytes).is_ok() };
            if !accepted && !state.penalise(1) {
                return Ok(Action::Fatal("too many rejected blocks"));
            }
            Ok(Action::None)
        }
        p2p_kind::TX => {
            let mut reader = Reader::new(payload);
            let Ok(tx) = Transaction::decode_from(&mut reader, MAX_TRANSACTION_BYTES) else {
                if !state.penalise(1) {
                    return Ok(Action::Fatal("malformed transaction"));
                }
                return Ok(Action::None);
            };
            if !state.note_verification() {
                if !state.penalise(1) {
                    return Ok(Action::Fatal("too many transactions"));
                }
                return Ok(Action::None);
            }
            let _ = submit(node, tx);
            Ok(Action::None)
        }
        p2p_kind::GET_PENDING => {
            let pending = { lock(node).pending_transactions() };
            reply(stream, p2p_kind::PENDING, &encode_pending(&pending))?;
            Ok(Action::None)
        }
        p2p_kind::GET_ADDR => {
            answer_addr_request(node, stream, state.peer_addr.as_deref(), payload)?;
            Ok(Action::None)
        }
        p2p_kind::ADDR => {
            // Unsolicited or late gossip is normal; it is unauthenticated and cheap, so it is only
            // learned, never trusted, and never fatal.
            if let Ok(entries) = vess_net::decode_addresses(payload) {
                lock(node).learn_peers(&entries, state.peer_is_local, now_unix());
            } else if !state.penalise(1) {
                return Ok(Action::Fatal("malformed address list"));
            }
            Ok(Action::None)
        }
        p2p_kind::GET_STATE => {
            // Any node can answer this, pruned or not: the snapshot is the live state.
            let frames = { lock(node).snapshot_frames() };
            for frame in frames {
                write_frame(stream, P2P_MAGIC, p2p_kind::STATE, &frame)
                    .map_err(|e| e.to_string())?;
            }
            Ok(Action::None)
        }
        p2p_kind::STATE => {
            // Replies are consumed by `recv_until`; a stray one is a protocol error.
            if !state.penalise(1) {
                return Ok(Action::Fatal("unsolicited snapshot frame"));
            }
            Ok(Action::None)
        }
        p2p_kind::PING => {
            reply(stream, p2p_kind::PONG, payload)?;
            Ok(Action::None)
        }
        p2p_kind::PONG => Ok(Action::None),
        p2p_kind::DISCONNECT => Err("peer disconnected".into()),
        other => {
            let _ = other;
            if !state.penalise(2) {
                return Ok(Action::Fatal("unknown message kind"));
            }
            Ok(Action::None)
        }
    }
}

/// Read frames until `want` arrives, serving whatever else the peer sends meanwhile.
fn recv_until(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    want: u16,
    state: &mut PeerState,
) -> Result<Option<Vec<u8>>, String> {
    let deadline = Instant::now() + Duration::from_millis(REPLY_TIMEOUT_MS);
    loop {
        if Instant::now() > deadline {
            return Err("peer did not answer".into());
        }
        match read_frame(stream, P2P_MAGIC, MAX_NETWORK_FRAME_BYTES) {
            Ok((kind, payload)) => {
                if kind == want {
                    return Ok(Some(payload));
                }
                if kind == p2p_kind::NOT_FOUND {
                    return Ok(None);
                }
                if !state.note_frame() {
                    return Err("peer exceeded the frame budget".into());
                }
                if let Action::Fatal(why) = dispatch(node, stream, kind, &payload, state)? {
                    return Err(why.into());
                }
            }
            Err(NetError::Timeout) => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Ask for one block in full and accept it.
fn fetch_full(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    id: &Hash,
    state: &mut PeerState,
) -> Result<bool, String> {
    write_frame(stream, P2P_MAGIC, p2p_kind::GET_BLOCK, id).map_err(|e| e.to_string())?;
    let Some(payload) = recv_until(node, stream, p2p_kind::BLOCK, state)? else {
        return Ok(false);
    };
    let mut reader = Reader::new(&payload);
    let bytes = reader
        .var_bytes(MAX_NETWORK_FRAME_BYTES)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        return Ok(false);
    }
    Ok(lock(node).accept_block(bytes).is_ok())
}

/// Pull everything the peer has that we do not.
///
/// Two phases, because they answer different questions. Headers are validated first as a chain, so
/// we know the peer's tip and its work without trusting any body. Then the *state* is filled: either
/// by replaying bodies, or — when the peer no longer has them — by installing a snapshot that is
/// checked against the `state_root` of a header we just validated ourselves.
fn pull(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    their_height: u64,
    their_oldest_body: u64,
    state: &mut PeerState,
) -> Result<usize, String> {
    // The normal path replays blocks the way they arrive, so the state never lags the chain. The
    // snapshot path is only for the case that path cannot handle: the peer no longer has our history.
    if !need_snapshot(node, their_oldest_body) {
        return pull_blocks(node, stream, their_height, state);
    }

    let applied = pull_headers(node, stream, their_height, state)?;
    match install_snapshot_from(node, stream, state) {
        Ok(true) => {}
        Ok(false) => {}
        // A snapshot that is merely ahead of our headers resolves on the next pull, so it is logged
        // rather than warned about, once per session.
        Err(SnapshotIssue::Retry(why)) => {
            if !state.warned_pruned {
                state.warned_pruned = true;
                log::record(
                    Level::Debug,
                    "sync",
                    &format!("{why}; will retry after the next header sync"),
                );
            }
            return Ok(applied);
        }
        Err(SnapshotIssue::Reject(why)) => {
            if !state.warned_pruned {
                state.warned_pruned = true;
                log::record(Level::Warn, "sync", &why);
            }
            return Ok(applied);
        }
    }
    // The snapshot lands on the peer's tip, which is where headers put us; anything that arrived in
    // between is fetched as ordinary blocks.
    let applied = applied + pull_blocks(node, stream, their_height, state)?;
    Ok(applied)
}

/// Header-only catch-up: validates the peer's whole chain (work, targets, timestamps) without
/// fetching a single body. This is what a snapshot is anchored to.
fn pull_headers(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    their_height: u64,
    state: &mut PeerState,
) -> Result<usize, String> {
    let mut added_total = 0usize;
    for _ in 0..MAX_PULL_ROUNDS {
        let from = { lock(node).height() }.saturating_sub(SYNC_LOOKBACK);
        let mut w = Writer::new();
        w.u64(from);
        w.u32(MAX_HEADERS_PER_MESSAGE as u32);
        write_frame(stream, P2P_MAGIC, p2p_kind::GET_HEADERS, w.as_slice())
            .map_err(|e| e.to_string())?;

        let Some(payload) = recv_until(node, stream, p2p_kind::HEADERS, state)? else {
            break;
        };
        let headers = decode_headers(&payload).map_err(|e| e.to_string())?;
        if headers.is_empty() {
            break;
        }
        let mut added = 0usize;
        for header in headers {
            let unknown = !{ lock(node).chain().contains(&header.id()) };
            if unknown {
                lock(node)
                    .insert_header_only(header)
                    .map_err(|e| e.to_string())?;
                added += 1;
            }
        }
        added_total += added;
        if added == 0 || lock(node).height() >= their_height {
            break;
        }
    }
    Ok(added_total)
}

/// Fetch blocks in the order the peer offers them, which keeps the state in step with the chain.
fn pull_blocks(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    their_height: u64,
    state: &mut PeerState,
) -> Result<usize, String> {
    let mut applied = 0usize;
    for _ in 0..MAX_PULL_ROUNDS {
        let from = { lock(node).height() }.saturating_sub(SYNC_LOOKBACK);
        let mut w = Writer::new();
        w.u64(from);
        w.u32(MAX_HEADERS_PER_MESSAGE as u32);
        write_frame(stream, P2P_MAGIC, p2p_kind::GET_HEADERS, w.as_slice())
            .map_err(|e| e.to_string())?;

        let Some(payload) = recv_until(node, stream, p2p_kind::HEADERS, state)? else {
            break;
        };
        let headers = decode_headers(&payload).map_err(|e| e.to_string())?;
        if headers.is_empty() {
            break;
        }

        let mut progress = 0usize;
        for header in headers {
            let id = header.id();
            if { lock(node).chain().contains(&id) } && !{ lock(node).needs_body(&id) } {
                continue;
            }
            write_frame(stream, P2P_MAGIC, p2p_kind::GET_BLOCK, &id).map_err(|e| e.to_string())?;
            let Some(payload) = recv_until(node, stream, p2p_kind::BLOCK, state)? else {
                return Ok(applied);
            };
            let mut reader = Reader::new(&payload);
            let Ok(bytes) = reader.var_bytes(MAX_NETWORK_FRAME_BYTES) else {
                return Ok(applied);
            };
            if bytes.is_empty() || lock(node).accept_block(bytes).is_err() {
                return Ok(applied);
            }
            applied += 1;
            progress += 1;
            if applied >= MAX_BLOCKS_PER_PULL {
                return Ok(applied);
            }
        }
        if progress == 0 || lock(node).height() >= their_height {
            break;
        }
    }
    Ok(applied)
}

/// True when replaying bodies is impossible, so a snapshot is the only way forward.
fn need_snapshot(node: &Arc<Mutex<Node>>, their_oldest_body: u64) -> bool {
    // `0` means the peer keeps everything.
    if their_oldest_body == 0 {
        return false;
    }
    let guard = lock(node);
    if !guard.trust_snapshots() {
        // Without a trust anchor of our own a snapshot is the peer's word for the whole state, so
        // the node never asks for one unless it was told to.
        return false;
    }
    match guard.next_body_height() {
        Some(next) => next < their_oldest_body,
        None => false,
    }
}

/// Why a snapshot was not installed. The distinction matters: a race with the peer's own progress is
/// not the peer's fault, while a snapshot that fails verification is.
enum SnapshotIssue {
    /// Try again after the next header sync.
    Retry(String),
    /// The peer sent something that does not verify; say so.
    Reject(String),
}

/// Ask for the peer's state and install it if it verifies against our own header chain.
fn install_snapshot_from(
    node: &Arc<Mutex<Node>>,
    stream: &mut SecureStream,
    state: &mut PeerState,
) -> Result<bool, SnapshotIssue> {
    write_frame(stream, P2P_MAGIC, p2p_kind::GET_STATE, &[])
        .map_err(|e| SnapshotIssue::Retry(e.to_string()))?;

    let mut start: Option<(u64, u32)> = None;
    let mut accounts: Vec<(AccountId, vess_core::Account)> = Vec::new();
    let mut end: Option<u32> = None;

    for _ in 0..MAX_SNAPSHOT_FRAMES {
        let Some(payload) =
            recv_until(node, stream, p2p_kind::STATE, state).map_err(SnapshotIssue::Retry)?
        else {
            return Ok(false);
        };
        let frame =
            SnapshotFrame::decode(&payload).map_err(|e| SnapshotIssue::Reject(e.to_string()))?;
        match frame {
            SnapshotFrame::Start {
                height,
                accounts: total_accounts,
            } => {
                if start.is_some() {
                    return Err(SnapshotIssue::Reject(
                        "peer sent two snapshot headers".into(),
                    ));
                }
                if u64::from(total_accounts) > vess_net::MAX_SNAPSHOT_ENTRIES {
                    return Err(SnapshotIssue::Reject(
                        "peer offered an oversized snapshot".into(),
                    ));
                }
                start = Some((height, total_accounts));
            }
            SnapshotFrame::Accounts(items) => {
                // Enforce the declared total *while* receiving: a peer that announces a plausible
                // count and then keeps sending must not be able to grow our buffer without bound.
                let declared = start.map(|(_, total)| total).unwrap_or(0);
                if accounts.len() + items.len() > declared as usize {
                    return Err(SnapshotIssue::Reject(
                        "peer sent more accounts than it announced".into(),
                    ));
                }
                accounts.extend(items);
            }
            SnapshotFrame::End {
                accounts: total_accounts,
            } => {
                end = Some(total_accounts);
                break;
            }
        }
    }

    let (Some((height, total_accounts)), Some(end_accounts)) = (start, end) else {
        return Err(SnapshotIssue::Retry(
            "peer sent an incomplete snapshot".into(),
        ));
    };
    if accounts.len() as u32 != total_accounts || end_accounts != total_accounts {
        return Err(SnapshotIssue::Reject(
            "peer sent a snapshot with the wrong number of records".into(),
        ));
    }

    let snapshot = vess_state::State::restore(accounts);
    match lock(node).install_snapshot(height, snapshot) {
        Ok(()) => {
            log::record(
                Level::Info,
                "sync",
                &format!("installed a verified state snapshot at height {height}"),
            );
            Ok(true)
        }
        // The peer advanced between the header sync and the snapshot, or we already have it. Both
        // resolve on the next pull, so they are not worth a warning.
        Err(
            why @ (NodeError::SnapshotNotAtTip
            | NodeError::UnknownParent
            | NodeError::SnapshotNotNewer
            | NodeError::SnapshotUnproven),
        ) => Err(SnapshotIssue::Retry(format!(
            "snapshot not applicable: {why}"
        ))),
        Err(why) => Err(SnapshotIssue::Reject(format!(
            "refused a state snapshot: {why}"
        ))),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Keep dialling peers out of the address book, so a node that was given one seed still finds the
/// rest of the network. One attempt at a time, with a pause between tries: this is discovery, not a
/// connection pool, and the configured `--peer` sessions remain the guaranteed ones.
pub fn crawl(
    node: Arc<Mutex<Node>>,
    connected: Arc<Mutex<Vec<String>>>,
    listen_port: u16,
    pause: Duration,
) {
    let pause = pause.max(Duration::from_millis(500));
    let conn = lock(&node).connections();
    loop {
        let candidate = {
            let guard = lock(&node);
            let connected = connected.lock().map(|c| c.clone()).unwrap_or_default();
            let refs: Vec<&str> = connected.iter().map(|s| s.as_str()).collect();
            guard.next_peer_to_dial(&refs)
        };
        let Some(record) = candidate else {
            std::thread::sleep(Duration::from_secs(5));
            continue;
        };
        {
            if let Ok(mut connected) = connected.lock() {
                connected.push(record.addr.clone());
            }
        }
        let started = Instant::now();
        match vess_net::connect(&record.addr) {
            Ok(stream) => {
                let ip = stream.peer_addr().map(|a| a.ip()).ok();
                let _guard = conn.outbound();
                if let Err(why) = session(
                    node.clone(),
                    stream,
                    listen_port,
                    ip,
                    true,
                    Some(record.addr.clone()),
                    None,
                ) {
                    crate::log_debug!("peers", "session to {} ended: {why}", record.addr);
                    lock(&node).record_peer_failure(&record.addr);
                }
            }
            Err(why) => {
                crate::log_debug!("peers", "could not dial {}: {why}", record.addr);
                lock(&node).record_peer_failure(&record.addr);
            }
        }
        if let Ok(mut connected) = connected.lock() {
            connected.retain(|addr| addr != &record.addr);
        }
        // A productive session reconnects promptly; a dead address backs off.
        if started.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(pause);
        }
    }
}

/// One catch-up pass over a fresh connection: pull blocks, then exchange mempools.
pub fn sync_once(node: &Arc<Mutex<Node>>, addr: &str, listen_port: u16) -> Result<usize, String> {
    let (ours, secret, chain) = {
        let guard = lock(node);
        (
            guard.handshake(listen_port),
            *guard.identity_secret(),
            guard.chain_id(),
        )
    };
    let (mut peer, theirs) =
        Peer::connect(addr, &ours, &secret, &chain).map_err(|e| e.to_string())?;
    peer.stream
        .set_read_timeout(SESSION_TICK_MS)
        .map_err(|e| e.to_string())?;

    let mut state = PeerState::default();
    let applied = pull(
        node,
        &mut peer.stream,
        theirs.best_height,
        theirs.oldest_body_height,
        &mut state,
    )?;

    // Blocks first, so a relayed transaction is grounded in a chain we already hold.
    let pending = { lock(node).pending_transactions() };
    for tx in pending {
        let _ = peer.send_transaction(&tx);
    }
    if peer.send(p2p_kind::GET_PENDING, &[]).is_ok()
        && let Ok(Some(payload)) = recv_until(node, &mut peer.stream, p2p_kind::PENDING, &mut state)
    {
        for tx in decode_pending(&payload) {
            let _ = submit(node, tx);
        }
    }
    Ok(applied)
}

/// Mine on top of the shared node until the process ends.
pub fn mine(node: Arc<Mutex<Node>>, payout: AccountId, pause: Duration) {
    loop {
        let started = std::time::Instant::now();
        let next = {
            let guard = lock(&node);
            guard.template(&payout, guard.next_timestamp_ms())
        };
        let (mut template, height) = match next {
            Ok(value) => value,
            Err(error) => {
                crate::log_warn!("miner", "template creation failed: {error}");
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        let signal = lock(&node).tip_signal();
        let result = crate::mine_fresh(&mut template.header, 200_000_000, started, |parent| {
            Ok::<_, std::convert::Infallible>(signal.current() != *parent)
        })
        .expect("infallible tip check");
        match result {
            crate::MiningResult::Refresh => continue,
            crate::MiningResult::Exhausted => {
                crate::log_warn!("miner", "no solution after 200 million nonces");
            }
            crate::MiningResult::Found => {
                let bytes = template.encode();
                match lock(&node).accept_mined_block(&bytes) {
                    Ok(Some(id)) => {
                        crate::log_debug!(
                            "miner",
                            "mined block {} at height {height}",
                            hex_short(&id)
                        )
                    }
                    Ok(None) => continue,
                    Err(why) => crate::log_warn!("miner", "mined block was refused: {why}"),
                }
            }
        }
        std::thread::sleep(pause);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_core::constants::NetworkProfile;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            use std::sync::atomic::AtomicU64;
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vess-p2p-{}-{}-{}",
                std::process::id(),
                tag,
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn listen() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    fn shared(path: &std::path::Path) -> Arc<Mutex<Node>> {
        Arc::new(Mutex::new(
            Node::open(path, NetworkProfile::DEVNET).unwrap(),
        ))
    }

    fn mine_one(node: &Arc<Mutex<Node>>, payout: &AccountId) -> Hash {
        let mut guard = lock(node);
        let timestamp = guard.next_timestamp_ms();
        let (mut template, _) = guard.template(payout, timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        guard.accept_block(&bytes).unwrap()
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if done() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for {what}");
    }

    #[test]
    fn a_poller_catches_up_and_follows_new_blocks() {
        let (dir_a, dir_b) = (TempDir::new("a"), TempDir::new("b"));
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);

        let (listener, port) = listen();
        let serve_a = a.clone();
        std::thread::spawn(move || serve(serve_a, listener, port));

        let payout = [0x41u8; 32];
        mine_one(&a, &payout);
        mine_one(&a, &payout);
        assert_eq!(a.lock().unwrap().height(), 2);

        // B pulls them in one pass.
        let applied = sync_once(&b, &format!("127.0.0.1:{port}"), 0).unwrap();
        assert!(applied >= 2, "applied {applied}");
        assert_eq!(b.lock().unwrap().height(), 2);
        assert_eq!(b.lock().unwrap().tip().id(), a.lock().unwrap().tip().id());
        assert_eq!(b.lock().unwrap().root(), a.lock().unwrap().root());

        // A mines a third; one more pass keeps them equal.
        mine_one(&a, &payout);
        sync_once(&b, &format!("127.0.0.1:{port}"), 0).unwrap();
        assert_eq!(b.lock().unwrap().height(), 3);
        assert_eq!(b.lock().unwrap().tip().id(), a.lock().unwrap().tip().id());
    }

    #[test]
    fn a_transaction_relayed_over_p2p_is_mined_and_synced() {
        let (dir_a, dir_b) = (TempDir::new("a"), TempDir::new("b"));
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);
        let (listener, port) = listen();
        let serve_a = a.clone();
        std::thread::spawn(move || serve(serve_a, listener, port));

        let wallet = vess_wallet::Wallet::from_seed(0, [0x42u8; 32]);
        let bob = [0xB8u8; 32];

        mine_one(&a, &wallet.account_id());
        sync_once(&b, &format!("127.0.0.1:{port}"), 0).unwrap();

        // The transfer is pushed to A as a raw TX frame. The client stays connected until the
        // transfer lands: closing a socket that still has unread frames queued would reset the
        // connection and discard the TX still in flight.
        let tx = wallet.build_transfer(bob, 1, 0, 0, 0);
        let mut client = connect_peer(&b, &format!("127.0.0.1:{port}"));
        client.send_transaction(&Transaction::Transfer(tx)).unwrap();
        wait_until("the transaction to arrive", || {
            a.lock().unwrap().mempool().transaction_count() == 1
        });
        drop(client);

        mine_one(&a, &wallet.account_id());
        sync_once(&b, &format!("127.0.0.1:{port}"), 0).unwrap();

        assert_eq!(b.lock().unwrap().balance(&bob), 1);
        assert_eq!(a.lock().unwrap().root(), b.lock().unwrap().root());
    }

    #[test]
    fn testnet_rejects_hostile_blocks_and_transactions_and_keeps_syncing() {
        let (dir_a, dir_b) = (TempDir::new("chaos-a"), TempDir::new("chaos-b"));
        let a = Arc::new(Mutex::new(
            Node::open(&dir_a.0, NetworkProfile::TESTNET).unwrap(),
        ));
        let b = Arc::new(Mutex::new(
            Node::open(&dir_b.0, NetworkProfile::TESTNET).unwrap(),
        ));
        let (listener, port) = listen();
        let serve_a = a.clone();
        std::thread::spawn(move || serve(serve_a, listener, port));
        let wallet = vess_wallet::Wallet::from_seed(NetworkProfile::TESTNET.network, [0x42; 32]);
        let recipient = [0x75; 32];
        let other = [0x76; 32];
        let mine = |node: &Arc<Mutex<Node>>| {
            let mut guard = lock(node);
            let (mut template, _) = guard
                .template(&wallet.account_id(), guard.next_timestamp_ms())
                .unwrap();
            assert!(template.mine(200_000_000));
            guard.accept_block(&template.encode()).unwrap()
        };
        mine(&a);
        sync_once(&b, &format!("127.0.0.1:{port}"), 0).unwrap();
        let before = lock(&a).tip().id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        {
            let mut guard = lock(&a);
            let (mut future, _) = guard.template(&wallet.account_id(), now + 600_000).unwrap();
            assert!(future.mine(200_000_000));
            assert!(matches!(
                guard.accept_block(&future.encode()),
                Err(crate::NodeError::Consensus(
                    vess_consensus::ConsensusError::BadTimestamp
                ))
            ));
            let (mut past, _) = guard
                .template(&wallet.account_id(), guard.next_timestamp_ms())
                .unwrap();
            past.header.timestamp_unix_ms = NetworkProfile::TESTNET.genesis_timestamp_ms;
            assert!(past.mine(200_000_000));
            assert!(matches!(
                guard.accept_block(&past.encode()),
                Err(crate::NodeError::Consensus(
                    vess_consensus::ConsensusError::BadTimestamp
                ))
            ));
            let mut bad = wallet.build_transfer(recipient, 10, 0, 0, 0);
            bad.signature[0] ^= 1;
            assert!(guard.submit_transfer(bad).is_err());
            let wrong_network =
                vess_wallet::Wallet::from_seed(NetworkProfile::DEVNET.network, [0x42; 32])
                    .build_transfer(recipient, 10, 0, 0, 0);
            assert!(guard.submit_transfer(wrong_network).is_err());
            assert_eq!(guard.tip().id(), before);
        }
        let tx = wallet.build_transfer(recipient, 10, 0, 0, 0);
        let conflict = wallet.build_transfer(other, 10, 0, 0, 0);
        lock(&a).submit_transfer(tx.clone()).unwrap();
        let pending_conflict = lock(&a).submit_transfer(conflict.clone());
        assert!(pending_conflict.is_err());
        println!("conflicting pending transfer: {pending_conflict:?}");
        {
            let mut guard = lock(&a);
            let (mut forged, _) = guard
                .template(&wallet.account_id(), guard.next_timestamp_ms())
                .unwrap();
            let mut bad = tx.clone();
            bad.signature[0] ^= 1;
            let invalid = Transaction::Transfer(bad);
            forged.header.transaction_root = vess_core::hash::tx_root(&[invalid.id()]);
            forged.body = vess_consensus::encode_body(&[invalid]).unwrap();
            assert!(forged.mine(200_000_000));
            let result = guard.accept_block(&forged.encode());
            println!("proof-of-work-valid block with forged signature: {result:?}");
            assert!(matches!(result, Err(crate::NodeError::Consensus(_))));
            assert_eq!(guard.tip().id(), before);
            let (mut doubled, _) = guard
                .template(&wallet.account_id(), guard.next_timestamp_ms())
                .unwrap();
            let first = Transaction::Transfer(tx.clone());
            let second = Transaction::Transfer(conflict.clone());
            doubled.header.transaction_root = vess_core::hash::tx_root(&[first.id(), second.id()]);
            doubled.body = vess_consensus::encode_body(&[first, second]).unwrap();
            assert!(doubled.mine(200_000_000));
            let result = guard.accept_block(&doubled.encode());
            println!("proof-of-work-valid double spend block: {result:?}");
            assert!(matches!(
                result,
                Err(crate::NodeError::Consensus(
                    vess_consensus::ConsensusError::BadTransaction { .. }
                ))
            ));
            assert_eq!(guard.tip().id(), before);
        }
        mine(&a);
        assert!(lock(&a).submit_transfer(tx.clone()).is_err());
        assert!(lock(&a).submit_transfer(conflict).is_err());
        sync_once(&b, &format!("127.0.0.1:{port}"), 0).unwrap();
        assert_eq!(lock(&a).balance(&recipient), 10);
        assert_eq!(lock(&a).balance(&other), 0);
        assert_eq!(lock(&a).root(), lock(&b).root());
        mine(&a);
        sync_once(&b, &format!("127.0.0.1:{port}"), 0).unwrap();
        assert_eq!(lock(&a).tip().id(), lock(&b).tip().id());
        assert_eq!(lock(&a).root(), lock(&b).root());
        println!("testnet chaos completed: height 3, matching state and tip");
    }

    #[test]
    fn the_poller_carries_transactions_to_the_miner() {
        let (dir_a, dir_b) = (TempDir::new("a"), TempDir::new("b"));
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);
        let (listener, port) = listen();
        let serve_b = b.clone();
        std::thread::spawn(move || serve(serve_b, listener, port));

        let wallet = vess_wallet::Wallet::from_seed(0, [0x44u8; 32]);
        let payout = wallet.account_id();

        mine_one(&b, &payout);
        let tx = wallet.build_transfer([0xBAu8; 32], 1, 0, 0, 0);
        b.lock().unwrap().submit_transfer(tx).unwrap();
        assert_eq!(a.lock().unwrap().mempool().transaction_count(), 0);

        sync_once(&a, &format!("127.0.0.1:{port}"), 0).unwrap();
        assert_eq!(a.lock().unwrap().height(), 1);
        assert_eq!(a.lock().unwrap().mempool().transaction_count(), 1);
        assert_eq!(a.lock().unwrap().tip().id(), b.lock().unwrap().tip().id());
    }

    #[test]
    fn a_session_announces_a_new_tip_without_being_asked() {
        let (dir_a, dir_b) = (TempDir::new("a"), TempDir::new("b"));
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);

        // B listens; A dials it and keeps the session open.
        let (listener, port_a_dials) = listen();
        let serve_b = b.clone();
        std::thread::spawn(move || serve(serve_b, listener, port_a_dials));
        let polled = a.clone();
        std::thread::spawn(move || {
            poll(
                polled,
                vec![format!("127.0.0.1:{port_a_dials}")],
                Duration::from_millis(50),
                0,
            )
        });

        // A mines while the session is up: the INV must carry it to B, which then pulls.
        let payout = [0x43u8; 32];
        mine_one(&a, &payout);
        mine_one(&a, &payout);
        wait_until("the announced blocks to reach B", || {
            b.lock().unwrap().height() == 2
        });
        let b_at = {
            let guard = b.lock().unwrap();
            (guard.tip().id(), guard.height())
        };
        let a_at = {
            let guard = a.lock().unwrap();
            (guard.tip().id(), guard.height())
        };
        assert!(b_at == a_at, "tips differ: b {b_at:?} a {a_at:?}");
        assert_eq!(b.lock().unwrap().root(), a.lock().unwrap().root());
    }

    #[test]
    fn a_session_catches_up_without_an_announcement() {
        let node_dir = TempDir::new("timer");
        let node = shared(&node_dir.0);
        let (listener, port) = listen();
        let serve_node = node.clone();
        std::thread::spawn(move || serve(serve_node, listener, port));

        // A peer that claims height 5 in its handshake and then never announces anything: the only
        // way the node can learn it is behind is the periodic catch-up check.
        let mut fake = node.lock().unwrap().handshake(7);
        fake.best_height = 5;
        fake.best_id = [0xABu8; 32];
        fake.connection_nonce = [0x11u8; 32];
        let mut client = connect_raw(&node, port, &fake);

        client.stream.set_read_timeout(250).unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut asked_for_headers = false;
        while Instant::now() < deadline {
            match client.recv() {
                Ok((kind, _)) if kind == p2p_kind::GET_HEADERS => {
                    asked_for_headers = true;
                    break;
                }
                Ok(_) => {}
                Err(NetError::Timeout) => {}
                Err(_) => break,
            }
        }
        assert!(
            asked_for_headers,
            "a session must re-check the peer's height even with no INV"
        );
        assert_eq!(node.lock().unwrap().height(), 0);
    }

    fn mine_template(node: &Arc<Mutex<Node>>, payout: &AccountId) -> (Hash, Vec<u8>) {
        let mut guard = lock(node);
        let timestamp = guard.next_timestamp_ms();
        let (mut template, _) = guard.template(payout, timestamp).unwrap();
        assert!(template.mine(20_000_000));
        let bytes = template.encode();
        let id = guard.accept_block(&bytes).unwrap();
        (id, bytes)
    }

    /// An encrypted client that speaks a caller-supplied HELLO, for tests that need to lie about
    /// their height.
    fn connect_raw(node: &Arc<Mutex<crate::Node>>, port: u16, ours: &vess_net::Handshake) -> Peer {
        let (secret, chain) = {
            let guard = node.lock().unwrap();
            (*guard.identity_secret(), guard.chain_id())
        };
        let raw = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
        vess_net::configure(&raw).unwrap();
        let (mut stream, _) = SecureStream::connect(raw, &secret, &chain).expect("noise handshake");
        write_frame(&mut stream, P2P_MAGIC, p2p_kind::HELLO, &ours.encode()).unwrap();
        let (kind, _) = read_frame(&mut stream, P2P_MAGIC, MAX_NETWORK_FRAME_BYTES).unwrap();
        assert_eq!(kind, p2p_kind::HELLO_ACK);
        Peer {
            stream,
            static_key: [0u8; 32],
        }
    }

    /// Dial `addr` the way the network does: TCP, then Noise, then the protocol handshake.
    fn connect_peer(node: &Arc<Mutex<crate::Node>>, addr: &str) -> Peer {
        let (mut ours, secret, chain) = {
            let guard = node.lock().unwrap();
            (
                guard.handshake(0),
                *guard.identity_secret(),
                guard.chain_id(),
            )
        };
        // The test peer impersonates a *different* node, so it must not present the node's own
        // connection nonce: that is exactly what a self-connection looks like.
        ours.connection_nonce = [0x5au8; 32];
        Peer::connect(addr, &ours, &secret, &chain)
            .expect("handshake with a local node")
            .0
    }

    /// Read frames from `peer` until a `GET_BLOCK` arrives or the socket goes quiet.
    fn wait_for_get_block(peer: &mut Peer) -> bool {
        peer.stream.set_read_timeout(500).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match peer.recv() {
                Ok((p2p_kind::GET_BLOCK, _)) => return true,
                Ok(_) => {}
                Err(NetError::Timeout) => {}
                Err(_) => return false,
            }
        }
        false
    }

    #[test]
    fn a_compact_block_is_rebuilt_from_the_mempool() {
        let (dir_a, dir_b) = (TempDir::new("ca"), TempDir::new("cb"));
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);
        // Both are dialable: B syncs from A, and the test then talks to B.
        let (listener_a, port_a) = listen();
        let serve_a = a.clone();
        std::thread::spawn(move || serve(serve_a, listener_a, port_a));
        let (listener, port) = listen();
        let serve_b = b.clone();
        std::thread::spawn(move || serve(serve_b, listener, port));

        let wallet = vess_wallet::Wallet::from_seed(0, [0x45u8; 32]);
        let payout = wallet.account_id();
        let bob = [0xB7u8; 32];

        mine_one(&a, &payout);
        sync_once(&b, &format!("127.0.0.1:{port_a}"), 0).unwrap();
        assert_eq!(b.lock().unwrap().height(), 1);

        // Both nodes hold the transaction, so the body is rebuildable from the mempool alone.
        let tx = wallet.build_transfer(bob, 1, 0, 0, 0);
        b.lock().unwrap().submit_transfer(tx.clone()).unwrap();
        a.lock().unwrap().submit_transfer(tx).unwrap();

        let (_, bytes) = mine_template(&a, &payout);
        let height = a.lock().unwrap().height();
        let (header, transactions) = vess_consensus::split_block(&bytes).unwrap();
        assert_eq!(transactions.len(), 1);

        let mut client = connect_peer(&a, &format!("127.0.0.1:{port}"));
        let ids: Vec<[u8; SHORT_ID_BYTES]> = transactions
            .iter()
            .map(|tx| short_id(&header.id(), &tx.id()))
            .collect();
        client
            .send(p2p_kind::CMPCTBLOCK, &encode_compact(height, &header, &ids))
            .unwrap();

        wait_until("the compact block to be rebuilt", || {
            b.lock().unwrap().height() == height
        });
        assert_eq!(b.lock().unwrap().tip().id(), a.lock().unwrap().tip().id());
        assert_eq!(b.lock().unwrap().balance(&bob), 1);
        assert!(
            !wait_for_get_block(&mut client),
            "reconstruction should not need the full body"
        );
    }

    #[test]
    fn a_compact_block_falls_back_to_a_full_fetch() {
        let (dir_a, dir_b) = (TempDir::new("fa"), TempDir::new("fb"));
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);
        let (listener_a, port_a) = listen();
        let serve_a = a.clone();
        std::thread::spawn(move || serve(serve_a, listener_a, port_a));
        let (listener, port) = listen();
        let serve_b = b.clone();
        std::thread::spawn(move || serve(serve_b, listener, port));

        let wallet = vess_wallet::Wallet::from_seed(0, [0x46u8; 32]);
        let payout = wallet.account_id();
        let bob = [0xB8u8; 32];

        mine_one(&a, &payout);
        sync_once(&b, &format!("127.0.0.1:{port_a}"), 0).unwrap();

        // Only A has the transaction this time, so B cannot rebuild the body.
        let tx = wallet.build_transfer(bob, 1, 0, 0, 0);
        a.lock().unwrap().submit_transfer(tx).unwrap();
        let (_, bytes) = mine_template(&a, &payout);
        let height = a.lock().unwrap().height();
        let (header, transactions) = vess_consensus::split_block(&bytes).unwrap();

        let mut client = connect_peer(&a, &format!("127.0.0.1:{port}"));
        let ids: Vec<[u8; SHORT_ID_BYTES]> = transactions
            .iter()
            .map(|tx| short_id(&header.id(), &tx.id()))
            .collect();
        client
            .send(p2p_kind::CMPCTBLOCK, &encode_compact(height, &header, &ids))
            .unwrap();

        assert!(
            wait_for_get_block(&mut client),
            "a missing transaction must trigger a full fetch"
        );
        // Serve the block, exactly as the announcing node would.
        client.send_block(&bytes).unwrap();
        wait_until("the fallback to land", || {
            b.lock().unwrap().height() == height
        });
        assert_eq!(b.lock().unwrap().balance(&bob), 1);
    }

    /// A node that knows one seed must discover the rest of the network by itself: it asks the seed
    /// for addresses, learns the bridge's other peer, dials it, and syncs.
    #[test]
    fn a_node_discovers_a_peer_it_was_never_told_about() {
        let (dir_a, dir_b, dir_c) = (
            TempDir::new("disc-a"),
            TempDir::new("disc-b"),
            TempDir::new("disc-c"),
        );
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);
        let c = shared(&dir_c.0);

        // C is one block ahead, so a successful discovery is observable as A's height.
        mine_one(&c, &[0x31u8; 32]);

        let (listener_a, port_a) = listen();
        let (listener_b, port_b) = listen();
        let (listener_c, port_c) = listen();
        for (node, listener, port) in [
            (a.clone(), listener_a, port_a),
            (b.clone(), listener_b, port_b),
            (c.clone(), listener_c, port_c),
        ] {
            std::thread::spawn(move || serve(node, listener, port));
        }

        // B learns both others, so it can act as the only bridge between them.
        {
            let b = b.clone();
            let addrs = vec![format!("127.0.0.1:{port_a}"), format!("127.0.0.1:{port_c}")];
            std::thread::spawn(move || poll(b, addrs, Duration::from_millis(100), port_b));
        }
        wait_until("B to know both peers as verified", || {
            b.lock().unwrap().peer_book_size().1 >= 2
        });

        // A is told about B and nothing else. Its crawler has to do the rest.
        {
            let a = a.clone();
            let addrs = vec![format!("127.0.0.1:{port_b}")];
            std::thread::spawn(move || poll(a, addrs, Duration::from_millis(100), port_a));
        }

        // B's address is excluded because the seed loop already holds a session with it, exactly as
        // the crawler does.
        let seed = format!("127.0.0.1:{port_b}");
        wait_until("A to learn about C from B", || {
            let guard = a.lock().unwrap();
            guard
                .next_peer_to_dial(&[seed.as_str()])
                .map(|peer| peer.addr.contains(&port_c.to_string()))
                .unwrap_or(false)
        });
        // The property under test is that A *connects* to C, not merely that it learns the address:
        // A could have got the block from the seed alone, so wait for the discovery to complete.
        wait_until("A to connect to the peer it discovered", || {
            a.lock().unwrap().peer_book_size().1 >= 2
        });
        wait_until("A to sync", || a.lock().unwrap().height() == 1);
        assert_eq!(a.lock().unwrap().root(), c.lock().unwrap().root());
    }

    /// Gossip must not be able to steer a node into an attacker's clique: only addresses we have
    /// connected to ourselves are ever passed on.
    #[test]
    fn unverified_addresses_are_never_passed_on() {
        let node_dir = TempDir::new("gossip-poison");
        let node = shared(&node_dir.0);
        let (listener, port) = listen();
        let serve_node = node.clone();
        std::thread::spawn(move || serve(serve_node, listener, port));

        let mut client = connect_peer(&node, &format!("127.0.0.1:{port}"));
        // A list of addresses this node has never dialled, from a peer that is local.
        let entries: Vec<vess_net::AddressEntry> = (0..4)
            .map(|index| vess_net::AddressEntry {
                addr: format!("127.0.0.1:{}", 20_000 + index),
                static_key: [0x11u8; 32],
            })
            .collect();
        client
            .send(p2p_kind::ADDR, &vess_net::encode_addresses(&entries))
            .unwrap();
        wait_until("the addresses to be learned", || {
            node.lock().unwrap().peer_book_size().0 >= entries.len()
        });

        // Ask for addresses back: nothing unverified may be offered. The server may ask us for
        // addresses first, so skip anything that is not the answer.
        client
            .send(p2p_kind::GET_ADDR, &16u32.to_be_bytes())
            .unwrap();
        let offered = loop {
            match client.recv() {
                Ok((p2p_kind::ADDR, payload)) => {
                    break vess_net::decode_addresses(&payload).unwrap();
                }
                Ok(_) => continue,
                other => panic!("expected ADDR, got {other:?}"),
            }
        };
        assert!(
            offered.is_empty(),
            "unverified addresses must never be gossiped: {offered:?}"
        );
    }

    /// A node seeded with its own address must not end up holding a session with itself, and must
    /// not treat its own address as a discovered peer.
    /// A node that has verified an address refuses a later session from a different key at that address.
    /// Without this, an attacker who wins a first contact keeps the address for as long as they like.
    #[test]
    fn a_pinned_address_refuses_a_different_key() {
        let dir_a = TempDir::new("pin-a");
        let dir_b = TempDir::new("pin-b");
        let a = shared(&dir_a.0);
        let b = shared(&dir_b.0);
        let (listener_b, port_b) = listen();
        let serve_b = b.clone();
        std::thread::spawn(move || serve(serve_b, listener_b, port_b));

        // First contact: A dials B once, which pins B's real key.
        a.lock()
            .unwrap()
            .record_peer_success(&format!("127.0.0.1:{port_b}"), [0xAAu8; 32], 1);
        // Now B's identity is replaced by an impostor for A's eyes only.
        assert!(
            !a.lock()
                .unwrap()
                .peer_pinned(&format!("127.0.0.1:{port_b}"), &[0xBBu8; 32]),
            "a different key at a pinned address must not pass"
        );
        assert!(
            a.lock()
                .unwrap()
                .peer_pinned(&format!("127.0.0.1:{port_b}"), &[0xAAu8; 32]),
            "the proven key still passes"
        );
        // The book keeps the pinned key even if a later handshake claims another one.
        a.lock()
            .unwrap()
            .record_peer_success(&format!("127.0.0.1:{port_b}"), [0xBBu8; 32], 2);
        assert_eq!(
            a.lock().unwrap().peer_book_size().1,
            1,
            "still exactly one verified peer"
        );
        assert!(
            a.lock()
                .unwrap()
                .peer_pinned(&format!("127.0.0.1:{port_b}"), &[0xAAu8; 32])
        );
    }

    #[test]
    fn a_node_refuses_to_talk_to_itself() {
        let node_dir = TempDir::new("self-dial");
        let node = shared(&node_dir.0);
        let (listener, port) = listen();
        let serve_node = node.clone();
        std::thread::spawn(move || serve(serve_node, listener, port));
        {
            let node = node.clone();
            let addrs = vec![format!("127.0.0.1:{port}")];
            std::thread::spawn(move || poll(node, addrs, Duration::from_millis(100), port));
        }

        // The dial attempts happen immediately; give them several rounds to fail and be dropped.
        std::thread::sleep(Duration::from_millis(2_000));
        let guard = node.lock().unwrap();
        assert_eq!(
            guard.peer_book_size().1,
            0,
            "a node must not verify its own address"
        );
        assert_eq!(guard.height(), 0);
        assert!(
            guard.peer_counts().0 <= 1,
            "at most one failed dial may be in flight, got {:?}",
            guard.peer_counts()
        );
    }

    #[test]
    fn a_flooding_peer_is_disconnected() {
        let node_dir = TempDir::new("flood");
        let node = shared(&node_dir.0);
        let (listener, port) = listen();
        let serve_node = node.clone();
        std::thread::spawn(move || serve(serve_node, listener, port));

        // Handshake, then scream frames until the server cuts the connection.
        let mut client = connect_peer(&node, &format!("127.0.0.1:{port}"));

        let mut cut_off = false;
        for _ in 0..(FRAME_BUDGET_PER_SECOND * 8) {
            if client.send(0xEEEE, &[0u8; 16]).is_err() {
                cut_off = true;
                break;
            }
            let _ = client.stream.set_read_timeout(1);
            if let Ok((kind, _)) = client.recv()
                && kind == p2p_kind::DISCONNECT
            {
                cut_off = true;
                break;
            }
        }
        assert!(cut_off, "the session must end for a peer over its budget");
        assert_eq!(node.lock().unwrap().height(), 0);
    }

    /// A reply must fit one frame even when the pool is far larger, or `write_frame` fails and the
    /// session is dropped.
    #[test]
    fn a_pending_reply_never_exceeds_one_frame() {
        let tx = Transaction::Transfer(vess_core::Transfer {
            version: 1,
            chain_id: [0u8; 32],
            sender_public_key: [1u8; 1952],
            recipient_account_id: [2u8; 32],
            amount: 1,
            fee: 0,
            nonce: 0,
            expiry_unix: 0,
            signature: [3u8; 3309],
        });
        let transactions: Vec<Transaction> = (0..1_000).map(|_| tx.clone()).collect();
        let payload = encode_pending(&transactions);
        assert!(
            payload.len() <= MAX_NETWORK_FRAME_BYTES,
            "{} bytes",
            payload.len()
        );
        let decoded = decode_pending(&payload);
        assert!(!decoded.is_empty());
        assert!(
            decoded.len() < transactions.len(),
            "the test needs a pool that does not fit"
        );
    }

    /// A peer cannot force unbounded signature verifications: past the budget its frames are dropped
    /// and charged, and the session dies. Producing well-formed transactions with junk signatures is
    /// free for an attacker, which is why the frame budget alone is not enough.
    #[test]
    fn a_peer_cannot_force_unbounded_verifications() {
        let node_dir = TempDir::new("verifyflood");
        let node = shared(&node_dir.0);
        // Fund the sender so the transaction is otherwise acceptable.
        let wallet = vess_wallet::Wallet::from_seed(0, [0x92u8; 32]);
        mine_one(&node, &wallet.account_id());
        let tx = wallet.build_transfer([0x93u8; 32], 1, 0, 0, 0);
        let payload = Transaction::Transfer(tx).canonical();

        let (listener, port) = listen();
        let serve_node = node.clone();
        std::thread::spawn(move || serve(serve_node, listener, port));

        let mut client = connect_peer(&node, &format!("127.0.0.1:{port}"));

        // Every one of these is decodable, so each would force a verification if unbudgeted.
        let mut cut_off = false;
        for _ in 0..(MAX_VERIFICATIONS_PER_SECOND * 2) {
            if client.send(p2p_kind::TX, &payload).is_err() {
                cut_off = true;
                break;
            }
            let _ = client.stream.set_read_timeout(1);
            if let Ok((kind, _)) = client.recv()
                && kind == p2p_kind::DISCONNECT
            {
                cut_off = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // The server may still be flushing its goodbye; a blocking read settles it either way.
        if !cut_off {
            let _ = client.stream.set_read_timeout(500);
            cut_off = match client.recv() {
                Ok((kind, _)) => kind == p2p_kind::DISCONNECT,
                Err(_) => true,
            };
        }
        assert!(
            cut_off,
            "a peer over the verification budget must be cut off"
        );
        // The one transaction that got through the budget was admitted exactly once.
        assert_eq!(node.lock().unwrap().mempool().transaction_count(), 1);
    }
}
