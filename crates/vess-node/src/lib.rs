//! A running ledger node: storage, header chain, current state, mempool, and the RPC surface.
//!
//! Blocks that extend any known block are indexed; the live state always follows the heaviest branch,
//! so forks and reorganizations are handled here rather than left to the caller (see
//! `architecture.md` §10 and §15).

use std::net::TcpListener;

pub mod log;
pub mod p2p;
pub mod peers;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use vess_consensus::chain::{Chain, HeaderSource};
use vess_consensus::{BlockTemplate, ConsensusError, build_template, split_block, validate_block};
use vess_core::constants::NetworkProfile;
use vess_core::hash::{self, DOM_STATE_UPDATE, DOM_TRANSFER};
use vess_core::{AccountId, BlockHeader, Hash, StateUpdate, Transaction, Transfer};
use vess_mempool::{AddOutcome, Mempool, MempoolError};
use vess_net::rpc::{
    AccountInfo, BlockInfo, BlockQuery, ProofInfo, Reply, ReplyBody, Request, StatusInfo,
    TemplateInfo, TransactionInfo,
};
use vess_net::tx_status;
use vess_state::State;
use vess_storage::{PrunePolicy, PruneReport, StorageError, Store};

/// Load the transport identity, creating it on first run. The key is a file rather than database
/// state because peers may pin it and it must survive a wiped database.
fn load_or_create_identity(datadir: &Path) -> Result<[u8; 32], NodeError> {
    let path = datadir.join("identity.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
        return Err(NodeError::Malformed("identity.key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| NodeError::Io(format!("entropy: {e}")))?;
    std::fs::write(&path, key)?;
    Ok(key)
}

/// Pruning runs at most once every this many blocks, so it is not on the per-block path.
const PRUNE_INTERVAL_BLOCKS: u64 = 64;

/// Target payload size for one snapshot frame, well under the 2 MiB frame limit.
const SNAPSHOT_BATCH_BYTES: usize = 1_048_576;
pub const MINING_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MINING_BATCH_ATTEMPTS: u64 = 10_000;

pub enum MiningResult {
    Found,
    Refresh,
    Exhausted,
}

/// Search in bounded batches so callers can replace stale templates.
pub fn mine_fresh<E>(
    header: &mut BlockHeader,
    max_attempts: u64,
    started: Instant,
    mut stale: impl FnMut(&Hash) -> Result<bool, E>,
) -> Result<MiningResult, E> {
    let mut remaining = max_attempts;
    while remaining > 0 {
        if started.elapsed() >= MINING_REFRESH_INTERVAL || stale(&header.previous_block_id)? {
            return Ok(MiningResult::Refresh);
        }
        let attempts = remaining.min(MINING_BATCH_ATTEMPTS);
        let found = vess_consensus::mine_header(header, attempts);
        if started.elapsed() >= MINING_REFRESH_INTERVAL || stale(&header.previous_block_id)? {
            return Ok(MiningResult::Refresh);
        }
        if found {
            return Ok(MiningResult::Found);
        }
        remaining -= attempts;
    }
    Ok(MiningResult::Exhausted)
}
/// Approximate encoded size of one account record, used only for batching.
const SNAPSHOT_RECORD_BYTES: usize = 128;

#[derive(Debug)]
pub enum NodeError {
    Storage(StorageError),
    Consensus(ConsensusError),
    Mempool(MempoolError),
    Io(String),
    UnknownParent,
    ReorgUnavailable,
    UnknownAccount,
    Malformed(&'static str),
    /// A snapshot arrived for a height that is not the tip of our validated header chain.
    SnapshotNotAtTip,
    /// A snapshot's state root did not match the header it claims to belong to.
    SnapshotMismatch,
    /// A snapshot arrived for a block we cannot validate ourselves, so its state root is the peer's
    /// word alone.
    SnapshotUnproven,
    /// A snapshot is not newer than the state we already have.
    SnapshotNotNewer,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Storage(e) => write!(f, "storage: {e}"),
            NodeError::Consensus(e) => write!(f, "consensus: {e}"),
            NodeError::Mempool(e) => write!(f, "mempool: {e}"),
            NodeError::Io(e) => write!(f, "io: {e}"),
            NodeError::UnknownParent => f.write_str("previous block is not known"),
            NodeError::ReorgUnavailable => f.write_str("cannot rewind: undo data missing"),
            NodeError::UnknownAccount => f.write_str("account does not exist"),
            NodeError::Malformed(what) => write!(f, "malformed object: {what}"),
            NodeError::SnapshotNotAtTip => {
                f.write_str("snapshot is not at the tip of our header chain")
            }
            NodeError::SnapshotMismatch => {
                f.write_str("snapshot state root does not match its header")
            }
            NodeError::SnapshotUnproven => {
                f.write_str("snapshot anchors on a block this node cannot validate")
            }
            NodeError::SnapshotNotNewer => f.write_str("snapshot is not newer than our state"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<StorageError> for NodeError {
    fn from(e: StorageError) -> Self {
        NodeError::Storage(e)
    }
}

impl From<ConsensusError> for NodeError {
    fn from(e: ConsensusError) -> Self {
        NodeError::Consensus(e)
    }
}

impl From<MempoolError> for NodeError {
    fn from(e: MempoolError) -> Self {
        NodeError::Mempool(e)
    }
}

impl From<std::io::Error> for NodeError {
    fn from(e: std::io::Error) -> Self {
        NodeError::Io(e.to_string())
    }
}

/// Stable reason codes for RPC rejections (§7.6 of the architecture).
pub mod reason {
    pub const BAD_REQUEST: u16 = 1;
    pub const CONSENSUS: u16 = 2;
    pub const MEMPOOL: u16 = 3;
    pub const STORAGE: u16 = 4;
    pub const NOT_TIP: u16 = 5;
    pub const UNKNOWN_ACCOUNT: u16 = 6;
    pub const MALFORMED: u16 = 7;
    pub const NOT_FOUND: u16 = 8;
}

/// A node's tip, with a way for a waiting client to be woken when it moves.
///
/// Deliberately *not* the node mutex: `WAIT_FOR_TIP` blocks for up to 25 s, and holding the node lock
/// for that long would freeze mining, every peer session, and every other RPC call.
#[derive(Debug)]
pub struct TipSignal {
    tip: Mutex<Hash>,
    changed: Condvar,
}

impl TipSignal {
    pub fn new(tip: Hash) -> TipSignal {
        TipSignal {
            tip: Mutex::new(tip),
            changed: Condvar::new(),
        }
    }

    /// Record a new tip and wake everyone waiting for a change.
    pub fn publish(&self, tip: Hash) {
        let mut current = self.tip.lock().unwrap_or_else(|e| e.into_inner());
        if *current == tip {
            return;
        }
        *current = tip;
        self.changed.notify_all();
    }

    pub fn current(&self) -> Hash {
        *self.tip.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Block until the tip differs from `after`, or `timeout_ms` elapses. Returns the tip either way,
    /// so a caller that timed out simply asks again with the value it got.
    pub fn wait_for_change(&self, after: Hash, timeout_ms: u32) -> Hash {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        let mut current = self.tip.lock().unwrap_or_else(|e| e.into_inner());
        while *current == after {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (guard, _) = self
                .changed
                .wait_timeout(current, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            current = guard;
        }
        *current
    }
}

pub struct Node {
    network: NetworkProfile,
    datadir: PathBuf,
    store: Store,
    chain: Chain,
    state: State,
    /// The block whose post-state `state` currently holds. Normally the chain tip, but it trails
    /// during a rewind / replay.
    state_tip: Hash,
    mempool: Mempool,
    accepted_blocks: u64,
    accepted_transactions: u64,
    /// X25519 static key for the encrypted transport. Generated on first open and kept next to the
    /// database, because peers may pin it.
    identity: [u8; 32],
    /// Peers this node knows, and the ones it will gossip onward.
    book: peers::AddressBook,
    /// Open peer sessions and the caps on them. Per node rather than per process, so two nodes in
    /// one process (the tests) cannot spend each other's connection budget.
    conn: std::sync::Arc<crate::p2p::Connections>,
    /// Wakes `WAIT_FOR_TIP` callers when the tip moves. Shared with the RPC server.
    tip_signal: Arc<TipSignal>,
    /// Where the book is persisted.
    peers_path: PathBuf,
    /// How much history this node keeps. Persisted in the database; see `set_prune_policy`.
    prune: PrunePolicy,
    /// When the last pruning pass ran, so it happens on a schedule rather than per block.
    last_pruned_at_height: u64,
    /// Whether a snapshot may be installed for a block this node cannot validate itself. Off by
    /// default: it means trusting the peer's account set at that height.
    trust_snapshots: bool,
}

impl Node {
    pub fn open(datadir: impl AsRef<Path>, network: NetworkProfile) -> Result<Node, NodeError> {
        let datadir = datadir.as_ref().to_path_buf();
        std::fs::create_dir_all(&datadir)?;
        let store = Store::open(&datadir.join("ledger.redb"), network)?;
        let mut chain = store.load_chain()?;
        // The in-memory chain must not claim headers the store no longer has.
        chain.prune_below(store.oldest_header_height()?);
        let state = store.load_state()?;
        let state_tip = match store.tip()? {
            Some(id) => id,
            // No committed block yet: the state is the genesis state. Deriving the id instead of
            // reading header 0 keeps this working once headers are pruned.
            None => vess_consensus::genesis_header(&network).id(),
        };
        let prune = store.prune_policy()?;
        let identity = load_or_create_identity(&datadir)?;
        let peers_path = datadir.join("peers.txt");
        let book = peers::AddressBook::load(&peers_path);
        let mut conn = crate::p2p::Connections::default();
        // Bans survive a restart; a ban a restart forgets is barely a ban.
        conn.load_bans(datadir.join("bans.txt"));
        let conn = std::sync::Arc::new(conn);
        let tip_signal = Arc::new(TipSignal::new(chain.best_id()));
        let mut node = Node {
            network,
            datadir,
            store,
            chain,
            state,
            state_tip,
            mempool: Mempool::new(),
            accepted_blocks: 0,
            accepted_transactions: 0,
            identity,
            book,
            conn,
            tip_signal,
            peers_path,
            prune,
            last_pruned_at_height: 0,
            trust_snapshots: false,
        };
        node.reconcile()?;
        node.restore_mempool();
        node.verify_checkpoints()?;
        Ok(node)
    }

    /// Refuse to run on a chain that contradicts a compiled-in checkpoint.
    ///
    /// Validation cannot answer this question — a long-range fork below the last block this node ever
    /// checked looks exactly like the real chain — so a database built against another history has to
    /// be rejected outright rather than silently served. Headers below our own pruning window are not
    /// checkable any more; those were validated before they were pruned.
    fn verify_checkpoints(&self) -> Result<(), NodeError> {
        for checkpoint in self.chain.checkpoints() {
            let Some(header) = self.chain.main_header_at(checkpoint.height) else {
                continue;
            };
            if header.id() != checkpoint.id {
                return Err(NodeError::Consensus(ConsensusError::CheckpointMismatch));
            }
        }
        Ok(())
    }

    /// The X25519 secret this node proves in the Noise handshake.
    pub fn identity_secret(&self) -> &[u8; 32] {
        &self.identity
    }

    /// The chain this node speaks, for binding a transport session to it.
    pub fn chain_id(&self) -> Hash {
        hash::chain_id(self.network.network)
    }

    /// This node's connection accounting, shared with every session thread it spawns.
    pub fn connections(&self) -> std::sync::Arc<crate::p2p::Connections> {
        self.conn.clone()
    }

    /// The tip signal, so the RPC server can block on it without holding the node lock.
    pub fn tip_signal(&self) -> Arc<TipSignal> {
        self.tip_signal.clone()
    }

    /// Allow installing a snapshot this node cannot verify against a block it validated itself.
    /// Off by default; see `install_snapshot`.
    pub fn set_trust_snapshots(&mut self, trust: bool) {
        self.trust_snapshots = trust;
    }

    /// Whether unverifiable snapshots may be installed.
    pub fn trust_snapshots(&self) -> bool {
        self.trust_snapshots
    }

    /// Open sessions right now, reported by `STATUS`.
    pub fn peer_counts(&self) -> (usize, usize) {
        self.conn.counts()
    }

    /// How many peers this node knows, and how many of them it has actually connected to.
    pub fn peer_book_size(&self) -> (usize, usize) {
        (self.book.len(), self.book.verified_count())
    }

    /// A completed handshake: the address is real, so it may be gossiped onward from now on.
    pub fn record_peer_success(&mut self, addr: &str, static_key: [u8; 32], now: u64) {
        self.book.record_success(addr, static_key, now);
        self.persist_book();
    }

    /// Does this key match the one we pinned for `addr`? Always true when nothing is pinned.
    pub fn peer_pinned(&self, addr: &str, static_key: &[u8; 32]) -> bool {
        self.book.pin_matches(addr, static_key)
    }

    /// A failed dial. Unverified addresses are dropped after enough of them.
    pub fn record_peer_failure(&mut self, addr: &str) {
        self.book.record_failure(addr);
        self.persist_book();
    }

    /// Learn addresses a peer told us about. Only well-formed, non-local-unless-local-peer entries
    /// survive, and none of them is gossiped on until a handshake proves it.
    pub fn learn_peers(
        &mut self,
        entries: &[vess_net::AddressEntry],
        sender_is_local: bool,
        now: u64,
    ) {
        let mut changed = false;
        for entry in entries {
            if !peers::acceptable(&entry.addr, sender_is_local) {
                continue;
            }
            changed |= self.book.learn(&entry.addr, entry.static_key, now);
        }
        if changed {
            self.persist_book();
        }
    }

    /// Addresses to answer a `GET_ADDR` with: verified peers only, never the asker itself.
    pub fn gossip_peers(&mut self, asker: &str, max: usize) -> Vec<vess_net::AddressEntry> {
        self.book.gossip(&[asker], max)
    }

    /// The next peer worth dialling, skipping addresses we already hold a session with.
    pub fn next_peer_to_dial(&self, connected: &[&str]) -> Option<peers::PeerRecord> {
        self.book.next_dial(connected)
    }

    fn persist_book(&mut self) {
        if let Err(why) = self.book.save(&self.peers_path) {
            crate::log_debug!("peers", "could not save the address book: {why}");
        }
    }

    /// How much history this node keeps.
    pub fn prune_policy(&self) -> PrunePolicy {
        self.prune
    }

    /// Change the policy and remember it next to the data it affects.
    ///
    /// Pruning is destructive, so this is recorded in the database: a later run that passes no flags
    /// keeps the previous behaviour rather than silently becoming archival again (or pruning more).
    pub fn set_prune_policy(&mut self, policy: PrunePolicy) -> Result<(), NodeError> {
        self.store.set_prune_policy(policy)?;
        self.prune = policy;
        Ok(())
    }

    /// Run one pruning pass now, and keep the in-memory chain in step with the store.
    pub fn prune_now(&mut self) -> Result<PruneReport, NodeError> {
        let report = self.store.prune(self.chain.best_height(), self.prune)?;
        if report.headers_removed > 0 {
            self.chain.prune_below(report.oldest_header_height);
        }
        self.last_pruned_at_height = self.chain.best_height();
        Ok(report)
    }

    /// Prune if the policy asks for it and enough blocks have gone by.
    fn maybe_prune(&mut self) -> Result<(), NodeError> {
        if self.prune.is_archival() {
            return Ok(());
        }
        if self
            .chain
            .best_height()
            .saturating_sub(self.last_pruned_at_height)
            < PRUNE_INTERVAL_BLOCKS
        {
            return Ok(());
        }
        let report = self.prune_now()?;
        if report.headers_removed > 0 || report.bodies_removed > 0 {
            crate::log_debug!(
                "prune",
                "kept {} bodies and {} headers; removed {} bodies, {} headers",
                self.prune.blocks,
                self.prune.headers,
                report.bodies_removed,
                report.headers_removed
            );
        }
        Ok(())
    }

    pub fn network(&self) -> NetworkProfile {
        self.network
    }

    pub fn datadir(&self) -> &Path {
        &self.datadir
    }

    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    pub fn network_profile(&self) -> NetworkProfile {
        self.network
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    pub fn tip(&self) -> BlockHeader {
        self.chain.best_header()
    }

    /// Height of the state this node can prove: the block the account set belongs to.
    pub fn state_height(&self) -> u64 {
        self.chain
            .meta(&self.state_tip)
            .map(|meta| meta.height)
            .unwrap_or(0)
    }

    /// Build a state snapshot as wire frames: `Start`, batches of accounts, `End`.
    ///
    /// Any node can serve this, including one that has pruned every block, because it describes the
    /// *live* state rather than history. It is safe to send to anyone: the receiver checks it against
    /// the `state_root` of a header it has already validated.
    pub fn snapshot_frames(&self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        frames.push(
            vess_net::SnapshotFrame::Start {
                height: self.state_height(),
                accounts: self.state.account_count() as u32,
            }
            .encode(),
        );

        let mut batch: Vec<(AccountId, vess_core::Account)> = Vec::new();
        let mut bytes = 0usize;
        for (id, account) in self.state.accounts_iter() {
            batch.push((*id, *account));
            bytes += SNAPSHOT_RECORD_BYTES;
            if bytes >= SNAPSHOT_BATCH_BYTES {
                frames.push(vess_net::SnapshotFrame::Accounts(std::mem::take(&mut batch)).encode());
                bytes = 0;
            }
        }
        if !batch.is_empty() {
            frames.push(vess_net::SnapshotFrame::Accounts(batch).encode());
        }

        frames.push(
            vess_net::SnapshotFrame::End {
                accounts: self.state.account_count() as u32,
            }
            .encode(),
        );
        frames
    }

    /// Install a snapshot that a peer sent, after proving it against a block we validated ourselves.
    ///
    /// `state_root` commits to the account set, so a snapshot that matches it *is* the state at that
    /// height — but only if the header is one whose root we can confirm. A header alone proves
    /// nothing: a peer may mine a single block with any `state_root` it likes and hand us the
    /// matching accounts, so the anchor's body is validated here against the parent state we hold.
    /// Anything else is refused and the node keeps replaying blocks instead.
    pub fn install_snapshot(
        &mut self,
        height: u64,
        state: vess_state::State,
    ) -> Result<(), NodeError> {
        let header = self
            .chain
            .main_header_at(height)
            .ok_or(NodeError::UnknownParent)?;
        if height != self.chain.best_height() {
            return Err(NodeError::SnapshotNotAtTip);
        }
        if height <= self.state_height() {
            return Err(NodeError::SnapshotNotNewer);
        }
        let body = self.store.body(&header.id())?;
        if let Some(body) = body {
            let parent_state = self.state_at(&header.previous_block_id)?;
            let validated = validate_block(&self.chain, &self.network, &parent_state, &body)?;
            if validated.state.root() != state.root() || state.root() != header.state_root {
                return Err(NodeError::SnapshotMismatch);
            }
        } else if !self.trust_snapshots {
            // Without the anchor's body a peer could mine one header with any `state_root` and hand
            // us the accounts that hash to it, so an unproven snapshot is opt-in only.
            return Err(NodeError::SnapshotUnproven);
        } else if state.root() != header.state_root {
            return Err(NodeError::SnapshotMismatch);
        }
        self.store.install_snapshot(&header, height, &state)?;
        self.state = state;
        self.state_tip = header.id();
        self.restore_mempool();
        self.tip_signal.publish(self.chain.best_id());
        Ok(())
    }

    /// Height of the first block whose body we still need.
    ///
    /// Counted from the fork point between our state and the best chain, not from the state height:
    /// after a header-first sync the best chain may have switched branches, and replaying from
    /// `state_height + 1` would then skip the new branch's own history.
    pub fn next_body_height(&self) -> Option<u64> {
        let best = self.chain.best_id();
        let ancestor = self.common_ancestor(&self.state_tip, &best)?;
        self.chain.meta(&ancestor).map(|meta| meta.height + 1)
    }

    /// Store a header without its body (snapshot sync fetches headers first, bodies later).
    pub fn insert_header_only(&mut self, header: BlockHeader) -> Result<(), NodeError> {
        self.insert_header_only_at(header, Self::clock_ms()?)
    }

    fn insert_header_only_at(&mut self, header: BlockHeader, now: u128) -> Result<(), NodeError> {
        Self::check_future_timestamp(header.timestamp_unix_ms, now)?;
        let outcome = self.chain.insert(header)?;
        if outcome != vess_consensus::InsertOutcome::Duplicate {
            let meta = self
                .chain
                .meta(&header.id())
                .ok_or(NodeError::Malformed("inserted header missing metadata"))?;
            self.store
                .put_header(&header, meta.height, meta.chain_work)?;
        }
        Ok(())
    }

    pub fn height(&self) -> u64 {
        self.chain.best_height()
    }

    pub fn status(&self) -> StatusInfo {
        StatusInfo {
            network: self.network.network,
            height: self.chain.best_height(),
            tip: self.chain.best_id(),
            chain_work: self.chain.best_work(),
            mempool_transactions: self.mempool.transaction_count() as u32,
            total_supply: self.state.total_supply() as u64,
            next_reward: self.next_reward(),
            next_dev_fee: self.next_dev_fee(),
            next_timestamp_ms: self.next_timestamp_ms(),
            peers_inbound: self.conn.counts().0 as u32,
            peers_outbound: self.conn.counts().1 as u32,
            bans: self.conn.ban_count() as u32,
            prune_blocks: self.prune.blocks,
            prune_headers: self.prune.headers,
            oldest_body_height: self.store.oldest_body_height().unwrap_or(0),
            oldest_header_height: self.store.oldest_header_height().unwrap_or(0),
        }
    }

    /// What a block extending the current tip would pay its miner, net of the development fee.
    pub fn next_reward(&self) -> u64 {
        let parent = self.chain.best_id();
        let height = self.chain.best_height() + 1;
        match vess_consensus::chain::required_target(&self.chain, &self.network, &parent, height) {
            Ok(target) => vess_emission::split(self.network, target).0,
            Err(_) => 0,
        }
    }

    /// The development fee a block extending the current tip would pay out.
    pub fn next_dev_fee(&self) -> u64 {
        let parent = self.chain.best_id();
        let height = self.chain.best_height() + 1;
        match vess_consensus::chain::required_target(&self.chain, &self.network, &parent, height) {
            Ok(target) => vess_emission::split(self.network, target).1,
            Err(_) => 0,
        }
    }

    pub fn account_info(&self, id: &AccountId) -> AccountInfo {
        match self.state.account(id) {
            Some(account) => AccountInfo {
                exists: true,
                balance: account.balance,
                next_nonce: account.next_nonce,
                state_hash: account.state_hash,
            },
            None => AccountInfo::default(),
        }
    }

    pub fn proof(&self, id: &AccountId) -> ProofInfo {
        ProofInfo {
            root: self.state.account_root(),
            value: self.state.account_leaf_value(id),
            siblings: self.state.account_proof(id),
        }
    }

    /// Validate and index a block, then follow whichever branch has the most work.
    ///
    /// The parent's state is reconstructed from stored undo records and bodies, so a block may
    /// extend the tip, an ancestor of it, or a sibling branch. After indexing, `reconcile` makes
    /// the live state match the heaviest branch.
    pub fn accept_block(&mut self, bytes: &[u8]) -> Result<Hash, NodeError> {
        self.accept_block_at(bytes, Self::clock_ms()?)
    }

    pub fn accept_mined_block(&mut self, bytes: &[u8]) -> Result<Option<Hash>, NodeError> {
        let (header, _) = split_block(bytes)?;
        if header.previous_block_id != self.chain.best_id() {
            return Ok(None);
        }
        self.accept_block(bytes).map(Some)
    }

    fn accept_block_at(&mut self, bytes: &[u8], now: u128) -> Result<Hash, NodeError> {
        let (header, _) = split_block(bytes)?;
        Self::check_future_timestamp(header.timestamp_unix_ms, now)?;
        let id = header.id();
        let known = self.chain.contains(&id);
        if known && self.store.body(&id)?.is_some() {
            // Retry an interrupted reconciliation without revalidating irrelevant side branches.
            if self.state_tip != self.chain.best_id()
                && self.chain.is_ancestor(&id, &self.chain.best_id())
            {
                self.finish_block_acceptance()?;
            }
            return Ok(id);
        }
        if !known && !self.chain.contains(&header.previous_block_id) {
            return Err(NodeError::UnknownParent);
        }

        // Validate in both cases: after a header-first sync the header is already known, but the body
        // still has to prove it belongs to that header before it can be replayed.
        let parent_state = self.state_at(&header.previous_block_id)?;
        let validated = validate_block(&self.chain, &self.network, &parent_state, bytes)?;
        if !known {
            self.store.put_block_index(
                &validated.header,
                validated.height,
                validated.chain_work,
                bytes,
            )?;
            self.chain.insert(validated.header)?;
        } else if self.store.body(&id)?.is_none() {
            self.store.put_block_index(
                &validated.header,
                validated.height,
                validated.chain_work,
                bytes,
            )?;
        }

        self.finish_block_acceptance()?;
        self.accepted_blocks += 1;
        Ok(id)
    }

    fn finish_block_acceptance(&mut self) -> Result<(), NodeError> {
        self.reconcile()?;
        self.prune_stale()?;
        self.maybe_prune()?;
        for expired in self
            .mempool
            .expire(self.chain.best_header().timestamp_unix_ms / 1_000)
        {
            self.store.remove_pending(&expired.id())?;
        }
        Ok(())
    }

    /// Bring the live state into agreement with the heaviest branch: rewind to the common
    /// ancestor with the new best chain, then replay its bodies forward, committing as we go.
    fn reconcile(&mut self) -> Result<(), NodeError> {
        let target = self.chain.best_id();
        if self.state_tip == target {
            return Ok(());
        }

        let mut unwound = false;
        let mut orphaned: Vec<Transaction> = Vec::new();
        while !self.chain.is_ancestor(&self.state_tip, &target) {
            if let Some(block) = self.store.body(&self.state_tip)? {
                // Stored bodies are whole blocks, header included.
                if let Ok((_, transactions)) = vess_consensus::split_block(&block) {
                    orphaned.extend(transactions);
                }
            }
            let undo = self
                .store
                .undo(&self.state_tip)?
                .ok_or(NodeError::ReorgUnavailable)?;
            self.state.apply_undo(undo);
            let header = self
                .chain
                .header(&self.state_tip)
                .ok_or(NodeError::ReorgUnavailable)?;
            self.state_tip = header.previous_block_id;
            unwound = true;
        }
        if unwound {
            // Incremental diffs are now relative to the wrong parent, so rewrite the view.
            self.store.replace_state(&self.state, &self.state_tip)?;
        }

        // Anything the abandoned blocks contained goes back into the mempool, where it can be
        // included again. The nonce is valid again now that the state has been rewound.
        for tx in orphaned {
            let _ = match tx {
                Transaction::Transfer(t) => self.submit_transfer(t),
                Transaction::StateUpdate(t) => self.submit_state_update(t),
            };
        }

        while self.state_tip != target {
            let next = self
                .chain
                .child_on_path(&self.state_tip, &target)
                .ok_or(NodeError::ReorgUnavailable)?;
            // Headers are allowed to run ahead of bodies (header-first sync), so a missing body is a
            // pause, not a failure: the puller fetches it and comes back.
            let Some(body) = self.store.body(&next)? else {
                break;
            };
            let validated = validate_block(&self.chain, &self.network, &self.state, &body)?;
            self.store.commit_block(&validated, &body)?;
            self.state = validated.state;
            self.state_tip = next;
            // Blocks adopted here were accepted earlier as side branches, so their transactions
            // may still be pending; drop them so the miner cannot re-include them.
            self.prune_included(&validated.transactions)?;
        }
        self.store.set_tip(&self.state_tip)?;
        // The live chain moved; wake any RPC caller waiting on the tip.
        self.tip_signal.publish(self.chain.best_id());
        Ok(())
    }

    /// Remove transactions that are now on the chain from the mempool and pending storage.
    fn prune_included(&mut self, included: &[Transaction]) -> Result<(), NodeError> {
        for tx in included {
            match tx {
                Transaction::Transfer(t) => self.mempool.remove_account(&t.sender_id()),
                Transaction::StateUpdate(t) => self.mempool.remove_account(&t.sender_id()),
            }
            self.mempool.remove_transaction(&tx.id());
            self.store.remove_pending(&tx.id())?;
        }
        Ok(())
    }

    /// Post-state of any known block, reconstructed from the current state.
    fn state_at(&self, target: &Hash) -> Result<State, NodeError> {
        if *target == self.state_tip {
            return Ok(self.state.clone());
        }
        let ancestor = self
            .common_ancestor(&self.state_tip, target)
            .ok_or(NodeError::UnknownParent)?;

        let mut state = self.state.clone();
        let mut cursor = self.state_tip;
        while cursor != ancestor {
            let undo = self
                .store
                .undo(&cursor)?
                .ok_or(NodeError::ReorgUnavailable)?;
            state.apply_undo(undo);
            cursor = self
                .chain
                .header(&cursor)
                .ok_or(NodeError::ReorgUnavailable)?
                .previous_block_id;
        }
        while cursor != *target {
            let next = self
                .chain
                .child_on_path(&cursor, target)
                .ok_or(NodeError::UnknownParent)?;
            let body = self.store.body(&next)?.ok_or(NodeError::ReorgUnavailable)?;
            let validated = validate_block(&self.chain, &self.network, &state, &body)?;
            state = validated.state;
            cursor = next;
        }
        Ok(state)
    }

    fn common_ancestor(&self, a: &Hash, b: &Hash) -> Option<Hash> {
        let height = |id: &Hash| self.chain.meta(id).map(|m| m.height);
        let mut x = *a;
        let mut y = *b;
        while height(&x)? > height(&y)? {
            x = self.chain.header(&x)?.previous_block_id;
        }
        while height(&y)? > height(&x)? {
            y = self.chain.header(&y)?.previous_block_id;
        }
        while x != y {
            x = self.chain.header(&x)?.previous_block_id;
            y = self.chain.header(&y)?.previous_block_id;
        }
        Some(x)
    }

    /// Main-chain headers from `from_height`, at most `max` of them. Used to answer peers.
    pub fn headers_from(&self, from_height: u64, max: usize) -> Vec<BlockHeader> {
        let mut out = Vec::new();
        let mut height = from_height;
        while out.len() < max {
            match self.chain.main_header_at(height) {
                Some(header) => out.push(header),
                None => break,
            }
            height += 1;
        }
        out
    }

    /// Everything in the mempool, for relaying to peers.
    pub fn pending_transactions(&self) -> Vec<Transaction> {
        self.mempool.pending_transactions()
    }

    pub fn block_body(&self, id: &Hash) -> Option<Vec<u8>> {
        self.store.body(id).ok().flatten()
    }

    /// Whether the full body of this block is available.
    pub fn has_body(&self, id: &Hash) -> bool {
        self.store.body(id).ok().flatten().is_some()
    }

    /// Whether this block's body is still worth fetching: it must be above the state (blocks at or
    /// below it are already applied, and genesis has no body at all) and not already stored.
    pub fn needs_body(&self, id: &Hash) -> bool {
        let Some(meta) = self.chain.meta(id) else {
            return false;
        };
        meta.height > self.state_height() && !self.has_body(id)
    }

    /// What this node advertises to a peer.
    pub fn handshake(&self, listen_port: u16) -> vess_net::Handshake {
        vess_net::local_handshake(
            hash::chain_id(self.network.network),
            // Genesis is a constant of the network, so this works even with pruned headers.
            vess_consensus::genesis_header(&self.network).id(),
            self.chain.best_id(),
            self.chain.best_height(),
            self.chain.best_work(),
            listen_port,
            self.store.oldest_body_height().unwrap_or(0),
            self.store.oldest_header_height().unwrap_or(0),
            self.connection_nonce(),
        )
    }

    /// A stable per-node marker, echoed in every `HELLO`. A node that dials itself sees its own value
    /// come back and drops the session; a fresh value per handshake could never detect that.
    fn connection_nonce(&self) -> [u8; 32] {
        hash::tagged(b"VESS-CONNECTION-NONCE-V1", &[&self.identity])
    }
    /// Build a template from the mempool for the given payout account.
    ///
    /// Transactions that no longer apply to the current state — an overspend, or a nonce already
    /// consumed by a block from another node — are left out rather than failing the template.
    pub fn template(
        &self,
        payout: &AccountId,
        timestamp_unix_ms: u64,
    ) -> Result<(BlockTemplate, u64), NodeError> {
        let candidates = self
            .mempool
            .select_for_template(vess_core::constants::MAX_BLOCK_BYTES);
        let transactions: Vec<Transaction> = candidates
            .into_iter()
            .filter(|tx| self.applies(tx, timestamp_unix_ms))
            .collect();
        let template = build_template(
            &self.chain,
            &self.network,
            &self.chain.best_id(),
            &self.state,
            payout,
            timestamp_unix_ms,
            &transactions,
        )?;
        let height = self.chain.best_height() + 1;
        Ok((template, height))
    }

    /// Whether a pending transaction still applies to the current state.
    fn applies(&self, tx: &Transaction, timestamp_unix_ms: u64) -> bool {
        let payout = self.chain.best_header().payout_account_id;
        applies_to(&self.state, &payout, tx, timestamp_unix_ms)
    }

    /// Drop pending transactions that no longer apply, e.g. after a reorganization replayed a
    /// block that spent the same account.
    pub fn prune_stale(&mut self) -> Result<usize, NodeError> {
        let timestamp = self.chain.best_header().timestamp_unix_ms;
        let payout = self.chain.best_header().payout_account_id;
        let state = &self.state;
        let mut stale: Vec<Transaction> = Vec::new();
        self.mempool.retain_valid(|tx| {
            let ok = applies_to(state, &payout, tx, timestamp);
            if !ok {
                stale.push(tx.clone());
            }
            ok
        });
        for tx in &stale {
            self.store.remove_pending(&tx.id())?;
        }
        Ok(stale.len())
    }

    fn clock_ms() -> Result<u128, NodeError> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| NodeError::Io(format!("system clock before Unix epoch: {e}")))?
            .as_millis())
    }

    fn check_future_timestamp(timestamp: u64, now: u128) -> Result<(), NodeError> {
        if !Self::future_timestamp_allowed(timestamp, now) {
            return Err(NodeError::Consensus(ConsensusError::BadTimestamp));
        }
        Ok(())
    }

    fn future_timestamp_allowed(timestamp: u64, now: u128) -> bool {
        u128::from(timestamp) <= now + u128::from(vess_core::constants::MAX_FUTURE_DRIFT_MS)
    }

    /// Select a timestamp close to the local clock and above median time.
    pub fn next_timestamp_ms(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_millis()
            .try_into()
            .expect("system clock exceeds u64 milliseconds");
        let median = vess_consensus::chain::median_time_past(&self.chain, &self.chain.best_id())
            .expect("best chain must have a complete median-time window");
        Self::timestamp_for_clock(now, median)
    }

    fn timestamp_for_clock(now: u64, median: u64) -> u64 {
        now.max(median.saturating_add(1))
    }

    /// The checks that need no node state: protocol version, chain, and signature.
    ///
    /// Separate from [`Self::apply_transfer`] so a caller can run the expensive ML-DSA verification
    /// before taking the node lock.
    pub fn check_transfer(network: NetworkProfile, tx: &Transfer) -> Result<(), NodeError> {
        if tx.version != vess_core::constants::PROTOCOL_VERSION {
            return Err(NodeError::Malformed("unsupported version"));
        }
        if tx.chain_id != hash::chain_id(network.network) {
            return Err(NodeError::Malformed("wrong chain"));
        }
        if !vess_crypto::verify(
            &tx.sender_public_key,
            DOM_TRANSFER,
            &tx.unsigned_bytes(),
            &tx.signature,
        ) {
            return Err(NodeError::Malformed("bad signature"));
        }
        Ok(())
    }

    /// Admit a transfer that has passed [`Self::check_transfer`].
    pub(crate) fn apply_transfer(&mut self, tx: Transfer) -> Result<Hash, NodeError> {
        let sender = tx.sender_id();
        let account = self
            .state
            .account(&sender)
            .ok_or(NodeError::UnknownAccount)?;
        if tx.nonce != account.next_nonce {
            return Err(NodeError::Malformed("stale nonce"));
        }
        let id = tx.tx_id();
        let canonical = Transaction::Transfer(tx.clone()).canonical();
        match self.mempool.add_transaction(Transaction::Transfer(tx))? {
            AddOutcome::Added | AddOutcome::Replaced => {}
        }
        self.store.put_pending(&id, &canonical)?;
        self.accepted_transactions += 1;
        Ok(id)
    }

    pub fn submit_transfer(&mut self, tx: Transfer) -> Result<Hash, NodeError> {
        Self::check_transfer(self.network, &tx)?;
        self.apply_transfer(tx)
    }

    /// The checks that need no node state, for a state update.
    pub fn check_state_update(network: NetworkProfile, tx: &StateUpdate) -> Result<(), NodeError> {
        if tx.version != vess_core::constants::PROTOCOL_VERSION {
            return Err(NodeError::Malformed("unsupported version"));
        }
        if tx.chain_id != hash::chain_id(network.network) {
            return Err(NodeError::Malformed("wrong chain"));
        }
        if !vess_crypto::verify(
            &tx.sender_public_key,
            DOM_STATE_UPDATE,
            &tx.unsigned_bytes(),
            &tx.signature,
        ) {
            return Err(NodeError::Malformed("bad signature"));
        }
        Ok(())
    }

    /// Admit a state update that has passed [`Self::check_state_update`].
    pub(crate) fn apply_state_update(&mut self, tx: StateUpdate) -> Result<Hash, NodeError> {
        let sender = tx.sender_id();
        let account = self
            .state
            .account(&sender)
            .ok_or(NodeError::UnknownAccount)?;
        if tx.nonce != account.next_nonce {
            return Err(NodeError::Malformed("stale nonce"));
        }
        let id = tx.tx_id();
        let canonical = Transaction::StateUpdate(tx.clone()).canonical();
        self.mempool.add_transaction(Transaction::StateUpdate(tx))?;
        self.store.put_pending(&id, &canonical)?;
        self.accepted_transactions += 1;
        Ok(id)
    }

    pub fn submit_state_update(&mut self, tx: StateUpdate) -> Result<Hash, NodeError> {
        Self::check_state_update(self.network, &tx)?;
        self.apply_state_update(tx)
    }

    /// Re-admit everything that was pending before the last shutdown.
    fn restore_mempool(&mut self) {
        for bytes in self.store.load_pending().unwrap_or_default() {
            let mut reader = vess_core::codec::Reader::new(&bytes);
            match Transaction::decode_from(&mut reader, vess_core::constants::MAX_TRANSACTION_BYTES)
            {
                Ok(Transaction::Transfer(tx)) => {
                    let _ = self.submit_transfer(tx);
                }
                Ok(Transaction::StateUpdate(tx)) => {
                    let _ = self.submit_state_update(tx);
                }
                _ => {}
            }
        }
        self.accepted_transactions = 0;
    }

    pub fn balance(&self, id: &AccountId) -> u64 {
        self.state.balance(id)
    }

    pub fn root(&self) -> Hash {
        self.state.root()
    }

    /// Dispatch one RPC request. Never panics on hostile input.
    pub fn handle_rpc(&mut self, request: Request) -> Reply {
        match request {
            Request::Status => Reply::ok(ReplyBody::Status(self.status())),
            Request::Balance(id) => Reply::ok(ReplyBody::Account(self.account_info(&id))),
            Request::Template(payout) => {
                let ts = self.next_timestamp_ms();
                match self.template(&payout, ts) {
                    Ok((template, height)) => {
                        let reward = vess_emission::split(self.network, template.header.target).0;
                        let transactions =
                            vess_consensus::decode_body(&template.body).unwrap_or_default();
                        Reply::ok(ReplyBody::Template(TemplateInfo {
                            header: template.header,
                            height,
                            reward,
                            transactions,
                        }))
                    }
                    Err(NodeError::Consensus(_)) => Reply::reject(reason::CONSENSUS),
                    Err(NodeError::Storage(_)) => Reply::reject(reason::STORAGE),
                    Err(_) => Reply::reject(reason::BAD_REQUEST),
                }
            }
            Request::SubmitBlock(bytes) => match self.accept_block(&bytes) {
                Ok(id) => Reply::ok(ReplyBody::Accepted(id)),
                Err(NodeError::UnknownParent) => Reply::reject(reason::NOT_TIP),
                Err(NodeError::Consensus(_)) => Reply::reject(reason::CONSENSUS),
                Err(NodeError::Storage(_)) => Reply::reject(reason::STORAGE),
                Err(_) => Reply::reject(reason::MALFORMED),
            },
            Request::SubmitMinedBlock(bytes) => match self.accept_mined_block(&bytes) {
                Ok(Some(id)) => Reply::ok(ReplyBody::Accepted(id)),
                Ok(None) | Err(NodeError::UnknownParent) => Reply::reject(reason::NOT_TIP),
                Err(NodeError::Consensus(_)) => Reply::reject(reason::CONSENSUS),
                Err(NodeError::Storage(_)) => Reply::reject(reason::STORAGE),
                Err(_) => Reply::reject(reason::MALFORMED),
            },
            Request::SubmitTransfer(tx) => match self.submit_transfer(tx) {
                Ok(id) => Reply::ok(ReplyBody::Accepted(id)),
                Err(NodeError::Mempool(_)) => Reply::reject(reason::MEMPOOL),
                Err(NodeError::UnknownAccount) => Reply::reject(reason::UNKNOWN_ACCOUNT),
                Err(_) => Reply::reject(reason::MALFORMED),
            },
            Request::SubmitStateUpdate(tx) => match self.submit_state_update(tx) {
                Ok(id) => Reply::ok(ReplyBody::Accepted(id)),
                Err(NodeError::Mempool(_)) => Reply::reject(reason::MEMPOOL),
                Err(NodeError::UnknownAccount) => Reply::reject(reason::UNKNOWN_ACCOUNT),
                Err(_) => Reply::reject(reason::MALFORMED),
            },
            Request::Proof(id) => Reply::ok(ReplyBody::Proof(self.proof(&id))),
            Request::Block(query) => match self.block_info(query) {
                Some(info) => Reply::ok(ReplyBody::Block(info)),
                None => Reply::reject(reason::NOT_FOUND),
            },
            Request::Transaction(id) => {
                Reply::ok(ReplyBody::Transaction(self.transaction_info(&id)))
            }
            // `serve` answers these without the node lock, because they may block for seconds.
            // Reaching here means a caller asked a bare `Node` and gets the immediate answer.
            Request::WaitForTip { .. } => Reply::ok(ReplyBody::Tip {
                tip: self.chain.best_id(),
                height: self.chain.best_height(),
            }),
            Request::WaitForAccount { account, .. } => {
                Reply::ok(ReplyBody::Account(self.account_info(&account)))
            }
            Request::Stop => Reply::ok(ReplyBody::Empty),
        }
    }

    /// A block by height on the main chain, or by id (which may be a side branch).
    pub fn block_info(&self, query: BlockQuery) -> Option<BlockInfo> {
        let id = match query {
            BlockQuery::Height(height) => self.chain.main_header_at(height)?.id(),
            BlockQuery::Id(id) => id,
        };
        let meta = self.chain.meta(&id)?;
        let body = self.store.body(&id).ok().flatten()?;
        let (header, transactions) = split_block(&body).ok()?;
        Some(BlockInfo {
            id,
            height: meta.height,
            timestamp_unix_ms: header.timestamp_unix_ms,
            state_root: header.state_root,
            chain_work: meta.chain_work,
            transaction_ids: transactions.iter().map(|tx| tx.id()).collect(),
        })
    }

    /// Where a transaction is — pending, mined and how deep, orphaned, or gone from our window — and,
    /// when we have seen it, what it does. A scanner watching for deposits needs both halves: a block
    /// lists only ids, so without sender/recipient/amount it cannot tell who paid it.
    pub fn transaction_info(&self, txid: &Hash) -> TransactionInfo {
        let in_mempool = self
            .mempool
            .pending_transactions()
            .iter()
            .any(|tx| tx.id() == *txid);
        let mut info = TransactionInfo {
            transaction_id: *txid,
            in_mempool,
            ..TransactionInfo::default()
        };
        let best_height = self.chain.best_height();
        let location = self.store.transaction_location(txid).ok().flatten();
        if let Some((block_id, stored_height)) = location {
            match self.chain.meta(&block_id) {
                // The header is still here, so membership on the main chain is checkable.
                Some(meta) => {
                    let on_main = self
                        .chain
                        .main_header_at(meta.height)
                        .map(|header| header.id() == block_id)
                        .unwrap_or(false);
                    if on_main {
                        info.status = tx_status::MINED;
                        info.block_id = Some(block_id);
                        info.height = Some(meta.height);
                        info.confirmations = best_height.saturating_sub(meta.height) + 1;
                    } else if in_mempool {
                        // A reorg put it back in the pool, so it is actionable again.
                        info.status = tx_status::PENDING;
                    } else {
                        info.status = tx_status::ORPHANED;
                        info.block_id = Some(block_id);
                        info.height = Some(meta.height);
                    }
                }
                // The header has been pruned. The index still knows where it was mined, and a
                // deposit that deep is not going to be reorged out, so report it as pruned rather
                // than pretending it is unknown.
                None => match stored_height {
                    Some(height) if height <= best_height => {
                        info.status = tx_status::PRUNED;
                        info.block_id = Some(block_id);
                        info.height = Some(height);
                        info.confirmations = best_height.saturating_sub(height) + 1;
                    }
                    _ => {
                        if in_mempool {
                            info.status = tx_status::PENDING;
                        }
                    }
                },
            }
        } else if in_mempool {
            info.status = tx_status::PENDING;
        }
        if let Some(tx) = self.find_transaction(txid) {
            info.kind = tx.kind();
            match tx {
                Transaction::Transfer(t) => {
                    info.sender_id = t.sender_id();
                    info.recipient_id = t.recipient_account_id;
                    info.amount = t.amount;
                    info.fee = t.fee;
                }
                Transaction::StateUpdate(t) => {
                    info.sender_id = t.sender_id();
                    info.fee = t.fee;
                    info.new_state_hash = t.new_state_hash;
                }
            }
        }
        info
    }

    /// The transaction itself, from the mempool or from the body of the block that carries it.
    fn find_transaction(&self, txid: &Hash) -> Option<Transaction> {
        if let Some(tx) = self
            .mempool
            .pending_transactions()
            .into_iter()
            .find(|tx| tx.id() == *txid)
        {
            return Some(tx);
        }
        let block_id = self.store.transaction_block(txid).ok().flatten()?;
        let body = self.store.body(&block_id).ok().flatten()?;
        let (_, transactions) = split_block(&body).ok()?;
        transactions.into_iter().find(|tx| tx.id() == *txid)
    }
}

/// Bind the RPC listener on `addr`, retrying nothing: a busy port is a hard failure.
pub fn bind_rpc(addr: &str) -> Result<TcpListener, NodeError> {
    Ok(TcpListener::bind(addr)?)
}

pub fn addr_of(listener: &TcpListener) -> Result<String, NodeError> {
    Ok(listener.local_addr()?.to_string())
}

/// Longest a `WAIT_FOR_TIP` may block. Kept below `READ_TIMEOUT_MS` so a waiting client always
/// receives its reply instead of hitting its own read timeout.
pub const MAX_WAIT_MS: u32 = 25_000;

/// Take the node lock, recovering a poisoned mutex: one panicking thread must not take RPC down.
fn lock_node(node: &Arc<Mutex<Node>>) -> std::sync::MutexGuard<'_, Node> {
    match node.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Serve RPC requests from a shared node.
pub fn serve(node: Arc<Mutex<Node>>, listener: TcpListener) -> std::io::Result<()> {
    vess_net::rpc::serve_rpc(listener, move |request| {
        // A long-poll must not hold the node lock while it waits, so it is answered here rather
        // than in `handle_rpc`: read the tip under a short lock, wait on the signal, then re-read
        // the height under another short lock.
        if let Request::WaitForTip { after, timeout_ms } = request {
            let signal = lock_node(&node).tip_signal();
            signal.wait_for_change(after, timeout_ms.min(MAX_WAIT_MS));
            let guard = lock_node(&node);
            return Reply::ok(ReplyBody::Tip {
                tip: guard.chain.best_id(),
                height: guard.chain.best_height(),
            });
        }
        // The account long-poll re-checks after every tip change and only returns when the account
        // itself moved, so a wallet is not woken by blocks that do not concern it.
        if let Request::WaitForAccount {
            account,
            since,
            timeout_ms,
        } = &request
        {
            let deadline =
                Instant::now() + Duration::from_millis(u64::from((*timeout_ms).min(MAX_WAIT_MS)));
            let signal = lock_node(&node).tip_signal();
            loop {
                let (current, tip) = {
                    let guard = lock_node(&node);
                    (guard.account_info(account), guard.chain.best_id())
                };
                if current != *since || Instant::now() >= deadline {
                    return Reply::ok(ReplyBody::Account(current));
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                signal.wait_for_change(tip, remaining.as_millis() as u32);
            }
        }
        let mut guard = lock_node(&node);
        guard.handle_rpc(request)
    })
}

/// Convenience for tests and tooling: a single request over a fresh connection.
pub fn call(addr: &str, request: Request) -> Result<Reply, NodeError> {
    let mut client =
        vess_net::rpc::RpcClient::connect(addr).map_err(|e| NodeError::Io(e.to_string()))?;
    client
        .call(&request)
        .map_err(|e| NodeError::Io(e.to_string()))
}

/// Whether a transaction still applies to `state`, evaluated in isolation.
fn applies_to(state: &State, payout: &AccountId, tx: &Transaction, timestamp_unix_ms: u64) -> bool {
    let mut probe = state.clone();
    match tx {
        Transaction::Transfer(t) => probe
            .execute_transfer(t, &t.sender_id(), timestamp_unix_ms / 1_000, payout)
            .is_ok(),
        Transaction::StateUpdate(t) => probe
            .execute_state_update(t, &t.sender_id(), timestamp_unix_ms / 1_000, payout)
            .is_ok(),
    }
}

#[cfg(test)]
mod tests;
