//! Header store, timestamp and target rules, and fork choice.

use std::collections::{BTreeMap, HashMap};

use vess_core::constants::{
    DIFFICULTY_FIRST_RETARGET_HEIGHT, DIFFICULTY_WINDOW_BLOCKS, MAX_FUTURE_DRIFT_SECONDS,
    MAX_PER_BLOCK_ELAPSED_SECONDS, MAX_RETARGET_ELAPSED_SECONDS, MAXIMUM_TARGET,
    MIN_RETARGET_ELAPSED_SECONDS, MINIMUM_TARGET, MTP_SPAN_BLOCKS, NetworkProfile,
    PROTOCOL_VERSION,
};
use vess_core::hash;
use vess_core::{BlockHeader, Hash, U256};
use vess_state::State;

use crate::error::ConsensusError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockMeta {
    pub height: u64,
    pub chain_work: u128,
}

/// Anything that can answer "do you know this header, and how much work is behind it".
pub trait HeaderSource {
    fn header(&self, id: &Hash) -> Option<BlockHeader>;
    fn meta(&self, id: &Hash) -> Option<BlockMeta>;
    fn network(&self) -> NetworkProfile;
    /// Heights whose block id this node refuses to dispute. Empty for a chain that carries none,
    /// which is what the synthetic chains in the tests use.
    fn checkpoints(&self) -> &[Checkpoint] {
        &[]
    }
}

/// A block this network treats as settled: the header chain must contain exactly this id at this
/// height, or it is not this network's chain at all.
///
/// Re-exported from `vess-core::constants`, where the per-network lists live: the type has to sit
/// below the consensus crate so the constants can name it.
pub use vess_core::constants::Checkpoint;

/// Reject `id` at `height` when a checkpoint says that height belongs to another block.
pub fn check_checkpoint(
    checkpoints: &[Checkpoint],
    height: u64,
    id: &Hash,
) -> Result<(), ConsensusError> {
    match checkpoints.iter().find(|c| c.height == height) {
        Some(expected) if expected.id != *id => Err(ConsensusError::CheckpointMismatch),
        _ => Ok(()),
    }
}

pub fn empty_state_root() -> Hash {
    State::new().root()
}

pub fn genesis_header(network: &NetworkProfile) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        chain_id: hash::chain_id(network.network),
        previous_block_id: [0u8; 32],
        transaction_root: hash::empty_tx_root(),
        state_root: empty_state_root(),
        timestamp_unix: network.genesis_timestamp,
        target: network.genesis_target,
        payout_account_id: [0u8; 32],
        security_nonce: [0u8; 32],
    }
}

/// Walk back from `id` to the ancestor at `height`.
pub fn ancestor<C: HeaderSource + ?Sized>(
    chain: &C,
    id: &Hash,
    height: u64,
) -> Option<BlockHeader> {
    let mut cur = *id;
    loop {
        let meta = chain.meta(&cur)?;
        if meta.height == height {
            return chain.header(&cur);
        }
        if meta.height < height {
            return None;
        }
        cur = chain.header(&cur)?.previous_block_id;
    }
}

/// Median of the timestamps of `id` and up to ten of its ancestors.
pub fn median_time_past<C: HeaderSource + ?Sized>(
    chain: &C,
    id: &Hash,
) -> Result<u64, ConsensusError> {
    let mut times = Vec::with_capacity(MTP_SPAN_BLOCKS);
    let mut cur = *id;
    for _ in 0..MTP_SPAN_BLOCKS {
        let header = chain.header(&cur).ok_or(ConsensusError::UnknownParent)?;
        times.push(header.timestamp_unix);
        let meta = chain.meta(&cur).ok_or(ConsensusError::UnknownParent)?;
        if meta.height == 0 {
            break;
        }
        cur = header.previous_block_id;
    }
    times.sort_unstable();
    // Fixed lower-median convention: short histories stay deterministic, and a stalled chain
    // can never look cheaper than a moving one.
    Ok(times[(times.len() - 1) / 2])
}

pub fn clamp_target(target: U256) -> U256 {
    if target < MINIMUM_TARGET {
        MINIMUM_TARGET
    } else if target > MAXIMUM_TARGET {
        MAXIMUM_TARGET
    } else {
        target
    }
}

/// The target a block at `height` extending `parent_id` must carry.
pub fn required_target<C: HeaderSource + ?Sized>(
    chain: &C,
    network: &NetworkProfile,
    parent_id: &Hash,
    height: u64,
) -> Result<U256, ConsensusError> {
    let parent = chain
        .header(parent_id)
        .ok_or(ConsensusError::UnknownParent)?;
    if height < DIFFICULTY_FIRST_RETARGET_HEIGHT {
        return Ok(network.genesis_target);
    }
    if !height.is_multiple_of(DIFFICULTY_WINDOW_BLOCKS) {
        return Ok(parent.target);
    }

    // Window: the 64 parent-child deltas ending at the parent.
    let mut elapsed: u64 = 0;
    for i in (height - DIFFICULTY_WINDOW_BLOCKS)..=height - 1 {
        let current = ancestor(chain, parent_id, i).ok_or(ConsensusError::UnknownParent)?;
        let previous = ancestor(chain, parent_id, i - 1).ok_or(ConsensusError::UnknownParent)?;
        let delta = current.timestamp_unix as i128 - previous.timestamp_unix as i128;
        elapsed =
            elapsed.saturating_add(delta.clamp(0, MAX_PER_BLOCK_ELAPSED_SECONDS as i128) as u64);
    }
    let elapsed = elapsed.clamp(MIN_RETARGET_ELAPSED_SECONDS, MAX_RETARGET_ELAPSED_SECONDS);

    let scaled = parent
        .target
        .checked_mul_u64(elapsed)
        .ok_or(ConsensusError::BadTarget)?;
    let (quotient, _) = scaled
        .div_rem(U256::from_u64(DIFFICULTY_WINDOW_BLOCKS))
        .ok_or(ConsensusError::BadTarget)?;
    Ok(clamp_target(quotient))
}

/// Full header validation: version, chain, parent, target, timestamps, and optionally PoW.
pub fn check_header<C: HeaderSource + ?Sized>(
    chain: &C,
    network: &NetworkProfile,
    header: &BlockHeader,
    check_pow: bool,
) -> Result<BlockMeta, ConsensusError> {
    if header.version != PROTOCOL_VERSION {
        return Err(ConsensusError::BadVersion);
    }
    if header.chain_id != hash::chain_id(network.network) {
        return Err(ConsensusError::BadChainId);
    }
    let parent_meta = chain
        .meta(&header.previous_block_id)
        .ok_or(ConsensusError::UnknownParent)?;
    let height = parent_meta
        .height
        .checked_add(1)
        .ok_or(ConsensusError::BadHeader)?;

    // A checkpointed height belongs to one block and no other, whatever the work behind it.
    check_checkpoint(chain.checkpoints(), height, &header.id())?;

    let required = required_target(chain, network, &header.previous_block_id, height)?;
    if header.target != required || header.target < MINIMUM_TARGET || header.target > MAXIMUM_TARGET
    {
        return Err(ConsensusError::BadTarget);
    }

    let mtp = median_time_past(chain, &header.previous_block_id)?;
    if header.timestamp_unix <= mtp
        || header.timestamp_unix > mtp.saturating_add(MAX_FUTURE_DRIFT_SECONDS)
    {
        return Err(ConsensusError::BadTimestamp);
    }

    if check_pow && !header.meets_target() {
        return Err(ConsensusError::BadPow);
    }

    Ok(BlockMeta {
        height,
        chain_work: parent_meta
            .chain_work
            .saturating_add(U256::work_from_target(header.target)),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Extended the current best chain.
    NewTip,
    /// Heavier than the current best chain and not its direct child.
    Reorg,
    /// Stored, but the current best chain is unaffected.
    SideBranch,
    /// Already known.
    Duplicate,
}

#[derive(Debug, Clone)]
pub struct Chain {
    network: NetworkProfile,
    headers: HashMap<Hash, BlockHeader>,
    meta: HashMap<Hash, BlockMeta>,
    main: BTreeMap<u64, Hash>,
    best: Hash,
    checkpoints: Vec<Checkpoint>,
}

impl Chain {
    /// A chain containing only genesis, carrying the network's compiled-in checkpoints.
    pub fn new(network: NetworkProfile) -> Chain {
        Chain::with_checkpoints(
            network,
            vess_core::constants::checkpoints(network.network).to_vec(),
        )
    }

    /// A chain with an explicit checkpoint list. Used by the node (which passes what the binary was
    /// compiled with) and by the tests (which need a checkpoint they can predict).
    pub fn with_checkpoints(network: NetworkProfile, checkpoints: Vec<Checkpoint>) -> Chain {
        let genesis = genesis_header(&network);
        let id = genesis.id();
        let meta = BlockMeta {
            height: 0,
            chain_work: U256::work_from_target(genesis.target),
        };
        let mut main = BTreeMap::new();
        main.insert(0, id);
        Chain {
            network,
            headers: HashMap::from([(id, genesis)]),
            meta: HashMap::from([(id, meta)]),
            main,
            best: id,
            checkpoints,
        }
    }

    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    /// The checkpointed id at `height`, if this chain has one.
    pub fn checkpoint_at(&self, height: u64) -> Option<Hash> {
        self.checkpoints
            .iter()
            .find(|c| c.height == height)
            .map(|c| c.id)
    }

    pub fn network(&self) -> NetworkProfile {
        self.network
    }

    pub fn best_id(&self) -> Hash {
        self.best
    }

    pub fn best_height(&self) -> u64 {
        self.meta[&self.best].height
    }

    pub fn best_work(&self) -> u128 {
        self.meta[&self.best].chain_work
    }

    pub fn best_header(&self) -> BlockHeader {
        self.headers[&self.best]
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.headers.contains_key(id)
    }

    /// Main-chain header at `height`.
    pub fn main_header_at(&self, height: u64) -> Option<BlockHeader> {
        self.main
            .get(&height)
            .and_then(|id| self.headers.get(id).copied())
    }

    pub fn main_height(&self) -> u64 {
        self.main.keys().next_back().copied().unwrap_or(0)
    }

    /// An empty chain with no genesis header.
    ///
    /// Only used when loading a database whose header prefix has been pruned: there is no parent to
    /// validate against, so the stored headers are adopted and the tail is re-checked by the loader.
    pub fn empty(network: NetworkProfile) -> Chain {
        Chain {
            network,
            headers: HashMap::new(),
            meta: HashMap::new(),
            main: BTreeMap::new(),
            best: [0u8; 32],
            checkpoints: vess_core::constants::checkpoints(network.network).to_vec(),
        }
    }

    /// Add a header that was validated when it was written. Its parent may no longer exist.
    pub fn adopt(&mut self, header: BlockHeader, height: u64, chain_work: u128) {
        let id = header.id();
        self.headers.insert(id, header);
        self.meta.insert(id, BlockMeta { height, chain_work });
    }

    /// Pick the best adopted header and rebuild the main chain. Call once after the last `adopt`.
    pub fn finish_loading(&mut self) {
        let best = self
            .meta
            .iter()
            .max_by(|a, b| {
                a.1.chain_work
                    .cmp(&b.1.chain_work)
                    // Equal work: the lower block id wins, as everywhere else.
                    .then(b.0.cmp(a.0))
            })
            .map(|(id, _)| *id);
        if let Some(best) = best {
            self.best = best;
            self.rebuild_main();
        }
    }

    /// Forget headers below `height`, so memory matches a pruned store.
    ///
    /// Genesis is never dropped: it is a constant, and the handshake and empty-state checks want it.
    /// After this, `is_ancestor` and `child_on_path` simply stop at the boundary, which is the same
    /// limit the reorg horizon imposes.
    pub fn prune_below(&mut self, height: u64) {
        if height <= 1 {
            // Genesis is a constant the chain keeps forever; 0/1 means "nothing pruned".
            return;
        }
        let cutoff = height;
        self.main.retain(|block_height, _| *block_height >= cutoff);
        let live: std::collections::HashSet<Hash> = self.main.values().copied().collect();
        let keep_best = self.best;
        self.headers
            .retain(|id, _| live.contains(id) || *id == keep_best);
        self.meta
            .retain(|id, _| live.contains(id) || *id == keep_best);
    }

    /// The lowest main-chain height still held. 0 for an unpruned chain.
    pub fn oldest_main_height(&self) -> u64 {
        self.main.keys().next().copied().unwrap_or(0)
    }

    /// Is `ancestor` on the path from `descendant` back to genesis?
    pub fn is_ancestor(&self, ancestor: &Hash, descendant: &Hash) -> bool {
        let mut cur = *descendant;
        loop {
            if cur == *ancestor {
                return true;
            }
            let Some(meta) = self.meta.get(&cur) else {
                return false;
            };
            if meta.height == 0 {
                return false;
            }
            let Some(header) = self.headers.get(&cur) else {
                return false;
            };
            cur = header.previous_block_id;
        }
    }

    /// The child of `ancestor` that lies on the ancestry of `descendant`.
    pub fn child_on_path(&self, ancestor: &Hash, descendant: &Hash) -> Option<Hash> {
        let target_height = self.meta.get(ancestor)?.height + 1;
        let mut cur = *descendant;
        loop {
            let meta = self.meta.get(&cur)?;
            if meta.height == target_height {
                return Some(cur);
            }
            if meta.height < target_height {
                return None;
            }
            cur = self.headers.get(&cur)?.previous_block_id;
        }
    }

    /// Validate a header against this chain without storing it.
    pub fn validate_header(&self, header: &BlockHeader) -> Result<BlockMeta, ConsensusError> {
        check_header(self, &self.network, header, true)
    }

    pub fn insert(&mut self, header: BlockHeader) -> Result<InsertOutcome, ConsensusError> {
        let id = header.id();
        if self.headers.contains_key(&id) {
            return Ok(InsertOutcome::Duplicate);
        }
        let meta = self.validate_header(&header)?;
        self.headers.insert(id, header);
        self.meta.insert(id, meta);
        Ok(self.select_best(id))
    }

    /// Store a header without checking its proof of work. Test-only: builds synthetic histories
    /// for difficulty tests without spending CPU on mining.
    #[cfg(test)]
    pub(crate) fn insert_unmined(
        &mut self,
        header: BlockHeader,
    ) -> Result<InsertOutcome, ConsensusError> {
        let id = header.id();
        if self.headers.contains_key(&id) {
            return Ok(InsertOutcome::Duplicate);
        }
        let meta = check_header(self, &self.network, &header, false)?;
        self.headers.insert(id, header);
        self.meta.insert(id, meta);
        Ok(self.select_best(id))
    }

    fn select_best(&mut self, id: Hash) -> InsertOutcome {
        let new_meta = self.meta[&id];
        let best_meta = self.meta[&self.best];
        let better = new_meta.chain_work > best_meta.chain_work
            || (new_meta.chain_work == best_meta.chain_work && id < self.best);
        if !better {
            return InsertOutcome::SideBranch;
        }
        let extends_tip = self.headers[&id].previous_block_id == self.best;
        self.best = id;
        self.rebuild_main();
        if extends_tip {
            InsertOutcome::NewTip
        } else {
            InsertOutcome::Reorg
        }
    }

    fn rebuild_main(&mut self) {
        let mut path = Vec::new();
        let mut cur = self.best;
        loop {
            let Some(meta) = self.meta.get(&cur).copied() else {
                break;
            };
            path.push((meta.height, cur));
            if meta.height == 0 {
                break;
            }
            // A pruned chain has no header below its boundary, so stop there instead of indexing
            // through a parent that is no longer held.
            match self
                .headers
                .get(&cur)
                .map(|header| header.previous_block_id)
            {
                Some(parent) if self.headers.contains_key(&parent) => cur = parent,
                _ => break,
            }
        }
        self.main = path.into_iter().collect();
    }
}

impl HeaderSource for Chain {
    fn header(&self, id: &Hash) -> Option<BlockHeader> {
        self.headers.get(id).copied()
    }

    fn meta(&self, id: &Hash) -> Option<BlockMeta> {
        self.meta.get(id).copied()
    }

    fn network(&self) -> NetworkProfile {
        self.network
    }

    fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }
}
