//! **vess-clock** — Trustless hash tick clock for the Vess network.
//!
//! Each node maintains a sequential hash chain:
//!
//! ```text
//! tick_0 = blake3(node_id || started_at_ms_be || "vess-clock-genesis-v1")
//! tick_n = blake3(tick_{n-1} || n_be || node_id)
//! ```
//!
//! Ticks advance every ~6 seconds (configurable).  The chain is
//! inherently sequential — tick N cannot be computed without first
//! computing ticks 0 through N-1 — providing a verifiable monotonic
//! clock without any external time source.
//!
//! The genesis hash commits to the Unix-millis start time, making
//! `started_at_ms` verifiable: a node cannot claim it started its
//! clock earlier than it actually did, because that would change
//! the genesis hash and invalidate the entire chain.
//!
//! ## Network Time
//!
//! The global "network time" is the **median tick** of all verified
//! peers' clock states, computed by the DHT.  No single node is
//! authoritative.  An attacker controlling < 50% of verified peers
//! cannot accelerate the network clock.
//!
//! ## Tick Proofs
//!
//! A tick proof links a specific tick hash to the node's genesis tick
//! via a Merkle mountain range (MMR).  Any node can verify: "this tick
//! is genuine and corresponds to position N in the chain."
//!
//! ## Lock Integration
//!
//! Ownership claims reference network ticks for time-locks:
//!
//! ```text
//! lock_until_tick: 5_256_000   // don't transfer before this tick
//! ```
//!
//! The DHT validates: "median_tick >= lock_until_tick" before
//! accepting a transfer of the locked bill.

use std::collections::VecDeque;

use blake3::Hash;
use serde::{Deserialize, Serialize};

/// Target tick interval in seconds.
pub const TICK_INTERVAL_SECS: u64 = 6;

/// How many recent ticks to retain for proof generation.
const TICK_HISTORY_DEPTH: usize = 128;

/// How often to create a Merkle checkpoint (every N ticks).
const CHECKPOINT_INTERVAL: u64 = 256;

/// Approximate number of ticks in one year (at 6s/tick).
pub const TICKS_PER_YEAR: u64 = 365 * 24 * 60 * 60 / TICK_INTERVAL_SECS;

/// Domain separator for genesis.
const GENESIS_DOMAIN: &[u8] = b"vess-clock-genesis-v1";

// ── Core types ──────────────────────────────────────────────────────

/// A single tick in a node's hash chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TickEntry {
    /// Zero-based tick index.
    pub tick: u64,
    /// Hash of this tick: `blake3(prev_hash || tick_be || node_id)`.
    pub hash: [u8; 32],
    /// Monotonic wall time when this tick was created (used for drift
    /// detection, not consensus).
    pub wall_time_ms: u64,
}

/// A checkpoint that anchors a range of ticks for Merkle proofs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TickCheckpoint {
    /// The tick number this checkpoint anchors.
    pub tick: u64,
    /// Merkle root of all ticks in this checkpoint's range.
    pub merkle_root: [u8; 32],
}

/// A compact proof that a specific tick exists in a node's chain.
/// Verifiable against the node's genesis hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickProof {
    /// The node this proof belongs to.
    pub node_id: [u8; 32],
    /// The tick number being proven.
    pub tick: u64,
    /// Hash at this tick.
    pub tick_hash: [u8; 32],
    /// Merkle path from this tick to the nearest checkpoint root.
    /// Each entry is (sibling_hash, is_left) — the sibling's position
    /// relative to the current node.  If is_left, sibling was on the
    /// left (so we hash sibling || current).  Otherwise current || sibling.
    pub merkle_path: Vec<([u8; 32], bool)>,
    /// The checkpoint that anchors this proof.
    pub checkpoint: TickCheckpoint,
    /// Direct hash-chain link back to genesis (for proofs within
    /// the most recent checkpoint window).
    pub genesis_hash: [u8; 32],
    /// Wall time when this proof was generated.
    pub proof_time_ms: u64,
}

/// A node's clock state, shared with peers for network-time computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockState {
    /// The node that owns this clock.
    pub node_id: [u8; 32],
    /// Genesis hash: `blake3(node_id || started_at_ms_be || GENESIS_DOMAIN)`.
    /// Verifiable — binds `started_at_ms` to the hash, preventing fabrication.
    pub genesis_hash: [u8; 32],
    /// Current tick number.
    pub current_tick: u64,
    /// Hash at the current tick.
    pub current_hash: [u8; 32],
    /// When this clock was started.  Committed into `genesis_hash`,
    /// so a peer cannot lie about start time without breaking the chain.
    pub started_at_ms: u64,
    /// When the current tick was created.
    pub last_tick_at_ms: u64,
    /// Most recent checkpoint (for proof anchoring).
    pub latest_checkpoint: Option<TickCheckpoint>,
}

/// Network time computed from multiple peers' clock states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTime {
    /// Median tick across observed peers.
    pub median_tick: u64,
    /// Number of peer clocks used in the computation.
    pub observed_peers: usize,
    /// Individual tick samples (for debugging).
    pub tick_samples: Vec<u64>,
    /// When this network time was computed (local wall time).
    pub computed_at_ms: u64,
}

// ── TickChain ───────────────────────────────────────────────────────

/// A node's local hash-tick clock.
///
/// Advances every `TICK_INTERVAL_SECS` seconds. Each tick is a Blake3
/// hash chained to the previous tick, making the chain inherently
/// sequential and non-parallelizable.
pub struct TickChain {
    node_id: [u8; 32],
    genesis_hash: [u8; 32],
    current_tick: u64,
    current_hash: [u8; 32],
    started_at_ms: u64,
    last_tick_at_ms: u64,
    /// Ring buffer of recent ticks for proof generation.
    history: VecDeque<TickEntry>,
    /// Accumulated ticks since last checkpoint.
    ticks_since_checkpoint: Vec<TickEntry>,
    /// Completed checkpoints.
    checkpoints: Vec<TickCheckpoint>,
}

impl TickChain {
    /// Create a new tick chain from a node ID.
    ///
    /// Tick 0 = `blake3(node_id || GENESIS_DOMAIN)`.
    pub fn new(node_id: [u8; 32]) -> Self {
        let now = wall_time_ms();
        let genesis_hash = hash_tick_genesis(&node_id, now);
        let entry = TickEntry {
            tick: 0,
            hash: genesis_hash,
            wall_time_ms: now,
        };

        let mut history = VecDeque::with_capacity(TICK_HISTORY_DEPTH);
        history.push_back(entry.clone());

        Self {
            node_id,
            genesis_hash,
            current_tick: 0,
            current_hash: genesis_hash,
            started_at_ms: now,
            last_tick_at_ms: now,
            history,
            ticks_since_checkpoint: vec![entry],
            checkpoints: Vec::new(),
        }
    }

    /// Advance the clock by one tick.
    ///
    /// Returns the new tick entry.  This is intentionally sequential —
    /// you cannot skip ticks.
    pub fn advance(&mut self) -> TickEntry {
        let next_tick = self.current_tick + 1;
        let next_hash = hash_tick(self.current_hash, next_tick, &self.node_id);
        let now = wall_time_ms();

        let entry = TickEntry {
            tick: next_tick,
            hash: next_hash,
            wall_time_ms: now,
        };

        self.current_tick = next_tick;
        self.current_hash = next_hash;
        self.last_tick_at_ms = now;

        if self.history.len() >= TICK_HISTORY_DEPTH {
            self.history.pop_front();
        }
        self.history.push_back(entry.clone());

        self.ticks_since_checkpoint.push(entry.clone());

        // Create checkpoint every CHECKPOINT_INTERVAL ticks
        if self.ticks_since_checkpoint.len() as u64 >= CHECKPOINT_INTERVAL {
            let merkle_root = build_merkle_root(
                &self
                    .ticks_since_checkpoint
                    .iter()
                    .map(|e| e.hash)
                    .collect::<Vec<_>>(),
            );
            self.checkpoints.push(TickCheckpoint {
                tick: next_tick,
                merkle_root,
            });
            // Keep a few recent checkpoints
            if self.checkpoints.len() > 8 {
                self.checkpoints.remove(0);
            }
            self.ticks_since_checkpoint.clear();
        }

        entry
    }

    /// Return the current clock state for sharing with peers.
    pub fn state(&self) -> ClockState {
        ClockState {
            node_id: self.node_id,
            genesis_hash: self.genesis_hash,
            current_tick: self.current_tick,
            current_hash: self.current_hash,
            started_at_ms: self.started_at_ms,
            last_tick_at_ms: self.last_tick_at_ms,
            latest_checkpoint: self.checkpoints.last().cloned(),
        }
    }

    /// Generate a Merkle proof for a specific tick.
    ///
    /// Returns `None` if the tick is too old (outside history window).
    pub fn prove_tick(&self, tick: u64) -> Option<TickProof> {
        // Find the tick in our history or current checkpoint window
        let entry = self.history.iter().find(|e| e.tick == tick).cloned();
        let entry = entry.or_else(|| {
            self.ticks_since_checkpoint
                .iter()
                .find(|e| e.tick == tick)
                .cloned()
        })?;

        // Find the nearest checkpoint at or after this tick
        let checkpoint = self
            .checkpoints
            .iter()
            .find(|cp| cp.tick >= tick)
            .cloned();

        // Build Merkle path within the checkpoint window
        let merkle_path = if let Some(ref cp) = checkpoint {
            let window_hashes: Vec<[u8; 32]> = self
                .ticks_since_checkpoint
                .iter()
                .map(|e| e.hash)
                .collect();
            build_merkle_path(&window_hashes, entry.hash)
        } else {
            // No checkpoint yet — use the current window
            let window_hashes: Vec<[u8; 32]> = self
                .ticks_since_checkpoint
                .iter()
                .map(|e| e.hash)
                .collect();
            build_merkle_path(&window_hashes, entry.hash)
        };

        Some(TickProof {
            node_id: self.node_id,
            tick: entry.tick,
            tick_hash: entry.hash,
            merkle_path,
            checkpoint: checkpoint.unwrap_or_else(|| {
                // Build a synthetic checkpoint from the current window
                let window_hashes: Vec<[u8; 32]> = self
                    .ticks_since_checkpoint
                    .iter()
                    .map(|e| e.hash)
                    .collect();
                TickCheckpoint {
                    tick: self.current_tick,
                    merkle_root: build_merkle_root(&window_hashes),
                }
            }),
            genesis_hash: self.genesis_hash,
            proof_time_ms: wall_time_ms(),
        })
    }

    /// Verify that a foreign node's clock state is consistent with what
    /// we know about physical time (drift detection).
    ///
    /// Returns `true` if the clock has advanced at a reasonable rate
    /// since `started_at_ms`.
    pub fn verify_clock_rate(state: &ClockState) -> bool {
        let now = wall_time_ms();
        let elapsed_ms = now.saturating_sub(state.started_at_ms);
        let elapsed_secs = elapsed_ms / 1000;

        // At TICK_INTERVAL_SECS per tick, the max expected ticks is
        // elapsed_secs / TICK_INTERVAL_SECS plus some tolerance.
        let max_expected_ticks =
            (elapsed_secs / TICK_INTERVAL_SECS).saturating_add(elapsed_secs / 100); // ~1% tolerance
        let min_expected_ticks = elapsed_secs.saturating_sub(60) / TICK_INTERVAL_SECS;

        state.current_tick <= max_expected_ticks && state.current_tick >= min_expected_ticks
    }

    /// How many ticks ahead of `other` is this clock?
    pub fn ticks_ahead_of(&self, other: &ClockState) -> i64 {
        self.current_tick as i64 - other.current_tick as i64
    }

    // ── Accessors ──

    pub fn node_id(&self) -> [u8; 32] {
        self.node_id
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    pub fn current_hash(&self) -> [u8; 32] {
        self.current_hash
    }

    pub fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }
}

// ── Network time computation ────────────────────────────────────────

/// Compute the network median tick from multiple peers' clock states.
///
/// The median is robust against outliers — a single fast or slow clock
/// doesn't skew the result.
pub fn compute_network_time(peers: &[ClockState]) -> NetworkTime {
    let now = wall_time_ms();
    if peers.is_empty() {
        return NetworkTime {
            median_tick: 0,
            observed_peers: 0,
            tick_samples: Vec::new(),
            computed_at_ms: now,
        };
    }

    let mut ticks: Vec<u64> = peers.iter().map(|p| p.current_tick).collect();
    ticks.sort_unstable();

    let median = if ticks.len() % 2 == 0 {
        let mid = ticks.len() / 2;
        (ticks[mid - 1] + ticks[mid]) / 2
    } else {
        ticks[ticks.len() / 2]
    };

    NetworkTime {
        median_tick: median,
        observed_peers: peers.len(),
        tick_samples: ticks,
        computed_at_ms: now,
    }
}

// ── Hash helpers ────────────────────────────────────────────────────

/// Compute the genesis hash for a node's tick chain.
///
/// `tick_0 = blake3(node_id || started_at_ms_be || GENESIS_DOMAIN)`
///
/// Committing the Unix-millis start time makes `started_at_ms` verifiable:
/// anyone can check that `current_tick ≈ (now - started_at_ms) / 6s`.
/// A node cannot fabricate an older start time without also changing
/// the genesis hash — which would break the entire chain.
pub fn hash_tick_genesis(node_id: &[u8; 32], started_at_ms: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(node_id);
    hasher.update(&started_at_ms.to_be_bytes());
    hasher.update(GENESIS_DOMAIN);
    *hasher.finalize().as_bytes()
}

/// Compute tick_n = blake3(tick_{n-1} || n_be || node_id).
fn hash_tick(prev_hash: [u8; 32], tick: u64, node_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&prev_hash);
    hasher.update(&tick.to_be_bytes());
    hasher.update(node_id);
    *hasher.finalize().as_bytes()
}

/// Verify a tick hash: recompute from genesis and check.
pub fn verify_tick_chain(
    genesis_hash: [u8; 32],
    node_id: &[u8; 32],
    target_tick: u64,
    target_hash: [u8; 32],
) -> bool {
    let mut h = genesis_hash;
    for n in 1..=target_tick {
        h = hash_tick(h, n, node_id);
    }
    h == target_hash
}

/// Verify a tick proof against a known genesis hash.
pub fn verify_tick_proof(proof: &TickProof) -> bool {
    // 1. Verify the checkpoint Merkle root includes this tick
    let mut current = proof.tick_hash;
    for (sibling, is_left) in &proof.merkle_path {
        if *is_left {
            current = hash_pair(*sibling, current);
        } else {
            current = hash_pair(current, *sibling);
        }
    }
    if current != proof.checkpoint.merkle_root {
        return false;
    }

    // 2. Verify the hash chain from genesis to this tick
    verify_tick_chain(
        proof.genesis_hash,
        &proof.node_id,
        proof.tick,
        proof.tick_hash,
    )
}

// ── Merkle tree helpers ─────────────────────────────────────────────

/// Build a Merkle root from a slice of leaf hashes.
fn build_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(chunk[0], chunk[1]));
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// Build a Merkle inclusion path for a specific leaf hash.
/// Returns (sibling_hash, is_left) pairs from leaf to root.
fn build_merkle_path(leaves: &[[u8; 32]], target: [u8; 32]) -> Vec<([u8; 32], bool)> {
    let idx = leaves.iter().position(|h| *h == target);
    let Some(mut idx) = idx else {
        return Vec::new();
    };

    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();

    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
            // is_left = sibling is on the left side
            let is_left = sibling_idx < idx;
            path.push((level[sibling_idx], is_left));
        }
        idx /= 2;

        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_pair(chunk[0], chunk[1]));
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
    }
    path
}

/// Hash two leaves together: blake3(left || right).
fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

// ── Utility ─────────────────────────────────────────────────────────

fn wall_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node_id() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0..8].copy_from_slice(b"testnode");
        id
    }

    #[test]
    fn genesis_is_deterministic() {
        let id = test_node_id();
        let now = wall_time_ms();
        let g1 = hash_tick_genesis(&id, now);
        let g2 = hash_tick_genesis(&id, now);
        assert_eq!(g1, g2);
    }

    #[test]
    fn genesis_differs_per_node() {
        let mut id1 = [0u8; 32];
        let mut id2 = [0u8; 32];
        id1[0] = 1;
        id2[0] = 2;
        let now = wall_time_ms();
        assert_ne!(hash_tick_genesis(&id1, now), hash_tick_genesis(&id2, now));
    }

    #[test]
    fn genesis_differs_per_time() {
        let id = test_node_id();
        assert_ne!(hash_tick_genesis(&id, 1000), hash_tick_genesis(&id, 2000));
    }

    #[test]
    fn tick_chain_is_verifiable() {
        let id = test_node_id();
        let now = wall_time_ms();
        let gen = hash_tick_genesis(&id, now);
        let t1 = hash_tick(gen, 1, &id);
        let t2 = hash_tick(t1, 2, &id);

        assert!(verify_tick_chain(gen, &id, 1, t1));
        assert!(verify_tick_chain(gen, &id, 2, t2));
        assert!(!verify_tick_chain(gen, &id, 2, t1)); // wrong hash
        assert!(!verify_tick_chain(gen, &id, 3, t2)); // wrong tick
    }

    #[test]
    fn tick_chain_advances() {
        let id = test_node_id();
        let mut chain = TickChain::new(id);
        assert_eq!(chain.current_tick(), 0);

        let e1 = chain.advance();
        assert_eq!(e1.tick, 1);
        assert_eq!(chain.current_tick(), 1);

        let e2 = chain.advance();
        assert_eq!(e2.tick, 2);
        assert_ne!(e1.hash, e2.hash);

        // Verify chain integrity
        assert!(verify_tick_chain(
            chain.genesis_hash(),
            &id,
            2,
            chain.current_hash()
        ));
    }

    #[test]
    fn tick_proof_verifies() {
        let id = test_node_id();
        let mut chain = TickChain::new(id);
        for _ in 0..10 {
            chain.advance();
        }

        let proof = chain.prove_tick(5).expect("should have proof for tick 5");
        assert!(verify_tick_proof(&proof));
    }

    #[test]
    fn network_time_median() {
        let make_state = |node_id: u8, tick: u64| ClockState {
            node_id: [node_id; 32],
            genesis_hash: [0; 32],
            current_tick: tick,
            current_hash: [0; 32],
            started_at_ms: 0,
            last_tick_at_ms: 0,
            latest_checkpoint: None,
        };

        let peers = vec![
            make_state(1, 100),
            make_state(2, 200),
            make_state(3, 150),
            make_state(4, 1000), // outlier
            make_state(5, 180),
        ];

        let nt = compute_network_time(&peers);
        assert_eq!(nt.observed_peers, 5);
        // Sorted: 100, 150, 180, 200, 1000 → median = 180
        assert_eq!(nt.median_tick, 180);
    }

    #[test]
    fn clock_rate_verification() {
        let state = ClockState {
            node_id: test_node_id(),
            genesis_hash: [0; 32],
            current_tick: 10,
            current_hash: [0; 32],
            started_at_ms: wall_time_ms() - 60_000, // 60 seconds ago
            last_tick_at_ms: wall_time_ms(),
            latest_checkpoint: None,
        };
        // 60s at 6s/tick = max ~10 ticks. 10 is reasonable.
        assert!(TickChain::verify_clock_rate(&state));
    }

    #[test]
    fn clock_rate_rejects_impossible_speed() {
        let state = ClockState {
            node_id: test_node_id(),
            genesis_hash: [0; 32],
            current_tick: 1_000_000,
            current_hash: [0; 32],
            started_at_ms: wall_time_ms() - 1000, // 1 second ago
            last_tick_at_ms: wall_time_ms(),
            latest_checkpoint: None,
        };
        assert!(!TickChain::verify_clock_rate(&state));
    }

    #[test]
    fn merkle_root_consistent() {
        let leaves: Vec<[u8; 32]> = (0..8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        let root = build_merkle_root(&leaves);
        // Rebuild should give same result
        assert_eq!(root, build_merkle_root(&leaves));
    }

    #[test]
    fn merkle_path_verifies() {
        let leaves: Vec<[u8; 32]> = (0..8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i as u8;
                h
            })
            .collect();
        let root = build_merkle_root(&leaves);
        let target = leaves[3];
        let path = build_merkle_path(&leaves, target);

        // Reconstruct root from path
        let mut current = target;
        for (sibling, is_left) in &path {
            if *is_left {
                current = hash_pair(*sibling, current);
            } else {
                current = hash_pair(current, *sibling);
            }
        }
        assert_eq!(current, root);
    }
}
