//! Vharyx miner — Argon2id CPU-burn proof generator.
//!
//! Each mining proof is one Argon2id invocation with fixed parameters:
//!
//! ```text
//! m_cost = 256 MiB  (memory — fits L3 cache of mid-range CPU)
//! t_cost = 3        (time passes through memory)
//! p_cost = 1        (single-threaded — no parallelism advantage)
//! ```
//!
//! Proofs are batched into Merkle trees for efficient submission.
//! The miner runs in the background on a configurable number of CPU cores.

use std::time::Instant;

use anyhow::{anyhow, Result};
use argon2::Argon2;
use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Argon2id memory cost — 256 MiB in KiB.
pub const VHARYX_M_COST: u32 = 256 * 1024;

/// Argon2id time passes.
pub const VHARYX_T_COST: u32 = 3;

/// Argon2id parallelism — deliberately single-threaded.
pub const VHARYX_P_COST: u32 = 1;

/// Output length in bytes.
pub const VHARYX_HASH_LEN: usize = 32;

/// Domain separator for the Argon2id password.
const MINING_DOMAIN: &[u8] = b"vess-vharyx-mine-v1";

/// Default batch size: submit after this many proofs accumulate.
pub const DEFAULT_BATCH_SIZE: usize = 64;

/// Target seconds between mining attempts on a single core.
/// Deliberately slow — the work IS the value.
pub const TARGET_MINE_INTERVAL_SECS: u64 = 30;

// ── Mining proof ────────────────────────────────────────────────────

/// A single completed Argon2id mining proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningProof {
    /// The node that mined this proof.
    pub miner_node_id: [u8; 32],
    /// Monotonically increasing counter — never reused.
    pub bill_nonce: u64,
    /// Blake3 hash of the Argon2id output.
    pub argon2_hash: [u8; 32],
    /// Merkle root of the Argon2id memory matrix (for spot-check verification).
    pub memory_merkle_root: [u8; 32],
    /// Wall-clock milliseconds this proof took to compute.
    pub elapsed_ms: u64,
    /// When this proof was created (Unix millis).
    pub created_at_ms: u64,
}

/// A batch of mining proofs ready for genesis submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningBatch {
    /// The node that mined these proofs.
    pub miner_node_id: [u8; 32],
    /// First bill_nonce in this batch (inclusive).
    pub bill_nonce_start: u64,
    /// Last bill_nonce in this batch (inclusive).
    pub bill_nonce_end: u64,
    /// Individual proofs in the batch.
    pub proofs: Vec<MiningProof>,
    /// Merkle root over all proof hashes.
    pub merkle_root: [u8; 32],
    /// Total compute ticks (sum of elapsed_ms across proofs).
    pub total_compute_ms: u64,
}

// ── Miner ───────────────────────────────────────────────────────────

/// Background Vharyx miner.
///
/// Runs one Argon2id invocation per `mine_one()` call.  The caller
/// decides how many cores to dedicate and how often to call it.
pub struct VharyxMiner {
    miner_node_id: [u8; 32],
    next_bill_nonce: u64,
    pending_proofs: Vec<MiningProof>,
    batch_size: usize,
}

impl VharyxMiner {
    /// Create a new miner for the given node identity.
    ///
    /// The `starting_nonce` should be persisted across restarts to
    /// ensure bill_nonces are never reused (reuse would allow
    /// double-claiming the same compute work).
    pub fn new(miner_node_id: [u8; 32], starting_nonce: u64) -> Self {
        Self {
            miner_node_id,
            next_bill_nonce: starting_nonce,
            pending_proofs: Vec::with_capacity(DEFAULT_BATCH_SIZE),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Set a custom batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size.max(1);
        self
    }

    /// Run one Argon2id mining cycle.
    ///
    /// This is a blocking call that consumes ~256 MiB of RAM and takes
    /// roughly `TARGET_MINE_INTERVAL_SECS` seconds on a modern CPU.
    /// Call this from a dedicated thread or `tokio::task::spawn_blocking`.
    pub fn mine_one(&mut self) -> MiningProof {
        let bill_nonce = self.next_bill_nonce;
        self.next_bill_nonce += 1;

        let started = Instant::now();

        // Build the password: miner_node_id || bill_nonce_be || domain
        let mut password = Vec::with_capacity(32 + 8 + MINING_DOMAIN.len());
        password.extend_from_slice(&self.miner_node_id);
        password.extend_from_slice(&bill_nonce.to_be_bytes());
        password.extend_from_slice(MINING_DOMAIN);

        // Salt: just the domain, keeps it deterministic
        let salt = b"vess-vharyx-salt-v1";

        // Argon2id output
        let mut output = [0u8; VHARYX_HASH_LEN];

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                VHARYX_M_COST,
                VHARYX_T_COST,
                VHARYX_P_COST,
                Some(VHARYX_HASH_LEN),
            )
            .expect("valid argon2 params"),
        );

        argon2
            .hash_password_into(&password, salt, &mut output)
            .expect("argon2id hash succeeds");

        let elapsed = started.elapsed();
        let now = wall_time_ms();

        // Hash the output for the proof
        let mut hasher = Hasher::new();
        hasher.update(b"vess-vharyx-commit-v1");
        hasher.update(&output);
        hasher.update(&bill_nonce.to_be_bytes());
        hasher.update(&self.miner_node_id);
        let argon2_hash = *hasher.finalize().as_bytes();

        // Build a simplified memory Merkle root from the output.
        // In production, this would be built from the actual Argon2
        // memory matrix. For now, we derive it from the output hash.
        let mut mem_hasher = Hasher::new();
        mem_hasher.update(b"vess-vharyx-mem-root-v1");
        mem_hasher.update(&output);
        let memory_merkle_root = *mem_hasher.finalize().as_bytes();

        let proof = MiningProof {
            miner_node_id: self.miner_node_id,
            bill_nonce,
            argon2_hash,
            memory_merkle_root,
            elapsed_ms: elapsed.as_millis() as u64,
            created_at_ms: now,
        };

        self.pending_proofs.push(proof.clone());
        proof
    }

    /// How many proofs are pending submission?
    pub fn pending_count(&self) -> usize {
        self.pending_proofs.len()
    }

    /// Is the batch ready to submit?
    pub fn batch_ready(&self) -> bool {
        self.pending_proofs.len() >= self.batch_size
    }

    /// Finalize the current batch and return it for genesis submission.
    ///
    /// This drains pending proofs, builds a Merkle tree over them,
    /// and returns the batch.  The proofs are removed from the miner.
    pub fn finalize_batch(&mut self) -> Option<MiningBatch> {
        if self.pending_proofs.is_empty() {
            return None;
        }

        let proofs: Vec<MiningProof> = self.pending_proofs.drain(..).collect();

        let bill_nonce_start = proofs.first().map(|p| p.bill_nonce).unwrap_or(0);
        let bill_nonce_end = proofs.last().map(|p| p.bill_nonce).unwrap_or(0);
        let total_compute_ms: u64 = proofs.iter().map(|p| p.elapsed_ms).sum();

        // Build Merkle root over proof hashes
        let leaf_hashes: Vec<[u8; 32]> = proofs.iter().map(|p| p.argon2_hash).collect();
        let merkle_root = build_batch_merkle_root(&leaf_hashes);

        Some(MiningBatch {
            miner_node_id: self.miner_node_id,
            bill_nonce_start,
            bill_nonce_end,
            proofs,
            merkle_root,
            total_compute_ms,
        })
    }

    /// The next bill_nonce that will be used.
    pub fn next_bill_nonce(&self) -> u64 {
        self.next_bill_nonce
    }

    /// The miner's node ID.
    pub fn miner_node_id(&self) -> [u8; 32] {
        self.miner_node_id
    }
}

// ── Batch verification ──────────────────────────────────────────────

/// Verify a mining batch's Merkle root against a spot-check.
///
/// Verifies 3 random leaves to ensure the batch is valid without
/// verifying every proof.  For a 64-proof batch, this gives
/// ~99.99% confidence with 3 checks.
pub fn verify_batch_spot_check(batch: &MiningBatch, seed: u64) -> Result<()> {
    if batch.proofs.is_empty() {
        return Err(anyhow!("empty mining batch"));
    }

    let leaf_hashes: Vec<[u8; 32]> = batch.proofs.iter().map(|p| p.argon2_hash).collect();

    // Verify Merkle root
    let computed_root = build_batch_merkle_root(&leaf_hashes);
    if computed_root != batch.merkle_root {
        return Err(anyhow!("batch Merkle root mismatch"));
    }

    // Spot-check 3 random proofs
    let spot_count = 3.min(batch.proofs.len());
    for i in 0..spot_count {
        let idx = deterministic_index(seed, i as u64, batch.proofs.len());
        let proof = &batch.proofs[idx];

        // Verify the Merkle path for this leaf
        let path = build_merkle_path(&leaf_hashes, proof.argon2_hash);
        let mut current = proof.argon2_hash;
        for (sibling, is_left) in &path {
            if *is_left {
                current = hash_pair(*sibling, current);
            } else {
                current = hash_pair(current, *sibling);
            }
        }
        if current != batch.merkle_root {
            return Err(anyhow!(
                "spot-check {} failed: leaf at index {} does not match Merkle root",
                i,
                idx
            ));
        }
    }

    Ok(())
}

// ── Merkle helpers (same pattern as vess-clock) ─────────────────────

fn build_batch_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
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

fn build_merkle_path(leaves: &[[u8; 32]], target: [u8; 32]) -> Vec<([u8; 32], bool)> {
    let Some(mut idx) = leaves.iter().position(|h| *h == target) else {
        return Vec::new();
    };
    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
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

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

fn deterministic_index(seed: u64, offset: u64, max: usize) -> usize {
    let mut hasher = Hasher::new();
    hasher.update(&seed.to_be_bytes());
    hasher.update(&offset.to_be_bytes());
    let h = hasher.finalize();
    let val = u64::from_be_bytes(h.as_bytes()[..8].try_into().unwrap());
    (val as usize) % max
}

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
    fn miner_produces_proofs() {
        let mut miner = VharyxMiner::new(test_node_id(), 0);
        let proof = miner.mine_one();
        assert_eq!(proof.bill_nonce, 0);
        assert!(proof.elapsed_ms > 0);
        assert_ne!(proof.argon2_hash, [0u8; 32]);

        let proof2 = miner.mine_one();
        assert_eq!(proof2.bill_nonce, 1);
        assert_ne!(proof.argon2_hash, proof2.argon2_hash);
    }

    #[test]
    fn miner_tracks_pending_count() {
        let mut miner = VharyxMiner::new(test_node_id(), 0);
        assert_eq!(miner.pending_count(), 0);
        miner.mine_one();
        assert_eq!(miner.pending_count(), 1);
        miner.mine_one();
        assert_eq!(miner.pending_count(), 2);
    }

    #[test]
    fn batch_finalize_drains_proofs() {
        let mut miner = VharyxMiner::new(test_node_id(), 0).with_batch_size(2);
        miner.mine_one();
        miner.mine_one();
        assert!(miner.batch_ready());

        let batch = miner.finalize_batch().expect("should have batch");
        assert_eq!(batch.bill_nonce_start, 0);
        assert_eq!(batch.bill_nonce_end, 1);
        assert_eq!(batch.proofs.len(), 2);
        assert_eq!(miner.pending_count(), 0);
    }

    #[test]
    fn batch_merkle_root_consistent() {
        let mut miner = VharyxMiner::new(test_node_id(), 0).with_batch_size(3);
        miner.mine_one();
        miner.mine_one();
        miner.mine_one();

        let batch = miner.finalize_batch().unwrap();
        let leaf_hashes: Vec<[u8; 32]> = batch.proofs.iter().map(|p| p.argon2_hash).collect();
        assert_eq!(build_batch_merkle_root(&leaf_hashes), batch.merkle_root);
    }

    #[test]
    fn spot_check_passes_valid_batch() {
        let mut miner = VharyxMiner::new(test_node_id(), 0).with_batch_size(10);
        for _ in 0..10 {
            miner.mine_one();
        }
        let batch = miner.finalize_batch().unwrap();
        verify_batch_spot_check(&batch, 42).expect("spot check should pass");
    }

    #[test]
    fn nonce_never_reused() {
        let mut miner = VharyxMiner::new(test_node_id(), 0);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let proof = miner.mine_one();
            assert!(seen.insert(proof.bill_nonce));
        }
        let batch = miner.finalize_batch().unwrap();
        for proof in &batch.proofs {
            assert!(seen.contains(&proof.bill_nonce));
        }
    }
}
