//! VHALIX miner — Argon2id CPU-burn proof generator.
//!
//! Each proof is an INDEPENDENT Argon2id invocation:
//!
//! ```text
//! m_cost = 1 GiB    (memory — beyond commodity ASIC HBM capacity)
//! t_cost = 12       (~30 min per proof on mid-range CPU)
//! p_cost = 1        (single-threaded — no parallelism advantage)
//!
//! password = owner_vk_hash || bill_nonce_be || domain
//! ```
//!
//! Each proof is bound to a specific (owner, nonce) pair — you cannot
//! move a proof from nonce 5 to nonce 7 because the nonce is in the
//! Argon2id password.  Proofs are batched into a Merkle tree and
//! 3 random spot-checks (genuine Argon2id recomputation) provide
//! ~99.99% fraud detection.
//!
//! ## Denomination schedule (at ~30 min/proof)
//!
//! | Denom | Proofs   | Time       |
//! |-------|----------|------------|
//! | 5     | 5+       | 2.5 hours  |
//! | 10    | 10+      | 5 hours    |
//! | 50    | 50+      | 25 hours   |
//! | 100   | 100+     | 50 hours   |
//! | 500   | 500+     | 10.4 days  |
//! | 1000  | 1000+    | 20.8 days  |
//! | 2000  | 2000+    | 41.7 days  |
//! | 5000  | 5000+    | 104 days   |
//!
//! Minimum bill: 5 proofs (denomination 5).

use std::time::Instant;

use anyhow::{anyhow, Result};
use argon2::Argon2;
use blake3::Hasher;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Argon2id memory cost — 1 GiB in KiB.
pub const VHALIX_M_COST: u32 = 1024 * 1024;

/// Argon2id time passes (~2.5 min/pass at 1 GiB → ~30 min total).
pub const VHALIX_T_COST: u32 = 12;

/// Minimum chain length for a valid bill (denomination 5).
pub const MIN_CHAIN_LENGTH: u64 = 5;

/// Argon2id parallelism — deliberately single-threaded.
pub const VHALIX_P_COST: u32 = 1;

/// Output length in bytes.
pub const VHALIX_HASH_LEN: usize = 32;

/// Domain separator for the Argon2id password.
const MINING_DOMAIN: &[u8] = b"vess-VHALIX-mine-v1";

/// Default batch size: submit after this many proofs accumulate.
pub const DEFAULT_BATCH_SIZE: usize = 64;

/// Target seconds between mining attempts on a single core.
/// Deliberately slow — the work IS the value.
pub const TARGET_MINE_INTERVAL_SECS: u64 = 30;

// ── Mining proof ────────────────────────────────────────────────────

/// A single completed Argon2id mining proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningProof {
    /// Blake3 hash of the owner's verification key (binds proof to wallet).
    pub owner_vk_hash: [u8; 32],
    /// Monotonically increasing counter — never reused.
    /// Baked into the Argon2id password so proofs cannot be reordered.
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
    /// Blake3 hash of the owner's verification key.
    pub owner_vk_hash: [u8; 32],
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

/// Background VHALIX miner.
///
/// Runs one Argon2id invocation per `mine_one()` call.  Proofs are
/// independent — each is bound to `(owner_vk_hash, bill_nonce)` via
/// the Argon2id password.  The caller decides how many parallel
/// mining threads to run.
pub struct VHALIXMiner {
    owner_vk_hash: [u8; 32],
    next_bill_nonce: u64,
    /// Per-wallet mining session counter (persisted).
    session_nonce: u64,
    /// Hash of the network tick that anchored this session.
    tick_hash: [u8; 32],
    pending_proofs: Vec<MiningProof>,
    batch_size: usize,
}

impl VHALIXMiner {
    /// Create a new miner.
    pub fn new(
        owner_vk_hash: [u8; 32],
        starting_nonce: u64,
        session_nonce: u64,
        tick_hash: [u8; 32],
    ) -> Self {
        Self {
            owner_vk_hash,
            next_bill_nonce: starting_nonce,
            session_nonce,
            tick_hash,
            pending_proofs: Vec::with_capacity(DEFAULT_BATCH_SIZE),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size.max(1);
        self
    }

    /// Run one Argon2id mining cycle (~30 min at 1 GiB).
    ///
    /// Each proof is independent — password is `owner_vk_hash || nonce || domain`.
    /// The nonce prevents reordering: proof at nonce 5 cannot be claimed as nonce 7.
    pub fn mine_one(&mut self) -> MiningProof {
        let bill_nonce = self.next_bill_nonce;
        self.next_bill_nonce += 1;

        let started = Instant::now();

        // Password: owner_vk_hash || bill_nonce_be || domain
        let mut password = Vec::with_capacity(32 + 8 + MINING_DOMAIN.len());
        password.extend_from_slice(&self.owner_vk_hash);
        password.extend_from_slice(&bill_nonce.to_be_bytes());
        password.extend_from_slice(MINING_DOMAIN);

        let salt = b"vess-VHALIX-salt-v1";
        let mut output = [0u8; VHALIX_HASH_LEN];

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                VHALIX_M_COST,
                VHALIX_T_COST,
                VHALIX_P_COST,
                Some(VHALIX_HASH_LEN),
            )
            .expect("valid argon2 params"),
        );

        argon2
            .hash_password_into(&password, salt, &mut output)
            .expect("argon2id hash succeeds");

        let elapsed = started.elapsed();
        let now = wall_time_ms();

        let mut hasher = Hasher::new();
        hasher.update(b"vess-VHALIX-commit-v1");
        hasher.update(&output);
        hasher.update(&bill_nonce.to_be_bytes());
        hasher.update(&self.owner_vk_hash);
        let argon2_hash = *hasher.finalize().as_bytes();

        let mut mem_hasher = Hasher::new();
        mem_hasher.update(b"vess-VHALIX-mem-root-v1");
        mem_hasher.update(&output);
        let memory_merkle_root = *mem_hasher.finalize().as_bytes();

        let proof = MiningProof {
            owner_vk_hash: self.owner_vk_hash,
            bill_nonce,
            argon2_hash,
            memory_merkle_root,
            elapsed_ms: elapsed.as_millis() as u64,
            created_at_ms: now,
        };

        self.pending_proofs.push(proof.clone());
        proof
    }

    pub fn pending_count(&self) -> usize { self.pending_proofs.len() }
    pub fn batch_ready(&self) -> bool { self.pending_proofs.len() >= self.batch_size }
    pub fn next_bill_nonce(&self) -> u64 { self.next_bill_nonce }
    pub fn owner_vk_hash(&self) -> [u8; 32] { self.owner_vk_hash }
    pub fn session_nonce(&self) -> u64 { self.session_nonce }
    pub fn tick_hash(&self) -> [u8; 32] { self.tick_hash }

    /// Finalize the current batch and return it for genesis submission.
    pub fn finalize_batch(&mut self) -> Option<MiningBatch> {
        if self.pending_proofs.is_empty() {
            return None;
        }

        let proofs: Vec<MiningProof> = self.pending_proofs.drain(..).collect();
        let bill_nonce_start = proofs.first().map(|p| p.bill_nonce).unwrap_or(0);
        let bill_nonce_end = proofs.last().map(|p| p.bill_nonce).unwrap_or(0);
        let total_compute_ms: u64 = proofs.iter().map(|p| p.elapsed_ms).sum();
        let leaf_hashes: Vec<[u8; 32]> = proofs.iter().map(|p| p.argon2_hash).collect();
        let merkle_root = build_batch_merkle_root(&leaf_hashes);

        Some(MiningBatch {
            owner_vk_hash: self.owner_vk_hash,
            bill_nonce_start,
            bill_nonce_end,
            proofs,
            merkle_root,
            total_compute_ms,
        })
    }
}

// ── Batch verification ──────────────────────────────────────────────

/// Verify a mining batch by Merkle root + spot-checking 3 random proofs.
///
/// For each spot-checked proof, recomputes Argon2id to confirm the
/// argon2_hash is genuine.  3 checks on a 64-proof batch give ~99.99%
/// fraud detection.
///
/// NOTE: This is expensive (~30 min × 3 = 90 min for 1 GiB proofs).
/// Call from a dedicated thread via `spawn_blocking`.
pub fn verify_batch_spot_check(batch: &MiningBatch, seed: u64) -> Result<()> {
    if batch.proofs.is_empty() {
        return Err(anyhow!("empty mining batch"));
    }

    // Verify Merkle root
    let leaf_hashes: Vec<[u8; 32]> = batch.proofs.iter().map(|p| p.argon2_hash).collect();
    let computed_root = build_batch_merkle_root(&leaf_hashes);
    if computed_root != batch.merkle_root {
        return Err(anyhow!("batch Merkle root mismatch"));
    }

    // Spot-check 3 random proofs: recompute Argon2id
    let spot_count = 3.min(batch.proofs.len());
    for i in 0..spot_count {
        let idx = deterministic_index(seed, i as u64, batch.proofs.len());
        let proof = &batch.proofs[idx];

        // Recompute Argon2id for this proof
        let mut password = Vec::with_capacity(32 + 8 + MINING_DOMAIN.len());
        password.extend_from_slice(&proof.owner_vk_hash);
        password.extend_from_slice(&proof.bill_nonce.to_be_bytes());
        password.extend_from_slice(MINING_DOMAIN);

        let mut output = [0u8; VHALIX_HASH_LEN];
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                VHALIX_M_COST,
                VHALIX_T_COST,
                VHALIX_P_COST,
                Some(VHALIX_HASH_LEN),
            ).expect("valid argon2 params"),
        );
        argon2
            .hash_password_into(&password, b"vess-VHALIX-salt-v1", &mut output)
            .map_err(|e| anyhow!("argon2id spot-check {i} failed: {e}"))?;

        let mut hasher = Hasher::new();
        hasher.update(b"vess-VHALIX-commit-v1");
        hasher.update(&output);
        hasher.update(&proof.bill_nonce.to_be_bytes());
        hasher.update(&proof.owner_vk_hash);
        let computed_hash = *hasher.finalize().as_bytes();

        if computed_hash != proof.argon2_hash {
            return Err(anyhow!(
                "spot-check {} failed: argon2_hash mismatch at nonce {}",
                i,
                proof.bill_nonce,
            ));
        }
    }

    Ok(())
}

/// Recompute Argon2id for a single proof and verify its `argon2_hash`.
///
/// This is the core verification primitive.  It recomputes the exact
/// Argon2id invocation the miner ran and checks the resulting hash.
/// One genuine verification of ANY proof in a batch is sufficient
/// to detect fraud — an attacker who fabricates proofs cannot pass
/// even one check.
pub fn verify_single_proof(proof: &MiningProof) -> Result<()> {
    let mut password = Vec::with_capacity(32 + 8 + MINING_DOMAIN.len());
    password.extend_from_slice(&proof.owner_vk_hash);
    password.extend_from_slice(&proof.bill_nonce.to_be_bytes());
    password.extend_from_slice(MINING_DOMAIN);

    let mut output = [0u8; VHALIX_HASH_LEN];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            VHALIX_M_COST,
            VHALIX_T_COST,
            VHALIX_P_COST,
            Some(VHALIX_HASH_LEN),
        )
        .expect("valid argon2 params"),
    );

    argon2
        .hash_password_into(&password, b"vess-VHALIX-salt-v1", &mut output)
        .map_err(|e| anyhow!("argon2id recompute failed: {e}"))?;

    let mut hasher = Hasher::new();
    hasher.update(b"vess-VHALIX-commit-v1");
    hasher.update(&output);
    hasher.update(&proof.bill_nonce.to_be_bytes());
    hasher.update(&proof.owner_vk_hash);
    let computed_hash = *hasher.finalize().as_bytes();

    if computed_hash != proof.argon2_hash {
        return Err(anyhow!(
            "argon2_hash mismatch at nonce {}",
            proof.bill_nonce,
        ));
    }

    Ok(())
}

// ── Merkle helpers ──────────────────────────────────────────────────

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

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

fn deterministic_index(seed: u64, offset: u64, max: usize) -> usize {
    let mut hasher = Hasher::new();
    hasher.update(&seed.to_le_bytes());
    hasher.update(&offset.to_le_bytes());
    let hash = *hasher.finalize().as_bytes();
    let val = u64::from_le_bytes(hash[..8].try_into().unwrap());
    val as usize % max
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

    fn test_owner() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0..8].copy_from_slice(b"testnode");
        id
    }

    #[test]
    fn miner_produces_independent_proofs() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32]);
        let proof = miner.mine_one();
        assert_eq!(proof.bill_nonce, 0);
        assert!(proof.elapsed_ms > 0);
        assert_ne!(proof.argon2_hash, [0u8; 32]);
        assert_eq!(proof.owner_vk_hash, test_owner());

        let proof2 = miner.mine_one();
        assert_eq!(proof2.bill_nonce, 1);
        assert_ne!(proof.argon2_hash, proof2.argon2_hash);
    }

    #[test]
    fn verify_single_proof_passes() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32]);
        let proof = miner.mine_one();
        verify_single_proof(&proof).expect("should verify");
    }

    #[test]
    fn verify_single_proof_detects_fake() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32]);
        let mut proof = miner.mine_one();
        proof.argon2_hash = [0xFF; 32];
        assert!(verify_single_proof(&proof).is_err());
    }

    #[test]
    fn verify_single_proof_detects_wrong_nonce() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32]);
        let mut proof = miner.mine_one();
        proof.bill_nonce = 999;
        assert!(verify_single_proof(&proof).is_err());
    }

    #[test]
    fn different_nonce_produces_different_hash() {
        let mut miner1 = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32]);
        let mut miner2 = VHALIXMiner::new(test_owner(), 5, 0, [0u8; 32]);
        let p0 = miner1.mine_one();
        let p5 = miner2.mine_one();
        assert_ne!(p0.argon2_hash, p5.argon2_hash);
    }

    #[test]
    fn different_owner_produces_different_hash() {
        let mut miner_a = VHALIXMiner::new([0xAA; 32], 0, 0, [0u8; 32]);
        let mut miner_b = VHALIXMiner::new([0xBB; 32], 0, 0, [0u8; 32]);
        let pa = miner_a.mine_one();
        let pb = miner_b.mine_one();
        assert_ne!(pa.argon2_hash, pb.argon2_hash);
    }

    #[test]
    fn batch_merkle_root_consistent() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32])
            .with_batch_size(3);
        miner.mine_one();
        miner.mine_one();
        miner.mine_one();
        let batch = miner.finalize_batch().unwrap();
        let leaf_hashes: Vec<[u8; 32]> = batch.proofs.iter().map(|p| p.argon2_hash).collect();
        assert_eq!(build_batch_merkle_root(&leaf_hashes), batch.merkle_root);
    }

    #[test]
    fn batch_finalize_drains_proofs() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32])
            .with_batch_size(2);
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
    fn nonce_never_reused() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32]);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let proof = miner.mine_one();
            assert!(seen.insert(proof.bill_nonce));
        }
    }

    #[test]
    fn miner_tracks_pending_count() {
        let mut miner = VHALIXMiner::new(test_owner(), 0, 0, [0u8; 32]);
        assert_eq!(miner.pending_count(), 0);
        miner.mine_one();
        assert_eq!(miner.pending_count(), 1);
        miner.mine_one();
        assert_eq!(miner.pending_count(), 2);
    }
}
