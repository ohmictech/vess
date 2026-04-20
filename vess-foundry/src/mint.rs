//! Minting loop — background task that produces [`VessBill`]s.
//!
//! The minter:
//! 1. Selects a denomination.
//! 2. Derives a challenge seed from randomness + denomination.
//! 3. Builds the 1 GiB scratchpad.
//! 4. Runs the VM for `base_iterations × denomination_multiplier` steps.
//! 5. Checks the final digest against the difficulty target.
//! 6. On success, generates a STARK proof of the execution trace and emits
//!    a `VessBill`.

use crate::proof;
use crate::vm;
use crate::{Denomination, VessBill};
use blake3::Hasher;
use rand::RngCore;
use tracing;

/// Base number of VM iterations for denomination 1.
#[cfg(not(feature = "test-mint"))]
const BASE_ITERATIONS: u64 = 1 << 20; // ~1M steps

#[cfg(feature = "test-mint")]
const BASE_ITERATIONS: u64 = 1 << 10; // 1024 steps (fast test minting)

/// Difficulty: the digest must have this many leading zero bits for denom 1.
#[cfg(not(feature = "test-mint"))]
const BASE_DIFFICULTY_BITS: u32 = 20;

#[cfg(feature = "test-mint")]
const BASE_DIFFICULTY_BITS: u32 = 4; // Trivial difficulty for test minting

/// Compute the number of VM iterations for a given denomination.
///
/// Higher denominations require linearly more work, so a `100` bill costs
/// roughly 100× the electricity of a `1` bill.
pub fn iterations_for(denom: Denomination) -> u64 {
    BASE_ITERATIONS * denom.multiplier()
}

/// Difficulty (leading zero bits) required for a given denomination.
///
/// Scales logarithmically with denomination value to complement the linear
/// iteration scaling — together they make forgery exponentially harder at
/// higher denominations.
pub fn difficulty_bits_for(denom: Denomination) -> u32 {
    BASE_DIFFICULTY_BITS + denom.series_position()
}

/// Check whether `digest` meets the required number of leading zero bits.
fn meets_difficulty(digest: &[u8; 32], required_bits: u32) -> bool {
    let mut bits_remaining = required_bits;
    for byte in digest.iter() {
        if bits_remaining == 0 {
            return true;
        }
        let lz = byte.leading_zeros();
        if lz < 8.min(bits_remaining) {
            return false;
        }
        bits_remaining = bits_remaining.saturating_sub(8);
    }
    true
}

/// Public wrapper for difficulty checking (used by proof verification).
pub fn meets_difficulty_pub(digest: &[u8; 32], required_bits: u32) -> bool {
    meets_difficulty(digest, required_bits)
}

/// Result of a single minting attempt.
pub enum MintOutcome {
    /// The VM execution did not produce a digest meeting the difficulty target.
    Miss,
    /// A valid bill was minted, along with its STARK proof bytes
    /// (needed for OwnershipGenesis but not stored on the bill).
    Hit {
        bill: VessBill,
        proof_bytes: Vec<u8>,
    },
}

/// Run one minting attempt for the given denomination.
///
/// Returns `MintOutcome::Hit` with a freshly minted bill if the VM digest
/// meets the difficulty target, or `MintOutcome::Miss` otherwise.
///
/// Two-phase execution: first runs the VM without recording a trace
/// (`execute_digest_only`, ~1 GiB scratchpad only). If the digest
/// meets difficulty, re-executes with full trace recording (~72 MiB
/// for D1) and generates the STARK proof. This avoids the trace
/// allocation on the >99.99% of attempts that miss.
pub fn try_mint(denom: Denomination, owner_vk_hash: &[u8; 32]) -> MintOutcome {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    // Derive the challenge seed from nonce + denomination + genesis owner.
    let seed = derive_seed_pub(&nonce, denom, owner_vk_hash);

    let iters = iterations_for(denom);
    let diff = difficulty_bits_for(denom);

    tracing::debug!(
        denomination = ?denom,
        iterations = iters,
        difficulty_bits = diff,
        "Starting minting attempt"
    );

    // Build scratchpad and disk dataset.
    let scratchpad = vm::build_scratchpad(&seed);
    let disk_dataset = vm::build_disk_dataset(owner_vk_hash);

    // Phase 1: fast digest-only check (no trace allocation).
    let digest = vm::execute_digest_only(&scratchpad, &disk_dataset, &seed, iters);

    if !meets_difficulty(&digest, diff) {
        return MintOutcome::Miss;
    }

    tracing::info!(denomination = ?denom, "Minting hit — re-executing with trace for proof");

    // Phase 2: re-execute with full trace for STARK proof generation.
    let trace = vm::execute(&scratchpad, &disk_dataset, &seed, iters);
    debug_assert_eq!(trace.digest, digest, "deterministic re-execution diverged");

    // Generate the IOP proof: Merkle-commit the trace + scratchpad + disk,
    // derive Fiat-Shamir challenges, and open queried positions.
    let iop_proof = proof::generate_proof(&trace, &scratchpad, &disk_dataset, &nonce, denom, owner_vk_hash);
    let proof_bytes = proof::serialize_proof(&iop_proof);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Derive permanent mint_id and genesis chain_tip.
    let mint_id = crate::derive_mint_id(&trace.digest, &nonce);
    let chain_tip = crate::genesis_chain_tip(&mint_id, owner_vk_hash);

    // Self-stealth: minted bills are bound to the minter's own identity.
    let stealth_id = {
        let mut h = Hasher::new();
        h.update(&mint_id);
        h.update(b"vess-self-stealth");
        *h.finalize().as_bytes()
    };

    MintOutcome::Hit {
        bill: VessBill {
            denomination: denom,
            digest: trace.digest,
            created_at: now,
            stealth_id,
            dht_index: 0, // Assigned by the wallet when stored in DHT.
            mint_id,
            chain_tip,
            chain_depth: 0,
        },
        proof_bytes,
    }
}

/// Run the minting loop, retrying until a bill is produced.
///
/// This is the blocking entry point meant to be called from a background
/// thread / tokio `spawn_blocking`.
/// Returns `(bill, proof_bytes)` — the proof is needed for OwnershipGenesis
/// but is NOT stored on the bill itself.
pub fn mint_blocking(denom: Denomination, owner_vk_hash: &[u8; 32]) -> (VessBill, Vec<u8>) {
    let mut attempts = 0u64;
    loop {
        attempts += 1;
        if attempts.is_multiple_of(10) {
            tracing::info!(attempts, denomination = ?denom, "Minting in progress…");
        }
        match try_mint(denom, owner_vk_hash) {
            MintOutcome::Hit { bill, proof_bytes } => {
                tracing::info!(attempts, denomination = ?denom, "Bill minted!");
                return (bill, proof_bytes);
            }
            MintOutcome::Miss => continue,
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────

/// Derive the minting seed from nonce + denomination + genesis owner.
///
/// Public so the proof verifier can reconstruct the seed.
/// Including `owner_vk_hash` binds the STARK to a specific genesis
/// owner — copying the proof with a different owner changes the seed,
/// which changes the entire execution trace, invalidating the proof.
pub fn derive_seed_pub(nonce: &[u8; 32], denom: Denomination, owner_vk_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(nonce);
    h.update(&denom.value().to_le_bytes());
    h.update(owner_vk_hash);
    *h.finalize().as_bytes()
}

// ── Flow-based minting ──────────────────────────────────────────────

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A completed D1 solve, ready for aggregation.
///
/// Proof bytes are NOT stored here (they'd be ~170 KiB each, scaling to
/// GBs over long mining sessions). Instead, the nonce + owner_vk_hash
/// are enough to deterministically regenerate the proof on demand via
/// [`regenerate_proof`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedSolve {
    /// The minted D1 bill.
    pub bill: VessBill,
    /// The nonce that produced this solve (needed for proof regeneration
    /// and aggregate proof construction).
    pub nonce: [u8; 32],
}

/// Persistent state for a mint session, saved to disk after each solve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintSessionState {
    /// Owner's vk_hash (baked into all STARK seeds).
    pub owner_vk_hash: [u8; 32],
    /// Completed D1 solves accumulated so far.
    pub solves: Vec<CompletedSolve>,
    /// Total mining attempts made (across all saves).
    pub total_attempts: u64,
    /// Unix timestamp when the session started.
    pub started_at: u64,
}

impl MintSessionState {
    fn new(owner_vk_hash: [u8; 32]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            owner_vk_hash,
            solves: Vec::new(),
            total_attempts: 0,
            started_at: now,
        }
    }

    /// Load from a file, or create a new session if the file doesn't exist.
    pub fn load_or_create(path: &Path, owner_vk_hash: [u8; 32]) -> Self {
        if path.exists() {
            match std::fs::read(path) {
                Ok(data) => match serde_json::from_slice::<MintSessionState>(&data) {
                    Ok(mut state) => {
                        // Verify the owner matches.
                        if state.owner_vk_hash == owner_vk_hash {
                            tracing::info!(
                                solves = state.solves.len(),
                                "Resuming mint session"
                            );
                            return state;
                        }
                        tracing::warn!("Existing session has different owner — starting fresh");
                        state = Self::new(owner_vk_hash);
                        state
                    }
                    Err(e) => {
                        tracing::warn!("Corrupt session file: {e} — starting fresh");
                        Self::new(owner_vk_hash)
                    }
                },
                Err(e) => {
                    tracing::warn!("Cannot read session file: {e} — starting fresh");
                    Self::new(owner_vk_hash)
                }
            }
        } else {
            Self::new(owner_vk_hash)
        }
    }

    /// Atomically save to disk (write to temp + rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let data = serde_json::to_vec_pretty(self)
            .map_err(std::io::Error::other)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Run one D1 mining attempt using the digest-only fast path.
///
/// On a hit, verifies the digest against difficulty and returns a
/// `CompletedSolve` with the nonce (but NO proof bytes — those are
/// regenerated lazily at finalization via [`regenerate_proof`]).
/// Returns `None` on a miss.
pub fn try_mint_d1(owner_vk_hash: &[u8; 32]) -> Option<CompletedSolve> {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);

    let denom = Denomination::D1;
    let seed = derive_seed_pub(&nonce, denom, owner_vk_hash);
    let iters = iterations_for(denom);
    let diff = difficulty_bits_for(denom);

    // Build scratchpad and disk dataset.
    let scratchpad = vm::build_scratchpad(&seed);
    let disk_dataset = vm::build_disk_dataset(owner_vk_hash);

    // Fast path: compute only the digest (no trace allocation).
    let digest = vm::execute_digest_only(&scratchpad, &disk_dataset, &seed, iters);

    if !meets_difficulty(&digest, diff) {
        return None;
    }

    tracing::info!("D1 solve found");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mint_id = crate::derive_mint_id(&digest, &nonce);
    let chain_tip = crate::genesis_chain_tip(&mint_id, owner_vk_hash);

    let stealth_id = {
        let mut h = Hasher::new();
        h.update(&mint_id);
        h.update(b"vess-self-stealth");
        *h.finalize().as_bytes()
    };

    let bill = VessBill {
        denomination: denom,
        digest,
        created_at: now,
        stealth_id,
        dht_index: 0,
        mint_id,
        chain_tip,
        chain_depth: 0,
    };

    Some(CompletedSolve { bill, nonce })
}

/// Regenerate the STARK proof for a completed solve.
///
/// Deterministic: same `nonce + owner_vk_hash` always produces the same
/// proof. This avoids storing ~170 KiB of proof bytes per solve in the
/// session file, keeping storage at ~100 bytes per solve regardless of
/// how many solves accumulate.
///
/// Called lazily at finalization time, one solve at a time.
pub fn regenerate_proof(solve: &CompletedSolve, owner_vk_hash: &[u8; 32]) -> Vec<u8> {
    let denom = Denomination::D1;
    let seed = derive_seed_pub(&solve.nonce, denom, owner_vk_hash);
    let iters = iterations_for(denom);

    let scratchpad = vm::build_scratchpad(&seed);
    let disk_dataset = vm::build_disk_dataset(owner_vk_hash);
    let trace = vm::execute(&scratchpad, &disk_dataset, &seed, iters);
    debug_assert_eq!(trace.digest, solve.bill.digest, "deterministic re-execution diverged");

    let iop_proof = proof::generate_proof(&trace, &scratchpad, &disk_dataset, &solve.nonce, denom, owner_vk_hash);
    proof::serialize_proof(&iop_proof)
}

/// Run the D1 mining loop until the stop flag is set.
///
/// Checkpoints completed solves to the session file after each hit.
/// Returns the final session state.
pub fn mine_flow(
    session_path: &Path,
    owner_vk_hash: &[u8; 32],
    stop: Arc<AtomicBool>,
    on_solve: impl Fn(usize, u64),
) -> MintSessionState {
    let mut state = MintSessionState::load_or_create(session_path, *owner_vk_hash);

    while !stop.load(Ordering::Relaxed) {
        state.total_attempts += 1;

        if let Some(solve) = try_mint_d1(owner_vk_hash) {
            state.solves.push(solve);
            let count = state.solves.len();

            // Checkpoint to disk after every solve.
            if let Err(e) = state.save(session_path) {
                tracing::error!("Failed to checkpoint session: {e}");
            }

            on_solve(count, state.total_attempts);
        }

        if state.total_attempts.is_multiple_of(10_000) {
            tracing::debug!(attempts = state.total_attempts, "Mining in progress…");
        }
    }

    state
}

// ── Aggregation ─────────────────────────────────────────────────────

/// Compute the optimal denomination breakdown for `total` vess using
/// the 1-2-5 series, minimizing the number of bills.
///
/// No denomination cap: sampled aggregate proofs keep proof size at
/// ~14 MiB constant regardless of denomination. A $1M payment can be
/// a single bill rather than millions of small ones.
///
/// Example: 250 → [V200, V50]
pub fn optimal_breakdown(total: u64) -> Vec<Denomination> {
    if total == 0 {
        return Vec::new();
    }

    let series = Denomination::series_up_to(total);
    let mut remaining = total;
    let mut result = Vec::new();

    for denom in &series {
        let v = denom.value();
        while remaining >= v {
            result.push(*denom);
            remaining -= v;
        }
    }

    result
}

/// Aggregate completed D1 solves into optimally-denominated bills.
///
/// Takes `N` individual D1 solves and produces the minimum number of
/// bills following the 1-2-5 denomination series. Each aggregated bill's
/// proof is either:
///
/// - **AggregateProof** (≤80 solves): bundles all individual STARK proofs.
/// - **SampledAggregateProof** (>80 solves): Merkle commitment over all
///   digests/nonces + 80 random STARK proofs. Constant ~14 MiB regardless
///   of denomination.
///
/// Only the sampled proofs (~80) are regenerated for large batches, making
/// finalization O(1) in wall-clock time regardless of denomination.
pub fn aggregate_solves(
    solves: &[CompletedSolve],
    owner_vk_hash: &[u8; 32],
    on_proof_regen: Option<&dyn Fn(usize, usize)>,
) -> Vec<(VessBill, Vec<u8>)> {
    if solves.is_empty() {
        return Vec::new();
    }

    let total = solves.len() as u64;
    let breakdown = optimal_breakdown(total);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut solve_offset = 0usize;
    let mut result = Vec::new();
    let total_solves = solves.len();

    for denom in breakdown {
        let count = denom.value() as usize;
        let batch = &solves[solve_offset..solve_offset + count];
        solve_offset += count;

        if count == 1 {
            // D1 — single STARK proof.
            let solve = &batch[0];
            if let Some(cb) = on_proof_regen.as_ref() {
                cb(solve_offset, total_solves);
            }
            let proof_bytes = regenerate_proof(solve, owner_vk_hash);
            let mut bill = solve.bill.clone();
            bill.created_at = now;
            result.push((bill, proof_bytes));
        } else if count <= 80 {
            // Small aggregate — full AggregateProof (all proofs bundled).
            let proof_bytes_batch: Vec<Vec<u8>> = batch
                .iter()
                .enumerate()
                .map(|(i, solve)| {
                    if let Some(cb) = on_proof_regen.as_ref() {
                        cb(solve_offset - count + i + 1, total_solves);
                    }
                    regenerate_proof(solve, owner_vk_hash)
                })
                .collect();

            let agg = proof::AggregateProof {
                d1_proofs: proof_bytes_batch,
                d1_digests: batch.iter().map(|s| s.bill.digest).collect(),
                owner_vk_hash: *owner_vk_hash,
            };

            let compound_digest = agg.compound_digest()
                .expect("freshly-created aggregate sub-proofs must deserialize");
            let proof_bytes = agg.serialize();

            let aggregate_nonce = {
                let mut h = Hasher::new();
                h.update(b"vess-aggregate-nonce-v0");
                for s in batch {
                    h.update(&s.nonce);
                }
                *h.finalize().as_bytes()
            };
            let mint_id = crate::derive_mint_id(&compound_digest, &aggregate_nonce);
            let chain_tip = crate::genesis_chain_tip(&mint_id, owner_vk_hash);

            let stealth_id = {
                let mut h = Hasher::new();
                h.update(&mint_id);
                h.update(b"vess-self-stealth");
                *h.finalize().as_bytes()
            };

            result.push((VessBill {
                denomination: denom,
                digest: compound_digest,
                created_at: now,
                stealth_id,
                dht_index: 0,
                mint_id,
                chain_tip,
                chain_depth: 0,
            }, proof_bytes));
        } else {
            // Large aggregate — sampled proof (~14 MiB constant).
            let digests: Vec<[u8; 32]> = batch.iter().map(|s| s.bill.digest).collect();
            let nonces: Vec<[u8; 32]> = batch.iter().map(|s| s.nonce).collect();

            let sap = proof::build_sampled_aggregate(
                &digests,
                &nonces,
                owner_vk_hash,
                &|idx| {
                    if let Some(cb) = on_proof_regen.as_ref() {
                        cb(solve_offset - count + idx + 1, total_solves);
                    }
                    regenerate_proof(&batch[idx], owner_vk_hash)
                },
            );

            let compound_digest = sap.compound_digest();
            let proof_bytes = sap.serialize();

            // For sampled aggregates, the nonce is the nonce_tree_root
            // (verifier can reproduce this from the proof without needing
            // all N individual nonces).
            let aggregate_nonce = sap.nonce_tree_root;
            let mint_id = crate::derive_mint_id(&compound_digest, &aggregate_nonce);
            let chain_tip = crate::genesis_chain_tip(&mint_id, owner_vk_hash);

            let stealth_id = {
                let mut h = Hasher::new();
                h.update(&mint_id);
                h.update(b"vess-self-stealth");
                *h.finalize().as_bytes()
            };

            result.push((VessBill {
                denomination: denom,
                digest: compound_digest,
                created_at: now,
                stealth_id,
                dht_index: 0,
                mint_id,
                chain_tip,
                chain_depth: 0,
            }, proof_bytes));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_check() {
        let easy = [0x00, 0x00, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(meets_difficulty(&easy, 16));  // 16 leading zeros
        assert!(meets_difficulty(&easy, 20));  // 20 leading zeros (0x0F has 4 lz)
        assert!(!meets_difficulty(&easy, 21)); // needs 21 but only has 20
    }

    #[test]
    fn iteration_scaling() {
        assert_eq!(iterations_for(Denomination::D1), BASE_ITERATIONS);
        assert_eq!(iterations_for(Denomination::D2), BASE_ITERATIONS * 2);
        assert_eq!(iterations_for(Denomination::D50), BASE_ITERATIONS * 50);
    }

    #[test]
    fn seed_derivation_differs_per_denom() {
        let nonce = [0x42u8; 32];
        let s1 = derive_seed_pub(&nonce, Denomination::D1, &[0u8; 32]);
        let s2 = derive_seed_pub(&nonce, Denomination::D2, &[0u8; 32]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn optimal_breakdown_basic() {
        // 1 → [D1]
        assert_eq!(optimal_breakdown(1), vec![Denomination::D1]);
        // 2 → [D2]
        assert_eq!(optimal_breakdown(2), vec![Denomination::D2]);
        // 3 → [D2, D1]
        assert_eq!(optimal_breakdown(3), vec![Denomination::D2, Denomination::D1]);
        // 5 → [D5]
        assert_eq!(optimal_breakdown(5), vec![Denomination::D5]);
        // 7 → [D5, D2]
        assert_eq!(optimal_breakdown(7), vec![Denomination::D5, Denomination::D2]);
        // 13 → [D10, D2, D1]
        assert_eq!(optimal_breakdown(13), vec![Denomination::D10, Denomination::D2, Denomination::D1]);
    }

    #[test]
    fn optimal_breakdown_value_conserved() {
        for n in 1..=200u64 {
            let breakdown = optimal_breakdown(n);
            let sum: u64 = breakdown.iter().map(|d| d.value()).sum();
            assert_eq!(sum, n, "value not conserved for n={n}");
        }
    }

    #[test]
    fn optimal_breakdown_large_denomination() {
        // Without cap, 200 becomes a single D200 bill (not 2 × D100).
        assert_eq!(optimal_breakdown(200), vec![Denomination::D200]);
        // 1000 → [D1000]
        assert_eq!(optimal_breakdown(1000), vec![Denomination::D1000]);
        // 1_000_000 → single bill
        let breakdown = optimal_breakdown(1_000_000);
        let sum: u64 = breakdown.iter().map(|d| d.value()).sum();
        assert_eq!(sum, 1_000_000);
        assert!(breakdown.len() <= 3, "1M should need ≤3 bills");
    }

    #[test]
    fn aggregate_empty() {
        let result = aggregate_solves(&[], &[0u8; 32], None);
        assert!(result.is_empty());
    }
}
