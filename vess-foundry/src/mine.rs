//! VHALIX miner — Argon2d proof-of-work with epoch expiry.
//!
//! ```text
//! Argon2d(m_cost=1 GiB, t_cost=1, p_cost=1)
//! password = miner_id || epoch || nonce
//!
//! Difficulty: count leading zero bytes of the 32-byte output.
//! - 5 zeros → 1 VHALIX (base difficulty)
//! - 6 zeros → 2 VHALIX (256× harder)
//! - 7 zeros → 5 VHALIX (65,536× harder)
//!
//! Proofs expire after 2 epochs (48 hours). Nodes must re-mine to
//! maintain DHT trust. The miner_id is the node's public mesh ID,
//! so the proof is bound to a specific node without revealing its
//! wallet keys.
//! ```

use argon2::Argon2;
use serde::{Deserialize, Serialize};

// ── Mining params ───────────────────────────────────────────────────

/// Argon2d memory cost — 1 GiB in KiB (1,048,576 KiB).
pub const ARGON2D_M_COST: u32 = 1024 * 1024;

/// Argon2d time iterations — single pass for fast mining and verification.
pub const ARGON2D_T_COST: u32 = 1;

/// Argon2d parallelism — single-threaded.
pub const ARGON2D_P_COST: u32 = 1;

/// Output length in bytes.
pub const ARGON2D_HASH_LEN: usize = 32;

/// Domain separator for the Argon2d password.
const MINING_DOMAIN: &[u8] = b"vess-VHALIX-mine-v3";

/// Salt for Argon2d.
const MINING_SALT: &[u8] = b"vess-VHALIX-salt-v3";

/// Maximum epoch age before a MintProof is rejected (2 epochs = 48 hours).
pub const MAX_PROOF_EPOCH_AGE: u64 = 2;

// ── Tunable difficulty ──────────────────────────────────────────────

/// Leading zero bytes required for 1 VHALIX.
pub const DIFF_ZEROS_1: u32 = 5;

/// Leading zero bytes required for 2 VHALIX.
pub const DIFF_ZEROS_2: u32 = 6;

/// Leading zero bytes required for 5 VHALIX.
pub const DIFF_ZEROS_5: u32 = 7;

// ── Mint proof ──────────────────────────────────────────────────────

/// A self-verifying proof of Argon2d work.
///
/// Bound to a specific node (via `miner_id`) and epoch.
/// Expires after `MAX_PROOF_EPOCH_AGE` epochs (48 hours).
///
/// Verification:
/// ```text
/// output = Argon2d(miner_id || epoch || nonce)
/// zeros = count_leading_zero_bytes(output)
/// zeros ≥ threshold for denomination_value
/// current_epoch - epoch ≤ MAX_PROOF_EPOCH_AGE
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintProof {
    /// The miner's public mesh node_id (32 bytes).
    pub miner_id: [u8; 32],
    /// Epoch when this proof was mined (from `vess_foundry::clock`).
    pub epoch: u64,
    /// Monotonically increasing counter — never reused.
    pub nonce: u64,
    /// Denomination found: 1, 2, or 5.
    pub denomination_value: u64,
    /// The Argon2d output (32 bytes). Included so verifiers can check
    /// leading zeros without recomputing, but recomputation is cheap.
    pub argon2d_output: [u8; 32],
}

// ── Core mining functions ───────────────────────────────────────────

/// Run one Argon2d hash for a given (miner_id, epoch, nonce) triple.
///
/// Returns the 32-byte Argon2d output.
pub fn mine_argon2d(miner_id: &[u8; 32], epoch: u64, nonce: u64) -> [u8; 32] {
    let mut password = Vec::with_capacity(32 + 8 + 8 + MINING_DOMAIN.len());
    password.extend_from_slice(miner_id);
    password.extend_from_slice(&epoch.to_be_bytes());
    password.extend_from_slice(&nonce.to_be_bytes());
    password.extend_from_slice(MINING_DOMAIN);

    let mut output = [0u8; ARGON2D_HASH_LEN];

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2d,
        argon2::Version::V0x13,
        argon2::Params::new(
            ARGON2D_M_COST,
            ARGON2D_T_COST,
            ARGON2D_P_COST,
            Some(ARGON2D_HASH_LEN),
        )
        .expect("valid argon2d params"),
    );

    argon2
        .hash_password_into(&password, MINING_SALT, &mut output)
        .expect("argon2d hash succeeds");

    output
}

/// Count the number of leading zero bytes in a 32-byte array.
pub fn count_leading_zero_bytes(hash: &[u8; 32]) -> u32 {
    let mut count: u32 = 0;
    for &byte in hash.iter() {
        if byte == 0 {
            count += 1;
        } else {
            break;
        }
    }
    count
}

/// Map a leading-zero count to a denomination value.
///
/// Returns 0 if the difficulty is too low for any denomination.
pub fn zeros_to_denomination(zeros: u32) -> u64 {
    if zeros >= DIFF_ZEROS_5 { return 5; }
    if zeros >= DIFF_ZEROS_2 { return 2; }
    if zeros >= DIFF_ZEROS_1 { return 1; }
    0
}

/// Map a denomination value to the minimum zero count.
pub fn denomination_to_zeros(denom: u64) -> u32 {
    match denom {
        5 => DIFF_ZEROS_5,
        2 => DIFF_ZEROS_2,
        1 => DIFF_ZEROS_1,
        _ => u32::MAX,
    }
}

// ── Verification ────────────────────────────────────────────────────

/// Verify a MintProof by recomputing Argon2d and checking difficulty + epoch freshness.
///
/// Returns `Ok(())` if valid, `Err(msg)` otherwise.
/// Cheap (~0.5–1 sec at 1 GiB) — can be called by every node.
pub fn verify_mint_proof(proof: &MintProof, current_epoch: u64) -> Result<(), String> {
    // Check epoch freshness — proofs expire after MAX_PROOF_EPOCH_AGE epochs
    if current_epoch.saturating_sub(proof.epoch) > MAX_PROOF_EPOCH_AGE {
        return Err(format!(
            "proof expired: epoch {} vs current {} (max age {})",
            proof.epoch, current_epoch, MAX_PROOF_EPOCH_AGE
        ));
    }
    if proof.epoch > current_epoch {
        return Err(format!(
            "proof from future: epoch {} > current {}",
            proof.epoch, current_epoch
        ));
    }

    // Recompute Argon2d
    let output = mine_argon2d(&proof.miner_id, proof.epoch, proof.nonce);

    // Verify the claimed output matches
    if output != proof.argon2d_output {
        return Err("argon2d_output mismatch: claimed != recomputed".to_string());
    }

    // Count leading zeros
    let zeros = count_leading_zero_bytes(&output);

    // Check denomination
    let expected_denom = zeros_to_denomination(zeros);
    if expected_denom == 0 {
        return Err(format!(
            "insufficient difficulty: {} leading zeros (need {})",
            zeros, DIFF_ZEROS_1
        ));
    }
    if expected_denom != proof.denomination_value {
        return Err(format!(
            "denomination mismatch: proof claims {} but zeros={} maps to {}",
            proof.denomination_value, zeros, expected_denom
        ));
    }

    Ok(())
}

/// Quick check: verify the leading zeros of a stored proof's output
/// without recomputing Argon2d. Trusts the output is genuine;
/// use `verify_mint_proof` for full verification.
pub fn check_leading_zeros(output: &[u8; 32]) -> u64 {
    zeros_to_denomination(count_leading_zero_bytes(output))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_miner_id() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn argon2d_produces_32_bytes() {
        let output = mine_argon2d(&test_miner_id(), 0, 0);
        assert_eq!(output.len(), 32);
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn different_nonce_different_output() {
        let mid = test_miner_id();
        let o0 = mine_argon2d(&mid, 0, 0);
        let o1 = mine_argon2d(&mid, 0, 1);
        assert_ne!(o0, o1);
    }

    #[test]
    fn different_miner_id_different_output() {
        let oa = mine_argon2d(&[0xAA; 32], 0, 0);
        let ob = mine_argon2d(&[0xBB; 32], 0, 0);
        assert_ne!(oa, ob);
    }

    #[test]
    fn different_epoch_different_output() {
        let mid = test_miner_id();
        let o0 = mine_argon2d(&mid, 0, 0);
        let o1 = mine_argon2d(&mid, 1, 0);
        assert_ne!(o0, o1);
    }

    #[test]
    fn count_leading_zeros_works() {
        let mut h = [0xFFu8; 32];
        assert_eq!(count_leading_zero_bytes(&h), 0);
        h[0] = 0;
        assert_eq!(count_leading_zero_bytes(&h), 1);
        h[1] = 0; h[2] = 0;
        assert_eq!(count_leading_zero_bytes(&h), 3);
        assert_eq!(count_leading_zero_bytes(&[0u8; 32]), 32);
    }

    #[test]
    fn zeros_to_denomination_mapping() {
        assert_eq!(zeros_to_denomination(0), 0);
        assert_eq!(zeros_to_denomination(4), 0);
        assert_eq!(zeros_to_denomination(DIFF_ZEROS_1), 1);
        assert_eq!(zeros_to_denomination(DIFF_ZEROS_1 + 1), 1);
        assert_eq!(zeros_to_denomination(DIFF_ZEROS_2), 2);
        assert_eq!(zeros_to_denomination(DIFF_ZEROS_5), 5);
        assert_eq!(zeros_to_denomination(8), 5);
    }

    #[test]
    fn verify_mint_proof_rejects_expired() {
        let mid = test_miner_id();
        let output = mine_argon2d(&mid, 5, 42);
        let proof = MintProof {
            miner_id: mid, epoch: 5, nonce: 42,
            denomination_value: 1, argon2d_output: output,
        };
        // Current epoch is 8, proof from epoch 5 → age 3 > max 2
        assert!(verify_mint_proof(&proof, 8).is_err());
    }

    #[test]
    fn verify_mint_proof_accepts_fresh() {
        let mid = test_miner_id();
        let output = mine_argon2d(&mid, 6, 42);
        let proof = MintProof {
            miner_id: mid, epoch: 6, nonce: 42,
            denomination_value: 1, argon2d_output: output,
        };
        // Current epoch is 8, proof from epoch 6 → age 2 = max 2 → valid
        assert!(verify_mint_proof(&proof, 8).is_ok());
    }

    #[test]
    fn verify_mint_proof_rejects_invalid_denom() {
        let mid = test_miner_id();
        let output = mine_argon2d(&mid, 0, 42);
        let zeros = count_leading_zero_bytes(&output);
        let wrong_denom = if zeros_to_denomination(zeros) == 1 { 5 } else { 1 };
        let proof = MintProof {
            miner_id: mid, epoch: 0, nonce: 42,
            denomination_value: wrong_denom, argon2d_output: output,
        };
        assert!(verify_mint_proof(&proof, 0).is_err());
    }

    #[test]
    fn verify_mint_proof_rejects_wrong_output() {
        let mid = test_miner_id();
        let mut output = mine_argon2d(&mid, 0, 0);
        output[0] ^= 0xFF;
        let proof = MintProof {
            miner_id: mid, epoch: 0, nonce: 0,
            denomination_value: 1, argon2d_output: output,
        };
        assert!(verify_mint_proof(&proof, 0).is_err());
    }
}
