//! VHALIX miner — Argon2d proof-of-work.
//!
//! Hash-based difficulty model (like Bitcoin):
//!
//! ```text
//! Argon2d(m_cost=1 GiB, t_cost=1, p_cost=1)
//! password = vk_hash(owner_vk) || nonce
//!
//! Difficulty: count leading zero bytes of the 32-byte output.
//! - 5 zeros → 1 VHALIX (base difficulty)
//! - 6 zeros → 2 VHALIX (256× harder)
//! - 7 zeros → 5 VHALIX (65,536× harder)
//! ```
//!
//! Each Argon2d invocation takes ~0.5–1 second on a single core at 1 GiB.
//! Verification is equally fast — every node recomputes the exact
//! Argon2d call and checks leading zeros.  A `MintProof` is self-verifying:
//! fraud is mathematically impossible.

use argon2::Argon2;
use serde::{Deserialize, Serialize};

// ── Difficulty constants ────────────────────────────────────────────

/// Argon2d memory cost — 1 GiB in KiB (1,048,576 KiB).
pub const ARGON2D_M_COST: u32 = 1024 * 1024;

/// Argon2d time iterations — single pass for fast mining and verification.
pub const ARGON2D_T_COST: u32 = 1;

/// Argon2d parallelism — single-threaded.
pub const ARGON2D_P_COST: u32 = 1;

/// Output length in bytes.
pub const ARGON2D_HASH_LEN: usize = 32;

/// Domain separator for the Argon2d password.
const MINING_DOMAIN: &[u8] = b"vess-VHALIX-mine-v2";

/// Salt for Argon2d.
const MINING_SALT: &[u8] = b"vess-VHALIX-salt-v2";

// ── Tunable difficulty ──────────────────────────────────────────────
//
// These define the minimum number of leading zero BYTES required for
// each denomination.  Each additional zero byte is 256× harder.
//
// Tune these so that finding a proof takes a reasonable amount of time
// on a mid-range CPU (~0.5–1 sec per attempt at 1 GiB).
//
// For testing, lower these.  For production, raise them.

/// Leading zero bytes required for 1 VHALIX.
pub const DIFF_ZEROS_1: u32 = 5;

/// Leading zero bytes required for 2 VHALIX.
pub const DIFF_ZEROS_2: u32 = 6;

/// Leading zero bytes required for 5 VHALIX.
pub const DIFF_ZEROS_5: u32 = 7;

// ── Mint proof ──────────────────────────────────────────────────────

/// A self-verifying proof of Argon2d work.
///
/// Anyone can verify this proof by recomputing:
/// ```text
/// output = Argon2d(vk_hash(owner_vk) || nonce)
/// zeros = count_leading_zero_bytes(output)
/// zeros ≥ threshold for denomination_value
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintProof {
    /// ML-DSA-65 verification key of the miner (binds proof to wallet).
    pub owner_vk: Vec<u8>,
    /// Monotonically increasing counter — never reused.
    pub nonce: u64,
    /// Denomination found: 1, 2, or 5.
    pub denomination_value: u64,
    /// The Argon2d output (32 bytes).  Included so verifiers can check
    /// leading zeros without recomputing — they can still recompute
    /// to be sure.
    pub argon2d_output: [u8; 32],
}

// ── Core mining functions ───────────────────────────────────────────

/// Run one Argon2d hash for a given (owner_vk, nonce) pair.
///
/// Returns the 32-byte Argon2d output.
pub fn mine_argon2d(owner_vk: &[u8], nonce: u64) -> [u8; 32] {
    let vk_hash = crate::spend_auth::vk_hash(owner_vk);

    let mut password = Vec::with_capacity(32 + 8 + MINING_DOMAIN.len());
    password.extend_from_slice(&vk_hash);
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
    if zeros >= DIFF_ZEROS_5 {
        return 5;
    }
    if zeros >= DIFF_ZEROS_2 {
        return 2;
    }
    if zeros >= DIFF_ZEROS_1 {
        return 1;
    }
    0
}

/// Map a denomination value to the minimum zero count.
pub fn denomination_to_zeros(denom: u64) -> u32 {
    match denom {
        5 => DIFF_ZEROS_5,
        2 => DIFF_ZEROS_2,
        1 => DIFF_ZEROS_1,
        _ => u32::MAX, // invalid denomination
    }
}

// ── Verification ────────────────────────────────────────────────────

/// Verify a MintProof by recomputing Argon2d and checking difficulty.
///
/// Returns `Ok(())` if the proof is valid, `Err(msg)` otherwise.
/// This is cheap (~0.5–1 sec at 1 GiB) and can be called on every
/// node that receives a MintProof.
pub fn verify_mint_proof(proof: &MintProof) -> Result<(), String> {
    // Recompute Argon2d
    let output = mine_argon2d(&proof.owner_vk, proof.nonce);

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
/// without recomputing Argon2d.  This trusts that the output is genuine;
/// use `verify_mint_proof` for full verification.
pub fn check_leading_zeros(output: &[u8; 32]) -> u64 {
    zeros_to_denomination(count_leading_zero_bytes(output))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vk() -> Vec<u8> {
        vec![0xAB; 1953] // ML-DSA-65 key size placeholder for test
    }

    #[test]
    fn argon2d_produces_32_bytes() {
        let vk = test_vk();
        let output = mine_argon2d(&vk, 0);
        assert_eq!(output.len(), 32);
        assert_ne!(output, [0u8; 32]); // vanishingly unlikely to be all zeros
    }

    #[test]
    fn different_nonce_different_output() {
        let vk = test_vk();
        let o0 = mine_argon2d(&vk, 0);
        let o1 = mine_argon2d(&vk, 1);
        assert_ne!(o0, o1);
    }

    #[test]
    fn different_vk_different_output() {
        let vk_a = vec![0xAA; 1953];
        let vk_b = vec![0xBB; 1953];
        let oa = mine_argon2d(&vk_a, 0);
        let ob = mine_argon2d(&vk_b, 0);
        assert_ne!(oa, ob);
    }

    #[test]
    fn count_leading_zeros_works() {
        let mut h = [0xFFu8; 32];
        assert_eq!(count_leading_zero_bytes(&h), 0);
        h[0] = 0;
        assert_eq!(count_leading_zero_bytes(&h), 1);
        h[1] = 0;
        h[2] = 0;
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
    fn verify_mint_proof_rejects_invalid_denom() {
        let vk = test_vk();
        let output = mine_argon2d(&vk, 42);
        let zeros = count_leading_zero_bytes(&output);
        let wrong_denom = if zeros_to_denomination(zeros) == 1 { 5 } else { 1 };
        let proof = MintProof {
            owner_vk: vk,
            nonce: 42,
            denomination_value: wrong_denom,
            argon2d_output: output,
        };
        assert!(verify_mint_proof(&proof).is_err());
    }

    #[test]
    fn verify_mint_proof_rejects_wrong_output() {
        let vk = test_vk();
        let output = mine_argon2d(&vk, 0);
        let mut fake_output = output;
        fake_output[0] ^= 0xFF;
        let proof = MintProof {
            owner_vk: vk,
            nonce: 0,
            denomination_value: 1,
            argon2d_output: fake_output,
        };
        assert!(verify_mint_proof(&proof).is_err());
    }
}
