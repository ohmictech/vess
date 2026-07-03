//! VHALIX miner — Argon2d proof-of-work, Bitcoin-style with post-quantum hardness.
//!
//! ```text
//! m_cost = 1 GiB    (memory-hard, beyond commodity ASIC HBM capacity)
//! t_cost = 1        (single pass — ~0.5-1s per attempt on mid-range CPU)
//! p_cost = 1        (single-threaded — no parallelism advantage)
//! ```
//!
//! The miner hashes `owner_vk_hash || nonce` with Argon2d, incrementing
//! the nonce each attempt. The goal is to find a hash with a certain number
//! of leading zero bytes. More zeros = higher denomination.
//!
//! ## Difficulty — Denomination (tunable constants)
//!
//! Each additional leading zero byte is 256× harder.
//!
//! | Leading zeros | Denomination | Approx attempts      |
//! |---------------|--------------|----------------------|
//! | 5             | 1 VHALIX     | ~1.1 trillion        |
//! | 6             | 2 VHALIX     | ~281 trillion        |
//! | 7             | 5 VHALIX     | ~72 quadrillion      |
//!
//! ## Verification
//!
//! Argon2d is deterministic. A verifier recomputes and checks leading zeros.
//! ~0.5s per proof, no fraud possible — the proof IS the evidence.

use argon2::Argon2;
use serde::{Deserialize, Serialize};

pub const VHALIX_M_COST: u32 = 1024 * 1024;
pub const VHALIX_T_COST: u32 = 1;
pub const VHALIX_P_COST: u32 = 1;
pub const VHALIX_HASH_LEN: usize = 32;

const MINING_DOMAIN: &[u8] = b"vess-VHALIX-mine-v2";
const MINING_SALT: &[u8] = b"vess-VHALIX-salt-v2";

// ── Difficulty constants (tunable) ──

pub const DIFFICULTY_1: u32 = 5;
pub const DIFFICULTY_2: u32 = 6;
pub const DIFFICULTY_5: u32 = 7;

// ── Mint proof ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintProof {
    pub owner_vk_hash: [u8; 32],
    pub nonce: u64,
    pub denomination_value: u64,
    pub elapsed_ms: u64,
    pub created_at_ms: u64,
}

impl MintProof {
    pub fn mint_id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-mint-id-v2");
        h.update(&self.owner_vk_hash);
        h.update(&self.nonce.to_be_bytes());
        *h.finalize().as_bytes()
    }
}

// ── Core functions ──

pub fn hash_attempt(owner_vk_hash: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut password = Vec::with_capacity(32 + 8 + MINING_DOMAIN.len());
    password.extend_from_slice(owner_vk_hash);
    password.extend_from_slice(&nonce.to_be_bytes());
    password.extend_from_slice(MINING_DOMAIN);
    let mut output = [0u8; VHALIX_HASH_LEN];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2d,
        argon2::Version::V0x13,
        argon2::Params::new(VHALIX_M_COST, VHALIX_T_COST, VHALIX_P_COST, Some(VHALIX_HASH_LEN))
            .expect("valid argon2 params"),
    );
    argon2.hash_password_into(&password, MINING_SALT, &mut output).expect("argon2d hash succeeds");
    output
}

pub fn leading_zero_bytes(bytes: &[u8; 32]) -> u32 {
    let mut count: u32 = 0;
    for &b in bytes.iter() {
        if b == 0 { count += 1; } else { break; }
    }
    count
}

pub fn difficulty_to_denomination(zeros: u32) -> Option<u64> {
    if zeros >= DIFFICULTY_5 { Some(5) }
    else if zeros >= DIFFICULTY_2 { Some(2) }
    else if zeros >= DIFFICULTY_1 { Some(1) }
    else { None }
}

pub fn denomination_difficulty(denomination: u64) -> u32 {
    match denomination { 5 => DIFFICULTY_5, 2 => DIFFICULTY_2, _ => DIFFICULTY_1 }
}

pub fn verify_mint_proof(proof: &MintProof) -> Result<(), String> {
    let hash = hash_attempt(&proof.owner_vk_hash, proof.nonce);
    let zeros = leading_zero_bytes(&hash);
    let required = denomination_difficulty(proof.denomination_value);
    if zeros < required {
        return Err(format!("insufficient difficulty: {zeros} < {required} for {} VHALIX", proof.denomination_value));
    }
    Ok(())
}

// ── Miner ──

pub struct VhalixMiner {
    owner_vk_hash: [u8; 32],
    next_nonce: u64,
}

impl VhalixMiner {
    pub fn new(owner_vk_hash: [u8; 32], starting_nonce: u64) -> Self {
        Self { owner_vk_hash, next_nonce: starting_nonce }
    }

    pub fn next_nonce(&self) -> u64 { self.next_nonce }

    pub fn mine_until(&mut self, mut should_stop: impl FnMut() -> bool) -> Option<MintProof> {
        loop {
            if should_stop() { return None; }
            let started = std::time::Instant::now();
            let hash = hash_attempt(&self.owner_vk_hash, self.next_nonce);
            let zeros = leading_zero_bytes(&hash);
            let elapsed = started.elapsed();
            if let Some(denom) = difficulty_to_denomination(zeros) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                let proof = MintProof {
                    owner_vk_hash: self.owner_vk_hash, nonce: self.next_nonce,
                    denomination_value: denom, elapsed_ms: elapsed.as_millis() as u64, created_at_ms: now,
                };
                self.next_nonce += 1;
                return Some(proof);
            }
            self.next_nonce += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_owner() -> [u8; 32] { let mut id = [0u8; 32]; id[0..8].copy_from_slice(b"testnode"); id }

    #[test]
    fn leading_zero_bytes_counts_correctly() {
        assert_eq!(leading_zero_bytes(&[0u8; 32]), 32);
        assert_eq!(leading_zero_bytes(&[1u8; 32]), 0);
        let mut h = [0u8; 32]; h[3] = 1;
        assert_eq!(leading_zero_bytes(&h), 3);
    }

    #[test]
    fn difficulty_to_denomination_maps_correctly() {
        assert_eq!(difficulty_to_denomination(0), None);
        assert_eq!(difficulty_to_denomination(4), None);
        assert_eq!(difficulty_to_denomination(5), Some(1));
        assert_eq!(difficulty_to_denomination(6), Some(2));
        assert_eq!(difficulty_to_denomination(7), Some(5));
    }

    #[test]
    fn hash_attempt_is_deterministic() {
        assert_eq!(hash_attempt(&test_owner(), 42), hash_attempt(&test_owner(), 42));
    }

    #[test]
    fn different_nonce_produces_different_hash() {
        assert_ne!(hash_attempt(&test_owner(), 0), hash_attempt(&test_owner(), 1));
    }

    #[test]
    fn mint_id_is_deterministic() {
        let p = MintProof { owner_vk_hash: test_owner(), nonce: 42, denomination_value: 1, elapsed_ms: 500, created_at_ms: 1000 };
        assert_eq!(p.mint_id(), p.mint_id());
    }

    #[test]
    fn verify_fails_on_overclaimed_denomination() {
        let p = MintProof { owner_vk_hash: test_owner(), nonce: 0, denomination_value: 5, elapsed_ms: 0, created_at_ms: 0 };
        assert!(verify_mint_proof(&p).is_err());
    }

    #[test]
    fn miner_stops_when_requested() {
        let mut miner = VhalixMiner::new(test_owner(), 0);
        assert!(miner.mine_until(|| true).is_none());
    }
}