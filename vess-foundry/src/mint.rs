//! Vess miner — Argon2d proof-of-work with bit-level difficulty.
//!
//! ```text
//! Argon2d(m_cost=1 GiB, t_cost=1, p_cost=1)
//! password = initial_pk || epoch || nonce || amount
//!
//! Difficulty scales by leading zero BITS (not bytes):
//!   16 bits → 1 Vess        (1 in 65,536, ~9 hours at 0.5s/attempt)
//!   17 bits → 2 Vess        (2× harder)
//!   18 bits → 4 Vess
//!   ...
//!   24 bits → 256 Vess
//!
//! amount = 1 << (leading_zero_bits - BASE_BITS)
//! No wasted work — every extra bit doubles the claimable Vess.
//! ```

use argon2::Argon2;
use crate::Vess;

// ── Mining params ───────────────────────────────────────────────────

pub const ARGON2D_M_COST: u32 = 1024 * 1024; // 1 GiB in KiB
pub const ARGON2D_T_COST: u32 = 1;
pub const ARGON2D_P_COST: u32 = 1;
pub const ARGON2D_HASH_LEN: usize = 32;
const MINTING_DOMAIN: &[u8] = b"vess-mint-v4";
const MINTING_SALT: &[u8] = b"vess-mint-salt-v4";
pub const MAX_PROOF_EPOCH_AGE: u64 = 1;

// ── Difficulty ──────────────────────────────────────────────────────

/// Minimum leading zero bits to claim any Vess.
pub const BASE_BITS: u32 = 16;

/// Maximum Vess claimable at a given leading-zero-bit count.
/// Super-linear: `base + 10% bonus per extra bit` to reward consolidation.
pub fn bits_to_max_amount(bits: u32) -> u64 {
    if bits < BASE_BITS { return 0; }
    let shift = bits - BASE_BITS;
    if shift >= 64 { return u64::MAX; }
    let base = 1u64 << shift;
    let bonus = base.saturating_mul(shift as u64) / 10; // +10% per extra bit
    base.saturating_add(bonus)
}

/// Minimum leading zero bits required to claim `amount` Vess.
pub fn amount_to_bits(amount: u64) -> u32 {
    if amount <= 1 { return BASE_BITS; }
    let mut bits = BASE_BITS;
    while bits < BASE_BITS + 64 && bits_to_max_amount(bits) < amount {
        bits += 1;
    }
    bits
}

// ── Mining ──────────────────────────────────────────────────────────

/// Run one Argon2d hash for mining.
/// `password = initial_pk || epoch || nonce || amount`
pub fn mint_argon2d(initial_pk: &[u8; 32], epoch: u64, nonce: u64, amount: u64) -> [u8; 32] {
    let mut password = Vec::with_capacity(32 + 8 + 8 + 8 + MINTING_DOMAIN.len());
    password.extend_from_slice(initial_pk);
    password.extend_from_slice(&epoch.to_be_bytes());
    password.extend_from_slice(&nonce.to_be_bytes());
    password.extend_from_slice(&amount.to_be_bytes());
    password.extend_from_slice(MINTING_DOMAIN);

    let mut output = [0u8; ARGON2D_HASH_LEN];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2d,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2D_M_COST, ARGON2D_T_COST, ARGON2D_P_COST, Some(ARGON2D_HASH_LEN))
            .expect("valid argon2d params"),
    );
    argon2.hash_password_into(&password, MINTING_SALT, &mut output).expect("argon2d succeeds");
    output
}

/// Count leading zero bytes.
fn leading_zero_bytes(hash: &[u8; 32]) -> u32 {
    let mut count: u32 = 0;
    for &byte in hash.iter() { if byte == 0 { count += 1; } else { break; } }
    count
}

/// Count leading zero bits in a 32-byte hash.
pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let bytes = leading_zero_bytes(hash);
    if bytes == 32 { return 256; }
    let next_byte = hash[bytes as usize];
    bytes * 8 + next_byte.leading_zeros()
}

// ── Verification ────────────────────────────────────────────────────

/// Verify a minted (proof-of-work) Vess.
pub fn verify_minted_vess(v: &Vess, current_epoch: u64) -> Result<(), String> {
    if !v.is_minted() { return Err("not a minted Vess".into()); }
    verify_epoch(v, current_epoch)?;
    let output = mint_argon2d(&v.initial_pk, v.epoch, v.nonce, v.amount);
    let bits = leading_zero_bits(&output);
    let required = amount_to_bits(v.amount);
    if bits < required {
        return Err(format!("insufficient difficulty: {} zero bits, need {} for amount {}", bits, required, v.amount));
    }
    Ok(())
}

/// Verify a dev faucet Vess: check epoch and dev signature.
pub fn verify_faucet_vess(v: &Vess, current_epoch: u64, dev_vk: &[u8]) -> Result<(), String> {
    if !v.is_faucet() { return Err("not a faucet Vess".into()); }
    verify_epoch(v, current_epoch)?;

    let mut msg = blake3::Hasher::new();
    msg.update(b"vess-faucet-v1");
    msg.update(&v.epoch.to_be_bytes());
    msg.update(&v.amount.to_be_bytes());
    msg.update(&v.owner_vk);
    let sig_msg = *msg.finalize().as_bytes();

    if !crate::spend_auth::verify_spend(dev_vk, &sig_msg, &v.change_sig)
        .unwrap_or(false)
    {
        return Err("invalid dev faucet signature".into());
    }
    Ok(())
}

fn verify_epoch(v: &Vess, current_epoch: u64) -> Result<(), String> {
    if current_epoch.saturating_sub(v.epoch) > MAX_PROOF_EPOCH_AGE {
        return Err(format!("epoch {} expired (current {})", v.epoch, current_epoch));
    }
    if v.epoch > current_epoch {
        return Err(format!("epoch {} in the future", v.epoch));
    }
    Ok(())
}

// ── Dev faucet ──────────────────────────────────────────────────────

/// Create and sign a dev faucet Vess for the given epoch and recipient.
/// The dev secret key must match `vess_protocol::DEV_VK`.
pub fn create_faucet(dev_sk: &[u8], epoch: u64, owner_vk: &[u8], initial_pk: &[u8; 32]) -> Result<crate::Vess, String> {
    let mut v = crate::Vess {
        amount: 30_000, // DEV_FAUCET_AMOUNT
        epoch, nonce: 0, initial_pk: *initial_pk,
        owner_vk: owner_vk.to_vec(), prev_sig: vec![], chain_depth: 0,
        consumed: vec![], change_sig: vec![], chain_tip: [0u8; 32],
        digest: [0u8; 32], created_at: 0, stealth_id: [0u8; 32], dht_index: 0,
    };

    let mut msg = blake3::Hasher::new();
    msg.update(b"vess-faucet-v1");
    msg.update(&epoch.to_be_bytes());
    msg.update(&v.amount.to_be_bytes());
    msg.update(&v.owner_vk);
    let sig_msg = *msg.finalize().as_bytes();

    v.change_sig = crate::spend_auth::sign_spend(dev_sk, &sig_msg)
        .map_err(|e| format!("sign faucet: {e}"))?;
    v.chain_tip = crate::genesis_chain_tip(&v.compute_vess_id(), &v.owner_vk_hash());
    Ok(v)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pk() -> [u8; 32] { [0xAB; 32] }

    #[test]
    fn argon2d_produces_32_bytes() {
        let out = mint_argon2d(&test_pk(), 0, 0, 1);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn different_params_different_output() {
        let pk = test_pk();
        assert_ne!(mint_argon2d(&pk, 0, 0, 1), mint_argon2d(&pk, 0, 1, 1));
        assert_ne!(mint_argon2d(&pk, 0, 0, 1), mint_argon2d(&pk, 0, 0, 2));
    }

    #[test]
    fn leading_zero_bits_works() {
        let mut h = [0xFFu8; 32];
        assert_eq!(leading_zero_bits(&h), 0);
        h[0] = 0x7F;
        assert_eq!(leading_zero_bits(&h), 1);
        h[0] = 0x00; h[1] = 0x0F;
        assert_eq!(leading_zero_bits(&h), 12);
    }

    #[test]
    fn difficulty_mapping() {
        assert_eq!(bits_to_max_amount(15), 0);
        assert_eq!(bits_to_max_amount(BASE_BITS), 1);
        assert_eq!(bits_to_max_amount(17), 2);
        assert_eq!(bits_to_max_amount(20), 22);      // 16 + 16*4/10
        assert_eq!(bits_to_max_amount(24), 460);      // 256 + 256*8/10
        assert_eq!(amount_to_bits(1), BASE_BITS);
        assert_eq!(amount_to_bits(2), 17);
        assert_eq!(amount_to_bits(22), 20);
        assert_eq!(amount_to_bits(460), 24);
    }
}
