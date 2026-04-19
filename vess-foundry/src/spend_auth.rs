//! Post-quantum spend authorization using ML-DSA-65 (FIPS 204 / Dilithium3).
//!
//! Each bill has an associated ML-DSA-65 keypair generated at creation
//! time. The verification key hash (`vk_hash`) is stored publicly in the
//! [`SealedBill`](crate::seal::SealedBill), while the full keypair is
//! encrypted inside. Only the bill's owner can produce a valid spend
//! signature.
//!
//! # Security Level
//!
//! ML-DSA-65 provides NIST security level 3 (AES-192 equivalent),
//! matching the ML-KEM-768 used for stealth addresses. No pre-quantum
//! signature schemes are used.
//!
//! # Spend Message
//!
//! The signed message binds the authorization to the specific spend:
//!
//! ```text
//! message = Blake3("vess-spend-v0" ‖ mint_id ‖ denomination ‖ destination ‖ timestamp)
//! ```

use anyhow::{anyhow, Result};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
};

/// Generate a fresh ML-DSA-65 keypair for bill spend authorization.
///
/// Returns `(verification_key_bytes, signing_key_bytes)`.
pub fn generate_spend_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = dilithium3::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Construct the message digest that gets signed for spend authorization.
///
/// Binds the signature to the specific mint_id, denomination, destination,
/// and timestamp — preventing replay or modification.
pub fn spend_message(
    mint_id: &[u8; 32],
    denomination_value: u64,
    destination_stealth_id: &[u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-spend-v0");
    h.update(mint_id);
    h.update(&denomination_value.to_le_bytes());
    h.update(destination_stealth_id);
    h.update(&timestamp.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Construct the message digest for an ownership transfer authorization.
///
/// The sender signs this to authorize transferring a bill to a new owner.
/// Binds the signature to the specific bill (by mint_id), the intended
/// recipient (by stealth_id), and a timestamp — preventing replay and
/// redirection attacks.
///
/// The recipient's ML-DSA-65 vk_hash is NOT included here because it
/// doesn't exist yet — the recipient generates a fresh keypair on receive.
/// Instead, the stealth_id (known to the sender) anchors the transfer.
///
/// ```text
/// message = Blake3("vess-transfer-v0" ‖ mint_id ‖ recipient_stealth_id ‖ timestamp)
/// ```
pub fn transfer_message(
    mint_id: &[u8; 32],
    recipient_stealth_id: &[u8; 32],
    timestamp: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-transfer-v0");
    h.update(mint_id);
    h.update(recipient_stealth_id);
    h.update(&timestamp.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Sign a spend authorization using the owner's ML-DSA-65 signing key.
pub fn sign_spend(sk_bytes: &[u8], message: &[u8; 32]) -> Result<Vec<u8>> {
    let sk = dilithium3::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA signing key"))?;
    let sig = dilithium3::detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Verify a spend authorization against the owner's ML-DSA-65 verification key.
///
/// Used by artery nodes to confirm the spender owns the bill.
pub fn verify_spend(vk_bytes: &[u8], message: &[u8; 32], sig_bytes: &[u8]) -> Result<bool> {
    let pk = dilithium3::PublicKey::from_bytes(vk_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA verification key"))?;
    let sig = dilithium3::DetachedSignature::from_bytes(sig_bytes)
        .map_err(|_| anyhow!("invalid ML-DSA signature"))?;
    Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
}

/// Compute the verification key hash for a [`SealedBill`](crate::seal::SealedBill) commitment.
pub fn vk_hash(vk_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(vk_bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_generation() {
        let (vk, sk) = generate_spend_keypair();
        assert!(!vk.is_empty());
        assert!(!sk.is_empty());
    }

    #[test]
    fn sign_and_verify() {
        let (vk, sk) = generate_spend_keypair();
        let msg = spend_message(&[0xAA; 32], 10, &[0xBB; 32], 1000);

        let sig = sign_spend(&sk, &msg).unwrap();
        assert!(verify_spend(&vk, &msg, &sig).unwrap());
    }

    #[test]
    fn wrong_key_rejects() {
        let (_vk1, sk1) = generate_spend_keypair();
        let (vk2, _sk2) = generate_spend_keypair();
        let msg = spend_message(&[0xAA; 32], 10, &[0xBB; 32], 1000);

        let sig = sign_spend(&sk1, &msg).unwrap();
        assert!(!verify_spend(&vk2, &msg, &sig).unwrap());
    }

    #[test]
    fn wrong_message_rejects() {
        let (vk, sk) = generate_spend_keypair();
        let msg1 = spend_message(&[0xAA; 32], 10, &[0xBB; 32], 1000);
        let msg2 = spend_message(&[0xCC; 32], 10, &[0xBB; 32], 1000);

        let sig = sign_spend(&sk, &msg1).unwrap();
        assert!(!verify_spend(&vk, &msg2, &sig).unwrap());
    }

    #[test]
    fn vk_hash_deterministic() {
        let (vk, _) = generate_spend_keypair();
        assert_eq!(vk_hash(&vk), vk_hash(&vk));
    }
}
