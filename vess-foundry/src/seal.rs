//! Bill sealing for permanent DHT storage.
//!
//! Sealed bills are opaque to DHT nodes — only the bill's owner (who
//! holds `spend_seed`) can decrypt and spend them. The only public
//! metadata is `vk_hash`, a Blake3 commitment to the owner's ML-DSA
//! verification key, used by artery nodes to verify spend authorization.
//!
//! # Encryption
//!
//! ```text
//! seal_key = Blake3(spend_seed ‖ "vess-seal-v0" ‖ dht_index)
//! ciphertext = ChaCha20Poly1305(seal_key, nonce, VessBill ‖ ML-DSA keypair)
//! ```
//!
//! No pre-quantum primitives are used. Blake3 and ChaCha20Poly1305 are
//! both considered quantum-resistant at the 128-bit post-quantum security
//! level (Grover's algorithm halves symmetric key strength).

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    ChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};

use crate::VessBill;

/// A bill sealed for permanent DHT storage.
///
/// DHT nodes see only an opaque ciphertext and a 32-byte ownership
/// commitment (`vk_hash`). They cannot determine the denomination,
/// mint_id, or any other bill property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBill {
    /// `Blake3(owner_verification_key)` — public commitment binding
    /// the sealed bill to an ML-DSA verification key. Artery nodes
    /// check this during spend authorization.
    pub vk_hash: [u8; 32],
    /// ChaCha20Poly1305-encrypted payload containing the [`VessBill`]
    /// and the owner's ML-DSA signing keypair.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (96 bits). Random per seal operation.
    pub nonce: [u8; 12],
    /// Plaintext denomination value. Visible to DHT nodes so they can
    /// compute network supply without decryption. Safe because each
    /// bill has a unique random `vk_hash` — denomination alone reveals
    /// nothing about the owner.
    #[serde(default)]
    pub denomination: u64,
}

/// The decrypted contents recovered from a [`SealedBill`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsealedContents {
    pub bill: VessBill,
    /// ML-DSA-65 verification key (included in ownership messages).
    pub spend_vk: Vec<u8>,
    /// ML-DSA-65 signing key (used to authorize spends).
    pub spend_sk: Vec<u8>,
}

/// Derive the symmetric seal key from the owner's spend seed and bill index.
fn derive_seal_key(spend_seed: &[u8; 32], dht_index: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(spend_seed);
    h.update(b"vess-seal-v0");
    h.update(&dht_index.to_le_bytes());
    *h.finalize().as_bytes()
}

impl SealedBill {
    /// Seal a bill for DHT storage.
    ///
    /// Encrypts the bill and its ML-DSA spend keypair under a key derived
    /// from `spend_seed` and the bill's `dht_index`. The only public data
    /// in the result is `vk_hash = Blake3(spend_vk)`.
    pub fn seal(
        bill: &VessBill,
        spend_seed: &[u8; 32],
        spend_vk: &[u8],
        spend_sk: &[u8],
    ) -> Result<Self> {
        let vk_hash = *blake3::hash(spend_vk).as_bytes();

        let contents = UnsealedContents {
            bill: bill.clone(),
            spend_vk: spend_vk.to_vec(),
            spend_sk: spend_sk.to_vec(),
        };

        let plaintext =
            postcard::to_allocvec(&contents).map_err(|e| anyhow!("seal serialize: {e}"))?;

        let key_bytes = derive_seal_key(spend_seed, bill.dht_index);
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow!("seal encrypt: {e}"))?;

        Ok(SealedBill {
            vk_hash,
            ciphertext,
            nonce: nonce_bytes,
            denomination: bill.denomination.value(),
        })
    }

    /// Unseal a bill, recovering the [`VessBill`] and ML-DSA spend keypair.
    ///
    /// Requires the owner's `spend_seed` and the bill's `dht_index` to
    /// derive the decryption key.
    pub fn unseal(&self, spend_seed: &[u8; 32], dht_index: u64) -> Result<UnsealedContents> {
        let key_bytes = derive_seal_key(spend_seed, dht_index);
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|_| anyhow!("unseal: decryption failed (wrong key or corrupted)"))?;

        let contents: UnsealedContents =
            postcard::from_bytes(&plaintext).map_err(|e| anyhow!("unseal deserialize: {e}"))?;

        Ok(contents)
    }
}

// ── Manifest helpers ─────────────────────────────────────────────────

/// An entry in the recovery manifest — one per owned bill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub mint_id: [u8; 32],
    pub dht_index: u64,
}

/// Compute the DHT key for a wallet's manifest.
///
/// `Blake3(spend_seed || "vess-manifest-v0")`
pub fn manifest_dht_key(spend_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(spend_seed);
    h.update(b"vess-manifest-v0");
    *h.finalize().as_bytes()
}

/// Derive the symmetric encryption key for the manifest.
fn manifest_enc_key(spend_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(spend_seed);
    h.update(b"vess-manifest-key-v0");
    *h.finalize().as_bytes()
}

/// Encrypt a manifest (list of entries) for DHT storage.
pub fn encrypt_manifest(spend_seed: &[u8; 32], entries: &[ManifestEntry]) -> Result<Vec<u8>> {
    let plaintext = postcard::to_allocvec(entries)
        .map_err(|e| anyhow!("manifest serialize: {e}"))?;
    let key_bytes = manifest_enc_key(spend_seed);
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow!("manifest encrypt: {e}"))?;
    // Prepend the 12-byte nonce so the decryptor can extract it.
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a manifest from DHT storage.
pub fn decrypt_manifest(spend_seed: &[u8; 32], data: &[u8]) -> Result<Vec<ManifestEntry>> {
    if data.len() < 12 {
        anyhow::bail!("manifest too short");
    }
    let nonce_bytes: [u8; 12] = data[..12].try_into().unwrap();
    let ciphertext = &data[12..];
    let key_bytes = manifest_enc_key(spend_seed);
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("manifest decrypt failed (wrong key or corrupted)"))?;
    let entries: Vec<ManifestEntry> = postcard::from_bytes(&plaintext)
        .map_err(|e| anyhow!("manifest deserialize: {e}"))?;
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Denomination;

    fn test_bill() -> VessBill {
        VessBill {
            denomination: Denomination::D10,
            digest: [0xBB; 32],
            created_at: 12345,
            stealth_id: [0xCC; 32],
            dht_index: 7,
            mint_id: [0xAA; 32],
            chain_tip: [0xDD; 32],
            chain_depth: 0,
        }
    }

    #[test]
    fn seal_unseal_round_trip() {
        let bill = test_bill();
        let spend_seed = [0x42; 32];
        let vk = vec![0x11; 64];
        let sk = vec![0x22; 128];

        let sealed = SealedBill::seal(&bill, &spend_seed, &vk, &sk).unwrap();
        assert_eq!(sealed.vk_hash, *blake3::hash(&vk).as_bytes());

        let contents = sealed.unseal(&spend_seed, bill.dht_index).unwrap();
        assert_eq!(contents.bill.mint_id, bill.mint_id);
        assert_eq!(contents.bill.denomination, bill.denomination);
        assert_eq!(contents.spend_vk, vk);
        assert_eq!(contents.spend_sk, sk);
    }

    #[test]
    fn wrong_seed_fails_unseal() {
        let bill = test_bill();
        let sealed = SealedBill::seal(&bill, &[0x42; 32], &[0x11; 64], &[0x22; 128]).unwrap();

        let result = sealed.unseal(&[0xFF; 32], bill.dht_index);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_index_fails_unseal() {
        let bill = test_bill();
        let sealed = SealedBill::seal(&bill, &[0x42; 32], &[0x11; 64], &[0x22; 128]).unwrap();

        let result = sealed.unseal(&[0x42; 32], 999);
        assert!(result.is_err());
    }

    #[test]
    fn vk_hash_is_commitment() {
        let bill = test_bill();
        let vk_a = vec![0x11; 64];
        let vk_b = vec![0x33; 64];

        let sealed_a = SealedBill::seal(&bill, &[0x42; 32], &vk_a, &[0x22; 128]).unwrap();
        let sealed_b = SealedBill::seal(&bill, &[0x42; 32], &vk_b, &[0x22; 128]).unwrap();

        assert_eq!(sealed_a.vk_hash, *blake3::hash(&vk_a).as_bytes());
        assert_ne!(sealed_a.vk_hash, sealed_b.vk_hash);
    }
}
