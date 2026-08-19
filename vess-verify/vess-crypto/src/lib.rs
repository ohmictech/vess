use blake3::Hasher;

#[cfg(feature = "full")]
use chacha20poly1305::aead::OsRng;
#[cfg(feature = "full")]
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
#[cfg(feature = "full")]
use ml_dsa::{
    EncodedVerifyingKey as DsaVerifyingKeyBytes, Generate as _, Keypair as _, MlDsa65,
    Signature as DsaSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
    B32 as DsaSeed,
};
#[cfg(feature = "full")]
use ml_kem::{
    Ciphertext as KemCiphertext, Decapsulate as _, DecapsulationKey, Encapsulate as _,
    EncapsulationKey, Kem as _, KeyExport as _, MlKem512, Seed as KemSeed,
};
#[cfg(feature = "full")]
use rand::RngCore;

pub mod cuckoo;

// ---- hashing ---------------------------------------------------------

pub const VESS_ID_V1: &[u8] = b"vess-id-v1";

pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize().into()
}

pub fn blake3_hash_multi(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---- difficulty & reward ----------------------------------------------

pub type Amount = u64;

pub fn check_difficulty(hash: &[u8; 32], target_bits: u32) -> bool {
    if target_bits > 256 {
        return false;
    }
    let full_bytes = (target_bits / 8) as usize;
    let rem_bits = target_bits % 8;
    if hash[..full_bytes].iter().any(|&b| b != 0) {
        return false;
    }
    if rem_bits > 0 {
        hash[full_bytes] >> (8 - rem_bits) == 0
    } else {
        true
    }
}

pub fn block_reward(diff_bits: u32) -> Amount {
    if diff_bits >= 32 {
        return 1u64 << 32;
    }
    1u64 << diff_bits
}

// ---- mint attempt -----------------------------------------------------

pub struct MintAttempt {
    pub chain_hash: [u8; 32],
    pub diff_bits: u32,
    pub address: [u8; 32],
    pub timestamp: u64,
    pub nonce: u64,
    pub proof: Vec<u32>,
}

pub fn chain_hash(name: &str) -> [u8; 32] {
    blake3_hash(name.as_bytes())
}

// ---- full feature: DSA / KEM / ChaCha / Argon2 -----------------------

#[cfg(feature = "full")]
fn arr_bytes(a: &impl AsRef<[u8]>) -> Vec<u8> {
    a.as_ref().to_vec()
}

#[cfg(feature = "full")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(feature = "full")]
pub fn argon2id_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use argon2::Argon2;
    let a = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 1, None).unwrap(),
    );
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt, &mut out).unwrap();
    out
}

#[cfg(feature = "full")]
pub fn chacha_encrypt(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    cipher.encrypt(Nonce::from_slice(nonce), pt).unwrap()
}

#[cfg(feature = "full")]
pub fn chacha_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

// ML-DSA-65

#[cfg(feature = "full")]
pub const DSA_PUBKEY_BYTES: usize = 1952;
#[cfg(feature = "full")]
pub const DSA_SEED_BYTES: usize = 32;
#[cfg(feature = "full")]
pub const DSA_SIGNATURE_BYTES: usize = 3309;

#[cfg(feature = "full")]
pub fn dsa_generate() -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::<MlDsa65>::generate();
    let vk = sk.verifying_key();
    (arr_bytes(&vk.encode()), arr_bytes(&sk.to_seed()))
}

#[cfg(feature = "full")]
pub fn dsa_public_from_seed(seed: &[u8]) -> Option<Vec<u8>> {
    let seed: [u8; DSA_SEED_BYTES] = seed.try_into().ok()?;
    let sk = SigningKey::<MlDsa65>::from_seed(&DsaSeed::from(seed));
    Some(arr_bytes(&sk.verifying_key().encode()))
}

#[cfg(feature = "full")]
pub fn dsa_pubkey_hash(pk: &[u8]) -> [u8; 32] {
    blake3_hash(pk)
}

#[cfg(feature = "full")]
pub fn dsa_sign(seed: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let seed: [u8; DSA_SEED_BYTES] = seed.try_into().ok()?;
    let sk = SigningKey::<MlDsa65>::from_seed(&DsaSeed::from(seed));
    Some(arr_bytes(&sk.try_sign(msg).ok()?.encode()))
}

#[cfg(feature = "full")]
pub fn dsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let vk = DsaVerifyingKeyBytes::<MlDsa65>::try_from(pk)
        .map(|enc| VerifyingKey::<MlDsa65>::decode(&enc));
    let (Ok(vk), Ok(sig)) = (vk, DsaSignature::<MlDsa65>::try_from(sig)) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

#[cfg(feature = "full")]
pub fn node_id(pk: &[u8]) -> [u8; 32] {
    blake3_hash(pk)
}

// ML-KEM-512

#[cfg(feature = "full")]
pub const KEM_PUBKEY_BYTES: usize = 800;
#[cfg(feature = "full")]
pub const KEM_SEED_BYTES: usize = 64;
#[cfg(feature = "full")]
pub const KEM_CIPHERTEXT_BYTES: usize = 768;
#[cfg(feature = "full")]
pub const KEM_SHARED_SECRET_BYTES: usize = 32;
#[cfg(feature = "full")]
pub const KEM_PK_BYTES: usize = 800;
#[cfg(feature = "full")]
pub const KEM_CT_BYTES: usize = 768;

#[cfg(feature = "full")]
pub fn kem_generate() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem512::generate_keypair();
    (arr_bytes(&ek.to_bytes()), arr_bytes(&dk.to_bytes()))
}

#[cfg(feature = "full")]
pub fn kem_encapsulate(ek_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let enc = ml_kem::Key::<EncapsulationKey<MlKem512>>::try_from(ek_bytes).ok()?;
    let ek = EncapsulationKey::<MlKem512>::new(&enc).ok()?;
    let (ct, ss) = ek.encapsulate();
    Some((arr_bytes(&ct), arr_bytes(&ss)))
}

#[cfg(feature = "full")]
pub fn kem_decapsulate(ct_bytes: &[u8], dk_bytes: &[u8]) -> Option<Vec<u8>> {
    let seed = KemSeed::try_from(dk_bytes).ok()?;
    let dk = DecapsulationKey::<MlKem512>::from_seed(seed);
    let ct = KemCiphertext::<MlKem512>::try_from(ct_bytes).ok()?;
    Some(arr_bytes(&dk.decapsulate(&ct)))
}

// ---- tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_deterministic() {
        assert_eq!(blake3_hash(b"hello"), blake3_hash(b"hello"));
    }

    #[test]
    fn test_blake3_multi() {
        assert_eq!(
            blake3_hash_multi(&[b"ab", b"c"]),
            blake3_hash_multi(&[b"a", b"bc"])
        );
    }

    #[test]
    fn test_check_difficulty_zero() {
        assert!(check_difficulty(&[0u8; 32], 0));
        assert!(check_difficulty(&[0x80; 32], 0));
    }

    #[test]
    fn test_check_difficulty_bits() {
        assert!(check_difficulty(&[0x00; 32], 8));
        assert!(!check_difficulty(&[0x01; 32], 8));
    }

    #[test]
    fn test_block_reward() {
        assert_eq!(block_reward(1), 2);
        assert_eq!(block_reward(2), 4);
        assert_eq!(block_reward(10), 1024);
        assert_eq!(block_reward(32), 1u64 << 32);
        assert_eq!(block_reward(64), 1u64 << 32);
    }

    #[test]
    fn test_chain_hash() {
        let a = chain_hash("arbitrum");
        assert_eq!(a.len(), 32);
        assert_eq!(chain_hash("arbitrum"), a);
        assert_ne!(chain_hash("ethereum"), a);
    }
}
