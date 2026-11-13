//! ML-DSA-65 adapter: the only place the ledger talks to a signature scheme.
//!
//! Signatures use FIPS 204 with an explicit context string, so the domain is enforced by the
//! scheme itself rather than by pre-hashing the message.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey,
};
use vess_core::constants::{ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES};
use vess_core::{AccountId, PublicKey};

/// Signature length produced by ML-DSA-65.
pub const SIGNATURE_BYTES: usize = ML_DSA_SIG_BYTES;
/// Public key length produced by ML-DSA-65.
pub const PUBLIC_KEY_BYTES: usize = ML_DSA_PK_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The context string exceeded the 255-byte ML-DSA limit.
    ContextTooLong,
    /// The signature could not be produced.
    SigningFailed,
    /// The encoded public key was malformed or not canonical.
    BadPublicKey,
}

pub type Key = SigningKey<MlDsa65>;
pub type Sig = Signature<MlDsa65>;

/// Deterministic key generation from a 32-byte seed (FIPS 204 `KeyGen_internal`).
pub fn key_from_seed(seed: [u8; 32]) -> Key {
    let seed: ml_dsa::Seed = seed.into();
    SigningKey::from_seed(&seed)
}

/// Fresh key material from the operating system CSPRNG.
pub fn generate_key() -> Key {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("operating system CSPRNG unavailable");
    key_from_seed(seed)
}

/// The 32-byte seed that reproduces a key pair.
pub fn seed_of(key: &Key) -> [u8; 32] {
    let seed = key.to_seed();
    let mut out = [0u8; 32];
    out.copy_from_slice(seed.as_slice());
    out
}

/// Domain separation for hierarchical derivation.
const DOM_HD: &[u8] = b"VESS-HD-V1";

/// Derive the seed of child `index` from a master seed.
///
/// Derivation is hardened-only, because ML-DSA has no public-key derivation: knowing an account's
/// public key says nothing about its siblings or its parent, which means a leaked child key cannot
/// walk upwards or sideways. What it costs is that an observer cannot generate addresses from a
/// public key alone — the master seed is needed, which is the right trade for a wallet that keeps its
/// master offline.
pub fn derive_seed(master: &[u8; 32], index: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOM_HD);
    hasher.update(master);
    hasher.update(&index.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// A fresh master seed.
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("operating system CSPRNG unavailable");
    seed
}

pub fn public_key_bytes(key: &Key) -> PublicKey {
    let encoded = key.verifying_key().encode();
    let mut out = [0u8; PUBLIC_KEY_BYTES];
    out.copy_from_slice(encoded.as_slice());
    out
}

pub fn account_id(public_key: &PublicKey) -> AccountId {
    vess_core::hash::account_id(public_key)
}

/// Deterministic signature over `msg` with the given context string.
pub fn sign(key: &Key, ctx: &[u8], msg: &[u8]) -> Result<[u8; SIGNATURE_BYTES], CryptoError> {
    let sig = key
        .expanded_key()
        .sign_deterministic(msg, ctx)
        .map_err(|_| CryptoError::ContextTooLong)?;
    let encoded = sig.encode();
    let mut out = [0u8; SIGNATURE_BYTES];
    out.copy_from_slice(encoded.as_slice());
    Ok(out)
}

/// Verify, rejecting non-canonical public-key and signature encodings.
pub fn verify(
    public_key: &PublicKey,
    ctx: &[u8],
    msg: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> bool {
    let encoded_pk = match EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&encoded_pk);
    if vk.encode().as_slice() != public_key.as_slice() {
        return false;
    }

    let encoded_sig = match EncodedSignature::<MlDsa65>::try_from(signature.as_slice()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match Signature::<MlDsa65>::decode(&encoded_sig) {
        Some(s) => s,
        None => return false,
    };
    if sig.encode().as_slice() != signature.as_slice() {
        return false;
    }

    vk.verify_with_context(msg, ctx, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_core::hash::{DOM_STATE_UPDATE, DOM_TRANSFER};

    const MSG: &[u8] = b"canonical transaction body";

    #[test]
    fn sizes_match_the_protocol() {
        let key = key_from_seed([1u8; 32]);
        assert_eq!(public_key_bytes(&key).len(), 1952);
        assert_eq!(sign(&key, DOM_TRANSFER, MSG).unwrap().len(), 3309);
    }

    #[test]
    fn seed_roundtrip_is_deterministic() {
        let a = key_from_seed([7u8; 32]);
        let b = key_from_seed([7u8; 32]);
        assert_eq!(public_key_bytes(&a), public_key_bytes(&b));
        assert_eq!(seed_of(&a), [7u8; 32]);
        assert_eq!(
            sign(&a, DOM_TRANSFER, MSG).unwrap(),
            sign(&b, DOM_TRANSFER, MSG).unwrap()
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = key_from_seed([2u8; 32]);
        let pk = public_key_bytes(&key);
        let sig = sign(&key, DOM_TRANSFER, MSG).unwrap();
        assert!(verify(&pk, DOM_TRANSFER, MSG, &sig));
    }

    #[test]
    fn context_is_bound() {
        let key = key_from_seed([3u8; 32]);
        let pk = public_key_bytes(&key);
        let sig = sign(&key, DOM_TRANSFER, MSG).unwrap();
        assert!(!verify(&pk, DOM_STATE_UPDATE, MSG, &sig));
        assert!(!verify(&pk, b"", MSG, &sig));
    }

    #[test]
    fn message_is_bound() {
        let key = key_from_seed([4u8; 32]);
        let pk = public_key_bytes(&key);
        let sig = sign(&key, DOM_TRANSFER, MSG).unwrap();
        assert!(!verify(&pk, DOM_TRANSFER, b"another body", &sig));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = key_from_seed([5u8; 32]);
        let b = key_from_seed([6u8; 32]);
        let sig = sign(&a, DOM_TRANSFER, MSG).unwrap();
        assert!(!verify(&public_key_bytes(&b), DOM_TRANSFER, MSG, &sig));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let key = key_from_seed([8u8; 32]);
        let pk = public_key_bytes(&key);
        let mut sig = sign(&key, DOM_TRANSFER, MSG).unwrap();
        sig[0] ^= 0xFF;
        assert!(!verify(&pk, DOM_TRANSFER, MSG, &sig));
    }

    #[test]
    fn account_id_is_the_key_hash() {
        let key = key_from_seed([9u8; 32]);
        let pk = public_key_bytes(&key);
        assert_eq!(account_id(&pk), vess_core::hash::account_id(&pk));
    }

    #[test]
    fn over_long_context_is_rejected_at_sign_time() {
        let key = key_from_seed([10u8; 32]);
        let ctx = [0u8; 256];
        assert_eq!(sign(&key, &ctx, MSG), Err(CryptoError::ContextTooLong));
    }
}
