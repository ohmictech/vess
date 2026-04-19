//! **vess-tag** — Human-readable identity layer for the Vess protocol.
//!
//! VessTags are lowercase alphanumeric names (3-20 chars) prefixed with `+`
//! that map to a master stealth address. Users send Vess to `+alice` instead
//! of pasting a public key.
//!
//! # Registration
//!
//! Claiming a tag requires computing a memory-hard Argon2id proof-of-work
//! (2 GiB RAM, ~10 seconds on typical hardware). No bills are required,
//! lowering the onboarding barrier to zero. Each master stealth address may
//! only hold **one** tag — duplicates are rejected by the DHT.
//!
//! # Lookup
//!
//! Tag records are stored in a DHT keyed on `Blake3(tag)`. Each record
//! contains the tag string, master stealth address, and the PoW nonce/hash.

use anyhow::{anyhow, Result};
use argon2::Argon2;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use vess_stealth::MasterStealthAddress;

// ── VessTag ──────────────────────────────────────────────────────────

/// A validated VessTag string (3-20 lowercase alphanumeric characters).
///
/// The `+` prefix is a display convention and is **not** stored in the inner value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VessTag(String);

impl VessTag {
    /// Parse and validate a tag string.
    ///
    /// Accepts either `+alice` or `alice` — the `+` prefix is stripped.
    /// The inner string must be 3-20 lowercase ASCII alphanumeric characters.
    pub fn new(raw: &str) -> Result<Self> {
        let s = raw.strip_prefix('+').unwrap_or(raw);

        if s.len() < 3 {
            return Err(anyhow!("tag too short (min 3 chars): {s:?}"));
        }
        if s.len() > 20 {
            return Err(anyhow!("tag too long (max 20 chars): {s:?}"));
        }
        if !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
            return Err(anyhow!(
                "tag must be lowercase alphanumeric only: {s:?}"
            ));
        }

        Ok(Self(s.to_owned()))
    }

    /// The raw tag string without the `+` prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Character length of the tag.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the tag is empty (always false for a valid tag).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Display form with `+` prefix (e.g. `+alice`).
    pub fn display(&self) -> String {
        format!("+{}", self.0)
    }

    /// DHT key for this tag: `Blake3(tag_string)`.
    pub fn dht_key(&self) -> [u8; 32] {
        *blake3::hash(self.0.as_bytes()).as_bytes()
    }
}

impl std::fmt::Display for VessTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "+{}", self.0)
    }
}

// ── Argon2id Proof-of-Work ────────────────────────────────────────────

/// How long an unhardened tag survives before pruning: 7 days in seconds.
/// Short TTL raises the cost of tag squatting — squatters must re-register
/// weekly (paying PoW each time) or harden via real economic activity.
pub const TAG_PRUNE_SECS: u64 = 7 * 24 * 3600;

/// Argon2id memory cost: 2 GiB in KiB.
pub const TAG_POW_M_COST: u32 = 2_097_152;
/// Argon2id time cost (iterations).  One pass over 2 GiB takes ~10 s
/// on typical consumer hardware.
pub const TAG_POW_T_COST: u32 = 1;
/// Argon2id parallelism lanes.
pub const TAG_POW_P_COST: u32 = 1;
/// Output hash length in bytes.
pub const TAG_POW_HASH_LEN: usize = 32;

/// Build the Argon2id password input for a tag PoW.
///
/// `password = "vess-tag-pow-v2" || tag_hash || scan_ek || spend_ek`
fn pow_password(tag_hash: &[u8; 32], scan_ek: &[u8], spend_ek: &[u8]) -> Vec<u8> {
    let mut pwd = Vec::with_capacity(16 + 32 + scan_ek.len() + spend_ek.len());
    pwd.extend_from_slice(b"vess-tag-pow-v2\0");
    pwd.extend_from_slice(tag_hash);
    pwd.extend_from_slice(scan_ek);
    pwd.extend_from_slice(spend_ek);
    pwd
}

/// Compute the Argon2id proof-of-work for a tag registration.
///
/// Returns `(nonce, hash)`.  The nonce is a random 32-byte salt; the hash
/// is the 32-byte Argon2id output.  This function is deliberately
/// expensive (~10 s, 2 GiB RAM) — that cost IS the anti-spam mechanism.
pub fn compute_tag_pow(
    tag_hash: &[u8; 32],
    scan_ek: &[u8],
    spend_ek: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    let nonce: [u8; 32] = rand::random();
    let password = pow_password(tag_hash, scan_ek, spend_ek);

    let params = argon2::Params::new(TAG_POW_M_COST, TAG_POW_T_COST, TAG_POW_P_COST, Some(TAG_POW_HASH_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = vec![0u8; TAG_POW_HASH_LEN];
    argon2
        .hash_password_into(&password, &nonce, &mut hash)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;

    Ok((nonce, hash))
}

/// Verify an Argon2id proof-of-work for a tag registration.
///
/// Recomputes the hash from the given inputs and checks it matches
/// `expected_hash`.  This is as expensive as computing the PoW (~10 s,
/// 2 GiB RAM).
pub fn verify_tag_pow(
    tag_hash: &[u8; 32],
    scan_ek: &[u8],
    spend_ek: &[u8],
    nonce: &[u8; 32],
    expected_hash: &[u8],
) -> Result<bool> {
    if expected_hash.len() != TAG_POW_HASH_LEN {
        return Ok(false);
    }

    let password = pow_password(tag_hash, scan_ek, spend_ek);

    let params = argon2::Params::new(TAG_POW_M_COST, TAG_POW_T_COST, TAG_POW_P_COST, Some(TAG_POW_HASH_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = vec![0u8; TAG_POW_HASH_LEN];
    argon2
        .hash_password_into(&password, nonce, &mut hash)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;

    Ok(hash == expected_hash)
}

/// Compute the Argon2id PoW with **test-friendly** parameters (tiny memory)
/// so unit tests finish in milliseconds.
#[cfg(any(test, feature = "test-pow"))]
pub fn compute_tag_pow_test(
    tag_hash: &[u8; 32],
    scan_ek: &[u8],
    spend_ek: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    let nonce: [u8; 32] = rand::random();
    let password = pow_password(tag_hash, scan_ek, spend_ek);

    let params = argon2::Params::new(64, 1, 1, Some(TAG_POW_HASH_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = vec![0u8; TAG_POW_HASH_LEN];
    argon2
        .hash_password_into(&password, &nonce, &mut hash)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;

    Ok((nonce, hash))
}

/// Verify a PoW hash with **test-friendly** parameters (tiny memory).
#[cfg(any(test, feature = "test-pow"))]
pub fn verify_tag_pow_test(
    tag_hash: &[u8; 32],
    scan_ek: &[u8],
    spend_ek: &[u8],
    nonce: &[u8; 32],
    expected_hash: &[u8],
) -> Result<bool> {
    if expected_hash.len() != TAG_POW_HASH_LEN {
        return Ok(false);
    }
    let password = pow_password(tag_hash, scan_ek, spend_ek);

    let params = argon2::Params::new(64, 1, 1, Some(TAG_POW_HASH_LEN))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = vec![0u8; TAG_POW_HASH_LEN];
    argon2
        .hash_password_into(&password, nonce, &mut hash)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?;

    Ok(hash == expected_hash)
}

/// Blake3 fingerprint of a master stealth address for reverse-index lookups.
pub fn address_fingerprint(addr: &MasterStealthAddress) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"vess-addr-fp-v1");
    h.update(&addr.scan_ek);
    h.update(&addr.spend_ek);
    *h.finalize().as_bytes()
}

// ── Tag Record ───────────────────────────────────────────────────────

/// A VessTag registration record stored in the DHT.
///
/// Small enough to replicate across K artery nodes responsible for the
/// tag's DHT region. The plaintext tag name never leaves the client —
/// only the Blake3 hash is stored and transmitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRecord {
    /// Blake3 hash of the tag string. The plaintext is never stored
    /// on relay nodes, preventing tag → address correlation by observers.
    pub tag_hash: [u8; 32],
    /// The owner's master stealth address (scan + spend public keys).
    pub master_address: MasterStealthAddress,
    /// Random 32-byte nonce used as salt for the Argon2id PoW.
    pub pow_nonce: [u8; 32],
    /// 32-byte Argon2id hash output proving the registrant performed the work.
    pub pow_hash: Vec<u8>,
    /// Unix timestamp of registration.
    pub registered_at: u64,
    /// ML-DSA-65 verification key of the registrant.
    /// Included in the digest to make the record self-authenticating.
    #[serde(default)]
    pub registrant_vk: Vec<u8>,
    /// ML-DSA-65 signature over `digest()` by the registrant.
    /// Allows clients to verify the record hasn't been tampered with.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Unix timestamp when the tag was hardened (confirmed with payment proof).
    /// `None` means the tag is still unhardened and subject to pruning.
    #[serde(default)]
    pub hardened_at: Option<u64>,
}

impl TagRecord {
    /// Blake3 hash of this record for integrity verification.
    /// Includes registrant_vk so the signature is self-authenticating.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"vess-tag-record-v3");
        h.update(&self.tag_hash);
        h.update(&self.master_address.scan_ek);
        h.update(&self.master_address.spend_ek);
        h.update(&self.pow_nonce);
        h.update(&self.pow_hash);
        h.update(&self.registered_at.to_le_bytes());
        h.update(&self.registrant_vk);
        *h.finalize().as_bytes()
    }

    /// DHT key for this record (same as the tag hash).
    pub fn dht_key(&self) -> [u8; 32] {
        self.tag_hash
    }

    /// Blake3 fingerprint of this record's master stealth address.
    pub fn address_fingerprint(&self) -> [u8; 32] {
        address_fingerprint(&self.master_address)
    }
}

// ── Registration Request ─────────────────────────────────────────────

/// A request to register a VessTag, broadcast to artery nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRegistration {
    /// Blake3 hash of the desired tag.
    pub tag_hash: [u8; 32],
    /// The owner's master stealth address.
    pub master_address: MasterStealthAddress,
    /// Random 32-byte nonce (salt) for the Argon2id PoW.
    pub pow_nonce: [u8; 32],
    /// 32-byte Argon2id output hash.
    pub pow_hash: Vec<u8>,
}

/// Validate a tag registration's PoW hash length (format check only).
///
/// The actual Argon2id verification (expensive, ~10 s) is performed
/// separately by `verify_tag_pow` / `verify_tag_pow_test`.
pub fn validate_registration(reg: &TagRegistration) -> Result<()> {
    if reg.pow_hash.len() != TAG_POW_HASH_LEN {
        return Err(anyhow!(
            "invalid PoW hash length: expected {TAG_POW_HASH_LEN}, got {}",
            reg.pow_hash.len(),
        ));
    }
    Ok(())
}

/// Verify the ML-DSA-65 signature on a TagRecord.
///
/// Returns `Ok(true)` if signature is valid, `Ok(false)` if invalid,
/// and `Err` if the record has no signature or the key/sig bytes are malformed.
pub fn verify_record_signature(record: &TagRecord) -> Result<bool> {
    if record.registrant_vk.is_empty() || record.signature.is_empty() {
        return Err(anyhow!("tag record missing registrant_vk or signature"));
    }
    let digest = record.digest();
    vess_foundry::spend_auth::verify_spend(&record.registrant_vk, &digest, &record.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tags() {
        assert!(VessTag::new("abc").is_ok());
        assert!(VessTag::new("+alice").is_ok());
        assert!(VessTag::new("shop99").is_ok());
        assert!(VessTag::new("a1b2c3d4e5f6g7h8i9j0").is_ok()); // 20 chars
    }

    #[test]
    fn invalid_tags() {
        assert!(VessTag::new("ab").is_err()); // too short
        assert!(VessTag::new("a]b").is_err()); // invalid char
        assert!(VessTag::new("ABC").is_err()); // uppercase
        assert!(VessTag::new("+ab").is_err()); // too short after strip
        let long = "a".repeat(21);
        assert!(VessTag::new(&long).is_err()); // too long
    }

    #[test]
    fn display_has_plus_prefix() {
        let tag = VessTag::new("alice").unwrap();
        assert_eq!(tag.to_string(), "+alice");
        assert_eq!(tag.display(), "+alice");
        assert_eq!(tag.as_str(), "alice");
    }

    #[test]
    fn burn_cost_table_removed() {
        // BurnCostTable no longer exists — burn system replaced by PoW.
        // This test verifies the PoW constants are sane.
        assert!(TAG_POW_M_COST > 0);
        assert!(TAG_POW_T_COST > 0);
        assert!(TAG_POW_HASH_LEN == 32);
    }

    #[test]
    fn pow_compute_and_verify() {
        let tag = VessTag::new("alice").unwrap();
        let tag_hash = tag.dht_key();
        let (_s, addr) = vess_stealth::generate_master_keys();

        let (nonce, hash) = compute_tag_pow_test(&tag_hash, &addr.scan_ek, &addr.spend_ek).unwrap();
        assert_eq!(hash.len(), TAG_POW_HASH_LEN);

        let ok = verify_tag_pow_test(&tag_hash, &addr.scan_ek, &addr.spend_ek, &nonce, &hash).unwrap();
        assert!(ok);

        // Wrong nonce → different hash → fails.
        let bad_nonce = [0xFF; 32];
        let bad = verify_tag_pow_test(&tag_hash, &addr.scan_ek, &addr.spend_ek, &bad_nonce, &hash).unwrap();
        assert!(!bad);
    }

    #[test]
    fn registration_invalid_pow_hash_length() {
        let (_s, addr) = vess_stealth::generate_master_keys();
        let tag_hash = VessTag::new("abc").unwrap().dht_key();
        let reg = TagRegistration {
            tag_hash,
            master_address: addr,
            pow_nonce: [0x00; 32],
            pow_hash: vec![0u8; 16], // too short
        };
        assert!(validate_registration(&reg).is_err());
    }

    #[test]
    fn registration_valid_pow_hash_length() {
        let (_s, addr) = vess_stealth::generate_master_keys();
        let tag_hash = VessTag::new("shop99").unwrap().dht_key();
        let reg = TagRegistration {
            tag_hash,
            master_address: addr,
            pow_nonce: [0x00; 32],
            pow_hash: vec![0u8; 32],
        };
        assert!(validate_registration(&reg).is_ok());
    }

    #[test]
    fn address_fingerprint_deterministic() {
        let (_s, addr) = vess_stealth::generate_master_keys();
        assert_eq!(address_fingerprint(&addr), address_fingerprint(&addr));

        let (_s2, addr2) = vess_stealth::generate_master_keys();
        assert_ne!(address_fingerprint(&addr), address_fingerprint(&addr2));
    }

    #[test]
    fn dht_key_deterministic() {
        let t1 = VessTag::new("alice").unwrap();
        let t2 = VessTag::new("+alice").unwrap();
        assert_eq!(t1.dht_key(), t2.dht_key());
    }

    #[test]
    fn tag_record_digest_changes_with_content() {
        let (_s, addr) = vess_stealth::generate_master_keys();
        let tag_hash = VessTag::new("alice").unwrap().dht_key();
        let r1 = TagRecord {
            tag_hash,
            master_address: addr.clone(),
            pow_nonce: [0x01; 32],
            pow_hash: vec![0xAA; 32],
            registered_at: 1000,
            registrant_vk: Vec::new(),
            signature: Vec::new(),
            hardened_at: None,
        };
        let r2 = TagRecord {
            tag_hash,
            master_address: addr,
            pow_nonce: [0x02; 32],
            pow_hash: vec![0xBB; 32],
            registered_at: 1000,
            registrant_vk: Vec::new(),
            signature: Vec::new(),
            hardened_at: None,
        };
        assert_ne!(r1.digest(), r2.digest());
    }

    #[test]
    fn pow_verify_rejects_wrong_tag() {
        let tag1_hash = VessTag::new("alice").unwrap().dht_key();
        let tag2_hash = VessTag::new("bob").unwrap().dht_key();
        let (_s, addr) = vess_stealth::generate_master_keys();

        let (nonce, hash) = compute_tag_pow_test(&tag1_hash, &addr.scan_ek, &addr.spend_ek).unwrap();
        // Verify with different tag → fails.
        let ok = verify_tag_pow_test(&tag2_hash, &addr.scan_ek, &addr.spend_ek, &nonce, &hash).unwrap();
        assert!(!ok);
    }
}
