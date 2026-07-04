//! **vess-stealth** — Post-quantum stealth address primitives for the Vess protocol.
//!
//! Implements a Dual-Key Stealth Address Protocol (DKSAP) using ML-KEM-768
//! (FIPS 203) for quantum-resistant key encapsulation. All key exchanges use
//! lattice-based cryptography; no elliptic curves are involved.
//!
//! # Stealth Address Flow
//!
//! 1. **Recipient** publishes a [`MasterStealthAddress`] containing two ML-KEM
//!    encapsulation keys: `scan_ek` (for scanning) and `spend_ek` (for claiming).
//!
//! 2. **Sender** calls [`prepare_stealth_payload`] which:
//!    - Encapsulates to `scan_ek` → `(ct_scan, ss_scan)`
//!    - Encapsulates to `spend_ek` → `(ct_spend, ss_spend)`
//!    - Derives a `view_tag` (first byte of `Blake3(ss_scan)`) for efficient scanning
//!    - Derives a unique `stealth_id = Blake3(ss_scan ‖ ss_spend)`
//!    - Encrypts the bill payload under `ChaCha20Poly1305(Blake3(ss_scan ‖ "vess-aead"))`
//!
//! 3. **Recipient** calls [`scan_view_tag`] with each incoming pulse's view tag
//!    to quickly filter (1/256 false-positive rate). On match, calls
//!    [`open_stealth_payload`] to decapsulate, verify `stealth_id`, and decrypt.
//!
//! # Post-Quantum Security
//!
//! - ML-KEM-768 provides NIST security level 3 (AES-192 equivalent).
//! - ChaCha20Poly1305 for authenticated encryption (256-bit symmetric).
//! - Blake3 for all hashing (256-bit output).
//! - No pre-quantum primitives are used anywhere in the protocol.
//!
//! # Deterministic Key Recovery
//!
//! ML-KEM keypairs are derived deterministically from a 64-byte seed via
//! [`generate_master_keys_from_seed`]. The seed is split into two 32-byte
//! halves fed into ChaCha20Rng, one for each keypair. This ensures wallets
//! are fully recoverable from a recovery phrase alone.

use anyhow::{anyhow, Result};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Concrete ML-KEM-768 type aliases for readability.
type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

/// ML-KEM-768 public key — serialised bytes.
pub type EncapKeyBytes = Vec<u8>;
/// ML-KEM-768 secret key — serialised bytes.
pub type DecapKeyBytes = Vec<u8>;
/// ML-KEM-768 ciphertext bytes.
pub type CiphertextBytes = Vec<u8>;

/// A master stealth address published by a recipient.
///
/// Contains two ML-KEM-768 public keys:
/// - `scan_ek`: Used by senders to derive view tags for efficient scanning.
/// - `spend_ek`: Used by senders to bind bills to the recipient's spending authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterStealthAddress {
    pub scan_ek: EncapKeyBytes,
    pub spend_ek: EncapKeyBytes,
}

/// The secret half of a master stealth address, held only by the recipient.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StealthSecretKey {
    pub scan_dk: DecapKeyBytes,
    pub spend_dk: DecapKeyBytes,
}

impl std::fmt::Debug for StealthSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StealthSecretKey(<redacted>)")
    }
}

/// A stealth payload attached to a bill when sent to a recipient.
///
/// Contains everything the recipient needs to detect, claim, and decrypt
/// the enclosed bill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthPayload {
    /// KEM ciphertext encapsulated to the recipient's scan key.
    pub ct_scan: CiphertextBytes,
    /// KEM ciphertext encapsulated to the recipient's spend key.
    pub ct_spend: CiphertextBytes,
    /// View tag: first byte of `Blake3(ss_scan)`. For quick scan filtering.
    pub view_tag: u8,
    /// Unique stealth identifier: `Blake3(ss_scan ‖ ss_spend)`.
    pub stealth_id: [u8; 32],
    /// AEAD-encrypted bill payload.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (96 bits).
    pub nonce: [u8; 12],
}

// ── Uniform payment size padding ──────────────────────────────────────

/// All plaintexts are padded to exactly this many bytes before AEAD encryption.
///
/// This guarantees every [`StealthPayload`] (and thus every payment on the
/// wire) is identical in size regardless of bill count, killing the
/// `bill_count` observable for traffic analysis.
///
/// 48 KB accommodates ~300 simple bills or ~9 transfer-authorized bills
/// (each carrying an ML-DSA-65 VK + signature, ~5.4 KB/bill).
/// Payments exceeding this limit are split by the sender.
///
/// Format: `[u16 LE actual_len] || plaintext || random_padding`
pub const PADDED_PLAINTEXT_SIZE: usize = 49152;

/// Pad `plaintext` to exactly [`PADDED_PLAINTEXT_SIZE`] bytes.
///
/// If the plaintext is too large to fit in a single padded payload,
/// a warning is logged and the plaintext is returned length-prefixed
/// as-is. Callers should split oversized payments before calling this.
pub fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let actual = plaintext.len();
    if actual > PADDED_PLAINTEXT_SIZE.saturating_sub(2) {
        // Too large for uniform padding — caller should split.
        // Returning length-prefixed as-is; size will leak on-wire.
        let mut out = Vec::with_capacity(actual + 2);
        out.extend_from_slice(&(actual as u16).to_le_bytes());
        out.extend_from_slice(plaintext);
        return out;
    }
    let mut out = vec![0u8; PADDED_PLAINTEXT_SIZE];
    out[..2].copy_from_slice(&(actual as u16).to_le_bytes());
    out[2..2 + actual].copy_from_slice(plaintext);
    // Fill tail with cryptographically random bytes to look like ciphertext.
    rand::thread_rng().fill_bytes(&mut out[2 + actual..]);
    out
}

/// Extract the original plaintext from a padded buffer.
///
/// Returns `None` if the buffer is shorter than 2 bytes or the declared
/// length exceeds the buffer size.
pub fn unpad_plaintext(padded: &[u8]) -> Option<&[u8]> {
    if padded.len() < 2 {
        return None;
    }
    let actual = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if actual + 2 > padded.len() {
        return None;
    }
    Some(&padded[2..2 + actual])
}

// ── Serialization helpers ─────────────────────────────────────────────

fn ek_to_vec(ek: &Ek) -> Vec<u8> {
    ek.as_bytes().to_vec()
}

fn dk_to_vec(dk: &Dk) -> Vec<u8> {
    dk.as_bytes().to_vec()
}

fn vec_to_ek(bytes: &[u8]) -> Result<Ek> {
    let encoded: Encoded<Ek> = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid encapsulation key length"))?;
    Ok(Ek::from_bytes(&encoded))
}

fn vec_to_dk(bytes: &[u8]) -> Result<Dk> {
    let encoded: Encoded<Dk> = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid decapsulation key length"))?;
    Ok(Dk::from_bytes(&encoded))
}

fn vec_to_ct(bytes: &[u8]) -> Result<ml_kem::Ciphertext<MlKem768>> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid ciphertext length"))
}

// ── Key generation ────────────────────────────────────────────────────

/// Generate a fresh ML-KEM-768 master stealth keypair using OS randomness.
///
/// Returns (secret_key, public_address). For deterministic generation from
/// a recovery phrase, use [`generate_master_keys_from_seed`] instead.
pub fn generate_master_keys() -> (StealthSecretKey, MasterStealthAddress) {
    let mut rng = rand::thread_rng();
    let (scan_dk, scan_ek) = MlKem768::generate(&mut rng);
    let (spend_dk, spend_ek) = MlKem768::generate(&mut rng);

    let secret = StealthSecretKey {
        scan_dk: dk_to_vec(&scan_dk),
        spend_dk: dk_to_vec(&spend_dk),
    };
    let address = MasterStealthAddress {
        scan_ek: ek_to_vec(&scan_ek),
        spend_ek: ek_to_vec(&spend_ek),
    };
    (secret, address)
}

/// Generate ML-KEM-768 master stealth keypair deterministically from a seed.
///
/// The 64-byte seed is split into two domain-separated 32-byte ChaCha20 seeds:
/// - `Blake3(seed ‖ "vess-stealth-scan-v0")` → scan keypair RNG
/// - `Blake3(seed ‖ "vess-stealth-spend-v0")` → spend keypair RNG
///
/// Given the same seed, this always produces the same keypair, enabling
/// wallet recovery from the recovery phrase alone.
pub fn generate_master_keys_from_seed(seed: &[u8; 64]) -> (StealthSecretKey, MasterStealthAddress) {
    let scan_rng_seed = {
        let mut h = Hasher::new();
        h.update(seed);
        h.update(b"vess-stealth-scan-v0");
        *h.finalize().as_bytes()
    };
    let spend_rng_seed = {
        let mut h = Hasher::new();
        h.update(seed);
        h.update(b"vess-stealth-spend-v0");
        *h.finalize().as_bytes()
    };

    let mut scan_rng = ChaCha20Rng::from_seed(scan_rng_seed);
    let mut spend_rng = ChaCha20Rng::from_seed(spend_rng_seed);

    let (scan_dk, scan_ek) = MlKem768::generate(&mut scan_rng);
    let (spend_dk, spend_ek) = MlKem768::generate(&mut spend_rng);

    let secret = StealthSecretKey {
        scan_dk: dk_to_vec(&scan_dk),
        spend_dk: dk_to_vec(&spend_dk),
    };
    let address = MasterStealthAddress {
        scan_ek: ek_to_vec(&scan_ek),
        spend_ek: ek_to_vec(&spend_ek),
    };
    (secret, address)
}

// ── Stealth operations ────────────────────────────────────────────────

/// Pre-computed KEM context for two-phase stealth payload construction.
///
/// Use [`generate_stealth_context_with_tag`] to create one, inspect `stealth_id`,
/// and optionally bind a per-payment tag context for unlinkable view tags.
/// then call [`StealthContext::encrypt`] to produce the final
/// [`StealthPayload`].  This avoids the need for a "preview" call that
/// would yield a different `stealth_id` due to fresh random KEM keys.
pub struct StealthContext {
    pub ct_scan: Vec<u8>,
    pub ct_spend: Vec<u8>,
    pub view_tag: u8,
    pub stealth_id: [u8; 32],
    aead_key: [u8; 32],
    nonce_bytes: [u8; 12],
}

/// Generate a [`StealthContext`] for the given master address.
///
/// Performs both KEM encapsulations up front so `stealth_id` is known
/// before the plaintext is ready (e.g. when the plaintext depends on
/// `stealth_id` itself, as in transfer-authorized payments).
/// Generate a fresh stealth context for encrypting a payment to `address`.
///
/// `tag_context` is bound into the view tag to make it per-payment unlinkable.
/// Pass the `payment_id` here so each payment has a different view tag,
/// preventing an observer from clustering payments by recipient.
pub fn generate_stealth_context_with_tag(
    address: &MasterStealthAddress,
    tag_context: &[u8],
) -> Result<StealthContext> {
    generate_stealth_context_impl(address, tag_context)
}

/// Generate a stealth context without a per-payment tag (legacy).
/// Prefer [`generate_stealth_context_with_tag`] for new code.
pub fn generate_stealth_context(address: &MasterStealthAddress) -> Result<StealthContext> {
    generate_stealth_context_impl(address, b"")
}

fn generate_stealth_context_impl(
    address: &MasterStealthAddress,
    tag_context: &[u8],
) -> Result<StealthContext> {
    let scan_ek = vec_to_ek(&address.scan_ek)?;
    let spend_ek = vec_to_ek(&address.spend_ek)?;

    let mut rng = rand::thread_rng();
    let (ct_scan, ss_scan) = scan_ek
        .encapsulate(&mut rng)
        .map_err(|_| anyhow!("scan encapsulate failed"))?;
    let (ct_spend, ss_spend) = spend_ek
        .encapsulate(&mut rng)
        .map_err(|_| anyhow!("spend encapsulate failed"))?;

    let ss_scan_bytes: &[u8] = ss_scan.as_ref();
    let ss_spend_bytes: &[u8] = ss_spend.as_ref();

    Ok(StealthContext {
        ct_scan: ct_scan.to_vec(),
        ct_spend: ct_spend.to_vec(),
        view_tag: compute_view_tag(ss_scan_bytes, tag_context),
        stealth_id: compute_stealth_id(ss_scan_bytes, ss_spend_bytes),
        aead_key: derive_aead_key(ss_scan_bytes),
        nonce_bytes: derive_nonce(ss_scan_bytes, ss_spend_bytes),
    })
}

impl StealthContext {
    /// Encrypt `plaintext` using the pre-computed KEM context.
    pub fn encrypt(self, plaintext: &[u8]) -> Result<StealthPayload> {
        let nonce = GenericArray::from_slice(&self.nonce_bytes);
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.aead_key));
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("AEAD encrypt: {e}"))?;

        Ok(StealthPayload {
            ct_scan: self.ct_scan,
            ct_spend: self.ct_spend,
            view_tag: self.view_tag,
            stealth_id: self.stealth_id,
            ciphertext,
            nonce: self.nonce_bytes,
        })
    }
}

/// Prepare a stealth payload encrypting `plaintext` for the given master address.
///
/// This is the **sender-side** operation. The returned [`StealthPayload`]
/// should be attached to the bill and transmitted via a vascular pulse.
pub fn prepare_stealth_payload(
    address: &MasterStealthAddress,
    plaintext: &[u8],
) -> Result<StealthPayload> {
    generate_stealth_context(address)?.encrypt(plaintext)
}

/// Prepare a stealth payload with a per-payment tag context for unlinkable view tags.
///
/// `tag_context` (typically the `payment_id`) is bound into the view tag so
/// each payment has a different tag, preventing observer clustering.
pub fn prepare_stealth_payload_with_tag(
    address: &MasterStealthAddress,
    plaintext: &[u8],
    tag_context: &[u8],
) -> Result<StealthPayload> {
    generate_stealth_context_with_tag(address, tag_context)?.encrypt(plaintext)
}

/// Quick-scan a view tag against the recipient's scan secret key.
///
/// Returns `true` if the tag matches (potential match, 1/256 false positive).
/// The recipient should call [`open_stealth_payload`] on matches.
/// Scan a view tag, checking whether a payment is potentially for this recipient.
///
/// `tag_context` must be the same value passed to `generate_stealth_context_with_tag`
/// (typically the `payment_id`). Returns `true` if the tag matches (1/256 false positive).
pub fn scan_view_tag_with_context(
    secret: &StealthSecretKey,
    ct_scan: &[u8],
    view_tag: u8,
    tag_context: &[u8],
) -> Result<bool> {
    let dk = vec_to_dk(&secret.scan_dk)?;
    let ct = vec_to_ct(ct_scan)?;
    let ss_scan = dk
        .decapsulate(&ct)
        .map_err(|_| anyhow!("scan decapsulate failed"))?;
    Ok(compute_view_tag(ss_scan.as_ref(), tag_context) == view_tag)
}

/// Scan a view tag (legacy — without per-payment context).
/// Prefer [`scan_view_tag_with_context`] for new code.
pub fn scan_view_tag(secret: &StealthSecretKey, ct_scan: &[u8], view_tag: u8) -> Result<bool> {
    scan_view_tag_with_context(secret, ct_scan, view_tag, b"")
}

/// Open a stealth payload, decrypting the enclosed bill.
///
/// This is the **recipient-side** operation. Decapsulates both KEM
/// ciphertexts, verifies the stealth ID, and decrypts the payload.
pub fn open_stealth_payload(
    secret: &StealthSecretKey,
    payload: &StealthPayload,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let scan_dk = vec_to_dk(&secret.scan_dk)?;
    let spend_dk = vec_to_dk(&secret.spend_dk)?;
    let ct_scan = vec_to_ct(&payload.ct_scan)?;
    let ct_spend = vec_to_ct(&payload.ct_spend)?;

    let ss_scan = scan_dk
        .decapsulate(&ct_scan)
        .map_err(|_| anyhow!("scan decapsulate failed"))?;
    let ss_spend = spend_dk
        .decapsulate(&ct_spend)
        .map_err(|_| anyhow!("spend decapsulate failed"))?;

    let ss_scan_bytes: &[u8] = ss_scan.as_ref();
    let ss_spend_bytes: &[u8] = ss_spend.as_ref();

    // Verify stealth ID.
    let expected_id = compute_stealth_id(ss_scan_bytes, ss_spend_bytes);
    if expected_id != payload.stealth_id {
        return Err(anyhow!("stealth ID mismatch — not for this recipient"));
    }

    // Decrypt payload.
    let aead_key = derive_aead_key(ss_scan_bytes);
    let nonce = GenericArray::from_slice(&payload.nonce);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&aead_key));
    let plaintext = cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|e| anyhow!("AEAD decrypt: {e}"))?;

    // Derive a separate recovery key so callers can encrypt bill-recovery
    // blobs that only the recipient (who can re-run KEM decapsulation) can read.
    let recovery_key = derive_recovery_key(ss_scan_bytes);

    Ok((plaintext, payload.stealth_id, recovery_key))
}

// ── Internal helpers ──────────────────────────────────────────────────

fn compute_view_tag(ss_scan: &[u8], tag_context: &[u8]) -> u8 {
    let mut h = Hasher::new();
    h.update(ss_scan);
    h.update(tag_context);
    h.finalize().as_bytes()[0]
}

fn compute_stealth_id(ss_scan: &[u8], ss_spend: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(ss_scan);
    h.update(ss_spend);
    *h.finalize().as_bytes()
}

fn derive_aead_key(ss_scan: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(ss_scan);
    h.update(b"vess-aead-v0");
    *h.finalize().as_bytes()
}

/// Derive a per-payment key for encrypting the claim recovery blob
/// (`encrypted_bill` in `OwnershipClaim`).  Uses a separate domain from
/// the payload AEAD key so the two purposes never share key material.
fn derive_recovery_key(ss_scan: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(ss_scan);
    h.update(b"vess-recovery-v0");
    *h.finalize().as_bytes()
}

fn derive_nonce(ss_scan: &[u8], ss_spend: &[u8]) -> [u8; 12] {
    let mut h = Hasher::new();
    h.update(ss_scan);
    h.update(ss_spend);
    h.update(b"vess-nonce-v0");
    let hash = h.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash.as_bytes()[..12]);
    nonce
}

// ── Onion Routing Helpers ────────────────────────────────────────────

/// Domain separator for onion-layer AEAD key derivation.
const ONION_AEAD_DOMAIN: &[u8] = b"vess-onion-aead-v1";

/// Derive the AEAD key for an onion layer from the scan shared secret.
fn derive_onion_aead_key(ss_scan: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ss_scan);
    h.update(ONION_AEAD_DOMAIN);
    *h.finalize().as_bytes()
}

/// Wrap an `OnionPayload` as an `OnionLayer` encrypted to a relay's master address.
///
/// This is the sender-side operation. The caller provides the relay's public
/// `MasterStealthAddress` and the serialized `OnionPayload` bytes. Returns an
/// `OnionLayer` that only the relay (with the corresponding `StealthSecretKey`)
/// can decrypt.
pub fn wrap_onion_layer(
    relay_address: &MasterStealthAddress,
    next_hop: [u8; 32],
    payload_bytes: &[u8],
    tag_context: &[u8],
) -> Result<vess_protocol::OnionLayer> {
    // Encapsulate to scan key
    let scan_ek = vec_to_ek(relay_address.scan_ek.as_slice())?;
    let (ct_scan, ss_scan) = scan_ek
        .encapsulate(&mut rand::thread_rng())
        .map_err(|_| anyhow!("scan encapsulate failed"))?;

    // Encapsulate to spend key
    let spend_ek = vec_to_ek(relay_address.spend_ek.as_slice())?;
    let (ct_spend, ss_spend) = spend_ek
        .encapsulate(&mut rand::thread_rng())
        .map_err(|_| anyhow!("spend encapsulate failed"))?;

    let ss_scan_bytes: &[u8] = ss_scan.as_ref();
    let ss_spend_bytes: &[u8] = ss_spend.as_ref();

    // Compute view tag with context
    let mut h = blake3::Hasher::new();
    h.update(ss_scan_bytes);
    h.update(tag_context);
    let view_tag = h.finalize().as_bytes()[0];

    // AEAD key from onion domain
    let aead_key = derive_onion_aead_key(ss_scan_bytes);

    // Nonce from ss_scan + ss_spend
    let mut h_nonce = blake3::Hasher::new();
    h_nonce.update(ss_scan_bytes);
    h_nonce.update(ss_spend_bytes);
    h_nonce.update(b"vess-onion-nonce-v1");
    let nonce_hash = h_nonce.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_hash.as_bytes()[..12]);

    // Encrypt payload
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&aead_key));
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), payload_bytes)
        .map_err(|e| anyhow!("onion AEAD encrypt: {e}"))?;

    Ok(vess_protocol::OnionLayer {
        next_hop,
        ct_scan: ct_scan.to_vec(),
        ct_spend: ct_spend.to_vec(),
        view_tag,
        nonce,
        ciphertext,
    })
}

/// Decrypt an onion layer using the relay's secret key.
///
/// Returns the decrypted `OnionPayload` if successful, or an error if
/// the KEM decapsulation fails, the AEAD tag doesn't verify, or the
/// view tag doesn't match.
pub fn unwrap_onion_layer(
    secret: &StealthSecretKey,
    layer: &vess_protocol::OnionLayer,
    tag_context: &[u8],
) -> Result<vess_protocol::OnionPayload> {
    // Decapsulate scan key
    let scan_dk = vec_to_dk(&secret.scan_dk)?;
    let ct_scan = vec_to_ct(&layer.ct_scan)?;
    let ss_scan = scan_dk
        .decapsulate(&ct_scan)
        .map_err(|_| anyhow!("scan decapsulate failed"))?;
    let ss_scan_bytes: &[u8] = ss_scan.as_ref();

    // Verify view tag
    let mut h = blake3::Hasher::new();
    h.update(ss_scan_bytes);
    h.update(tag_context);
    let expected_tag = h.finalize().as_bytes()[0];
    if expected_tag != layer.view_tag {
        // Not for us — return error to let caller skip
        return Err(anyhow!("view tag mismatch"));
    }

    // Derive AEAD key
    let aead_key = derive_onion_aead_key(ss_scan_bytes);

    // Decrypt
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&aead_key));
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&layer.nonce), layer.ciphertext.as_slice())
        .map_err(|e| anyhow!("onion AEAD decrypt: {e}"))?;

    // Deserialize OnionPayload
    let payload: vess_protocol::OnionPayload = bincode::deserialize(&plaintext)?;
    Ok(payload)
}

/// Encrypt an `OnionPayload` to a relay node's mesh public key.
///
/// This is the simple single-KEM path for onion routing — encrypt directly
/// to the node's ML-KEM-768 `scan_ek` (mesh identity key), not to a wallet
/// stealth address. The relay node decrypts with its mesh private key.
/// No DKSAP dual-key, no view tag scanning — the relay knows it received
/// an `OnionRoute` message.
pub fn wrap_onion_layer_to_node(
    relay_scan_ek: &[u8],
    next_hop: [u8; 32],
    payload_bytes: &[u8],
) -> Result<vess_protocol::OnionLayer> {
    let ek = vec_to_ek(relay_scan_ek)?;
    let (ct_scan, ss) = ek
        .encapsulate(&mut rand::thread_rng())
        .map_err(|_| anyhow!("onion node encapsulate failed"))?;
    let ss_bytes: &[u8] = ss.as_ref();

    // AEAD key from onion domain
    let aead_key = derive_onion_aead_key(ss_bytes);

    // Nonce
    let mut h_nonce = blake3::Hasher::new();
    h_nonce.update(ss_bytes);
    h_nonce.update(b"vess-onion-node-nonce-v1");
    let nonce_hash = h_nonce.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_hash.as_bytes()[..12]);

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&aead_key));
    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&nonce), payload_bytes)
        .map_err(|e| anyhow!("onion node AEAD encrypt: {e}"))?;

    Ok(vess_protocol::OnionLayer {
        next_hop,
        ct_scan: ct_scan.to_vec(),
        ct_spend: Vec::new(), // unused for node-key path
        view_tag: 0,          // unused for node-key path
        nonce,
        ciphertext,
    })
}

/// Decrypt an onion layer using the relay node's mesh private key (scan_dk).
///
/// Single-KEM decryption — no DKSAP dual-key, no view tag scanning.
/// The relay knows it received an OnionRoute and decrypts with its
/// mesh identity key.
pub fn decrypt_onion_with_node_key(
    scan_dk: &[u8],
    layer: &vess_protocol::OnionLayer,
) -> Result<vess_protocol::OnionPayload> {
    let dk = vec_to_dk(scan_dk)?;
    let ct = vec_to_ct(&layer.ct_scan)?;
    let ss = dk
        .decapsulate(&ct)
        .map_err(|_| anyhow!("onion node decapsulate failed"))?;
    let ss_bytes: &[u8] = ss.as_ref();

    let aead_key = derive_onion_aead_key(ss_bytes);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&aead_key));
    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&layer.nonce), layer.ciphertext.as_slice())
        .map_err(|e| anyhow!("onion node AEAD decrypt: {e}"))?;

    let payload: vess_protocol::OnionPayload = bincode::deserialize(&plaintext)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_stealth_payload() {
        let (secret, address) = generate_master_keys();
        let plaintext = b"Vess{denomination:D10,nullifier:abc123}";

        let payload = prepare_stealth_payload(&address, plaintext).unwrap();

        // View tag should match.
        assert!(scan_view_tag(&secret, &payload.ct_scan, payload.view_tag).unwrap());

        // Full open should succeed.
        let (decrypted, stealth_id, _rk) = open_stealth_payload(&secret, &payload).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(stealth_id, payload.stealth_id);
    }

    #[test]
    fn wrong_key_cannot_open() {
        let (_secret1, address1) = generate_master_keys();
        let (secret2, _address2) = generate_master_keys();

        let plaintext = b"secret bill data";
        let payload = prepare_stealth_payload(&address1, plaintext).unwrap();

        // Different recipient's key should fail to decrypt (stealth ID mismatch).
        assert!(open_stealth_payload(&secret2, &payload).is_err());
    }

    #[test]
    fn view_tag_filters_wrong_recipient() {
        let (_secret1, address1) = generate_master_keys();
        let (secret2, _address2) = generate_master_keys();

        let payload = prepare_stealth_payload(&address1, b"data").unwrap();

        // While there's a 1/256 chance of false positive, the stealth_id
        // check in open_stealth_payload will catch it.
        let tag_match = scan_view_tag(&secret2, &payload.ct_scan, payload.view_tag);
        // Whether it matches or not, opening should fail.
        if tag_match.unwrap_or(false) {
            assert!(open_stealth_payload(&secret2, &payload).is_err());
        }
    }

    #[test]
    fn stealth_ids_are_unique() {
        let (_secret, address) = generate_master_keys();
        let p1 = prepare_stealth_payload(&address, b"bill-1").unwrap();
        let p2 = prepare_stealth_payload(&address, b"bill-2").unwrap();
        assert_ne!(p1.stealth_id, p2.stealth_id);
    }

    #[test]
    fn deterministic_keygen_from_seed() {
        let seed = [0x42u8; 64];
        let (sec1, addr1) = generate_master_keys_from_seed(&seed);
        let (sec2, addr2) = generate_master_keys_from_seed(&seed);

        // Same seed → identical keys.
        assert_eq!(addr1.scan_ek, addr2.scan_ek);
        assert_eq!(addr1.spend_ek, addr2.spend_ek);
        assert_eq!(sec1.scan_dk, sec2.scan_dk);
        assert_eq!(sec1.spend_dk, sec2.spend_dk);

        // Different seed → different keys.
        let other_seed = [0x99u8; 64];
        let (_sec3, addr3) = generate_master_keys_from_seed(&other_seed);
        assert_ne!(addr1.scan_ek, addr3.scan_ek);
    }

    #[test]
    fn deterministic_keys_round_trip() {
        let seed = [0xABu8; 64];
        let (secret, address) = generate_master_keys_from_seed(&seed);

        let plaintext = b"Vess from seed-derived keys";
        let payload = prepare_stealth_payload(&address, plaintext).unwrap();

        assert!(scan_view_tag(&secret, &payload.ct_scan, payload.view_tag).unwrap());

        let (decrypted, sid, _rk) = open_stealth_payload(&secret, &payload).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(sid, payload.stealth_id);
    }

    #[test]
    fn pad_unpad_round_trip() {
        // Short plaintext
        let original = b"hello";
        let padded = pad_plaintext(original);
        assert_eq!(padded.len(), PADDED_PLAINTEXT_SIZE);
        let unpadded = unpad_plaintext(&padded).unwrap();
        assert_eq!(unpadded, original);

        // Empty plaintext
        let padded = pad_plaintext(b"");
        assert_eq!(padded.len(), PADDED_PLAINTEXT_SIZE);
        let unpadded = unpad_plaintext(&padded).unwrap();
        assert_eq!(unpadded, b"");

        // Max-length plaintext
        let max = vec![0x42u8; PADDED_PLAINTEXT_SIZE - 2];
        let padded = pad_plaintext(&max);
        assert_eq!(padded.len(), PADDED_PLAINTEXT_SIZE);
        let unpadded = unpad_plaintext(&padded).unwrap();
        assert_eq!(unpadded, &max[..]);
    }

    #[test]
    fn uniform_stealth_payload_size() {
        let (_secret, address) = generate_master_keys();

        // Two different plaintexts of very different sizes → same ciphertext size.
        let small = pad_plaintext(b"one bill");
        let large = pad_plaintext(&vec![0xAAu8; 512]);

        let p1 = prepare_stealth_payload_with_tag(&address, &small, b"pid1").unwrap();
        let p2 = prepare_stealth_payload_with_tag(&address, &large, b"pid2").unwrap();

        // The ciphertext portions should be identical in length.
        assert_eq!(p1.ciphertext.len(), p2.ciphertext.len());
        // All fixed fields should match in size too.
        assert_eq!(p1.ct_scan.len(), p2.ct_scan.len());
        assert_eq!(p1.ct_spend.len(), p2.ct_spend.len());
        assert_eq!(p1.nonce.len(), p2.nonce.len());
        assert_eq!(p1.stealth_id.len(), p2.stealth_id.len());
    }
}
