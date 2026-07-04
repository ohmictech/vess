//! Wallet recovery via a standard 12-word BIP39 mnemonic → deterministic keys.
//!
//! This implements Section J of the Vess protocol: human-memorable wallet
//! recovery with checksum-validated BIP39 words.
//!
//! # Derivation Flow
//!
//! 1. `mnemonic = 12 English BIP39 words` (128 bits entropy + checksum)
//! 2. `raw_seed = BIP39 PBKDF2-HMAC-SHA512(mnemonic, passphrase="")` → 64 bytes
//! 3. `enc_key = Blake3(raw_seed || "vess-wallet-enc-v0")` → 32 bytes (AEAD key)
//! 4. ML-KEM keypairs are derived deterministically from the raw seed via
//!    domain-separated Blake3 → ChaCha20Rng → `ml-kem::generate()`.
//! 5. The enc_key encrypts the ML-KEM secrets on disk for fast access.
//!
//! # Recovery Scenario
//!
//! Since ML-KEM keys are deterministically derived from the recovery phrase,
//! a wallet can be fully regenerated from the phrase alone — no wallet file
//! is needed. `recover_master_keys` re-derives the raw seed and regenerates
//! the exact same keypairs.

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};
use vess_stealth::{MasterStealthAddress, StealthSecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Standard BIP39 wallet recovery phrase length.
pub const RECOVERY_WORD_COUNT: usize = 12;

/// Lighter Argon2id parameters for daily password-based unlock.
/// 256 MiB memory, 3 iterations — practical for mobile/embedded
/// while still resistant to GPU/ASIC brute-force (~1 s on modern HW).
const PWD_ARGON2_T_COST: u32 = 3;
const PWD_ARGON2_M_COST: u32 = 256 * 1024; // 256 MiB in KiB
const PWD_ARGON2_P_COST: u32 = 1;
const PWD_ARGON2_OUTPUT_LEN: usize = 32;

/// A wallet's recovery phrase: a checksum-validated 12-word English BIP39 mnemonic.
#[derive(Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryPhrase {
    pub words: [String; RECOVERY_WORD_COUNT],
}

impl std::fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryPhrase(<redacted>)")
    }
}

impl RecoveryPhrase {
    /// Generate a new random recovery phrase.
    pub fn generate() -> Self {
        use rand::RngCore;

        let mut entropy = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut entropy);
        let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
            .expect("16 bytes of entropy always yields a valid 12-word BIP39 mnemonic");

        Self::from_mnemonic(mnemonic).expect("generated BIP39 mnemonic should always have 12 words")
    }

    /// Parse from user input.
    pub fn from_input(words_str: &str) -> Result<Self> {
        let normalized = words_str
            .split_whitespace()
            .map(|word| word.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(" ");
        let word_count = normalized.split_whitespace().count();
        if word_count != RECOVERY_WORD_COUNT {
            return Err(anyhow!(
                "expected {RECOVERY_WORD_COUNT} words, got {word_count}"
            ));
        }

        let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, normalized)
            .map_err(|e| anyhow!("invalid 12-word BIP39 recovery phrase: {e}"))?;
        Self::from_mnemonic(mnemonic)
    }

    /// Display the recovery phrase (for initial backup).
    pub fn display_phrase(&self) -> String {
        self.words.join(" ")
    }

    fn from_mnemonic(mnemonic: bip39::Mnemonic) -> Result<Self> {
        let words = mnemonic
            .words()
            .map(str::to_string)
            .collect::<Vec<String>>();
        let word_count = words.len();
        let words = words
            .try_into()
            .map_err(|_| anyhow!("expected {RECOVERY_WORD_COUNT} BIP39 words, got {word_count}"))?;
        Ok(Self { words })
    }

    fn to_mnemonic(&self) -> Result<bip39::Mnemonic> {
        bip39::Mnemonic::parse_in(bip39::Language::English, self.display_phrase())
            .map_err(|e| anyhow!("invalid 12-word BIP39 recovery phrase: {e}"))
    }
}

/// Encrypted wallet secrets stored on disk.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedSecrets {
    /// AEAD-encrypted scan decapsulation key.
    pub scan_dk_ct: Vec<u8>,
    /// AEAD nonce for scan key.
    pub scan_dk_nonce: [u8; 12],
    /// AEAD-encrypted spend decapsulation key.
    pub spend_dk_ct: Vec<u8>,
    /// AEAD nonce for spend key.
    pub spend_dk_nonce: [u8; 12],
}

/// Password-encrypted copy of the 64-byte raw seed (xPriv).
///
/// After initial wallet creation (which uses the BIP39 mnemonic to derive
/// the recovery seed), the raw_seed is re-encrypted under a
/// user-chosen password with lighter KDF parameters (256 MiB, ~1 s).
/// On unlock the raw_seed is decrypted and all keys are derived from
/// it instantly (Blake3 + ML-KEM keygen) — no further decryption needed.
#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordCache {
    /// Random 16-byte salt for the password KDF.
    pub salt: [u8; 16],
    /// AEAD-encrypted 64-byte raw seed.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; 12],
}

/// Derive the 64-byte raw seed from a standard 12-word BIP39 recovery phrase.
///
/// This raw seed is the root from which all keys are derived:
/// - ML-KEM stealth keys (via domain-separated Blake3 + ChaCha20Rng)
/// - Wallet encryption key (via `Blake3(seed || "vess-wallet-enc-v0")`)
pub fn derive_raw_seed(phrase: &RecoveryPhrase) -> Result<[u8; 64]> {
    Ok(phrase.to_mnemonic()?.to_seed(""))
}

/// Compatibility wrapper retained for older callers/tests.
///
/// Standard 12-word BIP39 recovery no longer uses Argon2id, so the
/// parameters are ignored.
pub fn derive_raw_seed_with_params(
    phrase: &RecoveryPhrase,
    _t_cost: u32,
    _m_cost_kib: u32,
    _p_cost: u32,
) -> Result<[u8; 64]> {
    derive_raw_seed(phrase)
}

/// Derive the 32-byte encryption key from a recovery phrase.
pub fn derive_encryption_key(phrase: &RecoveryPhrase) -> Result<[u8; 32]> {
    let seed = derive_raw_seed(phrase)?;
    Ok(encryption_key_from_seed(&seed))
}

/// Compatibility wrapper retained for older callers/tests.
///
/// Standard 12-word BIP39 recovery no longer uses Argon2id, so the
/// parameters are ignored.
pub fn derive_encryption_key_with_params(
    phrase: &RecoveryPhrase,
    _t_cost: u32,
    _m_cost_kib: u32,
    _p_cost: u32,
) -> Result<[u8; 32]> {
    derive_encryption_key(phrase)
}

/// Derive the encryption key from a raw seed (no argon2).
pub fn encryption_key_from_seed(seed: &[u8; 64]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(seed);
    h.update(b"vess-wallet-enc-v0");
    *h.finalize().as_bytes()
}

/// Derive the 32-byte spend seed from a raw seed (no argon2).
///
/// The spend seed is used for deterministic DHT key derivation and
/// bill sealing. It is domain-separated from the encryption key.
pub fn spend_seed_from_raw_seed(seed: &[u8; 64]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(seed);
    h.update(b"vess-spend-seed-v0");
    *h.finalize().as_bytes()
}

/// Derive a 32-byte Ethereum private key from a raw seed.
///
/// Domain-separated so the ETH key is independent from the encryption
/// key and spend seed. The same BIP39 phrase always produces the same
/// Ethereum address, making it recoverable without the wallet file.
pub fn eth_key_from_raw_seed(seed: &[u8; 64]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(seed);
    h.update(b"vess-eth-key-v0");
    *h.finalize().as_bytes()
}

/// Deterministically recover ML-KEM master keys from a recovery phrase.
///
/// This regenerates the exact same keypairs that were created during
/// wallet init — no wallet file or encrypted secrets needed.
pub fn recover_master_keys(
    phrase: &RecoveryPhrase,
) -> Result<(StealthSecretKey, MasterStealthAddress)> {
    let seed = derive_raw_seed(phrase)?;
    Ok(vess_stealth::generate_master_keys_from_seed(&seed))
}

/// Compatibility wrapper retained for older callers/tests.
///
/// Standard 12-word BIP39 recovery no longer uses Argon2id, so the
/// parameters are ignored.
pub fn recover_master_keys_with_params(
    phrase: &RecoveryPhrase,
    _t_cost: u32,
    _m_cost_kib: u32,
    _p_cost: u32,
) -> Result<(StealthSecretKey, MasterStealthAddress)> {
    recover_master_keys(phrase)
}

/// Encrypt wallet secret keys with a recovery-derived key.
pub fn encrypt_secrets(secret: &StealthSecretKey, enc_key: &[u8; 32]) -> Result<EncryptedSecrets> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(enc_key));

    let scan_nonce_bytes = random_nonce();
    let scan_nonce = GenericArray::from_slice(&scan_nonce_bytes);
    let scan_dk_ct = cipher
        .encrypt(scan_nonce, secret.scan_dk.as_slice())
        .map_err(|e| anyhow!("encrypt scan key: {e}"))?;

    let spend_nonce_bytes = random_nonce();
    let spend_nonce = GenericArray::from_slice(&spend_nonce_bytes);
    let spend_dk_ct = cipher
        .encrypt(spend_nonce, secret.spend_dk.as_slice())
        .map_err(|e| anyhow!("encrypt spend key: {e}"))?;

    Ok(EncryptedSecrets {
        scan_dk_ct,
        scan_dk_nonce: scan_nonce_bytes,
        spend_dk_ct,
        spend_dk_nonce: spend_nonce_bytes,
    })
}

/// Decrypt wallet secret keys with a recovery-derived key.
pub fn decrypt_secrets(
    encrypted: &EncryptedSecrets,
    enc_key: &[u8; 32],
) -> Result<StealthSecretKey> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(enc_key));

    let scan_nonce = GenericArray::from_slice(&encrypted.scan_dk_nonce);
    let scan_dk = cipher
        .decrypt(scan_nonce, encrypted.scan_dk_ct.as_slice())
        .map_err(|_| anyhow!("decrypt scan key failed — wrong passphrase or corrupted"))?;

    let spend_nonce = GenericArray::from_slice(&encrypted.spend_dk_nonce);
    let spend_dk = cipher
        .decrypt(spend_nonce, encrypted.spend_dk_ct.as_slice())
        .map_err(|_| anyhow!("decrypt spend key failed — wrong passphrase or corrupted"))?;

    Ok(StealthSecretKey { scan_dk, spend_dk })
}

// ── Password-based fast unlock ──────────────────────────────────────

/// Derive a 32-byte key from a password and salt using lighter Argon2id.
pub fn derive_key_from_password(password: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
    derive_key_from_password_with_params(
        password,
        salt,
        PWD_ARGON2_T_COST,
        PWD_ARGON2_M_COST,
        PWD_ARGON2_P_COST,
    )
}

/// Derive key from password with custom Argon2id parameters (for testing).
pub fn derive_key_from_password_with_params(
    password: &str,
    salt: &[u8; 16],
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(PWD_ARGON2_OUTPUT_LEN))
        .map_err(|e| anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2id password KDF failed: {e}"))?;
    Ok(key)
}

/// Create a password cache by encrypting the raw_seed under a password.
pub fn create_password_cache(raw_seed: &[u8; 64], password: &str) -> Result<PasswordCache> {
    create_password_cache_with_params(
        raw_seed,
        password,
        PWD_ARGON2_T_COST,
        PWD_ARGON2_M_COST,
        PWD_ARGON2_P_COST,
    )
}

/// Create a password cache with custom Argon2id parameters (for testing).
pub fn create_password_cache_with_params(
    raw_seed: &[u8; 64],
    password: &str,
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u32,
) -> Result<PasswordCache> {
    use rand::Rng;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill(&mut salt);
    let pwd_key = Zeroizing::new(derive_key_from_password_with_params(
        password,
        &salt,
        t_cost,
        m_cost_kib,
        p_cost,
    )?);

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(pwd_key.as_ref()));
    let nonce_bytes = random_nonce();
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, raw_seed.as_slice())
        .map_err(|e| anyhow!("password cache encryption failed: {e}"))?;

    Ok(PasswordCache {
        salt,
        ciphertext,
        nonce: nonce_bytes,
    })
}

/// Decrypt the raw_seed from a password cache.
pub fn decrypt_password_cache(cache: &PasswordCache, password: &str) -> Result<[u8; 64]> {
    decrypt_password_cache_with_params(
        cache,
        password,
        PWD_ARGON2_T_COST,
        PWD_ARGON2_M_COST,
        PWD_ARGON2_P_COST,
    )
}

/// Decrypt the raw_seed from a password cache with custom params (for testing).
pub fn decrypt_password_cache_with_params(
    cache: &PasswordCache,
    password: &str,
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u32,
) -> Result<[u8; 64]> {
    let pwd_key = Zeroizing::new(derive_key_from_password_with_params(
        password,
        &cache.salt,
        t_cost,
        m_cost_kib,
        p_cost,
    )?);

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(pwd_key.as_ref()));
    let nonce = GenericArray::from_slice(&cache.nonce);
    let plaintext = Zeroizing::new(cipher
        .decrypt(nonce, cache.ciphertext.as_slice())
        .map_err(|_| anyhow!("wrong password or corrupted password cache"))?);

    let mut seed = [0u8; 64];
    if plaintext.len() != seed.len() {
        return Err(anyhow!("decrypted password cache has wrong length"));
    }
    seed.copy_from_slice(plaintext.as_slice());
    Ok(seed)
}

fn random_nonce() -> [u8; 12] {
    use rand::Rng;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_stealth::generate_master_keys;

    const VALID_12_WORDS: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn generate_recovery_phrase() {
        let phrase = RecoveryPhrase::generate();
        assert_eq!(phrase.words.len(), RECOVERY_WORD_COUNT);
        assert!(RecoveryPhrase::from_input(&phrase.display_phrase()).is_ok());
    }

    #[test]
    fn parse_recovery_phrase() {
        let phrase = RecoveryPhrase::from_input(VALID_12_WORDS);
        assert!(phrase.is_ok());
    }

    #[test]
    fn invalid_word_count_rejected() {
        let result = RecoveryPhrase::from_input("abandon ability");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_checksum_rejected() {
        let result = RecoveryPhrase::from_input(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        );
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let (secret, _addr) = generate_master_keys();
        let phrase = RecoveryPhrase::generate();

        // Use small params for testing.
        let enc_key = derive_encryption_key_with_params(&phrase, 1, 64, 1).unwrap();

        let encrypted = encrypt_secrets(&secret, &enc_key).unwrap();
        let decrypted = decrypt_secrets(&encrypted, &enc_key).unwrap();

        assert_eq!(secret.scan_dk, decrypted.scan_dk);
        assert_eq!(secret.spend_dk, decrypted.spend_dk);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let (secret, _addr) = generate_master_keys();
        let phrase1 = RecoveryPhrase::generate();
        let phrase2 = RecoveryPhrase::generate();

        let enc_key1 = derive_encryption_key_with_params(&phrase1, 1, 64, 1).unwrap();
        let enc_key2 = derive_encryption_key_with_params(&phrase2, 1, 64, 1).unwrap();

        let encrypted = encrypt_secrets(&secret, &enc_key1).unwrap();
        let result = decrypt_secrets(&encrypted, &enc_key2);

        assert!(result.is_err());
    }

    #[test]
    fn display_phrase_format() {
        let phrase = RecoveryPhrase::generate();
        let display = phrase.display_phrase();
        assert_eq!(display.split_whitespace().count(), RECOVERY_WORD_COUNT);
        assert!(!display.contains("PIN:"));
        assert_eq!(RecoveryPhrase::from_input(&display).unwrap(), phrase);
    }

    #[test]
    fn raw_seed_matches_standard_bip39_seed() {
        let phrase = RecoveryPhrase::from_input(VALID_12_WORDS).unwrap();
        let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, VALID_12_WORDS).unwrap();
        assert_eq!(derive_raw_seed(&phrase).unwrap(), mnemonic.to_seed(""));
    }

    #[test]
    fn deterministic_recovery_produces_same_keys() {
        let phrase = RecoveryPhrase::generate();

        // Derive keys twice from the same phrase.
        let (sec1, addr1) = recover_master_keys_with_params(&phrase, 1, 64, 1).unwrap();
        let (sec2, addr2) = recover_master_keys_with_params(&phrase, 1, 64, 1).unwrap();

        assert_eq!(sec1.scan_dk, sec2.scan_dk);
        assert_eq!(sec1.spend_dk, sec2.spend_dk);
        assert_eq!(addr1.scan_ek, addr2.scan_ek);
        assert_eq!(addr1.spend_ek, addr2.spend_ek);
    }

    #[test]
    fn different_phrases_produce_different_keys() {
        let phrase1 = RecoveryPhrase::generate();
        let phrase2 = RecoveryPhrase::generate();

        let (_sec1, addr1) = recover_master_keys_with_params(&phrase1, 1, 64, 1).unwrap();
        let (_sec2, addr2) = recover_master_keys_with_params(&phrase2, 1, 64, 1).unwrap();

        assert_ne!(addr1.scan_ek, addr2.scan_ek);
    }

    #[test]
    fn recovered_keys_work_for_stealth() {
        let phrase = RecoveryPhrase::generate();
        let (secret, address) = recover_master_keys_with_params(&phrase, 1, 64, 1).unwrap();

        let plaintext = b"Vess from recovered keys";
        let payload = vess_stealth::prepare_stealth_payload(&address, plaintext).unwrap();
        assert!(vess_stealth::scan_view_tag(&secret, &payload.ct_scan, payload.view_tag).unwrap());
        let (decrypted, _sid, _rk) = vess_stealth::open_stealth_payload(&secret, &payload).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
