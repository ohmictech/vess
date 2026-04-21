//! Wallet recovery via 5 BIP39 words + 5-digit PIN → argon2id → deterministic keys.
//!
//! This implements Section J of the Vess protocol: human-memorable wallet
//! protection that is resistant to brute-force.
//!
//! # Derivation Flow
//!
//! 1. `passphrase = join(words, " ")`
//! 2. `salt = "vess-recovery-v0:" || PIN`
//! 3. `raw_seed = argon2id(passphrase, salt, t=4, m=2GiB, p=1)` → 64 bytes
//! 4. `enc_key = Blake3(raw_seed || "vess-wallet-enc-v0")` → 32 bytes (AEAD key)
//! 5. ML-KEM keypairs are derived deterministically from the raw seed via
//!    domain-separated Blake3 → ChaCha20Rng → `ml-kem::generate()`.
//! 6. The enc_key encrypts the ML-KEM secrets on disk for fast access.
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

/// Argon2id parameters per protocol spec Section J.
const ARGON2_T_COST: u32 = 4;
/// 2 GiB in KiB.
const ARGON2_M_COST: u32 = 2 * 1024 * 1024;
const ARGON2_P_COST: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 64;

/// Lighter Argon2id parameters for daily password-based unlock.
/// 256 MiB memory, 3 iterations — practical for mobile/embedded
/// while still resistant to GPU/ASIC brute-force (~1 s on modern HW).
const PWD_ARGON2_T_COST: u32 = 3;
const PWD_ARGON2_M_COST: u32 = 256 * 1024; // 256 MiB in KiB
const PWD_ARGON2_P_COST: u32 = 1;
const PWD_ARGON2_OUTPUT_LEN: usize = 32;

/// A wallet's recovery phrase: 5 BIP39 words + 5-digit PIN.
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryPhrase {
    pub words: [String; 5],
    pub pin: String,
}

impl RecoveryPhrase {
    /// Generate a new random recovery phrase.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let lang = bip39::Language::English;

        let words: [String; 5] = std::array::from_fn(|_| {
            let idx = rng.gen_range(0..2048);
            lang.word_list()[idx].to_string()
        });

        let pin_num: u32 = rng.gen_range(0..100_000);
        let pin = format!("{pin_num:05}");

        Self { words, pin }
    }

    /// Parse from user input.
    pub fn from_input(words_str: &str, pin: &str) -> Result<Self> {
        let parts: Vec<&str> = words_str.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(anyhow!("expected 5 words, got {}", parts.len()));
        }

        let wl = bip39::Language::English.word_list();
        for word in &parts {
            if !wl.contains(word) {
                return Err(anyhow!("unknown BIP39 word: {word}"));
            }
        }

        if pin.len() != 5 || !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err(anyhow!("PIN must be exactly 5 digits"));
        }

        Ok(Self {
            words: std::array::from_fn(|i| parts[i].to_string()),
            pin: pin.to_string(),
        })
    }

    /// Display the recovery phrase (for initial backup).
    pub fn display_phrase(&self) -> String {
        format!("{} | PIN: {}", self.words.join(" "), self.pin)
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
/// After initial wallet creation (which uses the heavy 2 GiB Argon2id
/// with the recovery phrase), the raw_seed is re-encrypted under a
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

/// Derive the 64-byte raw seed from a recovery phrase using argon2id.
///
/// This raw seed is the root from which all keys are derived:
/// - ML-KEM stealth keys (via domain-separated Blake3 + ChaCha20Rng)
/// - Wallet encryption key (via `Blake3(seed || "vess-wallet-enc-v0")`)
///
/// **Warning**: With production params this allocates 2 GiB.
pub fn derive_raw_seed(phrase: &RecoveryPhrase) -> Result<[u8; 64]> {
    derive_raw_seed_with_params(phrase, ARGON2_T_COST, ARGON2_M_COST, ARGON2_P_COST)
}

/// Derive raw seed with custom argon2id parameters (for testing).
pub fn derive_raw_seed_with_params(
    phrase: &RecoveryPhrase,
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u32,
) -> Result<[u8; 64]> {
    let passphrase = phrase.words.join(" ");
    let salt = format!("vess-recovery-v0:{}", phrase.pin);

    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(ARGON2_OUTPUT_LEN))
        .map_err(|e| anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut seed)
        .map_err(|e| anyhow!("argon2id failed: {e}"))?;

    Ok(seed)
}

/// Derive the 32-byte encryption key from a recovery phrase.
///
/// Uses argon2id with Section J parameters.
/// **Warning**: With production params this allocates 2 GiB.
pub fn derive_encryption_key(phrase: &RecoveryPhrase) -> Result<[u8; 32]> {
    derive_encryption_key_with_params(phrase, ARGON2_T_COST, ARGON2_M_COST, ARGON2_P_COST)
}

/// Derive encryption key with custom argon2id parameters (for testing).
pub fn derive_encryption_key_with_params(
    phrase: &RecoveryPhrase,
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u32,
) -> Result<[u8; 32]> {
    let seed = derive_raw_seed_with_params(phrase, t_cost, m_cost_kib, p_cost)?;
    Ok(encryption_key_from_seed(&seed))
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

/// Deterministically recover ML-KEM master keys from a recovery phrase.
///
/// This regenerates the exact same keypairs that were created during
/// wallet init — no wallet file or encrypted secrets needed.
pub fn recover_master_keys(
    phrase: &RecoveryPhrase,
) -> Result<(StealthSecretKey, MasterStealthAddress)> {
    recover_master_keys_with_params(phrase, ARGON2_T_COST, ARGON2_M_COST, ARGON2_P_COST)
}

/// Recover master keys with custom argon2id parameters (for testing).
pub fn recover_master_keys_with_params(
    phrase: &RecoveryPhrase,
    t_cost: u32,
    m_cost_kib: u32,
    p_cost: u32,
) -> Result<(StealthSecretKey, MasterStealthAddress)> {
    let seed = derive_raw_seed_with_params(phrase, t_cost, m_cost_kib, p_cost)?;
    Ok(vess_stealth::generate_master_keys_from_seed(&seed))
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
    let pwd_key =
        derive_key_from_password_with_params(password, &salt, t_cost, m_cost_kib, p_cost)?;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&pwd_key));
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
    let pwd_key =
        derive_key_from_password_with_params(password, &cache.salt, t_cost, m_cost_kib, p_cost)?;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&pwd_key));
    let nonce = GenericArray::from_slice(&cache.nonce);
    let plaintext = cipher
        .decrypt(nonce, cache.ciphertext.as_slice())
        .map_err(|_| anyhow!("wrong password or corrupted password cache"))?;

    let seed: [u8; 64] = plaintext
        .try_into()
        .map_err(|_| anyhow!("decrypted password cache has wrong length"))?;
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

    #[test]
    fn generate_recovery_phrase() {
        let phrase = RecoveryPhrase::generate();
        assert_eq!(phrase.words.len(), 5);
        assert_eq!(phrase.pin.len(), 5);
        assert!(phrase.pin.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn parse_recovery_phrase() {
        let phrase = RecoveryPhrase::from_input("abandon ability able about above", "12345");
        assert!(phrase.is_ok());
    }

    #[test]
    fn invalid_word_count_rejected() {
        let result = RecoveryPhrase::from_input("abandon ability", "12345");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_pin_rejected() {
        let result = RecoveryPhrase::from_input("abandon ability able about above", "123");
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
        assert!(display.contains("PIN:"));
        assert!(display.contains(&phrase.pin));
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

        let plaintext = b"VessBill from recovered keys";
        let payload = vess_stealth::prepare_stealth_payload(&address, plaintext).unwrap();
        assert!(vess_stealth::scan_view_tag(&secret, &payload.ct_scan, payload.view_tag).unwrap());
        let (decrypted, _sid) = vess_stealth::open_stealth_payload(&secret, &payload).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
