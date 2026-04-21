//! Wallet persistence — save/load encrypted wallet to disk.
//!
//! The wallet file contains:
//! - Encrypted ML-KEM secret keys (protected by recovery phrase).
//! - Public master stealth address (plaintext, for receiving).
//! - BillFold contents (bills are public after mint, but spend credentials are encrypted).
//! - Encrypted spend seed (protected by recovery-phrase-derived key).
//! - Encrypted spend credentials (ML-DSA-65 signing keys for each bill).
//! - Encrypted tag registrant signing key.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::billfold::BillFold;

use crate::recovery::EncryptedSecrets;
use vess_stealth::MasterStealthAddress;

/// Generic AEAD-encrypted blob (ChaCha20-Poly1305).
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

impl EncryptedBlob {
    /// Encrypt arbitrary bytes under a 32-byte key.
    pub fn encrypt(plaintext: &[u8], enc_key: &[u8; 32]) -> Result<Self> {
        use chacha20poly1305::{
            aead::{generic_array::GenericArray, Aead, KeyInit},
            ChaCha20Poly1305,
        };
        use rand::RngCore;

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(enc_key));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt to raw bytes.
    pub fn decrypt(&self, enc_key: &[u8; 32]) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{generic_array::GenericArray, Aead, KeyInit},
            ChaCha20Poly1305,
        };

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(enc_key));
        let nonce = GenericArray::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| anyhow::anyhow!("decryption failed (wrong key?): {e}"))
    }
}

/// On-disk wallet file format.
#[derive(Serialize, Deserialize)]
pub struct WalletFile {
    /// Format version for forward compatibility.
    pub version: u32,
    /// The public master stealth address.
    pub master_address: MasterStealthAddress,
    /// Encrypted secret keys (requires recovery phrase to decrypt).
    pub encrypted_secrets: EncryptedSecrets,
    /// The billfold (bills are publicly visible post-mint, but spend
    /// credentials are stripped and stored encrypted separately).
    pub billfold: BillFold,
    /// Encrypted spend seed (ChaCha20-Poly1305, keyed from recovery phrase).
    /// Replaces the old plaintext `spend_seed` field.
    #[serde(default)]
    pub encrypted_spend_seed: Option<EncryptedSpendSeed>,
    /// Legacy plaintext spend seed — only used for migration from v1 wallets.
    /// New wallets always use `encrypted_spend_seed`.
    #[serde(default, skip_serializing)]
    pub spend_seed: [u8; 32],
    /// Next DHT index to assign to a newly minted/reforged bill.
    #[serde(default)]
    pub next_dht_index: u64,

    /// ML-DSA-65 verification key used for VessTag registration (public).
    #[serde(default)]
    pub tag_registrant_vk: Vec<u8>,
    /// Legacy plaintext tag signing key — only read for migration.
    #[serde(default, skip_serializing)]
    pub tag_registrant_sk: Vec<u8>,
    /// Encrypted ML-DSA-65 tag signing key.
    #[serde(default)]
    pub encrypted_tag_sk: Option<EncryptedBlob>,

    /// Encrypted spend credentials (ML-DSA-65 signing keys for each bill).
    /// Keyed by mint_id, serialized via serde_json then AEAD-encrypted.
    #[serde(default)]
    pub encrypted_spend_credentials: Option<EncryptedBlob>,

    /// Password-encrypted copy of the encryption key for fast daily unlock.
    /// Set via `vess init --password` or `vess set-password`.
    #[serde(default)]
    pub password_cache: Option<crate::recovery::PasswordCache>,
}

/// Encrypted spend seed stored on disk.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedSpendSeed {
    /// AEAD ciphertext of the 32-byte spend seed.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; 12],
}

impl EncryptedSpendSeed {
    /// Encrypt a spend seed with the given 32-byte key.
    pub fn encrypt(spend_seed: &[u8; 32], enc_key: &[u8; 32]) -> Result<Self> {
        use chacha20poly1305::{
            aead::{generic_array::GenericArray, Aead, KeyInit},
            ChaCha20Poly1305,
        };
        use rand::RngCore;

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(enc_key));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, spend_seed.as_slice())
            .map_err(|e| anyhow::anyhow!("spend seed encryption failed: {e}"))?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt the spend seed with the given 32-byte key.
    pub fn decrypt(&self, enc_key: &[u8; 32]) -> Result<[u8; 32]> {
        use chacha20poly1305::{
            aead::{generic_array::GenericArray, Aead, KeyInit},
            ChaCha20Poly1305,
        };

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(enc_key));
        let nonce = GenericArray::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|e| anyhow::anyhow!("spend seed decryption failed (wrong key?): {e}"))?;

        let seed: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| anyhow::anyhow!("decrypted spend seed has wrong length"))?;
        Ok(seed)
    }
}

impl WalletFile {
    /// Current file format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a new wallet file with encrypted spend seed.
    pub fn new(
        master_address: MasterStealthAddress,
        encrypted_secrets: EncryptedSecrets,
        billfold: BillFold,
        spend_seed: [u8; 32],
        enc_key: &[u8; 32],
    ) -> Result<Self> {
        let encrypted_spend_seed = Some(EncryptedSpendSeed::encrypt(&spend_seed, enc_key)?);
        Ok(Self {
            version: Self::CURRENT_VERSION,
            master_address,
            encrypted_secrets,
            billfold,
            encrypted_spend_seed,
            spend_seed: [0u8; 32], // zeroed — never serialized (skip_serializing)
            next_dht_index: 0,
            tag_registrant_vk: Vec::new(),
            tag_registrant_sk: Vec::new(),
            encrypted_tag_sk: None,
            encrypted_spend_credentials: None,
            password_cache: None,
        })
    }

    /// Allocate the next DHT index and increment the counter.
    pub fn alloc_dht_index(&mut self) -> u64 {
        let idx = self.next_dht_index;
        self.next_dht_index += 1;
        idx
    }

    /// Decrypt and return the spend seed.
    ///
    /// Handles migration: if the wallet has the legacy plaintext field,
    /// returns it directly; otherwise decrypts `encrypted_spend_seed`.
    pub fn decrypt_spend_seed(&self, enc_key: &[u8; 32]) -> Result<[u8; 32]> {
        if let Some(ref ess) = self.encrypted_spend_seed {
            ess.decrypt(enc_key)
        } else if self.spend_seed != [0u8; 32] {
            // Legacy v1 wallet with plaintext spend_seed.
            Ok(self.spend_seed)
        } else {
            anyhow::bail!("wallet has no spend seed (encrypted or plaintext)")
        }
    }

    // ── Spend credential encryption ─────────────────────────────

    /// Encrypt the billfold's spend credentials and store in the wallet.
    pub fn encrypt_spend_credentials(
        &mut self,
        billfold: &BillFold,
        enc_key: &[u8; 32],
    ) -> Result<()> {
        let creds = billfold.export_credentials();
        if creds.is_empty() {
            self.encrypted_spend_credentials = None;
            return Ok(());
        }
        let json = serde_json::to_vec(creds).context("serialize spend credentials")?;
        self.encrypted_spend_credentials = Some(EncryptedBlob::encrypt(&json, enc_key)?);
        Ok(())
    }

    /// Decrypt spend credentials and import them into the billfold.
    ///
    /// Handles migration: if the billfold already has legacy plaintext
    /// credentials (from an old wallet), those are preserved.
    pub fn decrypt_spend_credentials_into(
        &self,
        billfold: &mut BillFold,
        enc_key: &[u8; 32],
    ) -> Result<()> {
        if let Some(ref blob) = self.encrypted_spend_credentials {
            let json = blob.decrypt(enc_key)?;
            let creds: std::collections::HashMap<[u8; 32], crate::billfold::SpendCredential> =
                serde_json::from_slice(&json).context("deserialize spend credentials")?;
            billfold.import_credentials(creds);
        }
        // If no encrypted blob, the billfold may still have legacy plaintext
        // credentials from deserialization — those remain untouched.
        Ok(())
    }

    // ── Tag key encryption ──────────────────────────────────────

    /// Encrypt and store the tag registrant signing key.
    pub fn set_encrypted_tag_sk(&mut self, sk: &[u8], enc_key: &[u8; 32]) -> Result<()> {
        self.encrypted_tag_sk = Some(EncryptedBlob::encrypt(sk, enc_key)?);
        // Clear any legacy plaintext (not serialized, but zero in memory).
        self.tag_registrant_sk = Vec::new();
        Ok(())
    }

    /// Decrypt the tag registrant signing key.
    ///
    /// Handles migration: returns the legacy plaintext key if no encrypted
    /// version exists yet.
    pub fn decrypt_tag_sk(&self, enc_key: &[u8; 32]) -> Result<Vec<u8>> {
        if let Some(ref blob) = self.encrypted_tag_sk {
            blob.decrypt(enc_key)
        } else if !self.tag_registrant_sk.is_empty() {
            // Legacy wallet with plaintext tag SK.
            Ok(self.tag_registrant_sk.clone())
        } else {
            anyhow::bail!("no tag registrant signing key (encrypted or plaintext)")
        }
    }

    /// Set (or replace) the password cache for fast daily unlock.
    ///
    /// The `raw_seed` is the 64-byte root key derived from the recovery
    /// phrase via Argon2id.  It gets re-encrypted under `password` with
    /// lighter Argon2id parameters so the user only needs the password
    /// for day-to-day operation.  On unlock the raw_seed is decrypted
    /// and all keys are derived from it instantly.
    pub fn set_password_cache(&mut self, raw_seed: &[u8; 64], password: &str) -> Result<()> {
        self.password_cache = Some(crate::recovery::create_password_cache(raw_seed, password)?);
        Ok(())
    }

    /// Set password cache with custom Argon2id parameters (for testing).
    pub fn set_password_cache_with_params(
        &mut self,
        raw_seed: &[u8; 64],
        password: &str,
        t_cost: u32,
        m_cost_kib: u32,
        p_cost: u32,
    ) -> Result<()> {
        self.password_cache = Some(crate::recovery::create_password_cache_with_params(
            raw_seed, password, t_cost, m_cost_kib, p_cost,
        )?);
        Ok(())
    }

    /// Unlock the wallet using a password (fast daily unlock).
    ///
    /// Returns the 64-byte raw seed from which all keys can be derived:
    /// - `encryption_key_from_seed()` → enc_key for legacy decrypt
    /// - `spend_seed_from_raw_seed()` → spend_seed
    /// - `generate_master_keys_from_seed()` → stealth keypairs
    pub fn unlock_with_password(&self, password: &str) -> Result<[u8; 64]> {
        match &self.password_cache {
            Some(cache) => crate::recovery::decrypt_password_cache(cache, password),
            None => anyhow::bail!(
                "no password set on this wallet — use recovery phrase or run set-password first"
            ),
        }
    }

    /// Save wallet to a JSON file with restrictive permissions.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create wallet directory: {}", parent.display()))?;
        }

        let json = serde_json::to_string_pretty(self).context("serialize wallet")?;

        std::fs::write(path, json.as_bytes())
            .with_context(|| format!("write wallet file: {}", path.display()))?;

        // Restrict file permissions (Unix: owner-only read/write).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("set wallet permissions: {}", path.display()))?;
        }

        Ok(())
    }

    /// Load wallet from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let data =
            std::fs::read(path).with_context(|| format!("read wallet file: {}", path.display()))?;

        let wallet: WalletFile = serde_json::from_slice(&data).context("deserialize wallet")?;

        if wallet.version > Self::CURRENT_VERSION {
            anyhow::bail!(
                "wallet file version {} is newer than supported ({})",
                wallet.version,
                Self::CURRENT_VERSION
            );
        }

        Ok(wallet)
    }

    /// Create a backup copy of the wallet at the given path.
    pub fn backup(&self, backup_path: &Path) -> Result<()> {
        self.save(backup_path)
    }
}

/// Default wallet file path: `~/.vess/wallet.json`.
pub fn default_wallet_path() -> Result<std::path::PathBuf> {
    let home = dirs_next().context("cannot determine home directory")?;
    Ok(home.join(".vess").join("wallet.json"))
}

fn dirs_next() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("USERPROFILE").map(std::path::PathBuf::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var_os("HOME").map(std::path::PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{derive_encryption_key_with_params, encrypt_secrets, RecoveryPhrase};
    use vess_stealth::generate_master_keys;

    #[test]
    fn save_and_load_round_trip() {
        let (secret, address) = generate_master_keys();
        let phrase = RecoveryPhrase::generate();
        let enc_key = derive_encryption_key_with_params(&phrase, 1, 64, 1).unwrap();
        let encrypted = encrypt_secrets(&secret, &enc_key).unwrap();

        let wallet =
            WalletFile::new(address, encrypted, BillFold::new(), [0u8; 32], &enc_key).unwrap();

        let dir = std::env::temp_dir().join("vess-test-persistence");
        let path = dir.join("wallet.json");

        wallet.save(&path).unwrap();
        let loaded = WalletFile::load(&path).unwrap();

        assert_eq!(loaded.version, WalletFile::CURRENT_VERSION);
        assert_eq!(loaded.billfold.balance(), 0);

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_creates_copy() {
        let (secret, address) = generate_master_keys();
        let phrase = RecoveryPhrase::generate();
        let enc_key = derive_encryption_key_with_params(&phrase, 1, 64, 1).unwrap();
        let encrypted = encrypt_secrets(&secret, &enc_key).unwrap();

        let wallet =
            WalletFile::new(address, encrypted, BillFold::new(), [0u8; 32], &enc_key).unwrap();

        let dir = std::env::temp_dir().join("vess-test-backup");
        let backup_path = dir.join("backup.json");

        wallet.backup(&backup_path).unwrap();
        let loaded = WalletFile::load(&backup_path).unwrap();
        assert_eq!(loaded.version, WalletFile::CURRENT_VERSION);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
