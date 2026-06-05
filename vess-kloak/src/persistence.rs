//! Wallet persistence — save/load encrypted wallet to disk.
//!
//! The wallet file contains:
//! - Encrypted ML-KEM secret keys (protected by recovery phrase).
//! - Public master stealth address (plaintext, for receiving).
//! - BillFold contents (bills are public after mint, but spend credentials are encrypted).
//! - Encrypted spend seed (protected by recovery-phrase-derived key).
//! - Encrypted spend credentials (ML-DSA-65 signing keys for each bill).
//! - Encrypted tag registrant signing key.
//! - Encrypted Bitcoin auto-burn state (address indexes, tracked UTXOs, pending burns).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

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
#[derive(Clone, Serialize, Deserialize)]
pub struct WalletFile {
    /// Format version for forward compatibility.
    pub version: u32,
    /// Optional user-facing local wallet VessTag name. Older single-wallet
    /// files do not contain this field and are shown as `default` by wallet
    /// discovery.
    #[serde(default)]
    pub name: Option<String>,
    /// The public master stealth address.
    pub master_address: MasterStealthAddress,
    /// Encrypted secret keys (requires recovery phrase to decrypt).
    pub encrypted_secrets: EncryptedSecrets,
    /// The billfold (bills are publicly visible post-mint, but spend
    /// credentials are stripped and stored encrypted separately).
    #[serde(default)]
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
    /// Persisted tag registration metadata so the wallet's tag can be
    /// re-announced after a node restart.
    #[serde(default)]
    pub tag_registration: Option<StoredTagRegistration>,

    /// Encrypted private wallet metadata: bill inventory, next DHT index,
    /// and persisted tag-registration replay state.
    #[serde(default)]
    pub encrypted_private_metadata: Option<EncryptedBlob>,

    /// Encrypted spend credentials (ML-DSA-65 signing keys for each bill).
    /// Keyed by mint_id, serialized via serde_json then AEAD-encrypted.
    #[serde(default)]
    pub encrypted_spend_credentials: Option<EncryptedBlob>,

    /// Encrypted Bitcoin auto-burn wallet state.
    /// Stores derived address indexes, tracked UTXOs, and pending burn retry state.
    #[serde(default)]
    pub encrypted_bitcoin_wallet_state: Option<EncryptedBlob>,

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

/// Persisted metadata for replaying a wallet tag registration.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredTagRegistration {
    /// Random 32-byte nonce used as salt for the Argon2id PoW.
    pub pow_nonce: [u8; 32],
    /// 32-byte Argon2id hash output proving the work.
    pub pow_hash: Vec<u8>,
    /// Unix timestamp of registration.
    pub registered_at: u64,
    /// ML-DSA-65 signature over the registration digest.
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct WalletPrivateMetadata {
    billfold: BillFold,
    next_dht_index: u64,
    tag_registration: Option<StoredTagRegistration>,
}

#[derive(Serialize, Deserialize)]
struct StoredSpendCredential {
    mint_id: [u8; 32],
    credential: crate::billfold::SpendCredential,
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
    pub const CURRENT_VERSION: u32 = 2;

    /// Create a new wallet file with encrypted spend seed.
    pub fn new(
        master_address: MasterStealthAddress,
        encrypted_secrets: EncryptedSecrets,
        billfold: BillFold,
        spend_seed: [u8; 32],
        enc_key: &[u8; 32],
    ) -> Result<Self> {
        let encrypted_spend_seed = Some(EncryptedSpendSeed::encrypt(&spend_seed, enc_key)?);
        let mut wallet = Self {
            version: Self::CURRENT_VERSION,
            name: None,
            master_address,
            encrypted_secrets,
            billfold,
            encrypted_spend_seed,
            spend_seed: [0u8; 32], // zeroed — never serialized (skip_serializing)
            next_dht_index: 0,
            tag_registrant_vk: Vec::new(),
            tag_registrant_sk: Vec::new(),
            encrypted_tag_sk: None,
            tag_registration: None,
            encrypted_private_metadata: None,
            encrypted_spend_credentials: None,
            encrypted_bitcoin_wallet_state: None,
            password_cache: None,
        };
        wallet.refresh_encrypted_private_metadata(enc_key)?;
        Ok(wallet)
    }

    /// Allocate the next DHT index and increment the counter.
    pub fn alloc_dht_index(&mut self) -> u64 {
        let idx = self.next_dht_index;
        self.next_dht_index += 1;
        idx
    }

    fn private_metadata(&self) -> WalletPrivateMetadata {
        WalletPrivateMetadata {
            billfold: self.billfold.clone(),
            next_dht_index: self.next_dht_index,
            tag_registration: self.tag_registration.clone(),
        }
    }

    fn refresh_encrypted_private_metadata(&mut self, enc_key: &[u8; 32]) -> Result<()> {
        let json = Zeroizing::new(
            serde_json::to_vec(&self.private_metadata()).context("serialize private wallet metadata")?,
        );
        self.encrypted_private_metadata = Some(EncryptedBlob::encrypt(json.as_slice(), enc_key)?);
        Ok(())
    }

    pub fn decrypt_private_metadata(&mut self, enc_key: &[u8; 32]) -> Result<()> {
        let Some(blob) = &self.encrypted_private_metadata else {
            return Ok(());
        };
        let json = Zeroizing::new(blob.decrypt(enc_key)?);
        let metadata: WalletPrivateMetadata =
            serde_json::from_slice(json.as_slice()).context("deserialize private wallet metadata")?;
        self.billfold = metadata.billfold;
        self.next_dht_index = metadata.next_dht_index;
        self.tag_registration = metadata.tag_registration;
        Ok(())
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
        let stored = creds
            .iter()
            .map(|(mint_id, credential)| StoredSpendCredential {
                mint_id: *mint_id,
                credential: crate::billfold::SpendCredential {
                    spend_vk: credential.spend_vk.clone(),
                    spend_sk: credential.spend_sk.clone(),
                },
            })
            .collect::<Vec<_>>();
        let json = Zeroizing::new(
            serde_json::to_vec(&stored).context("serialize spend credentials")?,
        );
        self.encrypted_spend_credentials = Some(EncryptedBlob::encrypt(json.as_slice(), enc_key)?);
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
            let json = Zeroizing::new(blob.decrypt(enc_key)?);
            let stored: Vec<StoredSpendCredential> =
                serde_json::from_slice(json.as_slice()).context("deserialize spend credentials")?;
            let creds = stored
                .into_iter()
                .map(|entry| (entry.mint_id, entry.credential))
                .collect::<std::collections::HashMap<_, _>>();
            billfold.import_credentials(creds);
        }
        // If no encrypted blob, the billfold may still have legacy plaintext
        // credentials from deserialization — those remain untouched.
        Ok(())
    }

    /// Encrypt and store opaque Bitcoin wallet state bytes.
    pub fn set_encrypted_bitcoin_wallet_state(
        &mut self,
        state_bytes: &[u8],
        enc_key: &[u8; 32],
    ) -> Result<()> {
        if state_bytes.is_empty() {
            self.encrypted_bitcoin_wallet_state = None;
        } else {
            self.encrypted_bitcoin_wallet_state =
                Some(EncryptedBlob::encrypt(state_bytes, enc_key)?);
        }
        Ok(())
    }

    /// Decrypt and return opaque Bitcoin wallet state bytes, if present.
    pub fn decrypt_bitcoin_wallet_state(&self, enc_key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        self.encrypted_bitcoin_wallet_state
            .as_ref()
            .map(|blob| blob.decrypt(enc_key))
            .transpose()
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

    /// Persist the metadata needed to replay this wallet's tag registration.
    pub fn set_tag_registration(
        &mut self,
        pow_nonce: [u8; 32],
        pow_hash: Vec<u8>,
        registered_at: u64,
        signature: Vec<u8>,
        enc_key: &[u8; 32],
    ) -> Result<()> {
        self.tag_registration = Some(StoredTagRegistration {
            pow_nonce,
            pow_hash,
            registered_at,
            signature,
        });
        self.refresh_encrypted_private_metadata(enc_key)
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
    pub fn save(&self, path: &Path, enc_key: &[u8; 32]) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create wallet directory: {}", parent.display()))?;
        }

        let mut serializable = self.clone();
        serializable.version = Self::CURRENT_VERSION;
        serializable.refresh_encrypted_private_metadata(enc_key)?;
        serializable.encrypt_spend_credentials(&self.billfold, enc_key)?;
        serializable.billfold = BillFold::new();
        serializable.next_dht_index = 0;
        serializable.tag_registration = None;

        let json = serde_json::to_string_pretty(&serializable).context("serialize wallet")?;

        write_wallet_file_atomically(path, json.as_bytes())?;

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
    pub fn backup(&self, backup_path: &Path, enc_key: &[u8; 32]) -> Result<()> {
        self.save(backup_path, enc_key)
    }
}

/// Default wallet file path: `~/.vess/wallet.json`.
pub fn default_wallet_path() -> Result<std::path::PathBuf> {
    let home = dirs_next().context("cannot determine home directory")?;
    Ok(home.join(".vess").join("wallet.json"))
}

/// Local Vess application directory: `~/.vess`.
pub fn wallet_storage_dir() -> Result<PathBuf> {
    let home = dirs_next().context("cannot determine home directory")?;
    Ok(home.join(".vess"))
}

/// Directory containing named local wallet files.
pub fn named_wallets_dir() -> Result<PathBuf> {
    Ok(wallet_storage_dir()?.join("wallets"))
}

/// Marker file storing the last successfully opened wallet path.
pub fn active_wallet_marker_path() -> Result<PathBuf> {
    Ok(wallet_storage_dir()?.join("active-wallet"))
}

/// One discovered local wallet object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletDescriptor {
    /// Display name shown to the user, normally the wallet's VessTag without `+`.
    pub name: String,
    /// Wallet JSON file path.
    pub path: PathBuf,
    /// True for the historical single-wallet path `~/.vess/wallet.json`.
    pub legacy_default: bool,
}

/// Convert a display wallet name or VessTag into a safe, stable filename stem.
pub fn sanitize_wallet_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        anyhow::bail!("wallet name cannot be empty");
    }

    let mut out = String::new();
    let mut last_dash = false;
    for ch in trimmed.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
        if out.len() >= 64 {
            break;
        }
    }

    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        anyhow::bail!("wallet name must contain at least one letter or number");
    }

    let reserved = [
        "con",
        "prn",
        "aux",
        "nul",
        "com1",
        "com2",
        "com3",
        "com4",
        "com5",
        "com6",
        "com7",
        "com8",
        "com9",
        "lpt1",
        "lpt2",
        "lpt3",
        "lpt4",
        "lpt5",
        "lpt6",
        "lpt7",
        "lpt8",
        "lpt9",
        "active-wallet",
    ];
    if reserved.contains(&out.as_str()) {
        anyhow::bail!("wallet name `{}` is reserved", trimmed);
    }

    Ok(out)
}

/// Path for a named local wallet object.
pub fn named_wallet_path(name: &str) -> Result<PathBuf> {
    let slug = sanitize_wallet_name(name)?;
    Ok(named_wallets_dir()?.join(format!("{slug}.json")))
}

/// List valid wallet objects stored locally, including the historical default.
pub fn list_wallets() -> Result<Vec<WalletDescriptor>> {
    let mut wallets = Vec::new();
    let mut seen = std::collections::HashSet::<PathBuf>::new();

    let legacy = default_wallet_path()?;
    if legacy.exists() {
        if let Ok(wallet) = WalletFile::load(&legacy) {
            let name = wallet
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| "default".to_string());
            seen.insert(legacy.clone());
            wallets.push(WalletDescriptor {
                name,
                path: legacy,
                legacy_default: true,
            });
        }
    }

    let dir = named_wallets_dir()?;
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("read wallet directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if seen.contains(&path) {
                continue;
            }
            let Ok(wallet) = WalletFile::load(&path) else {
                continue;
            };
            let name = wallet
                .name
                .filter(|name| !name.trim().is_empty())
                .or_else(|| {
                    path.file_stem()
                        .and_then(|stem| stem.to_str())
                        .map(|stem| stem.to_string())
                })
                .unwrap_or_else(|| "unnamed".to_string());
            seen.insert(path.clone());
            wallets.push(WalletDescriptor {
                name,
                path,
                legacy_default: false,
            });
        }
    }

    wallets.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(wallets)
}

/// Read the last successfully opened wallet path, ignoring stale markers.
pub fn read_active_wallet_path() -> Result<Option<PathBuf>> {
    let marker = active_wallet_marker_path()?;
    if !marker.exists() {
        return Ok(None);
    }
    let path = PathBuf::from(std::fs::read_to_string(&marker)?.trim());
    if path.as_os_str().is_empty() || !path.exists() {
        return Ok(None);
    }
    Ok(Some(path))
}

/// Persist the last successfully opened wallet path for non-interactive commands.
pub fn set_active_wallet_path(path: &Path) -> Result<()> {
    let marker = active_wallet_marker_path()?;
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create wallet directory: {}", parent.display()))?;
    }
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    std::fs::write(&marker, path.display().to_string())
        .with_context(|| format!("write active wallet marker: {}", marker.display()))?;
    Ok(())
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

fn write_wallet_file_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("wallet path has no parent directory"))?;
    let temp_name = format!(
        ".{}.tmp-{}-{}",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("wallet"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let temp_path = parent.join(temp_name);

    let write_result = (|| -> Result<()> {
        std::fs::write(&temp_path, contents)
            .with_context(|| format!("write wallet temp file: {}", temp_path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&temp_path, perms).with_context(|| {
                format!("set wallet temp permissions: {}", temp_path.display())
            })?;
        }

        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("remove existing wallet file: {}", path.display()))?;
        }
        std::fs::rename(&temp_path, path).with_context(|| {
            format!(
                "replace wallet file {} with {}",
                path.display(),
                temp_path.display()
            )
        })?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result
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

        wallet.save(&path, &enc_key).unwrap();
        let mut loaded = WalletFile::load(&path).unwrap();
        loaded.decrypt_private_metadata(&enc_key).unwrap();

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

        wallet.backup(&backup_path, &enc_key).unwrap();
        let mut loaded = WalletFile::load(&backup_path).unwrap();
        loaded.decrypt_private_metadata(&enc_key).unwrap();
        assert_eq!(loaded.version, WalletFile::CURRENT_VERSION);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_bitcoin_wallet_state_round_trip() {
        let (secret, address) = generate_master_keys();
        let phrase = RecoveryPhrase::generate();
        let enc_key = derive_encryption_key_with_params(&phrase, 1, 64, 1).unwrap();
        let encrypted = encrypt_secrets(&secret, &enc_key).unwrap();

        let mut wallet =
            WalletFile::new(address, encrypted, BillFold::new(), [0u8; 32], &enc_key).unwrap();
        let state_bytes = br#"{"next_external_index":1,"pending_burns":[]}"#;

        wallet
            .set_encrypted_bitcoin_wallet_state(state_bytes, &enc_key)
            .unwrap();

        let decrypted = wallet
            .decrypt_bitcoin_wallet_state(&enc_key)
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, state_bytes);
    }

    #[test]
    fn save_overwrites_existing_wallet_file() {
        let (secret, address) = generate_master_keys();
        let phrase = RecoveryPhrase::generate();
        let enc_key = derive_encryption_key_with_params(&phrase, 1, 64, 1).unwrap();
        let encrypted = encrypt_secrets(&secret, &enc_key).unwrap();

        let dir = std::env::temp_dir().join("vess-test-persistence-overwrite");
        let path = dir.join("wallet.json");

        let mut wallet =
            WalletFile::new(address, encrypted, BillFold::new(), [0u8; 32], &enc_key).unwrap();
        wallet.name = Some("first".to_string());
        wallet.save(&path, &enc_key).unwrap();

        wallet.name = Some("second".to_string());
        wallet.save(&path, &enc_key).unwrap();

        let loaded = WalletFile::load(&path).unwrap();
        assert_eq!(loaded.name.as_deref(), Some("second"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_persists_spend_credentials_from_billfold() {
        let (secret, address) = generate_master_keys();
        let phrase = RecoveryPhrase::generate();
        let enc_key = derive_encryption_key_with_params(&phrase, 1, 64, 1).unwrap();
        let encrypted = encrypt_secrets(&secret, &enc_key).unwrap();

        let mut billfold = BillFold::new();
        let bill = vess_foundry::VessBill {
            denomination: vess_foundry::Denomination::D10,
            digest: [0x11; 32],
            created_at: 1,
            stealth_id: [0x22; 32],
            dht_index: 7,
            mint_id: [0x33; 32],
            chain_tip: [0x44; 32],
            chain_depth: 0,
        };
        billfold.deposit_with_credentials(
            bill.clone(),
            crate::billfold::SpendCredential {
                spend_vk: vec![0x55; 64],
                spend_sk: vec![0x66; 64],
            },
        );

        let wallet = WalletFile::new(address, encrypted, billfold, [0u8; 32], &enc_key).unwrap();

        let dir = std::env::temp_dir().join("vess-test-persistence-creds");
        let path = dir.join("wallet.json");

        wallet.save(&path, &enc_key).unwrap();
        let mut loaded = WalletFile::load(&path).unwrap();
        loaded.decrypt_private_metadata(&enc_key).unwrap();
        let mut loaded_billfold = loaded.billfold.clone();
        loaded
            .decrypt_spend_credentials_into(&mut loaded_billfold, &enc_key)
            .unwrap();

        assert_eq!(loaded_billfold.balance(), 10);
        assert!(loaded_billfold.get_credentials(&bill.mint_id).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wallet_names_are_sanitized_for_filenames() {
        assert_eq!(
            sanitize_wallet_name("Personal Wallet").unwrap(),
            "personal-wallet"
        );
        assert_eq!(sanitize_wallet_name("+alice").unwrap(), "alice");
        assert_eq!(sanitize_wallet_name("  Alice/BTC  ").unwrap(), "alice-btc");
        assert!(sanitize_wallet_name("   ").is_err());
        assert!(sanitize_wallet_name("CON").is_err());
    }
}
