//! Keyfile encryption: Argon2id over the passphrase, then ChaCha20-Poly1305 over the seed.
//!
//! Two formats exist and both are read; only the encrypted one is ever written unless the caller
//! explicitly asks for a plaintext keyfile.
//!
//! ```text
//! v1 (legacy, plaintext)        v2 (encrypted)                v3 (encrypted, kinded)
//! ----------------------        ----------------------        ----------------------
//! u16 version = 1               u16 version = 2               u16 version = 3
//! u8  network                   u8  network                   u8  network
//! [u8; 32] seed                 u8  kdf = 1 (Argon2id)        u8  kind (0 single, 1 hd)
//!                               u32 m_cost_kib                u8  kdf = 1 (Argon2id)
//!                               u32 t_cost                    u32 m_cost_kib
//!                               u32 p_cost                    u32 t_cost
//!                               [u8; 16] salt                 u32 p_cost
//!                               [u8; 12] nonce                [u8; 16] salt
//!                               [u8; 32] ct || [u8; 16] tag   [u8; 12] nonce
//!                                                             [u8; 32] ct || [u8; 16] tag
//! ```
//!
//! `kind` says what the 32 plaintext bytes mean: with `Single` they are an ML-DSA seed and the file
//! describes exactly one account (every v1 and v2 file is this); with `Hd` they are a master seed
//! from which accounts are derived by index.
//!
//! The associated data for the AEAD is the whole header (version through salt), so the parameters
//! cannot be changed to weaken an existing file without the tag failing.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::WalletError;

/// Read but never written any more: kept so existing keyfiles keep opening.
pub const ENCRYPTED_VERSION: u16 = 2;
/// Written now. Adds the `kind` byte, so one format covers single-key and HD keyfiles.
pub const HD_VERSION: u16 = 3;

/// What the 32 plaintext bytes in a keyfile are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// One ML-DSA seed, one account. What a v1 or v2 file holds.
    Single,
    /// A master seed; accounts are derived from it by index.
    Hd,
}

impl KeyKind {
    pub fn byte(self) -> u8 {
        match self {
            KeyKind::Single => 0,
            KeyKind::Hd => 1,
        }
    }

    pub fn from_byte(byte: u8) -> Result<KeyKind, WalletError> {
        match byte {
            0 => Ok(KeyKind::Single),
            1 => Ok(KeyKind::Hd),
            _ => Err(WalletError::MalformedKeyfile("unknown key kind")),
        }
    }
}
/// Argon2id v0x13.
const KDF_ARGON2ID: u8 = 1;

/// Default cost: 64 MiB, 3 passes, 1 lane. Roughly 0.2 s per attempt on a laptop, which is what makes
/// an offline dictionary attack on a stolen keyfile expensive. Stored in the file, so raising it later
/// does not strand existing keys.
pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

/// v2 header: version 2 | network 1 | kdf 1 | m 4 | t 4 | p 4 | salt 16.
const V2_HEADER_BYTES: usize = 2 + 1 + 1 + 4 + 4 + 4 + SALT_BYTES;
/// v3 header: version 2 | network 1 | kind 1 | kdf 1 | m 4 | t 4 | p 4 | salt 16.
const V3_HEADER_BYTES: usize = V2_HEADER_BYTES + 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const SEED_BYTES: usize = 32;

/// KDF parameters, as read back from a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

/// The plaintext header of an encrypted file, plus what is needed to derive the key.
struct Header {
    /// 2 for a `Single` key (the historical layout), 3 for an `Hd` one.
    version: u16,
    network: u8,
    kind: KeyKind,
    params: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    /// Bytes covered by the AEAD as associated data.
    aad: Vec<u8>,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], WalletError> {
    use getrandom::fill;
    let mut out = [0u8; N];
    fill(&mut out).map_err(|e| WalletError::Io(format!("entropy: {e}")))?;
    Ok(out)
}

impl Header {
    fn new(network: u8, kind: KeyKind, params: KdfParams) -> Result<Header, WalletError> {
        let salt = random_bytes::<SALT_BYTES>()?;
        let nonce = random_bytes::<NONCE_BYTES>()?;
        Ok(Header {
            // A single-key file keeps the v2 layout, so nothing about existing keyfiles changes.
            version: match kind {
                KeyKind::Single => ENCRYPTED_VERSION,
                KeyKind::Hd => HD_VERSION,
            },
            network,
            kind,
            params,
            salt,
            nonce,
            aad: Vec::new(),
        })
    }

    /// The exact bytes that are authenticated: version, network, (kind), KDF id, parameters, salt.
    fn associated_data(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(V3_HEADER_BYTES);
        w.extend_from_slice(&self.version.to_be_bytes());
        w.push(self.network);
        if self.version == HD_VERSION {
            w.push(self.kind.byte());
        }
        w.push(KDF_ARGON2ID);
        w.extend_from_slice(&self.params.m_cost_kib.to_be_bytes());
        w.extend_from_slice(&self.params.t_cost.to_be_bytes());
        w.extend_from_slice(&self.params.p_cost.to_be_bytes());
        w.extend_from_slice(&self.salt);
        w
    }

    fn derive_key(&self, passphrase: &[u8]) -> Result<[u8; 32], WalletError> {
        let params = Params::new(
            self.params.m_cost_kib,
            self.params.t_cost,
            self.params.p_cost,
            Some(32),
        )
        .map_err(|_| WalletError::MalformedKeyfile("impossible kdf parameters"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase, &self.salt, &mut key)
            .map_err(|_| WalletError::MalformedKeyfile("kdf failure"))?;
        Ok(key)
    }
}

/// Serialize an encrypted keyfile. A `Single` kind is what a v1 or v2 file meant; `Hd` marks the 32
/// bytes as a master seed.
pub fn encrypt_key(
    network: u8,
    kind: KeyKind,
    seed: &[u8; SEED_BYTES],
    passphrase: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>, WalletError> {
    if passphrase.is_empty() {
        return Err(WalletError::WeakPassphrase);
    }
    let header = Header::new(network, kind, params)?;
    let aad = header.associated_data();
    let key = header.derive_key(passphrase)?;
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(header.nonce),
            Payload {
                msg: seed,
                aad: &aad,
            },
        )
        .map_err(|_| WalletError::MalformedKeyfile("encryption failed"))?;

    let mut out = aad;
    out.extend_from_slice(&header.nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Parse an encrypted keyfile (v2 or v3) and recover the seed and its kind.
pub fn decrypt_key(
    bytes: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<([u8; SEED_BYTES], u8, KeyKind), WalletError> {
    let version = u16::from_be_bytes([*bytes.first().unwrap_or(&0), *bytes.get(1).unwrap_or(&0)]);
    // v3 has one extra header byte (the kind) before the KDF id.
    let (header_bytes, kind) = match version {
        ENCRYPTED_VERSION => (V2_HEADER_BYTES, KeyKind::Single),
        HD_VERSION => {
            if bytes.len() < V3_HEADER_BYTES {
                return Err(WalletError::MalformedKeyfile("truncated"));
            }
            (V3_HEADER_BYTES, KeyKind::from_byte(bytes[3])?)
        }
        _ => return Err(WalletError::MalformedKeyfile("unsupported version")),
    };
    if bytes.len() != header_bytes + NONCE_BYTES + SEED_BYTES + TAG_BYTES {
        return Err(WalletError::MalformedKeyfile("wrong length"));
    }
    let kdf_at = if version == ENCRYPTED_VERSION { 3 } else { 4 };
    let params_at = kdf_at + 1;
    if bytes[kdf_at] != KDF_ARGON2ID {
        return Err(WalletError::MalformedKeyfile("unknown kdf"));
    }
    let params = KdfParams {
        m_cost_kib: u32::from_be_bytes([
            bytes[params_at],
            bytes[params_at + 1],
            bytes[params_at + 2],
            bytes[params_at + 3],
        ]),
        t_cost: u32::from_be_bytes([
            bytes[params_at + 4],
            bytes[params_at + 5],
            bytes[params_at + 6],
            bytes[params_at + 7],
        ]),
        p_cost: u32::from_be_bytes([
            bytes[params_at + 8],
            bytes[params_at + 9],
            bytes[params_at + 10],
            bytes[params_at + 11],
        ]),
    };
    let salt_at = params_at + 12;
    let mut salt = [0u8; SALT_BYTES];
    salt.copy_from_slice(&bytes[salt_at..salt_at + SALT_BYTES]);
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&bytes[header_bytes..header_bytes + NONCE_BYTES]);
    let mut header = Header {
        version,
        network: bytes[2],
        kind,
        params,
        salt,
        nonce,
        aad: Vec::new(),
    };
    header.aad = header.associated_data();
    if header.aad[..] != bytes[..header_bytes] {
        return Err(WalletError::MalformedKeyfile("non-canonical header"));
    }
    let passphrase = passphrase.ok_or(WalletError::PasswordRequired)?;
    let key = header.derive_key(passphrase)?;
    let cipher = ChaCha20Poly1305::new(&Key::from(key));
    let plain = cipher
        .decrypt(
            &Nonce::from(header.nonce),
            Payload {
                msg: &bytes[header_bytes + NONCE_BYTES..],
                aad: &header.aad,
            },
        )
        .map_err(|_| WalletError::WrongPassphrase)?;
    let mut seed = [0u8; SEED_BYTES];
    seed.copy_from_slice(&plain);
    Ok((seed, header.network, header.kind))
}

/// Encrypt with the older single-key meaning: the 32 bytes are an ML-DSA seed.
pub fn encrypt_seed(
    network: u8,
    seed: &[u8; SEED_BYTES],
    passphrase: &[u8],
    params: KdfParams,
) -> Result<Vec<u8>, WalletError> {
    encrypt_key(network, KeyKind::Single, seed, passphrase, params)
}

/// Recover just the seed and network, discarding the kind. Existing callers only ever had one account.
pub fn decrypt_seed(
    bytes: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<([u8; SEED_BYTES], u8), WalletError> {
    decrypt_key(bytes, passphrase).map(|(seed, network, _)| (seed, network))
}

/// A passphrase supplied by the operator, best-effort zeroed after use.
pub struct Passphrase(Vec<u8>);

impl Passphrase {
    pub fn new(bytes: Vec<u8>) -> Passphrase {
        Passphrase(bytes)
    }

    /// Read the first line of a file, stripping a trailing newline. Files are the least bad way to
    /// pass a secret to a CLI: it is not visible in `ps` and not in shell history.
    pub fn from_file(path: &Path) -> Result<Passphrase, WalletError> {
        let text = std::fs::read_to_string(path)?;
        let line = text.lines().next().unwrap_or("");
        if line.is_empty() {
            return Err(WalletError::WeakPassphrase);
        }
        Ok(Passphrase(line.as_bytes().to_vec()))
    }

    pub fn from_env(name: &str) -> Result<Passphrase, WalletError> {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => Ok(Passphrase(v.into_bytes())),
            _ => Err(WalletError::WeakPassphrase),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
