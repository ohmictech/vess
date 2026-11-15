//! Minimal wallet: key material, signing, and an RPC client.
//!
//! Contains no consensus logic beyond encoding and signing. Keyfiles are encrypted with
//! Argon2id + ChaCha20-Poly1305 when a passphrase is supplied (see `keyfile`); the legacy plaintext
//! format is still readable.

pub mod keyfile;
#[cfg(test)]
mod keyfile_tests;

use std::io::Write;
use std::path::Path;

use bip39::{Language, Mnemonic};
use vess_core::codec::{Reader, Writer};
use vess_core::constants::PROTOCOL_VERSION;
use vess_core::hash::{self, DOM_STATE_UPDATE, DOM_TRANSFER};
use vess_core::{AccountId, Hash, PublicKey, Signature, StateUpdate, Transfer};
use vess_crypto::Key;
use vess_net::rpc::{
    AccountInfo, BlockInfo, BlockQuery, Reply, ReplyBody, Request, RpcClient, StatusInfo,
    TransactionInfo,
};
use zeroize::Zeroizing;

/// The legacy plaintext format. Written only when the caller asks for it.
pub const KEYFILE_VERSION: u16 = 1;

/// ML-DSA context for local message signatures, distinct from transaction contexts.
pub const MESSAGE_SIGNING_CONTEXT: &str = "VESS-SIGNED-MESSAGE-V1";

#[derive(Debug)]
pub enum WalletError {
    Io(String),
    MalformedKeyfile(&'static str),
    Rpc(String),
    Rejected(u16),
    /// The file is encrypted and no passphrase was supplied.
    PasswordRequired,
    /// The passphrase did not decrypt the file (wrong password, or a tampered file).
    WrongPassphrase,
    /// An empty passphrase would encrypt nothing.
    WeakPassphrase,
    /// A single-key keyfile has one account, so it has no index other than 0.
    NotHierarchical,
    /// The recovery phrase is not a valid 24-word English BIP-39 phrase.
    InvalidRecoveryPhrase(String),
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::Io(e) => write!(f, "io error: {e}"),
            WalletError::MalformedKeyfile(what) => write!(f, "malformed key file: {what}"),
            WalletError::Rpc(e) => write!(f, "rpc error: {e}"),
            WalletError::Rejected(code) => write!(f, "node rejected the object (reason {code})"),
            WalletError::PasswordRequired => {
                f.write_str("keyfile is encrypted: pass --password-file FILE or --password-env VAR")
            }
            WalletError::WrongPassphrase => {
                f.write_str("wrong passphrase, or the keyfile is corrupt")
            }
            WalletError::WeakPassphrase => f.write_str("refusing an empty passphrase"),
            WalletError::NotHierarchical => f.write_str(
                "this keyfile holds a single account; reopen it without --index (or create an HD wallet)",
            ),
            WalletError::InvalidRecoveryPhrase(reason) => {
                write!(f, "invalid recovery phrase: {reason}")
            }
        }
    }
}

impl std::error::Error for WalletError {}

impl From<std::io::Error> for WalletError {
    fn from(e: std::io::Error) -> Self {
        WalletError::Io(e.to_string())
    }
}

impl From<vess_net::NetError> for WalletError {
    fn from(e: vess_net::NetError) -> Self {
        WalletError::Rpc(e.to_string())
    }
}

/// A 24-word English BIP-39 recovery phrase for a new Vess HD wallet.
///
/// The phrase is not stored in the keyfile. Anyone with it can recover the wallet.
pub struct RecoveryPhrase(Mnemonic);

impl RecoveryPhrase {
    pub fn generate() -> Result<Self, WalletError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut())
            .map_err(|e| WalletError::Io(format!("operating system randomness: {e}")))?;
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
            .map_err(|e| WalletError::InvalidRecoveryPhrase(e.to_string()))?;
        Ok(Self(mnemonic))
    }

    pub fn parse(words: &str) -> Result<Self, WalletError> {
        if words.split_whitespace().count() != 24 {
            return Err(WalletError::InvalidRecoveryPhrase(
                "expected exactly 24 words".into(),
            ));
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, words)
            .map_err(|e| WalletError::InvalidRecoveryPhrase(e.to_string()))?;
        Ok(Self(mnemonic))
    }

    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.words()
    }

    /// BIP-39 with an empty passphrase, then the versioned Vess master-seed mapping.
    pub fn keyring(&self, network: u8) -> Keyring {
        let seed = Zeroizing::new(self.0.to_seed_normalized(""));
        let master = hash::tagged(b"VESS-BIP39-HD-V1", &[seed.as_ref()]);
        Keyring::from_master(network, master)
    }
}

pub struct Wallet {
    key: Key,
    public_key: PublicKey,
    account_id: AccountId,
    network: u8,
}

impl Wallet {
    pub fn create(network: u8) -> Wallet {
        let key = vess_crypto::generate_key();
        Self::from_key(network, key)
    }

    pub fn from_seed(network: u8, seed: [u8; 32]) -> Wallet {
        Self::from_key(network, vess_crypto::key_from_seed(seed))
    }

    pub fn from_key(network: u8, key: Key) -> Wallet {
        let public_key = vess_crypto::public_key_bytes(&key);
        let account_id = vess_crypto::account_id(&public_key);
        Wallet {
            key,
            public_key,
            account_id,
            network,
        }
    }

    /// Open a keyfile. Handles both the legacy plaintext format and the encrypted one; `passphrase`
    /// is required only for the latter.
    pub fn open(
        path: &Path,
        network: u8,
        passphrase: Option<&keyfile::Passphrase>,
    ) -> Result<Wallet, WalletError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 2 {
            return Err(WalletError::MalformedKeyfile("truncated"));
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        match version {
            KEYFILE_VERSION => {
                let mut r = Reader::new(&bytes);
                let _ = r
                    .u16()
                    .map_err(|_| WalletError::MalformedKeyfile("truncated"))?;
                let file_network = r
                    .u8()
                    .map_err(|_| WalletError::MalformedKeyfile("truncated"))?;
                if file_network != network {
                    return Err(WalletError::MalformedKeyfile(
                        "key belongs to another network",
                    ));
                }
                let seed: [u8; 32] = r
                    .array()
                    .map_err(|_| WalletError::MalformedKeyfile("truncated"))?;
                r.finish()
                    .map_err(|_| WalletError::MalformedKeyfile("trailing bytes"))?;
                Ok(Wallet::from_seed(network, seed))
            }
            keyfile::ENCRYPTED_VERSION => {
                let (seed, file_network) =
                    keyfile::decrypt_seed(&bytes, passphrase.map(|p| p.as_bytes()))?;
                if file_network != network {
                    return Err(WalletError::MalformedKeyfile(
                        "key belongs to another network",
                    ));
                }
                Ok(Wallet::from_seed(network, seed))
            }
            _ => Err(WalletError::MalformedKeyfile("unsupported version")),
        }
    }

    /// Write the keyfile. With a passphrase it is Argon2id-encrypted (`keyfile::ENCRYPTED_VERSION`);
    /// without one it is the legacy plaintext format, which the caller should refuse to use in
    /// earnest.
    pub fn save(
        &self,
        path: &Path,
        passphrase: Option<&keyfile::Passphrase>,
    ) -> Result<(), WalletError> {
        let seed = vess_crypto::seed_of(&self.key);
        let bytes = match passphrase {
            Some(p) => keyfile::encrypt_seed(
                self.network,
                &seed,
                p.as_bytes(),
                keyfile::KdfParams::default(),
            )?,
            None => {
                let mut w = Writer::new();
                w.u16(KEYFILE_VERSION);
                w.u8(self.network);
                w.fixed(&seed);
                w.into_vec()
            }
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &bytes)?;
        Ok(())
    }

    pub fn network(&self) -> u8 {
        self.network
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn chain_id(&self) -> Hash {
        hash::chain_id(self.network)
    }

    /// Sign the exact message bytes locally without constructing a transaction.
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, vess_crypto::CryptoError> {
        vess_crypto::sign(&self.key, MESSAGE_SIGNING_CONTEXT.as_bytes(), message)
    }

    pub fn build_transfer(
        &self,
        recipient: AccountId,
        amount: u64,
        fee: u64,
        nonce: u64,
        expiry_unix: u64,
    ) -> Transfer {
        let mut tx = Transfer {
            version: PROTOCOL_VERSION,
            chain_id: self.chain_id(),
            sender_public_key: self.public_key,
            recipient_account_id: recipient,
            amount,
            fee,
            nonce,
            expiry_unix,
            signature: [0u8; vess_core::constants::ML_DSA_SIG_BYTES],
        };
        tx.signature = vess_crypto::sign(&self.key, DOM_TRANSFER, &tx.unsigned_bytes())
            .expect("transaction context is short");
        tx
    }

    pub fn build_state_update(
        &self,
        new_state_hash: Hash,
        fee: u64,
        nonce: u64,
        expiry_unix: u64,
    ) -> StateUpdate {
        let mut tx = StateUpdate {
            version: PROTOCOL_VERSION,
            chain_id: self.chain_id(),
            sender_public_key: self.public_key,
            new_state_hash,
            fee,
            nonce,
            expiry_unix,
            signature: [0u8; vess_core::constants::ML_DSA_SIG_BYTES],
        };
        tx.signature = vess_crypto::sign(&self.key, DOM_STATE_UPDATE, &tx.unsigned_bytes())
            .expect("transaction context is short");
        tx
    }
}

/// What a keyfile holds: one account, or a master seed that derives many.
///
/// Derivation is hardened-only (see `vess_crypto::derive_seed`), so an account index is the whole
/// address space of a wallet and the master seed is the backup. A file written before this existed is
/// `Single`: its 32 bytes *are* an ML-DSA seed, and index 0 is that account, so old keyfiles keep the
/// address they always had.
pub enum Keyring {
    /// Boxed: a `Wallet` carries an ML-DSA key, which is far larger than a seed.
    Single(Box<Wallet>),
    Hd {
        network: u8,
        master: [u8; 32],
    },
}

impl Keyring {
    /// A new HD keyring with a random master. It has no recovery phrase; back up its keyfile.
    pub fn create(network: u8) -> Keyring {
        Keyring::Hd {
            network,
            master: vess_crypto::generate_seed(),
        }
    }

    pub fn from_master(network: u8, master: [u8; 32]) -> Keyring {
        Keyring::Hd { network, master }
    }

    pub fn network(&self) -> u8 {
        match self {
            Keyring::Single(wallet) => wallet.network(),
            Keyring::Hd { network, .. } => *network,
        }
    }

    pub fn is_hd(&self) -> bool {
        matches!(self, Keyring::Hd { .. })
    }

    /// The account at `index`. A single-key keyring has exactly one account, at index 0.
    pub fn account(&self, index: u32) -> Result<Wallet, WalletError> {
        match self {
            Keyring::Single(wallet) => {
                if index != 0 {
                    return Err(WalletError::NotHierarchical);
                }
                Ok(Wallet::from_key(wallet.network(), wallet.key.clone()))
            }
            Keyring::Hd { network, master } => Ok(Wallet::from_seed(
                *network,
                vess_crypto::derive_seed(master, index),
            )),
        }
    }

    pub fn account_id(&self, index: u32) -> Result<AccountId, WalletError> {
        Ok(self.account(index)?.account_id())
    }

    /// The first `count` account ids, which is what a receiving UI needs to display.
    pub fn account_ids(&self, count: u32) -> Result<Vec<AccountId>, WalletError> {
        (0..count).map(|index| self.account_id(index)).collect()
    }

    /// Open a keyfile of any version.
    pub fn open(
        path: &Path,
        network: u8,
        passphrase: Option<&keyfile::Passphrase>,
    ) -> Result<Keyring, WalletError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 2 {
            return Err(WalletError::MalformedKeyfile("truncated"));
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        match version {
            // v1: plaintext single key.
            KEYFILE_VERSION => {
                let mut r = Reader::new(&bytes);
                let _ = r
                    .u16()
                    .map_err(|_| WalletError::MalformedKeyfile("truncated"))?;
                let file_network = r
                    .u8()
                    .map_err(|_| WalletError::MalformedKeyfile("truncated"))?;
                if file_network != network {
                    return Err(WalletError::MalformedKeyfile(
                        "key belongs to another network",
                    ));
                }
                let seed: [u8; 32] = r
                    .array()
                    .map_err(|_| WalletError::MalformedKeyfile("truncated"))?;
                r.finish()
                    .map_err(|_| WalletError::MalformedKeyfile("trailing bytes"))?;
                Ok(Keyring::Single(Box::new(Wallet::from_seed(network, seed))))
            }
            keyfile::ENCRYPTED_VERSION | keyfile::HD_VERSION => {
                let (seed, file_network, kind) =
                    keyfile::decrypt_key(&bytes, passphrase.map(|p| p.as_bytes()))?;
                if file_network != network {
                    return Err(WalletError::MalformedKeyfile(
                        "key belongs to another network",
                    ));
                }
                Ok(match kind {
                    keyfile::KeyKind::Single => {
                        Keyring::Single(Box::new(Wallet::from_seed(network, seed)))
                    }
                    keyfile::KeyKind::Hd => Keyring::Hd {
                        network,
                        master: seed,
                    },
                })
            }
            _ => Err(WalletError::MalformedKeyfile("unsupported version")),
        }
    }

    /// Write the keyfile. An HD keyring always writes v3 (it needs the kind byte); a single-key one
    /// keeps the v2 layout it has always had.
    pub fn save(
        &self,
        path: &Path,
        passphrase: Option<&keyfile::Passphrase>,
    ) -> Result<(), WalletError> {
        self.save_inner(path, passphrase, false)
    }

    /// Create a keyfile without replacing an existing file.
    pub fn save_new(
        &self,
        path: &Path,
        passphrase: Option<&keyfile::Passphrase>,
    ) -> Result<(), WalletError> {
        self.save_inner(path, passphrase, true)
    }

    fn save_inner(
        &self,
        path: &Path,
        passphrase: Option<&keyfile::Passphrase>,
        create_new: bool,
    ) -> Result<(), WalletError> {
        let (network, seed, kind) = match self {
            Keyring::Single(wallet) => (
                wallet.network(),
                vess_crypto::seed_of(&wallet.key),
                keyfile::KeyKind::Single,
            ),
            Keyring::Hd { network, master } => (*network, *master, keyfile::KeyKind::Hd),
        };
        let bytes = match passphrase {
            Some(p) => keyfile::encrypt_key(
                network,
                kind,
                &seed,
                p.as_bytes(),
                keyfile::KdfParams::default(),
            )?,
            None => {
                // The plaintext format has no room for a kind, so an unencrypted HD keyring would be
                // indistinguishable from a single-key one. Refuse rather than silently downgrade.
                if kind == keyfile::KeyKind::Hd {
                    return Err(WalletError::PasswordRequired);
                }
                let mut w = Writer::new();
                w.u16(KEYFILE_VERSION);
                w.u8(network);
                w.fixed(&seed);
                w.into_vec()
            }
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if create_new {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            file.write_all(&bytes)?;
        } else {
            std::fs::write(path, &bytes)?;
        }
        Ok(())
    }
}

/// Thin RPC wrapper so callers do not build requests by hand.
pub struct NodeClient {
    client: RpcClient,
}

impl NodeClient {
    pub fn connect(addr: &str) -> Result<NodeClient, WalletError> {
        Ok(NodeClient {
            client: RpcClient::connect(addr)?,
        })
    }

    pub fn status(&mut self) -> Result<StatusInfo, WalletError> {
        match self.call(Request::Status)? {
            ReplyBody::Status(s) => Ok(s),
            _ => Err(WalletError::Rpc("unexpected status reply".into())),
        }
    }

    pub fn balance(&mut self, account: AccountId) -> Result<AccountInfo, WalletError> {
        match self.call(Request::Balance(account))? {
            ReplyBody::Account(a) => Ok(a),
            _ => Err(WalletError::Rpc("unexpected balance reply".into())),
        }
    }

    pub fn submit_transfer(&mut self, tx: Transfer) -> Result<Hash, WalletError> {
        self.accepted(Request::SubmitTransfer(tx))
    }

    /// Read the sender's nonce from the node, sign the transfer, and submit it in one call.
    pub fn transfer(
        &mut self,
        wallet: &Wallet,
        to: AccountId,
        amount: u64,
        fee: u64,
    ) -> Result<Hash, WalletError> {
        let info = self.balance(wallet.account_id())?;
        let tx = wallet.build_transfer(to, amount, fee, info.next_nonce, 0);
        self.submit_transfer(tx)
    }

    /// Read the sender's nonce from the node, sign a state update, and submit it in one call.
    pub fn update_state(
        &mut self,
        wallet: &Wallet,
        new_state_hash: Hash,
        fee: u64,
    ) -> Result<Hash, WalletError> {
        let info = self.balance(wallet.account_id())?;
        let tx = wallet.build_state_update(new_state_hash, fee, info.next_nonce, 0);
        self.submit_state_update(tx)
    }

    pub fn submit_state_update(&mut self, tx: StateUpdate) -> Result<Hash, WalletError> {
        self.accepted(Request::SubmitStateUpdate(tx))
    }

    /// Fetch a block by height on the main chain or by id.
    pub fn block(&mut self, query: BlockQuery) -> Result<BlockInfo, WalletError> {
        match self.call(Request::Block(query))? {
            ReplyBody::Block(info) => Ok(info),
            _ => Err(WalletError::Rpc("unexpected block reply".into())),
        }
    }

    /// Ask where a transaction is, and how deep its block is.
    pub fn transaction(&mut self, id: Hash) -> Result<TransactionInfo, WalletError> {
        match self.call(Request::Transaction(id))? {
            ReplyBody::Transaction(info) => Ok(info),
            _ => Err(WalletError::Rpc("unexpected transaction reply".into())),
        }
    }

    pub fn stop(&mut self) -> Result<(), WalletError> {
        let _ = self.call(Request::Stop)?;
        Ok(())
    }

    fn accepted(&mut self, request: Request) -> Result<Hash, WalletError> {
        match self.call(request)? {
            ReplyBody::Accepted(id) => Ok(id),
            _ => Err(WalletError::Rpc("unexpected submit reply".into())),
        }
    }

    /// Raw call, for callers that want the rejection code instead of an error.
    pub fn call_raw(&mut self, request: Request) -> Result<Reply, WalletError> {
        self.client.call(&request).map_err(WalletError::from)
    }

    fn call(&mut self, request: Request) -> Result<ReplyBody, WalletError> {
        let reply = self.client.call(&request)?;
        if !reply.is_ok() {
            return Err(WalletError::Rejected(reply.reason));
        }
        Ok(reply.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfiles_round_trip_and_are_network_bound() {
        let dir = std::env::temp_dir().join(format!("vess-wallet-{}", std::process::id()));
        let path = dir.join("alice.key");
        let wallet = Wallet::from_seed(0, [42u8; 32]);
        wallet.save(&path, None).unwrap();

        let loaded = Wallet::open(&path, 0, None).unwrap();
        assert_eq!(loaded.account_id(), wallet.account_id());
        assert_eq!(loaded.public_key(), wallet.public_key());

        assert!(matches!(
            Wallet::open(&path, 1, None),
            Err(WalletError::MalformedKeyfile(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn transfers_are_signed_and_bound_to_the_sender() {
        let wallet = Wallet::from_seed(0, [7u8; 32]);
        let tx = wallet.build_transfer([9u8; 32], 10, 1, 0, 0);
        assert_eq!(tx.sender_id(), wallet.account_id());
        assert!(vess_crypto::verify(
            &tx.sender_public_key,
            DOM_TRANSFER,
            &tx.unsigned_bytes(),
            &tx.signature
        ));
    }

    #[test]
    fn message_signatures_are_bound_to_the_bytes_and_separate_from_transactions() {
        let wallet = Wallet::from_seed(0, [7u8; 32]);
        let message = "hello Vess \u{1f30d}".as_bytes();
        let signature = wallet.sign_message(message).unwrap();
        assert!(vess_crypto::verify(
            wallet.public_key(),
            MESSAGE_SIGNING_CONTEXT.as_bytes(),
            message,
            &signature,
        ));
        assert!(!vess_crypto::verify(
            wallet.public_key(),
            MESSAGE_SIGNING_CONTEXT.as_bytes(),
            b"changed",
            &signature,
        ));
        assert!(!vess_crypto::verify(
            wallet.public_key(),
            DOM_TRANSFER,
            message,
            &signature,
        ));
        assert!(!vess_crypto::verify(
            wallet.public_key(),
            DOM_STATE_UPDATE,
            message,
            &signature,
        ));
    }

    #[test]
    fn state_updates_are_signed_under_their_own_context() {
        let wallet = Wallet::from_seed(0, [8u8; 32]);
        let tx = wallet.build_state_update([3u8; 32], 5, 0, 0);
        assert_eq!(tx.sender_id(), wallet.account_id());
        assert!(vess_crypto::verify(
            &tx.sender_public_key,
            DOM_STATE_UPDATE,
            &tx.unsigned_bytes(),
            &tx.signature
        ));
        assert!(!vess_crypto::verify(
            &tx.sender_public_key,
            DOM_TRANSFER,
            &tx.unsigned_bytes(),
            &tx.signature
        ));
    }

    /// The private master seed of a keyring, for round-trip tests.
    fn master_of(keyring: &Keyring) -> [u8; 32] {
        match keyring {
            Keyring::Hd { master, .. } => *master,
            Keyring::Single(_) => panic!("not an HD keyring"),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn bip39_and_vess_derivation_vector() {
        let words = format!("{}art", "abandon ".repeat(23));
        let phrase = RecoveryPhrase::parse(&words).unwrap();
        assert_eq!(
            hex(&phrase.0.to_seed_normalized("")),
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
        );
        let keyring = phrase.keyring(0);
        assert_eq!(
            hex(&master_of(&keyring)),
            "712cc78bbbc7d53b68a21adf9c3581605ea83feafcc9b83cef6820ff247147fb"
        );
        assert_eq!(
            hex(&keyring.account_id(0).unwrap()),
            "6a627498f64f1d678f4023ce75689c5caa55bd60756de8d643a25f3abaa49c80"
        );
        assert_eq!(
            hex(&keyring.account_id(1).unwrap()),
            "205802b235ae5c2a45f099a0f55d24887f739d91b87b226d8b03aeb778ac96c1"
        );
    }

    #[test]
    fn recovery_phrase_validation_and_generation() {
        let generated = RecoveryPhrase::generate().unwrap();
        let words = Zeroizing::new(generated.words().collect::<Vec<_>>().join(" "));
        let recovered = RecoveryPhrase::parse(&words).unwrap();
        assert_eq!(
            generated.keyring(0).account_ids(3).unwrap(),
            recovered.keyring(0).account_ids(3).unwrap()
        );
        for invalid in [
            "abandon ".repeat(12),
            "abandon ".repeat(24),
            format!("{}notaword", "abandon ".repeat(23)),
        ] {
            assert!(matches!(
                RecoveryPhrase::parse(&invalid),
                Err(WalletError::InvalidRecoveryPhrase(_))
            ));
        }
    }

    #[test]
    fn saving_new_keyfiles_never_replaces_existing_files() {
        let dir = std::env::temp_dir().join(format!("vess-save-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.key");
        std::fs::write(&path, b"existing").unwrap();
        let ring = Keyring::from_master(0, [7; 32]);
        let pass = keyfile::Passphrase::new(b"password".to_vec());
        assert!(ring.save_new(&path, Some(&pass)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn hd_accounts_are_deterministic_distinct_and_recoverable() {
        let dir = std::env::temp_dir().join(format!("vess-hd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hd.key");
        let pass = keyfile::Passphrase::new(b"correct horse".to_vec());

        let keyring = Keyring::create(0);
        assert!(keyring.is_hd());
        let ids = keyring.account_ids(3).unwrap();
        assert_eq!(ids.len(), 3);
        assert_ne!(ids[0], ids[1], "each index is its own account");
        assert_ne!(ids[1], ids[2]);
        // One master always yields the same accounts, which is what makes one backup enough.
        let same = Keyring::from_master(0, master_of(&keyring));
        assert_eq!(same.account_ids(3).unwrap(), ids);

        keyring.save(&path, Some(&pass)).unwrap();
        let reopened = Keyring::open(&path, 0, Some(&pass)).unwrap();
        assert!(reopened.is_hd(), "the kind survives the keyfile");
        assert_eq!(reopened.account_ids(3).unwrap(), ids);

        // A derived account signs for the address it claims.
        let wallet = reopened.account(2).unwrap();
        assert_eq!(wallet.account_id(), ids[2]);

        // An HD keyring has no honest plaintext form, so an unencrypted save is refused.
        assert!(matches!(
            keyring.save(&path, None),
            Err(WalletError::PasswordRequired)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_single_key_keyfile_keeps_its_one_address() {
        let dir = std::env::temp_dir().join(format!("vess-single-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("single.key");
        let pass = keyfile::Passphrase::new(b"pw".to_vec());

        // A wallet written by the old API: one ML-DSA seed, one account, address unchanged.
        let wallet = Wallet::from_seed(0, [21u8; 32]);
        let expected = wallet.account_id();
        wallet.save(&path, None).unwrap();
        let legacy = Keyring::open(&path, 0, None).unwrap();
        assert_eq!(legacy.account_id(0).unwrap(), expected);
        assert!(matches!(
            legacy.account(1),
            Err(WalletError::NotHierarchical)
        ));
        wallet.save(&path, Some(&pass)).unwrap();

        let keyring = Keyring::open(&path, 0, Some(&pass)).unwrap();
        assert!(!keyring.is_hd(), "an old keyfile is not hierarchical");
        assert_eq!(keyring.account(0).unwrap().account_id(), expected);
        assert!(matches!(
            keyring.account(1),
            Err(WalletError::NotHierarchical)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }
}
