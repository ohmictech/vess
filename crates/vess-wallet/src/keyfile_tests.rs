//! Encryption tests: round trip, wrong passphrase, tampering, and the legacy format.

use crate::keyfile::{self, KdfParams, Passphrase};
use crate::{KEYFILE_VERSION, Wallet, WalletError};

/// Argon2 at production cost is ~0.2 s per call, which is far too slow for a test suite that
/// round-trips several files. These parameters exercise the same code path at 1/64th the memory.
fn cheap() -> KdfParams {
    KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vess-keyfile-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("wallet.key")
}

#[test]
fn an_encrypted_keyfile_round_trips() {
    let path = tmp("roundtrip");
    let pass = Passphrase::new(b"correct horse battery staple".to_vec());
    let wallet = Wallet::from_seed(0, [9u8; 32]);
    wallet.save(&path, Some(&pass)).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        u16::from_be_bytes([bytes[0], bytes[1]]),
        keyfile::ENCRYPTED_VERSION
    );
    // The seed must not be recoverable from the file without the passphrase.
    let seed = vess_crypto::seed_of(&wallet.key);
    assert!(
        !bytes.windows(seed.len()).any(|w| w == seed),
        "the plaintext seed must not appear in the keyfile"
    );

    let opened = Wallet::open(&path, 0, Some(&pass)).unwrap();
    assert_eq!(opened.account_id(), wallet.account_id());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_wrong_passphrase_is_refused() {
    let path = tmp("wrongpass");
    let wallet = Wallet::from_seed(0, [10u8; 32]);
    wallet
        .save(&path, Some(&Passphrase::new(b"right".to_vec())))
        .unwrap();

    let err = match Wallet::open(&path, 0, Some(&Passphrase::new(b"wrong".to_vec()))) {
        Ok(_) => panic!("a wrong passphrase must not open the file"),
        Err(e) => e,
    };
    assert!(matches!(err, WalletError::WrongPassphrase), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_encrypted_file_without_a_passphrase_says_so() {
    let path = tmp("nopass");
    let wallet = Wallet::from_seed(0, [11u8; 32]);
    wallet
        .save(&path, Some(&Passphrase::new(b"secret".to_vec())))
        .unwrap();

    let err = match Wallet::open(&path, 0, None) {
        Ok(_) => panic!("an encrypted file must demand a passphrase"),
        Err(e) => e,
    };
    assert!(matches!(err, WalletError::PasswordRequired), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_tampered_header_or_body_is_detected() {
    let path = tmp("tamper");
    let wallet = Wallet::from_seed(0, [12u8; 32]);
    let mut bytes =
        keyfile::encrypt_seed(0, &vess_crypto::seed_of(&wallet.key), b"secret", cheap()).unwrap();

    // The KDF parameters are authenticated: changing the pass count changes the derived key, so the
    // tag must fail rather than silently opening the file with a weaker KDF.
    let mut weaker = bytes.clone();
    weaker[8..12].copy_from_slice(&2u32.to_be_bytes());
    let err = keyfile::decrypt_seed(&weaker, Some(b"secret")).unwrap_err();
    assert!(matches!(err, WalletError::WrongPassphrase), "{err}");

    // Parameters Argon2 itself rejects are a malformed file, not a wrong password.
    let mut impossible = bytes.clone();
    impossible[4..8].copy_from_slice(&1u32.to_be_bytes());
    let err = keyfile::decrypt_seed(&impossible, Some(b"secret")).unwrap_err();
    assert!(matches!(err, WalletError::MalformedKeyfile(_)), "{err}");

    // A flipped bit in the ciphertext must fail the tag.
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let err = keyfile::decrypt_seed(&bytes, Some(b"secret")).unwrap_err();
    assert!(matches!(err, WalletError::WrongPassphrase), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_empty_passphrase_is_refused() {
    let err = keyfile::encrypt_seed(0, &[13u8; 32], b"", cheap()).unwrap_err();
    assert!(matches!(err, WalletError::WeakPassphrase), "{err}");
}

#[test]
fn the_legacy_plaintext_format_still_loads() {
    let path = tmp("legacy");
    let wallet = Wallet::from_seed(0, [14u8; 32]);
    wallet.save(&path, None).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), KEYFILE_VERSION);
    assert_eq!(bytes.len(), 35);

    // No passphrase needed, and none is demanded.
    let opened = Wallet::open(&path, 0, None).unwrap();
    assert_eq!(opened.account_id(), wallet.account_id());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_keyfile_from_another_network_is_refused() {
    let path = tmp("network");
    let wallet = Wallet::from_seed(0, [15u8; 32]);
    wallet
        .save(&path, Some(&Passphrase::new(b"pw".to_vec())))
        .unwrap();
    let err = match Wallet::open(&path, 1, Some(&Passphrase::new(b"pw".to_vec()))) {
        Ok(_) => panic!("a foreign-network keyfile must be refused"),
        Err(e) => e,
    };
    assert!(matches!(err, WalletError::MalformedKeyfile(_)), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_truncated_or_overlong_file_is_refused() {
    let good = keyfile::encrypt_seed(0, &[16u8; 32], b"pw", cheap()).unwrap();
    for length in [0usize, 1, 2, 3, good.len() - 1, good.len() + 1] {
        let mut bytes = good.clone();
        bytes.resize(length, 0);
        assert!(keyfile::decrypt_seed(&bytes, Some(b"pw")).is_err());
    }
}
