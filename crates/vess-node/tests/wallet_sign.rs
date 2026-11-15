use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use vess_core::constants::{ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES};
use vess_wallet::{Keyring, MESSAGE_SIGNING_CONTEXT, Wallet, keyfile::Passphrase};

fn command(dir: &Path, name: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vess"));
    command
        .current_dir(dir)
        .args(["wallet", "sign", "--datadir"])
        .arg(dir)
        .args(["--name", name])
        .arg("--config")
        .arg(dir.join("vess.toml"));
    command
}

fn verify_command(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vess"));
    command.current_dir(dir).args(["wallet", "sign", "verify"]);
    command
}

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
        .unwrap()
}

fn decode<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn signed(output: Output, message: &str, expected: &Wallet) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(field(&text, "algorithm"), "ML-DSA-65");
    assert_eq!(field(&text, "context"), MESSAGE_SIGNING_CONTEXT);
    let account: [u8; 32] = decode(field(&text, "account"));
    let public_key: [u8; ML_DSA_PK_BYTES] = decode(field(&text, "public_key"));
    let signature: [u8; ML_DSA_SIG_BYTES] = decode(field(&text, "signature"));
    assert_eq!(account, expected.account_id());
    assert_eq!(public_key, *expected.public_key());
    assert_eq!(vess_crypto::account_id(&public_key), account);
    assert!(vess_crypto::verify(
        &public_key,
        MESSAGE_SIGNING_CONTEXT.as_bytes(),
        message.as_bytes(),
        &signature
    ));
    assert!(!vess_crypto::verify(
        &public_key,
        MESSAGE_SIGNING_CONTEXT.as_bytes(),
        b"altered",
        &signature
    ));
}

#[test]
fn sign_is_local_and_supports_encrypted_hd_and_legacy_wallets() {
    let dir = tempfile::tempdir().unwrap();
    let keyring = Keyring::from_master(0, [0x45; 32]);
    let password = Passphrase::new(b"test-password".to_vec());
    keyring
        .save_new(&dir.path().join("wallets").join("hd.key"), Some(&password))
        .unwrap();
    let message = "A message \u{1f30d}\nwith a second line";
    let output = command(dir.path(), "hd")
        .args([
            "--message",
            message,
            "--index",
            "1",
            "--password-env",
            "VESS_SIGN_TEST_PASSWORD",
        ])
        .env("VESS_SIGN_TEST_PASSWORD", "test-password")
        .output()
        .unwrap();
    signed(output, message, &keyring.account(1).unwrap());
    assert!(!dir.path().join("ledger.redb").exists());

    let legacy = Wallet::from_seed(0, [0x23; 32]);
    legacy
        .save(&dir.path().join("wallets").join("legacy.key"), None)
        .unwrap();
    let output = command(dir.path(), "legacy")
        .arg("--message=--literal")
        .output()
        .unwrap();
    signed(output, "--literal", &legacy);

    let output = command(dir.path(), "legacy")
        .args(["--message", "true"])
        .output()
        .unwrap();
    signed(output, "true", &legacy);
    let output = command(dir.path(), "legacy")
        .arg("--message=")
        .output()
        .unwrap();
    signed(output, "", &legacy);
}

#[test]
fn sign_rejects_missing_message_invalid_index_and_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::from_seed(0, [0x24; 32]);
    wallet
        .save(&dir.path().join("wallets").join("legacy.key"), None)
        .unwrap();
    for args in [
        vec![],
        vec!["--message"],
        vec!["--message", "hello", "--index", "4294967296"],
    ] {
        let output = command(dir.path(), "legacy").args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
    }

    Keyring::from_master(0, [0x25; 32])
        .save_new(
            &dir.path().join("wallets").join("encrypted.key"),
            Some(&Passphrase::new(b"correct".to_vec())),
        )
        .unwrap();
    let output = command(dir.path(), "encrypted")
        .args([
            "--message",
            "hello",
            "--password-env",
            "VESS_SIGN_TEST_PASSWORD",
        ])
        .env("VESS_SIGN_TEST_PASSWORD", "incorrect")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("wrong passphrase"));
}

#[test]
fn verify_accepts_proof_file_stdin_and_explicit_fields_offline() {
    let signer = tempfile::tempdir().unwrap();
    let verifier = tempfile::tempdir().unwrap();
    let wallet = Wallet::from_seed(0, [0x30; 32]);
    wallet
        .save(&signer.path().join("wallets").join("alice.key"), None)
        .unwrap();
    let message = "hello \u{1f30d}";
    let signed = command(signer.path(), "alice")
        .args(["--message", message])
        .output()
        .unwrap();
    assert!(signed.status.success());
    let proof = String::from_utf8(signed.stdout).unwrap();
    let account = field(&proof, "account");
    let public_key = field(&proof, "public_key");
    let signature = field(&proof, "signature");
    let path = signer.path().join("proof.txt");
    std::fs::write(&path, &proof).unwrap();

    let output = verify_command(verifier.path())
        .args(["--message", message, "--proof"])
        .arg(&path)
        .args(["--account", account])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(field(&text, "valid"), "1");
    assert_eq!(field(&text, "account"), account);
    assert!(!verifier.path().join("vess.toml").exists());
    assert!(!verifier.path().join("chain").exists());

    let output = verify_command(verifier.path())
        .args([
            "--message",
            message,
            "--public-key",
            public_key,
            "--signature",
            signature,
            "--account",
            account,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut child = verify_command(verifier.path())
        .args(["--message", message, "--proof", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(proof.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut utf16 = vec![0xff, 0xfe];
    for word in proof.encode_utf16() {
        utf16.extend_from_slice(&word.to_le_bytes());
    }
    std::fs::write(&path, utf16).unwrap();
    let output = verify_command(verifier.path())
        .args(["--message", message, "--proof"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::write(&path, format!("\u{feff}{proof}")).unwrap();
    let output = verify_command(verifier.path())
        .args(["--message", message, "--proof"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn verify_rejects_tampering_wrong_signer_and_malformed_input() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::from_seed(0, [0x31; 32]);
    wallet
        .save(&dir.path().join("wallets").join("alice.key"), None)
        .unwrap();
    let signed = command(dir.path(), "alice")
        .args(["--message", "original"])
        .output()
        .unwrap();
    assert!(signed.status.success());
    let proof = String::from_utf8(signed.stdout).unwrap();
    let path = dir.path().join("proof.txt");
    std::fs::write(&path, &proof).unwrap();
    let other_account = "00".repeat(32);

    for (message, account) in [
        ("changed", None),
        ("original", Some(other_account.as_str())),
    ] {
        let mut command = verify_command(dir.path());
        command.args(["--message", message, "--proof"]).arg(&path);
        if let Some(account) = account {
            command.args(["--account", account]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("valid=0"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
    }

    let signature = field(&proof, "signature");
    let mut altered_signature = signature.to_owned();
    altered_signature.replace_range(..1, if signature.starts_with('0') { "1" } else { "0" });
    let malformed = [
        proof.replace("context=VESS-SIGNED-MESSAGE-V1", "context=VESS-TRANSFER-V1"),
        proof.replace(field(&proof, "account"), &other_account),
        proof.replacen(signature, &altered_signature, 1),
        format!("{proof}signature=00\n"),
        "x".repeat(32_769),
    ];
    for content in malformed {
        std::fs::write(&path, content).unwrap();
        let output = verify_command(dir.path())
            .args(["--message", "original", "--proof"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
    }

    let public_key = field(&proof, "public_key");
    let signature = field(&proof, "signature");
    let wrong_key = Wallet::from_seed(0, [0x32; 32]);
    let wrong_public_key: String = wrong_key
        .public_key()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let wrong_context_signature = vess_crypto::sign(
        &vess_crypto::key_from_seed([0x31; 32]),
        vess_core::hash::DOM_TRANSFER,
        b"original",
    )
    .unwrap();
    let wrong_context_signature: String = wrong_context_signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for (key, sig) in [
        (wrong_public_key.as_str(), signature),
        (public_key, wrong_context_signature.as_str()),
    ] {
        let output = verify_command(dir.path())
            .args([
                "--message",
                "original",
                "--public-key",
                key,
                "--signature",
                sig,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("valid=0"));
    }
    for args in [
        vec![
            "--message",
            "original",
            "--public-key",
            public_key,
            "--signature",
            "00",
        ],
        vec![
            "--message",
            "original",
            "--public-key",
            public_key,
            "--signature",
            signature,
            "--message",
            "again",
        ],
        vec![
            "--message",
            "original",
            "--public-key",
            public_key,
            "--signature",
            signature,
            "--acct",
            "00",
        ],
    ] {
        let output = verify_command(dir.path()).args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
    }
    let non_ascii_key = "\u{00e9}".repeat(ML_DSA_PK_BYTES);
    let output = verify_command(dir.path())
        .args([
            "--message",
            "original",
            "--public-key",
            &non_ascii_key,
            "--signature",
            signature,
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid hex"));
}
