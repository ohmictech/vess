use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn command(dir: &Path, action: &str, name: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vess"));
    command
        .current_dir(dir)
        .args(["wallet", action, "--datadir"])
        .arg(dir)
        .args(["--name", name, "--password-env", "VESS_TEST_PASSWORD"])
        .arg("--config")
        .arg(dir.join("vess.toml"))
        .env("VESS_TEST_PASSWORD", "test-only-password");
    command
}

fn with_input(mut command: Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn field<'a>(output: &'a str, name: &str) -> &'a str {
    output
        .lines()
        .find_map(|line| line.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
        .unwrap()
}

#[test]
fn create_and_restore_without_overwriting_or_echoing() {
    let dir = std::env::temp_dir().join(format!("vess-phrase-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let denied = command(&dir, "new", "denied").output().unwrap();
    assert!(!denied.status.success());
    assert!(!dir.join("wallets").join("denied.key").exists());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("redirected stdout"));

    let no_password = Command::new(env!("CARGO_BIN_EXE_vess"))
        .current_dir(&dir)
        .args(["wallet", "new", "--datadir"])
        .arg(&dir)
        .args(["--name", "no-password", "--unsafe-phrase-stdout"])
        .arg("--config")
        .arg(dir.join("vess.toml"))
        .output()
        .unwrap();
    assert!(!no_password.status.success());
    assert!(no_password.stdout.is_empty());
    assert!(!dir.join("wallets").join("no-password.key").exists());

    let mut broken = command(&dir, "new", "broken")
        .arg("--unsafe-phrase-stdout")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(broken.stdout.take());
    let failed_display = broken.wait_with_output().unwrap();
    assert!(!failed_display.status.success());
    assert!(!dir.join("wallets").join("broken.key").exists());
    assert!(String::from_utf8_lossy(&failed_display.stderr).contains("recovery phrase"));

    let created = command(&dir, "new", "original")
        .arg("--unsafe-phrase-stdout")
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let created_stdout = String::from_utf8(created.stdout).unwrap();
    let phrase = field(&created_stdout, "recovery_phrase");
    assert_eq!(phrase.split_whitespace().count(), 24);

    let restored = with_input(
        {
            let mut cmd = command(&dir, "restore", "restored");
            cmd.arg("--mnemonic-stdin");
            cmd
        },
        phrase,
    );
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let restored_stdout = String::from_utf8(restored.stdout).unwrap();
    assert_eq!(
        field(&created_stdout, "account"),
        field(&restored_stdout, "account")
    );
    assert!(!restored_stdout.contains(phrase));
    assert!(!String::from_utf8_lossy(&restored.stderr).contains(phrase));

    let list = |name| {
        let output = command(&dir, "addresses", name)
            .args(["--count", "3"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        text.lines()
            .filter(|line| line.starts_with("account["))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(list("original"), list("restored"));

    let old = std::fs::read(dir.join("wallets").join("restored.key")).unwrap();
    let overwritten = command(&dir, "restore", "restored")
        .arg("--mnemonic-stdin")
        .output()
        .unwrap();
    assert!(!overwritten.status.success());
    assert_eq!(
        std::fs::read(dir.join("wallets").join("restored.key")).unwrap(),
        old
    );

    for (name, invalid) in [
        ("short", "abandon ".repeat(12)),
        ("checksum", "abandon ".repeat(24)),
        ("unknown", format!("{}notaword", "abandon ".repeat(23))),
    ] {
        let mut cmd = command(&dir, "restore", name);
        cmd.arg("--mnemonic-stdin");
        let result = with_input(cmd, &invalid);
        assert!(!result.status.success());
        assert!(!dir.join("wallets").join(format!("{name}.key")).exists());
    }

    let legacy = Command::new(env!("CARGO_BIN_EXE_vess"))
        .current_dir(&dir)
        .args(["wallet", "new", "--datadir"])
        .arg(&dir)
        .args(["--name", "legacy", "--legacy"])
        .arg("--config")
        .arg(dir.join("vess.toml"))
        .output()
        .unwrap();
    assert!(legacy.status.success());
    let legacy_stdout = String::from_utf8(legacy.stdout).unwrap();
    assert_eq!(field(&legacy_stdout, "hd"), "0");
    assert_eq!(field(&legacy_stdout, "encrypted"), "0");
    assert!(!legacy_stdout.contains("recovery_phrase="));

    for name in ["original", "restored", "legacy"] {
        std::fs::remove_file(dir.join("wallets").join(format!("{name}.key"))).unwrap();
    }
    std::fs::remove_dir(dir.join("wallets")).unwrap();
    std::fs::remove_file(dir.join("vess.toml")).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
