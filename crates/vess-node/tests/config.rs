use std::collections::HashSet;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

fn command(dir: &Path) -> Command {
    let exe = Path::new(env!("CARGO_BIN_EXE_vess"));
    let mut cmd = Command::new(dir.join(exe.file_name().unwrap()));
    cmd.current_dir(dir).env_remove("VESS_SEEDS");
    cmd
}

fn prepare(dir: &Path) {
    let exe = Path::new(env!("CARGO_BIN_EXE_vess"));
    std::fs::copy(exe, dir.join(exe.file_name().unwrap())).unwrap();
}

fn unused_port() -> u16 {
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    loop {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if USED
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .unwrap()
            .insert(port)
        {
            return port;
        }
    }
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(mut cmd: Command, port: u16) -> Running {
    start_with_log(&mut cmd, port, None)
}

fn start_with_log(cmd: &mut Command, port: u16, log: Option<&Path>) -> Running {
    let dir = cmd.get_current_dir().unwrap().to_path_buf();
    let executable = cmd.get_program().to_os_string();
    let stderr = match log {
        Some(path) => Stdio::from(std::fs::File::create(path).unwrap()),
        None => Stdio::null(),
    };
    let mut process = Running(cmd.stdout(Stdio::null()).stderr(stderr).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Command::new(&executable)
            .current_dir(&dir)
            .args(["node", "status", "--rpc", &format!("127.0.0.1:{port}")])
            .output()
            .unwrap()
            .status
            .success()
        {
            return process;
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "node exited before listening"
        );
        assert!(Instant::now() < deadline, "node did not start");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn node_startup_enables_snapshot_trust_by_default_and_respects_opt_out() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let port = unused_port();
    let log = dir.path().join("node.log");
    let mut defaults = command(dir.path());
    defaults.args(["--rpc", &port.to_string(), "--port", "0"]);
    drop(start_with_log(&mut defaults, port, Some(&log)));
    assert!(
        std::fs::read_to_string(&log)
            .unwrap()
            .contains("snapshot trust is enabled")
    );

    let mut disabled = command(dir.path());
    disabled.args([
        "--rpc",
        &port.to_string(),
        "--port",
        "0",
        "--no-trust-snapshot",
    ]);
    drop(start_with_log(&mut disabled, port, Some(&log)));
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap()
            .contains("snapshot trust is enabled")
    );

    let config = dir.path().join("vess.toml");
    let mut settings: toml::Value =
        toml::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    settings["trust_snapshot"] = false.into();
    std::fs::write(&config, toml::to_string_pretty(&settings).unwrap()).unwrap();
    let mut configured_off = command(dir.path());
    configured_off.args(["--rpc", &port.to_string(), "--port", "0"]);
    drop(start_with_log(&mut configured_off, port, Some(&log)));
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap()
            .contains("snapshot trust is enabled")
    );

    let mut override_on = command(dir.path());
    override_on.args([
        "--rpc",
        &port.to_string(),
        "--port",
        "0",
        "--trust-snapshot",
    ]);
    drop(start_with_log(&mut override_on, port, Some(&log)));
    assert!(
        std::fs::read_to_string(&log)
            .unwrap()
            .contains("snapshot trust is enabled")
    );
}

#[test]
fn bare_invocation_uses_config_and_first_run_flags_are_not_saved() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let port = unused_port();
    let data = dir.path().join("node-data");
    let mut first = command(dir.path());
    first
        .args(["node", "run", "--network", "testnet", "--datadir"])
        .arg(&data)
        .args([
            "--rpc",
            &port.to_string(),
            "--port",
            "0",
            "--seed",
            "127.0.0.1:4",
        ]);
    drop(start(first, port));

    let path = dir.path().join("vess.toml");
    let defaults = std::fs::read_to_string(&path).unwrap();
    assert!(defaults.contains("network = \"devnet\""));
    assert!(defaults.contains("rpc_port = 9733"));
    assert!(!defaults.contains("127.0.0.1:4"));
    assert!(defaults.contains("mine = false"));
    let mut settings: toml::Value = toml::from_str(&defaults).unwrap();
    settings["network"] = "testnet".into();
    settings["datadir"] = data.to_str().unwrap().into();
    settings["rpc_port"] = i64::from(port).into();
    settings["p2p_port"] = 0.into();
    settings["seeds"] = toml::Value::Array(vec!["127.0.0.1:4".into()]);
    let config = toml::to_string_pretty(&settings).unwrap();
    std::fs::write(&path, &config).unwrap();

    let bare = start(command(dir.path()), port);
    let status = command(dir.path())
        .args(["node", "status", "--rpc", &format!("127.0.0.1:{port}")])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(String::from_utf8_lossy(&status.stdout).contains("network=1"));
    drop(bare);

    let override_port = loop {
        let candidate = unused_port();
        if candidate != port {
            break candidate;
        }
    };
    let mut overridden = command(dir.path());
    overridden.args(["--rpc", &override_port.to_string()]);
    drop(start(overridden, override_port));
    assert_eq!(std::fs::read_to_string(path).unwrap(), config);
}

#[test]
fn default_config_never_captures_wallet_flags_or_secrets() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let data = dir.path().join("wallet-data");
    let output = command(dir.path())
        .args(["wallet", "new", "--network", "testnet", "--datadir"])
        .arg(&data)
        .args([
            "--name",
            "alice",
            "--password-env",
            "TEST_PASSWORD",
            "--unsafe-phrase-stdout",
        ])
        .env("TEST_PASSWORD", "a-private-test-password")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let phrase = stdout
        .lines()
        .find_map(|line| line.strip_prefix("recovery_phrase="))
        .unwrap();
    let config = std::fs::read_to_string(dir.path().join("vess.toml")).unwrap();
    assert!(config.contains("network = \"devnet\""));
    assert!(!config.contains(phrase));
    assert!(!config.contains("a-private-test-password"));
    assert!(!config.contains("TEST_PASSWORD"));

    let path = dir.path().join("vess.toml");
    let mut settings: toml::Value = toml::from_str(&config).unwrap();
    settings["network"] = "testnet".into();
    settings["datadir"] = data.to_str().unwrap().into();
    std::fs::write(path, toml::to_string_pretty(&settings).unwrap()).unwrap();

    let list = command(dir.path())
        .args([
            "wallet",
            "addresses",
            "--name",
            "alice",
            "--password-env",
            "TEST_PASSWORD",
            "--count",
            "1",
        ])
        .env("TEST_PASSWORD", "a-private-test-password")
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let account = stdout
        .lines()
        .find(|line| line.starts_with("account="))
        .unwrap();
    assert!(
        String::from_utf8_lossy(&list.stdout).contains(&account.replace("account=", "account[0]="))
    );
}

#[test]
fn custom_config_overrides_and_invalid_files_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let custom = dir.path().join("settings.toml");
    let init = command(dir.path())
        .args(["node", "init", "--config"])
        .arg(&custom)
        .args(["--network", "testnet", "--datadir", "test-chain"])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let initial = std::fs::read_to_string(&custom).unwrap();
    assert!(initial.contains("network = \"devnet\""));
    assert!(!dir.path().join("vess.toml").exists());
    let override_init = command(dir.path())
        .args(["node", "init", "--config"])
        .arg(&custom)
        .args(["--network", "devnet", "--datadir", "other-chain"])
        .output()
        .unwrap();
    assert!(
        override_init.status.success(),
        "{}",
        String::from_utf8_lossy(&override_init.stderr)
    );
    assert!(String::from_utf8_lossy(&override_init.stdout).contains("network=0"));
    assert_eq!(std::fs::read_to_string(&custom).unwrap(), initial);

    for invalid in [
        "network = \"testne\"\n",
        "rpc_prt = 1234\n",
        "mine = true\n",
        "invalid toml\n",
    ] {
        std::fs::write(&custom, invalid).unwrap();
        let result = command(dir.path())
            .args(["node", "params", "--config"])
            .arg(&custom)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("config"));
        assert_eq!(std::fs::read_to_string(&custom).unwrap(), invalid);
    }
}

#[test]
fn bare_start_creates_defaults_and_rejects_bad_options() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    for args in [
        vec!["--mine", "--no-mine"],
        vec!["--mine=false"],
        vec!["--datadiir", "wrong"],
    ] {
        let result = command(dir.path()).args(args).output().unwrap();
        assert!(!result.status.success());
        assert!(!dir.path().join("vess.toml").exists());
    }
    let port = unused_port();
    let mut node = command(dir.path());
    node.args(["--rpc", &port.to_string(), "--port", "0"]);
    let process = start(node, port);
    let config = std::fs::read_to_string(dir.path().join("vess.toml")).unwrap();
    assert!(config.contains("network = \"devnet\""));
    assert!(config.contains("datadir = \"./chain\""));
    assert!(config.contains("rpc_port = 9733"));
    assert!(config.contains("mine = false"));
    assert!(config.contains("trust_snapshot = true"));
    assert!(config.contains("seed.vess.invalid:9732"));
    for example in [
        "# payout = \"YOUR_64_CHARACTER_ACCOUNT_ADDRESS\"",
        "# prune_blocks = 1024",
        "# prune_headers = 100000000",
    ] {
        assert!(config.contains(example), "missing {example}");
    }
    let parsed: toml::Value = toml::from_str(&config).unwrap();
    assert!(parsed["seeds"].as_array().unwrap().is_empty());
    assert!(!config.contains("mine_interval"));
    for name in ["payout", "prune_blocks", "prune_headers"] {
        assert!(
            parsed.get(name).is_none(),
            "{name} must not override saved settings"
        );
    }
    assert!(dir.path().join("chain").exists());
    drop(process);
}

#[test]
fn mining_continues_without_legacy_interval_delay() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let port = unused_port();
    let log = dir.path().join("miner.log");
    let config = format!(
        "rpc_port = {port}\np2p_port = 0\nmine = true\npayout = \"{}\"\nmine_interval = 120000\n",
        "21".repeat(32)
    );
    std::fs::write(dir.path().join("vess.toml"), config).unwrap();
    let mut node = command(dir.path());
    node.args(["--mine-interval", "120000"]);
    let process = start_with_log(&mut node, port, Some(&log));
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let output = command(dir.path())
            .args(["node", "status", "--rpc", &format!("127.0.0.1:{port}")])
            .output()
            .unwrap();
        assert!(output.status.success());
        let status = String::from_utf8(output.stdout).unwrap();
        let height: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("height="))
            .unwrap()
            .parse()
            .unwrap();
        if height >= 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "miner did not produce two blocks"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let warnings = std::fs::read_to_string(&log).unwrap();
    assert!(warnings.contains("config mine_interval is obsolete and ignored"));
    assert!(warnings.contains("--mine-interval is obsolete and ignored"));
    drop(process);
}

#[test]
fn legacy_mining_interval_cli_rejects_invalid_values() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let result = command(dir.path())
        .args(["--mine-interval", "invalid"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("--mine-interval must be a decimal integer")
    );
}

#[test]
fn concurrent_first_commands_create_one_complete_config() {
    let dir = tempfile::tempdir().unwrap();
    prepare(dir.path());
    let mut children = Vec::new();
    for network in [
        "devnet", "testnet", "mainnet", "devnet", "testnet", "mainnet",
    ] {
        children.push(
            command(dir.path())
                .args(["node", "params", "--network", network])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for child in children {
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let text = std::fs::read_to_string(dir.path().join("vess.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&text).unwrap();
    assert_eq!(parsed["network"].as_str(), Some("devnet"));
    assert_eq!(parsed["mine"].as_bool(), Some(false));
}

#[test]
fn executable_directory_keeps_config_and_data_when_launched_elsewhere() {
    let app = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    prepare(app.path());
    let init = command(app.path())
        .current_dir(other.path())
        .args(["node", "params"])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let config_path = app.path().join("vess.toml");
    assert!(config_path.exists());
    assert!(!other.path().join("vess.toml").exists());
    let text = std::fs::read_to_string(&config_path).unwrap();
    let mut settings: toml::Value = toml::from_str(&text).unwrap();
    let port = unused_port();
    settings["rpc_port"] = i64::from(port).into();
    settings["p2p_port"] = 0.into();
    std::fs::write(&config_path, toml::to_string_pretty(&settings).unwrap()).unwrap();

    let mut bare = command(app.path());
    bare.current_dir(other.path());
    let running = start(bare, port);
    assert!(app.path().join("chain").exists());
    assert!(!other.path().join("chain").exists());
    drop(running);

    let override_data = command(app.path())
        .current_dir(other.path())
        .args(["node", "init", "--datadir", "explicit-data"])
        .output()
        .unwrap();
    assert!(
        override_data.status.success(),
        "{}",
        String::from_utf8_lossy(&override_data.stderr)
    );
    assert!(other.path().join("explicit-data").exists());
    assert!(!app.path().join("explicit-data").exists());
}

#[test]
fn previous_working_directory_config_is_never_silently_ignored() {
    let app = tempfile::tempdir().unwrap();
    let old = tempfile::tempdir().unwrap();
    prepare(app.path());
    let old_config = old.path().join("vess.toml");
    std::fs::write(
        &old_config,
        "network = \"testnet\"\ndatadir = \"./chain\"\n",
    )
    .unwrap();
    std::fs::create_dir(old.path().join("chain")).unwrap();
    let result = command(app.path())
        .current_dir(old.path())
        .args(["node", "params"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("existing working-directory config"));
    assert!(!app.path().join("vess.toml").exists());

    let opened = command(app.path())
        .current_dir(old.path())
        .args(["node", "init", "--config"])
        .arg(&old_config)
        .output()
        .unwrap();
    assert!(
        opened.status.success(),
        "{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    assert!(String::from_utf8_lossy(&opened.stdout).contains("network=1"));
    assert!(!app.path().join("chain").exists());
}

#[test]
fn existing_working_directory_data_does_not_block_portable_default() {
    let app = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    prepare(app.path());
    let existing = cwd.path().join("chain");
    std::fs::create_dir(&existing).unwrap();
    let marker = existing.join("keep.txt");
    std::fs::write(&marker, "do not modify").unwrap();

    let result = command(app.path())
        .current_dir(cwd.path())
        .args(["node", "init"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("warning: an existing data directory was found"));
    assert!(stderr.contains("This config uses"));
    assert!(app.path().join("chain").exists());
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "do not modify");
}

#[test]
fn explicit_config_anchors_data_and_protects_previous_relative_data() {
    let app = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    prepare(app.path());
    let config_dir = cwd.path().join("settings");
    std::fs::create_dir(&config_dir).unwrap();
    let config = config_dir.join("custom.toml");
    let relative_config = Path::new("settings").join("custom.toml");
    std::fs::write(&config, "network = \"devnet\"\ndatadir = \"./chain\"\n").unwrap();
    std::fs::create_dir(cwd.path().join("chain")).unwrap();

    let result = command(app.path())
        .current_dir(cwd.path())
        .args(["node", "init", "--config"])
        .arg(&relative_config)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("working-directory data path"));
    assert!(!config_dir.join("chain").exists());

    let explicit = command(app.path())
        .current_dir(cwd.path())
        .args(["node", "init", "--config"])
        .arg(&relative_config)
        .args(["--datadir", "chain"])
        .output()
        .unwrap();
    assert!(
        explicit.status.success(),
        "{}",
        String::from_utf8_lossy(&explicit.stderr)
    );
    assert!(!config_dir.join("chain").exists());
}

#[test]
fn configured_peers_and_mining_work_without_arguments() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    prepare(first.path());
    prepare(second.path());
    let mut ports = Vec::new();
    while ports.len() < 4 {
        let port = unused_port();
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    let (rpc1, p2p1, rpc2, p2p2) = (ports[0], ports[1], ports[2], ports[3]);
    let payout = "55".repeat(32);
    std::fs::write(
        first.path().join("vess.toml"),
        format!(
            "network = \"devnet\"\ndatadir = \"./chain\"\nrpc_port = {rpc1}\np2p_port = {p2p1}\nmine = true\npayout = \"{payout}\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        second.path().join("vess.toml"),
        format!(
            "network = \"devnet\"\ndatadir = \"./chain\"\nrpc_port = {rpc2}\np2p_port = {p2p2}\nseeds = [\"127.0.0.1:{p2p1}\"]\n"
        ),
    )
    .unwrap();
    let _first = start(command(first.path()), rpc1);
    let _second = start(command(second.path()), rpc2);
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let status = command(second.path())
            .args(["node", "status", "--rpc", &format!("127.0.0.1:{rpc2}")])
            .output()
            .unwrap();
        let account = command(first.path())
            .args([
                "node",
                "account",
                "--rpc",
                &format!("127.0.0.1:{rpc1}"),
                "--account",
                &payout,
            ])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(account.status.success());
        let status = String::from_utf8(status.stdout).unwrap();
        let account = String::from_utf8(account.stdout).unwrap();
        let value = |text: &str, key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };
        if value(&status, "peers_outbound=") > 0 && value(&account, "balance=") > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "configured mining or peer connection did not start"
        );
        thread::sleep(Duration::from_millis(200));
    }
}
