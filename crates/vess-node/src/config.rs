use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use vess_core::constants::{
    DEFAULT_PRUNE_BLOCKS, DEFAULT_PRUNE_HEADERS, P2P_DEFAULT_PORT, RPC_DEFAULT_PORT,
};

use crate::{Args, parse_hash};

#[derive(Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    network: String,
    datadir: String,
    rpc_port: u16,
    p2p_port: u16,
    peers: Vec<String>,
    seeds: Vec<String>,
    mine: bool,
    mine_threads: u16,
    payout: Option<String>,
    trust_snapshot: bool,
    prune_blocks: Option<u64>,
    prune_headers: Option<u64>,
    prune_undo: Option<u64>,
    finality_depth: Option<u64>,
    mine_interval: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: "devnet".into(),
            datadir: "./chain".into(),
            rpc_port: RPC_DEFAULT_PORT,
            p2p_port: P2P_DEFAULT_PORT,
            peers: Vec::new(),
            seeds: Vec::new(),
            mine: false,
            mine_threads: 1,
            payout: None,
            trust_snapshot: true,
            prune_blocks: None,
            prune_headers: None,
            prune_undo: None,
            finality_depth: None,
            mine_interval: None,
        }
    }
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if !matches!(self.network.as_str(), "devnet" | "testnet" | "mainnet") {
            return Err(format!("invalid config network: {}", self.network));
        }
        if self.datadir.is_empty() {
            return Err("config datadir must not be empty".into());
        }
        if !(1..=256).contains(&self.mine_threads) {
            return Err("config mine_threads must be between 1 and 256".into());
        }
        if let Some(payout) = &self.payout {
            parse_hash(payout).map_err(|e| format!("invalid config payout: {e}"))?;
        }
        if self.mine && self.payout.is_none() {
            return Err("config mining requires a payout address".into());
        }
        Ok(())
    }

    fn apply(&self, args: &mut Args, node_run: bool, config_dir: &Path) -> Result<(), String> {
        args.set_default("network", &self.network);
        if args.get("datadir").is_none() {
            let datadir = Path::new(&self.datadir);
            let resolved = config_dir.join(datadir);
            if datadir.is_relative() {
                let cwd = std::env::current_dir()
                    .map_err(|e| format!("cannot determine working directory: {e}"))?;
                let old_location = cwd.join(datadir);
                if !same_directory(&cwd, config_dir)?
                    && old_location.try_exists().map_err(|e| {
                        format!(
                            "cannot inspect existing data path {}: {e}",
                            old_location.display()
                        )
                    })?
                {
                    let old_location = std::fs::canonicalize(&old_location).map_err(|e| {
                        format!(
                            "cannot locate existing data path {}: {e}",
                            old_location.display()
                        )
                    })?;
                    if args.get("config").is_some() {
                        return Err(format!(
                            "the working-directory data path {} already exists; to keep using it, \
                             pass --datadir \"{}\" or set an absolute datadir in the config",
                            old_location.display(),
                            old_location.display()
                        ));
                    }
                    eprintln!(
                        "warning: an existing data directory was found at {}. \
                         This config uses {} instead; set datadir to the existing path \
                         if you want to keep using its chain and wallets.",
                        old_location.display(),
                        resolved.display()
                    );
                }
            }
            let datadir = resolved
                .to_str()
                .ok_or("config data path is not valid UTF-8")?;
            args.set_default("datadir", datadir);
        }
        if args.get("trust-snapshot").is_some() && args.get("no-trust-snapshot").is_some() {
            return Err("give only one of --trust-snapshot and --no-trust-snapshot".into());
        }
        if self.trust_snapshot && args.get("no-trust-snapshot").is_none() {
            args.set_default("trust-snapshot", "true");
        }
        if !node_run {
            return Ok(());
        }
        if args.get("mine").is_some() && args.get("no-mine").is_some() {
            return Err("give only one of --mine and --no-mine".into());
        }
        args.set_default("rpc", &self.rpc_port.to_string());
        args.set_default("port", &self.p2p_port.to_string());
        for flag in ["rpc", "port"] {
            args.require(flag)?
                .parse::<u16>()
                .map_err(|_| format!("--{flag} must be a port number (0-65535)"))?;
        }
        if !self.peers.is_empty() {
            args.set_default("peer", &self.peers.join(","));
        }
        if !self.seeds.is_empty() {
            args.set_default("seed", &self.seeds.join(","));
        }
        if self.mine && args.get("no-mine").is_none() {
            args.set_default("mine", "true");
        }
        args.set_default("mine-threads", &self.mine_threads.to_string());
        args.require_value("mine-threads")?;
        if !(1..=256).contains(&args.number("mine-threads", 1)?) {
            return Err("--mine-threads must be between 1 and 256".into());
        }
        if let Some(payout) = &self.payout {
            args.set_default("payout", payout);
        }
        for (flag, value) in [
            ("prune-blocks", self.prune_blocks),
            ("prune-headers", self.prune_headers),
            ("prune-undo", self.prune_undo),
            ("finality-depth", self.finality_depth),
        ] {
            if let Some(value) = value {
                args.set_default(flag, &value.to_string());
            }
        }
        if args.get("mine-interval").is_some() {
            args.number("mine-interval", 0)?;
            eprintln!("warning: --mine-interval is obsolete and ignored; mining no longer pauses");
        }
        if self.mine_interval.is_some() {
            eprintln!(
                "warning: config mine_interval is obsolete and ignored; mining no longer pauses"
            );
        }
        if args.get("mine").is_some() {
            parse_hash(args.require("payout")?).map_err(|e| format!("invalid payout: {e}"))?;
        }
        Ok(())
    }
}

fn same_directory(a: &Path, b: &Path) -> Result<bool, String> {
    let a = std::fs::canonicalize(a)
        .map_err(|e| format!("cannot locate directory {}: {e}", a.display()))?;
    let b = std::fs::canonicalize(b)
        .map_err(|e| format!("cannot locate directory {}: {e}", b.display()))?;
    Ok(a == b)
}

fn read(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    let config: Config =
        toml::from_str(&text).map_err(|e| format!("invalid config {}: {e}", path.display()))?;
    config.validate()?;
    Ok(config)
}

pub(super) fn configure(args: &mut Args, node_run: bool) -> Result<(), String> {
    if node_run {
        const OPTIONS: &[&str] = &[
            "config",
            "network",
            "datadir",
            "rpc",
            "port",
            "peer",
            "seed",
            "mine",
            "mine-threads",
            "no-mine",
            "payout",
            "trust-snapshot",
            "no-trust-snapshot",
            "prune-blocks",
            "prune-headers",
            "prune-undo",
            "finality-depth",
            "mine-interval",
        ];
        if let Some(name) = args
            .flags
            .keys()
            .find(|name| !OPTIONS.contains(&name.as_str()))
        {
            return Err(format!("unknown node run option --{name}"));
        }
        for flag in ["mine", "no-mine", "trust-snapshot", "no-trust-snapshot"] {
            if let Some(value) = args.get(flag)
                && value != "true"
            {
                return Err(format!("--{flag} does not take a value"));
            }
        }
    }
    if node_run && args.get("mine").is_some() && args.get("no-mine").is_some() {
        return Err("give only one of --mine and --no-mine".into());
    }
    if node_run && args.get("trust-snapshot").is_some() && args.get("no-trust-snapshot").is_some() {
        return Err("give only one of --trust-snapshot and --no-trust-snapshot".into());
    }
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine working directory: {e}"))?;
    let path = if let Some(path) = args.get("config") {
        cwd.join(path)
    } else {
        let exe =
            std::env::current_exe().map_err(|e| format!("cannot locate Vess executable: {e}"))?;
        let dir = exe
            .parent()
            .ok_or("cannot locate Vess executable directory")?;
        let path = dir.join("vess.toml");
        let previous = cwd.join("vess.toml");
        if !same_directory(&cwd, dir)?
            && previous.try_exists().map_err(|e| {
                format!("cannot inspect previous config {}: {e}", previous.display())
            })?
        {
            return Err(format!(
                "found an existing working-directory config at {}; to keep using it, \
                 pass --config {} or move it and its data to the executable directory",
                previous.display(),
                previous.display()
            ));
        }
        path
    };
    let config = match std::fs::read_to_string(&path) {
        Ok(text) => {
            let config: Config = toml::from_str(&text)
                .map_err(|e| format!("invalid config {}: {e}", path.display()))?;
            config.validate()?;
            config
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let config = Config::default();
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create config directory {}: {e}", parent.display()))?;
            let mut file = tempfile::NamedTempFile::new_in(parent)
                .map_err(|e| format!("cannot create config {}: {e}", path.display()))?;
            let text = toml::to_string_pretty(&config)
                .map_err(|e| format!("cannot encode config: {e}"))?;
            write!(
                file,
                "# Vess node settings. Do not put wallet passwords or recovery phrases here.\n\
                          # Future default seed (placeholder, inactive): seed.vess.invalid:9732\n\
                          # Add a real seed for your network to the seeds list below.\n\
                          # To mine, set mine = true and set a payout address below.\n{text}\n\
                          # Optional settings: remove the leading # to set a value.\n\
                          # payout = \"YOUR_64_CHARACTER_ACCOUNT_ADDRESS\"\n\
                          # Pruning uses the database's saved policy when these are unset.\n\
                          # Defaults below apply only if the database has no saved policy; 0 keeps all.\n\
                          # prune_blocks = {DEFAULT_PRUNE_BLOCKS}\n\
                          # prune_headers = {DEFAULT_PRUNE_HEADERS}\n"
            )
            .and_then(|_| file.flush())
            .map_err(|e| format!("cannot write config {}: {e}", path.display()))?;
            match file.persist_noclobber(&path) {
                Ok(_) => {
                    eprintln!("created config {}", path.display());
                    config
                }
                Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => read(&path)?,
                Err(e) => {
                    return Err(format!(
                        "cannot create config {}: {}",
                        path.display(),
                        e.error
                    ));
                }
            }
        }
        Err(e) => return Err(format!("cannot read config {}: {e}", path.display())),
    };
    let dir = path
        .parent()
        .ok_or_else(|| format!("invalid config path {}", path.display()))?;
    config.apply(args, node_run, dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Args {
        Args::parse(
            &values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn explicit_options_override_configured_mining_peers_and_trust() {
        let config = Config {
            network: "testnet".into(),
            mine: true,
            mine_threads: 4,
            payout: Some("12".repeat(32)),
            peers: vec!["127.0.0.1:8000".into()],
            seeds: vec!["127.0.0.1:8001".into()],
            trust_snapshot: true,
            prune_blocks: Some(500),
            ..Config::default()
        };
        config.validate().unwrap();
        let mut args = args(&[
            "--network",
            "devnet",
            "--no-mine",
            "--no-trust-snapshot",
            "--peer",
            "",
            "--prune-blocks",
            "0",
            "--mine-threads",
            "2",
        ]);
        config
            .apply(&mut args, true, &std::env::current_dir().unwrap())
            .unwrap();
        assert_eq!(args.get("network"), Some("devnet"));
        assert!(args.get("mine").is_none());
        assert!(args.get("trust-snapshot").is_none());
        assert_eq!(args.get("peer"), Some(""));
        assert_eq!(args.get("seed"), Some("127.0.0.1:8001"));
        assert_eq!(args.get("prune-blocks"), Some("0"));
        assert_eq!(args.get("mine-threads"), Some("2"));
    }

    #[test]
    fn mining_thread_count_defaults_and_validation() {
        let dir = std::env::current_dir().unwrap();
        let default: Config = toml::from_str("").unwrap();
        let mut defaults = args(&[]);
        default.validate().unwrap();
        default.apply(&mut defaults, true, &dir).unwrap();
        assert_eq!(defaults.get("mine-threads"), Some("1"));

        for value in [0, 257] {
            let config = Config {
                mine_threads: value,
                ..Config::default()
            };
            assert!(config.validate().unwrap_err().contains("mine_threads"));
        }
        let mut invalid = args(&["--mine-threads", "0"]);
        assert!(default.apply(&mut invalid, true, &dir).is_err());
        let mut invalid = args(&["--mine-threads", "257"]);
        assert!(default.apply(&mut invalid, true, &dir).is_err());
        let mut invalid = args(&["--mine-threads"]);
        assert!(default.apply(&mut invalid, true, &dir).is_err());
        let mut configured = args(&[]);
        let config = Config {
            mine_threads: 256,
            ..Config::default()
        };
        config.validate().unwrap();
        config.apply(&mut configured, true, &dir).unwrap();
        assert_eq!(configured.get("mine-threads"), Some("256"));
    }

    #[test]
    fn snapshot_trust_defaults_on_and_can_be_disabled() {
        let config: Config = toml::from_str("").unwrap();
        let dir = std::env::current_dir().unwrap();
        let mut defaults = args(&[]);
        config.apply(&mut defaults, true, &dir).unwrap();
        assert_eq!(defaults.get("trust-snapshot"), Some("true"));

        let mut override_args = args(&["--no-trust-snapshot"]);
        config.apply(&mut override_args, true, &dir).unwrap();
        assert!(override_args.get("trust-snapshot").is_none());

        let disabled: Config = toml::from_str("trust_snapshot = false").unwrap();
        let mut disabled_args = args(&[]);
        disabled.apply(&mut disabled_args, true, &dir).unwrap();
        assert!(disabled_args.get("trust-snapshot").is_none());
        let mut offline_args = args(&[]);
        disabled.apply(&mut offline_args, false, &dir).unwrap();
        assert!(offline_args.get("trust-snapshot").is_none());
        let mut offline_default = args(&[]);
        config.apply(&mut offline_default, false, &dir).unwrap();
        assert_eq!(offline_default.get("trust-snapshot"), Some("true"));
    }
}
