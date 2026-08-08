// Vess production miner - multi-threaded Cuckatoo27 solver with Arbitrum RPC.
// Usage: vess-miner [--config path] [--generate-config]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, FixedBytes, TxHash, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use alloy_sol_types::SolCall;
use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use vess_crypto::{chain_hash, cuckoo};


// ---- CLI

#[derive(Parser)]
#[command(name = "vess-miner", version, about = "Cuckatoo27 PoW miner for Vess on Arbitrum")]
struct Cli {
    #[arg(short, long, default_value = "miner.toml")]
    config: String,
    #[arg(short = 'G', long)]
    generate_config: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

// ---- config

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    chain: String,
    /// Your personal wallet address (0x...) — this is who gets the Vess rewards.
    reward_address: String,
    /// Arbitrum RPC endpoint.
    rpc_url: String,
    /// Deployed Vess contract address.
    contract_address: String,
    /// Path to miner key file (default: miner.key).
    #[serde(default = "default_key_file")]
    key_file: String,
    #[serde(default = "default_diff_bits")]
    diff_bits: u32,
    #[serde(default)]
    cores: Option<usize>,
    #[serde(default = "default_future_secs")]
    future_secs: u64,
    #[serde(default = "default_stats_interval")]
    stats_interval_secs: u64,
    #[serde(default = "default_gas_limit")]
    gas_limit: u64,
    /// Path to state file (default: miner.json next to config).
    #[serde(default = "default_state_file")]
    state_file: String,
}

fn default_key_file() -> String { "miner.key".into() }
fn default_state_file() -> String { "miner.json".into() }

fn default_diff_bits() -> u32 { 1 }
fn default_future_secs() -> u64 { 60 }
fn default_stats_interval() -> u64 { 30 }
fn default_gas_limit() -> u64 { 300_000 }

impl Default for Config {
    fn default() -> Self {
        Config {
            chain: "arbitrum".into(),
            reward_address: "0x0000000000000000000000000000000000000000".into(),
            rpc_url: "https://sepolia-rollup.arbitrum.io/rpc".into(),
            contract_address: "0x0000000000000000000000000000000000000000".into(),
            key_file: default_key_file(),
            diff_bits: default_diff_bits(),
            cores: None,
            future_secs: default_future_secs(),
            stats_interval_secs: default_stats_interval(),
            gas_limit: default_gas_limit(),
            state_file: default_state_file(),
        }
    }
}

impl Config {
    fn load_or_create(path: &str) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let cfg: Config = toml::from_str(&contents).context("parsing config")?;
                cfg.validate()?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Config::default();
                let toml_str = toml::to_string_pretty(&cfg).unwrap();
                std::fs::write(path, &toml_str).context("writing default config")?;
                eprintln!("Created default config at {}. Edit it and re-run.", path);
                std::process::exit(0);
            }
            Err(e) => Err(e).context("reading config"),
        }
    }

    fn validate(&self) -> Result<()> {
        let addr = parse_hex20(&self.reward_address)?;
        if addr == [0u8; 20] {
            anyhow::bail!("reward_address must be set (not zero)");
        }
        if self.diff_bits > 32 {
            anyhow::bail!("diff_bits must be <= 32");
        }
        if self.contract_address == "0x0000000000000000000000000000000000000000" {
            anyhow::bail!("contract_address must be set");
        }
        Ok(())
    }

    /// Load or generate the miner gas key. Returns (signer, address).
    fn load_miner_key(key_file: &str) -> Result<(PrivateKeySigner, Address)> {
        match std::fs::read_to_string(key_file) {
            Ok(hex_key) => {
                let hex_key = hex_key.trim();
                let signer: PrivateKeySigner = hex_key.parse()
                    .context("invalid miner key in key file")?;
                let addr = signer.address();
                Ok((signer, addr))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let signer = PrivateKeySigner::random();
                let addr = signer.address();
                let addr_hex = format!("0x{}", hex::encode(addr.0));
                let hex_key = hex::encode(signer.to_bytes());
                std::fs::write(key_file, &hex_key).context("writing miner key file")?;
                // Also write the address to a companion .address file for easy funding
                let addr_file = key_file.replace(".key", ".address");
                std::fs::write(&addr_file, &addr_hex).context("writing address file")?;
                eprintln!("Generated new miner gas key.");
                eprintln!("  Key saved to: {key_file}");
                eprintln!("  Address file: {addr_file}");
                eprintln!("  Fund this address with ETH: {addr_hex}");
                Ok((signer, addr))
            }
            Err(e) => Err(e).context("reading key file"),
        }
    }
}


// ---- ABI

alloy_sol_types::sol! {
    function mint(
        bytes32 chain_hash,
        uint32 diff_bits,
        bytes32 address,
        uint64 timestamp,
        uint64 nonce,
        bytes calldata proof
    ) external returns (bool);
}

// ---- helpers

// ---- state persistence

#[derive(Serialize, Deserialize, Default)]
struct MinerState {
    nonces: HashMap<String, u64>,  // core_id → last nonce
}

fn load_state(path: &str) -> MinerState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(path: &str, state: &MinerState) {
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(path, json);
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn parse_hex20(s: &str) -> Result<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 20, "must be 20 bytes");
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}


// ---- main

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.generate_config {
        let toml_str = toml::to_string_pretty(&Config::default()).unwrap();
        std::fs::write(&cli.config, &toml_str).context("writing config")?;
        eprintln!("Wrote default config to {}", cli.config);
        return Ok(());
    }

    let cfg = Config::load_or_create(&cli.config)?;
    let chain_h = chain_hash(&cfg.chain);

    // load or generate miner gas key (NOT the reward address)
    let (signer, miner_addr) = Config::load_miner_key(&cfg.key_file)?;

    // reward address — where the Vess go, committed into the preimage
    let reward_20 = parse_hex20(&cfg.reward_address)?;
    let mut reward_32 = [0u8; 32];
    reward_32[..20].copy_from_slice(&reward_20);
    let num_cores = cfg.cores.unwrap_or_else(num_cpus);

    eprintln!("reward address: 0x{}", hex::encode(reward_20));
    eprintln!("miner gas addr: 0x{}", hex::encode(miner_addr.0));
    eprintln!("  key file: {} (keep secret)", cfg.key_file);
    eprintln!("  address file: {} (copy this to fund gas)", cfg.key_file.replace(".key", ".address"));

    // connect to RPC
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&cfg.rpc_url)
        .await
        .context("connecting to RPC")?;

    let chain_id = provider.get_chain_id().await.context("fetching chain id")?;
    eprintln!("connected: chain_id={} rpc={}", chain_id, cfg.rpc_url);
    let balance = provider.get_balance(miner_addr).await.unwrap_or_default();
    let contract_addr: Address = cfg.contract_address.parse()?;
    eprintln!("  miner balance={} wei", balance);

    // Arbitrum gas is cheap (~0.01-0.1 gwei) but you still need some ETH.
    // Warn if below 0.001 ETH, error if below 0.0001 ETH.
    let min_safe = U256::from(1_000_000_000_000_000u64);  // 0.001 ETH
    let min_abs = U256::from(100_000_000_000_000u64);       // 0.0001 ETH
    if balance < min_abs {
        anyhow::bail!(
            "ETH balance too low ({balance} wei). Need at least ~0.0001 ETH for gas. \
             Fund 0x{} on Arbitrum.",
            hex::encode(miner_addr.0)
        );
    }
    if balance < min_safe {
        eprintln!("  WARNING: low ETH balance ({balance} wei). Mining will stop when gas runs out.");
    }
    eprintln!("  chain={} diff={} cores={} gas_limit={} future_secs={} stats_every={}s",
        cfg.chain, cfg.diff_bits, num_cores, cfg.gas_limit, cfg.future_secs, cfg.stats_interval_secs);

    // shared state — shutdown is only for Ctrl+C, solutions_counted for stats
    let shutdown = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let solutions = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();

    // load saved nonces from previous run
    let state_path = cfg.state_file.clone();
    let saved = load_state(&state_path);
    let mut core_nonces: Vec<Arc<AtomicU64>> = Vec::with_capacity(num_cores);
    for core_id in 0..num_cores {
        let key = core_id.to_string();
        let start_nonce = saved.nonces.get(&key).copied()
            .unwrap_or((core_id as u64) << 48);
        core_nonces.push(Arc::new(AtomicU64::new(start_nonce)));
        if saved.nonces.contains_key(&key) {
            eprintln!("  core {core_id} resuming from nonce {}", start_nonce);
        }
    }

    // background state saver
    let save_nonces: Vec<Arc<AtomicU64>> = core_nonces.iter().map(Arc::clone).collect();
    let save_shutdown = shutdown.clone();
    let save_path = state_path.clone();
    let save_handle = tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            if save_shutdown.load(Ordering::Relaxed) { break; }
            let mut state = MinerState::default();
            for (i, n) in save_nonces.iter().enumerate() {
                state.nonces.insert(i.to_string(), n.load(Ordering::Relaxed));
            }
            save_state(&save_path, &state);
        }
        // final save on shutdown
        let mut state = MinerState::default();
        for (i, n) in save_nonces.iter().enumerate() {
            state.nonces.insert(i.to_string(), n.load(Ordering::Relaxed));
        }
        save_state(&save_path, &state);
    });

    // stats reporter (doesn't stop on solutions — runs until shutdown)
    let stats_shutdown = shutdown.clone();
    let stats_att = attempts.clone();
    let stats_sol = solutions.clone();
    let stats_start = start_time;
    let stats_interval = cfg.stats_interval_secs;
    let stats_cores = num_cores;
    let stats_diff = cfg.diff_bits;
    let stats_handle = tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(stats_interval)).await;
            if stats_shutdown.load(Ordering::Relaxed) { break; }
            let att = stats_att.load(Ordering::Relaxed);
            let sol = stats_sol.load(Ordering::Relaxed);
            let elapsed = stats_start.elapsed().as_secs_f64();
            let rate = att as f64 / elapsed.max(0.001);
            eprintln!("[stats] {} attempts | {:.0} h/s | {} sols | {} cores | diff={}",
                att, rate, sol, stats_cores, stats_diff);
        }
    });

    // launch solver threads
    let provider = Arc::new(provider);
    let mut handles = Vec::new();
    for core_id in 0..num_cores {
        let pr = provider.clone();
        let sd = shutdown.clone();
        let at = attempts.clone();
        let so = solutions.clone();
        let nc = core_nonces[core_id].clone();
        let ch = chain_h;
        let ad = reward_32;
        let ca = contract_addr;
        let sgn = miner_addr;
        let gl = cfg.gas_limit;
        handles.push(std::thread::spawn(move || {
            mine_core(core_id, ch, ad, cfg.diff_bits, cfg.future_secs,
                sd, at, so, nc, pr, ca, sgn, gl);
        }));
    }

    // Ctrl+C handler
    let ctrlc = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("\nshutting down...");
        ctrlc.store(true, Ordering::Relaxed);
    });

    for h in handles { h.join().unwrap(); }
    stats_handle.abort();
    let elapsed = start_time.elapsed().as_secs_f64();
    let total = attempts.load(Ordering::Relaxed);
    let sols = solutions.load(Ordering::Relaxed);
    eprintln!("done. {} attempts, {} solutions in {:.1}s ({:.0} hash/s)",
        total, sols, elapsed, total as f64 / elapsed.max(0.001));
    Ok(())
}


// ---- per-core solver

fn mine_core(
    core_id: usize,
    chain_h: [u8; 32],
    addr: [u8; 32],
    diff_bits: u32,
    future_secs: u64,
    shutdown: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
    solutions: Arc<AtomicU64>,
    nonce: Arc<AtomicU64>,
    provider: Arc<impl Provider + Send + Sync + 'static>,
    contract_addr: Address,
    signer_addr: Address,
    gas_limit: u64,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().expect("tokio runtime");

    loop {
        if shutdown.load(Ordering::Relaxed) { break; }

        let current = nonce.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ts = now + future_secs;
        let header = cuckoo::mint_header(&chain_h, diff_bits, &addr, ts, current);
        let proof = match cuckoo::solve(&header, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
            Some(p) => p,
            None => {
                attempts.fetch_add(1, Ordering::Relaxed);
                nonce.store(current.saturating_add(1), Ordering::Relaxed);
                continue;
            }
        };

        solutions.fetch_add(1, Ordering::Relaxed);
        nonce.store(current.saturating_add(1), Ordering::Relaxed);
        eprintln!("[core {core_id}] SOLVED! nonce={current} ts={ts}");

        if !cuckoo::verify(&header, &proof, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
            eprintln!("[core {core_id}] local verify FAILED — bug?");
            continue;
        }

        // encode proof
        let mut proof_bytes = Vec::with_capacity(cuckoo::CYCLE_LENGTH * 4);
        for n in &proof { proof_bytes.extend_from_slice(&n.to_le_bytes()); }

        let call = mintCall {
            chain_hash: FixedBytes(chain_h), diff_bits,
            address: FixedBytes(addr), timestamp: ts, nonce: current,
            proof: proof_bytes.into(),
        };

        // fire-and-forget: submit async, keep mining immediately
        let pr = provider.clone();
        let ca = contract_addr;
        let sgn = signer_addr;
        let cid = core_id;
        rt.spawn(async move {
            match submit_mint(&*pr, ca, sgn, &call, gas_limit).await {
                Ok(tx_hash) => {
                    eprintln!("[core {cid}] SUBMITTED! tx=0x{}", hex::encode(tx_hash.0));
                }
                Err(e) => {
                    eprintln!("[core {cid}] submit failed: {e:#}");
                }
            }
        });

        // continue mining immediately — next nonce already set
    }
}

// ---- RPC submit

async fn submit_mint(
    provider: &(impl Provider + Send + Sync),
    contract: Address,
    from: Address,
    call: &mintCall,
    gas_limit: u64,
) -> Result<TxHash> {
    let nonce = provider.get_transaction_count(from).await.context("fetching nonce")?;

    let calldata = call.abi_encode();
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract).from(from).nonce(nonce).gas_limit(gas_limit)
        .input(calldata.into());

    let pending = provider.send_transaction(tx).await.context("sending tx")?;
    let tx_hash = *pending.tx_hash();
    eprintln!("  tx sent, waiting for confirmation...");
    let receipt = pending.get_receipt().await.context("waiting for receipt")?;
    if receipt.status() {
        eprintln!("  confirmed in block {}", receipt.block_number.unwrap_or_default());
        Ok(tx_hash)
    } else {
        anyhow::bail!("transaction reverted")
    }
}
