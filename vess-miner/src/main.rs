// Vess production miner - multi-threaded Cuckatoo27 solver with Arbitrum RPC.
// Usage: vess-miner [--config path] [--generate-config]
//
// Two modes:
//   solo (default) — solve with your own reward address, submit mints on-chain
//   pool         — solve with the pool's address, submit shares over JSON-RPC

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use vess_crypto::{chain_hash, check_difficulty, cuckoo};

// ---- CLI

#[derive(Parser)]
#[command(
    name = "vess-miner",
    version,
    about = "Cuckatoo27 PoW miner for Vess on Arbitrum"
)]
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
    /// Your personal wallet address (0x...). Solo mode: who the contract credits.
    /// Pool mode: your payout address, sent to the pool with each share.
    reward_address: String,
    /// Arbitrum RPC endpoint (solo mode only).
    rpc_url: String,
    /// Deployed Vess contract address (solo mode only).
    contract_address: String,
    /// Path to miner key file (default: miner.key, solo mode only).
    #[serde(default = "default_key_file")]
    key_file: String,
    #[serde(default = "default_diff_bits")]
    diff_bits: u32,
    /// Number of solver threads. Each one allocates ~1.5 GB RAM (default: 1).
    #[serde(default = "default_cores")]
    cores: usize,
    /// Pool mining: solve with the pool's address, submit shares over RPC.
    /// Unadvertised for now — not shown in generated configs (see skip rules).
    #[serde(default, skip_serializing_if = "is_false")]
    pool: bool,
    /// Pool JSON-RPC endpoint (used when pool = true).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pool_rpc: String,
    /// Proof acceptance window in seconds, baked into the preimage timestamp
    /// (default: 47h — just under the contract's 48h cap).
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

fn default_key_file() -> String {
    "miner.key".into()
}
fn default_state_file() -> String {
    "miner.json".into()
}

fn default_diff_bits() -> u32 {
    1
}
fn default_cores() -> usize {
    1
}
fn default_pool_rpc() -> String {
    String::new() // hidden until set explicitly — keeps pool mode out of generated configs
}
fn is_false(b: &bool) -> bool {
    !*b
}
fn default_future_secs() -> u64 {
    // The timestamp is the mint's acceptance window: the contract accepts the
    // proof until this timestamp passes, and rejects timestamps more than 48h
    // ahead of the block timestamp. Stay 1h under the cap so block-timestamp
    // lag can't reject a fresh proof.
    47 * 3600
}
fn default_stats_interval() -> u64 {
    30
}
fn default_gas_limit() -> u64 {
    300_000
}

impl Default for Config {
    fn default() -> Self {
        Config {
            chain: "arbitrum".into(),
            reward_address: "0x0000000000000000000000000000000000000000".into(),
            rpc_url: "https://sepolia-rollup.arbitrum.io/rpc".into(),
            contract_address: "0x0000000000000000000000000000000000000000".into(),
            key_file: default_key_file(),
            diff_bits: default_diff_bits(),
            cores: default_cores(),
            pool: false,
            pool_rpc: default_pool_rpc(),
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
        if self.cores == 0 {
            anyhow::bail!("cores must be >= 1");
        }
        if self.pool {
            if self.pool_rpc.trim().is_empty() {
                anyhow::bail!("pool_rpc must be set when pool = true");
            }
        } else if self.contract_address == "0x0000000000000000000000000000000000000000" {
            anyhow::bail!("contract_address must be set (solo mode)");
        }
        Ok(())
    }

    /// Load or generate the miner gas key. Returns (signer, address).
    fn load_miner_key(key_file: &str) -> Result<(PrivateKeySigner, Address)> {
        match std::fs::read_to_string(key_file) {
            Ok(hex_key) => {
                let hex_key = hex_key.trim();
                let signer: PrivateKeySigner =
                    hex_key.parse().context("invalid miner key in key file")?;
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
        uint32[42] proof
    ) external returns (bool);
}

// ---- state persistence

#[derive(Serialize, Deserialize, Default)]
struct MinerState {
    nonces: HashMap<String, u64>, // core_id → last nonce
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

fn snapshot_nonces(nonces: &[Arc<AtomicU64>], path: &str) {
    let mut state = MinerState::default();
    for (i, n) in nonces.iter().enumerate() {
        state
            .nonces
            .insert(i.to_string(), n.load(Ordering::Relaxed));
    }
    save_state(path, &state);
}

// ---- helpers

fn parse_hex20(s: &str) -> Result<[u8; 20]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).context("invalid hex")?;
    anyhow::ensure!(bytes.len() == 20, "must be 20 bytes");
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---- submission pipeline

/// A difficulty-passing proof queued for submission (chain or pool).
struct Submission {
    core_id: usize,
    call: mintCall,
}

enum SubmitError {
    /// The transaction was mined but reverted — retrying would burn gas again.
    Reverted,
    /// Transport/nonce/receipt failure — worth retrying.
    Failed(anyhow::Error),
}

const MAX_SUBMIT_ATTEMPTS: u32 = 3;

/// Single submitter loop. Serializes transactions so nonces never race, and
/// waits for receipts so failed mints are logged instead of silently dropped.
/// Runs until every solver thread has exited and dropped its sender.
fn submit_loop(
    rx: mpsc::Receiver<Submission>,
    provider: Arc<impl Provider>,
    contract_addr: Address,
    signer_addr: Address,
    gas_limit: u64,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    while let Ok(sub) = rx.recv() {
        let cid = sub.core_id;
        for attempt in 1..=MAX_SUBMIT_ATTEMPTS {
            let result = rt.block_on(submit_mint(
                &*provider,
                contract_addr,
                signer_addr,
                &sub.call,
                gas_limit,
            ));
            match result {
                Ok(tx_hash) => {
                    eprintln!("[core {cid}] SUBMITTED! tx=0x{}", hex::encode(tx_hash.0));
                    break;
                }
                Err(SubmitError::Reverted) => {
                    eprintln!(
                        "[core {cid}] mint reverted on-chain (proof already claimed or stale)"
                    );
                    break;
                }
                Err(SubmitError::Failed(e)) => {
                    eprintln!(
                        "[core {cid}] submit failed (attempt {attempt}/{MAX_SUBMIT_ATTEMPTS}): {e:#}"
                    );
                    if attempt < MAX_SUBMIT_ATTEMPTS {
                        rt.block_on(sleep(Duration::from_secs(2)));
                    }
                }
            }
        }
    }
}

// ---- pool RPC client

enum PoolError {
    /// Connection/transport failure — worth retrying.
    Transport(anyhow::Error),
    /// The pool answered but rejected the share — deterministic, don't retry.
    Remote(String),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Transport(e) => write!(f, "transport: {e:#}"),
            PoolError::Remote(m) => write!(f, "pool: {m}"),
        }
    }
}

/// Tiny JSON-RPC 2.0 over HTTP POST (plain http only — point it at pools you trust).
async fn pool_rpc_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> std::result::Result<serde_json::Value, PoolError> {
    let addr = url
        .strip_prefix("http://")
        .unwrap_or(url)
        .trim_end_matches('/');
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    })
    .to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let transport = |e: anyhow::Error| PoolError::Transport(e);
    let mut stream = TcpStream::connect(addr)
        .await
        .context("connecting to pool")
        .map_err(transport)?;
    stream
        .write_all(req.as_bytes())
        .await
        .context("writing request")
        .map_err(transport)?;
    let mut resp = Vec::new();
    stream
        .read_to_end(&mut resp)
        .await
        .context("reading response")
        .map_err(transport)?;

    let text = String::from_utf8_lossy(&resp);
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200") {
        return Err(transport(anyhow::anyhow!(
            "pool HTTP error: {}",
            text.lines().next().unwrap_or("<empty>")
        )));
    }
    let split = text
        .find("\r\n\r\n")
        .ok_or_else(|| transport(anyhow::anyhow!("malformed pool response")))?;
    let json: serde_json::Value = serde_json::from_str(text[split + 4..].trim())
        .map_err(|e| transport(anyhow::Error::new(e).context("parsing pool response")))?;
    if let Some(err) = json.get("error") {
        return Err(PoolError::Remote(err.to_string()));
    }
    Ok(json
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

/// Fetch the pool's public address — miners bind it into the mint preimage.
/// Fetch the pool's public address and its mandated share difficulty.
async fn pool_get_address(url: &str) -> Result<([u8; 20], Option<u32>)> {
    let r = pool_rpc_call(url, "getAddress", serde_json::json!({}))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let s = r
        .get("address")
        .and_then(|a| a.as_str())
        .context("pool returned no address")?;
    let addr = parse_hex20(s).context("parsing pool address")?;
    let diff_bits = r
        .get("diff_bits")
        .and_then(|d| d.as_u64())
        .map(|d| d as u32);
    Ok((addr, diff_bits))
}

/// Pool-mode submitter: ships each share to the pool over RPC.
fn pool_submit_loop(rx: mpsc::Receiver<Submission>, pool_rpc: String, payout: [u8; 20]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let payout_hex = format!("0x{}", hex::encode(payout));

    while let Ok(sub) = rx.recv() {
        let cid = sub.core_id;
        let mut proof_bytes = Vec::with_capacity(cuckoo::CYCLE_LENGTH * 4);
        for n in &sub.call.proof {
            proof_bytes.extend_from_slice(&n.to_le_bytes());
        }
        let params = serde_json::json!({
            "payout_address": payout_hex,
            "chain_hash": format!("0x{}", hex::encode(sub.call.chain_hash.0)),
            "diff_bits": sub.call.diff_bits,
            "address": format!("0x{}", hex::encode(sub.call.address.0)),
            "timestamp": sub.call.timestamp,
            "nonce": sub.call.nonce,
            "proof": format!("0x{}", hex::encode(&proof_bytes)),
        });
        for attempt in 1..=MAX_SUBMIT_ATTEMPTS {
            match rt.block_on(pool_rpc_call(&pool_rpc, "submitMint", params.clone())) {
                Ok(r) => {
                    eprintln!("[core {cid}] pool accepted share: {r}");
                    break;
                }
                Err(PoolError::Remote(e)) => {
                    eprintln!("[core {cid}] pool rejected share: {e}");
                    break;
                }
                Err(PoolError::Transport(e)) => {
                    eprintln!(
                        "[core {cid}] pool unreachable (attempt {attempt}/{MAX_SUBMIT_ATTEMPTS}): {e:#}"
                    );
                    if attempt < MAX_SUBMIT_ATTEMPTS {
                        rt.block_on(sleep(Duration::from_secs(2)));
                    }
                }
            }
        }
    }
}

// ---- per-core solver context

struct CoreCtx {
    core_id: usize,
    chain_h: [u8; 32],
    addr: [u8; 32],
    diff_bits: u32,
    future_secs: u64,
    /// Pool mode: submit every valid solve as a share, not just
    /// difficulty-passing ones.
    submit_all: bool,
    shutdown: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
    solutions: Arc<AtomicU64>,
    nonce: Arc<AtomicU64>,
    tx: mpsc::Sender<Submission>,
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

    // payout address — solo mode: credited by the contract directly;
    // pool mode: sent to the pool with each share for the payout ledger
    let reward_20 = parse_hex20(&cfg.reward_address)?;
    let num_cores = cfg.cores;
    eprintln!("payout address: 0x{}", hex::encode(reward_20));

    // Mode-dependent setup: the preimage address + difficulty + the submitter
    // thread. Pool mode needs no gas key, no chain RPC, no ETH — and every
    // valid solve is submitted as a share (the pool filters for mintable ones).
    let (mine_addr, mine_diff, submit_all, tx, submitter) = if cfg.pool {
        let (pool_addr, pool_diff) = pool_get_address(&cfg.pool_rpc)
            .await
            .context("fetching pool address")?;
        let mut a = [0u8; 32];
        a[..20].copy_from_slice(&pool_addr);
        let diff = pool_diff.unwrap_or(cfg.diff_bits);
        eprintln!(
            "pool mode: {} pool addr 0x{} diff={}",
            cfg.pool_rpc,
            hex::encode(pool_addr),
            diff
        );

        let (tx, rx) = mpsc::channel::<Submission>();
        let url = cfg.pool_rpc.clone();
        let submitter = std::thread::spawn(move || pool_submit_loop(rx, url, reward_20));
        (a, diff, true, tx, submitter)
    } else {
        // solo mode: load gas key, connect to RPC, check balance
        let (signer, miner_addr) = Config::load_miner_key(&cfg.key_file)?;
        let mut reward_32 = [0u8; 32];
        reward_32[..20].copy_from_slice(&reward_20);

        eprintln!("miner gas addr: 0x{}", hex::encode(miner_addr.0));
        eprintln!("  key file: {} (keep secret)", cfg.key_file);
        eprintln!(
            "  address file: {} (copy this to fund gas)",
            cfg.key_file.replace(".key", ".address")
        );

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
        let min_safe = U256::from(1_000_000_000_000_000u64); // 0.001 ETH
        let min_abs = U256::from(100_000_000_000_000u64); // 0.0001 ETH
        if balance < min_abs {
            anyhow::bail!(
                "ETH balance too low ({balance} wei). Need at least ~0.0001 ETH for gas. \
                 Fund 0x{} on Arbitrum.",
                hex::encode(miner_addr.0)
            );
        }
        if balance < min_safe {
            eprintln!(
                "  WARNING: low ETH balance ({balance} wei). Mining will stop when gas runs out."
            );
        }

        let (tx, rx) = mpsc::channel::<Submission>();
        let provider = Arc::new(provider);
        let submitter = {
            let pr = provider.clone();
            let ca = contract_addr;
            let gl = cfg.gas_limit;
            std::thread::spawn(move || submit_loop(rx, pr, ca, miner_addr, gl))
        };
        (reward_32, cfg.diff_bits, false, tx, submitter)
    };

    eprintln!(
        "  chain={} diff={} cores={} pool={} future_secs={} stats_every={}s",
        cfg.chain, mine_diff, num_cores, cfg.pool, cfg.future_secs, cfg.stats_interval_secs
    );
    eprintln!(
        "  solver memory: ~{:.1} GB ({} core{} × ~1.5 GB)",
        num_cores as f64 * 1.5,
        num_cores,
        if num_cores == 1 { "" } else { "s" }
    );

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
        let start_nonce = saved
            .nonces
            .get(&key)
            .copied()
            .unwrap_or((core_id as u64) << 48);
        core_nonces.push(Arc::new(AtomicU64::new(start_nonce)));
        if saved.nonces.contains_key(&key) {
            eprintln!("  core {core_id} resuming from nonce {}", start_nonce);
        }
    }

    // background state saver (final save happens in main after threads join)
    let save_nonces: Vec<Arc<AtomicU64>> = core_nonces.iter().map(Arc::clone).collect();
    let save_shutdown = shutdown.clone();
    let save_path = state_path.clone();
    let save_handle = tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(30)).await;
            if save_shutdown.load(Ordering::Relaxed) {
                break;
            }
            snapshot_nonces(&save_nonces, &save_path);
        }
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
            if stats_shutdown.load(Ordering::Relaxed) {
                break;
            }
            let att = stats_att.load(Ordering::Relaxed);
            let sol = stats_sol.load(Ordering::Relaxed);
            let elapsed = stats_start.elapsed().as_secs_f64();
            let rate = att as f64 / elapsed.max(0.001);
            eprintln!(
                "[stats] {} attempts | {:.0} h/s | {} sols | {} cores | diff={}",
                att, rate, sol, stats_cores, stats_diff
            );
        }
    });

    // launch solver threads
    let mut handles = Vec::new();
    for (core_id, nc) in core_nonces.iter().enumerate() {
        let ctx = CoreCtx {
            core_id,
            chain_h,
            addr: mine_addr,
            diff_bits: mine_diff,
            future_secs: cfg.future_secs,
            submit_all,
            shutdown: shutdown.clone(),
            attempts: attempts.clone(),
            solutions: solutions.clone(),
            nonce: nc.clone(),
            tx: tx.clone(),
        };
        handles.push(std::thread::spawn(move || mine_core(ctx)));
    }
    drop(tx); // channel closes once every solver thread has exited

    // Ctrl+C handler
    let ctrlc = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("\nshutting down...");
        ctrlc.store(true, Ordering::Relaxed);
    });

    for h in handles {
        h.join().unwrap();
    }
    submitter.join().unwrap(); // returns once the queue is drained
    stats_handle.abort();
    save_handle.abort();

    // final state save
    snapshot_nonces(&core_nonces, &state_path);

    let elapsed = start_time.elapsed().as_secs_f64();
    let total = attempts.load(Ordering::Relaxed);
    let sols = solutions.load(Ordering::Relaxed);
    eprintln!(
        "done. {} attempts, {} solutions in {:.1}s ({:.0} hash/s)",
        total,
        sols,
        elapsed,
        total as f64 / elapsed.max(0.001)
    );
    Ok(())
}

// ---- per-core solver

fn mine_core(ctx: CoreCtx) {
    loop {
        if ctx.shutdown.load(Ordering::Relaxed) {
            break;
        }

        let current = ctx.nonce.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = now + ctx.future_secs;
        let header = cuckoo::mint_header(&ctx.chain_h, ctx.diff_bits, &ctx.addr, ts, current);
        ctx.attempts.fetch_add(1, Ordering::Relaxed);

        let proof = match cuckoo::solve(&header, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
            Some(p) => p,
            None => {
                ctx.nonce
                    .store(current.saturating_add(1), Ordering::Relaxed);
                continue;
            }
        };

        ctx.solutions.fetch_add(1, Ordering::Relaxed);
        ctx.nonce
            .store(current.saturating_add(1), Ordering::Relaxed);

        if !cuckoo::verify(&header, &proof, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
            eprintln!("[core {}] local verify FAILED — bug?", ctx.core_id);
            continue;
        }

        // Solo mode: the contract rejects proofs below the target difficulty,
        // so skip them locally instead of spending gas on a doomed mint.
        // Pool mode: every valid solve is a share — the pool tracks them for
        // pro-rata payouts and submits the difficulty-passing ones on-chain.
        let passes = check_difficulty(&cuckoo::proof_to_id(&proof), ctx.diff_bits);
        if !passes && !ctx.submit_all {
            continue;
        }
        if passes {
            eprintln!("[core {}] SOLVED! nonce={current} ts={ts}", ctx.core_id);
        } else {
            eprintln!("[core {}] share nonce={current} ts={ts}", ctx.core_id);
        }

        // encode proof as a fixed uint32[42] array (LE bytes are NOT used —
        // the contract now takes the nonces directly, not packed bytes)
        let proof_arr: [u32; cuckoo::CYCLE_LENGTH] = proof
            .as_slice()
            .try_into()
            .expect("solver must return exactly CYCLE_LENGTH nonces");

        let call = mintCall {
            chain_hash: FixedBytes(ctx.chain_h),
            diff_bits: ctx.diff_bits,
            address: FixedBytes(ctx.addr),
            timestamp: ts,
            nonce: current,
            proof: proof_arr,
        };

        // hand off to the single submitter thread, keep mining immediately
        if ctx
            .tx
            .send(Submission {
                core_id: ctx.core_id,
                call,
            })
            .is_err()
        {
            eprintln!("[core {}] submitter gone — dropping solution", ctx.core_id);
        }
    }
}

// ---- RPC submit

/// Decode `Error(string)` or raw revert bytes into a readable string.
fn decode_revert(data: &[u8]) -> String {
    if data.len() >= 4 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if data.len() >= 68 {
            let len = u32::from_be_bytes(data[36..40].try_into().unwrap()) as usize;
            let start = 68;
            if start + len <= data.len() {
                return String::from_utf8_lossy(&data[start..start + len]).to_string();
            }
        }
        format!("Error(string) with {} bytes", data.len())
    } else if data.is_empty() {
        "empty revert data".into()
    } else {
        // Stylus `Result<T, Vec<u8>>` errors are raw bytes.
        String::from_utf8_lossy(data).into_owned()
    }
}

async fn submit_mint(
    provider: &impl Provider,
    contract: Address,
    from: Address,
    call: &mintCall,
    gas_limit: u64,
) -> std::result::Result<TxHash, SubmitError> {
    let nonce = provider
        .get_transaction_count(from)
        .await
        .context("fetching nonce")
        .map_err(SubmitError::Failed)?;

    let calldata = call.abi_encode();
    let tx = alloy::rpc::types::TransactionRequest::default()
        .to(contract)
        .from(from)
        .nonce(nonce)
        .gas_limit(gas_limit)
        .input(calldata.into());
    let tx_clone = tx.clone();

    let pending = provider
        .send_transaction(tx)
        .await
        .context("sending tx")
        .map_err(SubmitError::Failed)?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending
        .get_receipt()
        .await
        .context("waiting for receipt")
        .map_err(SubmitError::Failed)?;
    if receipt.status() {
        eprintln!(
            "  confirmed in block {}",
            receipt.block_number.unwrap_or_default()
        );
        Ok(tx_hash)
    } else {
        // Replay via eth_call to surface the real revert reason.
        match provider.call(tx_clone).await {
            Ok(_) => eprintln!("  (replay call unexpectedly succeeded)"),
            Err(alloy::transports::RpcError::ErrorResp(payload)) => {
                let reason = payload.data.as_ref().map(|raw| {
                    let hex_str = raw.get();
                    let bytes =
                        hex::decode(hex_str.trim_start_matches("0x")).unwrap_or_default();
                    decode_revert(&bytes)
                });
                eprintln!(
                    "  on-chain revert: {}",
                    reason.unwrap_or_else(|| payload.message.to_string())
                );
            }
            Err(e) => eprintln!("  revert reason unavailable: {e:?}"),
        }
        Err(SubmitError::Reverted)
    }
}
