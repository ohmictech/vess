// Vess production miner - multi-threaded Cuckatoo27 solver with Arbitrum RPC.
// Usage: vess-miner [--config path] [--generate-config]
//
// Solo mode: solve with your own reward address, submit mints on-chain.

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
    /// Your personal wallet address (0x...) — who the contract credits.
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
    /// Number of solver threads. Each one allocates ~1.5 GB RAM (default: 1).
    #[serde(default = "default_cores")]
    cores: usize,
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
    /// Optional monitoring webhook URL (ntfy/Discord/Slack/etc). Posts JSON
    /// events on mint success, low balance, and optional heartbeat. Empty = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    webhook_url: Option<String>,
    /// Alert when the gas key ETH balance drops below this (default 0.0002).
    #[serde(default = "default_min_balance_eth")]
    min_balance_eth: f64,
    /// Periodic webhook heartbeat every N seconds (0 = off).
    #[serde(default)]
    heartbeat_secs: u64,
}

fn default_key_file() -> String {
    "miner.key".into()
}
fn default_state_file() -> String {
    "miner.json".into()
}

fn default_diff_bits() -> u32 {
    // Default 4: each accepted proof mints 2^4 = 16 VESS, diluting per-VESS
    // gas ~16x vs diff=0 (gas becomes negligible vs the electricity floor) at
    // an average ~5h cadence per find on one core.
    4
}
fn default_cores() -> usize {
    1
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
fn default_min_balance_eth() -> f64 {
    0.0002
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
            future_secs: default_future_secs(),
            stats_interval_secs: default_stats_interval(),
            gas_limit: default_gas_limit(),
            state_file: default_state_file(),
            webhook_url: None,
            min_balance_eth: default_min_balance_eth(),
            heartbeat_secs: 0,
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

/// A difficulty-passing proof queued for submission.
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

/// Fire-and-forget JSON POST to the monitoring webhook. Never blocks the
/// solver or submitter on network trouble (5s timeout, errors logged only).
fn notify(
    webhook: &Option<String>,
    event: &str,
    mut fields: serde_json::Map<String, serde_json::Value>,
) {
    let Some(url) = webhook else { return };
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    fields.insert("event".into(), serde_json::Value::String(event.into()));
    fields.insert("ts".into(), serde_json::Value::Number(now.into()));
    let body = serde_json::Value::Object(fields);
    match ureq::post(url)
        .timeout(std::time::Duration::from_secs(5))
        .send_json(body)
    {
        Ok(_) => {}
        Err(e) => eprintln!("[monitor] webhook {event} failed: {e}"),
    }
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
    webhook: Option<String>,
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
                    let mut f = serde_json::Map::new();
                    f.insert("core".into(), serde_json::json!(cid));
                    f.insert("tx".into(), serde_json::json!(hex::encode(tx_hash.0)));
                    notify(&webhook, "mint", f);
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

// ---- per-core solver context

struct CoreCtx {
    core_id: usize,
    chain_h: [u8; 32],
    addr: [u8; 32],
    diff_bits: u32,
    future_secs: u64,
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

    // payout address — credited by the contract directly
    let reward_20 = parse_hex20(&cfg.reward_address)?;
    let num_cores = cfg.cores;
    eprintln!("payout address: 0x{}", hex::encode(reward_20));

    // Load gas key, connect to RPC, check balance, then start the submitter.
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
    let webhook = cfg.webhook_url.clone();
    let submitter = {
        let pr = provider.clone();
        let ca = contract_addr;
        let gl = cfg.gas_limit;
        let wh = webhook.clone();
        std::thread::spawn(move || submit_loop(rx, pr, ca, miner_addr, gl, wh))
    };
    let mine_addr = reward_32;
    let mine_diff = cfg.diff_bits;

    eprintln!(
        "  chain={} diff={} cores={} future_secs={} stats_every={}s",
        cfg.chain, mine_diff, num_cores, cfg.future_secs, cfg.stats_interval_secs
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

    // stats reporter + monitor (balance alerts, optional heartbeat)
    let stats_shutdown = shutdown.clone();
    let stats_att = attempts.clone();
    let stats_sol = solutions.clone();
    let stats_start = start_time;
    let stats_interval = cfg.stats_interval_secs;
    let stats_cores = num_cores;
    let stats_diff = cfg.diff_bits;
    let stats_provider = provider.clone();
    let stats_gas = miner_addr;
    let stats_webhook = webhook.clone();
    let stats_min_bal = U256::from((cfg.min_balance_eth * 1e18) as u128);
    let stats_min_bal_eth = cfg.min_balance_eth;
    let stats_heartbeat = cfg.heartbeat_secs;
    let stats_handle = tokio::spawn(async move {
        let mut low_alerted = false;
        let mut last_heartbeat = Instant::now();
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
            // Balance monitor: alert once when gas runs low, re-arm on refill.
            let bal = stats_provider
                .get_balance(stats_gas)
                .await
                .unwrap_or_default();
            if bal < stats_min_bal {
                if !low_alerted {
                    let mut f = serde_json::Map::new();
                    f.insert("balance_wei".into(), serde_json::json!(bal.to_string()));
                    f.insert("min_balance_eth".into(), serde_json::json!(stats_min_bal_eth));
                    notify(&stats_webhook, "low_balance", f);
                    low_alerted = true;
                }
            } else {
                low_alerted = false;
            }
            // Optional periodic heartbeat.
            if stats_heartbeat > 0 && last_heartbeat.elapsed().as_secs() >= stats_heartbeat {
                let mut f = serde_json::Map::new();
                f.insert("attempts".into(), serde_json::json!(att));
                f.insert("solutions".into(), serde_json::json!(sol));
                f.insert("balance_wei".into(), serde_json::json!(bal.to_string()));
                notify(&stats_webhook, "heartbeat", f);
                last_heartbeat = Instant::now();
            }
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

        // The contract rejects proofs below the target difficulty, so skip
        // them locally instead of spending gas on a doomed mint.
        let passes = check_difficulty(&cuckoo::proof_to_id(&proof), ctx.diff_bits);
        if !passes {
            continue;
        }
        eprintln!("[core {}] SOLVED! nonce={current} ts={ts}", ctx.core_id);

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
                // NB: RawValue::get() keeps the JSON quotes, so hex-decoding it
                // directly always fails — extract via as_revert_data() instead.
                let reason = payload.as_revert_data().map(|bytes| decode_revert(&bytes));
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
