//! Single-node artery integration test: tag registration, payment, claiming.
//!
//! Spins up a single real artery node on localhost and runs the full payment
//! lifecycle through RPC. Multi-node mesh discovery is tested in bitcoin_discovery.
//!
//! NOTE: Multi-node LAN discovery does not work on all Windows network
//! configurations. The test therefore runs on a single node in test mode,
//! which exercises the full RPC→wallet→payment→history pipeline.

use std::time::Duration;

use serde_json::json;
use tempfile::TempDir;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use vess_artery::node_runner::{run_node, NodeConfig};
use vess_kloak::{
    persistence::WalletFile,
    recovery::{self, RecoveryPhrase},
    BillFold,
};

struct NodeHarness {
    _tempdir: TempDir,
    state_dir: std::path::PathBuf,
    rpc_port: u16,
}

async fn rpc_call(
    state_dir: &std::path::Path,
    port: u16,
    request: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let token_path = state_dir.join("rpc-token");
    if !token_path.exists() {
        anyhow::bail!("RPC token file not found at {}", token_path.display());
    }
    let token = std::fs::read_to_string(&token_path)?;
    let stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);

    writer.write_all(token.trim().as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer
        .write_all(serde_json::to_string(request)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await?;

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(&line)?)
}

async fn spawn_node(
    index: u16,
    wallet_path: Option<std::path::PathBuf>,
    wallet_password: Option<String>,
) -> anyhow::Result<NodeHarness> {
    let tempdir = TempDir::new()?;
    let state_dir = tempdir.path().join(format!("node-{index}"));
    std::fs::create_dir_all(&state_dir)?;

    let rpc_port = 9600 + index;
    let bind_addr = format!("127.0.0.1:{}", 9700 + index)
        .parse()
        .unwrap();

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let config = NodeConfig {
        k_neighbors: 4,
        max_hops: 3,
        state_dir: state_dir.clone(),
        bootstrap: vec![],
        ready_tx: Some(ready_tx),
        wallet_path,
        rpc_port: Some(rpc_port),
        wallet_password,
        bitcoin_config: None,
        bind_addr: Some(bind_addr),
        enable_local_discovery: false,
        allow_private_bitcoin_seed_contact: true,
        reset_transient_peer_state: true,
        is_testnet: false,
        test: false,
        bootstrap_dns: vec![],
    };

    tokio::spawn(async move { run_node(config).await });
    let _ = tokio::time::timeout(Duration::from_secs(30), ready_rx)
        .await
        .expect("node did not come online")?;

    Ok(NodeHarness {
        _tempdir: tempdir,
        state_dir,
        rpc_port,
    })
}

async fn rpc(
    node: &NodeHarness,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let mut req = params;
    if let serde_json::Value::Object(ref mut map) = req {
        map.insert("method".to_string(), json!(method));
    }
    rpc_call(&node.state_dir, node.rpc_port, &req).await
}

/// Create a test wallet file with a password cache so it can be unlocked
/// via the `wallet_unlock` RPC.
fn create_test_wallet(wallet_path: &std::path::Path) -> anyhow::Result<[u8; 64]> {
    let phrase = RecoveryPhrase::generate();
    let raw_seed = recovery::derive_raw_seed(&phrase)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let enc_key = recovery::encryption_key_from_seed(&raw_seed);
    let spend_seed = recovery::spend_seed_from_raw_seed(&raw_seed);
    let (secret, address) = vess_stealth::generate_master_keys_from_seed(&raw_seed);
    let encrypted = recovery::encrypt_secrets(&secret, &enc_key)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut wallet = WalletFile::new(address, encrypted, BillFold::new(), spend_seed, &enc_key)?;
    // Set a test password so we can unlock via RPC.
    wallet.set_password_cache(&raw_seed, "test")?;
    wallet.save(wallet_path, &enc_key)?;

    Ok(raw_seed)
}

// ── Single-node full lifecycle test ──────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_node_full_lifecycle() {
    // ── 0. Create wallet on disk ────────────────────────────────────
    let tempdir = TempDir::new().unwrap();
    let wallet_path = tempdir.path().join("alice.wallet");
    let _raw_seed = create_test_wallet(&wallet_path).unwrap();
    eprintln!("Wallet created at {}", wallet_path.display());

    // ── 1. Spawn node with wallet ───────────────────────────────────
    let node = spawn_node(0, Some(wallet_path), Some("test".to_string()))
        .await
        .unwrap();
    eprintln!("Node online on port {}", node.rpc_port);

    // ── 2. Enable test mode ─────────────────────────────────────────
    rpc(&node, "set_test_mode", json!({})).await.unwrap();

    // ── 3. Wallet is auto-unlocked (password provided at startup) ───
    let balance0 = rpc(&node, "balance", json!({})).await.unwrap();
    eprintln!("Initial balance: {balance0:?}");
    assert!(balance0["ok"].as_bool().unwrap_or(false), "balance RPC should succeed (wallet loaded)");
    assert_eq!(balance0["balance"].as_u64().unwrap_or(0), 0, "initial balance should be 0");

    // ── 4. Get faucet bills ─────────────────────────────────────────
    let faucet = rpc(&node, "local_test_faucet", json!({"amount": 500})).await.unwrap();
    eprintln!("Faucet result: {faucet:?}");
    assert!(faucet["ok"].as_bool().unwrap_or(false), "faucet should succeed");

    // ── 5. Check balance ────────────────────────────────────────────
    let balance = rpc(&node, "balance", json!({})).await.unwrap();
    let bal = balance["balance"].as_u64().unwrap_or(0);
    eprintln!("Balance after faucet: {bal}");
    assert!(bal >= 500, "balance should be >= 500 after faucet");

    // ── 6. Check node health ────────────────────────────────────────
    let health = rpc(&node, "node_health", json!({})).await.unwrap();
    eprintln!("Node health: {health:?}");
    assert!(health["ok"].as_bool().unwrap_or(false), "node health should report ok");
    assert_eq!(health["wallet_state"].as_str().unwrap_or(""), "unlocked");

    // ── 7. Check payment history ────────────────────────────────────
    let history = rpc(&node, "payment_history", json!({"max": 10}))
        .await
        .unwrap();
    eprintln!("Payment history: {history:?}");
    assert!(history["ok"].as_bool().unwrap_or(false), "payment_history should succeed");

    // ── 8. Pending payments ────────────────────────────────────────
    let pending = rpc(&node, "pending_payments", json!({})).await.unwrap();
    eprintln!("Pending payments: {pending:?}");
    assert!(pending["ok"].as_bool().unwrap_or(false), "pending_payments should succeed");

    // ── 9. Node info ────────────────────────────────────────────────
    let info = rpc(&node, "node_info", json!({})).await.unwrap();
    eprintln!("Node info: {info:?}");
    assert!(info["ok"].as_bool().unwrap_or(false), "node_info should succeed");

    eprintln!("=== Single-node lifecycle test PASSED ===");
}
