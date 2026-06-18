use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

use vess_kloak::persistence::{named_wallet_path, set_active_wallet_path, WalletFile};
use vess_kloak::recovery::{derive_raw_seed, encrypt_secrets, encryption_key_from_seed, spend_seed_from_raw_seed, RecoveryPhrase};
use vess_kloak::BillFold;
use vess_stealth::generate_master_keys_from_seed;
use vess_tag::VessTag;

#[derive(uniffi::Record)]
pub struct NodeConfig {
    pub testnet: bool,
    pub k_neighbors: u32,
    pub max_hops: u8,
    pub state_dir: Option<String>,
    pub wallet_path: Option<String>,
    pub wallet_password: Option<String>,
    pub rpc_port: Option<u16>,
    pub bind_address: Option<String>,
    pub bootstrap_peers: Vec<String>,
}

#[derive(uniffi::Record)]
pub struct WalletInfo {
    pub tag: String,
    pub wallet_path: String,
    pub stealth_address: String,
    pub recovery_phrase: String,
}

#[derive(uniffi::Record)]
pub struct Balance {
    pub total: u64,
    pub spendable: u64,
    pub watch_only: u64,
    pub bill_count: u64,
    pub denominations: Vec<DenominationBreakdown>,
}

#[derive(uniffi::Record)]
pub struct DenominationBreakdown {
    pub value: u64,
    pub count: u64,
}

#[derive(uniffi::Record)]
pub struct PaymentResult {
    pub payment_id: String,
    pub amount: u64,
    pub recipient: String,
    pub bill_count: u64,
}

#[derive(uniffi::Record)]
pub struct Notification {
    pub kind: String,
    pub created_at: u64,
    pub payment_id: String,
    pub amount: Option<u64>,
    pub bill_count: Option<u64>,
    pub counterparty: Option<String>,
    pub message: String,
}

#[derive(uniffi::Record)]
pub struct NodeStatus {
    pub running: bool,
    pub uptime_secs: u64,
    pub peer_count: u64,
    pub bound_address: Option<String>,
    pub testnet: bool,
}

#[derive(uniffi::Record)]
pub struct TagInfo {
    pub tag: String,
    pub owner_vk_hash: String,
    pub stealth_address: String,
}

#[derive(uniffi::Record)]
pub struct EthBurnResult {
    /// Transaction hash of the burn submission.
    pub tx_hash: String,
    /// The Vess stealth address commitment (32 hex bytes).
    pub recipient: String,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum VessError {
    #[error("node is not running")]
    NodeNotRunning,
    #[error("node is already running")]
    AlreadyRunning,
    #[error("wallet error")]
    WalletError,
    #[error("payment error")]
    PaymentError,
    #[error("tag error")]
    TagError,
    #[error("configuration error")]
    ConfigError,
    #[error("internal error")]
    InternalError,
}

struct NodeHandle {
    rpc_port: u16,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    started_at: u64,
    is_testnet: bool,
    bind_address: String,
}

static NODE: OnceLock<Mutex<NodeHandle>> = OnceLock::new();

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn lock_handle() -> Result<std::sync::MutexGuard<'static, NodeHandle>, VessError> {
    NODE.get().ok_or(VessError::NodeNotRunning)?.lock().map_err(|_| VessError::InternalError)
}

fn map_err(e: impl std::fmt::Display) -> VessError {
    tracing::error!("{e}");
    VessError::InternalError
}

fn rpc_port() -> Result<u16, VessError> {
    lock_handle().map(|h| h.rpc_port)
}

fn rpc_call(method: &str, params: Value) -> Result<Value, VessError> {
    let port = rpc_port()?;
    let mut req = if let Value::Object(map) = params {
        map
    } else {
        serde_json::Map::new()
    };
    req.insert("method".to_string(), Value::String(method.to_string()));
    let request_str = serde_json::to_string(&req).map_err(|e| {
        tracing::error!("rpc serialize: {e}");
        VessError::InternalError
    })?;

    let addr = format!("127.0.0.1:{port}");
    let mut stream = std::net::TcpStream::connect(&addr).map_err(|e| {
        tracing::error!("rpc connect to {addr}: {e}");
        VessError::NodeNotRunning
    })?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();

    writeln!(stream, "{request_str}").map_err(|e| {
        tracing::error!("rpc write: {e}");
        VessError::InternalError
    })?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| {
        tracing::error!("rpc read: {e}");
        VessError::InternalError
    })?;

    let response: Value = serde_json::from_str(&line).map_err(|e| {
        tracing::error!("rpc parse response: {e} | raw: {line}");
        VessError::InternalError
    })?;

    if response.get("error").is_some() {
        return Err(VessError::InternalError);
    }
    Ok(response)
}

fn encode_stealth_address(addr: &vess_stealth::MasterStealthAddress) -> String {
    format!("{}:{}", hex::encode(&addr.scan_ek), hex::encode(&addr.spend_ek))
}

fn create_wallet_impl(tag_str: String, wallet_name: String, phrase: &RecoveryPhrase) -> Result<WalletInfo, VessError> {
    let raw_tag = tag_str.trim_start_matches('+');

    let wallet_path = named_wallet_path(&wallet_name).map_err(map_err)?;
    if wallet_path.exists() {
        return Err(VessError::WalletError);
    }

    let raw_seed = derive_raw_seed(phrase).map_err(map_err)?;
    let (secret, address) = generate_master_keys_from_seed(&raw_seed);
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = encrypt_secrets(&secret, &enc_key).map_err(map_err)?;

    let mut wallet = WalletFile::new(address.clone(), encrypted, BillFold::new(), spend_seed, &enc_key).map_err(map_err)?;
    wallet.name = Some(wallet_name.clone());
    wallet.save(&wallet_path, &enc_key).map_err(map_err)?;
    set_active_wallet_path(&wallet_path).map_err(map_err)?;

    Ok(WalletInfo {
        tag: format!("+{raw_tag}"),
        wallet_path: wallet_path.to_string_lossy().to_string(),
        stealth_address: encode_stealth_address(&address),
        recovery_phrase: phrase.display_phrase(),
    })
}

#[uniffi::export]
pub fn create_wallet(tag: String, wallet_name: String, _password: String) -> Result<WalletInfo, VessError> {
    let raw_tag = tag.trim_start_matches('+');
    VessTag::new(raw_tag).map_err(|_| VessError::TagError)?;
    let phrase = RecoveryPhrase::generate();
    create_wallet_impl(format!("+{raw_tag}"), wallet_name, &phrase)
}

#[uniffi::export]
pub fn recover_wallet(phrase_words: String, wallet_name: String, _password: String) -> Result<WalletInfo, VessError> {
    let phrase = RecoveryPhrase::from_input(&phrase_words).map_err(|_| VessError::WalletError)?;
    create_wallet_impl("+recovered".to_string(), wallet_name, &phrase)
}

#[uniffi::export]
pub fn start_node(config: NodeConfig) -> Result<NodeStatus, VessError> {
    if NODE.get().is_some() {
        return Err(VessError::AlreadyRunning);
    }

    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .with_target(false)
        .try_init();

    let state_dir = config.state_dir.as_deref().map(PathBuf::from).unwrap_or_else(|| {
        std::env::var("VESS_DATA_DIR").ok().map(PathBuf::from).unwrap_or_else(|| PathBuf::from(".vess-artery"))
    });

    let wallet_path = config.wallet_path.as_deref().map(PathBuf::from);
    let wallet_password = config.wallet_password.clone();
    let bind_addr_str = config.bind_address.clone().unwrap_or_else(|| "0.0.0.0:0".to_string());
    let bind_addr: Option<std::net::SocketAddr> = bind_addr_str.parse().ok();
    let is_testnet = config.testnet;
    let k_neighbors = config.k_neighbors as usize;
    let max_hops = config.max_hops;
    let rpc_port = config.rpc_port.unwrap_or(9400);
    let bootstrap = config.bootstrap_peers.clone();

    let artery_config = vess_artery::node_runner::NodeConfig {
        k_neighbors,
        max_hops,
        state_dir: state_dir.clone(),
        bootstrap,
        ready_tx: None,
        wallet_path: wallet_path.clone(),
        rpc_port: Some(rpc_port),
        wallet_password,
        bitcoin_config: None,
        bind_addr,
        enable_local_discovery: true,
        allow_private_bitcoin_seed_contact: false,
        reset_transient_peer_state: false,
        is_testnet,
        test: false,
        bootstrap_dns: vec![],
        eth_rpc_url: None,
        eth_burn_contract: None,
        eth_chain_id: None,
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let started_at = now_unix();
    let bind_address = bind_addr_str.clone();

    std::thread::Builder::new().name("vess-node".into()).spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build tokio runtime for node");
        rt.block_on(async move {
            tracing::info!("Vess node starting on mobile (testnet={is_testnet})");
            tokio::select! {
                result = vess_artery::node_runner::run_node(artery_config) => {
                    if let Err(e) = result { tracing::error!("node crashed: {e:?}"); }
                }
                _ = shutdown_rx => { tracing::info!("Vess node shutdown requested"); }
            }
            tracing::info!("Vess node stopped");
        });
    }).map_err(|e| {
        tracing::error!("failed to spawn node thread: {e}");
        VessError::InternalError
    })?;

    NODE.set(Mutex::new(NodeHandle { rpc_port, shutdown_tx: Some(shutdown_tx), started_at, is_testnet, bind_address }))
        .map_err(|_| VessError::AlreadyRunning)?;

    Ok(NodeStatus { running: true, uptime_secs: 0, peer_count: 0, bound_address: Some(bind_addr_str), testnet: is_testnet })
}

#[uniffi::export]
pub fn stop_node() -> Result<(), VessError> {
    let mut node = NODE.get().ok_or(VessError::NodeNotRunning)?.lock().map_err(|_| VessError::InternalError)?;
    if let Some(tx) = node.shutdown_tx.take() {
        let _ = tx.send(());
    }
    Ok(())
}

#[uniffi::export]
pub fn is_node_running() -> bool {
    NODE.get().is_some()
}

#[uniffi::export]
pub fn get_balance() -> Result<Balance, VessError> {
    let resp = rpc_call("balance", serde_json::json!({}))?;
    let total = resp["balance"].as_u64().unwrap_or(0);
    let bill_count = resp["bill_count"].as_u64().unwrap_or(0);
    let watch_only = resp["watch_only_balance"].as_u64();
    Ok(Balance { total, spendable: total.saturating_sub(watch_only.unwrap_or(0)), watch_only: watch_only.unwrap_or(0), bill_count, denominations: vec![] })
}

#[uniffi::export]
pub fn send_payment(amount: u64, recipient: String, memo: Option<String>) -> Result<PaymentResult, VessError> {
    let mut params = serde_json::json!({
        "amount": amount,
        "recipient": recipient,
    });
    if let Some(ref m) = memo {
        params["memo"] = Value::String(m.clone());
    }
    let resp = rpc_call("send", params)?;
    Ok(PaymentResult { payment_id: resp["payment_id"].as_str().unwrap_or("").to_string(), amount, recipient, bill_count: 0 })
}

#[uniffi::export]
pub fn get_notifications() -> Result<Vec<Notification>, VessError> {
    let resp = rpc_call("notifications", serde_json::json!({"max": 64}))?;
    let notes = match &resp["notifications"] { Value::Array(arr) => arr, _ => return Ok(Vec::new()) };
    Ok(notes.iter().map(|n| Notification {
        kind: n["kind"].as_str().unwrap_or("").to_string(),
        created_at: n["created_at"].as_u64().unwrap_or(0),
        payment_id: n["payment_id"].as_str().unwrap_or("").to_string(),
        amount: n["amount"].as_u64(),
        bill_count: n["bill_count"].as_u64(),
        counterparty: n["counterparty"].as_str().map(|s| s.to_string()),
        message: n["message"].as_str().unwrap_or("").to_string(),
    }).collect())
}

#[uniffi::export]
pub fn lookup_tag(tag: String) -> Result<TagInfo, VessError> {
    let resp = rpc_call("tag_lookup", serde_json::json!({"tag": tag}))?;
    Ok(TagInfo { tag: resp["tag"].as_str().unwrap_or("").to_string(), owner_vk_hash: String::new(), stealth_address: resp["scan_ek"].as_str().unwrap_or("").to_string() })
}

#[uniffi::export]
pub fn register_tag(_tag: String) -> Result<(), VessError> { Ok(()) }

#[uniffi::export]
pub fn get_status() -> Result<NodeStatus, VessError> {
    let handle = lock_handle()?;
    let uptime = now_unix().saturating_sub(handle.started_at);
    let peer_count = match rpc_call("node_info", serde_json::json!({})) {
        Ok(resp) => resp["verified_peer_count"].as_u64().unwrap_or(0),
        Err(_) => 0,
    };
    Ok(NodeStatus { running: true, uptime_secs: uptime, peer_count, bound_address: Some(handle.bind_address.clone()), testnet: handle.is_testnet })
}

#[uniffi::export]
pub fn get_stealth_address() -> Result<String, VessError> {
    let active_path = vess_kloak::persistence::read_active_wallet_path()
        .map_err(|_| VessError::WalletError)?
        .ok_or(VessError::WalletError)?;
    let data = std::fs::read_to_string(&active_path).map_err(|_| VessError::WalletError)?;
    let wf: WalletFile = serde_json::from_str(&data).map_err(|_| VessError::WalletError)?;
    Ok(encode_stealth_address(&wf.master_address))
}

// ── Ethereum bridge ──────────────────────────────────────────────────

fn parse_eth_address(s: &str) -> Result<vess_ethereum::Address, VessError> {
    s.parse::<vess_ethereum::Address>().map_err(|_| VessError::ConfigError)
}

fn parse_u256(s: &str) -> Result<vess_ethereum::U256, VessError> {
    vess_ethereum::U256::from_dec_str(s).map_err(|_| VessError::ConfigError)
}

fn load_eth_config() -> Result<(String, vess_ethereum::Address, u64), VessError> {
    let rpc_url = std::env::var("VESS_ETH_RPC")
        .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());
    let contract_addr = std::env::var("VESS_ETH_BURN_CONTRACT")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string())
        .parse::<vess_ethereum::Address>()
        .map_err(|_| VessError::ConfigError)?;
    let chain_id: u64 = std::env::var("VESS_ETH_CHAIN_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .map_err(|_| VessError::ConfigError)?;
    Ok((rpc_url, contract_addr, chain_id))
}

#[uniffi::export]
pub fn get_eth_address() -> Result<String, VessError> {
    let active_path = vess_kloak::persistence::read_active_wallet_path()
        .map_err(|_| VessError::WalletError)?
        .ok_or(VessError::WalletError)?;
    let data = std::fs::read_to_string(&active_path).map_err(|_| VessError::WalletError)?;
    let wf: WalletFile = serde_json::from_str(&data).map_err(|_| VessError::WalletError)?;
    let raw_seed = wf.unlock_with_password("").or_else(|_| {
        std::env::var("VESS_WALLET_PASSWORD")
            .map_err(|_| anyhow::anyhow!("no password"))
            .and_then(|p| wf.unlock_with_password(&p))
    }).map_err(|_| VessError::WalletError)?;
    Ok(format!("{:?}", vess_ethereum::wallet::eth_address_from_seed(&raw_seed)))
}

#[uniffi::export]
pub async fn get_eth_balance(rpc_url: Option<String>) -> Result<String, VessError> {
    let (rpc, _, _) = load_eth_config()?;
    let url = rpc_url.unwrap_or(rpc);
    let addr = get_eth_address()?.parse::<vess_ethereum::Address>().map_err(|_| VessError::ConfigError)?;
    let bal = vess_ethereum::wallet::eth_balance(&url, addr)
        .await
        .map_err(|_| VessError::InternalError)?;
    Ok(bal.to_string())
}

#[uniffi::export]
pub async fn get_erc20_balance(token_addr: String, rpc_url: Option<String>) -> Result<String, VessError> {
    let (rpc, _, _) = load_eth_config()?;
    let url = rpc_url.unwrap_or(rpc);
    let token = parse_eth_address(&token_addr)?;
    let wal_addr = get_eth_address()?.parse::<vess_ethereum::Address>().map_err(|_| VessError::ConfigError)?;
    let bal = vess_ethereum::wallet::erc20_balance(&url, token, wal_addr)
        .await
        .map_err(|_| VessError::InternalError)?;
    Ok(bal.to_string())
}

#[uniffi::export]
pub async fn burn_eth(
    amount_wei: String,
    recipient_commitment: String,
    rpc_url: Option<String>,
    contract_addr: Option<String>,
    chain_id: Option<u64>,
) -> Result<EthBurnResult, VessError> {
    let (rpc, default_contract, default_chain) = load_eth_config()?;
    let url = rpc_url.unwrap_or(rpc);
    let contract = match contract_addr {
        Some(a) => parse_eth_address(&a)?,
        None => default_contract,
    };
    let chain = chain_id.unwrap_or(default_chain);
    let amount = parse_u256(&amount_wei)?;
    let recipient: [u8; 32] = hex::decode(recipient_commitment.trim_start_matches("0x"))
        .map_err(|_| VessError::ConfigError)?
        .try_into()
        .map_err(|_| VessError::ConfigError)?;

    let active_path = vess_kloak::persistence::read_active_wallet_path()
        .map_err(|_| VessError::WalletError)?
        .ok_or(VessError::WalletError)?;
    let data = std::fs::read_to_string(&active_path).map_err(|_| VessError::WalletError)?;
    let wf: WalletFile = serde_json::from_str(&data).map_err(|_| VessError::WalletError)?;
    let raw_seed = wf.unlock_with_password("").or_else(|_| {
        std::env::var("VESS_WALLET_PASSWORD")
            .map_err(|_| anyhow::anyhow!("no password"))
            .and_then(|p| wf.unlock_with_password(&p))
    }).map_err(|_| VessError::WalletError)?;
    let eth_key = vess_kloak::recovery::eth_key_from_raw_seed(&raw_seed);

    let tx = vess_ethereum::wallet::burn_eth(&eth_key, &url, contract, amount, &recipient, chain)
        .await
        .map_err(|_| VessError::InternalError)?;
    Ok(EthBurnResult {
        tx_hash: format!("{:?}", tx),
        recipient: hex::encode(recipient),
    })
}

#[uniffi::export]
pub async fn burn_erc20(
    token_addr: String,
    amount: String,
    recipient_commitment: String,
    rpc_url: Option<String>,
    contract_addr: Option<String>,
    chain_id: Option<u64>,
) -> Result<EthBurnResult, VessError> {
    let (rpc, default_contract, default_chain) = load_eth_config()?;
    let url = rpc_url.unwrap_or(rpc);
    let contract = match contract_addr {
        Some(a) => parse_eth_address(&a)?,
        None => default_contract,
    };
    let chain = chain_id.unwrap_or(default_chain);
    let token = parse_eth_address(&token_addr)?;
    let amt = parse_u256(&amount)?;
    let recipient: [u8; 32] = hex::decode(recipient_commitment.trim_start_matches("0x"))
        .map_err(|_| VessError::ConfigError)?
        .try_into()
        .map_err(|_| VessError::ConfigError)?;

    let active_path = vess_kloak::persistence::read_active_wallet_path()
        .map_err(|_| VessError::WalletError)?
        .ok_or(VessError::WalletError)?;
    let data = std::fs::read_to_string(&active_path).map_err(|_| VessError::WalletError)?;
    let wf: WalletFile = serde_json::from_str(&data).map_err(|_| VessError::WalletError)?;
    let raw_seed = wf.unlock_with_password("").or_else(|_| {
        std::env::var("VESS_WALLET_PASSWORD")
            .map_err(|_| anyhow::anyhow!("no password"))
            .and_then(|p| wf.unlock_with_password(&p))
    }).map_err(|_| VessError::WalletError)?;
    let eth_key = vess_kloak::recovery::eth_key_from_raw_seed(&raw_seed);

    let tx = vess_ethereum::wallet::burn_erc20(&eth_key, &url, contract, token, amt, &recipient, chain)
        .await
        .map_err(|_| VessError::InternalError)?;
    Ok(EthBurnResult {
        tx_hash: format!("{:?}", tx),
        recipient: hex::encode(recipient),
    })
}

uniffi::setup_scaffolding!();
