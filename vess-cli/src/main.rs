//! Unified CLI for the Vess protocol.
//!
//! `init` and `recover` bootstrap a wallet via Bitcoin-side Vess peer discovery.
//! All other commands route through the local node's JSON-RPC server
//! (default port 9400). `node` starts an artery node with optional
//! embedded wallet and RPC listener.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    ChaCha20Poly1305,
};
use clap::{Parser, Subcommand};
use qrcode::QrCode;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing_subscriber::EnvFilter;

use vess_sovereign::persistence::{
    list_wallets, named_wallet_path, read_active_wallet_path, set_active_wallet_path,
    WalletDescriptor, WalletFile,
};
use vess_sovereign::recovery::{
    derive_key_from_password, derive_raw_seed, encrypt_secrets, encryption_key_from_seed,
    recover_master_keys, spend_seed_from_raw_seed, RecoveryPhrase,
};
use vess_sovereign::BillFold;
use vess_mesh::{
    decode_mesh_contact, decode_mesh_contact_string, encode_mesh_contact_string,
    validate_mesh_contact, MeshCarrier, MeshCarrierContact, PqUdpMeshCarrier,
};
use vess_protocol::{PulseMessage, TagLookup, TagRegister};
use vess_stealth::generate_master_keys_from_seed;
use vess_tag::VessTag;
use vess_mesh::MeshPulseNode;

#[derive(Parser)]
#[command(name = "vess", version, about = "Vess â€” stateless P2P digital cash")]
struct Cli {
    /// Path to wallet file. Overrides --wallet-name and active wallet selection.
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    /// VessTag of a local wallet stored under ~/.vess/wallets/.
    #[arg(long, global = true)]
    wallet_name: Option<String>,

    /// Output JSON instead of human-readable text (for AI agents / automation).
    #[arg(long, global = true)]
    json: bool,

    /// Connect to a running node's local RPC server on 127.0.0.1:<port>.
    /// When set, balance/send/tag-lookup commands talk to the node
    /// instead of operating on the wallet file directly.
    #[arg(long, global = true)]
    rpc: Option<u16>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet with a recovery phrase.
    Init {
        /// VessTag to claim (e.g. "alice" or "+alice").
        #[arg(long)]
        tag: String,
        name: Option<String>,
    },
    /// Recover a wallet from a 12-word recovery phrase.
    Recover {
        /// The 12-word BIP39 recovery phrase.
        words: String,
        /// Local wallet VessTag name to store the recovered wallet under.
        #[arg(long)]
        name: Option<String>,
    },

    /// Show wallet balance and denomination breakdown.
    Balance,

    /// Show the current Bitcoin receive address and an ASCII QR code.
    #[command(alias = "recieve")]
    Receive,

    /// Show sender/receiver wallet notifications from the local node.
    Notifications {
        /// Keep polling and print events as they arrive.
        #[arg(long)]
        follow: bool,
        /// Poll interval in milliseconds when following.
        #[arg(long, default_value = "1000")]
        interval_ms: u64,
        /// Maximum queued notifications to fetch per poll.
        #[arg(long, default_value = "64")]
        max: usize,
    },

    /// Local testing only: give the loaded wallet faucet bills.
    #[command(alias = "test-mint")]
    Faucet {
        /// Amount of local-test Vess to add.
        amount: u64,
    },

    /// Send Vess to a recipient (by +tag or stealth address).
    Send {
        /// Amount to send.
        amount: u64,
        /// Recipient: +tag or stealth address.
        recipient: String,
        /// Optional encrypted memo (max 256 bytes, e.g. order ID or note).
        #[arg(long)]
        memo: Option<String>,
        /// Send directly to a serialized mesh contact or cached mesh node ID.
        /// Bypasses mesh relay for instant IRL payments.
        #[arg(long)]
        node_direct: Option<String>,
    },

    /// Register a VessTag (computes PoW and auto-hardens if bills are available).
    RegisterTag {
        /// Tag to register (e.g. "alice" or "+alice").
        tag: String,
    },

    /// Send a raw Pulse to a remote node (low-level).
    Pulse {
        /// Target node's serialized mesh contact.
        target: String,
        /// Message payload.
        message: String,
    },

    /// Listen for raw incoming Pulses (low-level).
    Listen,

    /// Show whether the background node is running and a wallet summary.
    Status,

    /// Build the Vess executable in Cargo's target directory by default.
    #[command(alias = "build-exe")]
    Compile {
        /// Optional output executable path.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Build the debug profile instead of release.
        #[arg(long)]
        debug: bool,
    },

    /// Run as a full artery node (network participant).
    Node {
        /// Number of gossip neighbors (K).
        #[arg(long, default_value = "4")]
        k_neighbors: usize,
        /// Maximum gossip hops.
        #[arg(long, default_value = "3")]
        max_hops: u8,
        /// State directory for persistence (default: ~/.vess-artery).
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Optional manual bootstrap peer mesh contacts (comma-separated).
        #[arg(long, value_delimiter = ',')]
        bootstrap: Vec<String>,
        /// Path to wallet file. Embeds wallet in node for auto-receive.
        /// Requires VESS_WALLET_PASSWORD (or --wallet-password) to unlock,
        /// or VESS_RECOVERY_PHRASE as fallback.
        #[arg(long)]
        wallet: Option<PathBuf>,
        /// Password for fast wallet unlock.
        #[arg(long)]
        wallet_password: Option<String>,
        /// Enable the local-only JSON-RPC server on 127.0.0.1:<port>.
        #[arg(long)]
        rpc_port: Option<u16>,
        /// Discard persisted peer cache and ban state on startup.
        #[arg(long, hide = true)]
        reset_transient_peer_state: bool,
        /// Join the public testnet: Bitcoin signet, faucet enabled, seed peers.
        #[arg(long)]
        testnet: bool,
        /// Bind mesh UDP socket to a specific address (default: 0.0.0.0:0).
        #[arg(long)]
        bind: Option<String>,
    },

    /// Set a password for fast daily wallet unlock.
    SetPassword {
        /// The new password to set.
        #[arg(long)]
        password: String,
    },

    /// Manage the local VessTag address book (persistent tag â†’ stealth address cache).
    #[command(subcommand)]
    TagCache(TagCacheCmd),

    /// Cancel a pending outbound payment and recover reserved bills.
    CancelPayment {
        /// Payment ID (hex) of the outbound payment to cancel.
        payment_id: String,
    },

    /// List pending outbound payments that haven't been claimed yet.
    PendingPayments,

    /// Show local payment history with amounts, memos, and status.
    #[command(alias = "history")]
    PaymentHistory {
        /// Maximum number of entries to show (default: 20).
        #[arg(long, default_value = "20")]
        max: usize,
    },

    /// Toggle passive mode: save bandwidth on metered/mobile connections.
    /// In passive mode the node only relays its own payments.
    PassiveMode {
        /// Enable or disable passive mode.
        #[arg(long)]
        enable: bool,
    },
}

const LOCAL_BACKUP_FORMAT_VERSION: u32 = 1;

    #[derive(Serialize)]
struct LocalPhraseBackupFile {
    version: u32,
    kdf: &'static str,
    cipher: &'static str,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

fn local_phrase_backup_path(wallet_path: &Path) -> PathBuf {
        let file_name = wallet_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("wallet");
        wallet_path.with_file_name(format!("{file_name}.seed-backup.json"))
    }

fn prompt_yes_no(msg: &str, default_no: bool) -> Result<bool> {
        loop {
            let answer = prompt(msg)?;
            let normalized = answer.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Ok(!default_no);
            }
            match normalized.as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => println!("Please answer y or n."),
            }
        }
    }

fn write_local_phrase_backup_file(phrase: &RecoveryPhrase, backup_path: &Path) -> Result<()> {
        let mut password = prompt_password("  Backup password (min 16 chars): ")?;
        if password.len() < 16 {
            anyhow::bail!("backup password must be at least 16 characters");
        }
        let password_confirm = prompt_password("  Confirm backup password: ")?;
        if password != password_confirm {
            anyhow::bail!("backup passwords did not match");
        }

        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);
        let derived_key = derive_key_from_password(&password, &salt)?;
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&derived_key));

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill(&mut nonce);
        let phrase_text = phrase.display_phrase();
        let ciphertext = cipher
            .encrypt(GenericArray::from_slice(&nonce), phrase_text.as_bytes())
            .map_err(|err| anyhow::anyhow!("backup encryption failed: {err}"))?;

        let backup = LocalPhraseBackupFile {
            version: LOCAL_BACKUP_FORMAT_VERSION,
            kdf: "argon2id",
            cipher: "chacha20poly1305",
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        };

        let encoded = serde_json::to_vec_pretty(&backup)?;
        std::fs::write(backup_path, encoded)
            .with_context(|| format!("write backup file {}", backup_path.display()))?;
        password.clear();
        Ok(())
    }

fn maybe_store_local_phrase_backup(phrase: &RecoveryPhrase, wallet_path: &Path) -> Result<Option<PathBuf>> {
        let should_store = prompt_yes_no(
            "Store a local encrypted backup of your recovery phrase? [y/N]: ",
            true,
        )?;
        if !should_store {
            return Ok(None);
        }

        let backup_path = local_phrase_backup_path(wallet_path);
        if backup_path.exists() {
            let overwrite = prompt_yes_no(
                &format!(
                    "Encrypted backup already exists at {}. Overwrite it? [y/N]: ",
                    backup_path.display()
                ),
                true,
            )?;
            if !overwrite {
                println!("  Skipped local backup.");
                return Ok(None);
            }
        }

        println!("\nCreate a separate high-entropy password for this backup file.");
        println!("Do not store that password in the same place as the backup file.\n");
        write_local_phrase_backup_file(phrase, &backup_path)?;
        println!("Encrypted backup saved to {}", backup_path.display());
        println!("Store that file on a thumb drive or in cloud storage as an extra backup.\n");
        Ok(Some(backup_path))
}

/// Subcommands for `vess tag-cache`.
#[derive(Subcommand)]
enum TagCacheCmd {
    /// List all cached VessTag entries, most-recently-used first.
    List,
    /// Remove a specific tag from the cache (forces re-lookup next send).
    Clear {
        /// Tag to remove, e.g. "alice" or "+alice".
        /// Omit to clear the entire cache.
        tag: Option<String>,
    },
}

fn wallet_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(ref p) = cli.wallet {
        Ok(p.clone())
    } else if let Some(ref name) = cli.wallet_name {
        named_wallet_path(name)
    } else if let Some(active) = read_active_wallet_path()? {
        Ok(active)
    } else {
        let wallets = list_wallets()?;
        match wallets.len() {
            0 => vess_sovereign::persistence::default_wallet_path(),
            1 => Ok(wallets[0].path.clone()),
            _ => anyhow::bail!(
                "multiple wallets found; use --wallet-name <+tag>, --wallet <path>, or open Vess interactively to choose one"
            ),
        }
    }
}

fn wallet_create_path(cli: &Cli, name: Option<&str>) -> Result<(PathBuf, Option<String>)> {
    if let Some(ref p) = cli.wallet {
        return Ok((p.clone(), None));
    }
    let name = name.or(cli.wallet_name.as_deref());
    if let Some(name) = name {
        return Ok((named_wallet_path(name)?, Some(name.trim().to_string())));
    }
    Ok((vess_sovereign::persistence::default_wallet_path()?, None))
}

fn normalize_wallet_tag_name(value: &str) -> Result<String> {
    Ok(VessTag::new(value)?.as_str().to_string())
}

fn wallet_display_name(name: &str) -> String {
    VessTag::new(name)
        .map(|tag| tag.display())
        .unwrap_or_else(|_| name.to_string())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match dispatch_command(&cli).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if cli.json {
                println!("{}", json!({ "ok": false, "error": error.to_string() }));
            } else {
                eprintln!("Error: {error}");
            }
            std::process::ExitCode::from(1)
        }
    }
}

async fn dispatch_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        None => {
            println!("Vess â€” stateless P2P digital cash");
            println!("Run 'vess help' for commands, or launch the Vess GUI application.");
            Ok(())
        }
        Some(Command::Init { tag, name }) => cmd_init(&cli, tag, name.as_deref()).await,
        Some(Command::Recover { words, name }) => cmd_recover(&cli, words, name.as_deref()).await,
        Some(Command::Balance) => cmd_balance(&cli).await,
        Some(Command::Receive) => cmd_receive(&cli).await,
        Some(Command::Notifications {
            follow,
            interval_ms,
            max,
        }) => cmd_notifications(&cli, *follow, *interval_ms, *max).await,
        Some(Command::Faucet { amount }) => cmd_faucet(&cli, *amount).await,
        Some(Command::Send {
            amount,
            recipient,
            memo,
            node_direct,
        }) => {
            cmd_send(
                &cli,
                *amount,
                recipient,
                memo.as_deref(),
                node_direct.as_deref(),
            )
            .await
        }
        Some(Command::RegisterTag { tag }) => cmd_register_tag(&cli, tag).await,
        Some(Command::Pulse { target, message }) => cmd_pulse(&cli, target, message).await,
        Some(Command::Listen) => cmd_listen(&cli).await,
        Some(Command::Status) => cmd_status(&cli).await,
        Some(Command::Compile { output, debug }) => cmd_compile(&cli, output.as_deref(), *debug).await,
        Some(Command::Node {
            k_neighbors,
            max_hops,
            state_dir,
            bootstrap,
            wallet,
            wallet_password,
            rpc_port,
            reset_transient_peer_state,
            testnet,
            bind,
        }) => {
            let state_dir = match state_dir {
                Some(d) => d.clone(),
                None => vess_artery::persistence::NodeStorage::default_dir()?,
            };
            let bind_addr = bind.as_ref().and_then(|s| s.parse::<std::net::SocketAddr>().ok());
            let config = vess_artery::node_runner::NodeConfig {
                k_neighbors: *k_neighbors,
                max_hops: *max_hops,
                state_dir,
                bootstrap: bootstrap.clone(),
                ready_tx: None,
                wallet_path: wallet.clone(),
                rpc_port: *rpc_port,
                wallet_password: wallet_password.clone(),
                bitcoin_config: None,
                bind_addr,
                enable_local_discovery: true,
                allow_private_bitcoin_seed_contact: false,
                reset_transient_peer_state: *reset_transient_peer_state,
                is_testnet: *testnet,
                test: false,
                bootstrap_dns: vec![],
            };
            vess_artery::node_runner::run_node(config).await?;
            Ok(())
        }
        Some(Command::SetPassword { password }) => cmd_set_password(&cli, password.clone()).await,
        Some(Command::TagCache(sub)) => match sub {
            TagCacheCmd::List => cmd_tag_cache_list(&cli).await,
            TagCacheCmd::Clear { tag } => cmd_tag_cache_clear(&cli, tag.as_deref()).await,
        },
        Some(Command::CancelPayment { payment_id }) => cmd_cancel_payment(&cli, payment_id).await,
        Some(Command::PendingPayments) => cmd_pending_payments(&cli).await,
        Some(Command::PaymentHistory { max }) => cmd_payment_history(&cli, *max).await,
        Some(Command::PassiveMode { enable }) => cmd_passive_mode(&cli, *enable).await,
    }
}

async fn cmd_cancel_payment(cli: &Cli, payment_id: &str) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({"method": "cancel_payment", "payment_id": payment_id})).await?;
    if cli.json {
        println!("{resp}");
    } else if resp["ok"] == true {
        let released = resp["released_bills"].as_u64().unwrap_or(0);
        let amount = resp["recovered_amount"].as_u64().unwrap_or(0);
        println!("Cancelled payment {payment_id}: {released} bills worth {amount} Vess recovered.");
    } else {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(())
}

async fn cmd_pending_payments(cli: &Cli) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({"method": "pending_payments"})).await?;
    if cli.json {
        println!("{resp}");
    } else if resp["ok"] == true {
        let payments = resp["payments"].as_array().map(|a| a.len()).unwrap_or(0);
        if payments == 0 {
            println!("No pending outbound payments.");
        } else {
            println!("{:#}", resp);
        }
    } else {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(())
}

async fn cmd_payment_history(cli: &Cli, max: usize) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({"method": "payment_history", "max": max})).await?;
    if cli.json {
        println!("{resp}");
        return Ok(());
    }
    let entries = resp["entries"].as_array().cloned().unwrap_or_default();
    if entries.is_empty() {
        println!("No payment history.");
        return Ok(());
    }
    println!("{0: <16} {1: >8} {2: <8} {3: <12} {4: <20} {5}", "TIMESTAMP", "AMOUNT", "DIR", "STATUS", "COUNTERPARTY", "MEMO");
    println!("{:-<80}", "");
    for entry in &entries {
        let ts = entry["timestamp"].as_u64().unwrap_or(0);
        let amount = entry["amount"].as_u64().unwrap_or(0);
        let dir = entry["direction"].as_str().unwrap_or("?");
        let status = entry["status"].as_str().unwrap_or("?");
        let counterparty = entry["counterparty"].as_str().unwrap_or("-");
        let memo = entry["memo"].as_str().unwrap_or("-");
        // Format timestamp as readable date
        let dt = chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| ts.to_string());
        let truncated_memo = if memo.len() > 30 { format!("{}...", &memo[..27]) } else { memo.to_string() };
        println!("{dt: <16} {amount: >8} {dir: <8} {status: <12} {counterparty: <20} {truncated_memo}");
    }
    Ok(())
}

async fn cmd_passive_mode(cli: &Cli, enable: bool) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({"method": "set_passive_mode", "enabled": enable})).await?;
    if cli.json {
        println!("{resp}");
    } else if resp["ok"] == true {
        println!("{}", resp["message"].as_str().unwrap_or("Passive mode toggled."));
    } else {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(())
}

// â”€â”€ Subcommand implementations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Obtain the 64-byte raw_seed.  Tries password-based unlock first
/// (VESS_WALLET_PASSWORD env var), then falls back to the 12-word recovery phrase.
fn derive_raw_seed_for_wallet(cli: &Cli) -> Result<[u8; 64]> {
    // Fast path: password-based unlock.
    if let Ok(pwd) = std::env::var("VESS_WALLET_PASSWORD") {
        let wpath = wallet_path(cli)?;
        let wallet = WalletFile::load(&wpath)?;
        return wallet.unlock_with_password(&pwd);
    }
    // Slow path: 12-word recovery phrase.
    let words = std::env::var("VESS_RECOVERY_PHRASE")
        .map_err(|_| anyhow::anyhow!("set VESS_WALLET_PASSWORD or VESS_RECOVERY_PHRASE env var"))?;
    let phrase = RecoveryPhrase::from_input(&words)?;
    derive_raw_seed(&phrase)
}

/// Read the per-startup RPC session token from the state directory.
///
/// The token is generated fresh each time the node starts and written to
/// `{state_dir}/rpc-token` (mode 600 on Unix). The CLI must send it as
/// the first line on every new connection.
fn read_rpc_token(state_dir: &std::path::Path) -> Result<String> {
    let token_path = state_dir.join("rpc-token");
    let token = std::fs::read_to_string(&token_path).map_err(|e| {
        anyhow::anyhow!(
            "cannot read RPC token from {}: {} â€” is the node running?",
            token_path.display(),
            e
        )
    })?;
    Ok(token.trim().to_string())
}

/// Send a JSON-RPC request to the node's local RPC server and return the
/// parsed response.  The caller is responsible for constructing the request
/// object (must be a single JSON line).
async fn rpc_call(port: u16, request: &serde_json::Value) -> Result<serde_json::Value> {
    let state_dir = rpc_state_dir()?;
    rpc_call_with_dir(port, &state_dir, request).await
}

fn rpc_state_dir() -> Result<PathBuf> {
    vess_artery::persistence::NodeStorage::default_dir()
}

async fn rpc_call_with_dir(
    port: u16,
    state_dir: &std::path::Path,
    request: &serde_json::Value,
) -> Result<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let token = read_rpc_token(state_dir)?;
    let addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&addr).await.map_err(|e| {
        anyhow::anyhow!("cannot connect to node RPC at {addr}: {e} â€” is the node running with --rpc-port {port}?")
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut line_buf = String::new();
    let mut buf_reader = BufReader::new(reader);

    // H2: Send auth token as first line before any command.
    let mut token_bytes = token.into_bytes();
    token_bytes.push(b'\n');
    writer.write_all(&token_bytes).await?;

    let mut req_bytes = serde_json::to_vec(request)?;
    req_bytes.push(b'\n');
    writer.write_all(&req_bytes).await?;

    buf_reader.read_line(&mut line_buf).await?;
    let resp: serde_json::Value = serde_json::from_str(line_buf.trim())?;
    Ok(resp)
}

fn parse_mesh_contact(value: &str) -> Result<MeshCarrierContact> {
    let contact = decode_mesh_contact_string(value)
        .map_err(|error| anyhow::anyhow!("invalid mesh contact: {error}"))?;
    validate_mesh_contact(&contact)?;
    Ok(contact)
}

fn decode_mesh_contact_bytes(bytes: &[u8]) -> Result<MeshCarrierContact> {
    let contact = decode_mesh_contact(bytes)
        .map_err(|error| anyhow::anyhow!("invalid mesh contact bytes: {error}"))?;
    validate_mesh_contact(&contact)?;
    Ok(contact)
}

async fn spawn_udp_mesh_carrier() -> Result<PqUdpMeshCarrier> {
    let mut seed = [0u8; 64];
    rand::thread_rng().fill(&mut seed);
    PqUdpMeshCarrier::bind_from_seed(
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )),
        &seed,
        0,
    )
    .await
}

/// Discover bootstrap peers through local/LAN and Bitcoin-side Vess peer discovery.
/// Used by init/recover when the local node is not yet running.
async fn discover_peers(verbose: bool) -> Result<Vec<MeshCarrierContact>> {
    if verbose {
        println!("Discovering Bitcoin & Vess peers...");
    }
    let client = match vess_bitcoin::BitcoinLightClient::spawn(Default::default()).await {
        Ok(client) => Some(client),
        Err(error) => {
            tracing::warn!(%error, "Bitcoin peer discovery failed to start; continuing with LAN discovery");
            None
        }
    };

    loop {
        let mut peers = vess_artery::local_discovery::discover_lan_peer_contacts(
            std::time::Duration::from_secs(2),
            None,
        )
        .await;
        if !peers.is_empty() {
            if verbose {
                println!("Discovered {} Vess peer(s) on LAN/local host.", peers.len());
            }
            return Ok(peers);
        }

        if let Some(client) = &client {
            let connected = client
                .wait_for_peers(1, std::time::Duration::from_secs(5))
                .await;
            tracing::info!(connected, "Bitcoin peer discovery connection wait finished");
            if connected == 0 {
                if verbose {
                    println!("Still waiting for LAN or Bitcoin peers...");
                }
                continue;
            }

            let discovered = client.discover_vess_nodes().await;
            for node in discovered {
                match parse_mesh_contact(&node.contact) {
                    Ok(contact) if !peers.contains(&contact) => peers.push(contact),
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(node_id = %node.node_id, "Bitcoin-discovered Vess contact rejected: {error}");
                    }
                }
            }

            if !peers.is_empty() {
                if verbose {
                    println!("Discovered {} Vess peer(s) through Bitcoin.", peers.len());
                }
                return Ok(peers);
            }

            if verbose {
                println!(
                    "No Vess peers found yet through LAN or {connected} Bitcoin peer(s); still waiting..."
                );
            }
        } else {
            if verbose {
                println!("No Vess peers found yet on LAN/local host; still waiting...");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

async fn discover_recovery_targets(node: &MeshPulseNode, verbose: bool) -> Result<Vec<MeshCarrierContact>> {
    let peers = discover_peers(verbose).await?;
    let mut targets = peers.clone();

    let pe_msg = PulseMessage::PeerExchange(vess_protocol::PeerExchange {
        sender_id: node.id().as_bytes().to_vec(),
    });

    for bootstrap_target in &peers {
        if let Ok(Some(PulseMessage::PeerExchangeResponse(resp))) = node
            .send_message_with_response(bootstrap_target, &pe_msg)
            .await
        {
            for peer_bytes in &resp.peers {
                if let Ok(contact) = decode_mesh_contact_bytes(peer_bytes) {
                    if !targets.contains(&contact) {
                        targets.push(contact);
                    }
                }
            }
            break;
        }
    }

    Ok(targets)
}

async fn lookup_tag_on_reachable_peer(
    node: &MeshPulseNode,
    peers: &[MeshCarrierContact],
    tag_str: &str,
    display_tag: &str,
) -> Result<(bool, MeshCarrierContact)> {
    let lookup = PulseMessage::TagLookup(TagLookup {
        tag_hash: *blake3::hash(tag_str.as_bytes()).as_bytes(),
        nonce: rand::random(),
        burn_proof: None,
    });
    let mut failures = 0usize;

    for target in peers {
        match node.send_message_with_response(target, &lookup).await {
            Ok(Some(PulseMessage::TagLookupResponse(tlr))) => {
                return Ok((tlr.result.is_some(), target.clone()));
            }
            Ok(other) => {
                failures += 1;
                tracing::warn!(
                    ?other,
                    "discovered Vess peer returned unexpected tag lookup response"
                );
            }
            Err(error) => {
                failures += 1;
                tracing::warn!(%error, "discovered Vess peer did not answer tag lookup");
            }
        }
    }

    anyhow::bail!(
        "no discovered Vess peer answered tag lookup for {display_tag}; {failures} discovered peer(s) may be stale or still starting. Try again in a few seconds"
    )
}

/// Return the RPC port from the --rpc flag, or default 9400.
fn rpc_port(cli: &Cli) -> u16 {
    cli.rpc.unwrap_or(vess_artery::rpc::DEFAULT_RPC_PORT)
}

fn should_use_rpc(cli: &Cli) -> bool {
    cli.rpc.is_some()
}

async fn cmd_init(cli: &Cli, tag_str: &str, wallet_name: Option<&str>) -> Result<()> {
    let verbose = !cli.json;
    let tag = VessTag::new(tag_str)?;
    for supplied_name in [wallet_name, cli.wallet_name.as_deref()]
        .into_iter()
        .flatten()
    {
        let normalized = normalize_wallet_tag_name(supplied_name)?;
        if normalized != tag.as_str() {
            anyhow::bail!(
                "wallet name must match the VessTag being claimed: expected {}, got {}",
                tag.display(),
                wallet_display_name(&normalized)
            );
        }
    }
    let wallet_tag_name = tag.as_str().to_string();
    let (path, _) = wallet_create_path(cli, Some(&wallet_tag_name))?;
    if path.exists() {
        anyhow::bail!("wallet already exists at {}", path.display());
    }

    let node = MeshPulseNode::spawn().await?;
    node.wait_online().await;

    if verbose {
        println!("Checking if tag {} is available...", tag.display());
    }
    let peers = discover_peers(verbose).await?;
    let display_tag = tag.display();
    let (is_taken, target) =
        lookup_tag_on_reachable_peer(&node, &peers, tag.as_str(), &display_tag).await?;

    if is_taken {
        node.shutdown().await;
        anyhow::bail!(
            "tag {} is already claimed - wallet was NOT created",
            tag.display()
        );
    }

    if verbose {
        println!("Tag {} is available!", tag.display());
    }

    let phrase = RecoveryPhrase::generate();

    let raw_seed = derive_raw_seed(&phrase)?;
    let (secret, address) = generate_master_keys_from_seed(&raw_seed);
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = encrypt_secrets(&secret, &enc_key)?;

    let mut wallet = WalletFile::new(address, encrypted, BillFold::new(), spend_seed, &enc_key)?;
    wallet.name = Some(wallet_tag_name.clone());

    {
        if verbose {
            println!("Computing Argon2id proof-of-work (~10 seconds, 2 GiB RAM)...");
        }

        let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();
        let (pow_nonce, pow_hash) = vess_tag::compute_tag_pow(
            &tag_hash,
            &wallet.master_address.scan_ek,
            &wallet.master_address.spend_ek,
        )?;

        let (registrant_vk, registrant_sk) = vess_foundry::spend_auth::generate_spend_keypair();

        wallet.tag_registrant_vk = registrant_vk.clone();
        wallet.set_encrypted_tag_sk(&registrant_sk, &enc_key)?;

        let tmp_record = vess_tag::TagRecord {
            tag_hash,
            master_address: vess_stealth::MasterStealthAddress {
                scan_ek: wallet.master_address.scan_ek.clone(),
                spend_ek: wallet.master_address.spend_ek.clone(),
            },
            pow_nonce,
            pow_hash: pow_hash.clone(),
            registered_at: now_unix(),
            registrant_vk: registrant_vk.clone(),
            signature: Vec::new(),
            hardened_at: None,
        };
        let digest = tmp_record.digest();
        let signature = vess_foundry::spend_auth::sign_spend(&registrant_sk, &digest)?;
        wallet.set_tag_registration(
            pow_nonce,
            pow_hash.clone(),
            tmp_record.registered_at,
            signature.clone(),
            &enc_key,
        )?;

        let msg = PulseMessage::TagRegister(TagRegister {
            tag_hash,
            scan_ek: wallet.master_address.scan_ek.clone(),
            spend_ek: wallet.master_address.spend_ek.clone(),
            pow_nonce,
            pow_hash,
            timestamp: tmp_record.registered_at,
            registrant_vk,
            signature,
        });

        // Try all discovered peers until one accepts the registration.
        // The lookup target is tried first since it confirmed reachability,
        // but it may have become stale â€” fall through to other peers.
        let mut registered = false;
        let ordered_peers = std::iter::once(target.clone())
            .chain(peers.iter().cloned().filter(|p| *p != target));
        for peer in ordered_peers {
            match node.send_message(&peer, &msg).await {
                Ok(()) => {
                    registered = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!(%e, "tag registration to peer failed â€” trying next peer");
                }
            }
        }
        node.shutdown().await;

        if !registered {
            anyhow::bail!(
                "could not send tag registration to any discovered peer; \
                 the tag may not be visible to the network until a peer relays it"
            );
        }

        if !cli.json {
            println!("Tag {} registration sent.", tag.display());
        }
    }

    if cli.json {
        wallet.save(&path, &enc_key)?;
        set_active_wallet_path(&path)?;
        println!(
            "{}",
            json!({
                "ok": true,
                "tag_registered": true,
                "wallet_name": wallet.name,
                "vesstag": tag.display(),
                "recovery_phrase": phrase.display_phrase(),
                "wallet_path": path.display().to_string(),
            })
        );
    } else {
        println!("\n=== WRITE DOWN YOUR RECOVERY PHRASE ===\n");
        println!("  {}\n", phrase.display_phrase());
        println!("This is the ONLY way to recover your wallet.");
        println!("=========================================\n");

        use std::io::{self, Write};

        println!("Please re-enter your recovery phrase to confirm you saved it.\n");

        print!("Enter your 12-word recovery phrase: ");
        io::stdout().flush()?;
        let mut phrase_input = String::new();
        io::stdin().read_line(&mut phrase_input)?;

        let phrase_match = RecoveryPhrase::from_input(&phrase_input)
            .map(|entered| entered == phrase)
            .unwrap_or(false);

        if !phrase_match {
            anyhow::bail!(
                "recovery phrase verification failed - wallet NOT saved. Run `vess init` again."
            );
        }

        if let Err(error) = maybe_store_local_phrase_backup(&phrase, &path) {
            eprintln!("Warning: could not create encrypted local backup: {error}");
        }

        wallet.save(&path, &enc_key)?;
        set_active_wallet_path(&path)?;
        println!(
            "Recovery phrase verified. Wallet created at {}",
            path.display()
        );
    }

    Ok(())
}

async fn cmd_recover(cli: &Cli, words: &str, wallet_name: Option<&str>) -> Result<()> {
    let verbose = !cli.json;
    let wallet_name = wallet_name
        .or(cli.wallet_name.as_deref())
        .map(normalize_wallet_tag_name)
        .transpose()?;
    let (path, _) = wallet_create_path(cli, wallet_name.as_deref())?;
    let phrase = RecoveryPhrase::from_input(words)?;

    let (secret, address) = recover_master_keys(&phrase)?;
    let raw_seed = derive_raw_seed(&phrase)?;
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = encrypt_secrets(&secret, &enc_key)?;

    let mut billfold = if path.exists() {
        let mut existing = WalletFile::load(&path)?;
        existing.decrypt_private_metadata(&enc_key)?;
        existing.billfold
    } else {
        BillFold::new()
    };

    if verbose {
        println!("Recovering bills via manifest...");
    }

    let node = MeshPulseNode::spawn().await?;
    node.wait_online().await;

    let targets = discover_recovery_targets(&node, verbose).await?;

    let peer_count = targets.len();
    if verbose {
        println!("  Using {peer_count} peer(s) for recovery");
    }

    let manifest_key = vess_foundry::seal::manifest_dht_key(&spend_seed);
    let manifest_req = PulseMessage::ManifestRecover(vess_protocol::ManifestRecover {
        dht_key: manifest_key,
    });

    let mut manifest_entries = Vec::new();
    let mut manifest_found = false;

    for peer in &targets {
        let resp = node.send_message_with_response(peer, &manifest_req).await;
        if let Ok(Some(PulseMessage::ManifestRecoverResponse(mrr))) = resp {
            if mrr.found {
                match vess_foundry::seal::decrypt_manifest(&spend_seed, &mrr.encrypted_manifest) {
                    Ok(entries) => {
                        manifest_entries = entries;
                        manifest_found = true;
                        if verbose {
                            println!(
                                "  Manifest found with {} bill entries",
                                manifest_entries.len()
                            );
                        }
                        break;
                    }
                    Err(e) => {
                        if verbose {
                            println!("  Manifest decrypt failed from peer: {e}");
                        }
                    }
                }
            }
        }
    }

    let mut recovered: u64 = 0;
    let mut max_dht_index: u64 = 0;

    if manifest_found && !manifest_entries.is_empty() {
        let mint_ids: Vec<[u8; 32]> = manifest_entries.iter().map(|e| e.mint_id).collect();
        let fetch_req = PulseMessage::OwnershipFetch(vess_protocol::OwnershipFetch {
            mint_ids: mint_ids.clone(),
        });

        let mut fetched_records = Vec::new();
        for peer in &targets {
            let resp = node.send_message_with_response(peer, &fetch_req).await;
            if let Ok(Some(PulseMessage::OwnershipFetchResponse(ofr))) = resp {
                fetched_records = ofr.records;
                break;
            }
        }

        for (i, entry) in manifest_entries.iter().enumerate() {
            if i >= fetched_records.len() {
                break;
            }
            let rec = &fetched_records[i];
            if !rec.found {
                if verbose {
                    println!(
                        "  [{}] mint_id {}: not found in registry",
                        i,
                        hex(&entry.mint_id[..4])
                    );
                }
                continue;
            }

            let denomination = match |v: u64| Some(v)(rec.amount_value)
            {
                Some(d) => d,
                None => {
                    if verbose {
                        println!(
                            "  [{i}] unknown denomination value: {}",
                            rec.amount_value
                        );
                    }
                    continue;
                }
            };

            let bill = vess_foundry::Vess {
                denomination,
                digest: rec.digest,
                created_at: 0,
                stealth_id: [0u8; 32],
                dht_index: entry.dht_index,
                mint_id: entry.mint_id,
                chain_tip: rec.chain_tip,
                chain_depth: 0,
                asset: u64::Vess,
            };

            if verbose {
                println!(
                    "  [{}] recovered {} bill (mint_id: {})",
                    i,
                    bill.amount,
                    hex(&bill.compute_vess_id()[..4]),
                );
            }
            billfold.deposit(bill);
            recovered += 1;
            if entry.dht_index >= max_dht_index {
                max_dht_index = entry.dht_index + 1;
            }
        }
    } else {
        if verbose {
            println!("  No manifest found on any peer. No bills recovered.");
        }
    }

    node.shutdown().await;
    if verbose {
        println!("Recovery complete: {recovered} bills recovered.");
    }

    let mut wallet = WalletFile::new(address, encrypted, billfold, spend_seed, &enc_key)?;
    wallet.name = wallet_name.clone();
    wallet.next_dht_index = max_dht_index;
    wallet.save(&path, &enc_key)?;
    set_active_wallet_path(&path)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "ok": true,
                "wallet_name": wallet.name,
                "wallet_path": path.display().to_string(),
                "recovered_bills": recovered,
                "balance": wallet.billfold.balance(),
            })
        );
    } else {
        println!("Wallet recovered successfully at {}", path.display());
        println!("Scan key:  {} bytes", secret.scan_dk.len());
        println!("Spend key: {} bytes", secret.spend_dk.len());
        println!("Balance: {} Vess", wallet.billfold.balance());
    }
    Ok(())
}

async fn cmd_balance(cli: &Cli) -> Result<()> {
    // â”€â”€ RPC path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if should_use_rpc(cli) {
        let port = rpc_port(cli);
        let resp = rpc_call(port, &json!({"method": "balance"})).await?;
        if resp["ok"] == true {
            if cli.json {
                println!("{resp}");
            } else {
                println!("Spendable:  {} Vess", resp["balance"]);
                if let Some(watch_only_balance) = resp["watch_only_balance"].as_u64() {
                    println!("Watch-only: {} Vess", watch_only_balance);
                }
                println!("Bills:      {}", resp["bill_count"]);
            }
        } else {
            anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
        }
        return Ok(());
    }

    let path = wallet_path(cli)?;
    let mut wallet = WalletFile::load(&path)?;
    let raw_seed = derive_raw_seed_for_wallet(cli)?;
    let enc_key = encryption_key_from_seed(&raw_seed);
    wallet.decrypt_private_metadata(&enc_key)?;

    if cli.json {
        let breakdown: serde_json::Map<String, serde_json::Value> = wallet
            .billfold
            .amount_breakdown()
            .into_iter()
            .map(|(d, c)| (format!("{d}"), json!(c)))
            .collect();
        println!(
            "{}",
            json!({
                "ok": true,
                "balance": wallet.billfold.balance(),
                "bills": wallet.billfold.count(),
                "denominations": breakdown,
            })
        );
    } else {
        println!("Balance: {} Vess", wallet.billfold.balance());
        println!("Bills:   {}", wallet.billfold.count());

        let breakdown = wallet.billfold.amount_breakdown();
        if !breakdown.is_empty() {
            println!("\nu64 breakdown:");
            for (denom, count) in breakdown {
                println!("  {denom}: {count}");
            }
        }
    }
    Ok(())
}

fn render_ascii_qr(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes())
        .map_err(|error| anyhow::anyhow!("failed to encode QR code: {error}"))?;
    Ok(code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .dark_color('#')
        .light_color(' ')
        .build())
}

async fn cmd_receive(cli: &Cli) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({"method": "node_info"})).await?;
    if resp["ok"] != true {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }

    let address = resp["bitcoin_receive_address"]
        .as_str()
        .filter(|address| !address.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "wallet is not loaded in the running node; open Vess interactively or run `vess node --wallet ... --rpc-port {port}`"
            )
        })?;
    let qr_ascii = render_ascii_qr(address)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "ok": true,
                "address": address,
                "bitcoin_receive_address": address,
                "qr_ascii": qr_ascii,
            })
        );
    } else {
        println!("Bitcoin receive address:");
        println!();
        println!("{address}");
        println!();
        println!("{qr_ascii}");
        println!("Notice: BTC sent to this address will be permanently upgraded to Vess.");
    }

    Ok(())
}

async fn cmd_notifications(cli: &Cli, follow: bool, interval_ms: u64, max: usize) -> Result<()> {
    let port = rpc_port(cli);

    loop {
        let resp = rpc_call(
            port,
            &json!({
                "method": "notifications",
                "max": max,
            }),
        )
        .await?;

        let notifications = resp["notifications"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let had_notifications = !notifications.is_empty();

        for note in &notifications {
            if cli.json {
                println!(
                    "{}",
                    json!({ "event": "notification", "notification": note })
                );
            } else {
                let kind = note["kind"].as_str().unwrap_or("notification");
                let payment_id = note["payment_id"].as_str().unwrap_or("?");
                let message = note["message"].as_str().unwrap_or("wallet event");
                println!("[{kind}] {message} (payment_id: {payment_id})");
            }
        }

        if !follow {
            if !had_notifications && !cli.json {
                println!("No notifications.");
            }
            return Ok(());
        }

        tokio::time::sleep(std::time::Duration::from_millis(interval_ms.max(100))).await;
    }
}

async fn auto_watch_send_confirmation(cli: &Cli, payment_id: &str, timeout_ms: u64) -> Result<()> {
    let port = rpc_port(cli);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);

    while std::time::Instant::now() < deadline {
        let resp = rpc_call(
            port,
            &json!({
                "method": "notifications",
                "max": 64,
                "payment_id": payment_id,
            }),
        )
        .await?;

        let notifications = resp["notifications"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut confirmed = false;

        for note in &notifications {
            let note_payment_id = note["payment_id"].as_str().unwrap_or("");
            if note_payment_id != payment_id {
                continue;
            }

            if cli.json {
                println!(
                    "{}",
                    json!({ "event": "notification", "notification": note })
                );
            } else {
                let kind = note["kind"].as_str().unwrap_or("notification");
                let message = note["message"].as_str().unwrap_or("wallet event");
                println!("[{kind}] {message}");
            }

            let kind = note["kind"].as_str().unwrap_or("");
            if kind == "payment_sent_confirmed" || kind == "payment_sent_released" {
                confirmed = true;
            }
        }

        if confirmed {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    Ok(())
}

async fn cmd_faucet(cli: &Cli, amount: u64) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(
        port,
        &json!({"method": "local_test_faucet", "amount": amount}),
    )
    .await?;
    if resp["ok"] == true {
        if cli.json {
            println!("{resp}");
        } else {
            println!("Local test faucet minted {} Vess.", resp["amount"]);
            println!("Bills:   {}", resp["bill_count"]);
            println!("Balance: {} Vess", resp["balance"]);
            println!("These bills are only valid on nodes started with VESS_LOCAL_TEST_FAUCET=1.");
        }
    } else {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(())
}

async fn cmd_compile(cli: &Cli, output: Option<&Path>, debug: bool) -> Result<()> {
    let workspace_root = find_workspace_root()?;
    let profile = if debug { "debug" } else { "release" };

    let mut build = std::process::Command::new("cargo");
    build
        .current_dir(&workspace_root)
        .arg("build")
        .arg("-p")
        .arg("vess-cli")
        .arg("--bin")
        .arg("vess");
    if !debug {
        build.arg("--release");
    }

    if !cli.json {
        println!("Building Vess {profile} executable...");
    }

    let status = build.status().context("failed to run cargo build")?;
    if !status.success() {
        anyhow::bail!("cargo build failed with status {status}");
    }

    let exe_name = if cfg!(windows) { "vess.exe" } else { "vess" };
    let built_exe = workspace_root.join("target").join(profile).join(exe_name);
    if !built_exe.exists() {
        anyhow::bail!("built executable was not found at {}", built_exe.display());
    }

    let output_path = match output {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => workspace_root.join(path),
        None => built_exe.clone(),
    };
    if output_path != built_exe {
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::copy(&built_exe, &output_path).with_context(|| {
            format!(
                "failed to copy {} to {}",
                built_exe.display(),
                output_path.display()
            )
        })?;
    }

    if cli.json {
        println!(
            "{}",
            json!({
                "ok": true,
                "profile": profile,
                "executable": output_path,
            })
        );
    } else {
        println!("Built Vess executable:");
        println!("  {}", output_path.display());
    }

    Ok(())
}

fn find_workspace_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir().context("read current directory")?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            let contents = std::fs::read_to_string(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?;
            if contents.contains("[workspace]") && contents.contains("\"vess-cli\"") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            anyhow::bail!(
                "could not find the Vess workspace root; run this command from inside the source tree"
            );
        }
    }
}

async fn cmd_send(
    cli: &Cli,
    amount: u64,
    recipient_id: &str,
    memo: Option<&str>,
    node_direct: Option<&str>,
) -> Result<()> {
    let port = rpc_port(cli);
    let mut req = if let Some(node_id) = node_direct {
        json!({
            "method": "send_direct",
            "amount": amount,
            "recipient": recipient_id,
            "target": node_id,
        })
    } else {
        json!({
            "method": "send",
            "amount": amount,
            "recipient": recipient_id,
        })
    };
    if let Some(m) = memo {
        req["memo"] = json!(m);
    }
    let resp = rpc_call(port, &req).await?;
    if resp["ok"] == true {
        let payment_id = resp["payment_id"].as_str().unwrap_or("?").to_string();
        if cli.json {
            println!("{resp}");
        } else {
            if node_direct.is_some() {
                println!("Direct payment accepted by target contact.");
            } else {
                println!("Payment sent!");
            }
            println!("Payment ID: {}", payment_id);
            println!("Amount:     {} Vess", resp["amount"]);
            println!("Balance:    {} Vess", resp["remaining_balance"]);
        }

        // Automatic confirmation watch: no extra command needed.
        // For relay sends, this catches the eventual recipient claim event.
        // For direct sends, the accepted response is immediate but we still
        // drain any matching queued notification for consistency.
        auto_watch_send_confirmation(cli, &payment_id, 15_000).await?;
    } else {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(())
}

async fn cmd_register_tag(cli: &Cli, tag_str: &str) -> Result<()> {
    let verbose = !cli.json;
    let path = wallet_path(cli)?;
    let mut wallet = WalletFile::load(&path)?;

    // Derive enc_key â€” needed to encrypt the new tag signing key.
    let password = std::env::var("VESS_WALLET_PASSWORD").map_err(|_| {
        anyhow::anyhow!("VESS_WALLET_PASSWORD required for register-tag (encrypts tag signing key)")
    })?;
    let raw_seed = wallet.unlock_with_password(&password)?;
    let enc_key = vess_sovereign::recovery::encryption_key_from_seed(&raw_seed);
    wallet.decrypt_private_metadata(&enc_key)?;

    let tag = VessTag::new(tag_str)?;

    if verbose {
        println!("Registering tag {}", tag.display());
        println!("Computing Argon2id proof-of-work (this takes ~10 seconds and 2 GiB RAM)â€¦");
    }

    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();

    // Compute proof-of-work.
    let (pow_nonce, pow_hash) = vess_tag::compute_tag_pow(
        &tag_hash,
        &wallet.master_address.scan_ek,
        &wallet.master_address.spend_ek,
    )?;

    // Generate an ML-DSA keypair to sign the tag record.
    let (registrant_vk, registrant_sk) = vess_foundry::spend_auth::generate_spend_keypair();

    // Save the registrant keypair (encrypted) to the wallet.
    wallet.tag_registrant_vk = registrant_vk.clone();
    wallet.set_encrypted_tag_sk(&registrant_sk, &enc_key)?;
    wallet.save(&path, &enc_key)?;

    // Construct a temporary TagRecord to compute the digest for signing.
    let tmp_record = vess_tag::TagRecord {
        tag_hash,
        master_address: vess_stealth::MasterStealthAddress {
            scan_ek: wallet.master_address.scan_ek.clone(),
            spend_ek: wallet.master_address.spend_ek.clone(),
        },
        pow_nonce,
        pow_hash: pow_hash.clone(),
        registered_at: now_unix(),
        registrant_vk: registrant_vk.clone(),
        signature: Vec::new(),
        hardened_at: None,
    };
    let digest = tmp_record.digest();
    let signature = vess_foundry::spend_auth::sign_spend(&registrant_sk, &digest)?;
    wallet.set_tag_registration(
        pow_nonce,
        pow_hash.clone(),
        tmp_record.registered_at,
        signature.clone(),
        &enc_key,
    )?;
    wallet.save(&path, &enc_key)?;

    // Send registration via RPC to local artery node.
    let port = rpc_port(cli);
    let resp = rpc_call(
        port,
        &json!({
            "method": "tag_register",
            "tag": tag.as_str(),
            "scan_ek_hex": hex(&wallet.master_address.scan_ek),
            "spend_ek_hex": hex(&wallet.master_address.spend_ek),
            "pow_nonce_hex": hex(&pow_nonce),
            "pow_hash_hex": hex(&pow_hash),
            "timestamp": tmp_record.registered_at,
            "registrant_vk_hex": hex(&registrant_vk),
            "signature_hex": hex(&signature),
        }),
    )
    .await?;

    if resp["ok"] != true {
        anyhow::bail!(
            "{}",
            resp["error"].as_str().unwrap_or("tag registration failed")
        );
    }

    if !cli.json {
        println!("Tag {} registration sent.", tag.display());
    }

    // â”€â”€ Auto-harden with first available bill â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let (auto_hardening_attempted, hardened, hardening_error) = if let Some(bill) = wallet.billfold.bills().first() {
        let mint_id = bill.compute_vess_id();
        let confirm_digest = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-tag-confirm-v1");
            h.update(tag.as_str().as_bytes());
            h.update(&mint_id);
            *h.finalize().as_bytes()
        };
        let confirm_sig = vess_foundry::spend_auth::sign_spend(&registrant_sk, &confirm_digest)?;

        let confirm_resp = rpc_call(
            port,
            &json!({
                "method": "tag_confirm",
                "tag": tag.as_str(),
                "mint_id_hex": hex(&mint_id),
                "registrant_vk_hex": hex(&registrant_vk),
                "signature_hex": hex(&confirm_sig),
            }),
        )
        .await?;

        if confirm_resp["ok"] == true {
            if verbose {
                println!("Tag {} auto-hardened with bill proof.", tag.display());
            }
            (true, true, None)
        } else {
            let error = confirm_resp["error"].as_str().unwrap_or("unknown").to_string();
            if verbose {
                println!(
                    "Tag registered but hardening failed: {}",
                    error
                );
                println!("You can harden later once you have bills in your wallet.");
            }
            (true, false, Some(error))
        }
    } else {
        if verbose {
            println!("No bills in wallet â€” tag registered but not hardened.");
            println!("The tag will be auto-hardened when you receive bills.");
        }
        (false, false, Some("no bills in wallet".to_string()))
    };

    if cli.json {
        println!(
            "{}",
            json!({
                "ok": true,
                "tag_registered": true,
                "tag": tag.display(),
                "auto_hardening_attempted": auto_hardening_attempted,
                "hardened": hardened,
                "hardening_error": hardening_error,
            })
        );
    }
    Ok(())
}

async fn cmd_pulse(cli: &Cli, target: &str, message: &str) -> Result<()> {
    let target = parse_mesh_contact(target)?;
    let carrier = spawn_udp_mesh_carrier().await?;
    carrier.send(&target, message.as_bytes()).await?;
    if cli.json {
        println!("{}", json!({ "ok": true, "target": target }));
    } else {
        println!("Pulse delivered.");
    }
    Ok(())
}

async fn cmd_listen(cli: &Cli) -> Result<()> {
    let json_mode = cli.json;
    let carrier = spawn_udp_mesh_carrier().await?;
    let local_contact = carrier.local_contact();
    let local_contact_string = encode_mesh_contact_string(&local_contact)?;

    if json_mode {
        println!(
            "{}",
            json!({
                "event": "ready",
                "node_id": local_contact
                    .node_id()
                    .map(|node_id| node_id.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                "node_contact": local_contact_string,
            })
        );
    } else {
        println!(
            "Node ID:   {}",
            local_contact
                .node_id()
                .map(|node_id| node_id.to_string())
                .unwrap_or_else(|| "?".to_string())
        );
        println!("Mesh contact: {}", local_contact_string);
        println!("Listening for Pulsesâ€¦ (Ctrl+C to stop)\n");
    }

    carrier
        .listen_with_response(move |peer, payload| {
            if json_mode {
                let msg = String::from_utf8_lossy(&payload);
                let peer_contact = encode_mesh_contact_string(&peer.contact)
                    .unwrap_or_else(|_| peer.contact.to_string());
                println!(
                    "{}",
                    serde_json::json!({ "event": "pulse", "peer": peer_contact, "payload": msg })
                );
            } else {
                let msg = String::from_utf8_lossy(&payload);
                println!("[{}] {msg}", peer.contact);
            }
            Vec::new()
        })
        .await?;
    Ok(())
}

async fn cmd_set_password(cli: &Cli, password: String) -> Result<()> {
    let path = wallet_path(cli)?;
    let mut wallet = WalletFile::load(&path)?;

    // Obtain the raw_seed â€” from existing password or recovery phrase.
    let raw_seed = derive_raw_seed_for_wallet(cli)?;
    let enc_key = encryption_key_from_seed(&raw_seed);

    wallet.set_password_cache(&raw_seed, &password)?;
    wallet.save(&path, &enc_key)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "ok": true,
                "password_set": true,
                "wallet_path": path.display().to_string(),
            })
        );
    } else {
        println!("Password set. Open Vess interactively to choose and load this wallet.");
    }
    Ok(())
}

async fn cmd_tag_cache_list(cli: &Cli) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &serde_json::json!({ "method": "tag_cache_list" })).await?;
    if resp["ok"] != true {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    let entries = resp["entries"].as_array().cloned().unwrap_or_default();
    if cli.json {
        println!("{resp}");
    } else if entries.is_empty() {
        println!("Tag cache is empty.");
    } else {
        println!("{:<20} {:<12} {}", "TAG", "LAST USED", "VERIFIED AT");
        println!("{}", "-".repeat(60));
        for e in &entries {
            let tag = e["tag"].as_str().unwrap_or("?");
            let last_used = e["last_used"].as_u64().unwrap_or(0);
            let verified_at = e["verified_at"].as_u64().unwrap_or(0);
            println!("+{tag:<19} {last_used:<12} {verified_at}");
        }
        println!("\n{} cached tag(s)", entries.len());
    }
    Ok(())
}

async fn cmd_tag_cache_clear(cli: &Cli, tag: Option<&str>) -> Result<()> {
    let port = rpc_port(cli);
    let req = match tag {
        Some(t) => serde_json::json!({ "method": "tag_cache_clear", "tag": t }),
        None => serde_json::json!({ "method": "tag_cache_clear" }),
    };
    let resp = rpc_call(port, &req).await?;
    if resp["ok"] != true {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    if cli.json {
        println!("{resp}");
    } else {
        match tag {
            Some(t) => println!(
                "Removed +{} from tag cache.",
                t.strip_prefix('+').unwrap_or(t)
            ),
            None => println!("Tag cache cleared."),
        }
    }
    Ok(())
}

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// â”€â”€ Background-service helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// ~/.vess/ directory (wallet + PID + log live here).
fn vess_data_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let h = home.ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(h.join(".vess"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cli_node_pool_dir(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vess-cli-node-pool-{test_name}-{:016x}",
            rand::thread_rng().gen::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reuses_existing_unleased_slot_before_creating_new_one() {
        let base_dir = temp_cli_node_pool_dir("reuse-existing");
        let busy_slot = base_dir.join("slot-0001");
        let free_slot = base_dir.join("slot-0002");
        std::fs::create_dir_all(&busy_slot).unwrap();
        std::fs::create_dir_all(&free_slot).unwrap();

        write_cli_node_lease(
            &busy_slot.join("lease.json"),
            &CliNodeLease {
                owner_pid: 42,
                node_pid: Some(420),
                claimed_at_unix: 1,
            },
        )
        .unwrap();

        let slot = allocate_cli_node_slot_with(&base_dir, 1000, &|pid| pid == 42 || pid == 420)
            .unwrap();
        assert_eq!(slot.state_dir, free_slot);
        assert_eq!(read_cli_node_lease(&slot.lease_path).unwrap().owner_pid, 1000);

        release_cli_node_slot(&slot.lease_path);
        let _ = std::fs::remove_dir_all(base_dir);
    }

    #[test]
    fn reclaims_stale_slot_lease_before_allocating_new_slot() {
        let base_dir = temp_cli_node_pool_dir("reclaim-stale");
        let stale_slot = base_dir.join("slot-0001");
        std::fs::create_dir_all(&stale_slot).unwrap();

        write_cli_node_lease(
            &stale_slot.join("lease.json"),
            &CliNodeLease {
                owner_pid: 77,
                node_pid: Some(770),
                claimed_at_unix: 1,
            },
        )
        .unwrap();

        let slot = allocate_cli_node_slot_with(&base_dir, 2000, &|_| false).unwrap();
        assert_eq!(slot.state_dir, stale_slot);

        let lease = read_cli_node_lease(&slot.lease_path).unwrap();
        assert_eq!(lease.owner_pid, 2000);
        assert_eq!(lease.node_pid, None);

        release_cli_node_slot(&slot.lease_path);
        let _ = std::fs::remove_dir_all(base_dir);
    }
}
