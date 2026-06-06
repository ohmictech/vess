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

use vess_compute::{
    compute_program_pow, ProgramDefinition, ProgramManifest, ProgramName, ProgramVersionPointer,
    ProofSystem, StoredProgram, VessLogicProgram,
};
use vess_kloak::persistence::{
    list_wallets, named_wallet_path, read_active_wallet_path, set_active_wallet_path,
    WalletDescriptor, WalletFile,
};
use vess_kloak::recovery::{
    derive_key_from_password, derive_raw_seed, encrypt_secrets, encryption_key_from_seed,
    recover_master_keys, spend_seed_from_raw_seed, RecoveryPhrase,
};
use vess_kloak::BillFold;
use vess_mesh::{
    decode_mesh_contact, decode_mesh_contact_string, encode_mesh_contact_string,
    validate_mesh_contact, MeshCarrier, MeshCarrierContact, PqUdpMeshCarrier,
};
use vess_protocol::{PulseMessage, TagLookup, TagRegister};
use vess_stealth::generate_master_keys_from_seed;
use vess_tag::VessTag;
use vess_vascular::MeshPulseNode;

#[derive(Parser)]
#[command(name = "vess", version, about = "Vess — stateless P2P digital cash")]
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

    /// Deploy a decentralized program from a local directory.
    Deploy {
        /// Program root directory, or a single `.vess` source file.
        directory: PathBuf,
        /// Human-facing program name to publish, for example `+vl_market1`.
        #[arg(long)]
        name: String,
        /// Program entrypoints exposed by the artifact.
        #[arg(long, value_delimiter = ',', default_value = "main")]
        entrypoints: Vec<String>,
        /// Proof system identifier.
        #[arg(long, default_value = "vess-stark-v1")]
        proof_system: String,
        /// Maximum cycle budget expected by the program.
        #[arg(long, default_value_t = 1_000_000)]
        max_cycles: u64,
        /// Maximum memory footprint expected by the program.
        #[arg(long, default_value_t = 2_147_483_648u64)]
        max_memory_bytes: u64,
        /// Mark the program as allowed to own bills directly.
        #[arg(long)]
        supports_program_owned_bills: bool,
        /// Manifest version number when publishing a named program.
        #[arg(long, default_value_t = 1)]
        version: u32,
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
        #[arg(long, default_value = "6")]
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
        /// Join the public testnet (Bitcoin signet, production safety, zero-config seed peers).
        /// Equivalent to --profile testnet.
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

    /// Manage the local VessTag address book (persistent tag → stealth address cache).
    #[command(subcommand)]
    TagCache(TagCacheCmd),
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
            0 => vess_kloak::persistence::default_wallet_path(),
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
    Ok((vess_kloak::persistence::default_wallet_path()?, None))
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
        None => cmd_interactive(&cli).await,
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
        Some(Command::Deploy {
            directory,
            name,
            entrypoints,
            proof_system,
            max_cycles,
            max_memory_bytes,
            supports_program_owned_bills,
            version,
        }) => {
            cmd_deploy(
                &cli,
                directory,
                name,
                entrypoints,
                proof_system,
                *max_cycles,
                *max_memory_bytes,
                *supports_program_owned_bills,
                *version,
            )
            .await
        }
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
            };
            vess_artery::node_runner::run_node(config).await?;
            Ok(())
        }
        Some(Command::SetPassword { password }) => cmd_set_password(&cli, password.clone()).await,
        Some(Command::TagCache(sub)) => match sub {
            TagCacheCmd::List => cmd_tag_cache_list(&cli).await,
            TagCacheCmd::Clear { tag } => cmd_tag_cache_clear(&cli, tag.as_deref()).await,
        },
    }
}

// ── Subcommand implementations ──────────────────────────────────────

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
            "cannot read RPC token from {}: {} — is the node running?",
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
    if let Some(path) = std::env::var_os(VESS_RPC_STATE_DIR_ENV) {
        return Ok(PathBuf::from(path));
    }
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
        anyhow::anyhow!("cannot connect to node RPC at {addr}: {e} — is the node running with --rpc-port {port}?")
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

const VESS_RPC_PORT_ENV: &str = "VESS_RPC_PORT";
const VESS_RPC_STATE_DIR_ENV: &str = "VESS_RPC_STATE_DIR";
const VESS_NODE_PID_ENV: &str = "VESS_NODE_PID";

/// Return the RPC port to use: explicit --rpc flag, interactive instance env,
/// or default 9400.
fn rpc_port(cli: &Cli) -> u16 {
    cli.rpc
        .or_else(|| {
            std::env::var(VESS_RPC_PORT_ENV)
                .ok()
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(vess_artery::rpc::DEFAULT_RPC_PORT)
}

fn should_use_rpc(cli: &Cli) -> bool {
    cli.rpc.is_some() || std::env::var_os(VESS_RPC_PORT_ENV).is_some()
}

fn parse_proof_system(value: &str) -> Result<ProofSystem> {
    match value.trim().to_ascii_lowercase().as_str() {
        "vess-stark-v1" => Ok(ProofSystem::VessStarkV1),
        "vess-stark-aggregate-v1" => Ok(ProofSystem::VessStarkAggregateV1),
        other => anyhow::bail!(
            "unsupported proof system {other}; use vess-stark-v1 or vess-stark-aggregate-v1"
        ),
    }
}

fn normalized_program_rel_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not inside {}", path.display(), root.display()))?;
    Ok(rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}

fn collect_program_directory_entries(
    root: &Path,
    dir: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("read program directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_program_directory_entries(root, &path, entries)?;
        } else if file_type.is_file() {
            let rel = normalized_program_rel_path(root, &path)?;
            let bytes = std::fs::read(&path)
                .with_context(|| format!("read program file {}", path.display()))?;
            entries.push((rel, bytes));
        }
    }
    Ok(())
}

fn collect_program_source_files(dir: &Path, sources: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_program_source_files(&path, sources)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("vess"))
                .unwrap_or(false)
        {
            sources.push(path);
        }
    }
    Ok(())
}

fn load_vesslogic_program(path: &Path) -> Result<Option<VessLogicProgram>> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", path.display()))?;
    if canonical.is_file() {
        let is_vess = canonical
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("vess"))
            .unwrap_or(false);
        if !is_vess {
            return Ok(None);
        }
        let source = std::fs::read_to_string(&canonical)
            .with_context(|| format!("read {}", canonical.display()))?;
        return Ok(Some(VessLogicProgram::parse(&source)?));
    }
    if !canonical.is_dir() {
        anyhow::bail!("program path {} is neither a file nor a directory", canonical.display());
    }

    let mut sources = Vec::new();
    collect_program_source_files(&canonical, &mut sources)?;
    match sources.len() {
        0 => Ok(None),
        1 => {
            let source = std::fs::read_to_string(&sources[0])
                .with_context(|| format!("read {}", sources[0].display()))?;
            Ok(Some(VessLogicProgram::parse(&source)?))
        }
        _ => anyhow::bail!(
            "program directory {} contains multiple .vess files; keep exactly one VessLogic source per deploy root",
            canonical.display()
        ),
    }
}

fn program_bundle_from_directory(directory: &Path) -> Result<Vec<u8>> {
    let directory = directory
        .canonicalize()
        .with_context(|| format!("canonicalize {}", directory.display()))?;
    if !directory.is_dir() {
        anyhow::bail!("program path {} is not a directory", directory.display());
    }

    let mut entries = Vec::new();
    collect_program_directory_entries(&directory, &directory, &mut entries)?;
    if entries.is_empty() {
        anyhow::bail!("program directory {} is empty", directory.display());
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut bundle = Vec::new();
    for (path, bytes) in entries {
        bundle.extend_from_slice(&(path.len() as u64).to_le_bytes());
        bundle.extend_from_slice(path.as_bytes());
        bundle.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        bundle.extend_from_slice(&bytes);
    }
    Ok(bundle)
}

fn tagged_program_hash(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn load_optional_program_file(directory: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let path = directory.join(name);
    if !path.exists() {
        return Ok(None);
    }
    if !path.is_file() {
        anyhow::bail!("{} exists but is not a file", path.display());
    }
    Ok(Some(
        std::fs::read(&path).with_context(|| format!("read program file {}", path.display()))?,
    ))
}

fn build_program_definition_from_directory(
    directory: &Path,
    entrypoints: &[String],
    proof_system: ProofSystem,
    max_cycles: u64,
    max_memory_bytes: u64,
    supports_program_owned_bills: bool,
) -> Result<ProgramDefinition> {
    let canonical_dir = directory
        .canonicalize()
        .with_context(|| format!("canonicalize {}", directory.display()))?;
    let base_dir = if canonical_dir.is_dir() {
        canonical_dir.clone()
    } else {
        canonical_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", canonical_dir.display()))?
            .to_path_buf()
    };
    let metadata_bytes = load_optional_program_file(&base_dir, "metadata.json")?;
    let abi_bytes = load_optional_program_file(&base_dir, "abi.json")?;
    let public_inputs_bytes = load_optional_program_file(&base_dir, "public_inputs.json")?;
    let public_outputs_bytes = load_optional_program_file(&base_dir, "public_outputs.json")?;

    if let Some(vesslogic_program) = load_vesslogic_program(&canonical_dir)? {
        let compiled = vesslogic_program.compile();
        return Ok(ProgramDefinition {
            code: compiled.clone(),
            proof_system,
            public_input_schema_hash: tagged_program_hash(
                b"vess-program-public-inputs-v1",
                public_inputs_bytes.as_deref().unwrap_or(&compiled),
            ),
            public_output_schema_hash: tagged_program_hash(
                b"vess-program-public-outputs-v1",
                public_outputs_bytes.as_deref().unwrap_or(&compiled),
            ),
            metadata_hash: tagged_program_hash(
                b"vess-program-metadata-v1",
                metadata_bytes.as_deref().unwrap_or(&compiled),
            ),
            abi_hash: tagged_program_hash(
                b"vess-program-abi-v1",
                abi_bytes.as_deref().unwrap_or(&compiled),
            ),
            max_cycles,
            max_memory_bytes,
            supports_program_owned_bills,
            entrypoints: vesslogic_program.entrypoints(),
        });
    }

    let bundle = program_bundle_from_directory(&canonical_dir)?;

    Ok(ProgramDefinition {
        code: bundle.clone(),
        proof_system,
        public_input_schema_hash: tagged_program_hash(
            b"vess-program-public-inputs-v1",
            public_inputs_bytes.as_deref().unwrap_or(&bundle),
        ),
        public_output_schema_hash: tagged_program_hash(
            b"vess-program-public-outputs-v1",
            public_outputs_bytes.as_deref().unwrap_or(&bundle),
        ),
        metadata_hash: tagged_program_hash(
            b"vess-program-metadata-v1",
            metadata_bytes.as_deref().unwrap_or(&bundle),
        ),
        abi_hash: tagged_program_hash(
            b"vess-program-abi-v1",
            abi_bytes.as_deref().unwrap_or(&bundle),
        ),
        max_cycles,
        max_memory_bytes,
        supports_program_owned_bills,
        entrypoints: entrypoints.to_vec(),
    })
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
        // but it may have become stale — fall through to other peers.
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
                    tracing::warn!(%e, "tag registration to peer failed — trying next peer");
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

            let denomination = match vess_foundry::Denomination::from_value(rec.denomination_value)
            {
                Some(d) => d,
                None => {
                    if verbose {
                        println!(
                            "  [{i}] unknown denomination value: {}",
                            rec.denomination_value
                        );
                    }
                    continue;
                }
            };

            let bill = vess_foundry::VessBill {
                denomination,
                digest: rec.digest,
                created_at: 0,
                stealth_id: [0u8; 32],
                dht_index: entry.dht_index,
                mint_id: entry.mint_id,
                chain_tip: rec.chain_tip,
                chain_depth: 0,
            };

            if verbose {
                println!(
                    "  [{}] recovered {} bill (mint_id: {})",
                    i,
                    bill.denomination,
                    hex(&bill.mint_id[..4]),
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
    // ── RPC path ────────────────────────────────────────────────────
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
            .denomination_breakdown()
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

        let breakdown = wallet.billfold.denomination_breakdown();
        if !breakdown.is_empty() {
            println!("\nDenomination breakdown:");
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
                "interactive_on_launch": true,
            })
        );
    } else {
        println!("Built interactive Vess executable:");
        println!("  {}", output_path.display());
        println!("Run it with no arguments, or double-click it, to open the interactive CLI.");
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

    // Derive enc_key — needed to encrypt the new tag signing key.
    let password = std::env::var("VESS_WALLET_PASSWORD").map_err(|_| {
        anyhow::anyhow!("VESS_WALLET_PASSWORD required for register-tag (encrypts tag signing key)")
    })?;
    let raw_seed = wallet.unlock_with_password(&password)?;
    let enc_key = vess_kloak::recovery::encryption_key_from_seed(&raw_seed);
    wallet.decrypt_private_metadata(&enc_key)?;

    let tag = VessTag::new(tag_str)?;

    if verbose {
        println!("Registering tag {}", tag.display());
        println!("Computing Argon2id proof-of-work (this takes ~10 seconds and 2 GiB RAM)…");
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

    // ── Auto-harden with first available bill ────────────────────
    let (auto_hardening_attempted, hardened, hardening_error) = if let Some(bill) = wallet.billfold.bills().first() {
        let mint_id = bill.mint_id;
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
            println!("No bills in wallet — tag registered but not hardened.");
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

async fn cmd_deploy(
    cli: &Cli,
    directory: &Path,
    name: &str,
    entrypoints: &[String],
    proof_system: &str,
    max_cycles: u64,
    max_memory_bytes: u64,
    supports_program_owned_bills: bool,
    version: u32,
) -> Result<()> {
    let proof_system = parse_proof_system(proof_system)?;
    let definition = build_program_definition_from_directory(
        directory,
        entrypoints,
        proof_system,
        max_cycles,
        max_memory_bytes,
        supports_program_owned_bills,
    )?;
    let prog_id = definition.prog_id();

    if !cli.json {
        println!("Deploying program from {}", directory.display());
        println!("Computing Argon2id proof-of-work (this takes ~10 seconds and 2 GiB RAM)…");
    }

    let (pow_nonce, pow_hash) = compute_program_pow(&prog_id, None)?;
    let published_at = now_unix();
    let name = ProgramName::new(name)?;
    let program = StoredProgram {
        definition,
        published_at,
        pow_nonce,
        pow_hash,
        publisher_vk: None,
        signature: Vec::new(),
        last_bill_sent_at: None,
    };
    let manifest = ProgramManifest {
        name,
        latest_prog_id: prog_id,
        versions: vec![ProgramVersionPointer {
            version,
            prog_id,
            changelog_hash: [0u8; 32],
        }],
        created_at: published_at,
        updated_at: published_at,
        publisher_vk: None,
        signature: Vec::new(),
    };

    let port = rpc_port(cli);
    let resp = rpc_call(
        port,
        &json!({
            "method": "program_deploy",
            "program": program,
            "manifest": manifest,
        }),
    )
    .await?;

    if resp["ok"] != true {
        anyhow::bail!(
            "{}",
            resp["error"].as_str().unwrap_or("program deploy failed")
        );
    }

    if cli.json {
        println!("{resp}");
    } else {
        println!("Program deployed.");
        println!("Program ID: {}", resp["prog_id"].as_str().unwrap_or("?"));
        println!("Name:       {}", resp["name"].as_str().unwrap_or("?"));
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
        println!("Listening for Pulses… (Ctrl+C to stop)\n");
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

    // Obtain the raw_seed — from existing password or recovery phrase.
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

// ── Helpers ──────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Background-service helpers ────────────────────────────────────────

/// ~/.vess/ directory (wallet + PID + log live here).
fn vess_data_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let h = home.ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(h.join(".vess"))
}

fn node_pid_path() -> Result<PathBuf> {
    Ok(vess_data_dir()?.join("node.pid"))
}

fn read_node_pid() -> Option<u32> {
    if let Some(pid) = std::env::var(VESS_NODE_PID_ENV)
        .ok()
        .and_then(|value| value.trim().parse().ok())
    {
        return Some(pid);
    }
    node_pid_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse().ok())
}

fn clear_node_pid() {
    if std::env::var_os(VESS_NODE_PID_ENV).is_some() {
        std::env::remove_var(VESS_NODE_PID_ENV);
        return;
    }
    if let Ok(p) = node_pid_path() {
        let _ = std::fs::remove_file(p);
    }
}

/// Check if a process with the given PID is still alive.
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output();
        match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
            Err(_) => false,
        }
    }
}

/// Send SIGTERM (Unix) or taskkill (Windows) to a process.
fn kill_pid(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()?;
        if !status.success() {
            anyhow::bail!("kill returned non-zero for PID {pid}");
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()?;
        Ok(())
    }
}

/// Print a prompt and read a line from stdin.
fn prompt(msg: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{msg}");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Read a password from the terminal without echoing it.
fn prompt_password(msg: &str) -> Result<String> {
    rpassword::prompt_password(msg).map_err(|e| anyhow::anyhow!("{e}"))
}

#[derive(Clone)]
struct ActiveNodeRecord {
    pid: u32,
    lease_path: PathBuf,
}

type ActiveNodeRef = std::sync::Arc<std::sync::Mutex<Option<ActiveNodeRecord>>>;

#[derive(Clone)]
struct CliNodeSlot {
    state_dir: PathBuf,
    lease_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CliNodeLease {
    owner_pid: u32,
    #[serde(default)]
    node_pid: Option<u32>,
    claimed_at_unix: u64,
}

impl CliNodeSlot {
    fn record_node_pid(&self, owner_pid: u32, node_pid: u32) -> Result<()> {
        write_cli_node_lease(
            &self.lease_path,
            &CliNodeLease {
                owner_pid,
                node_pid: Some(node_pid),
                claimed_at_unix: now_unix(),
            },
        )
    }
}

struct NodeProcessGuard {
    child: std::process::Child,
    pid: u32,
    port: u16,
    state_dir: PathBuf,
    lease_path: PathBuf,
    active_node: ActiveNodeRef,
}

impl NodeProcessGuard {
    fn is_running(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_none() && is_pid_alive(self.pid)
    }

    fn stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        release_cli_node_slot(&self.lease_path);
        clear_interactive_node_env(self.pid, self.port, &self.state_dir);
        if let Ok(mut active) = self.active_node.lock() {
            if active
                .as_ref()
                .map(|record| record.pid == self.pid)
                .unwrap_or(false)
            {
                *active = None;
            }
        }
        Ok(())
    }
}

impl Drop for NodeProcessGuard {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn allocate_local_rpc_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

fn cli_node_slots_dir() -> Result<PathBuf> {
    Ok(vess_data_dir()?.join("cli-nodes"))
}

fn read_cli_node_lease(lease_path: &Path) -> Option<CliNodeLease> {
    std::fs::read(lease_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn write_cli_node_lease(lease_path: &Path, lease: &CliNodeLease) -> Result<()> {
    let bytes = serde_json::to_vec(lease).context("serialize CLI node lease")?;
    std::fs::write(lease_path, bytes)
        .with_context(|| format!("write CLI node lease: {}", lease_path.display()))?;
    Ok(())
}

fn create_cli_node_lease(lease_path: &Path, lease: &CliNodeLease) -> Result<bool> {
    use std::io::Write;

    if let Some(parent) = lease_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(lease).context("serialize CLI node lease")?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(lease_path)
    {
        Ok(mut file) => {
            file.write_all(&bytes)
                .with_context(|| format!("write CLI node lease: {}", lease_path.display()))?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("create CLI node lease: {}", lease_path.display())),
    }
}

fn release_cli_node_slot(lease_path: &Path) {
    let _ = std::fs::remove_file(lease_path);
}

fn cli_node_lease_is_active<F>(lease: &CliNodeLease, is_alive: &F) -> bool
where
    F: Fn(u32) -> bool,
{
    is_alive(lease.owner_pid) || lease.node_pid.map(is_alive).unwrap_or(false)
}

fn try_claim_cli_node_slot_with<F>(
    slot_dir: &Path,
    owner_pid: u32,
    is_alive: &F,
) -> Result<Option<CliNodeSlot>>
where
    F: Fn(u32) -> bool,
{
    std::fs::create_dir_all(slot_dir)
        .with_context(|| format!("create CLI node slot dir: {}", slot_dir.display()))?;

    let lease_path = slot_dir.join("lease.json");
    if let Some(lease) = read_cli_node_lease(&lease_path) {
        if cli_node_lease_is_active(&lease, is_alive) {
            return Ok(None);
        }
        release_cli_node_slot(&lease_path);
    } else if lease_path.exists() {
        release_cli_node_slot(&lease_path);
    }

    let lease = CliNodeLease {
        owner_pid,
        node_pid: None,
        claimed_at_unix: now_unix(),
    };
    if create_cli_node_lease(&lease_path, &lease)? {
        return Ok(Some(CliNodeSlot {
            state_dir: slot_dir.to_path_buf(),
            lease_path,
        }));
    }
    Ok(None)
}

fn allocate_cli_node_slot_with<F>(base_dir: &Path, owner_pid: u32, is_alive: &F) -> Result<CliNodeSlot>
where
    F: Fn(u32) -> bool,
{
    std::fs::create_dir_all(base_dir)
        .with_context(|| format!("create CLI node pool dir: {}", base_dir.display()))?;

    let mut existing_dirs = Vec::new();
    for entry in std::fs::read_dir(base_dir)
        .with_context(|| format!("read CLI node pool dir: {}", base_dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            existing_dirs.push(entry.path());
        }
    }
    existing_dirs.sort();

    for slot_dir in existing_dirs {
        if let Some(slot) = try_claim_cli_node_slot_with(&slot_dir, owner_pid, is_alive)? {
            return Ok(slot);
        }
    }

    for index in 1u32.. {
        let slot_dir = base_dir.join(format!("slot-{index:04}"));
        if let Some(slot) = try_claim_cli_node_slot_with(&slot_dir, owner_pid, is_alive)? {
            return Ok(slot);
        }
    }

    unreachable!("CLI node slot allocator exhausted unexpectedly")
}

fn allocate_cli_node_slot() -> Result<CliNodeSlot> {
    let owner_pid = std::process::id();
    let base_dir = cli_node_slots_dir()?;
    allocate_cli_node_slot_with(&base_dir, owner_pid, &is_pid_alive)
}

fn set_interactive_node_env(pid: u32, port: u16, state_dir: &Path) {
    std::env::set_var(VESS_NODE_PID_ENV, pid.to_string());
    std::env::set_var(VESS_RPC_PORT_ENV, port.to_string());
    std::env::set_var(VESS_RPC_STATE_DIR_ENV, state_dir);
}

fn clear_interactive_node_env(pid: u32, port: u16, state_dir: &Path) {
    if std::env::var(VESS_NODE_PID_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        == Some(pid)
    {
        std::env::remove_var(VESS_NODE_PID_ENV);
    }
    if std::env::var(VESS_RPC_PORT_ENV)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        == Some(port)
    {
        std::env::remove_var(VESS_RPC_PORT_ENV);
    }
    if std::env::var_os(VESS_RPC_STATE_DIR_ENV)
        .map(PathBuf::from)
        .as_deref()
        == Some(state_dir)
    {
        std::env::remove_var(VESS_RPC_STATE_DIR_ENV);
    }
}

fn install_interactive_node_signal_handler(active_node: ActiveNodeRef) {
    let _ = ctrlc::set_handler(move || {
        let active = active_node.lock().ok().and_then(|guard| guard.clone());
        if let Some(active) = active {
            let _ = kill_pid(active.pid);
            release_cli_node_slot(&active.lease_path);
        }
        std::process::exit(0);
    });
}

async fn spawn_interactive_node(cli: &Cli, active_node: ActiveNodeRef) -> Result<NodeProcessGuard> {
    let port = cli.rpc.unwrap_or(allocate_local_rpc_port()?);
    let owner_pid = std::process::id();
    let slot = allocate_cli_node_slot()?;
    let state_dir = slot.state_dir.clone();
    std::fs::create_dir_all(&state_dir)?;
    let log_path = state_dir.join("node.log");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_file2 = log_file.try_clone()?;

    let exe =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("cannot find own executable: {e}"))?;
    let port_str = port.to_string();
    let state_dir_arg = state_dir.display().to_string();

    let mut cmd = std::process::Command::new(&exe);
    cmd.args([
        "node",
        "--rpc-port",
        &port_str,
        "--state-dir",
        &state_dir_arg,
        "--reset-transient-peer-state",
    ]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(log_file);
    cmd.stderr(log_file2);

    let child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to launch per-CLI node process: {e}"));
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            release_cli_node_slot(&slot.lease_path);
            return Err(error);
        }
    };
    let pid = child.id();
    if let Err(error) = slot.record_node_pid(owner_pid, pid) {
        let _ = kill_pid(pid);
        release_cli_node_slot(&slot.lease_path);
        return Err(error);
    }
    set_interactive_node_env(pid, port, &state_dir);
    if let Ok(mut active) = active_node.lock() {
        *active = Some(ActiveNodeRecord {
            pid,
            lease_path: slot.lease_path.clone(),
        });
    }

    let mut guard = NodeProcessGuard {
        child,
        pid,
        port,
        state_dir,
        lease_path: slot.lease_path.clone(),
        active_node,
    };

    if !wait_for_node_rpc(cli, std::time::Duration::from_secs(30)).await {
        let _ = guard.stop();
        anyhow::bail!(
            "per-CLI node RPC did not become ready; see {}",
            log_path.display()
        );
    }

    println!("Vess node started for this CLI instance.");
    println!("  PID:     {pid}");
    println!("  RPC:     127.0.0.1:{port}");
    println!("  State:   {}", slot.state_dir.display());
    println!("  Log:     {}", log_path.display());
    Ok(guard)
}

async fn restart_interactive_node_if_needed(
    cli: &Cli,
    active_node: ActiveNodeRef,
    node_guard: &mut Option<NodeProcessGuard>,
) -> Result<()> {
    let stopped = node_guard
        .as_mut()
        .map(|guard| !guard.is_running())
        .unwrap_or(false);
    if !stopped {
        return Ok(());
    }

    if let Some(mut guard) = node_guard.take() {
        let _ = guard.stop();
    }
    println!("This CLI instance's node stopped unexpectedly; restarting it now...");
    let guard = spawn_interactive_node(cli, active_node).await?;
    *node_guard = Some(guard);
    if let Err(e) = ensure_wallet_layer(cli).await {
        println!("Warning: wallet layer not loaded: {e}");
    }
    Ok(())
}

fn interactive_command_uses_node(cmd: &str) -> bool {
    matches!(
        cmd,
        "status"
            | "balance"
            | "bal"
            | "receive"
            | "recv"
            | "recieve"
            | "faucet"
            | "test-mint"
            | "test-mode"
            | "testmode"
            | "send"
            | "notifications"
            | "notifs"
            | "events"
            | "health"
            | "inventory"
    )
}

async fn wait_for_node_rpc(cli: &Cli, timeout: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if rpc_call(rpc_port(cli), &json!({"method": "node_info"}))
            .await
            .map(|resp| resp["ok"] == true)
            .unwrap_or(false)
        {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn wallet_loaded_in_node(cli: &Cli) -> bool {
    rpc_call(rpc_port(cli), &json!({"method": "node_info"}))
        .await
        .map(|resp| resp["ok"] == true && resp["bitcoin_receive_address"].as_str().is_some())
        .unwrap_or(false)
}

enum WalletOpenChoice {
    Existing(PathBuf),
    CreateOrRecover,
    Skip,
}

fn prompt_wallet_tag_destination() -> Result<(PathBuf, String)> {
    loop {
        let name = prompt("Choose a unique VessTag. This is your 3-20 alphanumeric character identifier: ")?;
        let name = match normalize_wallet_tag_name(&name) {
            Ok(name) => name,
            Err(e) => {
                println!("Invalid VessTag: {e}");
                continue;
            }
        };
        let path = match named_wallet_path(&name) {
            Ok(path) => path,
            Err(e) => {
                println!("Invalid wallet filename: {e}");
                continue;
            }
        };
        if path.exists() {
            println!(
                "A wallet for {} already exists. Choose another tag.",
                wallet_display_name(&name)
            );
            continue;
        }
        return Ok((path, name));
    }
}

fn resolve_wizard_wallet_destination(
    wallet_path: Option<&PathBuf>,
    wallet_name: Option<&str>,
) -> Result<(PathBuf, Option<String>)> {
    match wallet_path {
        Some(wallet_path) => Ok((
            wallet_path.clone(),
            wallet_name.map(normalize_wallet_tag_name).transpose()?,
        )),
        None => {
            if let Some(wallet_name) = wallet_name {
                let wallet_name = normalize_wallet_tag_name(wallet_name)?;
                Ok((named_wallet_path(&wallet_name)?, Some(wallet_name)))
            } else {
                let (wallet_path, wallet_name) = prompt_wallet_tag_destination()?;
                Ok((wallet_path, Some(wallet_name)))
            }
        }
    }
}

fn print_local_wallets(wallets: &[WalletDescriptor]) {
    if wallets.is_empty() {
        println!("No local wallets found.");
        return;
    }
    println!("Local wallets:");
    for (idx, wallet) in wallets.iter().enumerate() {
        let kind = if wallet.legacy_default {
            "legacy default"
        } else {
            "named"
        };
        println!(
            "  [{}] {} ({}) — {}",
            idx + 1,
            wallet_display_name(&wallet.name),
            kind,
            wallet.path.display()
        );
    }
}

fn prompt_wallet_open_choice(wallets: &[WalletDescriptor]) -> Result<WalletOpenChoice> {
    if wallets.len() == 1 {
        let wallet = &wallets[0];
        println!("Found wallet: {}", wallet_display_name(&wallet.name));
        let answer = prompt("Unlock this wallet now? [y/n/new]: ")?;
        return match answer.trim().to_ascii_lowercase().as_str() {
            "n" | "no" | "skip" => Ok(WalletOpenChoice::Skip),
            "new" | "create" | "recover" => Ok(WalletOpenChoice::CreateOrRecover),
            _ => Ok(WalletOpenChoice::Existing(wallet.path.clone())),
        };
    }

    print_local_wallets(wallets);
    println!("  [N] Create or recover another VessTag wallet");
    println!("  [S] Skip wallet unlock");
    loop {
        let answer = prompt("Choose wallet to open: ")?;
        let answer = answer.trim();
        if matches!(answer.to_ascii_lowercase().as_str(), "s" | "skip" | "n/a") {
            return Ok(WalletOpenChoice::Skip);
        }
        if matches!(
            answer.to_ascii_lowercase().as_str(),
            "n" | "new" | "create" | "recover"
        ) {
            return Ok(WalletOpenChoice::CreateOrRecover);
        }
        match answer.parse::<usize>() {
            Ok(index) if (1..=wallets.len()).contains(&index) => {
                return Ok(WalletOpenChoice::Existing(wallets[index - 1].path.clone()))
            }
            _ => println!("Enter a wallet number, N for new/recover, or S to skip."),
        }
    }
}

async fn cmd_unlock_wallet_at_path(
    cli: &Cli,
    wallet_file: &Path,
    password: Option<String>,
) -> Result<()> {
    if !wallet_file.exists() {
        anyhow::bail!(
            "wallet not found at {}; create or recover one first",
            wallet_file.display()
        );
    }

    if !wait_for_node_rpc(cli, std::time::Duration::from_secs(20)).await {
        anyhow::bail!(
            "local node RPC is not ready yet; open Vess interactively or run `vess node --rpc-port {}`",
            rpc_port(cli)
        );
    }

    match password {
        Some(pwd) => {
            // External password — single attempt.
            let resp = rpc_call(rpc_port(cli), &json!({
                "method": "wallet_unlock",
                "password": pwd,
                "wallet_path": wallet_file.display().to_string(),
            })).await?;
            if resp["ok"] != true {
                anyhow::bail!("{}", resp["error"].as_str().unwrap_or("wallet unlock failed"));
            }
        }
        None => {
            // Interactive prompt — retry up to 3 times on wrong password.
            let mut ok = false;
            for attempt in 1..=3 {
                let pwd = prompt_password("Enter wallet password: ")?;
                let resp = rpc_call(rpc_port(cli), &json!({
                    "method": "wallet_unlock",
                    "password": pwd,
                    "wallet_path": wallet_file.display().to_string(),
                })).await?;
                if resp["ok"] == true {
                    ok = true;
                    break;
                }
                let err = resp["error"].as_str().unwrap_or("wallet unlock failed");
                if attempt < 3 {
                    eprintln!("  Incorrect password ({attempt}/3).");
                } else {
                    anyhow::bail!("{}", err);
                }
            }
            if !ok {
                anyhow::bail!("wallet unlock failed after 3 attempts");
            }
        }
    }
    set_active_wallet_path(wallet_file)?;

    if cli.json {
        println!("{}", json!({ "ok": true }));
    } else {
        println!("Wallet unlocked on the running node.");
    }

    Ok(())
}

async fn ensure_wallet_layer(cli: &Cli) -> Result<()> {
    if !wait_for_node_rpc(cli, std::time::Duration::from_secs(20)).await {
        println!("Node is starting; network discovery running in the background.");
        return Ok(());
    }
    if wallet_loaded_in_node(cli).await {
        return Ok(());
    }

    if cli.wallet.is_none() && cli.wallet_name.is_none() {
        let wallets = list_wallets()?;
        if wallets.is_empty() {
            println!("No local wallets found. The node is running without a wallet.");
            let answer = prompt("Create or recover a wallet now? [y/n]: ")?;
            if matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no") {
                return Ok(());
            }
            let (wallet_file, password) = first_run_wizard(None, None).await?;
            cmd_unlock_wallet_at_path(cli, &wallet_file, Some(password)).await?;
            return Ok(());
        }

        match prompt_wallet_open_choice(&wallets)? {
            WalletOpenChoice::Skip => return Ok(()),
            WalletOpenChoice::CreateOrRecover => {
                let (wallet_file, password) = first_run_wizard(None, None).await?;
                cmd_unlock_wallet_at_path(cli, &wallet_file, Some(password)).await?;
                return Ok(());
            }
            WalletOpenChoice::Existing(wallet_file) => {
                cmd_unlock_wallet_at_path(cli, &wallet_file, None).await?;
                return Ok(());
            }
        }
    }

    let wallet_file = wallet_path(cli)?;
    if !wallet_file.exists() {
        println!(
            "Selected wallet not found at {}. The node is running without a wallet.",
            wallet_file.display()
        );
        let answer = prompt("Create or recover a wallet now? [y/n]: ")?;
        if matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no") {
            return Ok(());
        }
        let (created_wallet_file, password) =
            first_run_wizard(Some(&wallet_file), cli.wallet_name.as_deref()).await?;
        cmd_unlock_wallet_at_path(cli, &created_wallet_file, Some(password)).await?;
        return Ok(());
    }

    let answer = prompt("Unlock wallet on the running node now? [y/n]: ")?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no") {
        return Ok(());
    }
    cmd_unlock_wallet_at_path(cli, &wallet_file, None).await
}

/// Interactive first-run wizard: creates or recovers a wallet, sets an
/// unlock password, and returns that password so the caller can unlock
/// the wallet into the already-running node.
async fn first_run_wizard(
    wallet_path: Option<&PathBuf>,
    wallet_name: Option<&str>,
) -> Result<(PathBuf, String)> {
    println!();
    println!("  ╔══════════════════════════════════════╗");
    println!("  ║           First-time Setup           ║");
    println!("  ╚══════════════════════════════════════╝");
    println!();
    println!("  [1] Create a new wallet");
    println!("  [2] Recover an existing wallet from recovery phrase");
    println!();

    let choice = prompt("Your choice [1/2]: ")?;

    let (wallet_path, raw_seed): (PathBuf, [u8; 64]) = match choice.trim() {
        "2" => wizard_recover(wallet_path, wallet_name).await?,
        _ => wizard_new(wallet_path, wallet_name).await?,
    };

    // Now set a quick-unlock password (raw_seed still in scope — no re-prompt).
    println!();
    println!("Set a quick-unlock password for the background service. Typing is hidden for security.");
    println!("(Your recovery phrase is the fallback if you ever forget it.)\n");
    let password = loop {
        let pwd = prompt_password("  New password:     ")?;
        if pwd.is_empty() {
            println!("  Password cannot be empty.");
            continue;
        }
        let pwd2 = prompt_password("  Confirm password: ")?;
        if pwd != pwd2 {
            println!("  Passwords don't match. Try again.\n");
            continue;
        }
        break pwd;
    };

    let mut wf = WalletFile::load(&wallet_path)?;
    let enc_key = encryption_key_from_seed(&raw_seed);
    wf.set_password_cache(&raw_seed, &password)?;
    wf.save(&wallet_path, &enc_key)?;
    println!("  Password set ✓\n");
    Ok((wallet_path, password))
}

/// Wizard sub-flow: create a brand new wallet. Returns the raw_seed so the
/// caller can set up a password without asking for the phrase again.
async fn wizard_new(
    wallet_path: Option<&PathBuf>,
    wallet_name: Option<&str>,
) -> Result<(PathBuf, [u8; 64])> {
    println!();
    println!("── New Wallet Setup ─────────────────────────────────────");

    let (wallet_path, wallet_name) = resolve_wizard_wallet_destination(wallet_path, wallet_name)?;

    let tag_str = if let Some(wallet_name) = wallet_name {
        println!(
            "Using {} as this wallet's VessTag.",
            wallet_display_name(&wallet_name)
        );
        wallet_name
    } else {
        loop {
            let t = prompt("Choose a +tag for your wallet (e.g. alice): ")?;
            match normalize_wallet_tag_name(&t) {
                Ok(tag) => break tag,
                Err(e) => {
                    println!("Invalid VessTag: {e}");
                    continue;
                }
            }
        }
    };

    // Check tag availability before doing the expensive PoW.
    println!("Checking if +{tag_str} is available…");
    let peers = discover_peers(true).await?;
    let node = MeshPulseNode::spawn().await?;
    node.wait_online().await;
    let display_tag = format!("+{tag_str}");
    let (is_taken, target) =
        lookup_tag_on_reachable_peer(&node, &peers, &tag_str, &display_tag).await?;
    if is_taken {
        node.shutdown().await;
        anyhow::bail!("+{tag_str} is already taken. Pick another tag and try again.");
    }
    println!("+{tag_str} is available!");

    // Derive keys.
    let phrase = RecoveryPhrase::generate();
    let raw_seed = derive_raw_seed(&phrase)?;
    let (secret, address) = generate_master_keys_from_seed(&raw_seed);
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = encrypt_secrets(&secret, &enc_key)?;
    let mut wallet = WalletFile::new(address, encrypted, BillFold::new(), spend_seed, &enc_key)?;
    wallet.name = Some(tag_str.clone());

    // Compute tag PoW and register.
    println!("\nComputing proof-of-work for tag registration (~10 s, 2 GiB RAM)…");
    let tag_hash = *blake3::hash(tag_str.as_bytes()).as_bytes();
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
    node.send_message(&target, &msg).await?;
    node.shutdown().await;
    println!("+{tag_str} registered!");

    // Display recovery phrase and require confirmation before saving.
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════════╗");
    println!("  ║      YOUR 12-WORD RECOVERY PHRASE — WRITE THIS DOWN NOW!      ║");
    println!("  ╚═══════════════════════════════════════════════════════════════╝");
    println!("  {}", phrase.display_phrase());
    println!();
    println!("  This is the ONLY way to recover your wallet if you lose your password.");
    println!("  Store it offline on paper, NOT on your device or as a screenshot.\n");

    loop {
        let words_in = prompt("  Re-enter your 12-word phrase to confirm you saved it: ")?;
        let phrase_ok = RecoveryPhrase::from_input(&words_in)
            .map(|entered| entered == phrase)
            .unwrap_or(false);
        if phrase_ok {
            println!("  Recovery phrase confirmed ✓\n");
            break;
        }
        println!("  That doesn't match. Please try again.\n");
    }

    if let Err(error) = maybe_store_local_phrase_backup(&phrase, &wallet_path) {
        eprintln!("Warning: could not create encrypted local backup: {error}");
    }

    wallet.save(&wallet_path, &enc_key)?;
    Ok((wallet_path, raw_seed))
}

/// Wizard sub-flow: recover wallet from a 12-word recovery phrase.
/// Returns the raw_seed so the caller can set up a password without
/// asking for the phrase a second time.
async fn wizard_recover(
    wallet_path: Option<&PathBuf>,
    wallet_name: Option<&str>,
) -> Result<(PathBuf, [u8; 64])> {
    println!();
    println!("── Wallet Recovery ─────────────────────────────────────");

    let (wallet_path, wallet_name) = resolve_wizard_wallet_destination(wallet_path, wallet_name)?;

    let words = prompt("Enter your 12-word recovery phrase: ")?;
    let phrase = RecoveryPhrase::from_input(&words)?;

    let (secret, address) = recover_master_keys(&phrase)?;
    let raw_seed = derive_raw_seed(&phrase)?;
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = encrypt_secrets(&secret, &enc_key)?;

    let mut billfold = if wallet_path.exists() {
        let mut wallet = WalletFile::load(&wallet_path)?;
        wallet.decrypt_private_metadata(&enc_key)?;
        wallet.billfold
    } else {
        BillFold::new()
    };

    println!("\nConnecting to the network to recover your bills…");
    let node = MeshPulseNode::spawn().await?;
    node.wait_online().await;

    let targets = discover_recovery_targets(&node, true).await?;
    println!("  Using {} peer(s) for manifest fetch", targets.len());

    let manifest_key = vess_foundry::seal::manifest_dht_key(&spend_seed);
    let manifest_req = PulseMessage::ManifestRecover(vess_protocol::ManifestRecover {
        dht_key: manifest_key,
    });

    let mut manifest_entries = Vec::new();
    let mut manifest_found = false;
    for peer in &targets {
        if let Ok(Some(PulseMessage::ManifestRecoverResponse(mrr))) =
            node.send_message_with_response(peer, &manifest_req).await
        {
            if mrr.found {
                if let Ok(entries) =
                    vess_foundry::seal::decrypt_manifest(&spend_seed, &mrr.encrypted_manifest)
                {
                    manifest_entries = entries;
                    manifest_found = true;
                    println!("  Manifest found: {} bill entries", manifest_entries.len());
                    break;
                }
            }
        }
    }

    let mut max_dht_index = 0u64;
    if manifest_found && !manifest_entries.is_empty() {
        let mint_ids: Vec<[u8; 32]> = manifest_entries.iter().map(|e| e.mint_id).collect();
        let fetch_req = PulseMessage::OwnershipFetch(vess_protocol::OwnershipFetch { mint_ids });
        let mut fetched = Vec::new();
        for peer in &targets {
            if let Ok(Some(PulseMessage::OwnershipFetchResponse(ofr))) =
                node.send_message_with_response(peer, &fetch_req).await
            {
                fetched = ofr.records;
                break;
            }
        }
        for (i, entry) in manifest_entries.iter().enumerate() {
            if i >= fetched.len() {
                break;
            }
            let rec = &fetched[i];
            if !rec.found {
                continue;
            }
            if let Some(denomination) =
                vess_foundry::Denomination::from_value(rec.denomination_value)
            {
                let bill = vess_foundry::VessBill {
                    denomination,
                    digest: rec.digest,
                    created_at: 0,
                    stealth_id: [0u8; 32],
                    dht_index: entry.dht_index,
                    mint_id: entry.mint_id,
                    chain_tip: rec.chain_tip,
                    chain_depth: 0,
                };
                billfold.deposit(bill);
                if entry.dht_index >= max_dht_index {
                    max_dht_index = entry.dht_index + 1;
                }
            }
        }
        println!(
            "  Recovered {} bill(s). Balance: {} Vess",
            billfold.count(),
            billfold.balance()
        );
    } else {
        println!("  No manifest found. Wallet created with empty balance.");
        println!("  (Bills in-flight will be delivered once the node is running.)");
    }

    node.shutdown().await;

    let mut wallet = WalletFile::new(address, encrypted, billfold, spend_seed, &enc_key)?;
    wallet.name = wallet_name;
    wallet.next_dht_index = max_dht_index;
    wallet.save(&wallet_path, &enc_key)?;
    println!("  Wallet saved ✓\n");
    Ok((wallet_path, raw_seed))
}

// ── `vess status` ────────────────────────────────────────────────────

async fn cmd_status(cli: &Cli) -> Result<()> {
    let port = rpc_port(cli);

    let running = match read_node_pid() {
        None => false,
        Some(pid) => {
            if is_pid_alive(pid) {
                if !cli.json {
                    println!("Status:  RUNNING  (PID {pid})");
                }
                true
            } else {
                if !cli.json {
                    println!("Status:  NOT RUNNING  (stale PID file removed)");
                }
                clear_node_pid();
                false
            }
        }
    };

    if !running {
        if cli.json {
            println!("{}", json!({ "ok": true, "running": false }));
            return Ok(());
        }
        println!("No Vess node is registered for this CLI session.");
        println!("Open Vess interactively, or run `vess node --rpc-port {port}` in another shell.");
        return Ok(());
    }

    let mut balance = None;
    let mut watch_only_balance = None;
    let mut bill_count = None;
    // Try RPC for live stats.
    if let Ok(resp) = rpc_call(port, &json!({"method": "balance"})).await {
        if resp["ok"] == true {
            balance = resp["balance"].as_u64();
            watch_only_balance = resp["watch_only_balance"].as_u64();
            bill_count = resp["bill_count"].as_u64();
        }
    }

    if let Ok(resp) = rpc_call(port, &json!({"method": "node_info"})).await {
        if resp["ok"] == true {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "ok": true,
                        "running": true,
                        "balance": balance,
                        "watch_only_balance": watch_only_balance,
                        "bill_count": bill_count,
                        "peer_count": resp["peer_count"],
                        "discovered_peer_count": resp["discovered_peer_count"],
                        "cached_peer_count": resp["cached_peer_count"],
                        "verified_peer_count": resp["verified_peer_count"],
                        "node_id": resp["node_id"],
                        "node_contact": resp["node_contact"],
                        "bitcoin_receive_address": resp["bitcoin_receive_address"],
                        "bitcoin_tracked_balance": resp["bitcoin_tracked_balance"],
                        "bitcoin_pending_burns": resp["bitcoin_pending_burns"],
                        "bitcoin_connected_peers": resp["bitcoin_connected_peers"],
                    })
                );
                return Ok(());
            }

            if let (Some(balance), Some(bill_count)) = (balance, bill_count) {
                if let Some(watch_only_balance) = watch_only_balance {
                    println!(
                        "Balance: {} spendable / {} watch-only Vess  ({} bills)",
                        balance,
                        watch_only_balance,
                        bill_count
                    );
                } else {
                    println!("Balance: {} Vess  ({} bills)", balance, bill_count);
                }
            }
            let discovered_peer_count = resp["discovered_peer_count"].as_u64().unwrap_or(0);
            let cached_peer_count = resp["cached_peer_count"].as_u64().unwrap_or(0);
            let verified_peer_count = resp["verified_peer_count"].as_u64().unwrap_or(0);
            if cached_peer_count > 0 {
                println!(
                    "Peers:   {} discovered / {} verified  ({} cached from prior state)",
                    discovered_peer_count,
                    verified_peer_count,
                    cached_peer_count
                );
            } else {
                println!(
                    "Peers:   {} discovered / {} verified",
                    discovered_peer_count,
                    verified_peer_count
                );
            }
            println!("Node ID: {}", resp["node_id"].as_str().unwrap_or("?"));
            println!(
                "Mesh contact: {}",
                resp["node_contact"].as_str().unwrap_or("?")
            );
            if let Some(address) = resp["bitcoin_receive_address"].as_str() {
                println!("BTC receive: {}", address);
            }
            if let Some(tracked_balance) = resp["bitcoin_tracked_balance"].as_u64() {
                println!("BTC tracked: {} sats", tracked_balance);
            }
            println!("BTC pending burns: {}", resp["bitcoin_pending_burns"]);
            println!("BTC peers: {}", resp["bitcoin_connected_peers"]);
        }
    }

    if cli.json {
        println!("{}", json!({ "ok": true, "running": true }));
        return Ok(());
    }

    Ok(())
}

// ── Interactive (double-click / no-subcommand) mode ──────────────────────────

async fn cmd_interactive(cli: &Cli) -> Result<()> {
    use std::io::{BufRead, Write};

    println!("╔══════════════════════════════════════╗");
    println!("║          Vess: Quantum Cash          ║");
    println!("╚══════════════════════════════════════╝");
    println!();

    // Every interactive CLI owns its own node process. The node starts before
    // wallet entry and is stopped automatically when this CLI exits.
    let active_node = std::sync::Arc::new(std::sync::Mutex::new(None));
    install_interactive_node_signal_handler(active_node.clone());
    let mut node_guard = match spawn_interactive_node(cli, active_node.clone()).await {
        Ok(guard) => Some(guard),
        Err(e) => {
            println!("Warning: could not start this CLI's node: {e}");
            None
        }
    };
    if node_guard.is_some() {
        if let Err(e) = ensure_wallet_layer(cli).await {
            println!("Warning: wallet layer not loaded: {e}");
        }
    }
    println!();

    // Show balance if node is now running.
    let port = rpc_port(cli);
    if let Some(pid) = read_node_pid() {
        if is_pid_alive(pid) {
            if let Ok(resp) = rpc_call(port, &json!({"method": "balance"})).await {
                if resp["ok"] == true {
                    println!(
                        "Balance: {} Vess  ({} bills)",
                        resp["balance"], resp["bill_count"]
                    );
                }
            }
        }
    }

    println!();
    println!("Type 'help' for commands, 'exit' to quit.");
    println!();

    // Read stdin on a blocking thread so the async loop is not blocked waiting
    // for keyboard input.
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Option<String>>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if stdin_tx.send(Some(l)).is_err() {
                        break;
                    }
                }
                Err(_) => {
                    let _ = stdin_tx.send(None);
                    break;
                }
            }
        }
    });

    // Background task: poll for wallet notifications every 2 s and display
    // them so the user sees payment receipts etc. in real time.
    let (notif_tx, mut notif_rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let notif_port = port;
    tokio::spawn(async move {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Ok(resp) = rpc_call(notif_port, &json!({"method": "notifications", "max": 16})).await {
                if let Some(notes) = resp["notifications"].as_array() {
                    for note in notes {
                        let kind = note["kind"].as_str().unwrap_or("");
                        let pid = note["payment_id"].as_str().unwrap_or("");
                        let key = format!("{}:{}", kind, pid);
                        if !pid.is_empty() && seen.insert(key) {
                            let _ = notif_tx.send(note.clone());
                        }
                    }
                }
            }
        }
    });

    loop {
        // Drain any pending notifications before showing the prompt.
        while let Ok(note) = notif_rx.try_recv() {
            let kind = note["kind"].as_str().unwrap_or("notification");
            let msg = note["message"].as_str().unwrap_or("");
            println!("\n  \x1b[1m[{kind}]\x1b[0m {msg}");
        }

        print!("vess> ");
        std::io::stdout().flush().ok();

        tokio::select! {
            biased;

            line = stdin_rx.recv() => {
                let line_str: String;
                match line.flatten() {
                    Some(l) => line_str = l,
                    None => {
                        println!();
                        break;
                    }
                }

        let line = line_str.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.splitn(4, ' ');
        let cmd = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();

        if interactive_command_uses_node(cmd) {
            if let Err(e) =
                restart_interactive_node_if_needed(cli, active_node.clone(), &mut node_guard).await
            {
                println!("Error: {e}");
                println!();
                continue;
            }
        }

        let result: Result<()> = match cmd {
            "exit" | "quit" | "q" => {
                println!("Goodbye.");
                break;
            }
            "help" | "h" | "?" => {
                print_interactive_help();
                Ok(())
            }
            "status" => cmd_status(cli).await,
            "wallets" => {
                let wallets = list_wallets()?;
                print_local_wallets(&wallets);
                Ok(())
            }
            "balance" | "bal" => cmd_balance(cli).await,
            "receive" | "recv" | "recieve" => cmd_receive(cli).await,
            "faucet" | "test-mint" => {
                if args.is_empty() {
                    println!("Usage: faucet <amount>");
                    Ok(())
                } else {
                    match args[0].parse::<u64>() {
                        Ok(amount) => cmd_faucet(cli, amount).await,
                        Err(_) => {
                            println!("Invalid amount — must be a whole number.");
                            Ok(())
                        }
                    }
                }
            }
            "send" => {
                if args.len() < 2 {
                    println!("Usage: send <amount> <+tag>");
                    Ok(())
                } else {
                    match args[0].parse::<u64>() {
                        Ok(amount) => cmd_send(cli, amount, args[1], None, None).await,
                        Err(_) => {
                            println!("Invalid amount — must be a whole number.");
                            Ok(())
                        }
                    }
                }
            }
            "test-mode" | "testmode" => cmd_test_mode(cli).await,
            "profile" | "set-profile" => cmd_profile(cli, args.first().copied()).await,
            "events" => cmd_events(cli, 32, false).await,
            "health" => cmd_health(cli, false).await,
            "explain" | "help-topic" => {
                let topic = args.first().copied();
                cmd_explain(topic)
            }
            "inventory" => cmd_inventory(cli, false).await,
            "notifications" | "notifs" => {
                let follow = args
                    .first()
                    .map(|arg| matches!(*arg, "follow" | "-f" | "--follow"))
                    .unwrap_or(false);
                cmd_notifications(cli, follow, 1_000, 64).await
            }
            _ => {
                if matches!(cmd, "start" | "stop") {
                    println!(
                        "`{cmd}` is not a CLI command. This CLI manages its node automatically."
                    );
                    Ok(())
                } else {
                println!("Unknown command '{cmd}'. Type 'help' for a list.");
                    Ok(())
                }
            }
        };

        if let Err(e) = result {
            println!("Error: {e}");
        }
        println!();
            }

            // Also wake on incoming notifications so they're shown promptly.
            note = notif_rx.recv() => {
                if let Some(n) = note {
                    let kind = n["kind"].as_str().unwrap_or("notification");
                    let msg = n["message"].as_str().unwrap_or("");
                    println!("\n  \x1b[1m[{kind}]\x1b[0m {msg}");
                }
            }
        }
    }

    drop(node_guard);
    Ok(())
}

async fn cmd_test_mode(cli: &Cli) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({"method": "set_test_mode"})).await?;
    if resp["ok"] == true {
        if cli.json {
            println!("{resp}");
        } else {
            println!("Test mode enabled.");
            println!("  test_faucet_enabled: {}", resp["test_faucet_enabled"]);
            println!("  unsafe_mode:         {}", resp["unsafe_mode"]);
            println!("You can now use `vess faucet <amount>` to mint test bills.");
        }
    } else {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(())
}

async fn cmd_profile(cli: &Cli, profile: Option<&str>) -> Result<()> {
    let port = rpc_port(cli);
    if let Some(label) = profile {
        let resp = rpc_call(port, &json!({"method": "set_profile", "profile": label})).await?;
        if resp["ok"] == true {
            if cli.json {
                println!("{resp}");
            } else {
                println!("Profile set: {}", resp["profile"]);
                println!("  {}", resp["description"]);
                println!("  unsafe_mode:         {}", resp["unsafe_mode"]);
                println!("  test_faucet_enabled: {}", resp["test_faucet_enabled"]);
                if let Some(warnings) = resp["audit_warnings"].as_array() {
                    if !warnings.is_empty() {
                        println!("Audit warnings:");
                        for w in warnings {
                            println!("  ⚠ {}", w.as_str().unwrap_or("?"));
                        }
                    }
                }
            }
        } else {
            anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
        }
    } else {
        // Query current profile
        let resp = rpc_call(port, &json!({"method": "node_info"})).await?;
        if resp["ok"] == true {
            if cli.json {
                println!("{resp}");
            } else {
                let p = resp["profile"].as_str().unwrap_or("unknown");
                let desc = resp["profile_description"].as_str().unwrap_or("");
                println!("Current profile: {p} — {desc}");
                println!("  unsafe_mode:         {}", resp["unsafe_mode"]);
                println!("  test_faucet_enabled: {}", resp["test_faucet_enabled"]);
            }
        } else {
            anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
        }
    }
    Ok(())
}

async fn cmd_events(cli: &Cli, max: usize, as_json: bool) -> Result<()> {
    let port = rpc_port(cli);
    let running = match read_node_pid() {
        None => false,
        Some(pid) => is_pid_alive(pid),
    };
    if !running {
        if as_json {
            println!("{}", json!({ "ok": false, "error": "node not running" }));
        } else {
            println!("Node is not running.");
        }
        return Ok(());
    }
    let resp = rpc_call(port, &json!({"method": "events", "max": max})).await?;
    if resp["ok"] != true {
        if as_json {
            println!("{}", resp);
        } else {
            println!("RPC error: {}", resp["error"]);
        }
        return Ok(());
    }
    let events = resp["events"].as_array().cloned().unwrap_or_default();
    if as_json {
        println!("{}", json!({ "ok": true, "count": events.len(), "events": events }));
        return Ok(());
    }
    if events.is_empty() {
        println!("No events.");
        return Ok(());
    }
    println!("\n── Node Events ──────────────────────────────────────\n");
    for event in &events {
        let event_type = event["event"].as_str().unwrap_or("unknown");
        let created_at = event["created_at"].as_u64().unwrap_or(0);
        println!("  [{event_type}]  at t={created_at}");
        for (key, value) in event.as_object().unwrap() {
            if key != "event" && key != "created_at" {
                println!("    {key}: {value}");
            }
        }
        println!();
    }
    Ok(())
}

async fn cmd_health(cli: &Cli, as_json: bool) -> Result<()> {
    let port = rpc_port(cli);
    let running = match read_node_pid() {
        None => false,
        Some(pid) => is_pid_alive(pid),
    };
    if !running {
        if as_json {
            println!("{}", json!({ "ok": false, "error": "node not running" }));
        } else {
            println!("Node is not running.");
        }
        return Ok(());
    }
    let resp = rpc_call(port, &json!({"method": "node_health"})).await?;
    if resp["ok"] != true {
        if as_json {
            println!("{}", resp);
        } else {
            println!("RPC error: {}", resp["error"]);
        }
        return Ok(());
    }
    if as_json {
        println!("{}", resp);
        return Ok(());
    }
    println!("\n── Node Health ──────────────────────────────────────\n");
    println!("  Node ID:           {}", resp["node_id"]);
    println!("  Peers:             {} total, {} verified, {} banished, {} discovered",
        resp["peer_count"], resp["verified_peer_count"], resp["banished_peer_count"], resp["discovered_peer_count"]);
    println!("  Network size:      {}", resp["estimated_network_size"]);
    println!("  Reputation:        {} high, {} medium, {} low",
        resp["reputation_high"], resp["reputation_medium"], resp["reputation_low"]);
    if let Some(b) = resp["wallet_balance"].as_u64() {
        println!("  Wallet balance:    {} Vess", b);
    }
    println!("  Limbo payments:    {}", resp["limbo_payment_count"]);
    println!("  Tags:              {}", resp["tag_count"]);
    Ok(())
}

// ── Explain topic constants ────────────────────────────────────────

const EXPLAIN_LIMBO: &str = "\
Limbo is a temporary holding area for payments sent to offline recipients.
When you send Vess to someone who isn't connected to the network, the payment
is held by infrastructure nodes (artery nodes) for up to 1 hour.
When the recipient comes online, they collect their pending payments
(trial-decrypting each payload with their keys) and finalize ownership.
You do not need to do anything — the recipient's wallet handles this
automatically. If a payment expires in limbo, the sender still has the
bills and can re-send.";

const EXPLAIN_OWNERSHIP: &str = "\
Ownership is tracked through the Vess Ownership Registry — a distributed
Merkle tree shared across all artery nodes. When you receive a payment,
your wallet broadcasts an OwnershipClaim that updates the registry.
'Ownership finalization' means the claim has been accepted by the network
and the bill is now provably yours. This happens automatically when the
recipient's wallet comes online and processes the limbo payment.";

const EXPLAIN_PROGRAM_BILLS: &str = "\
Program-owned bills are bills controlled by a VessLogic program rather than
a human. The program defines conditions (like 'release to address X after
timestamp Y') and the bill can only be spent by producing a valid witness
that satisfies those conditions. Think of them as smart escrows: you send
bills to a program, and the program releases them when the conditions are met.
Common patterns: timelocked vaults, capped treasuries, recurring payments.";

const EXPLAIN_TAGS: &str = "\
VessTags (+names) are human-readable aliases for stealth addresses.
They are registered on the DHT with an Argon2id proof-of-work to prevent
squatting. When you send to +alice, your wallet looks up alice's stealth
address from the DHT and encrypts the payment to that address.
Tags are globally unique — the first person to register a tag with valid
PoW owns it permanently. You can register a tag with `vess register-tag`.";

const EXPLAIN_BURNS: &str = "\
BTC burns are the only way to create Vess. You send bitcoin to a burn address
(which no one can spend from), and the network mints an equivalent amount of
Vess to your wallet at a 1:1 ratio (1 sat = 1 Vess). The burn is verified
by a Bitcoin light client embedded in the artery node. Once confirmed,
the burn proof is broadcast as an OwnershipGenesis and your wallet receives
the bills. Burns are irreversible — always double-check the address.";

fn cmd_explain(topic: Option<&str>) -> Result<()> {
    let text = match topic {
        Some("limbo") => crate::EXPLAIN_LIMBO,
        Some("ownership") => crate::EXPLAIN_OWNERSHIP,
        Some("program-bills") => crate::EXPLAIN_PROGRAM_BILLS,
        Some("tags") => crate::EXPLAIN_TAGS,
        Some("burns") => crate::EXPLAIN_BURNS,
        Some(_) | None => {
            println!("{}", crate::EXPLAIN_LIMBO);
            println!();
            println!("{}", crate::EXPLAIN_OWNERSHIP);
            println!();
            println!("{}", crate::EXPLAIN_PROGRAM_BILLS);
            println!();
            println!("{}", crate::EXPLAIN_TAGS);
            println!();
            println!("{}", crate::EXPLAIN_BURNS);
            return Ok(());
        }
    };
    println!("{text}");
    Ok(())
}

async fn cmd_inventory(cli: &Cli, as_json: bool) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({"method": "balance"})).await?;
    if resp["ok"] != true {
        if as_json {
            println!("{}", json!({ "ok": false, "error": resp["error"] }));
        } else {
            println!("RPC error: {}", resp["error"]);
        }
        return Ok(());
    }
    if as_json {
        println!("{}", resp);
        return Ok(());
    }
    let balance = resp["balance"].as_u64().unwrap_or(0);
    let bill_count = resp["bill_count"].as_u64().unwrap_or(0);
    println!("\n── Bill Inventory ───────────────────────────────────\n");
    if bill_count == 0 {
        println!("  No bills.");
    } else {
        println!("  Total: {balance} Vess across {bill_count} bills");
        if let Some(breakdown) = resp["denominations"].as_array() {
            for entry in breakdown {
                let denom = entry["denomination"].as_u64().unwrap_or(0);
                let count = entry["count"].as_u64().unwrap_or(0);
                println!("  {count:>4} × V{denom:<12} = {} Vess", denom * count);
            }
        }
    }
    println!();
    Ok(())
}

fn print_interactive_help() {
    println!("Commands:");
    println!("  status                 Show node status, Vess balance & BTC receive state");
    println!("  wallets                List local VessTag wallets");
    println!("  balance                Show wallet balance");
    println!("  receive                Show BTC receive address + QR code");
    println!("  test-mode              Enable test mode + faucet on this node");
    println!("  profile [dev|test|staging|prod]  Set or view deployment profile");
    println!("  faucet <amount>        Add local-test bills (test-mode must be on)");
    println!("  send <amount> <+tag>   Send Vess to a recipient");
    println!("  events                 Show recent node events");
    println!("  health                 Show detailed node health");
    println!("  explain [topic]        Explain core Vess concepts");
    println!("  inventory              Show wallet bill inventory");
    println!("  notifications [follow] Show recent notifications or follow them live");
    println!("  help                   Show this help");
    println!("  exit                   Close Vess");
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
