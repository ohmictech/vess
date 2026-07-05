//! Vess CLI — stateless P2P digital cash.
//!
//! Commands:
//!   init        Create a new wallet with seed phrase
//!   recover     Recover wallet from seed phrase (DHT manifest)
//!   balance     Show wallet balance
//!   send        Send Vess to a tag
//!   receive     Show your tag for receiving payments
//!   node        Start artery node (DHT + mining + mesh)
//!   mint        Start/stop/status minting
//!   dev-faucet  Submit dev faucet (dev only)
//!   status      Show node status
//!   tag         VessTag operations (register/lookup)
//!   manifest    Push wallet manifest to DHT

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use vess_foundry::mint;
use vess_foundry::spend_auth;
use vess_sovereign::billfold::BillFold;
use vess_sovereign::persistence::WalletFile;
use vess_sovereign::recovery::{self, RecoveryPhrase};

// ── CLI ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "vess", version, about = "Vess — stateless P2P digital cash")]
struct Cli {
    /// RPC port of local node (default 9400).
    #[arg(long, default_value = "9400")]
    rpc_port: u16,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet with a 12-word recovery phrase.
    Init {
        /// Wallet name (stored in ~/.vess/wallets/).
        #[arg(long)]
        name: Option<String>,
    },

    /// Recover a wallet from a 12-word seed phrase.
    Recover {
        /// Wallet name.
        #[arg(long)]
        name: Option<String>,
    },

    /// Show wallet balance.
    Balance,

    /// Show your tag for receiving payments.
    #[command(alias = "recv")]
    Receive,

    /// Send Vess to a tag (onion-routed by default for privacy).
    Send {
        /// Amount in Vess.
        amount: u64,
        /// Recipient tag (e.g. +alice).
        recipient: String,
        /// Skip onion routing, deliver directly (faster, less private).
        #[arg(long)]
        direct: bool,
    },

    /// Register or look up a VessTag.
    #[command(subcommand)]
    Tag(TagCmd),

    /// Submit the dev faucet for the current epoch.
    DevFaucet,

    /// Start/stop/status minting.
    #[command(subcommand)]
    Mint(MintCmd),

    /// Push wallet manifest to DHT for recovery.
    Manifest,

    /// Start the artery node.
    Node {
        /// Bind address (default 0.0.0.0:18348).
        #[arg(long)]
        bind: Option<String>,

        /// Bootstrap peer addresses.
        #[arg(long, value_delimiter = ',')]
        bootstrap: Vec<String>,

        /// State directory.
        #[arg(long)]
        state_dir: Option<PathBuf>,

        /// Wallet name to load.
        #[arg(long)]
        wallet: Option<String>,
    },

    /// Claim buffered payments from mailbox (auto-derives key + sweeps all epochs).
    Claim,

    /// Show wallet notifications.
    Notifications,

    /// Show node status.
    Status,
}

#[derive(Subcommand)]
enum TagCmd {
    /// Register a new VessTag.
    Register { tag: String },
    /// Look up a VessTag.
    Lookup { tag: String },
}

#[derive(Subcommand)]
enum MintCmd {
    /// Start continuous minting.
    Start {
        /// Target amount per bill (default 1).
        #[arg(default_value = "1")]
        amount: u64,
    },
    /// Stop minting.
    Stop,
    /// Show minting status.
    Status,
}

// ── Entry point ─────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    let port = cli.rpc_port;

    match &cli.command {
        Command::Init { name } => cmd_init(name).await,
        Command::Recover { name } => cmd_recover(name).await,
        Command::Balance => {
            rpc(port, "balance", json!({}))
                .await
                .map(|r| {
                    let total = r["total"].as_u64().unwrap_or(0);
                    let count = r["bill_count"].as_u64().unwrap_or(0);
                    println!("{} Vess ({} bills)", total, count);
                    if let Some(bills) = r["bills"].as_array() {
                        for b in bills {
                            let id = b["mint_id"].as_str().unwrap_or("?");
                            let amt = b["amount"].as_u64().unwrap_or(0);
                            let ep = b["epoch"].as_u64().unwrap_or(0);
                            println!("  {}  {} Vess  epoch {}", id, amt, ep);
                        }
                    }
                })
        }
        Command::Receive => cmd_receive(port).await,
        Command::Send { amount, recipient, direct } => {
            let method = if *direct { "send_direct" } else { "send" };
            rpc(port, method, json!({"amount": amount, "recipient": recipient}))
                .await
                .map(|r| {
                    let onion = r["onion"].as_bool().unwrap_or(true);
                    let label = if onion { "sent (onion)" } else { "sent (direct)" };
                    println!("{}: {}", label, r["payment_id"].as_str().unwrap_or("?"));
                })
        }
        Command::Tag(tag) => match tag {
            TagCmd::Register { tag } => {
                rpc(port, "tag_register", json!({"tag": tag}))
                    .await
                    .map(|r| println!("registered: {}", r["tag"].as_str().unwrap_or("?")))
            }
            TagCmd::Lookup { tag } => {
                rpc(port, "tag_lookup", json!({"tag": tag}))
                    .await
                    .map(|r| println!("{}", r["stealth_id"].as_str().unwrap_or("not found")))
            }
        },
        Command::DevFaucet => cmd_dev_faucet(port).await,
        Command::Mint(mint) => match mint {
            MintCmd::Start { amount } => {
                rpc(port, "mint_start", json!({"amount": amount}))
                    .await
                    .map(|r| println!("{}", r["message"].as_str().unwrap_or("?")))
            }
            MintCmd::Stop => {
                rpc(port, "mint_stop", json!({}))
                    .await
                    .map(|r| println!("{}", r["message"].as_str().unwrap_or("?")))
            }
            MintCmd::Status => {
                rpc(port, "mint_status", json!({})).await.map(|r| {
                    if r["active"].as_bool().unwrap_or(false) {
                        println!(
                            "minting: {} Vess target, {}s elapsed",
                            r["amount"].as_u64().unwrap_or(0),
                            r["seconds"].as_u64().unwrap_or(0)
                        );
                    } else {
                        println!("not minting");
                    }
                })
            }
        },
        Command::Manifest => {
            rpc(port, "manifest_push", json!({}))
                .await
                .map(|_| println!("manifest pushed"))
        }
        Command::Node {
            bind,
            bootstrap,
            state_dir,
            wallet,
        } => cmd_node(port, bind, bootstrap, state_dir, wallet).await,
        Command::Claim => {
            rpc(port, "auto_claim", json!({}))
                .await
                .map(|r| {
                    println!("Claimed {} payments ({} epochs scanned)",
                        r["claimed"].as_u64().unwrap_or(0),
                        r["epochs_scanned"].as_u64().unwrap_or(0));
                })
        }
        Command::Notifications => {
            rpc(port, "notifications", json!({})).await.map(|r| {
                if let Some(notes) = r["notifications"].as_array() {
                    if notes.is_empty() {
                        println!("No notifications.");
                    } else {
                        for n in notes {
                            let ts = n["timestamp"].as_u64().unwrap_or(0);
                            let msg = n["message"].as_str().unwrap_or("?");
                            println!("[{}] {}", ts, msg);
                        }
                    }
                }
            })
        }
        Command::Status => {
            rpc(port, "status", json!({})).await.map(|r| {
                println!("node:   {}", r["node_id"].as_str().unwrap_or("?"));
                println!("peers:  {}", r["peer_count"].as_u64().unwrap_or(0));
                println!("epoch:  {}", r["epoch"].as_u64().unwrap_or(0));
            })
        }
    }
}

// ── RPC helper (TCP JSON-line) ──────────────────────────────────────

async fn rpc(port: u16, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let addr = format!("127.0.0.1:{}", port);
    let stream = tokio::net::TcpStream::connect(&addr)
        .await
        .context(format!("cannot connect to node at {addr} — is it running?"))?;
    let (reader, mut writer) = stream.into_split();

    let req = serde_json::json!({"method": method, "params": params});
    let req_line = format!("{}\n", serde_json::to_string(&req)?);
    writer.write_all(req_line.as_bytes()).await?;
    writer.shutdown().await?;

    let mut lines = BufReader::new(reader).lines();
    let resp_line = lines.next_line().await?.context("no response from node")?;
    let body: serde_json::Value = serde_json::from_str(&resp_line)?;
    if body["ok"].as_bool().unwrap_or(false) {
        Ok(body["data"].clone())
    } else {
        anyhow::bail!(
            "{}",
            body["data"]["error"]
                .as_str()
                .unwrap_or("unknown error")
        );
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn wallets_dir() -> PathBuf {
    dirs_next::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("vess")
        .join("wallets")
}

// ── Commands ────────────────────────────────────────────────────────

async fn cmd_init(name: &Option<String>) -> Result<()> {
    // 1. Generate recovery phrase
    let phrase = RecoveryPhrase::generate();
    let phrase_str = phrase.display_phrase();

    println!("╔══════════════════════════════════════════╗");
    println!("║  WRITE DOWN YOUR RECOVERY PHRASE         ║");
    println!("║  Anyone with these words can spend       ║");
    println!("║  your Vess. Keep them safe.              ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║  {}", phrase_str);
    println!("╚══════════════════════════════════════════╝");

    // 2. Verify
    print!("\nType the phrase to confirm: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim() != phrase_str {
        anyhow::bail!("phrases don't match — try again");
    }

    // 3. Derive keys
    let seed = recovery::derive_raw_seed(&phrase)?;
    let enc_key = recovery::encryption_key_from_seed(&seed);
    let spend_seed = recovery::spend_seed_from_raw_seed(&seed);
    let (secret, master_address) = recovery::recover_master_keys(&phrase)?;
    let encrypted_secrets = recovery::encrypt_secrets(&secret, &enc_key)?;

    // 4. Save wallet
    let dir = wallets_dir();
    std::fs::create_dir_all(&dir)?;
    let wallet_name = name.clone().unwrap_or_else(|| "default".to_string());
    let path = dir.join(format!("{}.json", wallet_name));

    let wallet = WalletFile::new(
        master_address,
        encrypted_secrets,
        BillFold::new(),
        spend_seed,
        &enc_key,
    )?;

    wallet.save(&path, &enc_key)?;

    println!("\nWallet '{}' created.", wallet_name);
    println!("Register a tag to receive payments: vess tag register <yourname>");
    Ok(())
}

async fn cmd_recover(name: &Option<String>) -> Result<()> {
    // 1. Read phrase
    print!("Enter your 12-word recovery phrase: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let phrase = RecoveryPhrase::from_input(input.trim())?;

    // 2. Derive keys
    let seed = recovery::derive_raw_seed(&phrase)?;
    let enc_key = recovery::encryption_key_from_seed(&seed);
    let spend_seed = recovery::spend_seed_from_raw_seed(&seed);
    let (secret, master_address) = recovery::recover_master_keys(&phrase)?;
    let encrypted_secrets = recovery::encrypt_secrets(&secret, &enc_key)?;

    // 3. Derive seed hash for DHT manifest lookup
    let seed_hash = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-wallet-seed-v1");
        h.update(&seed);
        *h.finalize().as_bytes()
    };

    // 4. Try to recover from DHT manifest
    let billfold = BillFold::new();
    println!("Attempting DHT recovery...");
    match rpc(9400, "recover_manifest", json!({"seed_hash": hex::encode(&seed_hash)})).await {
        Ok(resp) => {
            let found = resp["bills_found"].as_u64().unwrap_or(0);
            println!("Found {} bills in local store.", found);
        }
        Err(_) => {
            println!("Node not running — billfold starts empty.");
            println!("Start the node with 'vess node --wallet {}' to sync from DHT.", 
                name.clone().unwrap_or_else(|| "recovered".to_string()));
        }
    }

    // 5. Save wallet
    let dir = wallets_dir();
    std::fs::create_dir_all(&dir)?;
    let wallet_name = name.clone().unwrap_or_else(|| "recovered".to_string());
    let path = dir.join(format!("{}.json", wallet_name));

    let wallet = WalletFile::new(
        master_address,
        encrypted_secrets,
        billfold,
        spend_seed,
        &enc_key,
    )?;

    wallet.save(&path, &enc_key)?;

    println!("\nWallet '{}' recovered.", wallet_name);
    println!("Use 'vess node --wallet {}' to start syncing.", wallet_name);
    println!("Register a tag to receive payments: vess tag register <yourname>");
    Ok(())
}

async fn cmd_receive(port: u16) -> Result<()> {
    let resp = rpc(port, "receive", json!({})).await?;
    if let Some(tag) = resp["tag"].as_str() {
        println!("Your tag: +{}", tag);
        println!("Share this to receive payments.");
    } else {
        println!("No tag registered yet.");
        println!("Register one with: vess tag register <yourname>");
    }
    Ok(())
}

async fn cmd_dev_faucet(port: u16) -> Result<()> {
    // Read dev secret key
    print!("Dev secret key (hex): ");
    io::stdout().flush()?;
    let mut sk_hex = String::new();
    io::stdin().read_line(&mut sk_hex)?;
    let dev_sk = hex::decode(sk_hex.trim()).context("invalid hex for dev SK")?;

    // Generate fresh ephemeral keypair for this faucet Vess (unique per bill)
    let (owner_vk, owner_sk) = spend_auth::generate_spend_keypair();
    let initial_pk = spend_auth::vk_hash(&owner_vk);

    // Create and submit
    let epoch = vess_foundry::clock::current_epoch();
    let faucet = mint::create_faucet(&dev_sk, epoch, &owner_vk, &initial_pk)
        .map_err(|e| anyhow::anyhow!("faucet creation failed: {e}"))?;

    rpc(
        port,
        "faucet_submit",
        json!({"vess": serde_json::to_value(&faucet)?, "owner_sk": hex::encode(&owner_sk)}),
    )
    .await?;
    println!(
        "Faucet submitted: epoch {}, {} Vess → wallet",
        epoch, faucet.amount
    );
    println!("vess_id: {}", hex::encode(faucet.compute_vess_id()));
    Ok(())
}

async fn cmd_node(
    rpc_port: u16,
    bind: &Option<String>,
    bootstrap: &[String],
    state_dir: &Option<PathBuf>,
    wallet_name: &Option<String>,
) -> Result<()> {
    let bind_addr: Option<std::net::SocketAddr> = bind.as_ref().and_then(|b| b.parse().ok());
    let state = state_dir.clone().unwrap_or_else(|| {
        dirs_next::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("vess")
            .join("artery")
    });
    let wallet_path = wallet_name
        .as_ref()
        .map(|n| wallets_dir().join(format!("{}.json", n)));

    let config = vess_artery::node_runner::NodeConfig {
        state_dir: state,
        wallet_path,
        wallet_password: None,
        rpc_port: Some(rpc_port),
        bind_addr,
        k_neighbors: 20,
        max_hops: 6,
        bootstrap: bootstrap.to_vec(),
        enable_local_discovery: true,
        test: false,
    };

    println!("Starting Vess node...");
    println!("  bind:      {}", bind.as_deref().unwrap_or("0.0.0.0:0"));
    if let Some(w) = wallet_name {
        println!("  wallet:    {}", w);
    }
    println!("  bootstrap: {:?}", bootstrap);
    println!();

    match vess_artery::node_runner::run_node(config).await {
        Ok(node_id) => {
            println!("Node {} shut down.", node_id);
        }
        Err(e) => {
            anyhow::bail!("node crashed: {e}");
        }
    }
    Ok(())
}
