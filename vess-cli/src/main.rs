//! Unified CLI for the Vess protocol.
//!
//! `init` and `recover` bootstrap a wallet via DNS seed discovery.
//! All other commands route through the local node's JSON-RPC server
//! (default port 9400). `node` starts an artery node with optional
//! embedded wallet and RPC listener.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;
use tracing_subscriber::EnvFilter;

use vess_kloak::persistence::WalletFile;
use vess_kloak::recovery::{
    derive_raw_seed, encrypt_secrets, encryption_key_from_seed,
    recover_master_keys, spend_seed_from_raw_seed, RecoveryPhrase,
};
use vess_kloak::BillFold;
use vess_kloak::payment::build_genesis_messages;
use vess_kloak::billfold::SpendCredential;
use vess_protocol::{PulseMessage, TagRegister, TagLookup};
use vess_stealth::generate_master_keys_from_seed;
use vess_tag::VessTag;
use vess_vascular::VessNode;

#[derive(Parser)]
#[command(name = "vess", version, about = "Vess — stateless P2P digital cash")]
struct Cli {
    /// Path to wallet file (default: ~/.vess/wallet.json).
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    /// Output JSON instead of human-readable text (for AI agents / automation).
    #[arg(long, global = true)]
    json: bool,

    /// Connect to a running node's local RPC server on 127.0.0.1:<port>.
    /// When set, balance/send/tag-lookup commands talk to the node
    /// instead of operating on the wallet file directly.
    #[arg(long, global = true)]
    rpc: Option<u16>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new wallet with a recovery phrase.
    Init {
        /// VessTag to claim (e.g. "alice" or "+alice").
        #[arg(long)]
        tag: String,
    },

    /// Recover a wallet from a recovery phrase.
    Recover {
        /// The 5 BIP39 words separated by spaces.
        #[arg(long)]
        words: String,
        /// The 5-digit PIN.
        #[arg(long)]
        pin: String,
    },

    /// Show wallet balance and denomination breakdown.
    Balance,

    /// Send Vess to a recipient (by +tag or stealth address).
    Send {
        /// Amount to send.
        amount: u64,
        /// Recipient: +tag or stealth address.
        recipient: String,
    },

    /// Mint new vess via proof-of-work (flow-based: mine until Ctrl+C).
    Mint {
        /// Only finalize an existing session (aggregate + register, no further mining).
        #[arg(long)]
        finalize: bool,
        /// Show status of an existing mint session.
        #[arg(long)]
        status: bool,
    },

    /// Register a VessTag (computes PoW and auto-hardens if bills are available).
    RegisterTag {
        /// Tag to register (e.g. "alice" or "+alice").
        tag: String,
    },

    /// Send a raw Pulse to a remote node (low-level).
    Pulse {
        /// Target node's endpoint ID (hex).
        node_id: String,
        /// Message payload.
        message: String,
    },

    /// Listen for raw incoming Pulses (low-level).
    Listen,

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
        /// Bootstrap peer node IDs to connect to on startup (comma-separated).
        #[arg(long, value_delimiter = ',')]
        bootstrap: Vec<String>,
        /// DNS seed domains for peer discovery (comma-separated).
        /// Defaults to node.vess.network. Use --no-seed to disable.
        #[arg(long, value_delimiter = ',')]
        seed: Vec<String>,
        /// Disable automatic DNS seed resolution.
        #[arg(long, default_value = "false")]
        no_seed: bool,
        /// Path to wallet file. Embeds wallet in node for auto-receive.
        /// Requires VESS_WALLET_PASSWORD (or --wallet-password) to unlock,
        /// or VESS_RECOVERY_PHRASE + VESS_RECOVERY_PIN as fallback.
        #[arg(long)]
        wallet: Option<PathBuf>,
        /// Password for fast wallet unlock.
        #[arg(long)]
        wallet_password: Option<String>,
        /// Enable the local-only JSON-RPC server on 127.0.0.1:<port>.
        #[arg(long)]
        rpc_port: Option<u16>,
    },

    /// Set a password for fast daily wallet unlock.
    ///
    /// Requires the wallet encryption key (via VESS_WALLET_PASSWORD or
    /// VESS_RECOVERY_PHRASE + VESS_RECOVERY_PIN) to encrypt the key
    /// cache.  After this, the node only needs the password to start.
    SetPassword {
        /// The new password to set.
        #[arg(long)]
        password: String,
    },
}

fn wallet_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(ref p) = cli.wallet {
        Ok(p.clone())
    } else {
        vess_kloak::persistence::default_wallet_path()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match &cli.command {
        Command::Init { tag } => cmd_init(&cli, tag).await,
        Command::Recover { words, pin } => cmd_recover(&cli, words, pin).await,
        Command::Balance => cmd_balance(&cli).await,
        Command::Send { amount, recipient } => {
            cmd_send(&cli, *amount, recipient).await
        }
        Command::Mint { finalize, status } => cmd_mint(&cli, *finalize, *status).await,
        Command::RegisterTag { tag } => cmd_register_tag(&cli, tag).await,
        Command::Pulse { node_id, message } => cmd_pulse(&cli, node_id, message).await,
        Command::Listen => cmd_listen(&cli).await,
        Command::Node { k_neighbors, max_hops, state_dir, bootstrap, seed, no_seed, wallet, wallet_password, rpc_port } => {
            let config = vess_artery::node_runner::NodeConfig {
                k_neighbors: *k_neighbors,
                max_hops: *max_hops,
                state_dir: match state_dir {
                    Some(d) => d.clone(),
                    None => vess_artery::persistence::NodeStorage::default_dir()?,
                },
                bootstrap: bootstrap.clone(),
                seeds: if *no_seed {
                    Vec::new()
                } else if seed.is_empty() {
                    vec![vess_artery::dns_seed::DEFAULT_SEED_DOMAIN.to_string()]
                } else {
                    seed.clone()
                },
                ready_tx: None,
                wallet_path: wallet.clone(),
                rpc_port: *rpc_port,
                wallet_password: wallet_password.clone(),
            };
            vess_artery::node_runner::run_node(config).await?;
            Ok(())
        }
        Command::SetPassword { password } => cmd_set_password(&cli, password.clone()).await,
    }
}

// ── Subcommand implementations ──────────────────────────────────────

/// Derive the wallet encryption key.  Tries password-based unlock first
/// (VESS_WALLET_PASSWORD env var), then falls back to recovery phrase + PIN.
fn derive_enc_key(cli: &Cli) -> Result<[u8; 32]> {
    let raw_seed = derive_raw_seed_for_wallet(cli)?;
    Ok(encryption_key_from_seed(&raw_seed))
}

/// Obtain the 64-byte raw_seed.  Tries password-based unlock first
/// (VESS_WALLET_PASSWORD env var), then falls back to recovery phrase + PIN.
fn derive_raw_seed_for_wallet(cli: &Cli) -> Result<[u8; 64]> {
    // Fast path: password-based unlock.
    if let Ok(pwd) = std::env::var("VESS_WALLET_PASSWORD") {
        let wpath = wallet_path(cli)?;
        let wallet = WalletFile::load(&wpath)?;
        return wallet.unlock_with_password(&pwd);
    }
    // Slow path: recovery phrase + PIN.
    let words = std::env::var("VESS_RECOVERY_PHRASE").map_err(|_| {
        anyhow::anyhow!(
            "set VESS_WALLET_PASSWORD or VESS_RECOVERY_PHRASE + VESS_RECOVERY_PIN env vars"
        )
    })?;
    let pin = std::env::var("VESS_RECOVERY_PIN").map_err(|_| {
        anyhow::anyhow!("set VESS_RECOVERY_PIN env var for this operation")
    })?;
    let phrase = RecoveryPhrase::from_input(&words, &pin)?;
    Ok(derive_raw_seed(&phrase)?)
}

/// Send a JSON-RPC request to the node's local RPC server and return the
/// parsed response.  The caller is responsible for constructing the request
/// object (must be a single JSON line).
async fn rpc_call(port: u16, request: &serde_json::Value) -> Result<serde_json::Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&addr).await.map_err(|e| {
        anyhow::anyhow!("cannot connect to node RPC at {addr}: {e} — is the node running with --rpc-port {port}?")
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut line_buf = String::new();
    let mut buf_reader = BufReader::new(reader);

    let mut req_bytes = serde_json::to_vec(request)?;
    req_bytes.push(b'\n');
    writer.write_all(&req_bytes).await?;

    buf_reader.read_line(&mut line_buf).await?;
    let resp: serde_json::Value = serde_json::from_str(line_buf.trim())?;
    Ok(resp)
}

/// Discover artery peers via DNS seeds. Used by init/recover when the
/// local node is not yet running.
async fn discover_peers() -> Result<Vec<iroh::EndpointId>> {
    let seeds = vess_artery::dns_seed::resolve_seeds(
        vess_artery::dns_seed::DEFAULT_SEED_DOMAIN,
    ).await?;
    let mut peers = Vec::new();
    for s in &seeds {
        if let Ok(eid) = s.parse::<iroh::EndpointId>() {
            peers.push(eid);
        }
    }
    if peers.is_empty() {
        anyhow::bail!(
            "no artery peers found via DNS seeds — check your internet connection"
        );
    }
    Ok(peers)
}

/// Return the RPC port to use: explicit --rpc flag or default 9400.
fn rpc_port(cli: &Cli) -> u16 {
    cli.rpc.unwrap_or(vess_artery::rpc::DEFAULT_RPC_PORT)
}

async fn cmd_init(cli: &Cli, tag_str: &str) -> Result<()> {
    let path = wallet_path(cli)?;
    if path.exists() {
        anyhow::bail!("wallet already exists at {}", path.display());
    }

    let tag = VessTag::new(tag_str)?;

    // ── Discover artery peers via DNS seeds ──────────────────────
    let peers = discover_peers().await?;
    let target = peers[0];

    // ── Check tag availability BEFORE creating wallet ────────────
    let vess_node = VessNode::spawn().await?;
    vess_node.wait_online().await;

    println!("Checking if tag {} is available…", tag.display());

    let lookup = PulseMessage::TagLookup(TagLookup {
        tag_hash: *blake3::hash(tag.as_str().as_bytes()).as_bytes(),
        nonce: rand::random(),
    });

    let resp = vess_node.send_message_with_response(target, &lookup).await?;

    let is_taken = match &resp {
        Some(PulseMessage::TagLookupResponse(tlr)) => tlr.result.is_some(),
        _ => false,
    };

    if is_taken {
        vess_node.shutdown().await;
        anyhow::bail!("tag {} is already claimed — wallet was NOT created", tag.display());
    }

    println!("Tag {} is available!", tag.display());

    let phrase = RecoveryPhrase::generate();

    // Derive raw seed → deterministic ML-KEM keys + encryption key + spend seed.
    let raw_seed = derive_raw_seed(&phrase)?;
    let (secret, address) = generate_master_keys_from_seed(&raw_seed);
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = encrypt_secrets(&secret, &enc_key)?;

    let mut wallet = WalletFile::new(address, encrypted, BillFold::new(), spend_seed, &enc_key)?;

    // ── Register tag ─────────────────────────────────────────────
    {
        println!("Computing Argon2id proof-of-work (~10 seconds, 2 GiB RAM)…");

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

        vess_node.send_message(target, &msg).await?;
        vess_node.shutdown().await;

        if cli.json {
            println!("{}", json!({ "tag_registered": true, "tag": tag.display() }));
        } else {
            println!("Tag {} registration sent.", tag.display());
        }
    }

    wallet.save(&path)?;

    if cli.json {
        println!("{}", json!({
            "ok": true,
            "recovery_phrase": phrase.display_phrase(),
            "wallet_path": path.display().to_string(),
        }));
    } else {
        println!("=== WRITE DOWN YOUR RECOVERY PHRASE ===");
        println!();
        println!("  {}", phrase.display_phrase());
        println!();
        println!("This is the ONLY way to recover your wallet.");
        println!("=========================================");
        println!("\nWallet created at {}", path.display());
    }

    Ok(())
}

async fn cmd_recover(cli: &Cli, words: &str, pin: &str) -> Result<()> {
    let path = wallet_path(cli)?;
    let phrase = RecoveryPhrase::from_input(words, pin)?;

    // Deterministically regenerate keys from phrase alone.
    let (secret, address) = recover_master_keys(&phrase)?;
    let raw_seed = derive_raw_seed(&phrase)?;
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = encrypt_secrets(&secret, &enc_key)?;

    // Create or overwrite wallet with regenerated keys.
    let mut billfold = if path.exists() {
        let existing = WalletFile::load(&path)?;
        existing.billfold
    } else {
        BillFold::new()
    };

    // ── Manifest-based bill recovery ────────────────────────────────
    println!("Recovering bills via manifest…");

    let node = VessNode::spawn().await?;
    node.wait_online().await;

    // Discover artery peers via DNS seeds.
    let peers = discover_peers().await?;
    let bootstrap_target = peers[0];

    // Discover additional peers via PeerExchange for fan-out.
    let mut targets: Vec<iroh::EndpointId> = vec![bootstrap_target];

    let pe_msg = PulseMessage::PeerExchange(vess_protocol::PeerExchange {
        sender_id: vec![0u8; 32],
    });
    if let Ok(Some(PulseMessage::PeerExchangeResponse(resp))) =
        node.send_message_with_response(bootstrap_target, &pe_msg).await
    {
        for peer_bytes in &resp.peers {
            if let Ok(arr) = <[u8; 32]>::try_from(peer_bytes.as_slice()) {
                if let Ok(eid) = iroh::EndpointId::from_bytes(&arr) {
                    if !targets.contains(&eid) {
                        targets.push(eid);
                    }
                }
            }
        }
    }

    let peer_count = targets.len();
    println!("  Using {peer_count} peer(s) for recovery");

    // Step 1: Fetch manifest.
    let manifest_key = vess_foundry::seal::manifest_dht_key(&spend_seed);
    let manifest_req = PulseMessage::ManifestRecover(vess_protocol::ManifestRecover {
        dht_key: manifest_key,
    });

    let mut manifest_entries = Vec::new();
    let mut manifest_found = false;

    for &peer in &targets {
        let resp = node.send_message_with_response(peer, &manifest_req).await;
        if let Ok(Some(PulseMessage::ManifestRecoverResponse(mrr))) = resp {
            if mrr.found {
                match vess_foundry::seal::decrypt_manifest(&spend_seed, &mrr.encrypted_manifest) {
                    Ok(entries) => {
                        manifest_entries = entries;
                        manifest_found = true;
                        println!("  Manifest found with {} bill entries", manifest_entries.len());
                        break;
                    }
                    Err(e) => {
                        println!("  Manifest decrypt failed from peer: {e}");
                    }
                }
            }
        }
    }

    let mut recovered: u64 = 0;
    let mut max_dht_index: u64 = 0;

    if manifest_found && !manifest_entries.is_empty() {
        // Step 2: Fetch ownership records for each mint_id.
        let mint_ids: Vec<[u8; 32]> = manifest_entries.iter().map(|e| e.mint_id).collect();
        let fetch_req = PulseMessage::OwnershipFetch(vess_protocol::OwnershipFetch {
            mint_ids: mint_ids.clone(),
        });

        // Try each peer until we get a response.
        let mut fetched_records = Vec::new();
        for &peer in &targets {
            let resp = node.send_message_with_response(peer, &fetch_req).await;
            if let Ok(Some(PulseMessage::OwnershipFetchResponse(ofr))) = resp {
                fetched_records = ofr.records;
                break;
            }
        }

        // Step 3: Reconstruct bills from registry data.
        for (i, entry) in manifest_entries.iter().enumerate() {
            if i >= fetched_records.len() {
                break;
            }
            let rec = &fetched_records[i];
            if !rec.found {
                println!("  [{}] mint_id {}: not found in registry", i, hex(&entry.mint_id[..4]));
                continue;
            }

            let denomination = match vess_foundry::Denomination::from_value(rec.denomination_value) {
                Some(d) => d,
                None => {
                    println!("  [{i}] unknown denomination value: {}", rec.denomination_value);
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

            println!(
                "  [{}] recovered {} bill (mint_id: {})",
                i,
                bill.denomination,
                hex(&bill.mint_id[..4]),
            );
            billfold.deposit(bill);
            recovered += 1;
            if entry.dht_index >= max_dht_index {
                max_dht_index = entry.dht_index + 1;
            }
        }
    } else {
        println!("  No manifest found on any peer. No bills recovered.");
    }

    node.shutdown().await;
    println!("Recovery complete: {recovered} bills recovered.");

    let mut wallet = WalletFile::new(address, encrypted, billfold, spend_seed, &enc_key)?;
    wallet.next_dht_index = max_dht_index;
    wallet.save(&path)?;

    if cli.json {
        println!("{}", json!({
            "ok": true,
            "wallet_path": path.display().to_string(),
            "recovered_bills": recovered,
            "balance": wallet.billfold.balance(),
        }));
    } else {
        println!("Wallet recovered successfully at {}", path.display());
        println!(
            "Scan key:  {} bytes",
            secret.scan_dk.len()
        );
        println!(
            "Spend key: {} bytes",
            secret.spend_dk.len()
        );
        println!("Balance: {} Vess", wallet.billfold.balance());
    }
    Ok(())
}

async fn cmd_balance(cli: &Cli) -> Result<()> {
    // ── RPC path ────────────────────────────────────────────────────
    if let Some(port) = cli.rpc {
        let resp = rpc_call(port, &json!({"method": "balance"})).await?;
        if resp["ok"] == true {
            if cli.json {
                println!("{resp}");
            } else {
                println!("Balance: {} Vess", resp["balance"]);
                println!("Bills:   {}", resp["bill_count"]);
            }
        } else {
            anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
        }
        return Ok(());
    }

    let path = wallet_path(cli)?;
    let wallet = WalletFile::load(&path)?;

    if cli.json {
        let breakdown: serde_json::Map<String, serde_json::Value> = wallet.billfold.denomination_breakdown()
            .into_iter()
            .map(|(d, c)| (format!("{d}"), json!(c)))
            .collect();
        println!("{}", json!({
            "ok": true,
            "balance": wallet.billfold.balance(),
            "bills": wallet.billfold.count(),
            "denominations": breakdown,
        }));
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

async fn cmd_send(cli: &Cli, amount: u64, recipient_id: &str) -> Result<()> {
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({
        "method": "send",
        "amount": amount,
        "recipient": recipient_id,
    })).await?;
    if resp["ok"] == true {
        if cli.json {
            println!("{resp}");
        } else {
            println!("Payment sent!");
            println!("Payment ID: {}", resp["payment_id"].as_str().unwrap_or("?"));
            println!("Amount:     {} Vess", resp["amount"]);
            println!("Balance:    {} Vess", resp["remaining_balance"]);
        }
    } else {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }
    Ok(())
}

async fn cmd_mint(cli: &Cli, finalize_only: bool, status_only: bool) -> Result<()> {
    let path = wallet_path(cli)?;
    let mut wallet = WalletFile::load(&path)?;

    // Decrypt spend seed (required for DHT key derivation and sealing).
    let enc_key = derive_enc_key(cli)?;
    let spend_seed = wallet.decrypt_spend_seed(&enc_key)?;

    // Session file lives next to the wallet.
    let session_path = path.with_extension("mint-session.json");

    // Generate ML-DSA-65 keypair — the owner's vk_hash is baked into STARK seeds.
    let (spend_vk, spend_sk) = vess_foundry::spend_auth::generate_spend_keypair();
    let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&spend_vk);

    // ── Status mode ────────────────────────────────────────────────
    if status_only {
        let state = vess_foundry::mint::MintSessionState::load_or_create(&session_path, owner_vk_hash);
        if state.solves.is_empty() {
            if cli.json {
                println!("{}", json!({ "ok": true, "solves": 0, "vess": 0, "attempts": state.total_attempts }));
            } else {
                println!("No active mint session (0 solves).");
            }
        } else {
            let vess = state.solves.len();
            let breakdown = vess_foundry::mint::optimal_breakdown(vess as u64);
            let bill_count = breakdown.len();
            if cli.json {
                println!("{}", json!({
                    "ok": true,
                    "solves": vess,
                    "vess": vess,
                    "attempts": state.total_attempts,
                    "bills_after_aggregation": bill_count,
                }));
            } else {
                println!("Mint session: {} solves ({} vess)", vess, vess);
                println!("Attempts:     {}", state.total_attempts);
                println!("Aggregation:  {} bills ({})", bill_count,
                    breakdown.iter().map(|d| format!("{d}")).collect::<Vec<_>>().join(" + "));
            }
        }
        return Ok(());
    }

    // ── Mine (unless --finalize) ───────────────────────────────────
    if !finalize_only {
        let json_mode = cli.json;
        if !json_mode {
            println!("Mining vess… (1 solve = 1 vess). Press Ctrl+C to stop and finalize.");
        }

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();
        ctrlc_flag(&stop_clone);

        let sp = session_path.clone();
        let vk_hash = owner_vk_hash;
        let state = tokio::task::spawn_blocking(move || {
            vess_foundry::mint::mine_flow(&sp, &vk_hash, stop, |count, attempts| {
                if json_mode {
                    println!("{}", serde_json::json!({
                        "event": "solve",
                        "solves": count,
                        "attempts": attempts,
                    }));
                } else {
                    println!("  Solve #{count} found! ({attempts} total attempts)");
                }
            })
        })
        .await?;

        if state.solves.is_empty() {
            if !cli.json {
                println!("No solves found. Session saved — resume with `vess mint`.");
            }
            return Ok(());
        }

        if !cli.json {
            println!("\nMining stopped. {} solves ({} vess) accumulated.", state.solves.len(), state.solves.len());
        }
    }

    // ── Finalize: aggregate + register ─────────────────────────────
    let state = vess_foundry::mint::MintSessionState::load_or_create(&session_path, owner_vk_hash);
    if state.solves.is_empty() {
        if cli.json {
            println!("{}", json!({ "ok": false, "error": "no solves to finalize" }));
        } else {
            println!("No solves to finalize.");
        }
        return Ok(());
    }

    let solve_count = state.solves.len();
    let json_regen = cli.json;
    let bills = vess_foundry::mint::aggregate_solves(
        &state.solves,
        &owner_vk_hash,
        Some(&|current, total| {
            if json_regen {
                println!("{}", serde_json::json!({
                    "event": "proof_regen",
                    "current": current,
                    "total": total,
                }));
            } else {
                print!("\r  Regenerating proofs: {current}/{total}");
            }
        }),
    );
    if !json_regen {
        println!(); // newline after \r progress
    }

    if !cli.json {
        println!("Aggregating {} solves into {} bill(s):", solve_count, bills.len());
        for (b, _) in &bills {
            println!("  {} (mint_id: {})", b.denomination, b.mint_id_hex());
        }
    }

    // Store aggregated bills in wallet.
    for (bill, _proof_bytes) in &bills {
        let mut b = bill.clone();
        let dht_index = wallet.alloc_dht_index();
        b.dht_index = dht_index;

        wallet.billfold.deposit_with_credentials(
            b.clone(),
            SpendCredential {
                spend_vk: spend_vk.clone(),
                spend_sk: spend_sk.clone(),
            },
        );
    }

    // Broadcast OwnershipGenesis for every aggregated bill via RPC.
    let port = rpc_port(cli);
    let genesis_msgs = build_genesis_messages(&bills, &spend_vk);
    for gm in &genesis_msgs {
        if let PulseMessage::OwnershipGenesis(og) = gm {
            rpc_call(port, &json!({
                "method": "ownership_genesis",
                "mint_id_hex": hex(&og.mint_id),
                "chain_tip_hex": hex(&og.chain_tip),
                "owner_vk_hash_hex": hex(&og.owner_vk_hash),
                "owner_vk_hex": hex(&og.owner_vk),
                "denomination_value": og.denomination_value,
                "proof_hex": hex(&og.proof),
                "digest_hex": hex(&og.digest),
            })).await?;
        }
    }

    wallet.save(&path)?;

    // Update the recovery manifest via RPC.
    {
        let manifest_entries: Vec<vess_foundry::seal::ManifestEntry> = wallet
            .billfold
            .bills()
            .iter()
            .map(|b| vess_foundry::seal::ManifestEntry {
                mint_id: b.mint_id,
                dht_index: b.dht_index,
            })
            .collect();
        let manifest_key = vess_foundry::seal::manifest_dht_key(&spend_seed);
        let encrypted_manifest = vess_foundry::seal::encrypt_manifest(&spend_seed, &manifest_entries)?;

        rpc_call(port, &json!({
            "method": "manifest_store",
            "dht_key_hex": hex(&manifest_key),
            "encrypted_manifest_hex": hex(&encrypted_manifest),
        })).await?;
    }

    // Clean up session file after successful finalization.
    if session_path.exists() {
        let _ = std::fs::remove_file(&session_path);
    }

    if cli.json {
        println!("{}", json!({
            "ok": true,
            "solves": solve_count,
            "bills": bills.len(),
            "balance": wallet.billfold.balance(),
        }));
    } else {
        println!("Ownership genesis + manifest sent to artery node.");
        println!("Balance: {} Vess", wallet.billfold.balance());
    }
    Ok(())
}

/// Set a Ctrl+C handler that flips the stop flag.
fn ctrlc_flag(stop: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let s = stop.clone();
    let _ = ctrlc::set_handler(move || {
        s.store(true, std::sync::atomic::Ordering::Relaxed);
    });
}

async fn cmd_register_tag(cli: &Cli, tag_str: &str) -> Result<()> {
    let path = wallet_path(cli)?;
    let mut wallet = WalletFile::load(&path)?;

    // Derive enc_key — needed to encrypt the new tag signing key.
    let password = std::env::var("VESS_WALLET_PASSWORD")
        .map_err(|_| anyhow::anyhow!("VESS_WALLET_PASSWORD required for register-tag (encrypts tag signing key)"))?;
    let raw_seed = wallet.unlock_with_password(&password)?;
    let enc_key = vess_kloak::recovery::encryption_key_from_seed(&raw_seed);

    let tag = VessTag::new(tag_str)?;

    println!("Registering tag {}", tag.display());
    println!("Computing Argon2id proof-of-work (this takes ~10 seconds and 2 GiB RAM)…");

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
    wallet.save(&path)?;

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

    // Send registration via RPC to local artery node.
    let port = rpc_port(cli);
    let resp = rpc_call(port, &json!({
        "method": "tag_register",
        "tag": tag.as_str(),
        "scan_ek_hex": hex(&wallet.master_address.scan_ek),
        "spend_ek_hex": hex(&wallet.master_address.spend_ek),
        "pow_nonce_hex": hex(&pow_nonce),
        "pow_hash_hex": hex(&pow_hash),
        "timestamp": tmp_record.registered_at,
        "registrant_vk_hex": hex(&registrant_vk),
        "signature_hex": hex(&signature),
    })).await?;

    if resp["ok"] != true {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("tag registration failed"));
    }

    if !cli.json {
        println!("Tag {} registration sent.", tag.display());
    }

    // ── Auto-harden with first available bill ────────────────────
    let hardened = if let Some(bill) = wallet.billfold.bills().first() {
        let mint_id = bill.mint_id;
        let confirm_digest = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-tag-confirm-v1");
            h.update(tag.as_str().as_bytes());
            h.update(&mint_id);
            *h.finalize().as_bytes()
        };
        let confirm_sig = vess_foundry::spend_auth::sign_spend(&registrant_sk, &confirm_digest)?;

        let confirm_resp = rpc_call(port, &json!({
            "method": "tag_confirm",
            "tag": tag.as_str(),
            "mint_id_hex": hex(&mint_id),
            "registrant_vk_hex": hex(&registrant_vk),
            "signature_hex": hex(&confirm_sig),
        })).await?;

        if confirm_resp["ok"] == true {
            if !cli.json {
                println!("Tag {} auto-hardened with bill proof.", tag.display());
            }
            true
        } else {
            if !cli.json {
                println!("Tag registered but hardening failed: {}", confirm_resp["error"].as_str().unwrap_or("unknown"));
                println!("You can harden later once you have bills in your wallet.");
            }
            false
        }
    } else {
        if !cli.json {
            println!("No bills in wallet — tag registered but not hardened.");
            println!("The tag will be auto-hardened when you receive or mint bills.");
        }
        false
    };

    if cli.json {
        println!("{}", json!({
            "ok": true,
            "tag": tag.display(),
            "hardened": hardened,
        }));
    }
    Ok(())
}

async fn cmd_pulse(cli: &Cli, node_id: &str, message: &str) -> Result<()> {
    let node = VessNode::spawn().await?;

    let target: iroh::EndpointId = node_id
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid endpoint id: {e}"))?;

    node.send_pulse(target, message.as_bytes()).await?;
    node.shutdown().await;
    if cli.json {
        println!("{}", json!({ "ok": true, "node_id": node_id }));
    } else {
        println!("Pulse delivered.");
    }
    Ok(())
}

async fn cmd_listen(cli: &Cli) -> Result<()> {
    let json_mode = cli.json;
    let node = VessNode::spawn().await?;
    if !json_mode {
        println!("Connecting to relay for NAT traversal…");
    }
    node.wait_online().await;

    if json_mode {
        println!("{}", json!({ "event": "ready", "node_id": node.id().to_string() }));
    } else {
        println!("Node ID:   {}", node.id());
        println!("Node Addr: {:?}", node.addr());
        println!("Listening for Pulses… (Ctrl+C to stop)\n");
    }

    node.listen(move |peer, payload| {
        if json_mode {
            let msg = String::from_utf8_lossy(&payload);
            println!("{}", serde_json::json!({ "event": "pulse", "peer": peer.to_string(), "payload": msg }));
        } else {
            let msg = String::from_utf8_lossy(&payload);
            println!("[{peer}] {msg}");
        }
    })
    .await?;

    node.shutdown().await;
    Ok(())
}

async fn cmd_set_password(cli: &Cli, password: String) -> Result<()> {
    let path = wallet_path(cli)?;
    let mut wallet = WalletFile::load(&path)?;

    // Obtain the raw_seed — from existing password or recovery phrase.
    let raw_seed = derive_raw_seed_for_wallet(cli)?;

    wallet.set_password_cache(&raw_seed, &password)?;
    wallet.save(&path)?;

    println!("Password set.  The node can now start with VESS_WALLET_PASSWORD or --wallet-password.");
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
