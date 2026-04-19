//! Local-only JSON-RPC server for controlling the embedded wallet and node.
//!
//! Binds exclusively to `127.0.0.1` — never a public interface — so
//! only the machine owner can interact with the node via the CLI.
//!
//! Protocol: newline-delimited JSON over TCP. Each request is a single
//! JSON object terminated by `\n`; each response is a single JSON object
//! terminated by `\n`. The connection stays open for multiple exchanges.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, warn};

use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::{prepare_payment_with_transfer, prepare_payment_from_bills};
use vess_kloak::selection::{select_bills, decompose_amount};
use vess_foundry::reforge::{reforge, ReforgeRequest};
use vess_foundry::spend_auth::generate_spend_keypair;
use vess_protocol::{PulseMessage, TagStore, ManifestStore};
use vess_stealth::MasterStealthAddress;
use vess_tag::{VessTag, TagRecord};

use crate::node_runner::ArteryState;
use crate::node_runner::WalletState;
use crate::persistence::hex_key;

/// Hex-encode an arbitrary byte slice.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string into bytes.
fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err("odd-length hex string".to_string());
    }
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at offset {i}: {e}"))
        })
        .collect()
}

/// Default RPC port.
pub const DEFAULT_RPC_PORT: u16 = 9400;

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RpcRequest {
    Balance,
    NodeInfo,
    TagLookup { tag: String },
    Send { amount: u64, recipient: String },
    WalletUnlock { password: String },
    WalletSetPassword { current_password: String, new_password: String },
    WalletLock,
    TagRegister {
        tag: String,
        scan_ek_hex: String,
        spend_ek_hex: String,
        pow_nonce_hex: String,
        pow_hash_hex: String,
        timestamp: u64,
        registrant_vk_hex: String,
        signature_hex: String,
    },
    TagConfirm {
        tag: String,
        mint_id_hex: String,
        registrant_vk_hex: String,
        signature_hex: String,
    },
    OwnershipGenesis {
        mint_id_hex: String,
        chain_tip_hex: String,
        owner_vk_hash_hex: String,
        owner_vk_hex: String,
        denomination_value: u64,
        proof_hex: String,
        digest_hex: String,
    },
    ManifestStore {
        dht_key_hex: String,
        encrypted_manifest_hex: String,
    },
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RpcResponse {
    Ok(RpcOk),
    Err(RpcErr),
}

#[derive(Debug, Serialize)]
pub struct RpcOk {
    pub ok: bool,
    #[serde(flatten)]
    pub data: RpcData,
}

#[derive(Debug, Serialize)]
pub struct RpcErr {
    pub ok: bool,
    pub error: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum RpcData {
    Balance {
        balance: u64,
        bill_count: usize,
    },
    NodeInfo {
        node_id: String,
        peer_count: usize,
        verified_peers: usize,
        estimated_network_size: usize,
        tag_count: usize,
        registry_count: usize,
        limbo_count: usize,
    },
    TagLookup {
        found: bool,
        tag: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        scan_ek: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        spend_ek: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hardened: Option<bool>,
    },
    Send {
        payment_id: String,
        amount: u64,
        remaining_balance: u64,
    },
    WalletStatus {
        locked: bool,
        has_password: bool,
    },
    Empty {},
}

impl RpcResponse {
    fn ok(data: RpcData) -> Self {
        RpcResponse::Ok(RpcOk { ok: true, data })
    }

    fn err(msg: impl Into<String>) -> Self {
        RpcResponse::Err(RpcErr {
            ok: false,
            error: msg.into(),
        })
    }
}

// ── Server ──────────────────────────────────────────────────────────

/// Spawn the RPC listener. Returns when the node shuts down.
pub(crate) async fn run_rpc_server(
    port: u16,
    state: Arc<Mutex<ArteryState>>,
) -> Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    info!(%addr, "RPC server listening");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "RPC accept error");
                continue;
            }
        };
        info!(%peer_addr, "RPC client connected");

        let st = state.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let resp = handle_request(&line, &st);
                let mut buf = match serde_json::to_vec(&resp) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error = %e, "RPC serialize error");
                        break;
                    }
                };
                buf.push(b'\n');
                if writer.write_all(&buf).await.is_err() {
                    break;
                }
            }
            info!(%peer_addr, "RPC client disconnected");
        });
    }
}

fn handle_request(line: &str, state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let req: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return RpcResponse::err(format!("invalid request: {e}")),
    };

    match req {
        RpcRequest::Balance => handle_balance(state),
        RpcRequest::NodeInfo => handle_node_info(state),
        RpcRequest::TagLookup { tag } => handle_tag_lookup(state, &tag),
        RpcRequest::Send { amount, recipient } => handle_send(state, amount, &recipient),
        RpcRequest::WalletUnlock { password } => handle_wallet_unlock(state, &password),
        RpcRequest::WalletSetPassword { current_password, new_password } => handle_wallet_set_password(state, &current_password, &new_password),
        RpcRequest::WalletLock => handle_wallet_lock(state),
        RpcRequest::TagRegister { tag, scan_ek_hex, spend_ek_hex, pow_nonce_hex, pow_hash_hex, timestamp, registrant_vk_hex, signature_hex } =>
            handle_tag_register(state, &tag, &scan_ek_hex, &spend_ek_hex, &pow_nonce_hex, &pow_hash_hex, timestamp, &registrant_vk_hex, &signature_hex),
        RpcRequest::TagConfirm { tag, mint_id_hex, registrant_vk_hex, signature_hex } =>
            handle_tag_confirm(state, &tag, &mint_id_hex, &registrant_vk_hex, &signature_hex),
        RpcRequest::OwnershipGenesis { mint_id_hex, chain_tip_hex, owner_vk_hash_hex, owner_vk_hex, denomination_value, proof_hex, digest_hex } =>
            handle_ownership_genesis(state, &mint_id_hex, &chain_tip_hex, &owner_vk_hash_hex, &owner_vk_hex, denomination_value, &proof_hex, &digest_hex),
        RpcRequest::ManifestStore { dht_key_hex, encrypted_manifest_hex } =>
            handle_manifest_store(state, &dht_key_hex, &encrypted_manifest_hex),
    }
}

// ── Handlers ────────────────────────────────────────────────────────

fn handle_balance(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    match &s.wallet {
        Some(ws) => RpcResponse::ok(RpcData::Balance {
            balance: ws.billfold.balance(),
            bill_count: ws.billfold.bills().len(),
        }),
        None => RpcResponse::err("wallet not loaded"),
    }
}

fn handle_node_info(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    RpcResponse::ok(RpcData::NodeInfo {
        node_id: hex_key(&s.node_id),
        peer_count: s.routing_table.peer_count(),
        verified_peers: s.peer_registry.count_in_state(
            crate::handshake::PeerState::Verified,
        ),
        estimated_network_size: s.estimated_network_size,
        tag_count: s.tag_dht.record_count(),
        registry_count: s.registry.len(),
        limbo_count: s.limbo_mint_ids.len(),
    })
}

fn handle_tag_lookup(state: &Arc<Mutex<ArteryState>>, tag: &str) -> RpcResponse {
    let tag_str = tag.strip_prefix('+').unwrap_or(tag);
    let s = state.lock().unwrap();
    match s.tag_dht.lookup(tag_str) {
        Some(record) => RpcResponse::ok(RpcData::TagLookup {
            found: true,
            tag: record.tag.as_str().to_owned(),
            scan_ek: Some(to_hex(&record.master_address.scan_ek)),
            spend_ek: Some(to_hex(&record.master_address.spend_ek)),
            hardened: Some(record.hardened_at.is_some()),
        }),
        None => RpcResponse::ok(RpcData::TagLookup {
            found: false,
            tag: tag_str.to_owned(),
            scan_ek: None,
            spend_ek: None,
            hardened: None,
        }),
    }
}

fn handle_send(
    state: &Arc<Mutex<ArteryState>>,
    amount: u64,
    recipient_tag: &str,
) -> RpcResponse {
    let tag_str = recipient_tag.strip_prefix('+').unwrap_or(recipient_tag);

    let mut s = state.lock().unwrap();

    // ── Require wallet ──────────────────────────────────────────────
    if s.wallet.is_none() {
        return RpcResponse::err("wallet not loaded");
    }

    // ── Resolve tag ─────────────────────────────────────────────────
    let recipient_address = match s.tag_dht.lookup(tag_str) {
        Some(record) => MasterStealthAddress {
            scan_ek: record.master_address.scan_ek.clone(),
            spend_ek: record.master_address.spend_ek.clone(),
        },
        None => return RpcResponse::err(format!("tag +{tag_str} not found")),
    };

    // ── Build credential map ────────────────────────────────────────
    let ws = s.wallet.as_ref().unwrap();
    let cred_map: HashMap<[u8; 32], SpendCredential> = ws
        .billfold
        .bills()
        .iter()
        .filter_map(|b| {
            ws.billfold
                .get_credentials(&b.mint_id)
                .cloned()
                .map(|c| (b.mint_id, c))
        })
        .collect();

    if !ws.billfold.can_afford(amount) {
        return RpcResponse::err(format!(
            "insufficient funds: need {amount}, have {}",
            ws.billfold.balance()
        ));
    }

    // ── Bill selection ──────────────────────────────────────────────
    let selection = match select_bills(ws.billfold.bills(), amount) {
        Ok(sel) => sel,
        Err(e) => return RpcResponse::err(format!("bill selection failed: {e}")),
    };

    let (msg, payment_id, _mint_ids_to_remove) = if selection.change > 0 {
        // === CHANGE PATH: reforge ===
        let input_bills: Vec<vess_foundry::VessBill> = selection
            .send_indices
            .iter()
            .map(|&i| ws.billfold.bills()[i].clone())
            .collect();

        let send_denoms = decompose_amount(amount);
        let mut all_denoms = send_denoms.clone();
        all_denoms.extend(&selection.change_denominations);

        let stealth_ids: Vec<[u8; 32]> = all_denoms
            .iter()
            .map(|_| input_bills[0].stealth_id)
            .collect();

        let result = match reforge(ReforgeRequest {
            inputs: input_bills,
            output_denominations: all_denoms,
            output_stealth_ids: stealth_ids,
        }) {
            Ok(r) => r,
            Err(e) => return RpcResponse::err(format!("reforge failed: {e}")),
        };

        let send_count = send_denoms.len();
        let send_bills: Vec<vess_foundry::VessBill> =
            result.outputs[..send_count].iter().map(|(b, _)| b.clone()).collect();
        let change_bills: Vec<vess_foundry::VessBill> =
            result.outputs[send_count..].iter().map(|(b, _)| b.clone()).collect();

        let mut reforged_creds: HashMap<[u8; 32], SpendCredential> = HashMap::new();
        for (bill, _) in &result.outputs {
            let (vk, sk) = generate_spend_keypair();
            reforged_creds.insert(bill.mint_id, SpendCredential {
                spend_vk: vk,
                spend_sk: sk,
            });
        }

        let (msg, pid) = match prepare_payment_from_bills(
            &send_bills,
            &recipient_address,
            &reforged_creds,
        ) {
            Ok(v) => v,
            Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
        };

        // Deposit change back, remove originals
        let ws_mut = s.wallet.as_mut().unwrap();
        for bill in &change_bills {
            if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                ws_mut.billfold.deposit_with_credentials(bill.clone(), cred.clone());
            }
        }
        for mid in &result.consumed_mint_ids {
            ws_mut.billfold.withdraw(mid);
        }

        let sent_mints: Vec<[u8; 32]> = send_bills.iter().map(|b| b.mint_id).collect();
        (msg, pid, sent_mints)
    } else {
        // === EXACT MATCH PATH ===
        let (msg, pid, send_indices) = match prepare_payment_with_transfer(
            &ws.billfold,
            amount,
            &recipient_address,
            &cred_map,
        ) {
            Ok(v) => v,
            Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
        };

        let ws_mut = s.wallet.as_mut().unwrap();
        let mint_ids: Vec<[u8; 32]> = send_indices
            .iter()
            .map(|&i| ws_mut.billfold.bills()[i].mint_id)
            .collect();
        for mid in &mint_ids {
            ws_mut.billfold.withdraw(mid);
        }
        (msg, pid, mint_ids)
    };

    // ── Queue payment for relay ─────────────────────────────────────
    if let PulseMessage::Payment(ref payment) = msg {
        s.payment_relay_queue.push(payment.clone());
    }

    let remaining = s.wallet.as_ref().map(|w| w.billfold.balance()).unwrap_or(0);

    RpcResponse::ok(RpcData::Send {
        payment_id: hex_key(&payment_id),
        amount,
        remaining_balance: remaining,
    })
}

fn handle_wallet_unlock(
    state: &Arc<Mutex<ArteryState>>,
    password: &str,
) -> RpcResponse {
    use vess_kloak::payment::receive_and_claim;
    use vess_kloak::billfold::SpendCredential;

    // 1. Get wallet_path (set from config even when wallet is locked).
    let wallet_path = {
        let s = state.lock().unwrap();
        match &s.wallet_path {
            Some(p) => p.clone(),
            None => return RpcResponse::err("no wallet path configured — start node with --wallet"),
        }
    };

    // 2. Already unlocked?
    {
        let s = state.lock().unwrap();
        if s.wallet.is_some() {
            return RpcResponse::err("wallet already unlocked");
        }
    }

    // 3. Load wallet file and decrypt raw_seed (outside lock — password KDF takes ~1 s).
    let wallet = match vess_kloak::WalletFile::load(&wallet_path) {
        Ok(w) => w,
        Err(e) => return RpcResponse::err(format!("failed to load wallet: {e}")),
    };
    let raw_seed = match wallet.unlock_with_password(password) {
        Ok(s) => s,
        Err(e) => return RpcResponse::err(format!("{e}")),
    };

    // Derive stealth keys from raw_seed — instant, no decryption needed.
    // raw_seed is NOT stored in WalletState; it is zeroized after this block.
    let (stealth_secret, _address) =
        vess_stealth::generate_master_keys_from_seed(&raw_seed);
    let billfold = wallet.billfold.clone();

    // 4. Set wallet state + sweep limbo.
    let mut s = state.lock().unwrap();
    s.wallet = Some(WalletState {
        stealth_secret: stealth_secret.clone(),
        billfold,
        wallet_path: wallet_path.clone(),
    });

    // Sweep existing limbo entries through the newly unlocked wallet.
    let all_sids: Vec<[u8; 32]> = s.limbo_buffer.stealth_ids_with_payments();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for sid in &all_sids {
        for entry in s.limbo_buffer.peek(sid) {
            payloads.push(entry.payment.stealth_payload.clone());
        }
    }
    if !payloads.is_empty() {
        let ws = s.wallet.as_mut().unwrap();
        let mut received = 0u64;
        let mut bill_count = 0usize;
        let mut pending_claims = Vec::new();
        for payload in &payloads {
            match receive_and_claim(&ws.stealth_secret, payload) {
                Ok(Some(result)) => {
                    for claimed in result.claimed {
                        received += claimed.bill.denomination.value();
                        bill_count += 1;
                        ws.billfold.deposit_with_credentials(
                            claimed.bill,
                            SpendCredential {
                                spend_vk: claimed.spend_vk,
                                spend_sk: claimed.spend_sk,
                            },
                        );
                    }
                    for claim in result.ownership_claims {
                        if let PulseMessage::OwnershipClaim(oc) = claim {
                            pending_claims.push(oc);
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }
        s.ownership_claim_queue.extend(pending_claims);
        if received > 0 {
            tracing::info!(amount = received, bills = bill_count, "swept limbo into wallet after unlock");
        }
    }

    let balance = s.wallet.as_ref().map(|w| w.billfold.balance()).unwrap_or(0);
    let bill_count = s.wallet.as_ref().map(|w| w.billfold.bills().len()).unwrap_or(0);

    RpcResponse::ok(RpcData::Balance { balance, bill_count })
}

fn handle_wallet_set_password(
    state: &Arc<Mutex<ArteryState>>,
    current_password: &str,
    new_password: &str,
) -> RpcResponse {
    let wallet_path = {
        let s = state.lock().unwrap();
        match &s.wallet {
            Some(ws) => ws.wallet_path.clone(),
            None => return RpcResponse::err("wallet not loaded — unlock first"),
        }
    };

    // Transiently decrypt raw_seed using the current password (outside lock).
    let mut wf = match vess_kloak::WalletFile::load(&wallet_path) {
        Ok(w) => w,
        Err(e) => return RpcResponse::err(format!("failed to load wallet file: {e}")),
    };
    let raw_seed = match wf.unlock_with_password(current_password) {
        Ok(s) => s,
        Err(e) => return RpcResponse::err(format!("current password incorrect: {e}")),
    };

    // Re-encrypt raw_seed under the new password.
    if let Err(e) = wf.set_password_cache(&raw_seed, new_password) {
        return RpcResponse::err(format!("failed to create password cache: {e}"));
    }
    if let Err(e) = wf.save(&wallet_path) {
        return RpcResponse::err(format!("failed to save wallet: {e}"));
    }

    RpcResponse::ok(RpcData::WalletStatus {
        locked: false,
        has_password: true,
    })
}

fn handle_wallet_lock(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let mut s = state.lock().unwrap();
    if s.wallet.is_none() {
        return RpcResponse::err("wallet already locked");
    }
    s.wallet = None;
    RpcResponse::ok(RpcData::WalletStatus {
        locked: true,
        has_password: false,
    })
}

/// Decode a hex string into a fixed-length byte array.
fn decode_hex_fixed<const N: usize>(hex_str: &str) -> Result<[u8; N], String> {
    let bytes = from_hex(hex_str)?;
    if bytes.len() != N {
        return Err(format!("expected {N} bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn handle_tag_register(
    state: &Arc<Mutex<ArteryState>>,
    tag: &str,
    scan_ek_hex: &str,
    spend_ek_hex: &str,
    pow_nonce_hex: &str,
    pow_hash_hex: &str,
    timestamp: u64,
    registrant_vk_hex: &str,
    signature_hex: &str,
) -> RpcResponse {
    let tag = match VessTag::new(tag) {
        Ok(t) => t,
        Err(e) => return RpcResponse::err(format!("invalid tag: {e}")),
    };
    let scan_ek = match from_hex(scan_ek_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid scan_ek_hex: {e}")),
    };
    let spend_ek = match from_hex(spend_ek_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid spend_ek_hex: {e}")),
    };
    let pow_nonce: [u8; 32] = match decode_hex_fixed(pow_nonce_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid pow_nonce_hex: {e}")),
    };
    let pow_hash = match from_hex(pow_hash_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid pow_hash_hex: {e}")),
    };
    let registrant_vk = match from_hex(registrant_vk_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid registrant_vk_hex: {e}")),
    };
    let signature = match from_hex(signature_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid signature_hex: {e}")),
    };

    let record = TagRecord {
        tag: tag.clone(),
        master_address: vess_stealth::MasterStealthAddress {
            scan_ek: scan_ek.clone(),
            spend_ek: spend_ek.clone(),
        },
        pow_nonce,
        pow_hash: pow_hash.clone(),
        registered_at: timestamp,
        registrant_vk: registrant_vk.clone(),
        signature: signature.clone(),
        hardened_at: None,
    };

    let mut s = state.lock().unwrap();

    // Check if tag is already registered.
    if s.tag_dht.lookup(tag.as_str()).is_some() {
        return RpcResponse::err(format!("tag {} is already registered", tag.display()));
    }

    // Store in local tag DHT.
    s.tag_dht.store(record);

    // Queue TagStore for gossip to other artery nodes.
    s.tag_store_queue.push(TagStore {
        tag: tag.as_str().to_owned(),
        scan_ek,
        spend_ek,
        pow_nonce,
        pow_hash,
        registered_at: timestamp,
        hops_remaining: 8,
        registrant_vk,
        signature,
    });

    RpcResponse::ok(RpcData::Empty {})
}

fn handle_tag_confirm(
    state: &Arc<Mutex<ArteryState>>,
    tag_str: &str,
    mint_id_hex: &str,
    registrant_vk_hex: &str,
    signature_hex: &str,
) -> RpcResponse {
    let tag_str = tag_str.strip_prefix('+').unwrap_or(tag_str);
    let mint_id: [u8; 32] = match decode_hex_fixed(mint_id_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid mint_id_hex: {e}")),
    };
    let registrant_vk = match from_hex(registrant_vk_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid registrant_vk_hex: {e}")),
    };
    let signature = match from_hex(signature_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid signature_hex: {e}")),
    };

    let mut s = state.lock().unwrap();

    // Validate tag exists and is unhardened.
    match s.tag_dht.lookup(tag_str) {
        None => return RpcResponse::err(format!("tag +{tag_str} not found")),
        Some(r) if r.hardened_at.is_some() => {
            return RpcResponse::err(format!("tag +{tag_str} is already hardened"));
        }
        _ => {}
    }

    // Harden the tag in local DHT.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    s.tag_dht.harden(tag_str, &mint_id, now);

    // Queue TagConfirm for gossip.
    s.tag_confirm_queue.push(vess_protocol::TagConfirm {
        tag: tag_str.to_owned(),
        mint_id,
        registrant_vk,
        signature,
        hops_remaining: 8,
    });

    RpcResponse::ok(RpcData::Empty {})
}

fn handle_ownership_genesis(
    state: &Arc<Mutex<ArteryState>>,
    mint_id_hex: &str,
    chain_tip_hex: &str,
    owner_vk_hash_hex: &str,
    owner_vk_hex: &str,
    denomination_value: u64,
    proof_hex: &str,
    digest_hex: &str,
) -> RpcResponse {
    let mint_id: [u8; 32] = match decode_hex_fixed(mint_id_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid mint_id_hex: {e}")),
    };
    let chain_tip: [u8; 32] = match decode_hex_fixed(chain_tip_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid chain_tip_hex: {e}")),
    };
    let owner_vk_hash: [u8; 32] = match decode_hex_fixed(owner_vk_hash_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid owner_vk_hash_hex: {e}")),
    };
    let owner_vk = match from_hex(owner_vk_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid owner_vk_hex: {e}")),
    };
    let proof = match from_hex(proof_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid proof_hex: {e}")),
    };
    let digest: [u8; 32] = match decode_hex_fixed(digest_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid digest_hex: {e}")),
    };

    let mut s = state.lock().unwrap();

    s.ownership_genesis_queue.push(vess_protocol::OwnershipGenesis {
        mint_id,
        chain_tip,
        owner_vk_hash,
        owner_vk,
        denomination_value,
        proof,
        digest,
        hops_remaining: 6,
        chain_depth: 0,
    });

    RpcResponse::ok(RpcData::Empty {})
}

fn handle_manifest_store(
    state: &Arc<Mutex<ArteryState>>,
    dht_key_hex: &str,
    encrypted_manifest_hex: &str,
) -> RpcResponse {
    let dht_key: [u8; 32] = match decode_hex_fixed(dht_key_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid dht_key_hex: {e}")),
    };
    let encrypted_manifest = match from_hex(encrypted_manifest_hex) {
        Ok(v) => v,
        Err(e) => return RpcResponse::err(format!("invalid encrypted_manifest_hex: {e}")),
    };

    let mut s = state.lock().unwrap();

    // Store locally.
    s.manifest_store.insert(dht_key, encrypted_manifest.clone());

    // Queue for gossip.
    s.manifest_store_queue.push(ManifestStore {
        dht_key,
        encrypted_manifest,
        hops_remaining: 6,
    });

    RpcResponse::ok(RpcData::Empty {})
}
