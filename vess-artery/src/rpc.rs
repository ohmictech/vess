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

use anyhow::{anyhow, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, warn};
use zeroize::Zeroizing;

use vess_compute::{ProgramManifest, StoredProgram};
use vess_foundry::reforge::{reforge, ReforgeRequest};
use vess_foundry::spend_auth::{generate_spend_keypair, vk_hash};
use vess_kloak::auto_reforge::ConsolidationScheduler;
use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::prepare_payment_from_bills;
use vess_kloak::selection::{decompose_amount, select_bills_filtered, SelectionResult};
use vess_mesh::MeshCarrierContact;
use vess_protocol::{
    ManifestStore, ProgramManifestStore, ProgramStore, PulseMessage, TagLookup, TagStore,
};
use vess_stealth::MasterStealthAddress;
use vess_tag::{TagRecord, VessTag};
use vess_vascular::MeshPulseNode;

use crate::gossip::k_nearest;
use crate::mesh_contact::{
    decode_contact_bytes, encode_contact_string, parse_contact_string, parse_node_id_hex,
};
use crate::node_runner::ArteryState;
use crate::node_runner::DeploymentProfile;
use crate::node_runner::WalletState;
use crate::persistence::hex_key;
use crate::tag_resolver::{TagResolution, TagResolver};

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn verified_peer_count(state: &Arc<Mutex<ArteryState>>) -> usize {
    let s = state.lock().unwrap();
    s.peer_registry
        .count_in_state(crate::handshake::PeerState::Verified)
}

fn select_spendable_bills(
    billfold: &vess_kloak::BillFold,
    amount: u64,
) -> anyhow::Result<SelectionResult> {
    let reserved = billfold.reserved_set();
    let mut spendable_indices = Vec::new();
    let mut spendable_bills = Vec::new();
    let mut spendable_total = 0u64;
    let mut watch_only_total = 0u64;

    for (index, bill) in billfold.bills().iter().enumerate() {
        if reserved.contains(&bill.mint_id) {
            continue;
        }

        let value = bill.denomination.value();
        if billfold.get_credentials(&bill.mint_id).is_some() {
            spendable_indices.push(index);
            spendable_bills.push(bill.clone());
            spendable_total += value;
        } else {
            watch_only_total += value;
        }
    }

    if spendable_total < amount {
        let mut message = format!("insufficient spendable funds: need {amount}, have {spendable_total}");
        if watch_only_total > 0 {
            message.push_str(&format!(
                " ({watch_only_total} Vess is present without spend credentials)"
            ));
        }
        return Err(anyhow!(message));
    }

    let mut selection = select_bills_filtered(&spendable_bills, amount, &[])?;
    selection.send_indices = selection
        .send_indices
        .iter()
        .map(|&i| spendable_indices[i])
        .collect();
    Ok(selection)
}

pub(crate) fn wallet_tag_store(
    wallet: &mut vess_kloak::WalletFile,
    wallet_path: &std::path::Path,
    enc_key: &[u8; 32],
) -> Result<Option<(String, TagStore)>> {
    use zeroize::Zeroizing;

    let Some(wallet_name) = wallet.name.clone() else {
        return Ok(None);
    };
    if wallet.tag_registrant_vk.is_empty() {
        return Ok(None);
    }

    let tag = VessTag::new(&wallet_name)?;
    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();

    let registration = if let Some(existing) = wallet.tag_registration.clone() {
        existing
    } else {
        let registrant_sk = Zeroizing::new(wallet.decrypt_tag_sk(enc_key)?);
        #[cfg(any(test, feature = "test-pow"))]
        let (pow_nonce, pow_hash) = vess_tag::compute_tag_pow_test(
            &tag_hash,
            &wallet.master_address.scan_ek,
            &wallet.master_address.spend_ek,
        )?;
        #[cfg(not(any(test, feature = "test-pow")))]
        let (pow_nonce, pow_hash) = vess_tag::compute_tag_pow(
            &tag_hash,
            &wallet.master_address.scan_ek,
            &wallet.master_address.spend_ek,
        )?;

        let registered_at = now_unix();
        let unsigned_record = TagRecord {
            tag_hash,
            master_address: wallet.master_address.clone(),
            pow_nonce,
            pow_hash: pow_hash.clone(),
            registered_at,
            registrant_vk: wallet.tag_registrant_vk.clone(),
            signature: Vec::new(),
            hardened_at: None,
        };
        let signature =
            vess_foundry::spend_auth::sign_spend(registrant_sk.as_slice(), &unsigned_record.digest())?;

        wallet.set_tag_registration(
            pow_nonce,
            pow_hash.clone(),
            registered_at,
            signature.clone(),
            enc_key,
        )?;
        wallet.save(wallet_path, enc_key)?;
        wallet
            .tag_registration
            .clone()
            .expect("tag registration metadata was just stored")
    };

    let record = TagRecord {
        tag_hash,
        master_address: wallet.master_address.clone(),
        pow_nonce: registration.pow_nonce,
        pow_hash: registration.pow_hash.clone(),
        registered_at: registration.registered_at,
        registrant_vk: wallet.tag_registrant_vk.clone(),
        signature: registration.signature.clone(),
        hardened_at: None,
    };
    if !vess_tag::verify_record_signature(&record).unwrap_or(false) {
        anyhow::bail!("wallet tag registration signature is invalid")
    }

    Ok(Some((
        tag.as_str().to_string(),
        TagStore {
            tag_hash,
            scan_ek: wallet.master_address.scan_ek.clone(),
            spend_ek: wallet.master_address.spend_ek.clone(),
            pow_nonce: registration.pow_nonce,
            pow_hash: registration.pow_hash,
            registered_at: registration.registered_at,
            hops_remaining: 8,
            registrant_vk: wallet.tag_registrant_vk.clone(),
            signature: registration.signature,
        },
    )))
}

/// Channel senders for gossip queues (shared with drain loops via mpsc).
#[derive(Clone)]
pub(crate) struct QueueSenders {
    pub manifest_tx: tokio::sync::mpsc::UnboundedSender<ManifestStore>,
    pub program_tx: tokio::sync::mpsc::UnboundedSender<ProgramStore>,
    pub program_manifest_tx: tokio::sync::mpsc::UnboundedSender<ProgramManifestStore>,
    pub tag_store_tx: tokio::sync::mpsc::UnboundedSender<TagStore>,
    pub tag_confirm_tx: tokio::sync::mpsc::UnboundedSender<vess_protocol::TagConfirm>,
    pub og_tx: tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipGenesis>,
    pub oc_tx: tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipClaim>,
    pub ra_tx: tokio::sync::mpsc::UnboundedSender<vess_protocol::ReforgeAttestation>,
    pub pay_tx: tokio::sync::mpsc::UnboundedSender<vess_protocol::Payment>,
}

/// Hex-encode an arbitrary byte slice.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string into bytes.
fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if !hex_str.len().is_multiple_of(2) {
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

fn local_test_faucet_digest(
    nonce: &[u8; 32],
    denomination_value: u64,
    owner_vk_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-local-test-faucet-digest-v0");
    h.update(nonce);
    h.update(&denomination_value.to_le_bytes());
    h.update(owner_vk_hash);
    *h.finalize().as_bytes()
}

fn resolve_target_contact_from_str(
    state: &Arc<Mutex<ArteryState>>,
    value: &str,
) -> Result<MeshCarrierContact, String> {
    if let Ok(contact) = parse_contact_string(value) {
        return Ok(contact);
    }

    let peer_id = parse_node_id_hex(value).ok_or_else(|| {
        "invalid node_id: expected serialized mesh contact or 64-char mesh node id".to_string()
    })?;

    let contact_bytes = {
        let s = state.lock().unwrap();
        s.routing_table
            .peer_id_bytes(&peer_id)
            .ok_or_else(|| format!("unknown node_id: {value}"))?
    };
    decode_contact_bytes(&contact_bytes).map_err(|e| format!("stored peer contact is invalid: {e}"))
}

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RpcRequest {
    Balance,
    NodeInfo,
    Notifications {
        #[serde(default)]
        max: Option<usize>,
        /// Optional: only return notifications matching this payment_id.
        #[serde(default)]
        payment_id: Option<String>,
    },
    Events {
        #[serde(default)]
        max: Option<usize>,
    },
    NodeHealth,
    TagLookup {
        tag: String,
    },
    Send {
        amount: u64,
        recipient: String,
        #[serde(default)]
        memo: Option<String>,
    },
    SendDirect {
        amount: u64,
        recipient: String,
        #[serde(alias = "node_id")]
        target: String,
        #[serde(default)]
        memo: Option<String>,
    },
    WalletUnlock {
        password: String,
        #[serde(default)]
        wallet_path: Option<String>,
    },
    WalletSetPassword {
        current_password: String,
        new_password: String,
    },
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
    LocalTestFaucet {
        amount: u64,
    },
    /// Enable test mode on a running node (unsafe_mode + faucet).
    SetTestMode,
    /// Set the deployment profile at runtime.
    SetProfile {
        profile: String,
    },
    ManifestStore {
        dht_key_hex: String,
        encrypted_manifest_hex: String,
    },
    ProgramDeploy {
        program: StoredProgram,
        #[serde(default)]
        manifest: Option<ProgramManifest>,
    },
    TagCacheList,
    TagCacheClear {
        /// Tag to remove (e.g. "alice" or "+alice"). Omit to clear all.
        #[serde(default)]
        tag: Option<String>,
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
        #[serde(skip_serializing_if = "Option::is_none")]
        watch_only_balance: Option<u64>,
    },
    NodeInfo {
        node_id: String,
        peer_count: usize,
        discovered_peer_count: usize,
        cached_peer_count: usize,
        verified_peer_count: usize,
        node_contact: String,
        estimated_network_size: usize,
        tag_count: usize,
        registry_count: usize,
        limbo_count: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        bitcoin_receive_address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        bitcoin_tracked_balance: Option<u64>,
        bitcoin_pending_burns: usize,
        bitcoin_connected_peers: usize,
        profile: String,
        profile_description: String,
        unsafe_mode: bool,
        test_faucet_enabled: bool,
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
    Notifications {
        notifications: Vec<crate::node_runner::WalletNotification>,
    },
    Events {
        events: Vec<crate::node_runner::NodeEvent>,
    },
    NodeHealth {
        node_id: String,
        peer_count: usize,
        verified_peer_count: usize,
        banished_peer_count: usize,
        discovered_peer_count: usize,
        cached_peer_count: usize,
        estimated_network_size: usize,
        tag_count: usize,
        registry_count: usize,
        limbo_payment_count: usize,
        reputation_high: usize,
        reputation_medium: usize,
        reputation_low: usize,
        wallet_state: String, // "no_wallet" | "locked" | "unlocked"
        wallet_balance: u64,
        wallet_watch_only: u64,
        bitcoin_peers: usize,
        bitcoin_pending_burns: usize,
        discovery_sources: Vec<String>,
        total_supply: u64,
    },
    WalletStatus {
        locked: bool,
        has_password: bool,
    },
    LocalTestFaucet {
        amount: u64,
        bill_count: usize,
        balance: u64,
    },
    TestModeEnabled {
        test_faucet_enabled: bool,
        unsafe_mode: bool,
    },
    ProfileInfo {
        profile: String,
        description: String,
        unsafe_mode: bool,
        test_faucet_enabled: bool,
        audit_warnings: Vec<String>,
    },
    ProgramDeploy {
        prog_id: String,
        name: String,
    },
    TagCacheList {
        entries: Vec<crate::tag_cache::TagCacheEntryView>,
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
///
/// `token` is a per-startup secret written to `{state_dir}/rpc-token` (mode 600
/// on Unix) and must be sent as the very first line on every new connection.
/// Connections that fail the token check are silently closed.
pub(crate) async fn run_rpc_server(
    port: u16,
    token: String,
    state: Arc<Mutex<ArteryState>>,
    senders: QueueSenders,
    node: MeshPulseNode,
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

        let st = state.clone();
        let snd = senders.clone();
        let nd = node.clone();
        let tok = token.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            // H2: First line must be the session token.
            // Reject silently to avoid oracle behaviour.
            match lines.next_line().await {
                Ok(Some(first)) if first.trim() == tok => {}
                _ => {
                    warn!(%peer_addr, "RPC client rejected: bad or missing auth token");
                    return;
                }
            }
            info!(%peer_addr, "RPC client authenticated");

            while let Ok(Some(line)) = lines.next_line().await {
                let resp = handle_request(&line, &st, &snd, &nd).await;
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

async fn handle_request(
    line: &str,
    state: &Arc<Mutex<ArteryState>>,
    senders: &QueueSenders,
    node: &MeshPulseNode,
) -> RpcResponse {
    let req: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return RpcResponse::err(format!("invalid request: {e}")),
    };

    match req {
        RpcRequest::Balance => handle_balance(state),
        RpcRequest::NodeInfo => handle_node_info(state, node),
        RpcRequest::Notifications { max, payment_id } => {
            handle_notifications(state, max.unwrap_or(64), payment_id.as_deref())
        }
        RpcRequest::Events { max } => handle_events(state, max.unwrap_or(64)),
        RpcRequest::NodeHealth => handle_node_health(state),
        RpcRequest::TagLookup { tag } => handle_tag_lookup(state, node, &tag).await,
        RpcRequest::Send {
            amount,
            recipient,
            memo,
        } => handle_send(state, node, amount, &recipient, memo, senders).await,
        RpcRequest::SendDirect {
            amount,
            recipient,
            target,
            memo,
        } => handle_send_direct(state, amount, &recipient, &target, memo, senders, node).await,
        RpcRequest::WalletUnlock {
            password,
            wallet_path,
        } => {
            handle_wallet_unlock(
                state,
                node,
                &password,
                wallet_path.as_deref(),
                &senders.oc_tx,
                &senders.tag_store_tx,
            )
            .await
        }
        RpcRequest::WalletSetPassword {
            current_password,
            new_password,
        } => handle_wallet_set_password(state, &current_password, &new_password),
        RpcRequest::WalletLock => handle_wallet_lock(state),
        RpcRequest::TagRegister {
            tag,
            scan_ek_hex,
            spend_ek_hex,
            pow_nonce_hex,
            pow_hash_hex,
            timestamp,
            registrant_vk_hex,
            signature_hex,
        } => handle_tag_register(
            state,
            &tag,
            &scan_ek_hex,
            &spend_ek_hex,
            &pow_nonce_hex,
            &pow_hash_hex,
            timestamp,
            &registrant_vk_hex,
            &signature_hex,
            &senders.tag_store_tx,
        ),
        RpcRequest::TagConfirm {
            tag,
            mint_id_hex,
            registrant_vk_hex,
            signature_hex,
        } => handle_tag_confirm(
            state,
            &tag,
            &mint_id_hex,
            &registrant_vk_hex,
            &signature_hex,
            &senders.tag_confirm_tx,
        ),
        RpcRequest::OwnershipGenesis {
            mint_id_hex,
            chain_tip_hex,
            owner_vk_hash_hex,
            owner_vk_hex,
            denomination_value,
            proof_hex,
            digest_hex,
        } => handle_ownership_genesis(
            state,
            &mint_id_hex,
            &chain_tip_hex,
            &owner_vk_hash_hex,
            &owner_vk_hex,
            denomination_value,
            &proof_hex,
            &digest_hex,
            &senders.og_tx,
        ),
        RpcRequest::LocalTestFaucet { amount } => {
            handle_local_test_faucet(state, amount, &senders.og_tx)
        }
        RpcRequest::SetTestMode => handle_set_test_mode(state),
        RpcRequest::SetProfile { profile } => handle_set_profile(state, &profile),
        RpcRequest::ManifestStore {
            dht_key_hex,
            encrypted_manifest_hex,
        } => handle_manifest_store(
            state,
            &dht_key_hex,
            &encrypted_manifest_hex,
            &senders.manifest_tx,
        ),
        RpcRequest::ProgramDeploy { program, manifest } => handle_program_deploy(
            state,
            program,
            manifest,
            &senders.program_tx,
            &senders.program_manifest_tx,
        ),
        RpcRequest::TagCacheList => handle_tag_cache_list(state),
        RpcRequest::TagCacheClear { tag } => handle_tag_cache_clear(state, tag.as_deref()),
    }
}

// ── Handlers ────────────────────────────────────────────────────────

fn handle_balance(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    match &s.wallet {
        Some(ws) => RpcResponse::ok(RpcData::Balance {
            // Report spendable balance; reserved and watch-only bills are excluded.
            balance: ws.billfold.spendable_balance(),
            bill_count: ws.billfold.bills().len(),
            watch_only_balance: Some(ws.billfold.watch_only_balance()),
        }),
        None => RpcResponse::err("wallet not loaded"),
    }
}

fn handle_node_info(state: &Arc<Mutex<ArteryState>>, node: &MeshPulseNode) -> RpcResponse {
    let s = state.lock().unwrap();
    let node_contact = match encode_contact_string(&node.contact()) {
        Ok(contact) => contact,
        Err(error) => {
            return RpcResponse::err(format!("failed to encode local mesh contact: {error}"))
        }
    };
    let peer_count = s.routing_table.peer_count();
    let discovered_peer_count = s
        .routing_table
        .all_peers()
        .iter()
        .filter(|peer| peer.last_seen > 0)
        .count();
    let cached_peer_count = peer_count.saturating_sub(discovered_peer_count);

    RpcResponse::ok(RpcData::NodeInfo {
        node_id: hex_key(&s.node_id),
        peer_count,
        discovered_peer_count,
        cached_peer_count,
        verified_peer_count: s
            .peer_registry
            .count_in_state(crate::handshake::PeerState::Verified),
        node_contact,
        estimated_network_size: s.estimated_network_size,
        tag_count: s.tag_dht.record_count(),
        registry_count: s.registry.len(),
        limbo_count: s.limbo_mint_ids.len(),
        bitcoin_receive_address: s
            .wallet
            .as_ref()
            .map(|wallet| wallet.bitcoin_receive_address.clone()),
        bitcoin_tracked_balance: s
            .wallet
            .as_ref()
            .map(|wallet| wallet.bitcoin_wallet.spendable_tracked_balance()),
        bitcoin_pending_burns: s
            .wallet
            .as_ref()
            .map(|wallet| wallet.bitcoin_wallet.pending_burn_count())
            .unwrap_or(0),
        bitcoin_connected_peers: s
            .bitcoin_client
            .as_ref()
            .map(|client| client.connected_peers())
            .unwrap_or(0),
        profile: s.profile.as_label().to_string(),
        profile_description: s.profile.describe().to_string(),
        unsafe_mode: s.unsafe_mode,
        test_faucet_enabled: s.test_faucet_enabled,
    })
}

fn handle_notifications(
    state: &Arc<Mutex<ArteryState>>,
    max: usize,
    payment_id: Option<&str>,
) -> RpcResponse {
    let mut s = state.lock().unwrap();
    let all = s.take_notifications(max);
    if let Some(pid) = payment_id {
        // Filter: only return matching notifications. Re-queue the rest.
        let (matching, rest): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|n| n.payment_id == pid);
        for n in rest {
            s.push_notification_raw(n);
        }
        RpcResponse::ok(RpcData::Notifications {
            notifications: matching,
        })
    } else {
        RpcResponse::ok(RpcData::Notifications {
            notifications: all,
        })
    }
}

fn handle_events(state: &Arc<Mutex<ArteryState>>, max: usize) -> RpcResponse {
    let mut s = state.lock().unwrap();
    RpcResponse::ok(RpcData::Events {
        events: s.take_events(max),
    })
}

fn handle_node_health(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();

    let peer_count = s.routing_table.peer_count();
    let verified_peer_count = s.peer_registry.count_in_state(crate::handshake::PeerState::Verified);
    let banished_count = s.banishment.count();

    let discovered_peer_count = s
        .routing_table
        .all_peers()
        .iter()
        .filter(|peer| peer.last_seen > 0)
        .count();
    let cached_peer_count = peer_count.saturating_sub(discovered_peer_count);

    // Rough reputation buckets from the reputation table.
    let (high, medium, low) = s.reputation.bucket_counts();

    let wallet_state = match &s.wallet {
        None => "no_wallet",
        Some(_) => "unlocked",
    };

    let wallet_balance = s
        .wallet
        .as_ref()
        .map(|ws| ws.billfold.spendable_balance())
        .unwrap_or(0);
    let wallet_watch_only = s
        .wallet
        .as_ref()
        .map(|ws| ws.billfold.watch_only_balance())
        .unwrap_or(0);

    let total_supply = s.registry.total_supply();

    // Report which discovery sources may have been active.
    let discovery_sources: Vec<String> = {
        let mut sources = Vec::new();
        if s.routing_table.peer_count() > 0 {
            sources.push("peers_present".to_string());
        }
        if s.bitcoin_client.is_some() {
            sources.push("bitcoin_seed".to_string());
        }
        sources
    };

    RpcResponse::ok(RpcData::NodeHealth {
        node_id: crate::persistence::hex_key(&s.node_id),
        peer_count,
        verified_peer_count,
        banished_peer_count: banished_count,
        discovered_peer_count,
        cached_peer_count,
        estimated_network_size: s.estimated_network_size,
        tag_count: s.tag_dht.record_count(),
        registry_count: s.registry.len(),
        limbo_payment_count: s.limbo_payment_ids.len(),
        reputation_high: high,
        reputation_medium: medium,
        reputation_low: low,
        wallet_state: wallet_state.to_string(),
        wallet_balance,
        wallet_watch_only,
        bitcoin_peers: s
            .bitcoin_client
            .as_ref()
            .map(|client| client.connected_peers())
            .unwrap_or(0),
        bitcoin_pending_burns: s
            .wallet
            .as_ref()
            .map(|ws| ws.bitcoin_wallet.pending_burn_count())
            .unwrap_or(0),
        discovery_sources,
        total_supply,
    })
}

/// Number of peers to query for a DHT tag lookup when the local shard
/// has no record.  We fan out to up to this many peers and run
/// `TagResolver` quorum verification over the responses.
const TAG_LOOKUP_FAN_OUT: usize = 9;

/// Timeout (milliseconds) for a single peer's `TagLookup` response.
const TAG_LOOKUP_TIMEOUT_MS: u64 = 4_000;

fn tag_lookup_result_address(result: &vess_protocol::TagLookupResult) -> MasterStealthAddress {
    MasterStealthAddress {
        scan_ek: result.scan_ek.clone(),
        spend_ek: result.spend_ek.clone(),
    }
}

fn tag_lookup_address_fingerprint(address: &MasterStealthAddress) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&address.scan_ek);
    hasher.update(&address.spend_ek);
    *hasher.finalize().as_bytes()
}

fn validate_tag_lookup_result(
    tag_hash: [u8; 32],
    result: &vess_protocol::TagLookupResult,
) -> Option<MasterStealthAddress> {
    if result.registrant_vk.is_empty() || result.signature.is_empty() {
        return None;
    }

    let address = tag_lookup_result_address(result);
    let record = TagRecord {
        tag_hash,
        master_address: address.clone(),
        pow_nonce: result.pow_nonce,
        pow_hash: result.pow_hash.clone(),
        registered_at: result.registered_at,
        registrant_vk: result.registrant_vk.clone(),
        signature: result.signature.clone(),
        hardened_at: None,
    };

    match vess_tag::verify_record_signature(&record) {
        Ok(true) => {}
        _ => return None,
    }

    #[cfg(any(test, feature = "test-pow"))]
    let pow_ok = vess_tag::verify_tag_pow_test(
        &tag_hash,
        &record.master_address.scan_ek,
        &record.master_address.spend_ek,
        &record.pow_nonce,
        &record.pow_hash,
    );
    #[cfg(not(any(test, feature = "test-pow")))]
    let pow_ok = vess_tag::verify_tag_pow(
        &tag_hash,
        &record.master_address.scan_ek,
        &record.master_address.spend_ek,
        &record.pow_nonce,
        &record.pow_hash,
    );

    match pow_ok {
        Ok(true) => Some(address),
        _ => None,
    }
}

/// Active DHT tag resolution.
///
/// Priority order:
/// 1. Local tag cache (fastest — no I/O).
/// 2. Local DHT shard (in-memory, no network).
/// 3. Fan out `TagLookup` pulses to the K-nearest routable peers and
///    verify the result with `TagResolver` (quorum ≥ 5 matching nodes).
///
/// Returns `Some(address)` when verified, `None` if the tag is unknown
/// across the network.
async fn resolve_tag(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    tag_str: &str,
) -> Option<MasterStealthAddress> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── 1. Local cache ───────────────────────────────────────────────
    {
        let mut s = state.lock().unwrap();
        if let Some(cached) = s.tag_cache.get(tag_str, now) {
            return Some(MasterStealthAddress {
                scan_ek: cached.scan_ek,
                spend_ek: cached.spend_ek,
            });
        }
    }

    // ── 2. Local DHT shard ──────────────────────────────────────────
    {
        let mut s = state.lock().unwrap();
        if let Some(record) = s.tag_dht.lookup(tag_str) {
            let addr = MasterStealthAddress {
                scan_ek: record.master_address.scan_ek.clone(),
                spend_ek: record.master_address.spend_ek.clone(),
            };
            s.tag_cache
                .insert(tag_str, addr.scan_ek.clone(), addr.spend_ek.clone(), now);
            return Some(addr);
        }
    }

    // ── 3. Active DHT query (privacy-preserving) ─────────────────────
    // Pick from the 2K nearest peers with random jitter rather than
    // deterministically selecting the exact K-nearest.  This prevents
    // an observer from predicting exactly which peers will be queried
    // for a given tag.
    let tag_hash: [u8; 32] = *blake3::hash(tag_str.as_bytes()).as_bytes();
    let nonce: [u8; 16] = rand::random();

    let targets: Vec<(MeshCarrierContact, [u8; 32])> = {
        use rand::seq::SliceRandom;
        let s = state.lock().unwrap();
        let peers = s.routing_table.routable_peers(|_| true);
        if peers.is_empty() {
            return None;
        }
        let peer_hashes: Vec<[u8; 32]> = peers.iter().map(|p| p.id_hash).collect();
        // Get 2K nearest, then randomly select K from them.
        let fan_2k = (TAG_LOOKUP_FAN_OUT * 2).min(peer_hashes.len());
        let mut nearest_indices = k_nearest(&tag_hash, &peer_hashes, fan_2k);
        let mut rng = rand::thread_rng();
        nearest_indices.shuffle(&mut rng);
        nearest_indices.truncate(TAG_LOOKUP_FAN_OUT.min(nearest_indices.len()));
        nearest_indices
            .into_iter()
            .filter_map(|i| {
                let p = &peers[i];
                let contact = decode_contact_bytes(&p.id_bytes).ok()?;
                Some((contact, p.id_hash))
            })
            .collect()
    };

    if targets.is_empty() {
        return None;
    }

    let required_confirmations = std::cmp::min(crate::QUORUM_THRESHOLD, targets.len()).max(1);

    // Send `TagLookup` concurrently to all selected peers.
    let lookup_msg = PulseMessage::TagLookup(TagLookup { tag_hash, nonce });

    let mut tasks = Vec::with_capacity(targets.len());
    for (contact, id_hash) in targets {
        let n = node.clone();
        let msg = lookup_msg.clone();
        tasks.push(tokio::spawn(async move {
            let resp = tokio::time::timeout(
                std::time::Duration::from_millis(TAG_LOOKUP_TIMEOUT_MS),
                n.send_message_with_response(&contact, &msg),
            )
            .await;
            (id_hash, resp)
        }));
    }

    let results = futures::future::join_all(tasks).await;

    // Collect responses and run quorum verification.
    let mut resolver = TagResolver::with_threshold(required_confirmations);
    let mut relaxed_candidate: Option<MasterStealthAddress> = None;
    let mut relaxed_fingerprint: Option<[u8; 32]> = None;
    let mut relaxed_conflict = false;
    for join_result in results {
        let Ok((id_hash, timeout_result)) = join_result else {
            continue;
        };
        let Ok(Ok(Some(PulseMessage::TagLookupResponse(tlr)))) = timeout_result else {
            continue;
        };
        // Ignore responses with wrong nonce (could be stale).
        if tlr.nonce != nonce {
            continue;
        }

        let validated_address = match &tlr.result {
            Some(result) => match validate_tag_lookup_result(tlr.tag_hash, result) {
                Some(address) => Some(address),
                None => continue,
            },
            None => None,
        };

        if let Some(address) = validated_address.clone() {
            let fingerprint = tag_lookup_address_fingerprint(&address);
            match relaxed_fingerprint {
                None => {
                    relaxed_fingerprint = Some(fingerprint);
                    relaxed_candidate = Some(address);
                }
                Some(existing) if existing != fingerprint => {
                    relaxed_conflict = true;
                }
                _ => {}
            }
        }

        match resolver.add_response(id_hash, &tlr) {
            TagResolution::Verified { address, .. } => {
                // Quorum reached — cache and return.
                let mut s = state.lock().unwrap();
                s.tag_cache.insert(
                    tag_str,
                    address.scan_ek.clone(),
                    address.spend_ek.clone(),
                    now,
                );
                return Some(address);
            }
            TagResolution::Conflict { .. } => {
                warn!(
                    tag = tag_str,
                    "tag lookup: conflicting records from network"
                );
                return None;
            }
            _ => {} // Pending or NotFound — keep collecting
        }
    }

    if !relaxed_conflict && resolver.response_count() < crate::QUORUM_THRESHOLD {
        if let Some(address) = relaxed_candidate {
            let mut s = state.lock().unwrap();
            s.tag_cache.insert(
                tag_str,
                address.scan_ek.clone(),
                address.spend_ek.clone(),
                now,
            );
            return Some(address);
        }
    }

    None
}

async fn handle_tag_lookup(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    tag: &str,
) -> RpcResponse {
    let tag_str = tag.strip_prefix('+').unwrap_or(tag);

    match resolve_tag(state, node, tag_str).await {
        Some(addr) => RpcResponse::ok(RpcData::TagLookup {
            found: true,
            tag: tag_str.to_owned(),
            scan_ek: Some(to_hex(&addr.scan_ek)),
            spend_ek: Some(to_hex(&addr.spend_ek)),
            hardened: None,
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

/// Opportunistic consolidation: while spend keys are already unlocked for a
/// payment, reforge small bills into larger denominations in the background.
///
/// Scans bills that are NOT being sent (`excluded`) and NOT already reserved,
/// finds groups whose combined value equals a valid denomination, and reforges
/// up to 2 groups (highest combined value first). Each consolidation is
/// completely independent of the payment — failures are silently skipped.
#[allow(dead_code)]
fn fire_opportunistic_consolidations(
    s: &mut ArteryState,
    cred_map: &HashMap<[u8; 32], SpendCredential>,
    excluded: &[[u8; 32]],
    senders: &QueueSenders,
) {
    let ws = match s.wallet.as_ref() {
        Some(w) => w,
        None => return,
    };

    // Bills eligible for consolidation: not being sent, not reserved, have known creds.
    let excluded_set: std::collections::HashSet<[u8; 32]> = excluded.iter().copied().collect();
    let available: Vec<vess_foundry::VessBill> = ws
        .billfold
        .bills()
        .iter()
        .filter(|b| {
            !excluded_set.contains(&b.mint_id)
                && !ws.billfold.is_reserved(&b.mint_id)
                && cred_map.contains_key(&b.mint_id)
        })
        .cloned()
        .collect();

    if available.len() < 2 {
        return;
    }

    let mut candidates = ConsolidationScheduler::new().scan(&available);
    if candidates.is_empty() {
        return;
    }

    // Largest target denomination first, cap at 2 to avoid network noise.
    candidates.sort_by(|a, b| {
        b.target_denomination
            .value()
            .cmp(&a.target_denomination.value())
    });
    candidates.truncate(2);

    for candidate in candidates {
        let input_bills: Vec<vess_foundry::VessBill> = candidate
            .indices
            .iter()
            .map(|&i| available[i].clone())
            .collect();

        if input_bills
            .iter()
            .any(|b| !cred_map.contains_key(&b.mint_id))
        {
            continue;
        }

        // M6: Generate a fresh random stealth_id for the consolidated output
        // rather than reusing the input bill's stealth_id.
        let output_stealth_id = {
            use rand::Rng;
            let mut id = [0u8; 32];
            rand::thread_rng().fill(&mut id);
            id
        };
        let result = match reforge(ReforgeRequest {
            inputs: input_bills.clone(),
            output_denominations: vec![candidate.target_denomination],
            output_stealth_ids: vec![output_stealth_id],
        }) {
            Ok(r) => r,
            Err(e) => {
                warn!("opportunistic consolidation: reforge error: {e}");
                continue;
            }
        };

        let (new_bill, proof_bytes) = result.outputs[0].clone();
        let (new_vk, new_sk) = generate_spend_keypair();
        let new_cred = SpendCredential {
            spend_vk: new_vk,
            spend_sk: new_sk,
        };

        // Build and sign ReforgeAttestation.
        let mut sorted_consumed = result.consumed_mint_ids.clone();
        sorted_consumed.sort();
        let reforge_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-reforge-id-v0");
            for mid in &sorted_consumed {
                h.update(mid);
            }
            *h.finalize().as_bytes()
        };

        let mut consume_sigs = Vec::<Vec<u8>>::new();
        let mut owner_vk_for_ra = Vec::<u8>::new();
        let mut sig_ok = true;
        for mid in &result.consumed_mint_ids {
            if let Some(cred) = cred_map.get(mid) {
                let digest = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"vess-reforge-consume-v0");
                    h.update(mid);
                    h.update(&reforge_id);
                    *h.finalize().as_bytes()
                };
                match vess_foundry::spend_auth::sign_spend(&cred.spend_sk, &digest) {
                    Ok(sig) => {
                        consume_sigs.push(sig);
                        if owner_vk_for_ra.is_empty() {
                            owner_vk_for_ra = cred.spend_vk.clone();
                        }
                    }
                    Err(e) => {
                        warn!("opportunistic consolidation: sign error: {e}");
                        sig_ok = false;
                        break;
                    }
                }
            } else {
                sig_ok = false;
                break;
            }
        }
        if !sig_ok || consume_sigs.len() != result.consumed_mint_ids.len() {
            warn!("opportunistic consolidation: incomplete signatures — skipping");
            continue;
        }

        crate::node_runner::queue_local_reforge_attestation(
            s,
            &senders.ra_tx,
            vess_protocol::ReforgeAttestation {
                consumed_mint_ids: result.consumed_mint_ids.clone(),
                owner_vk: owner_vk_for_ra,
                consume_sigs,
                reforge_id,
                output_mint_ids: vec![new_bill.mint_id],
                hops_remaining: 6,
            },
        );

        let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&new_cred.spend_vk);
        let chain_tip = vess_foundry::genesis_chain_tip(&new_bill.mint_id, &owner_vk_hash);
        crate::node_runner::queue_local_ownership_genesis(
            s,
            &senders.og_tx,
            vess_protocol::OwnershipGenesis {
                mint_id: new_bill.mint_id,
                chain_tip,
                owner_vk_hash,
                owner_vk: new_cred.spend_vk.clone(),
                program_owner: None,
                denomination_value: new_bill.denomination.value(),
                genesis_proof: vess_protocol::GenesisProof::Vess(proof_bytes),
                digest: new_bill.digest,
                hops_remaining: 6,
                chain_depth: 0,
                output_index: 0,
            ..Default::default()
            },
        );

        // Update billfold atomically.
        let ws_mut = s.wallet.as_mut().unwrap();
        for mid in &result.consumed_mint_ids {
            ws_mut.billfold.withdraw(mid);
        }
        ws_mut
            .billfold
            .deposit_with_credentials(new_bill.clone(), new_cred);

        info!(
            "opportunistic consolidation: {}×{} → {} (mint_id {:?})",
            input_bills.len(),
            input_bills[0].denomination.value(),
            new_bill.denomination.value(),
            &new_bill.mint_id[..4],
        );
    }
}

/// Attempt to deliver a payment directly to the recipient if they are a
/// known verified peer whose mesh contact is in the routing table.
/// Returns true if the delivery was acknowledged.
async fn try_direct_delivery(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    payment: &vess_protocol::Payment,
    _recipient_scan_ek: &[u8],
) -> bool {
    use crate::handshake::PeerState;

    // Find any verified peer that's not ourselves. On a 2-node network
    // this is always the correct recipient. On larger networks the
    // Payment handler will just relay if it's the wrong node.
    let target_contact = {
        let s = state.lock().unwrap();
        let routable = s.routing_table.routable_peers(|_| true);
        routable
            .iter()
            .find(|peer| {
                peer.id_hash != s.node_id
                    && s.peer_registry.state(&peer.id_hash) == PeerState::Verified
            })
            .and_then(|peer| decode_contact_bytes(&peer.id_bytes).ok())
    };

    let Some(target) = target_contact else {
        return false;
    };

    // Build the pulse message and send directly with a short timeout.
    let pulse_msg = PulseMessage::Payment(payment.clone());
    match tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        node.send_message_with_response(&target, &pulse_msg),
    )
    .await
    {
        Ok(Ok(Some(ack))) => {
            // Verify PaymentReceipt signature if present.
            if let PulseMessage::PaymentReceipt(ref pr) = ack {
                if pr.signature.is_empty() {
                    warn!("direct delivery: PaymentReceipt missing signature");
                    return false;
                }
                // Peer responded with a receipt — they decrypted and claimed it.
                // Full signature verification requires the recipient's owner_vk
                // from the ownership registry; that check is done in the payment
                // handler on the receiving side.
                info!("direct delivery: PaymentReceipt confirmed ({} Vess, {} bills)",
                    pr.total_amount, pr.claimed_mint_ids.len());
                // Push confirmation notification.
                {
                    let mut s = state.lock().unwrap();
                    s.push_notification(crate::node_runner::WalletNotification {
                        kind: "payment_receipt_confirmed".to_string(),
                        created_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        payment_id: hex_key(&pr.payment_id),
                        amount: Some(pr.total_amount),
                        bill_count: Some(pr.claimed_mint_ids.len()),
                        counterparty: None,
                        message: format!("Receipt: {} Vess received", pr.total_amount),
                    });
                }
            }
            info!("direct delivery: payment acknowledged by recipient");
            true
        }
        Ok(Ok(None)) => {
            info!("direct delivery: recipient accepted (no ack)");
            true
        }
        Ok(Err(e)) => {
            warn!("direct delivery: mesh send failed: {e}");
            false
        }
        Err(_timeout) => {
            warn!("direct delivery: timed out, falling back to gossip");
            false
        }
    }
}

async fn handle_send(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    amount: u64,
    recipient_tag: &str,
    memo: Option<String>,
    senders: &QueueSenders,
) -> RpcResponse {
    let tag_str = recipient_tag.strip_prefix('+').unwrap_or(recipient_tag);

    if verified_peer_count(state) == 0 {
        return RpcResponse::err(
            "send refused: verified peer count is 0; wait for peer discovery and handshake to complete",
        );
    }

    // ── Resolve tag (cache → local DHT → active DHT query) ──────────
    // Done outside the mutex so the async network query doesn't block
    // the state lock.
    let recipient_address = match resolve_tag(state, node, tag_str).await {
        Some(addr) => addr,
        None => return RpcResponse::err(format!("tag +{tag_str} not found")),
    };

    // ── Prepare payment inside a block so the mutex guard is dropped
    // before the async direct-delivery attempt.
    let (msg, payment_id, sent_mints, recipient_scan_ek) = {
        let mut s = state.lock().unwrap();

    // ── Require wallet ──────────────────────────────────────────────
    if s.wallet.is_none() {
        return RpcResponse::err("wallet not loaded");
    }

    // ── Build credential map ────────────────────────────────────────
    let ws = s.wallet.as_ref().unwrap();
    let cred_map = ws.billfold.export_credentials();

    // Validate memo length.
    if let Some(ref m) = memo {
        if m.len() > 256 {
            return RpcResponse::err("memo exceeds 256 byte limit");
        }
    }

    // ── Bill selection (excludes reserved / in-flight and watch-only bills) ────────
    let selection = match select_spendable_bills(&ws.billfold, amount) {
        Ok(sel) => sel,
        Err(e) => return RpcResponse::err(format!("bill selection failed: {e}")),
    };

    let (msg, payment_id, sent_mints) = if selection.change > 0 {
        // === CHANGE PATH: reforge ===
        let input_bills: Vec<vess_foundry::VessBill> = selection
            .send_indices
            .iter()
            .map(|&i| ws.billfold.bills()[i].clone())
            .collect();

        let send_denoms = decompose_amount(amount);
        let mut all_denoms = send_denoms.clone();
        all_denoms.extend(&selection.change_denominations);

        // M6: Generate a fresh random stealth_id per output bill.
        // Reusing input_bills[0].stealth_id would link outputs to the consumed
        // bill, leaking the reforge graph to any observer of the billfold.
        let stealth_ids: Vec<[u8; 32]> = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            (0..all_denoms.len())
                .map(|_| {
                    let mut id = [0u8; 32];
                    rng.fill(&mut id);
                    id
                })
                .collect()
        };

        let result = match reforge(ReforgeRequest {
            inputs: input_bills,
            output_denominations: all_denoms,
            output_stealth_ids: stealth_ids,
        }) {
            Ok(r) => r,
            Err(e) => return RpcResponse::err(format!("reforge failed: {e}")),
        };

        let send_count = send_denoms.len();
        let send_bills: Vec<vess_foundry::VessBill> = result.outputs[..send_count]
            .iter()
            .map(|(b, _)| b.clone())
            .collect();
        let change_bills: Vec<(vess_foundry::VessBill, Vec<u8>)> =
            result.outputs[send_count..].to_vec();

        let mut reforged_creds: HashMap<[u8; 32], SpendCredential> = HashMap::new();
        for (bill, _) in &result.outputs {
            let (vk, sk) = generate_spend_keypair();
            reforged_creds.insert(
                bill.mint_id,
                SpendCredential {
                    spend_vk: vk,
                    spend_sk: sk,
                },
            );
        }

        let (msg, pid) = match prepare_payment_from_bills(
            &send_bills,
            &recipient_address,
            &reforged_creds,
            memo.clone(),
        ) {
            Ok(v) => v,
            Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
        };

        let sent_mints: Vec<[u8; 32]> = send_bills.iter().map(|b| b.mint_id).collect();

        // ── Broadcast reforge to the network ────────────────────────
        // ReforgeAttestation: tell artery nodes to delete consumed mint_ids.
        let mut sorted_consumed = result.consumed_mint_ids.clone();
        sorted_consumed.sort();
        let reforge_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-reforge-id-v0");
            for mid in &sorted_consumed {
                h.update(mid);
            }
            *h.finalize().as_bytes()
        };

        // Sign each consumed mint_id to prove ownership.
        let mut consume_sigs = Vec::new();
        let mut owner_vk_for_ra = Vec::new();
        for mid in &result.consumed_mint_ids {
            if let Some(cred) = cred_map.get(mid) {
                let digest = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"vess-reforge-consume-v0");
                    h.update(mid);
                    h.update(&reforge_id);
                    *h.finalize().as_bytes()
                };
                if let Ok(sig) = vess_foundry::spend_auth::sign_spend(&cred.spend_sk, &digest) {
                    consume_sigs.push(sig);
                    if owner_vk_for_ra.is_empty() {
                        owner_vk_for_ra = cred.spend_vk.clone();
                    }
                }
            }
        }
        if consume_sigs.len() == result.consumed_mint_ids.len() {
            let output_mint_ids: Vec<[u8; 32]> =
                result.outputs.iter().map(|(b, _)| b.mint_id).collect();
            crate::node_runner::queue_local_reforge_attestation(
                &mut s,
                &senders.ra_tx,
                vess_protocol::ReforgeAttestation {
                    consumed_mint_ids: result.consumed_mint_ids.clone(),
                    owner_vk: owner_vk_for_ra,
                    consume_sigs,
                    reforge_id,
                    output_mint_ids,
                    hops_remaining: 6,
                },
            );
        }

        // OwnershipGenesis for each change bill (registers them in the DHT).
        for (j, (bill, proof_bytes)) in change_bills.iter().enumerate() {
            if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                // Compute correct genesis chain_tip (reforge outputs have [0;32] placeholder).
                let chain_tip = vess_foundry::genesis_chain_tip(&bill.mint_id, &owner_vk_hash);
                crate::node_runner::queue_local_ownership_genesis(
                    &mut s,
                    &senders.og_tx,
                    vess_protocol::OwnershipGenesis {
                        mint_id: bill.mint_id,
                        chain_tip,
                        owner_vk_hash,
                        owner_vk: cred.spend_vk.clone(),
                        program_owner: None,
                        denomination_value: bill.denomination.value(),
                        genesis_proof: vess_protocol::GenesisProof::Vess(proof_bytes.clone()),
                        digest: bill.digest,
                        hops_remaining: 6,
                        chain_depth: 0,
                        output_index: (send_count + j) as u32,
            ..Default::default()
                    },
                );
            }
        }

        // OwnershipGenesis for each SENT bill (so the recipient can claim it).
        for (i, bill) in send_bills.iter().enumerate() {
            if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                let proof_bytes = result.outputs[i].1.clone();
                let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                let chain_tip = vess_foundry::genesis_chain_tip(&bill.mint_id, &owner_vk_hash);
                crate::node_runner::queue_local_ownership_genesis(
                    &mut s,
                    &senders.og_tx,
                    vess_protocol::OwnershipGenesis {
                        mint_id: bill.mint_id,
                        chain_tip,
                        owner_vk_hash,
                        owner_vk: cred.spend_vk.clone(),
                        program_owner: None,
                        denomination_value: bill.denomination.value(),
                        genesis_proof: vess_protocol::GenesisProof::Vess(proof_bytes),
                        digest: bill.digest,
                        hops_remaining: 6,
                        chain_depth: 0,
                        output_index: i as u32,
            ..Default::default()
                    },
                );
            }
        }

        let ws_mut = s.wallet.as_mut().unwrap();

        // Withdraw consumed originals and deposit change bills.
        for mid in &result.consumed_mint_ids {
            ws_mut.billfold.withdraw(mid);
        }
        for (bill, _) in &change_bills {
            if let Some(cred) = reforged_creds.remove(&bill.mint_id) {
                ws_mut
                    .billfold
                    .deposit_with_credentials(bill.clone(), cred);
            }
        }

        // Reserve sent bills so they can't be accidentally re-spent.
        // They stay in a pending state until the recipient claims them
        // (at which point the OwnershipClaim handler removes them) or
        // until the limbo TTL expires (periodic release task).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        ws_mut.billfold.reserve(&sent_mints, now);

        (msg, pid, sent_mints)
    } else {
        // === EXACT MATCH PATH ===
        let send_bills: Vec<vess_foundry::VessBill> = selection
            .send_indices
            .iter()
            .map(|&i| ws.billfold.bills()[i].clone())
            .collect();
        let (msg, pid) = match prepare_payment_from_bills(
            &send_bills,
            &recipient_address,
            cred_map,
            memo.clone(),
        ) {
            Ok(v) => v,
            Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
        };

        let ws_mut = s.wallet.as_mut().unwrap();
        let mint_ids: Vec<[u8; 32]> = selection
            .send_indices
            .iter()
            .map(|&i| ws_mut.billfold.bills()[i].mint_id)
            .collect();

        // Reserve instead of withdraw — bills stay in the billfold
        // but are excluded from future selection until confirmed.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        ws_mut.billfold.reserve(&mint_ids, now);

        (msg, pid, mint_ids)
    };

    // ── Return values from the payment-prep block ───────────────────
    let scan_ek = recipient_address.scan_ek.clone();
    (msg, payment_id, sent_mints, scan_ek)
    }; // mutex guard dropped here

    // ── Relay: always gossip for reliability, direct for speed ──────
    // Gossip relay provides retry-and-forward with dedup protection.
    // Direct delivery is a best-effort speed boost for verified peers.
    // Both paths are used — the recipient's limbo_payment_ids deduplicates.
    let delivery_method = if let PulseMessage::Payment(ref payment) = msg {
        let direct_ok =
            try_direct_delivery(state, node, payment, &recipient_scan_ek).await;
        // Always queue for gossip relay regardless of direct outcome.
        let _ = senders.pay_tx.send(payment.clone());
        if direct_ok {
            "direct+gossip"
        } else {
            "gossip"
        }
    } else {
        "none"
    };

    let mut s = state.lock().unwrap();
    s.record_outbound_payment(payment_id, amount, recipient_tag.to_string(), &sent_mints);
    s.push_notification(crate::node_runner::WalletNotification {
        kind: "payment_sent".to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        payment_id: hex_key(&payment_id),
        amount: Some(amount),
        bill_count: Some(sent_mints.len()),
        counterparty: Some(recipient_tag.to_string()),
        message: format!(
            "Payment sent to {recipient_tag} via ({delivery_method})."
        ),
    });

    // Persist wallet immediately so bill withdrawals/reservations survive a crash.
    s.flush_wallet();

    // Report available balance (excludes reserved in-flight bills).
    let remaining = s
        .wallet
        .as_ref()
        .map(|w| w.billfold.available_balance())
        .unwrap_or(0);

    RpcResponse::ok(RpcData::Send {
        payment_id: hex_key(&payment_id),
        amount,
        remaining_balance: remaining,
    })
}

/// Direct peer-to-peer send: connect to a specific mesh contact and deliver
/// the payment with a 5-second timeout. No PoW handshake required — the
/// connection is ephemeral and drops after the response.
#[allow(clippy::too_many_arguments)]
async fn handle_send_direct(
    state: &Arc<Mutex<ArteryState>>,
    amount: u64,
    recipient_tag: &str,
    node_id_str: &str,
    memo: Option<String>,
    senders: &QueueSenders,
    node: &MeshPulseNode,
) -> RpcResponse {
    if verified_peer_count(state) == 0 {
        return RpcResponse::err(
            "send refused: verified peer count is 0; wait for peer discovery and handshake to complete",
        );
    }

    let target = match resolve_target_contact_from_str(state, node_id_str) {
        Ok(contact) => contact,
        Err(error) => return RpcResponse::err(error),
    };

    let tag_str = recipient_tag.strip_prefix('+').unwrap_or(recipient_tag);
    let direct_receipt_tag_hash = *blake3::hash(tag_str.as_bytes()).as_bytes();

    // ── Resolve tag (cache → local DHT → active DHT query) ──────────
    let recipient_address = match resolve_tag(state, node, tag_str).await {
        Some(addr) => addr,
        None => return RpcResponse::err(format!("tag +{tag_str} not found")),
    };

    let (mut msg, payment_id, sent_mints) = {
        let mut s = state.lock().unwrap();

        if s.wallet.is_none() {
            return RpcResponse::err("wallet not loaded");
        }

        let ws = s.wallet.as_ref().unwrap();
        let cred_map = ws.billfold.export_credentials();

        if let Some(ref m) = memo {
            if m.len() > 256 {
                return RpcResponse::err("memo exceeds 256 byte limit");
            }
        }

        let selection = match select_spendable_bills(&ws.billfold, amount) {
            Ok(sel) => sel,
            Err(e) => return RpcResponse::err(format!("bill selection failed: {e}")),
        };

        if selection.change > 0 {
            // === CHANGE PATH: reforge ===
            let input_bills: Vec<vess_foundry::VessBill> = selection
                .send_indices
                .iter()
                .map(|&i| ws.billfold.bills()[i].clone())
                .collect();

            let send_denoms = decompose_amount(amount);
            let mut all_denoms = send_denoms.clone();
            all_denoms.extend(&selection.change_denominations);

            // M6: Generate fresh random stealth_ids per output (same fix as handle_send).
            let stealth_ids: Vec<[u8; 32]> = {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                (0..all_denoms.len())
                    .map(|_| {
                        let mut id = [0u8; 32];
                        rng.fill(&mut id);
                        id
                    })
                    .collect()
            };

            let result = match reforge(ReforgeRequest {
                inputs: input_bills,
                output_denominations: all_denoms,
                output_stealth_ids: stealth_ids,
            }) {
                Ok(r) => r,
                Err(e) => return RpcResponse::err(format!("reforge failed: {e}")),
            };

            let send_count = send_denoms.len();
            let send_bills: Vec<vess_foundry::VessBill> = result.outputs[..send_count]
                .iter()
                .map(|(b, _)| b.clone())
                .collect();
            let change_bills: Vec<(vess_foundry::VessBill, Vec<u8>)> =
                result.outputs[send_count..].to_vec();

            let mut reforged_creds: HashMap<[u8; 32], SpendCredential> = HashMap::new();
            for (bill, _) in &result.outputs {
                let (vk, sk) = generate_spend_keypair();
                reforged_creds.insert(
                    bill.mint_id,
                    SpendCredential {
                        spend_vk: vk,
                        spend_sk: sk,
                    },
                );
            }

            let (msg, pid) = match prepare_payment_from_bills(
                &send_bills,
                &recipient_address,
                &reforged_creds,
                memo.clone(),
            ) {
                Ok(v) => v,
                Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
            };


            // Broadcast reforge attestation + ownership genesis.
            let mut sorted_consumed = result.consumed_mint_ids.clone();
            sorted_consumed.sort();
            let reforge_id = {
                let mut h = blake3::Hasher::new();
                h.update(b"vess-reforge-id-v0");
                for mid in &sorted_consumed {
                    h.update(mid);
                }
                *h.finalize().as_bytes()
            };

            let mut consume_sigs = Vec::new();
            let mut owner_vk_for_ra = Vec::new();
            for mid in &result.consumed_mint_ids {
                if let Some(cred) = cred_map.get(mid) {
                    let digest = {
                        let mut h = blake3::Hasher::new();
                        h.update(b"vess-reforge-consume-v0");
                        h.update(mid);
                        h.update(&reforge_id);
                        *h.finalize().as_bytes()
                    };
                    if let Ok(sig) = vess_foundry::spend_auth::sign_spend(&cred.spend_sk, &digest) {
                        consume_sigs.push(sig);
                        if owner_vk_for_ra.is_empty() {
                            owner_vk_for_ra = cred.spend_vk.clone();
                        }
                    }
                }
            }
            if consume_sigs.len() == result.consumed_mint_ids.len() {
                let output_mint_ids: Vec<[u8; 32]> =
                    result.outputs.iter().map(|(b, _)| b.mint_id).collect();
                crate::node_runner::queue_local_reforge_attestation(
                    &mut s,
                    &senders.ra_tx,
                    vess_protocol::ReforgeAttestation {
                        consumed_mint_ids: result.consumed_mint_ids.clone(),
                        owner_vk: owner_vk_for_ra,
                        consume_sigs,
                        reforge_id,
                        output_mint_ids,
                        hops_remaining: 6,
                    },
                );
            }

            for (j, (bill, proof_bytes)) in change_bills.iter().enumerate() {
                if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                    let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                    let chain_tip = vess_foundry::genesis_chain_tip(&bill.mint_id, &owner_vk_hash);
                    crate::node_runner::queue_local_ownership_genesis(
                        &mut s,
                        &senders.og_tx,
                        vess_protocol::OwnershipGenesis {
                            mint_id: bill.mint_id,
                            chain_tip,
                            owner_vk_hash,
                            owner_vk: cred.spend_vk.clone(),
                            program_owner: None,
                            denomination_value: bill.denomination.value(),
                            genesis_proof: vess_protocol::GenesisProof::Vess(proof_bytes.clone()),
                            digest: bill.digest,
                            hops_remaining: 6,
                            chain_depth: 0,
                            output_index: (send_count + j) as u32,
            ..Default::default()
                        },
                    );
                }
            }

            for (i, bill) in send_bills.iter().enumerate() {
                if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                    let proof_bytes = result.outputs[i].1.clone();
                    let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                    let chain_tip = vess_foundry::genesis_chain_tip(&bill.mint_id, &owner_vk_hash);
                    crate::node_runner::queue_local_ownership_genesis(
                        &mut s,
                        &senders.og_tx,
                        vess_protocol::OwnershipGenesis {
                            mint_id: bill.mint_id,
                            chain_tip,
                            owner_vk_hash,
                            owner_vk: cred.spend_vk.clone(),
                            program_owner: None,
                            denomination_value: bill.denomination.value(),
                            genesis_proof: vess_protocol::GenesisProof::Vess(proof_bytes),
                            digest: bill.digest,
                            hops_remaining: 6,
                            chain_depth: 0,
                            output_index: i as u32,
            ..Default::default()
                        },
                    );
                }
            }

            let sent_mints: Vec<[u8; 32]> = send_bills.iter().map(|bill| bill.mint_id).collect();
            let ws_mut = s.wallet.as_mut().unwrap();
            for mid in &result.consumed_mint_ids {
                ws_mut.billfold.withdraw(mid);
            }
            for (bill, _) in &change_bills {
                if let Some(cred) = reforged_creds.remove(&bill.mint_id) {
                    ws_mut
                        .billfold
                        .deposit_with_credentials(bill.clone(), cred);
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ws_mut.billfold.reserve(&sent_mints, now);
            s.flush_wallet();
            (msg, pid, sent_mints)
        } else {
            // === EXACT MATCH PATH ===
            let send_bills: Vec<vess_foundry::VessBill> = selection
                .send_indices
                .iter()
                .map(|&i| ws.billfold.bills()[i].clone())
                .collect();
            let (msg, pid) = match prepare_payment_from_bills(
                &send_bills,
                &recipient_address,
                &cred_map,
                memo.clone(),
            ) {
                Ok(v) => v,
                Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
            };

            let ws_mut = s.wallet.as_mut().unwrap();
            let mint_ids: Vec<[u8; 32]> = selection
                .send_indices
                .iter()
                .map(|&i| ws_mut.billfold.bills()[i].mint_id)
                .collect();

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ws_mut.billfold.reserve(&mint_ids, now);
            s.flush_wallet();

            (msg, pid, mint_ids)
        }
    };

    let recipient_stealth_id = match &mut msg {
        PulseMessage::Payment(payment) => {
            payment.direct_receipt_tag_hash = Some(direct_receipt_tag_hash);
            payment.stealth_id
        }
        PulseMessage::DirectPayment(payment) => payment.recipient_stealth_id,
        _ => return RpcResponse::err("internal error: direct send built a non-payment message"),
    };

    // Send directly to the target node with a 5-second timeout.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        node.send_message_with_response(&target, &msg),
    )
    .await;

    match result {
        Ok(Ok(Some(PulseMessage::DirectPaymentResponse(dpr)))) => {
            if dpr.accepted {
                if let Err(error) = verify_direct_payment_receipt(
                    dpr.receipt.as_ref(),
                    &payment_id,
                    &direct_receipt_tag_hash,
                    &recipient_stealth_id,
                    &sent_mints,
                    amount,
                ) {
                    let mut s = state.lock().unwrap();
                    if let Some(ref mut ws) = s.wallet {
                        ws.billfold.release(&sent_mints);
                        s.flush_wallet();
                    }
                    return RpcResponse::err(format!("invalid direct payment receipt: {error}"));
                }
                let mut s = state.lock().unwrap();
                if let Some(ref mut ws) = s.wallet {
                    for mid in &sent_mints {
                        ws.billfold.withdraw(mid);
                    }
                    s.flush_wallet();
                }
                let remaining = s
                    .wallet
                    .as_ref()
                    .map(|w| w.billfold.available_balance())
                    .unwrap_or(0);
                s.push_notification(crate::node_runner::WalletNotification {
                    kind: "payment_sent_confirmed".to_string(),
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    payment_id: hex_key(&payment_id),
                    amount: Some(amount),
                    bill_count: Some(sent_mints.len()),
                    counterparty: Some(recipient_tag.to_string()),
                    message: format!(
                        "Direct payment to {recipient_tag} was accepted by the recipient."
                    ),
                });
                RpcResponse::ok(RpcData::Send {
                    payment_id: hex_key(&payment_id),
                    amount,
                    remaining_balance: remaining,
                })
            } else {
                let mut s = state.lock().unwrap();
                if let Some(ref mut ws) = s.wallet {
                    ws.billfold.release(&sent_mints);
                    s.flush_wallet();
                }
                RpcResponse::err(format!("recipient rejected: {}", dpr.reason))
            }
        }
        Ok(Ok(_)) => {
            let mut s = state.lock().unwrap();
            if let Some(ref mut ws) = s.wallet {
                ws.billfold.release(&sent_mints);
                s.flush_wallet();
            }
            RpcResponse::err("unexpected response from recipient node")
        }
        Ok(Err(_e)) => {
            // D4: Direct delivery failed — fall back to relay delivery via the
            // payment gossip drain.  The payment will reach the recipient when
            // they come online and collect from limbo.
            if let PulseMessage::Payment(payment) = msg {
                let _ = senders.pay_tx.send(payment);
            }
            let mut s = state.lock().unwrap();
            if let Some(ref mut ws) = s.wallet {
                ws.billfold.release(&sent_mints);
                s.record_outbound_payment(payment_id, amount, recipient_tag.to_string(), &sent_mints);
                s.flush_wallet();
            }
            RpcResponse::ok(RpcData::Send {
                payment_id: hex_key(&payment_id),
                amount,
                remaining_balance: s
                    .wallet
                    .as_ref()
                    .map(|w| w.billfold.available_balance())
                    .unwrap_or(0),
            })
        }
        Err(_) => {
            // D4: Direct delivery timed out — fall back to relay delivery.
            if let PulseMessage::Payment(payment) = msg {
                let _ = senders.pay_tx.send(payment);
            }
            let mut s = state.lock().unwrap();
            if let Some(ref mut ws) = s.wallet {
                ws.billfold.release(&sent_mints);
                s.record_outbound_payment(payment_id, amount, recipient_tag.to_string(), &sent_mints);
                s.flush_wallet();
            }
            RpcResponse::ok(RpcData::Send {
                payment_id: hex_key(&payment_id),
                amount,
                remaining_balance: s
                    .wallet
                    .as_ref()
                    .map(|w| w.billfold.available_balance())
                    .unwrap_or(0),
            })
        }
    }
}

async fn handle_wallet_unlock(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    password: &str,
    wallet_path_override: Option<&str>,
    oc_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipClaim>,
    tag_store_tx: &tokio::sync::mpsc::UnboundedSender<TagStore>,
) -> RpcResponse {
    use vess_kloak::billfold::SpendCredential;
    use vess_kloak::payment::receive_and_claim;

    // 1. Get wallet_path from the request or node config.
    let wallet_path = {
        let s = state.lock().unwrap();
        if let Some(path) = wallet_path_override {
            std::path::PathBuf::from(path)
        } else if let Some(p) = &s.wallet_path {
            p.clone()
        } else {
            return RpcResponse::err("no wallet path provided");
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
    let mut wallet = match vess_kloak::WalletFile::load(&wallet_path) {
        Ok(w) => w,
        Err(e) => return RpcResponse::err(format!("failed to load wallet: {e}")),
    };
    let raw_seed = match wallet.unlock_with_password(password) {
        Ok(s) => Zeroizing::new(s),
        Err(e) => return RpcResponse::err(format!("{e}")),
    };

    // Derive stealth keys and encryption key from raw_seed.
    let (stealth_secret, address) = vess_stealth::generate_master_keys_from_seed(&raw_seed);
    let enc_key = vess_kloak::recovery::encryption_key_from_seed(&raw_seed);
    if let Err(e) = wallet.decrypt_private_metadata(&enc_key) {
        return RpcResponse::err(format!("failed to decrypt wallet metadata: {e}"));
    }
    let mailbox_key = vess_kloak::derive_mailbox_key(&address.spend_ek);
    let (bitcoin_wallet, bitcoin_receive_address) =
        match crate::node_runner::load_bitcoin_wallet_state(&wallet, &raw_seed, &enc_key) {
            Ok(state) => state,
            Err(e) => return RpcResponse::err(format!("failed to load bitcoin wallet state: {e}")),
        };

    // Load billfold and decrypt spend credentials into it.
    let mut billfold = wallet.billfold.clone();
    if let Err(e) = wallet.decrypt_spend_credentials_into(&mut billfold, &enc_key) {
        tracing::warn!(error = %e, "failed to decrypt spend credentials on unlock");
    }
    let wallet_tag_store = match wallet_tag_store(&mut wallet, &wallet_path, &enc_key) {
        Ok(store) => store,
        Err(error) => {
            tracing::warn!(%error, "failed to prepare wallet tag announcement on unlock");
            None
        }
    };

    // 4. Set wallet state + sweep limbo.
    let (balance, bill_count, watch_only_balance) = {
        let mut s = state.lock().unwrap();
        s.wallet_path = Some(wallet_path.clone());
        let spend_seed = vess_kloak::recovery::spend_seed_from_raw_seed(&raw_seed);
        s.wallet = Some(WalletState {
            stealth_secret,
            billfold,
            bitcoin_wallet,
            bitcoin_receive_address,
            wallet_path: wallet_path.clone(),
            enc_key,
            spend_seed: Some(spend_seed),
            mailbox_key,
        });

        if let Some((tag_str, tag_store)) = wallet_tag_store.clone() {
            let record = TagRecord {
                tag_hash: tag_store.tag_hash,
                master_address: MasterStealthAddress {
                    scan_ek: tag_store.scan_ek.clone(),
                    spend_ek: tag_store.spend_ek.clone(),
                },
                pow_nonce: tag_store.pow_nonce,
                pow_hash: tag_store.pow_hash.clone(),
                registered_at: tag_store.registered_at,
                registrant_vk: tag_store.registrant_vk.clone(),
                signature: tag_store.signature.clone(),
                hardened_at: None,
            };
            let addr_fp = record.address_fingerprint();

            if s.tag_dht.lookup(&tag_str).is_none() && !s.tag_dht.has_address(&addr_fp) {
                if s.tag_dht.store(record) {
                    let _ = tag_store_tx.send(tag_store);
                    s.push_notification(crate::node_runner::WalletNotification {
                        kind: "tag_announced".to_string(),
                        created_at: now_unix(),
                        payment_id: hex_key(&addr_fp),
                        amount: None,
                        bill_count: None,
                        counterparty: Some(format!("+{tag_str}")),
                        message: format!("Wallet tag +{tag_str} is available for sends."),
                    });
                }
            }
        }

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
            for claim in pending_claims {
                crate::node_runner::queue_local_ownership_claim(&mut s, oc_tx, claim);
            }
            if received > 0 {
                tracing::info!(
                    amount = received,
                    bills = bill_count,
                    "swept limbo into wallet after unlock"
                );
                // Persist swept bills immediately.
                s.flush_wallet();
            }
        }

        let balance = s
            .wallet
            .as_ref()
            .map(|w| w.billfold.spendable_balance())
            .unwrap_or(0);
        let bill_count = s
            .wallet
            .as_ref()
            .map(|w| w.billfold.bills().len())
            .unwrap_or(0);
        let watch_only_balance = s
            .wallet
            .as_ref()
            .map(|w| w.billfold.watch_only_balance());
        (balance, bill_count, watch_only_balance)
    };

    let response = RpcResponse::ok(RpcData::Balance {
        balance,
        bill_count,
        watch_only_balance,
    });

    crate::node_runner::refresh_mailbox_forward_subscriptions(node, state).await;

    response
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
        Ok(s) => Zeroizing::new(s),
        Err(e) => return RpcResponse::err(format!("current password incorrect: {e}")),
    };

    // Re-encrypt raw_seed under the new password.
    if let Err(e) = wf.set_password_cache(&raw_seed, new_password) {
        return RpcResponse::err(format!("failed to create password cache: {e}"));
    }
    let enc_key = vess_kloak::recovery::encryption_key_from_seed(&raw_seed);
    if let Err(e) = wf.save(&wallet_path, &enc_key) {
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

fn verify_direct_payment_receipt(
    receipt: Option<&vess_protocol::DirectPaymentReceipt>,
    payment_id: &[u8; 32],
    tag_hash: &[u8; 32],
    recipient_stealth_id: &[u8; 32],
    sent_mints: &[[u8; 32]],
    amount: u64,
) -> Result<(), String> {
    let receipt =
        receipt.ok_or_else(|| "recipient did not include a signed receipt".to_string())?;
    if &receipt.payment_id != payment_id {
        return Err("receipt payment_id mismatch".to_string());
    }
    if &receipt.tag_hash != tag_hash {
        return Err("receipt tag_hash mismatch".to_string());
    }
    if &receipt.recipient_stealth_id != recipient_stealth_id {
        return Err("receipt recipient stealth_id mismatch".to_string());
    }
    if receipt.total_amount != amount {
        return Err("receipt amount mismatch".to_string());
    }

    let mut expected_mints = sent_mints.to_vec();
    let mut receipt_mints = receipt.claimed_mint_ids.clone();
    expected_mints.sort_unstable();
    receipt_mints.sort_unstable();
    if receipt_mints != expected_mints {
        return Err("receipt mint set mismatch".to_string());
    }

    let digest = vess_foundry::spend_auth::direct_payment_receipt_message(
        payment_id,
        tag_hash,
        recipient_stealth_id,
        &receipt.claimed_mint_ids,
        receipt.total_amount,
    );
    match vess_foundry::spend_auth::verify_spend(
        &receipt.recipient_owner_vk,
        &digest,
        &receipt.signature,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err("receipt signature verification failed".to_string()),
        Err(error) => Err(format!("receipt signature error: {error}")),
    }
}

#[allow(clippy::too_many_arguments)]
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
    tag_store_tx: &tokio::sync::mpsc::UnboundedSender<TagStore>,
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

    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();
    let record = TagRecord {
        tag_hash,
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

    let addr_fp = record.address_fingerprint();
    if s.tag_dht.has_address(&addr_fp) {
        return RpcResponse::err(
            "this wallet address already has a different tag registered; use a different wallet to claim another tag"
                .to_string(),
        );
    }

    // Store in local tag DHT.
    if !s.tag_dht.store(record) {
        return RpcResponse::err(
            "tag registration was rejected by the local DHT state".to_string(),
        );
    }

    // Queue TagStore for gossip to other artery nodes.
    let _ = tag_store_tx.send(TagStore {
        tag_hash,
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
    tag_confirm_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::TagConfirm>,
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
    let tag_hash = *blake3::hash(tag_str.as_bytes()).as_bytes();
    let _ = tag_confirm_tx.send(vess_protocol::TagConfirm {
        tag_hash,
        mint_id,
        registrant_vk,
        signature,
        hops_remaining: 8,
    });

    RpcResponse::ok(RpcData::Empty {})
}

fn handle_set_test_mode(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let mut s = state.lock().unwrap();
    s.unsafe_mode = true;
    s.test_faucet_enabled = true;
    RpcResponse::ok(RpcData::TestModeEnabled {
        test_faucet_enabled: true,
        unsafe_mode: true,
    })
}

fn handle_set_profile(state: &Arc<Mutex<ArteryState>>, label: &str) -> RpcResponse {
    let profile = match label {
        "dev" => DeploymentProfile::Development,
        "test" => DeploymentProfile::Test,
        "staging" => DeploymentProfile::Staging,
        "prod" => DeploymentProfile::Production,
        other => {
            return RpcResponse::err(&format!(
                "unknown profile '{other}'; expected: dev, test, staging, prod"
            ));
        }
    };

    let mut s = state.lock().unwrap();
    s.profile = profile;
    s.unsafe_mode = profile.allow_unsafe();
    // Only auto-enable faucet for Development; Test keeps it off by default.
    s.test_faucet_enabled = matches!(profile, DeploymentProfile::Development);

    let warnings = s.audit();
    RpcResponse::ok(RpcData::ProfileInfo {
        profile: profile.as_label().to_string(),
        description: profile.describe().to_string(),
        unsafe_mode: s.unsafe_mode,
        test_faucet_enabled: s.test_faucet_enabled,
        audit_warnings: warnings,
    })
}

fn handle_local_test_faucet(
    state: &Arc<Mutex<ArteryState>>,
    amount: u64,
    og_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipGenesis>,
) -> RpcResponse {
    // Gate behind runtime test-faucet flag (set via `set_test_mode` RPC or env var).
    {
        let s = state.lock().unwrap();
        if !s.test_faucet_enabled {
            return RpcResponse::err(
                "local test faucet is disabled; run `vess test-mode` on the node, or set VESS_LOCAL_TEST_FAUCET=1 before starting"
            );
        }
        if !s.unsafe_mode {
            return RpcResponse::err(
                "local test faucet is not available in production mode; use --profile dev or test"
            );
        }
    }
    if amount == 0 {
        return RpcResponse::err("amount must be greater than zero");
    }

    let denominations = vess_foundry::mint::optimal_breakdown(amount);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut rng = rand::thread_rng();
    let mut genesis_records = Vec::with_capacity(denominations.len());

    let (bill_count, balance) = {
        let mut s = state.lock().unwrap();
        let (bill_count, balance) = {
            let Some(ws) = s.wallet.as_mut() else {
                return RpcResponse::err("wallet not loaded — unlock first");
            };

            for denomination in denominations {
                let (owner_vk, owner_sk) = generate_spend_keypair();
                let owner_vk_hash = vk_hash(&owner_vk);
                let mut nonce = [0u8; 32];
                rng.fill_bytes(&mut nonce);
                let digest = local_test_faucet_digest(&nonce, denomination.value(), &owner_vk_hash);
                let mint_id = vess_foundry::derive_mint_id(&digest, &nonce);
                let chain_tip = vess_foundry::genesis_chain_tip(&mint_id, &owner_vk_hash);
                let stealth_id = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"vess-local-test-faucet-stealth-v0");
                    h.update(&mint_id);
                    *h.finalize().as_bytes()
                };
                let bill = vess_foundry::VessBill {
                    denomination,
                    digest,
                    created_at: now,
                    stealth_id,
                    dht_index: 0,
                    mint_id,
                    chain_tip,
                    chain_depth: 0,
                };
                let cred = SpendCredential {
                    spend_vk: owner_vk.clone(),
                    spend_sk: owner_sk,
                };
                if ws.billfold.deposit_with_credentials(bill.clone(), cred) {
                    genesis_records.push(vess_protocol::OwnershipGenesis {
                        mint_id,
                        chain_tip,
                        owner_vk_hash,
                        owner_vk,
                        program_owner: None,
                        denomination_value: denomination.value(),
                        genesis_proof: vess_protocol::GenesisProof::LocalTestFaucet(
                            vess_protocol::LocalTestFaucetProof { nonce },
                        ),
                        digest,
                        hops_remaining: 6,
                        chain_depth: 0,
                        output_index: 0,
            ..Default::default()
                    });
                }
            }
            (genesis_records.len(), ws.billfold.available_balance())
        };

        s.push_notification(crate::node_runner::WalletNotification {
            kind: "local_test_faucet".to_string(),
            created_at: now,
            payment_id: String::new(),
            amount: Some(amount),
            bill_count: Some(genesis_records.len()),
            counterparty: None,
            message: format!("Local test faucet minted {amount} Vess."),
        });
        s.flush_wallet();
        (bill_count, balance)
    };

    {
        let mut s = state.lock().unwrap();
        for og in genesis_records {
            crate::node_runner::queue_local_ownership_genesis(&mut s, og_tx, og);
        }
    }

    RpcResponse::ok(RpcData::LocalTestFaucet {
        amount,
        bill_count,
        balance,
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_ownership_genesis(
    state: &Arc<Mutex<ArteryState>>,
    mint_id_hex: &str,
    chain_tip_hex: &str,
    owner_vk_hash_hex: &str,
    owner_vk_hex: &str,
    denomination_value: u64,
    proof_hex: &str,
    digest_hex: &str,
    og_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipGenesis>,
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
    crate::node_runner::queue_local_ownership_genesis(
        &mut s,
        og_tx,
        vess_protocol::OwnershipGenesis {
            mint_id,
            chain_tip,
            owner_vk_hash,
            owner_vk,
            program_owner: None,
            denomination_value,
            genesis_proof: vess_protocol::GenesisProof::Vess(proof),
            digest,
            hops_remaining: 6,
            chain_depth: 0,
            output_index: 0,
            ..Default::default()
        },
    );

    RpcResponse::ok(RpcData::Empty {})
}

fn handle_manifest_store(
    state: &Arc<Mutex<ArteryState>>,
    dht_key_hex: &str,
    encrypted_manifest_hex: &str,
    manifest_tx: &tokio::sync::mpsc::UnboundedSender<ManifestStore>,
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

    // Store locally (record current time for oldest-first eviction).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    s.manifest_store
        .insert(dht_key, (encrypted_manifest.clone(), now));

    // Queue for gossip.
    let _ = manifest_tx.send(ManifestStore {
        dht_key,
        encrypted_manifest,
        hops_remaining: 6,
    });

    RpcResponse::ok(RpcData::Empty {})
}

fn handle_program_deploy(
    state: &Arc<Mutex<ArteryState>>,
    program: StoredProgram,
    manifest: Option<ProgramManifest>,
    program_tx: &tokio::sync::mpsc::UnboundedSender<ProgramStore>,
    program_manifest_tx: &tokio::sync::mpsc::UnboundedSender<ProgramManifestStore>,
) -> RpcResponse {
    let prog_id = program.prog_id();
    let Some(manifest) = manifest else {
        return RpcResponse::err("program deploy requires a named program manifest");
    };
    if manifest.latest_prog_id != prog_id {
        return RpcResponse::err("program manifest latest_prog_id must match the deployed program");
    }
    if !manifest.versions.iter().any(|version| version.prog_id == prog_id) {
        return RpcResponse::err("program manifest versions must include the deployed program");
    }

    let name = manifest.name.to_string();
    let mut s = state.lock().unwrap();
    let stored_program = match s.compute_dht.store_program(program.clone()) {
        Ok(inserted) => inserted,
        Err(error) => return RpcResponse::err(format!("program deploy rejected: {error}")),
    };
    let stored_manifest = match s.compute_dht.store_manifest(manifest.clone()) {
        Ok(inserted) => inserted,
        Err(error) => return RpcResponse::err(format!("program manifest rejected: {error}")),
    };
    drop(s);

    if stored_program {
        let _ = program_tx.send(ProgramStore {
            program,
            hops_remaining: 8,
        });
    }
    if stored_manifest {
        let _ = program_manifest_tx.send(ProgramManifestStore {
            manifest,
            hops_remaining: 8,
        });
    }

    RpcResponse::ok(RpcData::ProgramDeploy {
        prog_id: hex_key(prog_id.as_bytes()),
        name,
    })
}

// ── Tag cache handlers ───────────────────────────────────────────────

fn handle_tag_cache_list(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    RpcResponse::ok(RpcData::TagCacheList {
        entries: s.tag_cache.to_views(),
    })
}

fn handle_tag_cache_clear(state: &Arc<Mutex<ArteryState>>, tag: Option<&str>) -> RpcResponse {
    let mut s = state.lock().unwrap();
    match tag {
        Some(t) => {
            let tag_str = t.strip_prefix('+').unwrap_or(t);
            let removed = s.tag_cache.remove(tag_str);
            if removed {
                RpcResponse::ok(RpcData::Empty {})
            } else {
                RpcResponse::err(format!("tag +{tag_str} not in cache"))
            }
        }
        None => {
            s.tag_cache.clear_all();
            RpcResponse::ok(RpcData::Empty {})
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bill(mint_byte: u8, denomination: vess_foundry::Denomination) -> vess_foundry::VessBill {
        vess_foundry::VessBill {
            denomination,
            digest: [mint_byte; 32],
            created_at: 0,
            stealth_id: [mint_byte.wrapping_add(1); 32],
            dht_index: mint_byte as u64,
            mint_id: [mint_byte; 32],
            chain_tip: [mint_byte.wrapping_add(2); 32],
            chain_depth: 0,
        }
    }

    #[test]
    fn select_spendable_bills_ignores_watch_only_entries() {
        let mut billfold = vess_kloak::BillFold::new();
        billfold.deposit(test_bill(1, vess_foundry::Denomination::D50));

        let credentialed = test_bill(2, vess_foundry::Denomination::D50);
        let (spend_vk, spend_sk) = vess_foundry::spend_auth::generate_spend_keypair();
        billfold.deposit_with_credentials(
            credentialed.clone(),
            vess_kloak::billfold::SpendCredential { spend_vk, spend_sk },
        );

        let selection = select_spendable_bills(&billfold, 50).unwrap();
        assert_eq!(selection.send_indices, vec![1]);
        assert_eq!(billfold.bills()[selection.send_indices[0]].mint_id, credentialed.mint_id);
    }

    #[test]
    fn select_spendable_bills_reports_watch_only_balance() {
        let mut billfold = vess_kloak::BillFold::new();
        billfold.deposit(test_bill(3, vess_foundry::Denomination::D50));

        let error = select_spendable_bills(&billfold, 50).unwrap_err().to_string();
        assert!(error.contains("insufficient spendable funds: need 50, have 0"));
        assert!(error.contains("50 Vess is present without spend credentials"));
    }

    #[test]
    fn wallet_tag_store_generates_and_persists_missing_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_path = dir.path().join("alice.wallet");
        let raw_seed = [7u8; 64];
        let enc_key = vess_kloak::recovery::encryption_key_from_seed(&raw_seed);
        let spend_seed = vess_kloak::recovery::spend_seed_from_raw_seed(&raw_seed);
        let (secret, address) = vess_stealth::generate_master_keys_from_seed(&raw_seed);
        let encrypted = vess_kloak::recovery::encrypt_secrets(&secret, &enc_key).unwrap();

        let mut wallet = vess_kloak::WalletFile::new(
            address,
            encrypted,
            vess_kloak::BillFold::new(),
            spend_seed,
            &enc_key,
        )
        .unwrap();
        wallet.name = Some("alice".to_string());
        let (registrant_vk, registrant_sk) = vess_foundry::spend_auth::generate_spend_keypair();
        wallet.tag_registrant_vk = registrant_vk;
        wallet.set_encrypted_tag_sk(&registrant_sk, &enc_key).unwrap();
        wallet.save(&wallet_path, &enc_key).unwrap();

        let built = wallet_tag_store(&mut wallet, &wallet_path, &enc_key)
            .unwrap()
            .expect("wallet tag store should be generated");

        assert_eq!(built.0, "alice");
        assert_eq!(built.1.tag_hash, *blake3::hash(b"alice").as_bytes());

        let mut reloaded = vess_kloak::WalletFile::load(&wallet_path).unwrap();
        reloaded.decrypt_private_metadata(&enc_key).unwrap();
        assert!(reloaded.tag_registration.is_some());
    }
}
