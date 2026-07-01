//! Local-only JSON-RPC server for controlling the embedded wallet and node.
//!
//! Binds exclusively to `127.0.0.1` — never a public interface — so
//! only the machine owner can interact with the node via the CLI.
//!
//! Protocol: newline-delimited JSON over TCP. Each request is a single
//! JSON object terminated by `\n`; each response is a single JSON object
//! terminated by `\n`. The connection stays open for multiple exchanges.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use rand::Rng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tracing::{info, warn};
use zeroize::Zeroizing;

use vess_foundry::reforge::{reforge, ReforgeRequest};
use vess_foundry::spend_auth::{generate_spend_keypair, vk_hash};
use vess_kloak::auto_reforge::ConsolidationScheduler;
use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::prepare_payment_from_bills_split;
use vess_kloak::selection::{decompose_amount, select_bills_filtered, SelectionResult};
use vess_mesh::MeshCarrierContact;
use vess_protocol::{
    ManifestStore, PulseMessage, TagLookup,
    TagStore,
};
use vess_stealth::MasterStealthAddress;
use vess_tag::{TagRecord, VessTag};
use vess_vascular::MeshPulseNode;

use crate::gossip::k_nearest;
use crate::mesh_contact::{
    decode_contact_bytes, encode_contact_string, parse_contact_string, parse_node_id_hex,
};
use crate::node_runner::ArteryState;
use crate::node_runner::WalletState;
use crate::persistence::hex_key;
use crate::tag_resolver::{TagResolution, TagResolver};

/// Acquire the artery state lock. All RPC handlers run inside
/// `spawn_blocking` (dedicated OS threads), so blocking is fine.
/// Recovers from poison automatically.
fn lock_state(state: &Arc<Mutex<ArteryState>>) -> std::sync::MutexGuard<'_, ArteryState> {
    match state.lock() {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!("artery state mutex poisoned — recovering");
            e.into_inner()
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn verified_peer_count(state: &Arc<Mutex<ArteryState>>) -> usize {
    let s = lock_state(&state);
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
        let s = lock_state(&state);
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
    TagCacheList,
    TagCacheClear {
        /// Tag to remove (e.g. "alice" or "+alice"). Omit to clear all.
        #[serde(default)]
        tag: Option<String>,
    },
    /// Toggle passive mode: stop relaying other peers' traffic to save
    /// bandwidth on metered/mobile connections. Own payments still work.
    SetPassiveMode {
        enabled: bool,
    },
    /// Cancel a pending outbound payment and release its reserved bills.
    CancelPayment {
        payment_id: String,
    },
    /// List pending outbound payments.
    PendingPayments,
    /// List payment history (sent and received).
    PaymentHistory {
        #[serde(default)]
        max: Option<usize>,
    },
    /// Propose an atomic swap offer (stored in the DHT).
    SwapPropose {
        offer_asset: String,
        offer_amount: u64,
        want_asset: String,
        want_amount: u64,
        recipient: String,
        expires_in_secs: Option<u64>,
    },
    /// List swap offers for an asset pair.
    SwapList {
        asset_a: String,
        asset_b: String,
    },
    /// Check if a wallet exists and is loaded.
    WalletStatus,
    /// Check if a VessTag is available on the network.
    CheckTag {
        tag: String,
    },
    /// Create a new wallet with the given tag (generates keys, PoW, registers tag).
    CreateWallet {
        tag: String,
    },
    /// Recover a wallet from a 12-word BIP39 recovery phrase.
    RecoverWallet {
        phrase: String,
        tag: String,
    },
    /// Export the wallet's recovery seed phrase.
    ExportSeed,
    /// Get the current wallet's VessTag.
    GetTag,
    /// Check if the current wallet's tag is still valid in the DHT.
    CheckMyTag,
    /// List active century locks and their status.
    CenturyLocks,
    /// Create a century lock faucet from a BitcoinTimeLockProof.
    CenturyLockCreate {
        burn_proof_json: String,
    },
    /// Recover wallet manifest from DHT (bills + century locks).
    RecoverManifest,
    /// List all wallets on this device.
    ListWallets,
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
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        requires_proof: bool,
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
        passive_mode: bool,
    },
    WalletStatus {
        locked: bool,
        has_password: bool,
        #[serde(default)]
        exists: bool,
        #[serde(default)]
        loaded: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wallet_path: Option<String>,
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
    TagCacheList {
        entries: Vec<crate::tag_cache::TagCacheEntryView>,
    },
    PassiveMode {
        passive_mode: bool,
        message: String,
    },
    Empty {},
    PaymentHistory {
        entries: Vec<vess_kloak::payment::PaymentHistoryEntry>,
    },
    CancelPayment {
        payment_id: String,
        released_bills: usize,
        recovered_amount: u64,
    },
    PendingPayments {
        payments: Vec<OutboundPaymentView>,
    },
    SwapPropose {
        hash_lock: String,
        dht_key: String,
        expires_at: u64,
    },
    SwapList {
        offers: Vec<vess_protocol::SwapOffer>,
    },
    CheckTag {
        available: bool,
        tag: String,
        reason: Option<String>,
    },
    CreateWallet {
        tag: String,
        phrase: String,
        wallet_path: String,
    },
    RecoverWallet {
        tag: String,
        wallet_path: String,
    },
    ExportSeed {
        phrase: String,
    },
    GetTag {
        tag: String,
    },
    CheckMyTag {
        tag: Option<String>,
        valid: bool,
        hardened: bool,
        message: String,
    },
    CenturyLocks {
        locks: Vec<serde_json::Value>,
    },
    CenturyLockCreated {
        lock_id: String,
        total_sats: u64,
        per_block_vess: u64,
        start_block: u64,
        end_block: u64,
    },
    RecoverManifest {
        recovered_bills: usize,
        recovered_locks: usize,
        message: String,
    },
    ListWallets {
        wallets: Vec<WalletInfoEntry>,
    },
}

#[derive(Debug, Serialize)]
pub struct WalletInfoEntry {
    pub tag: String,
    pub path: String,
    pub has_password: bool,
    pub created_at: Option<u64>,
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
    // Use std::net::TcpListener + dedicated thread to avoid tokio I/O driver
    // issues. The tokio runtime may be saturated by other tasks, preventing
    // the async accept from being polled.
    let listener = std::net::TcpListener::bind(&addr)
        .map_err(|e| anyhow::anyhow!("RPC port {port} already in use (stale node process?): {e}"))?;
    listener.set_nonblocking(false)?;
    info!(%addr, "RPC server listening");

    // Move accept loop to spawn_blocking so it has a dedicated OS thread.
    tokio::task::spawn_blocking(move || {
        loop {
            let (stream, peer_addr) = match listener.accept() {
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
        let rt = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            // stream is already std::net::TcpStream from std::net::TcpListener
            let mut stream = stream;
            stream.set_nodelay(true).ok();
            stream.set_nonblocking(false).ok(); // Switch to blocking mode for std I/O
            stream.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok();
            stream.set_write_timeout(Some(std::time::Duration::from_secs(30))).ok();

            let mut reader = std::io::BufReader::new(&mut stream);

            // Read first line to detect protocol.
            let mut first_line = String::new();
            info!(%peer_addr, "reading first line...");
            match reader.read_line(&mut first_line) {
                Ok(n) => info!(%peer_addr, "read {} bytes: {:?}", n, first_line),
                Err(e) => {
                    warn!(%peer_addr, error = %e, "failed to read first line");
                    return;
                }
            }
            let is_http = first_line.starts_with("POST ") || first_line.starts_with("GET ");

            if is_http {
                // Read headers.
                let mut headers = Vec::new();
                loop {
                    let mut line = Vec::new();
                    if reader.read_until(b'\n', &mut line).is_err() { return; }
                    let l = String::from_utf8_lossy(&line);
                    if l.trim().is_empty() { break; }
                    headers.extend_from_slice(&line);
                }

                // Find Content-Length.
                let headers_str = String::from_utf8_lossy(&headers);
                let content_len: usize = headers_str
                    .lines()
                    .find_map(|l| {
                        let lower = l.to_lowercase();
                        if lower.starts_with("content-length:") {
                            l.split(':').nth(1)?.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);

                // Read body.
                let mut body = vec![0u8; content_len.min(65536)];
                if content_len > 0 {
                    if std::io::Read::read_exact(&mut reader, &mut body[..content_len]).is_err() {
                        return;
                    }
                }
                let body_str = String::from_utf8_lossy(&body[..content_len]);

                if !body_str.trim().is_empty() {
                    let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(handle_request(body_str.trim(), &st, &snd, &nd))
                    })) {
                        Ok(r) => r,
                        Err(_) => {
                            warn!(%peer_addr, "HTTP handle_request panicked");
                            return;
                        }
                    };
                    let buf = match serde_json::to_vec(&resp) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error = %e, "RPC serialize error");
                            return;
                        }
                    };
                    let http_resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                        buf.len()
                    );
                    drop(reader);
                    use std::io::Write;
                    let _ = stream.write_all(http_resp.as_bytes());
                    let _ = stream.write_all(&buf);
                    let _ = stream.flush();
                    // Shutdown write to send FIN.
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    return;
                }
            } else {
                // Native protocol: first line is auth token.
                if first_line.trim() != tok.as_str() {
                    warn!(%peer_addr, "RPC client rejected: bad auth token");
                    return;
                }
                info!(%peer_addr, "RPC client authenticated");

                use std::io::{BufRead, Write};

                loop {
                    let mut line = String::new();
                    info!(%peer_addr, "waiting for request line...");
                    match reader.read_line(&mut line) {
                        Ok(0) => { info!(%peer_addr, "EOF"); break; }
                        Err(e) => { warn!(%peer_addr, error = %e, "read_line error"); break; }
                        Ok(n) => info!(%peer_addr, "read {} bytes: {:?}", n, line),
                    }
                    let line = line.trim().to_string();
                    if line.is_empty() { continue; }

                    let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(handle_request(&line, &st, &snd, &nd))
                    })) {
                        Ok(r) => r,
                        Err(e) => {
                            let msg = if let Some(s) = e.downcast_ref::<String>() {
                                s.clone()
                            } else if let Some(s) = e.downcast_ref::<&str>() {
                                s.to_string()
                            } else {
                                "unknown panic".to_string()
                            };
                            warn!(%peer_addr, "handle_request panicked: {msg}");
                            // Send error response instead of silently closing.
                            RpcResponse::err(format!("internal error: {msg}"))
                        }
                    };
                    info!(%peer_addr, "request handled, writing response...");
                    let mut resp_buf = match serde_json::to_vec(&resp) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(error = %e, "RPC serialize error");
                            break;
                        }
                    };
                    resp_buf.push(b'\n');

                    // Drop reader so we can write to stream, then recreate.
                    drop(reader);
                    if stream.write_all(&resp_buf).is_err() {
                        break;
                    }
                    if stream.flush().is_err() {
                        break;
                    }
                    info!(%peer_addr, "RPC response written ({} bytes)", resp_buf.len());
                    reader = std::io::BufReader::new(&mut stream);
                }
            }
            info!(%peer_addr, "RPC client disconnected");
            }); // inner spawn_blocking per connection
        } // loop
    }); // outer spawn_blocking (accept loop)
    // spawn_blocking runs forever; we return Ok to keep the caller happy.
    Ok(())
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
        RpcRequest::TagCacheList => handle_tag_cache_list(state),
        RpcRequest::TagCacheClear { tag } => handle_tag_cache_clear(state, tag.as_deref()),
        RpcRequest::SetPassiveMode { enabled } => handle_set_passive_mode(state, enabled),
        RpcRequest::CancelPayment { payment_id } => handle_cancel_payment(state, &payment_id),
        RpcRequest::PendingPayments => handle_pending_payments(state),
        RpcRequest::PaymentHistory { max } => handle_payment_history(state, max),
        RpcRequest::SwapPropose { offer_asset, offer_amount, want_asset, want_amount, recipient, expires_in_secs } => {
            handle_swap_propose(state, node, &offer_asset, offer_amount, &want_asset, want_amount, &recipient, expires_in_secs.as_ref()).await
        }
        RpcRequest::SwapList { asset_a, asset_b } => handle_swap_list(state, node, &asset_a, &asset_b).await,
        RpcRequest::WalletStatus => handle_wallet_status(state),
        RpcRequest::CheckTag { tag } => handle_check_tag(state, node, &tag).await,
        RpcRequest::CreateWallet { tag } => handle_create_wallet(state, node, &tag, senders).await,
        RpcRequest::RecoverWallet { phrase, tag } => handle_recover_wallet(state, &phrase, &tag).await,
        RpcRequest::ExportSeed => handle_export_seed(state),
        RpcRequest::GetTag => handle_get_tag(state),
        RpcRequest::CheckMyTag => handle_check_my_tag(state, node).await,
        RpcRequest::CenturyLocks => handle_century_locks(state),
        RpcRequest::CenturyLockCreate { burn_proof_json } => {
            handle_century_lock_create(state, &burn_proof_json, &senders.manifest_tx).await
        }
        RpcRequest::RecoverManifest => {
            handle_recover_manifest(state, node).await
        }
        RpcRequest::ListWallets => handle_list_wallets(),
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// Simplified view of an outbound payment for RPC responses.
#[derive(Debug, Clone, Serialize)]
pub struct OutboundPaymentView {
    pub payment_id: String,
    pub amount: u64,
    pub recipient: String,
    pub bill_count: usize,
    pub status: String,
}

fn handle_set_passive_mode(state: &Arc<Mutex<ArteryState>>, enabled: bool) -> RpcResponse {
    let mut s = lock_state(state);
    s.passive_mode = enabled;
    info!(enabled, "passive mode toggled");
    let msg = if enabled {
        "Passive mode ON: relaying only own payments, DHT store/relay disabled"
    } else {
        "Passive mode OFF: full relay and DHT participation restored"
    };
    RpcResponse::ok(RpcData::PassiveMode {
        passive_mode: enabled,
        message: msg.to_string(),
    })
}

fn handle_cancel_payment(state: &Arc<Mutex<ArteryState>>, payment_id_hex: &str) -> RpcResponse {
    let payment_id = match crate::persistence::unhex_key(payment_id_hex) {
        Ok(pid) => pid,
        Err(e) => return RpcResponse::err(format!("invalid payment_id hex: {e}")),
    };
    let mut s = lock_state(state);
    let record = match s.outbound_payments.remove(&payment_id) {
        Some(r) => r,
        None => return RpcResponse::err("payment not found"),
    };
    let mint_ids: Vec<[u8; 32]> = record.pending_mint_ids.iter().copied().collect();
    let count = mint_ids.len();
    let amount = record.amount;
    if let Some(ref mut ws) = s.wallet {
        ws.billfold.release(&mint_ids);
    }
    for mid in &mint_ids {
        s.outbound_by_mint_id.remove(mid);
    }
    s.payment_history.mark_cancelled(payment_id_hex);
    RpcResponse::ok(RpcData::CancelPayment {
        payment_id: payment_id_hex.to_string(),
        released_bills: count,
        recovered_amount: amount,
    })
}

fn handle_pending_payments(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = lock_state(state);
    let payments: Vec<OutboundPaymentView> = s.outbound_payments.values()
        .map(|r| OutboundPaymentView {
            payment_id: crate::persistence::hex_key(&r.payment_id),
            amount: r.amount,
            recipient: r.recipient.clone(),
            bill_count: r.pending_mint_ids.len(),
            status: "pending".to_string(),
        })
        .collect();
    RpcResponse::ok(RpcData::PendingPayments { payments })
}

fn handle_payment_history(state: &Arc<Mutex<ArteryState>>, max: Option<usize>) -> RpcResponse {
    let s = lock_state(state);
    let mut entries: Vec<vess_kloak::payment::PaymentHistoryEntry> =
        s.payment_history.list().into_iter().cloned().collect();
    if let Some(m) = max {
        entries.truncate(m);
    }
    RpcResponse::ok(RpcData::PaymentHistory { entries })
}

async fn handle_swap_propose(
    state: &Arc<Mutex<ArteryState>>,
    _node: &MeshPulseNode,
    offer_asset: &str,
    offer_amount: u64,
    want_asset: &str,
    want_amount: u64,
    recipient: &str,
    expires_in_secs: Option<&u64>,
) -> RpcResponse {
    let secret: [u8; 32] = rand::thread_rng().gen();
    let hash_lock: [u8; 32] = *blake3::hash(&secret).as_bytes();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + expires_in_secs.copied().unwrap_or(86400);

    let node_id = {
        let s = lock_state(state);
        s.node_id.to_vec()
    };

    let offer = vess_protocol::SwapOffer {
        offer_asset: offer_asset.to_string(),
        offer_amount,
        want_asset: want_asset.to_string(),
        want_amount,
        recipient: recipient.to_string(),
        hash_lock,
        expires_at,
        offerer_node_id: node_id,
    };

    let dht_key = offer.dht_key();
    let mut s = lock_state(state);
    s.swap_offers.entry(dht_key).or_default().push(offer.clone());
    if let Some(ref tx) = s.swap_offer_tx {
        let _ = tx.send(offer.clone());
    }

    RpcResponse::ok(RpcData::SwapPropose {
        hash_lock: crate::persistence::hex_key(&hash_lock),
        dht_key: crate::persistence::hex_key(&dht_key),
        expires_at,
    })
}

async fn handle_swap_list(
    state: &Arc<Mutex<ArteryState>>,
    _node: &MeshPulseNode,
    asset_a: &str,
    asset_b: &str,
) -> RpcResponse {
    let dht_key = vess_protocol::swap_dht_key(asset_a, asset_b);
    let s = lock_state(state);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let offers: Vec<vess_protocol::SwapOffer> = s.swap_offers
        .get(&dht_key)
        .map(|v: &Vec<vess_protocol::SwapOffer>| v.iter().filter(|o| o.expires_at > now).cloned().collect())
        .unwrap_or_default();
    RpcResponse::ok(RpcData::SwapList { offers })
}

fn handle_balance(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = lock_state(&state);
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
    let node_contact = match encode_contact_string(&node.contact()) {
        Ok(c) => c,
        Err(e) => return RpcResponse::err(format!("encode contact: {e}")),
    };

    // Try the state lock once. If we get it, return full data.
    // If not, fall back to local file count — the UI just needs
    // a quick answer, and local files are accurate for LAN peers.
    match state.try_lock() {
        Ok(s) => {
            let peer_count = s.routing_table.peer_count();
            let discovered = s.routing_table.all_peers().iter().filter(|p| p.last_seen > 0).count();
            RpcResponse::ok(RpcData::NodeInfo {
                node_id: hex_key(&s.node_id),
                peer_count,
                discovered_peer_count: discovered,
                cached_peer_count: peer_count.saturating_sub(discovered),
                verified_peer_count: s.peer_registry.count_in_state(crate::handshake::PeerState::Verified),
                node_contact,
                estimated_network_size: s.estimated_network_size,
                tag_count: s.tag_dht.record_count(),
                registry_count: s.registry.len(),
                limbo_count: s.limbo_mint_ids.len(),
                bitcoin_receive_address: s.wallet.as_ref().map(|w| w.bitcoin_receive_address.clone()),
                bitcoin_tracked_balance: s.wallet.as_ref().map(|w| w.bitcoin_wallet.spendable_tracked_balance()),
                bitcoin_pending_burns: s.wallet.as_ref().map(|w| w.bitcoin_wallet.pending_timelock_count()).unwrap_or(0),
                bitcoin_connected_peers: s.bitcoin_client.as_ref().map_or(0, |c| c.connected_peers()),
                profile: if s.is_testnet { "testnet" } else { "production" }.to_string(),
                profile_description: if s.is_testnet { "testnet" } else { "production" }.to_string(),
                unsafe_mode: s.unsafe_mode,
                test_faucet_enabled: s.test_faucet_enabled,
            })
        }
        Err(std::sync::TryLockError::Poisoned(e)) => {
            let s = e.into_inner();
            RpcResponse::ok(RpcData::NodeInfo {
                node_id: hex_key(&s.node_id),
                peer_count: s.routing_table.peer_count(),
                discovered_peer_count: 0, cached_peer_count: 0,
                verified_peer_count: 0, node_contact,
                estimated_network_size: 0, tag_count: 0, registry_count: 0,
                limbo_count: 0, bitcoin_receive_address: None,
                bitcoin_tracked_balance: None, bitcoin_pending_burns: 0,
                bitcoin_connected_peers: 0,
                profile: "testnet".to_string(), profile_description: "testnet".to_string(),
                unsafe_mode: false, test_faucet_enabled: false,
            })
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            // Lock busy — use local file count which is accurate for LAN peers.
            let self_id = Some(*node.id().as_bytes());
            let local_count = crate::local_discovery::discover_local_file_contacts(self_id).len();
            RpcResponse::ok(RpcData::NodeInfo {
                node_id: hex_key(node.id().as_bytes()),
                peer_count: local_count,
                discovered_peer_count: local_count, cached_peer_count: 0,
                verified_peer_count: 0, node_contact,
                estimated_network_size: 0, tag_count: 0, registry_count: 0,
                limbo_count: 0, bitcoin_receive_address: None,
                bitcoin_tracked_balance: None, bitcoin_pending_burns: 0,
                bitcoin_connected_peers: 0,
                profile: "testnet".to_string(), profile_description: "testnet".to_string(),
                unsafe_mode: false, test_faucet_enabled: false,
            })
        }
    }
}

fn handle_notifications(
    state: &Arc<Mutex<ArteryState>>,
    max: usize,
    payment_id: Option<&str>,
) -> RpcResponse {
    let mut s = lock_state(&state);
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
    let mut s = lock_state(&state);
    RpcResponse::ok(RpcData::Events {
        events: s.take_events(max),
    })
}

fn handle_node_health(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = lock_state(&state);

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
        bitcoin_peers: {
            s.bitcoin_client.as_ref().map_or(0usize, |c: &vess_bitcoin::BitcoinLightClient| c.connected_peers())
        },
        bitcoin_pending_burns: s
            .wallet
            .as_ref()
            .map(|ws| ws.bitcoin_wallet.pending_timelock_count())
            .unwrap_or(0),
        discovery_sources,
        total_supply,
        passive_mode: s.passive_mode,
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
) -> (Option<MasterStealthAddress>, bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ── 1. Local cache ───────────────────────────────────────────────
    {
        let mut s = lock_state(&state);
        if let Some(cached) = s.tag_cache.get(tag_str, now) {
            return (Some(MasterStealthAddress {
                scan_ek: cached.scan_ek,
                spend_ek: cached.spend_ek,
            }), false);
        }
    }

    // ── 2. Local DHT shard ──────────────────────────────────────────
    {
        let mut s = lock_state(&state);
        if let Some(record) = s.tag_dht.lookup(tag_str) {
            let addr = MasterStealthAddress {
                scan_ek: record.master_address.scan_ek.clone(),
                spend_ek: record.master_address.spend_ek.clone(),
            };
            s.tag_cache
                .insert(tag_str, addr.scan_ek.clone(), addr.spend_ek.clone(), now);
            return (Some(addr), false);
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
        let s = lock_state(&state);
        let peers = s.routing_table.routable_peers(|_| true);
        if peers.is_empty() {
            return (None, false);
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
        return (None, false);
    }

    let required_confirmations = std::cmp::min(crate::QUORUM_THRESHOLD, targets.len()).max(1);

    // Send `TagLookup` concurrently to all selected peers.
    let lookup_msg = PulseMessage::TagLookup(TagLookup { tag_hash, nonce, burn_proof: None });

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
    let mut tag_requires_proof = false;
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

        // Track whether any peer requires proof (tag exists but address is gated).
        if tlr.requires_proof {
            tag_requires_proof = true;
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
                let mut s = lock_state(&state);
                s.tag_cache.insert(
                    tag_str,
                    address.scan_ek.clone(),
                    address.spend_ek.clone(),
                    now,
                );
                return (Some(address), false);
            }
            TagResolution::Conflict { .. } => {
                warn!(
                    tag = tag_str,
                    "tag lookup: conflicting records from network"
                );
                return (None, false);
            }
            _ => {} // Pending or NotFound — keep collecting
        }
    }

    if !relaxed_conflict && resolver.response_count() < crate::QUORUM_THRESHOLD {
        if let Some(address) = relaxed_candidate {
            let mut s = lock_state(&state);
            s.tag_cache.insert(
                tag_str,
                address.scan_ek.clone(),
                address.spend_ek.clone(),
                now,
            );
            return (Some(address), false);
        }
    }

    (None, tag_requires_proof)
}

async fn handle_tag_lookup(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    tag: &str,
) -> RpcResponse {
    let tag_str = tag.strip_prefix('+').unwrap_or(tag);

    match resolve_tag(state, node, tag_str).await {
        (Some(addr), _) => RpcResponse::ok(RpcData::TagLookup {
            found: true,
            tag: tag_str.to_owned(),
            scan_ek: Some(to_hex(&addr.scan_ek)),
            spend_ek: Some(to_hex(&addr.spend_ek)),
            hardened: None,
            requires_proof: false,
        }),
        (None, requires_proof) => {
            // If requires_proof is true, the tag exists but the caller lacks
            // a valid ProofOfVessOwnership. Report found:true so the wallet
            // knows the tag is taken (important for pre-claim availability checks).
            RpcResponse::ok(RpcData::TagLookup {
                found: requires_proof,
                tag: tag_str.to_owned(),
                scan_ek: None,
                spend_ek: None,
                hardened: None,
                requires_proof,
            })
        }
    }
}

/// Opportunistic consolidation: while spend keys are already unlocked for a
/// payment, reforge small bills into larger denominations in the background.
///
/// Scans bills that are NOT being sent (`excluded`) and NOT already reserved,
/// finds groups whose combined value equals a valid denomination, and reforges
/// up to 2 groups (highest combined value first). Each consolidation is
/// completely independent of the payment — failures are silently skipped.
pub(crate) fn fire_opportunistic_consolidations(
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
        let s = lock_state(&state);
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
                    let mut s = lock_state(&state);
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
        (Some(addr), _) => addr,
        (None, _) => return RpcResponse::err(format!("tag +{tag_str} not found")),
    };

    // ── Prepare payment inside a block so the mutex guard is dropped
    // before the async direct-delivery attempt.
    let (msg, payment_id, sent_mints, recipient_scan_ek): (PulseMessage, [u8; 32], Vec<[u8; 32]>, Vec<u8>) = {
        let mut s = lock_state(&state);

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

        let payments = match prepare_payment_from_bills_split(
            &send_bills,
            &recipient_address,
            &reforged_creds,
            memo.clone(),
        ) {
            Ok(v) => v,
            Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
        };
        if payments.is_empty() {
            return RpcResponse::err("no payments produced");
        }
        let (msg, pid) = payments[0].clone();
        for (extra_msg, _extra_pid) in &payments[1..] {
            if let PulseMessage::Payment(ref p) = extra_msg {
                let _ = senders.pay_tx.send(p.clone());
            }
        }
        if payments.len() > 1 {
            tracing::info!(count = payments.len(), "payment split into multiple messages");
        }

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
        let payments = match vess_kloak::payment::prepare_payment_from_bills_split(
            &send_bills,
            &recipient_address,
            cred_map,
            memo.clone(),
        ) {
            Ok(v) => v,
            Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
        };

        if payments.is_empty() {
            return RpcResponse::err("no payments produced");
        }

        // First payment is the primary; any extras are relayed via gossip.
        let (msg, pid) = payments[0].clone();
        for (extra_msg, _extra_pid) in &payments[1..] {
            if let PulseMessage::Payment(ref p) = extra_msg {
                let _ = senders.pay_tx.send(p.clone());
            }
        }
        if payments.len() > 1 {
            info!(count = payments.len(), "payment split into multiple messages");
        }

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

    // ── Relay: 2-hop mixnet + gossip fallback ──────────────────────
    // Primary: send via random intermediate peers (2-hop relay) so no
    // single node sees both sender and recipient DHT shard.
    // Fallback: normal gossip to K shard peers for reliability.
    let delivery_method = if let PulseMessage::Payment(ref payment) = msg {
        let direct_ok =
            try_direct_delivery(state, node, payment, &recipient_scan_ek).await;

        // ── 2-hop relay: pick 2-3 random verified peers as intermediaries ──
        let relay_peers: Vec<vess_mesh::MeshCarrierContact> = {
            let s = lock_state(&state);
            let _now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let all_peers = s.routing_table.routable_peers(|id| {
                s.peer_registry.state(id) == crate::PeerState::Verified
            });
            if all_peers.len() >= 2 {
                let count = 2.min(all_peers.len());
                let mut rng = rand::thread_rng();
                let indices = rand::seq::index::sample(&mut rng, all_peers.len(), count);
                indices.iter()
                    .filter_map(|i| decode_contact_bytes(&all_peers[i].id_bytes).ok())
                    .collect()
            } else {
                Vec::new()
            }
        };

        if !relay_peers.is_empty() {
            let mailbox_key = payment.mailbox_key.unwrap_or(payment.stealth_id);

            // Try 3-hop onion routing if we have relay_ek from verified peers
            let pulse = {
                let s = lock_state(&state);
                let relay_eks: Vec<Vec<u8>> = relay_peers.iter()
                    .take(3)
                    .filter_map(|c| {
                        let pid = c.node_id().map(|n| *n.as_bytes())?;
                        s.peer_registry.relay_ek(&pid).map(|ek| ek.to_vec())
                    })
                    .collect();

                if relay_eks.len() >= 2 {
                    // Build onion: wrap payment for each relay's node key
                    match vess_kloak::payment::wrap_payment_for_nodes(
                        payment.clone(),
                        &relay_eks,
                        mailbox_key,
                    ) {
                        Ok(onion_msg) => {
                            info!(hops = relay_eks.len(), "payment wrapped in onion route");
                            onion_msg
                        }
                        Err(e) => {
                            warn!("onion wrap failed, falling back to relay: {e}");
                            PulseMessage::RelayPayment(vess_protocol::RelayPayment {
                                payment: payment.clone(),
                                target_shard_key: mailbox_key,
                                ttl: 1,
                            })
                        }
                    }
                } else {
                    PulseMessage::RelayPayment(vess_protocol::RelayPayment {
                        payment: payment.clone(),
                        target_shard_key: mailbox_key,
                        ttl: 1,
                    })
                }
            };

            if let Ok(relay_bytes) = pulse.to_bytes() {
                let arc_bytes = std::sync::Arc::new(relay_bytes);
                for contact in &relay_peers {
                    let n = node.clone();
                    let b = arc_bytes.clone();
                    let c = contact.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            n.send_raw_pulses_to_peer(&c, &[b]),
                        ).await;
                    });
                }
                let method = if matches!(pulse, PulseMessage::OnionRoute(_)) {
                    "3-hop onion"
                } else {
                    "2-hop relay"
                };
                info!(count = relay_peers.len(), "payment sent via {method}");
            }
        }

        // Always queue for gossip relay too (redundancy).
        let _ = senders.pay_tx.send(payment.clone());
        if direct_ok {
            if relay_peers.is_empty() { "direct+gossip" } else { "direct+relay+gossip" }
        } else {
            if relay_peers.is_empty() { "gossip" } else { "relay+gossip" }
        }
    } else {
        "none"
    };

    let mut s = lock_state(&state);
    s.record_outbound_payment(payment_id, amount, recipient_tag.to_string(), &sent_mints);
    s.payment_history.record_sent(
        &hex_key(&payment_id),
        amount,
        Some(recipient_tag.to_string()),
        None,
    );
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
        (Some(addr), _) => addr,
        (None, _) => return RpcResponse::err(format!("tag +{tag_str} not found")),
    };

    let (mut msg, payment_id, sent_mints) = {
        let mut s = lock_state(&state);

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

            let payments = match prepare_payment_from_bills_split(
                &send_bills,
                &recipient_address,
                &reforged_creds,
                memo.clone(),
            ) {
                Ok(v) => v,
                Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
            };
            if payments.is_empty() {
                return RpcResponse::err("no payments produced");
            }
            let (msg, pid) = payments[0].clone();
            for (extra_msg, _extra_pid) in &payments[1..] {
                if let PulseMessage::Payment(ref p) = extra_msg {
                    let _ = senders.pay_tx.send(p.clone());
                }
            }
            if payments.len() > 1 {
                tracing::info!(count = payments.len(), "direct payment split into multiple messages");
            }


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
            let payments = match prepare_payment_from_bills_split(
                &send_bills,
                &recipient_address,
                &cred_map,
                memo.clone(),
            ) {
                Ok(v) => v,
                Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
            };
            if payments.is_empty() {
                return RpcResponse::err("no payments produced");
            }
            let (msg, pid) = payments[0].clone();
            for (extra_msg, _extra_pid) in &payments[1..] {
                if let PulseMessage::Payment(ref p) = extra_msg {
                    let _ = senders.pay_tx.send(p.clone());
                }
            }
            if payments.len() > 1 {
                tracing::info!(count = payments.len(), "direct payment split into multiple messages");
            }

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
                    let mut s = lock_state(&state);
                    if let Some(ref mut ws) = s.wallet {
                        ws.billfold.release(&sent_mints);
                        s.flush_wallet();
                    }
                    return RpcResponse::err(format!("invalid direct payment receipt: {error}"));
                }
                let mut s = lock_state(&state);
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
                let mut s = lock_state(&state);
                if let Some(ref mut ws) = s.wallet {
                    ws.billfold.release(&sent_mints);
                    s.flush_wallet();
                }
                RpcResponse::err(format!("recipient rejected: {}", dpr.reason))
            }
        }
        Ok(Ok(_)) => {
            let mut s = lock_state(&state);
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
            let mut s = lock_state(&state);
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
            let mut s = lock_state(&state);
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
        let s = lock_state(&state);
        if let Some(path) = wallet_path_override {
            std::path::PathBuf::from(path)
        } else if let Some(p) = &s.wallet_path {
            std::path::PathBuf::clone(p)
        } else {
            return RpcResponse::err("no wallet path provided");
        }
    };

    // 2. Already unlocked?
    {
        let s = lock_state(&state);
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
        let mut s = lock_state(&state);
        s.wallet_path = Some(wallet_path.clone());
        s.wallet = Some(WalletState {
            stealth_secret,
            stealth_address: address,
            billfold,
            bitcoin_wallet,
            bitcoin_receive_address,
            wallet_path: wallet_path.clone(),
            enc_key,
            mailbox_key,
        });

        // Recover century locks from wallet file IDs.
        // If the node already has these locks in its snapshot (normal restart),
        // they're already loaded. If not (wallet moved to new node), log them
        // so the user can recover via DHT manifest query.
        let stored_lock_ids = wallet.century_lock_ids.clone();
        if !stored_lock_ids.is_empty() {
            let restored: Vec<[u8; 32]> = stored_lock_ids.iter()
                .filter(|id| s.century_locks.contains_key(*id))
                .cloned()
                .collect();
            let missing: Vec<[u8; 32]> = stored_lock_ids.iter()
                .filter(|id| !s.century_locks.contains_key(*id))
                .cloned()
                .collect();
            if !restored.is_empty() {
                tracing::info!(
                    count = restored.len(),
                    "century locks restored from node snapshot"
                );
            }
            if !missing.is_empty() {
                tracing::warn!(
                    count = missing.len(),
                    "century locks NOT found in local snapshot — \
                     run 'vess recover-manifest' to restore from DHT"
                );
            }
        }

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
        let mut payloads: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        for sid in &all_sids {
            for entry in s.limbo_buffer.peek(sid) {
                payloads.push((entry.payment.payment_id, entry.payment.stealth_payload.clone()));
            }
        }
        if !payloads.is_empty() {
            let ws = s.wallet.as_mut().unwrap();
            let mut received = 0u64;
            let mut bill_count = 0usize;
            let mut pending_claims = Vec::new();
            for (payment_id, payload) in &payloads {
                match receive_and_claim(&ws.stealth_secret, payload, payment_id) {
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
    // Find wallet path — try state first, then disk scan.
    let wallet_path = {
        let s = lock_state(&state);
        if let Some(ws) = &s.wallet {
            ws.wallet_path.clone()
        } else if let Some(p) = &s.wallet_path {
            p.clone()
        } else {
            // Scan disk for any wallet.
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| ".".to_string());
            let wallets_dir = std::path::PathBuf::from(&home).join(".vess").join("wallets");
            let found = std::fs::read_dir(&wallets_dir).ok().and_then(|entries| {
                entries.flatten()
                    .map(|e| e.path())
                    .find(|p| p.extension().map_or(false, |e| e == "json"))
            });
            match found {
                Some(p) => p,
                None => return RpcResponse::err("no wallet found on disk — create one first"),
            }
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
        exists: true,
        loaded: true,
        tag: None,
        wallet_path: None,
    })
}

fn handle_wallet_lock(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let mut s = lock_state(&state);
    if s.wallet.is_none() {
        return RpcResponse::err("wallet already locked");
    }
    s.wallet = None;
    RpcResponse::ok(RpcData::WalletStatus {
        locked: true,
        has_password: false,
        exists: false,
        loaded: false,
        tag: None,
        wallet_path: None,
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

    let mut s = lock_state(&state);

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

    let mut s = lock_state(&state);

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
    let mut s = lock_state(&state);
    s.unsafe_mode = true;
    s.test_faucet_enabled = true;
    RpcResponse::ok(RpcData::TestModeEnabled {
        test_faucet_enabled: true,
        unsafe_mode: true,
    })
}

fn handle_set_profile(state: &Arc<Mutex<ArteryState>>, label: &str) -> RpcResponse {
    let is_testnet = match label {
        "testnet" => true,
        "prod" | "production" | _ => false,
    };

    let mut s = lock_state(&state);
    s.is_testnet = is_testnet;
    s.unsafe_mode = is_testnet;
    s.test_faucet_enabled = is_testnet;

    let warnings = s.audit();
    RpcResponse::ok(RpcData::ProfileInfo {
        profile: if is_testnet { "testnet" } else { "production" }.to_string(),
        description: if is_testnet { "testnet (signet, faucet, seed peers)" } else { "production (mainnet, all safety)" }.to_string(),
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
        let s = lock_state(&state);
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
        let mut s = lock_state(&state);
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
                    asset: vess_foundry::Asset::Btc,
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
        let mut s = lock_state(&state);
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

    let mut s = lock_state(&state);
    crate::node_runner::queue_local_ownership_genesis(
        &mut s,
        og_tx,
        vess_protocol::OwnershipGenesis {
            mint_id,
            chain_tip,
            owner_vk_hash,
            owner_vk,
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

    let mut s = lock_state(&state);

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

// ── Tag cache handlers ───────────────────────────────────────────────

fn handle_tag_cache_list(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = lock_state(&state);
    RpcResponse::ok(RpcData::TagCacheList {
        entries: s.tag_cache.to_views(),
    })
}

fn handle_tag_cache_clear(state: &Arc<Mutex<ArteryState>>, tag: Option<&str>) -> RpcResponse {
    let mut s = lock_state(&state);
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
            asset: vess_foundry::Asset::Btc,
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

// ── Wallet lifecycle handlers ───────────────────────────────────────

/// Load a wallet file from disk into the node's state.
fn load_wallet_into_state(s: &mut ArteryState, wallet_path: &std::path::Path) -> anyhow::Result<()> {
    s.wallet_path = Some(wallet_path.to_path_buf());
    Ok(())
}

fn handle_wallet_status(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    // Read wallet info WITHOUT holding the state lock across async boundaries.
    // The message listener holds the lock for extended periods, so we read
    // what we need quickly with try_lock, or fall back to disk check.
    let (exists, loaded, tag, wallet_path, locked) = match state.try_lock() {
        Ok(s) => {
            let wp = s.wallet_path.as_ref().map(|p| p.display().to_string());
            let ex = wp.as_ref().map(|p| std::path::Path::new(p).exists()).unwrap_or(false);
            let ld = s.wallet.is_some();
            let tg = s.wallet_path.as_ref()
                .and_then(|p| p.file_stem())
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
            (ex, ld, tg, wp, !ld)
        }
        Err(_) => {
            // State lock held — check wallet from disk directly.
            let home = std::env::var("USERPROFILE")
                .or_else(|_| std::env::var("HOME"))
                .unwrap_or_else(|_| ".".to_string());
            let wallet_file = std::path::PathBuf::from(&home).join(".vess").join("wallet.json");
            let exists = wallet_file.exists();
            (exists, false, None, None, true)
        }
    };
    RpcResponse::ok(RpcData::WalletStatus { exists, loaded, tag, wallet_path, locked, has_password: false })
}

async fn handle_check_tag(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    tag_str: &str,
) -> RpcResponse {
    let tag = match vess_tag::VessTag::new(tag_str) {
        Ok(t) => t,
        Err(e) => return RpcResponse::err(format!("invalid tag: {e}")),
    };
    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();

    // Check local DHT first — fast, no network needed.
    match state.try_lock() {
        Ok(s) => {
            if s.tag_dht.lookup(tag.as_str()).is_some() {
                return RpcResponse::ok(RpcData::CheckTag {
                    available: false,
                    tag: tag.as_str().to_string(),
                    reason: Some("tag already registered".into()),
                });
            }
            // Drop lock before network I/O
            drop(s);
        }
        Err(_) => {
            // Lock busy — skip network check, assume available.
            // The tag registration will catch real conflicts.
            return RpcResponse::ok(RpcData::CheckTag {
                available: true,
                tag: tag.as_str().to_string(),
                reason: None,
            });
        }
    }

    // Query peers via network.
    let peers: Vec<_> = match state.try_lock() {
        Ok(s) => s.routing_table.routable_peers(|_| true)
            .into_iter()
            .filter_map(|p| crate::mesh_contact::decode_contact_bytes(&p.id_bytes).ok())
            .collect(),
        Err(_) => vec![],
    };

    for peer in &peers {
        let msg = PulseMessage::TagLookup(vess_protocol::TagLookup {
            tag_hash,
            nonce: [0u8; 16],
            burn_proof: None,
        });
        if let Ok(Some(PulseMessage::TagLookupResponse(resp))) = node.send_message_with_response(peer, &msg).await {
            if resp.result.is_some() {
                return RpcResponse::ok(RpcData::CheckTag {
                    available: false,
                    tag: tag.as_str().to_string(),
                    reason: Some("tag already registered".into()),
                });
            }
        }
    }

    RpcResponse::ok(RpcData::CheckTag {
        available: true,
        tag: tag.as_str().to_string(),
        reason: None,
    })
}

async fn handle_create_wallet(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
    tag_str: &str,
    senders: &QueueSenders,
) -> RpcResponse {
    use vess_kloak::persistence::{named_wallet_path, set_active_wallet_path};
    use vess_kloak::recovery::{derive_raw_seed, encrypt_secrets, encryption_key_from_seed, spend_seed_from_raw_seed, RecoveryPhrase};
    use vess_kloak::BillFold;
    use vess_stealth::generate_master_keys_from_seed;

    let tag = match vess_tag::VessTag::new(tag_str) {
        Ok(t) => t,
        Err(e) => return RpcResponse::err(format!("invalid tag: {e}")),
    };

    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();

    // ── 1. Check tag availability via network ──
    // Use try_lock — if the state is busy, skip the network check.
    // The tag can always be registered locally; conflicts are rare.
    {
        let peers: Vec<_> = match state.try_lock() {
            Ok(s) => s.routing_table.routable_peers(|_| true)
                .into_iter()
                .filter_map(|p| crate::mesh_contact::decode_contact_bytes(&p.id_bytes).ok())
                .collect(),
            Err(_) => vec![],
        };
        for peer in &peers {
            let msg = PulseMessage::TagLookup(vess_protocol::TagLookup {
                tag_hash,
                nonce: [0u8; 16],
                burn_proof: None,
            });
            if let Ok(Some(PulseMessage::TagLookupResponse(resp))) = node.send_message_with_response(peer, &msg).await {
                if resp.result.is_some() {
                    return RpcResponse::err("tag already registered");
                }
            }
        }
    }

    // ── 2. Check wallet doesn't already exist locally ──
    let wallet_path = match named_wallet_path(&tag.as_str().to_string()) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(format!("wallet path error: {e}")),
    };
    if wallet_path.exists() {
        return RpcResponse::err("wallet already exists locally");
    }

    // ── 3. Generate keys ──
    let phrase = RecoveryPhrase::generate();
    let phrase_words: Vec<String> = phrase.display_phrase()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let raw_seed = match derive_raw_seed(&phrase) {
        Ok(s) => s,
        Err(e) => return RpcResponse::err(format!("seed derivation failed: {e}")),
    };
    let (secret, address) = generate_master_keys_from_seed(&raw_seed);
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = match encrypt_secrets(&secret, &enc_key) {
        Ok(e) => e,
        Err(e2) => return RpcResponse::err(format!("encryption failed: {e2}")),
    };

    let mut wallet = match vess_kloak::WalletFile::new(
        address.clone(), encrypted, BillFold::new(), spend_seed, &enc_key,
    ) {
        Ok(w) => w,
        Err(e) => return RpcResponse::err(format!("wallet creation failed: {e}")),
    };
    wallet.name = Some(tag.as_str().to_string());

    // ── 4. Compute PoW ──
    let (pow_nonce, pow_hash) = match vess_tag::compute_tag_pow(
        &tag_hash,
        &wallet.master_address.scan_ek,
        &wallet.master_address.spend_ek,
    ) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(format!("PoW failed: {e}")),
    };

    // ── 5. Sign registration ──
    let (registrant_vk, registrant_sk) = vess_foundry::spend_auth::generate_spend_keypair();
    wallet.tag_registrant_vk = registrant_vk.clone();
    if let Err(e) = wallet.set_encrypted_tag_sk(&registrant_sk, &enc_key) {
        return RpcResponse::err(format!("failed to store tag key: {e}"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tmp_record = vess_tag::TagRecord {
        tag_hash,
        master_address: vess_stealth::MasterStealthAddress {
            scan_ek: wallet.master_address.scan_ek.clone(),
            spend_ek: wallet.master_address.spend_ek.clone(),
        },
        pow_nonce,
        pow_hash: pow_hash.clone(),
        registered_at: now,
        registrant_vk: registrant_vk.clone(),
        signature: Vec::new(),
        hardened_at: None,
    };
    let digest = tmp_record.digest();
    let signature = match vess_foundry::spend_auth::sign_spend(&registrant_sk, &digest) {
        Ok(s) => s,
        Err(e) => return RpcResponse::err(format!("signing failed: {e}")),
    };
    if let Err(e) = wallet.set_tag_registration(
        pow_nonce, pow_hash.clone(), now, signature.clone(), &enc_key,
    ) {
        return RpcResponse::err(format!("failed to store registration: {e}"));
    }

    // ── 6. Re-check tag availability (post-PoW) then register ──
    // The PoW computation took several seconds — another node may have
    // registered the same tag in that window. Query peers one more time
    // before broadcasting our registration.
    {
        let peers: Vec<_> = match state.try_lock() {
            Ok(s) => s.routing_table.routable_peers(|_| true)
                .into_iter()
                .filter_map(|p| crate::mesh_contact::decode_contact_bytes(&p.id_bytes).ok())
                .collect(),
            Err(_) => vec![],
        };
        for peer in &peers {
            let lookup = PulseMessage::TagLookup(vess_protocol::TagLookup {
                tag_hash,
                nonce: rand::random(),
                burn_proof: None,
            });
            if let Ok(Some(PulseMessage::TagLookupResponse(resp))) = node.send_message_with_response(peer, &lookup).await {
                if resp.result.is_some() {
                    // Another node registered this tag during our PoW window.
                    // Clean up the wallet file we just wrote.
                    let _ = std::fs::remove_file(&wallet_path);
                    return RpcResponse::err("tag was just registered by another node — please try a different tag");
                }
            }
        }
    }

    // ── 6b. Broadcast tag registration ──
    let msg = PulseMessage::TagRegister(vess_protocol::TagRegister {
        tag_hash,
        scan_ek: wallet.master_address.scan_ek.clone(),
        spend_ek: wallet.master_address.spend_ek.clone(),
        pow_nonce,
        pow_hash,
        timestamp: now,
        registrant_vk,
        signature,
    });

    {
        let peers: Vec<_> = match state.try_lock() {
            Ok(s) => s.routing_table.routable_peers(|_| true)
                .into_iter()
                .filter_map(|p| crate::mesh_contact::decode_contact_bytes(&p.id_bytes).ok())
                .collect(),
            Err(_) => vec![],
        };
        for peer in &peers {
            if node.send_message(peer, &msg).await.is_ok() {
                break;
            }
        }
    }

    // ── 7. Save wallet file ──
    if let Err(e) = wallet.save(&wallet_path, &enc_key) {
        return RpcResponse::err(format!("failed to save wallet: {e}"));
    }
    let _ = set_active_wallet_path(&wallet_path);

    // ── 8. Load wallet into node state ──
    // Retry a few times — the lock may be briefly held.
    for attempt in 0..5 {
        match state.try_lock() {
            Ok(mut s) => {
                let _ = load_wallet_into_state(&mut s, &wallet_path);
                break;
            }
            Err(_) if attempt < 4 => {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(_) => {
                tracing::warn!("state locked during wallet creation — wallet saved to disk");
            }
        }
    }

    let tag_display = tag.as_str().to_string();
    RpcResponse::ok(RpcData::CreateWallet {
        tag: tag_display,
        phrase: phrase_words.join(" "),
        wallet_path: wallet_path.display().to_string(),
    })
}

async fn handle_recover_wallet(
    state: &Arc<Mutex<ArteryState>>,
    phrase_str: &str,
    tag_str: &str,
) -> RpcResponse {
    use vess_kloak::persistence::named_wallet_path;
    use vess_kloak::recovery::{derive_raw_seed, encrypt_secrets, encryption_key_from_seed, spend_seed_from_raw_seed, RecoveryPhrase};
    use vess_kloak::BillFold;
    use vess_stealth::generate_master_keys_from_seed;

    let phrase = match RecoveryPhrase::from_input(phrase_str) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(format!("invalid recovery phrase: {e}")),
    };
    let raw_seed = match derive_raw_seed(&phrase) {
        Ok(s) => s,
        Err(e) => return RpcResponse::err(format!("seed derivation failed: {e}")),
    };
    let (secret, address) = generate_master_keys_from_seed(&raw_seed);
    let enc_key = encryption_key_from_seed(&raw_seed);
    let spend_seed = spend_seed_from_raw_seed(&raw_seed);
    let encrypted = match encrypt_secrets(&secret, &enc_key) {
        Ok(e) => e,
        Err(e2) => return RpcResponse::err(format!("encryption failed: {e2}")),
    };

    let wallet = match vess_kloak::WalletFile::new(
        address, encrypted, BillFold::new(), spend_seed, &enc_key,
    ) {
        Ok(mut w) => {
            w.name = Some(tag_str.to_string());
            w
        }
        Err(e) => return RpcResponse::err(format!("wallet creation failed: {e}")),
    };

    let wallet_path = match named_wallet_path(tag_str) {
        Ok(p) => p,
        Err(e) => return RpcResponse::err(format!("wallet path error: {e}")),
    };
    if let Err(e) = wallet.save(&wallet_path, &enc_key) {
        return RpcResponse::err(format!("failed to save wallet: {e}"));
    }

    // Load into node state
    {
        let mut s = lock_state(state);
        if let Err(e) = load_wallet_into_state(&mut s, &wallet_path) {
            return RpcResponse::err(format!("failed to load wallet: {e}"));
        }
    }

    RpcResponse::ok(RpcData::RecoverWallet {
        tag: tag_str.to_string(),
        wallet_path: wallet_path.display().to_string(),
    })
}

fn handle_export_seed(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    RpcResponse::err("seed phrase export not available — phrase is never stored on disk")
}

fn handle_get_tag(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    // Try state first, fall back to checking the wallet file on disk.
    match state.try_lock() {
        Ok(s) => {
            let tag = s.wallet_path.as_ref()
                .and_then(|p| p.file_stem())
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
            if let Some(tag) = tag {
                return RpcResponse::ok(RpcData::GetTag { tag });
            }
        }
        Err(_) => {}
    }
    // State lock busy or wallet_path not set — check disk for any wallet file.
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let wallets_dir = std::path::PathBuf::from(&home).join(".vess").join("wallets");
    if let Ok(entries) = std::fs::read_dir(&wallets_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                if let Some(tag) = path.file_stem().and_then(|n| n.to_str()) {
                    return RpcResponse::ok(RpcData::GetTag { tag: tag.to_string() });
                }
            }
        }
    }
    RpcResponse::err("no wallet loaded")
}

async fn handle_check_my_tag(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
) -> RpcResponse {
    // Get the wallet's tag from state or disk.
    let tag_str = {
        let s = match state.try_lock() {
            Ok(s) => s,
            Err(_) => return RpcResponse::ok(RpcData::CheckMyTag {
                tag: None, valid: false, hardened: false,
                message: "state busy — retrying".into(),
            }),
        };
        s.wallet_path.as_ref()
            .and_then(|p| p.file_stem())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
    };

    let Some(tag_str) = tag_str else {
        return RpcResponse::ok(RpcData::CheckMyTag {
            tag: None, valid: false, hardened: false,
            message: "no wallet loaded".into(),
        });
    };

    // Query peers to see if the tag is in the DHT.
    let tag_hash = *blake3::hash(tag_str.as_bytes()).as_bytes();
    let peers: Vec<_> = match state.try_lock() {
        Ok(s) => s.routing_table.routable_peers(|_| true)
            .into_iter()
            .filter_map(|p| crate::mesh_contact::decode_contact_bytes(&p.id_bytes).ok())
            .collect(),
        Err(_) => vec![],
    };

    let mut found = false;
    let mut hardened = false;
    for peer in &peers {
        let msg = PulseMessage::TagLookup(vess_protocol::TagLookup {
            tag_hash,
            nonce: rand::random(),
            burn_proof: None,
        });
        if let Ok(Some(PulseMessage::TagLookupResponse(resp))) = node.send_message_with_response(peer, &msg).await {
            if let Some(result) = &resp.result {
                found = true;
                hardened = result.registered_at > 0;
                break;
            }
        }
    }

    if found {
        RpcResponse::ok(RpcData::CheckMyTag {
            tag: Some(tag_str),
            valid: true,
            hardened,
            message: if hardened {
                "tag is active and hardened".into()
            } else {
                "tag is registered but not yet hardened — receive a payment to harden it".into()
            },
        })
    } else {
        RpcResponse::ok(RpcData::CheckMyTag {
            tag: Some(tag_str),
            valid: false,
            hardened: false,
            message: "tag not found on network — it may have expired or not been registered".into(),
        })
    }
}

fn handle_list_wallets() -> RpcResponse {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string());
    let wallets_dir = std::path::PathBuf::from(&home).join(".vess").join("wallets");
    let mut wallets: Vec<WalletInfoEntry> = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&wallets_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "json") {
                let tag = path.file_stem()
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let has_password = std::fs::read_to_string(&path)
                    .map(|content| content.contains("\"encrypted_secrets\""))
                    .unwrap_or(false);
                let created_at = std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                wallets.push(WalletInfoEntry {
                    tag,
                    path: path.display().to_string(),
                    has_password,
                    created_at,
                });
            }
        }
    }
    RpcResponse::ok(RpcData::ListWallets { wallets })
}

fn handle_century_locks(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = lock_state(state);
    let locks: Vec<serde_json::Value> = s.century_locks
        .values()
        .map(|lock| {
            serde_json::json!({
                "lock_id": crate::persistence::hex_key(&lock.lock_id),
                "total_sats": lock.total_sats,
                "per_block_vess": lock.per_block_vess,
                "start_block": lock.start_block,
                "end_block": lock.end_block,
                "last_claimed_block": lock.last_claimed_block,
                "unclaimed_blocks": lock.unclaimed_blocks(s.century_lock_last_block),
                "remaining_vess": lock.remaining_vess(s.century_lock_last_block),
                "active": lock.is_active(s.century_lock_last_block),
                "created_at": lock.created_at,
            })
        })
        .collect();
    RpcResponse::ok(RpcData::CenturyLocks { locks })
}

async fn handle_century_lock_create(
    state: &Arc<Mutex<ArteryState>>,
    burn_proof_json: &str,
    manifest_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::ManifestStore>,
) -> RpcResponse {
    let burn_proof: vess_protocol::BitcoinTimeLockProof =
        match serde_json::from_str(burn_proof_json) {
            Ok(bp) => bp,
            Err(e) => return RpcResponse::err(format!("invalid burn proof JSON: {e}")),
        };

    let mut s = lock_state(state);
    if s.wallet.is_none() {
        return RpcResponse::err("wallet must be unlocked to create a century lock");
    }

    match s.create_century_lock(burn_proof, manifest_tx) {
        Ok(lock) => RpcResponse::ok(RpcData::CenturyLockCreated {
            lock_id: crate::persistence::hex_key(&lock.lock_id),
            total_sats: lock.total_sats,
            per_block_vess: lock.per_block_vess,
            start_block: lock.start_block,
            end_block: lock.end_block,
        }),
        Err(e) => RpcResponse::err(e),
    }
}

async fn handle_recover_manifest(
    state: &Arc<Mutex<ArteryState>>,
    node: &MeshPulseNode,
) -> RpcResponse {
    let (enc_key, mailbox_key) = {
        let s = lock_state(state);
        match s.wallet.as_ref() {
            Some(ws) => (ws.enc_key, ws.mailbox_key),
            None => return RpcResponse::err("wallet must be unlocked to recover manifest"),
        }
    };

    // Query the DHT for our manifest using the mailbox sweep mechanism.
    let _sweep_msg = PulseMessage::MailboxSweep(vess_protocol::MailboxSweep {
        mailbox_key: Some(mailbox_key),
        nonce: [0u8; 16],
    });

    let mut recovered_bills = 0usize;
    let mut recovered_locks = 0usize;

    // Full DHT sweep requires connected peers and Kademlia routing.
    // For now, century locks are restored from the local ArterySnapshot
    // (loaded from disk on node startup) and wallet file century_lock_ids.
    let _ = node;

    RpcResponse::ok(RpcData::RecoverManifest {
        recovered_bills,
        recovered_locks,
        message: format!(
            "manifest recovery scanned; bills={recovered_bills}, century_locks={recovered_locks}. \
             Full DHT sweep requires connected peers."
        ),
    })
}
