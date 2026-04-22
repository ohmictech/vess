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

use vess_foundry::reforge::{reforge, ReforgeRequest};
use vess_foundry::spend_auth::generate_spend_keypair;
use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::{prepare_payment_from_bills, prepare_payment_with_transfer};
use vess_kloak::selection::{decompose_amount, select_bills_filtered};
use vess_protocol::{ManifestStore, PulseMessage, TagLookup, TagStore};
use vess_stealth::MasterStealthAddress;
use vess_tag::{TagRecord, VessTag};
use vess_vascular::VessNode;

use crate::gossip::k_nearest;
use crate::node_runner::ArteryState;
use crate::node_runner::WalletState;
use crate::persistence::hex_key;
use crate::tag_resolver::{TagResolution, TagResolver};

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

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RpcRequest {
    Balance,
    NodeInfo,
    Notifications {
        #[serde(default)]
        max: Option<usize>,
    },
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
        node_id: String,
        #[serde(default)]
        memo: Option<String>,
    },
    WalletUnlock {
        password: String,
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
    Notifications {
        notifications: Vec<crate::node_runner::WalletNotification>,
    },
    WalletStatus {
        locked: bool,
        has_password: bool,
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
pub(crate) async fn run_rpc_server(
    port: u16,
    state: Arc<Mutex<ArteryState>>,
    senders: QueueSenders,
    node: VessNode,
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
        let snd = senders.clone();
        let nd = node.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

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
    node: &VessNode,
) -> RpcResponse {
    let req: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => return RpcResponse::err(format!("invalid request: {e}")),
    };

    match req {
        RpcRequest::Balance => handle_balance(state),
        RpcRequest::NodeInfo => handle_node_info(state),
        RpcRequest::Notifications { max } => handle_notifications(state, max.unwrap_or(64)),
        RpcRequest::TagLookup { tag } => handle_tag_lookup(state, node, &tag).await,
        RpcRequest::Send {
            amount,
            recipient,
            memo,
        } => handle_send(state, node, amount, &recipient, memo, senders).await,
        RpcRequest::SendDirect {
            amount,
            recipient,
            node_id,
            memo,
        } => handle_send_direct(state, amount, &recipient, &node_id, memo, senders, node).await,
        RpcRequest::WalletUnlock { password } => {
            handle_wallet_unlock(state, &password, &senders.oc_tx)
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
        verified_peers: s
            .peer_registry
            .count_in_state(crate::handshake::PeerState::Verified),
        estimated_network_size: s.estimated_network_size,
        tag_count: s.tag_dht.record_count(),
        registry_count: s.registry.len(),
        limbo_count: s.limbo_mint_ids.len(),
    })
}

fn handle_notifications(state: &Arc<Mutex<ArteryState>>, max: usize) -> RpcResponse {
    let mut s = state.lock().unwrap();
    RpcResponse::ok(RpcData::Notifications {
        notifications: s.take_notifications(max),
    })
}

/// Number of peers to query for a DHT tag lookup when the local shard
/// has no record.  We fan out to up to this many peers and run
/// `TagResolver` quorum verification over the responses.
const TAG_LOOKUP_FAN_OUT: usize = 9;

/// Timeout (milliseconds) for a single peer's `TagLookup` response.
const TAG_LOOKUP_TIMEOUT_MS: u64 = 4_000;

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
    node: &VessNode,
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
            s.tag_cache.insert(tag_str, addr.scan_ek.clone(), addr.spend_ek.clone(), now);
            return Some(addr);
        }
    }

    // ── 3. Active DHT query ─────────────────────────────────────────
    // Select peers closest to the tag's DHT key.
    let tag_hash: [u8; 32] = *blake3::hash(tag_str.as_bytes()).as_bytes();
    let nonce: [u8; 16] = rand::random();

    let targets: Vec<(iroh::EndpointId, [u8; 32])> = {
        let s = state.lock().unwrap();
        let peers = s.routing_table.routable_peers(|_| true);
        if peers.is_empty() {
            return None;
        }
        let peer_hashes: Vec<[u8; 32]> = peers.iter().map(|p| p.id_hash).collect();
        let nearest_indices = k_nearest(&tag_hash, &peer_hashes, TAG_LOOKUP_FAN_OUT);
        nearest_indices
            .into_iter()
            .filter_map(|i| {
                let p = &peers[i];
                let arr: [u8; 32] = p.id_bytes.as_slice().try_into().ok()?;
                let eid = iroh::EndpointId::from_bytes(&arr).ok()?;
                Some((eid, p.id_hash))
            })
            .collect()
    };

    if targets.is_empty() {
        return None;
    }

    // Send `TagLookup` concurrently to all selected peers.
    let lookup_msg = PulseMessage::TagLookup(TagLookup {
        tag_hash,
        nonce,
    });

    let mut tasks = Vec::with_capacity(targets.len());
    for (eid, id_hash) in targets {
        let n = node.clone();
        let msg = lookup_msg.clone();
        tasks.push(tokio::spawn(async move {
            let resp = tokio::time::timeout(
                std::time::Duration::from_millis(TAG_LOOKUP_TIMEOUT_MS),
                n.send_message_with_response(eid, &msg),
            )
            .await;
            (id_hash, resp)
        }));
    }

    let results = futures::future::join_all(tasks).await;

    // Collect responses and run quorum verification.
    let mut resolver = TagResolver::new();
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
                warn!(tag = tag_str, "tag lookup: conflicting records from network");
                return None;
            }
            _ => {} // Pending or NotFound — keep collecting
        }
    }

    None
}

async fn handle_tag_lookup(
    state: &Arc<Mutex<ArteryState>>,
    node: &VessNode,
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

async fn handle_send(
    state: &Arc<Mutex<ArteryState>>,
    node: &VessNode,
    amount: u64,
    recipient_tag: &str,
    memo: Option<String>,
    senders: &QueueSenders,
) -> RpcResponse {
    let tag_str = recipient_tag.strip_prefix('+').unwrap_or(recipient_tag);

    // ── Resolve tag (cache → local DHT → active DHT query) ──────────
    // Done outside the mutex so the async network query doesn't block
    // the state lock.
    let recipient_address = match resolve_tag(state, node, tag_str).await {
        Some(addr) => addr,
        None => return RpcResponse::err(format!("tag +{tag_str} not found")),
    };

    let mut s = state.lock().unwrap();

    // ── Require wallet ──────────────────────────────────────────────
    if s.wallet.is_none() {
        return RpcResponse::err("wallet not loaded");
    }

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

    // Validate memo length.
    if let Some(ref m) = memo {
        if m.len() > 256 {
            return RpcResponse::err("memo exceeds 256 byte limit");
        }
    }

    // ── Bill selection (excludes reserved / in-flight bills) ────────
    let reserved: Vec<[u8; 32]> = ws.billfold.reserved_set().iter().copied().collect();
    let selection = match select_bills_filtered(ws.billfold.bills(), amount, &reserved) {
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

        let ws_mut = s.wallet.as_mut().unwrap();

        // Withdraw consumed originals and deposit change bills.
        for mid in &result.consumed_mint_ids {
            ws_mut.billfold.withdraw(mid);
        }
        for (bill, _) in &change_bills {
            if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                ws_mut
                    .billfold
                    .deposit_with_credentials(bill.clone(), cred.clone());
            }
        }

        // Reserve sent bills so they can't be accidentally re-spent.
        // They stay in a pending state until the recipient claims them
        // (at which point the OwnershipClaim handler removes them) or
        // until the limbo TTL expires (periodic release task).
        let sent_mints: Vec<[u8; 32]> = send_bills.iter().map(|b| b.mint_id).collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        ws_mut.billfold.reserve(&sent_mints, now);

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
            let _ = senders.ra_tx.send(vess_protocol::ReforgeAttestation {
                consumed_mint_ids: result.consumed_mint_ids,
                owner_vk: owner_vk_for_ra,
                consume_sigs,
                reforge_id,
                hops_remaining: 6,
            });
        }

        // OwnershipGenesis for each change bill (registers them in the DHT).
        for (bill, proof_bytes) in &change_bills {
            if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                let _ = senders.og_tx.send(vess_protocol::OwnershipGenesis {
                    mint_id: bill.mint_id,
                    chain_tip: bill.chain_tip,
                    owner_vk_hash,
                    owner_vk: cred.spend_vk.clone(),
                    denomination_value: bill.denomination.value(),
                    proof: proof_bytes.clone(),
                    digest: bill.digest,
                    hops_remaining: 6,
                    chain_depth: 0,
                });
            }
        }

        // OwnershipGenesis for each SENT bill (so the recipient can claim it).
        for (i, bill) in send_bills.iter().enumerate() {
            if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                let proof_bytes = result.outputs[i].1.clone();
                let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                let _ = senders.og_tx.send(vess_protocol::OwnershipGenesis {
                    mint_id: bill.mint_id,
                    chain_tip: bill.chain_tip,
                    owner_vk_hash,
                    owner_vk: cred.spend_vk.clone(),
                    denomination_value: bill.denomination.value(),
                    proof: proof_bytes,
                    digest: bill.digest,
                    hops_remaining: 6,
                    chain_depth: 0,
                });
            }
        }

        (msg, pid, sent_mints)
    } else {
        // === EXACT MATCH PATH ===
        let (msg, pid, send_indices) = match prepare_payment_with_transfer(
            &ws.billfold,
            amount,
            &recipient_address,
            &cred_map,
            memo.clone(),
        ) {
            Ok(v) => v,
            Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
        };

        let ws_mut = s.wallet.as_mut().unwrap();
        let mint_ids: Vec<[u8; 32]> = send_indices
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

    // ── Queue payment for relay ─────────────────────────────────────
    if let PulseMessage::Payment(ref payment) = msg {
        let _ = senders.pay_tx.send(payment.clone());
    }

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
        message: format!("Payment to {recipient_tag} queued for delivery."),
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

/// Direct peer-to-peer send: connect to a specific node via QUIC and deliver
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
    node: &VessNode,
) -> RpcResponse {
    // Parse node ID.
    let target: iroh::EndpointId = match node_id_str.parse() {
        Ok(id) => id,
        Err(_) => return RpcResponse::err("invalid node_id: expected hex-encoded endpoint ID"),
    };

    let tag_str = recipient_tag.strip_prefix('+').unwrap_or(recipient_tag);

    // ── Resolve tag (cache → local DHT → active DHT query) ──────────
    let recipient_address = match resolve_tag(state, node, tag_str).await {
        Some(addr) => addr,
        None => return RpcResponse::err(format!("tag +{tag_str} not found")),
    };

    let (msg, payment_id, sent_mints) = {
        let mut s = state.lock().unwrap();

        if s.wallet.is_none() {
            return RpcResponse::err("wallet not loaded");
        }

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

        if let Some(ref m) = memo {
            if m.len() > 256 {
                return RpcResponse::err("memo exceeds 256 byte limit");
            }
        }

        let reserved: Vec<[u8; 32]> = ws.billfold.reserved_set().iter().copied().collect();
        let selection = match select_bills_filtered(ws.billfold.bills(), amount, &reserved) {
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

            let ws_mut = s.wallet.as_mut().unwrap();

            for mid in &result.consumed_mint_ids {
                ws_mut.billfold.withdraw(mid);
            }
            for (bill, _) in &change_bills {
                if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                    ws_mut
                        .billfold
                        .deposit_with_credentials(bill.clone(), cred.clone());
                }
            }

            let sent_mints: Vec<[u8; 32]> = send_bills.iter().map(|b| b.mint_id).collect();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ws_mut.billfold.reserve(&sent_mints, now);

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
                let _ = senders.ra_tx.send(vess_protocol::ReforgeAttestation {
                    consumed_mint_ids: result.consumed_mint_ids,
                    owner_vk: owner_vk_for_ra,
                    consume_sigs,
                    reforge_id,
                    hops_remaining: 6,
                });
            }

            for (bill, _) in &change_bills {
                if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                    let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                    let _ = senders.og_tx.send(vess_protocol::OwnershipGenesis {
                        mint_id: bill.mint_id,
                        chain_tip: bill.chain_tip,
                        owner_vk_hash,
                        owner_vk: cred.spend_vk.clone(),
                        denomination_value: bill.denomination.value(),
                        proof: Vec::new(),
                        digest: bill.digest,
                        hops_remaining: 6,
                        chain_depth: 0,
                    });
                }
            }

            for (i, bill) in send_bills.iter().enumerate() {
                if let Some(cred) = reforged_creds.get(&bill.mint_id) {
                    let proof_bytes = result.outputs[i].1.clone();
                    let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&cred.spend_vk);
                    let _ = senders.og_tx.send(vess_protocol::OwnershipGenesis {
                        mint_id: bill.mint_id,
                        chain_tip: bill.chain_tip,
                        owner_vk_hash,
                        owner_vk: cred.spend_vk.clone(),
                        denomination_value: bill.denomination.value(),
                        proof: proof_bytes,
                        digest: bill.digest,
                        hops_remaining: 6,
                        chain_depth: 0,
                    });
                }
            }

            s.flush_wallet();
            (msg, pid, sent_mints)
        } else {
            // === EXACT MATCH PATH ===
            let (msg, pid, send_indices) = match prepare_payment_with_transfer(
                &ws.billfold,
                amount,
                &recipient_address,
                &cred_map,
                memo.clone(),
            ) {
                Ok(v) => v,
                Err(e) => return RpcResponse::err(format!("prepare payment failed: {e}")),
            };

            let ws_mut = s.wallet.as_mut().unwrap();
            let mint_ids: Vec<[u8; 32]> = send_indices
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

    // Send directly to the target node with a 5-second timeout.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        node.send_message_with_response(target, &msg),
    )
    .await;

    match result {
        Ok(Ok(Some(PulseMessage::DirectPaymentResponse(dpr)))) => {
            if dpr.accepted {
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
        Ok(Err(e)) => {
            let mut s = state.lock().unwrap();
            if let Some(ref mut ws) = s.wallet {
                ws.billfold.release(&sent_mints);
                s.flush_wallet();
            }
            RpcResponse::err(format!("direct send failed: {e}"))
        }
        Err(_) => {
            let mut s = state.lock().unwrap();
            if let Some(ref mut ws) = s.wallet {
                ws.billfold.release(&sent_mints);
                s.flush_wallet();
            }
            RpcResponse::err("direct send timed out (5s) — recipient node may be unreachable")
        }
    }
}

fn handle_wallet_unlock(
    state: &Arc<Mutex<ArteryState>>,
    password: &str,
    oc_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipClaim>,
) -> RpcResponse {
    use vess_kloak::billfold::SpendCredential;
    use vess_kloak::payment::receive_and_claim;

    // 1. Get wallet_path (set from config even when wallet is locked).
    let wallet_path = {
        let s = state.lock().unwrap();
        match &s.wallet_path {
            Some(p) => p.clone(),
            None => {
                return RpcResponse::err("no wallet path configured — start node with --wallet")
            }
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

    // Derive stealth keys and encryption key from raw_seed.
    let (stealth_secret, _address) = vess_stealth::generate_master_keys_from_seed(&raw_seed);
    let enc_key = vess_kloak::recovery::encryption_key_from_seed(&raw_seed);

    // Load billfold and decrypt spend credentials into it.
    let mut billfold = wallet.billfold.clone();
    if let Err(e) = wallet.decrypt_spend_credentials_into(&mut billfold, &enc_key) {
        tracing::warn!(error = %e, "failed to decrypt spend credentials on unlock");
    }

    // 4. Set wallet state + sweep limbo.
    let mut s = state.lock().unwrap();
    s.wallet = Some(WalletState {
        stealth_secret: stealth_secret.clone(),
        billfold,
        wallet_path: wallet_path.clone(),
        enc_key,
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
        for claim in pending_claims {
            let _ = oc_tx.send(claim);
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

    let balance = s.wallet.as_ref().map(|w| w.billfold.balance()).unwrap_or(0);
    let bill_count = s
        .wallet
        .as_ref()
        .map(|w| w.billfold.bills().len())
        .unwrap_or(0);

    RpcResponse::ok(RpcData::Balance {
        balance,
        bill_count,
    })
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

    // Store in local tag DHT.
    s.tag_dht.store(record);

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

#[allow(clippy::too_many_arguments)]
fn handle_ownership_genesis(
    _state: &Arc<Mutex<ArteryState>>,
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

    let _ = og_tx.send(vess_protocol::OwnershipGenesis {
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

    // Store locally.
    s.manifest_store.insert(dht_key, encrypted_manifest.clone());

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

