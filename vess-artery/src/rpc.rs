//! Vess artery RPC — JSON-line over TCP.
//!
//! Each connection sends one JSON request per line: `{"method":"...","params":{...}}\n`.
//! The server responds with one JSON line: `{"ok":true,"data":{...}}\n` or `{"ok":false,"data":{"error":"..."}}\n`.

use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use vess_foundry::Vess;
use crate::node_runner::ArteryState;

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest { pub method: String, pub params: serde_json::Value }

#[derive(Debug, Serialize)]
pub struct RpcResponse { pub ok: bool, pub data: serde_json::Value }

#[derive(Debug, Clone)]
pub struct QueueSenders {
    pub og_tx: mpsc::UnboundedSender<Vess>,
}

pub fn run_rpc_server(_state: Arc<Mutex<ArteryState>>, _senders: QueueSenders) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async { /* legacy stub */ })
}

pub fn wallet_tag_store(_state: &Arc<Mutex<ArteryState>>) {}

pub fn fire_opportunistic_consolidations(_state: &Arc<Mutex<ArteryState>>) {}

pub fn handle_rpc(state: &Arc<Mutex<ArteryState>>, og_tx: &mpsc::UnboundedSender<Vess>, req: RpcRequest) -> RpcResponse {
    match req.method.as_str() {
        "add_peer" => rpc_add_peer(state, &req.params),
        "list_peers" => rpc_list_peers(state),
        "remove_peer" => rpc_remove_peer(state, &req.params),
        "ban_peer" => rpc_ban_peer(state, &req.params),
        "status" => rpc_status(state),
        "balance" => rpc_balance(state),
        "receive" => rpc_receive(state),
        "send" => rpc_send(state, og_tx, &req.params),
        "mine_start" => rpc_mine_start(state, og_tx, &req.params),
        "mine_stop" => rpc_mine_stop(state),
        "mine_status" => rpc_mine_status(state),
        "tag_register" => rpc_tag_register(state, &req.params),
        "tag_lookup" => rpc_tag_lookup(state, &req.params),
        "faucet_submit" => rpc_faucet_submit(state, &req.params),
        "manifest_push" => rpc_manifest_push(state),
        "mailbox_sweep" => rpc_mailbox_sweep(state, &req.params),
        "mailbox_register" => rpc_mailbox_register(state, &req.params),
        "send_onion" => rpc_send_onion(state, og_tx, &req.params),
        _ => RpcResponse { ok: false, data: serde_json::json!({"error": format!("unknown method: {}", req.method)}) },
    }
}

// ── Peer management ─────────────────────────────────────────────────

fn rpc_add_peer(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    let contact_str = params["contact"].as_str().unwrap_or("");
    if contact_str.is_empty() {
        return RpcResponse { ok: false, data: serde_json::json!({"error": "missing contact"}) };
    }
    match vess_mesh::decode_mesh_contact_string(contact_str) {
        Ok(contact) => {
            if let Some(id) = contact.node_id().map(|n| *n.as_bytes()) {
                let mut s = state.lock().unwrap();
                if s.banned_peers.contains(&id) {
                    return RpcResponse { ok: false, data: serde_json::json!({"error": "peer is banned"}) };
                }
                if id == s.node_id {
                    return RpcResponse { ok: false, data: serde_json::json!({"error": "cannot add self"}) };
                }
                s.known_peers.insert(id);
                s.peer_endpoints.insert(id, contact_str.to_string());
                RpcResponse { ok: true, data: serde_json::json!({"peer_id": hex::encode(&id[..8])}) }
            } else {
                RpcResponse { ok: false, data: serde_json::json!({"error": "invalid contact"}) }
            }
        }
        Err(e) => RpcResponse { ok: false, data: serde_json::json!({"error": format!("invalid contact: {e}")}) },
    }
}

fn rpc_list_peers(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    let peers: Vec<serde_json::Value> = s.peer_endpoints.iter().map(|(id, ep)| {
        serde_json::json!({"node_id": hex::encode(&id[..8]), "contact": ep})
    }).collect();
    RpcResponse { ok: true, data: serde_json::json!({"peers": peers, "count": peers.len()}) }
}

fn rpc_remove_peer(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    match decode_peer_id(params) {
        Some(key) => {
            let mut s = state.lock().unwrap();
            s.known_peers.remove(&key);
            s.peer_endpoints.remove(&key);
            RpcResponse { ok: true, data: serde_json::json!({"removed": true}) }
        }
        None => RpcResponse { ok: false, data: serde_json::json!({"error": "invalid node_id"}) },
    }
}

fn rpc_ban_peer(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    match decode_peer_id(params) {
        Some(key) => {
            let mut s = state.lock().unwrap();
            s.known_peers.remove(&key);
            s.peer_endpoints.remove(&key);
            s.banned_peers.insert(key);
            RpcResponse { ok: true, data: serde_json::json!({"banned": true}) }
        }
        None => RpcResponse { ok: false, data: serde_json::json!({"error": "invalid node_id"}) },
    }
}

fn decode_peer_id(params: &serde_json::Value) -> Option<[u8; 32]> {
    let hex_str = params["node_id"].as_str()?;
    let decoded = hex::decode(hex_str).ok()?;
    let mut key = [0u8; 32];
    let len = decoded.len().min(32);
    key[..len].copy_from_slice(&decoded[..len]);
    Some(key)
}

// ── Status ──────────────────────────────────────────────────────────

fn rpc_status(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    RpcResponse { ok: true, data: serde_json::json!({
        "node_id": hex::encode(&s.node_id[..8]),
        "peer_count": s.known_peers.len(),
        "epoch": vess_foundry::clock::current_epoch(),
        "bills_stored": s.store.len(),
        "mining": s.mining.is_some(),
    })}
}

// ── Wallet ───────────────────────────────────────────────────────────

fn rpc_balance(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    let owner_hash = s.wallet_vk.as_ref().map(|vk| vess_foundry::spend_auth::vk_hash(vk));
    let total: u64 = match owner_hash {
        Some(h) => s.store.iter().filter(|v| v.owner_vk_hash() == h).map(|v| v.amount).sum(),
        None => 0,
    };
    RpcResponse { ok: true, data: serde_json::json!({"total": total}) }
}

fn rpc_receive(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    let mut tag: Option<String> = None;
    if let Some(ref vk) = s.wallet_vk {
        let addr_fp = {
            let mut h = blake3::Hasher::new();
            h.update(vk);
            *h.finalize().as_bytes()
        };
        if let Some(record) = s.tag_dht.lookup_by_address(&addr_fp) {
            tag = Some(hex::encode(&record.tag_hash[..4]));
        }
    }
    RpcResponse { ok: true, data: serde_json::json!({"tag": tag}) }
}

// ── Send ─────────────────────────────────────────────────────────────

fn rpc_send(state: &Arc<Mutex<ArteryState>>, og_tx: &mpsc::UnboundedSender<Vess>, params: &serde_json::Value) -> RpcResponse {
    let amount: u64 = match params["amount"].as_u64() {
        Some(a) if a > 0 => a,
        _ => return RpcResponse { ok: false, data: serde_json::json!({"error": "invalid amount"}) },
    };
    let recipient = params["recipient"].as_str().unwrap_or("");
    let tag_clean = recipient.trim_start_matches('+');

    let tag_hash = {
        let mut h = blake3::Hasher::new();
        h.update(tag_clean.as_bytes());
        *h.finalize().as_bytes()
    };
    let (recipient_addr, recipient_spend_ek) = {
        let s = state.lock().unwrap();
        match s.tag_dht.lookup(tag_clean) {
            Some(r) => (r.master_address.clone(), r.master_address.spend_ek.clone()),
            None => return RpcResponse { ok: false, data: serde_json::json!({"error": format!("tag not found: {recipient}")}) },
        }
    };

    let built = match crate::payment_builder::build_payment_ephemeral(state, amount) {
        Ok(b) => b,
        Err(e) => return RpcResponse { ok: false, data: serde_json::json!({"error": format!("{e}")}) },
    };

    let payment_bytes = match serde_json::to_vec(&built.payment) {
        Ok(b) => b,
        Err(e) => return RpcResponse { ok: false, data: serde_json::json!({"error": format!("serialize: {e}")}) },
    };
    let stealth = match vess_stealth::prepare_stealth_payload(&recipient_addr, &payment_bytes) {
        Ok(s) => s,
        Err(e) => return RpcResponse { ok: false, data: serde_json::json!({"error": format!("stealth: {e}")}) },
    };

    // Derive epoch-rotating mailbox key for recipient privacy.
    // Pre-hash the spend_ek so raw key bytes never enter the outer hash.
    let current_epoch = vess_foundry::clock::current_epoch();
    let spend_ek_hash = blake3::hash(&recipient_spend_ek);
    let mailbox_key = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-mailbox-v2");
        h.update(spend_ek_hash.as_bytes());
        h.update(&current_epoch.to_le_bytes());
        *h.finalize().as_bytes()
    };

    let payment_id = stealth.stealth_id;
    let now = crate::node_runner::now_secs();
    let bill_id = built.payment.compute_vess_id();
    let node_id = {
        let s = state.lock().unwrap();
        s.node_id
    };

    // Build protocol Payment for limbo storage
    let payment = vess_protocol::Payment {
        payment_id,
        stealth_payload: serde_json::to_vec(&stealth).unwrap_or_default(),
        view_tag: stealth.view_tag,
        stealth_id: stealth.stealth_id,
        created_at: now,
        bill_count: 1,
        mailbox_key: Some(mailbox_key),
        direct_receipt_tag_hash: Some(tag_hash),
        hash_lock: None,
    };

    {
        let mut s = state.lock().unwrap();
        s.store.upsert(&built.payment);
        if let Some(ref change) = built.change {
            s.store.upsert(change);
        }
        // Hold in limbo for offline recipient
        s.limbo.hold(
            stealth.stealth_id,
            payment,
            vec![bill_id],
            now,
            node_id,
            Some(mailbox_key),
        );
        s.notify(&format!("sent {} Vess to {}", amount, recipient));
    }

    let _ = og_tx.send(built.payment);

    RpcResponse { ok: true, data: serde_json::json!({
        "payment_id": hex::encode(&payment_id),
        "amount": amount,
        "recipient": recipient,
        "mailbox_key": hex::encode(&mailbox_key[..8]),
    })}
}

// ── Mining ───────────────────────────────────────────────────────────

fn rpc_mine_start(state: &Arc<Mutex<ArteryState>>, og_tx: &mpsc::UnboundedSender<Vess>, params: &serde_json::Value) -> RpcResponse {
    let amount = params["amount"].as_u64().unwrap_or(100);
    let initial_pk = {
        let s = state.lock().unwrap();
        if s.mining.is_some() {
            return RpcResponse { ok: false, data: serde_json::json!({"error": "already mining"}) };
        }
        match &s.wallet_vk {
            Some(vk) => vess_foundry::spend_auth::vk_hash(vk),
            None => return RpcResponse { ok: false, data: serde_json::json!({"error": "no wallet loaded"}) },
        }
    };

    // Spawn the actual miner thread
    crate::node_runner::spawn_miner(state.clone(), amount, initial_pk, og_tx.clone());

    RpcResponse { ok: true, data: serde_json::json!({"message": "mining started", "amount": amount}) }
}

fn rpc_mine_stop(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let mut s = state.lock().unwrap();
    if let Some(ref mut mining) = s.mining {
        if let Some(tx) = mining.stop_tx.take() {
            let _ = tx.send(());
        }
    }
    s.mining = None;
    RpcResponse { ok: true, data: serde_json::json!({"message": "mining stopped"}) }
}

fn rpc_mine_status(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    if let Some(ref mining) = s.mining {
        let elapsed = crate::node_runner::now_secs().saturating_sub(mining.started_at);
        RpcResponse { ok: true, data: serde_json::json!({"active": true, "amount": mining.amount, "seconds": elapsed}) }
    } else {
        RpcResponse { ok: true, data: serde_json::json!({"active": false}) }
    }
}

// ── Tag ──────────────────────────────────────────────────────────────

fn rpc_tag_register(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    let tag_str = params["tag"].as_str().unwrap_or("");
    if tag_str.is_empty() {
        return RpcResponse { ok: false, data: serde_json::json!({"error": "missing tag"}) };
    }
    let tag_clean = tag_str.trim_start_matches('+');

    let vtag = match vess_tag::VessTag::new(tag_clean) {
        Ok(t) => t,
        Err(e) => return RpcResponse { ok: false, data: serde_json::json!({"error": format!("{e}")}) },
    };

    let mut s = state.lock().unwrap();
    let (wallet_vk, _wallet_sk) = match (&s.wallet_vk, &s.wallet_sk) {
        (Some(vk), Some(sk)) => (vk.clone(), sk.clone()),
        _ => return RpcResponse { ok: false, data: serde_json::json!({"error": "no wallet loaded"}) },
    };

    let tag_hash = vtag.dht_key();
    if s.tag_dht.lookup_by_hash(&tag_hash).is_some() {
        return RpcResponse { ok: false, data: serde_json::json!({"error": "tag already registered"}) };
    }

    let addr_fp = {
        let mut h = blake3::Hasher::new();
        h.update(&wallet_vk);
        *h.finalize().as_bytes()
    };
    if s.tag_dht.has_address(&addr_fp) {
        return RpcResponse { ok: false, data: serde_json::json!({"error": "this wallet already has a tag"}) };
    }

    let (_, master_address) = vess_stealth::generate_master_keys();
    let record = vess_tag::TagRecord {
        tag_hash,
        master_address,
        pow_nonce: [0u8; 32],
        pow_hash: vec![0u8; 32],
        registered_at: crate::node_runner::now_secs(),
        registrant_vk: wallet_vk,
        signature: vec![],
        hardened_at: None,
        grace_until_epoch: None, // set by store() to current_epoch + 30
    };

    if !s.tag_dht.store(record) {
        return RpcResponse { ok: false, data: serde_json::json!({"error": "failed to store tag"}) };
    }

    RpcResponse { ok: true, data: serde_json::json!({
        "tag": format!("+{}", tag_clean),
        "tag_hash": hex::encode(&tag_hash[..8]),
    })}
}

fn rpc_tag_lookup(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    let tag_str = params["tag"].as_str().unwrap_or("");
    if tag_str.is_empty() {
        return RpcResponse { ok: false, data: serde_json::json!({"error": "missing tag"}) };
    }
    let tag_clean = tag_str.trim_start_matches('+');

    let s = state.lock().unwrap();
    match s.tag_dht.lookup(tag_clean) {
        Some(record) => RpcResponse { ok: true, data: serde_json::json!({
            "tag": format!("+{}", tag_clean),
            "tag_hash": hex::encode(&record.tag_hash[..8]),
            "stealth_id": hex::encode(&record.master_address.spend_ek[..16]),
            "hardened": record.is_hardened(),
            "registered_at": record.registered_at,
        })},
        None => RpcResponse { ok: false, data: serde_json::json!({"error": "tag not found"}) },
    }
}

// ── Faucet ───────────────────────────────────────────────────────────

fn rpc_faucet_submit(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    let faucet: Vess = match serde_json::from_value(params["vess"].clone()) {
        Ok(v) => v,
        Err(e) => return RpcResponse { ok: false, data: serde_json::json!({"error": format!("invalid vess: {e}")}) },
    };
    if !faucet.is_faucet() {
        return RpcResponse { ok: false, data: serde_json::json!({"error": "not a faucet Vess"}) };
    }
    let current_epoch = vess_foundry::clock::current_epoch();
    if let Err(e) = vess_foundry::mine::verify_mined_vess(&faucet, current_epoch) {
        return RpcResponse { ok: false, data: serde_json::json!({"error": format!("{e}")}) };
    }
    let id = faucet.compute_vess_id();
    {
        let mut s = state.lock().unwrap();
        if s.store.is_consumed(&id) {
            return RpcResponse { ok: false, data: serde_json::json!({"error": "already consumed"}) };
        }
        s.store.upsert(&faucet);
    }
    RpcResponse { ok: true, data: serde_json::json!({
        "vess_id": hex::encode(&id[..8]),
        "amount": faucet.amount,
        "epoch": faucet.epoch,
    })}
}

// ── Manifest ─────────────────────────────────────────────────────────

fn rpc_manifest_push(state: &Arc<Mutex<ArteryState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    let seed_hash = match s.wallet_seed_hash {
        Some(h) => h,
        None => return RpcResponse { ok: false, data: serde_json::json!({"error": "no wallet seed hash set"}) },
    };
    if let Some(ref tx) = s.manifest_tx {
        let dht_key = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-wallet-manifest-v1");
            h.update(&seed_hash);
            *h.finalize().as_bytes()
        };
        let _ = tx.send(vess_protocol::ManifestStore {
            dht_key,
            encrypted_manifest: vec![],
            hops_remaining: 3,
        });
        RpcResponse { ok: true, data: serde_json::json!({"message": "manifest queued"}) }
    } else {
        RpcResponse { ok: false, data: serde_json::json!({"error": "manifest channel not available"}) }
    }
}

// ── Mailbox ──────────────────────────────────────────────────────────

fn rpc_mailbox_sweep(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    let key_hex = params["mailbox_key"].as_str().unwrap_or("");
    let key = match hex::decode(key_hex) {
        Ok(v) if v.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&v);
            k
        }
        _ => return RpcResponse { ok: false, data: serde_json::json!({"error": "invalid mailbox_key (need 32-byte hex)"}) },
    };

    let max = params["max"].as_u64().unwrap_or(64) as usize;
    let payloads = {
        let s = state.lock().unwrap();
        s.limbo.sweep_by_mailbox_key(&key, max)
    };

    let payloads_hex: Vec<String> = payloads.iter().map(|p| hex::encode(p)).collect();
    RpcResponse { ok: true, data: serde_json::json!({
        "count": payloads_hex.len(),
        "payloads": payloads_hex,
    })}
}

fn rpc_mailbox_register(state: &Arc<Mutex<ArteryState>>, params: &serde_json::Value) -> RpcResponse {
    let key_hex = params["mailbox_key"].as_str().unwrap_or("");
    let key = match hex::decode(key_hex) {
        Ok(v) if v.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&v);
            k
        }
        _ => return RpcResponse { ok: false, data: serde_json::json!({"error": "invalid mailbox_key (need 32-byte hex)"}) },
    };

    // Deliver any already-waiting payments for this mailbox
    let max = params["max"].as_u64().unwrap_or(64) as usize;
    let waiting = {
        let s = state.lock().unwrap();
        s.limbo.payments_by_mailbox_key(&key, max)
    };

    let waiting_hex: Vec<String> = waiting.iter().map(|p| hex::encode(&p.stealth_payload)).collect();
    RpcResponse { ok: true, data: serde_json::json!({
        "registered": true,
        "mailbox_key": key_hex,
        "waiting_payments": waiting_hex.len(),
        "payloads": waiting_hex,
    })}
}
