//! Vess artery RPC — JSON-line over TCP.
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use vess_foundry::Vess;
use crate::node_runner::{NodeState, spawn_miner};

#[derive(Debug, Serialize, Deserialize)] pub struct RpcRequest { pub method: String, pub params: serde_json::Value }
#[derive(Debug, Serialize)] pub struct RpcResponse { pub ok: bool, pub data: serde_json::Value }

pub fn handle_rpc(state: &Arc<Mutex<NodeState>>, og_tx: &mpsc::UnboundedSender<Vess>, req: RpcRequest) -> RpcResponse {
    match req.method.as_str() {
        "mine_start" => mine_start(state, og_tx, req.params),
        "mine_stop" => mine_stop(state),
        "mine_status" => mine_status(state),
        "balance" => balance(state),
        "send" => send(state, req.params),
        "list" => list(state),
        _ => RpcResponse { ok: false, data: serde_json::json!({"error":"unknown"}) },
    }
}

fn mine_start(state: &Arc<Mutex<NodeState>>, og_tx: &mpsc::UnboundedSender<Vess>, params: serde_json::Value) -> RpcResponse {
    let amount = params.get("amount").and_then(|v| v.as_u64()).unwrap_or(1);
    let mut s = state.lock().unwrap();
    if s.mining.is_some() { return RpcResponse { ok: false, data: serde_json::json!({"error":"already mining"}) }; }
    let pk = match &s.wallet_vk { Some(vk) => vess_foundry::spend_auth::vk_hash(vk), None => { let (vk,sk)=vess_foundry::spend_auth::generate_spend_keypair(); let h=vess_foundry::spend_auth::vk_hash(&vk); s.wallet_vk=Some(vk); s.wallet_sk=Some(sk); h } };
    let epoch = s.current_epoch;
    drop(s);
    spawn_miner(state.clone(), amount, pk, og_tx.clone());
    RpcResponse { ok: true, data: serde_json::json!({"message":"started","amount":amount,"epoch":epoch}) }
}

fn mine_stop(state: &Arc<Mutex<NodeState>>) -> RpcResponse {
    let mut s = state.lock().unwrap();
    match s.mining.take() { Some(ms) => { if let Some(tx)=ms.stop_tx { let _=tx.send(()); } RpcResponse{ok:true,data:serde_json::json!({"message":"stopped"})} } None => RpcResponse{ok:false,data:serde_json::json!({"error":"not mining"})} }
}

fn mine_status(state: &Arc<Mutex<NodeState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    match &s.mining { Some(ms) => RpcResponse{ok:true,data:serde_json::json!({"active":true,"amount":ms.amount,"epoch":s.current_epoch,"seconds":now-ms.started_at})}, None => RpcResponse{ok:true,data:serde_json::json!({"active":false,"amount":0,"epoch":s.current_epoch})} }
}

fn balance(state: &Arc<Mutex<NodeState>>) -> RpcResponse {
    let s = state.lock().unwrap(); let mut t=0u64; let mut c=0usize; let mut m=0usize; let mut ch=0usize;
    for v in s.store.iter() { t+=v.amount; c+=1; if v.is_mined(){m+=1;} if v.is_changed(){ch+=1;} }
    RpcResponse { ok: true, data: serde_json::json!({"total":t,"count":c,"mined":m,"changed":ch}) }
}

fn send(state: &Arc<Mutex<NodeState>>, params: serde_json::Value) -> RpcResponse {
    let amount = params.get("amount").and_then(|v|v.as_u64()).unwrap_or(0);
    let vk_hex = params.get("recipient_vk").and_then(|v|v.as_str()).unwrap_or("");
    if amount==0||vk_hex.is_empty() { return RpcResponse{ok:false,data:serde_json::json!({"error":"need amount+recipient_vk"})}; }
    let rvk = match hex::decode(vk_hex) { Ok(v)=>v, Err(_)=>return RpcResponse{ok:false,data:serde_json::json!({"error":"bad vk hex"})} };
    match crate::payment_builder::build_payment(state, amount, &rvk) {
        Ok((pay,change)) => { let pid=hex::encode(&pay.compute_vess_id()[..8]); let mut s=state.lock().unwrap(); s.store.upsert(&pay); if let Some(ref c)=change { s.store.upsert(c); } drop(s); RpcResponse{ok:true,data:serde_json::json!({"payment_id":pid,"amount":amount,"change":change.map(|c|c.amount).unwrap_or(0)})} }
        Err(e) => RpcResponse{ok:false,data:serde_json::json!({"error":e})},
    }
}

fn list(state: &Arc<Mutex<NodeState>>) -> RpcResponse {
    let s = state.lock().unwrap();
    let items: Vec<serde_json::Value> = s.store.iter().map(|v| serde_json::json!({"id":hex::encode(&v.compute_vess_id()[..8]),"amount":v.amount,"depth":v.chain_depth,"mined":v.is_mined(),"epoch":v.epoch})).collect();
    RpcResponse { ok: true, data: serde_json::json!({"vess":items,"count":items.len()}) }
}