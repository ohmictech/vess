//! DHT query — send queries to 5 nearest peers, collect up to 5 signed responses.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use crate::node_runner::ArteryState;
use vess_protocol::{DhtQuery, DhtQueryKind, DhtQueryResponse};

/// Number of peers to fan-out to for DHT queries.
const QUERY_FANOUT: usize = 5;
/// Number of responses to collect (3s timeout each).
const QUERY_COLLECT: usize = 5;

/// Query the 5 nearest DHT peers via mesh and wait for up to 5 responses.
/// No local fallback — purely network-based DHT queries.
pub fn query_dht_peers(
    state: &Arc<Mutex<ArteryState>>,
    dht_key: &[u8; 32],
    kind: DhtQueryKind,
) -> Vec<DhtQueryResponse> {
    let nonce: [u8; 16] = rand::random();
    let query = DhtQuery { query_kind: kind.clone(), dht_key: *dht_key, nonce };

    // Register response channel (mpsc for multiple responses)
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DhtQueryResponse>();
    {
        let mut s = state.lock().unwrap();
        s.pending_queries.insert(nonce, tx);
    }

    // Send queries to the 5 nearest peers by XOR distance
    {
        let s = state.lock().unwrap();
        if let Some(ref mesh_tx) = s.mesh_outbox {
            let msg = vess_protocol::PulseMessage::DhtQuery(query);
            let mut ranked: Vec<([u8; 32], String)> = s.peer_endpoints.iter()
                .map(|(id, ep)| (*id, ep.clone())).collect();
            ranked.sort_by_key(|(id, _)| crate::gossip::xor_distance(id, dht_key));
            for (_, ep) in ranked.iter().take(QUERY_FANOUT) {
                if let Ok(contact) = vess_mesh::decode_mesh_contact_string(ep) {
                    let _ = mesh_tx.send((contact, msg.clone()));
                }
            }
        }
    }

    // Collect up to QUERY_COLLECT responses with proof verification (3s each)
    let mut results = Vec::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    for _ in 0..QUERY_COLLECT {
        match rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), rx.recv()).await
        }) {
            Ok(Some(resp)) => {
                if let Some(ref proof) = resp.proof {
                    if !verify_dht_proof(state, proof) {
                        continue;
                    }
                }
                results.push(resp);
            }
            _ => break,
        }
    }

    // Cleanup
    {
        let mut s = state.lock().unwrap();
        s.pending_queries.remove(&nonce);
    }

    results
}

/// Verify a SignedDhtResponse against the responder's claimed Vess ownership.
fn verify_dht_proof(state: &Arc<Mutex<ArteryState>>, proof: &vess_protocol::SignedDhtResponse) -> bool {
    let s = state.lock().unwrap();
    let proof_vess = match s.store.get(&proof.proof_vess_id) {
        Some(v) => v,
        None => return false,
    };
    let sig_msg = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-dht-v1");
        h.update(&proof.results);
        h.update(&proof.proof_vess_id);
        *h.finalize().as_bytes()
    };
    vess_foundry::spend_auth::verify_spend(&proof_vess.owner_vk, &sig_msg, &proof.responder_sig)
        .unwrap_or(false)
}
