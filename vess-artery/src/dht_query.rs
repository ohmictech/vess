//! DHT query helpers — query K nearest peers via mesh and collect local results.

use std::sync::{Arc, Mutex};
use crate::node_runner::ArteryState;
use vess_protocol::{DhtQuery, DhtQueryKind, DhtQueryResponse};

/// Query K nearest DHT peers for data. Returns local results immediately
/// and also sends queries to K peers via mesh (responses handled async).
pub fn query_dht_peers(
    state: &Arc<Mutex<ArteryState>>,
    dht_key: &[u8; 32],
    kind: DhtQueryKind,
) -> Vec<DhtQueryResponse> {
    let nonce: [u8; 16] = rand::random();

    // Send queries to K nearest peers via mesh
    {
        let s = state.lock().unwrap();
        if let Some(ref tx) = s.mesh_outbox {
            let msg = vess_protocol::PulseMessage::DhtQuery(DhtQuery {
                query_kind: kind.clone(), dht_key: *dht_key, nonce,
            });
            let repl = s.dht_replication();
            let mut ranked: Vec<([u8; 32], String)> = s.peer_endpoints.iter()
                .map(|(id, ep)| (*id, ep.clone())).collect();
            ranked.sort_by_key(|(id, _)| crate::gossip::xor_distance(id, dht_key));
            for (_, ep) in ranked.iter().take(repl) {
                if let Ok(contact) = vess_mesh::decode_mesh_contact_string(ep) {
                    let _ = tx.send((contact, msg.clone()));
                }
            }
        }
    }

    // Return local results
    let s = state.lock().unwrap();
    let mut tags = vec![];
    let mut payloads = vec![];
    let mut vess = vec![];
    match &kind {
        DhtQueryKind::TagLookup => {
            if let Some(record) = s.tag_dht.lookup_by_hash(dht_key) {
                tags.push(serde_json::to_vec(record).unwrap_or_default());
            }
        }
        DhtQueryKind::MailboxSweep => {
            payloads = s.limbo.sweep_by_mailbox_key(dht_key, 64);
        }
        DhtQueryKind::VessLookup => {
            if let Some(v) = s.store.get(dht_key) {
                vess.push(serde_json::to_vec(v).unwrap_or_default());
            }
        }
        _ => {}
    }

    vec![DhtQueryResponse { nonce, query_kind: kind, tags, payloads, vess, manifests: vec![] }]
}
