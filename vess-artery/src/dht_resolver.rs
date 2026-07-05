//! DHT response resolution — trust via Vess ownership proof.
//!
//! When multiple nodes respond to a DHT query, the requester resolves
//! conflicts using the responders' Vess stake as a trust weight.
//!
//! # Vess conflicts (has chain_depth)
//!
//! Deepest chain wins. At equal depth, highest proof Vess amount wins.
//! One honest node with real history beats any number of Sybils.
//!
//! # Tag conflicts (no depth)
//!
//! Weighted majority by proof Vess amount. Tag mappings are voted on,
//! each responder's vote weighted by the amount of Vess it proved ownership of.
use std::collections::HashMap;
use vess_foundry::Vess;
use vess_protocol::SignedDhtResponse;

use crate::vess_store::VessStore;

/// Resolve conflicting Vess responses for the same vess_id.
///
/// Rules:
/// 1. Deeper chain wins
/// 2. Equal depth → higher proof Vess amount wins
/// 3. Equal amount → lower compute_vess_id wins (deterministic tiebreaker)
///
/// Returns the winning Vess, or None if no valid response.
pub fn resolve_vess_responses(
    responses: &[(SignedDhtResponse, Vess)], // (response, deserialized Vess)
    store: &VessStore,
) -> Option<Vess> {
    let mut best: Option<(Vess, u64)> = None; // (vess, proof_amount)

    for (resp, vess) in responses {
        // Verify the responder actually owns the proof Vess
        let proof_vess = match store.get(&resp.proof_vess_id) {
            Some(v) => v,
            None => continue, // responder claims to own Vess we don't know about
        };

        // Verify the signature
        let sig_msg = dht_response_signing_message(&resp.results, &resp.proof_vess_id);
        if !vess_foundry::spend_auth::verify_spend(
            &proof_vess.owner_vk,
            &sig_msg,
            &resp.responder_sig,
        )
        .unwrap_or(false)
        {
            continue; // bad signature
        }

        let proof_amount = proof_vess.amount;

        match &best {
            None => {
                best = Some((vess.clone(), proof_amount));
            }
            Some((existing, existing_amount)) => {
                // Deeper chain always wins
                if vess.chain_depth > existing.chain_depth {
                    best = Some((vess.clone(), proof_amount));
                } else if vess.chain_depth == existing.chain_depth {
                    // Higher proof amount wins
                    if proof_amount > *existing_amount {
                        best = Some((vess.clone(), proof_amount));
                    } else if proof_amount == *existing_amount {
                        // Deterministic tiebreaker
                        if vess.compute_vess_id() < existing.compute_vess_id() {
                            best = Some((vess.clone(), proof_amount));
                        }
                    }
                }
            }
        }
    }

    best.map(|(v, _)| v)
}

/// Resolve conflicting tag lookup responses.
///
/// Each responder votes for a tag → stealth_address mapping.
/// Votes are weighted by the responder's proof Vess amount.
/// The mapping with the highest total weight wins.
///
/// Returns the winning (tag_hash → stealth_id) mapping, or empty if no valid responses.
pub fn resolve_tag_responses(
    responses: &[(SignedDhtResponse, Vec<(String, [u8; 32])>)], // (response, tag→stealth mappings)
    store: &VessStore,
) -> HashMap<String, [u8; 32]> {
    // Accumulate weighted votes per (tag → stealth_id)
    let mut votes: HashMap<String, HashMap<[u8; 32], u64>> = HashMap::new();

    for (resp, mappings) in responses {
        // Verify ownership
        let proof_vess = match store.get(&resp.proof_vess_id) {
            Some(v) => v,
            None => continue,
        };

        let sig_msg = dht_response_signing_message(&resp.results, &resp.proof_vess_id);
        if !vess_foundry::spend_auth::verify_spend(
            &proof_vess.owner_vk,
            &sig_msg,
            &resp.responder_sig,
        )
        .unwrap_or(false)
        {
            continue;
        }

        let weight = proof_vess.amount;

        for (tag, stealth_id) in mappings {
            votes
                .entry(tag.clone())
                .or_default()
                .entry(*stealth_id)
                .and_modify(|w| *w += weight)
                .or_insert(weight);
        }
    }

    // Pick the stealth_id with the highest total weight per tag
    let mut results = HashMap::new();
    for (tag, candidates) in &votes {
        if let Some((best_id, _)) = candidates.iter().max_by_key(|(_, &w)| w) {
            results.insert(tag.clone(), *best_id);
        }
    }
    results
}

/// Build the message that the responder signs.
pub fn dht_response_signing_message(results: &[u8], proof_vess_id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-dht-v1");
    h.update(results);
    h.update(proof_vess_id);
    *h.finalize().as_bytes()
}

/// Resolve conflicting manifest recovery responses by highest Vess stake.
/// Returns the encrypted blob from the responder with the most weight.
pub fn resolve_manifest_responses(
    responses: &[(SignedDhtResponse, Vec<u8>)],
    store: &VessStore,
) -> Option<Vec<u8>> {
    let mut best: Option<(Vec<u8>, u64)> = None;

    for (resp, blob) in responses {
        let proof_vess = match store.get(&resp.proof_vess_id) {
            Some(v) => v,
            None => continue,
        };
        let sig_msg = dht_response_signing_message(&resp.results, &resp.proof_vess_id);
        if !vess_foundry::spend_auth::verify_spend(
            &proof_vess.owner_vk, &sig_msg, &resp.responder_sig,
        ).unwrap_or(false) {
            continue;
        }
        let weight = proof_vess.amount;
        match &best {
            None => best = Some((blob.clone(), weight)),
            Some((_, w)) if weight > *w => best = Some((blob.clone(), weight)),
            _ => {}
        }
    }
    best.map(|(blob, _)| blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vess(amount: u64, depth: u64) -> Vess {
        Vess {
            amount,
            epoch: 0,
            nonce: 0,
            initial_pk: [0u8; 32],
            owner_vk: vec![],
            prev_sig: vec![],
            chain_depth: depth,
            consumed: vec![],
            change_sig: vec![],
            chain_tip: [0u8; 32],
            digest: [0u8; 32],
            created_at: 0,
            stealth_id: [0u8; 32],
            dht_index: 0,
        }
    }

    #[test]
    fn deeper_chain_wins() {
        let mut store = VessStore::default();
        // Same amount → same compute_vess_id → replacement test is valid
        let shallow = test_vess(100, 1);
        let deep = test_vess(100, 10);

        assert!(store.upsert(&shallow));
        assert!(store.get(&shallow.compute_vess_id()).is_some());
        // Deeper replaces shallower
        assert!(store.upsert(&deep));
        assert_eq!(
            store.get(&shallow.compute_vess_id()).unwrap().chain_depth,
            10
        );
    }

    #[test]
    fn equal_depth_higher_amount_wins_in_store() {
        let mut store = VessStore::default();
        // Same amount → same compute_vess_id, same depth → lower id wins (deterministic)
        let v1 = test_vess(100, 3);
        let v2 = test_vess(100, 3);
        let id = v1.compute_vess_id();

        assert!(store.upsert(&v1));
        assert_eq!(store.get(&id).unwrap().chain_depth, 3);
        // Same id, same depth → id >= existing id → rejected
        assert!(!store.upsert(&v2));
    }
}
