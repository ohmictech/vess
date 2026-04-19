//! Tag resolution with quorum verification.
//!
//! When a wallet wants to pay `+bob15`, it must resolve the tag to a
//! [`MasterStealthAddress`]. To prevent a single malicious node from
//! lying about the association, the resolver queries **multiple** artery
//! nodes and requires a **quorum** of matching responses.
//!
//! # Protocol
//!
//! 1. Wallet sends `TagLookup { tag, nonce }` to N different artery nodes.
//! 2. Each node replies with `TagLookupResponse` containing the registration
//!    record (or None if unknown).
//! 3. Wallet collects responses and requires at least `QUORUM_THRESHOLD`
//!    identical `(scan_ek, spend_ek)` pairs from **distinct** nodes.
//! 4. On success, the verified association is returned and can be cached
//!    permanently by the wallet.
//!
//! No single node—nor any minority coalition—can forge a tag association.

use std::collections::HashMap;
use vess_stealth::MasterStealthAddress;
use vess_protocol::TagLookupResponse;

/// Minimum number of distinct matching responses required to trust a
/// tag → address association. Five nodes must independently agree.
pub const QUORUM_THRESHOLD: usize = 5;

/// Outcome of a quorum-verified tag resolution attempt.
#[derive(Debug, Clone)]
pub enum TagResolution {
    /// Quorum reached: at least `QUORUM_THRESHOLD` nodes returned the
    /// same `(scan_ek, spend_ek)`. The association is trustworthy.
    Verified {
        address: MasterStealthAddress,
        confirming_nodes: usize,
        registered_at: u64,
    },
    /// Not enough responses yet. Call [`TagResolver::add_response`] with more.
    Pending {
        responses_so_far: usize,
    },
    /// Multiple conflicting records exist — possible attack or race.
    Conflict {
        variants: usize,
    },
    /// All responding nodes returned "not found".
    NotFound,
}

/// Collects `TagLookupResponse` messages from multiple nodes and
/// determines whether quorum has been reached.
pub struct TagResolver {
    /// Node ID → response. Deduplicates by node.
    responses: HashMap<[u8; 32], Option<ResponseKey>>,
    /// Count per unique `(scan_ek, spend_ek)` fingerprint.
    fingerprint_counts: HashMap<[u8; 32], (MasterStealthAddress, u64, usize)>,
}

/// Blake3 fingerprint of a `(scan_ek, spend_ek)` pair, used for grouping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResponseKey([u8; 32]);

impl ResponseKey {
    fn from_keys(scan_ek: &[u8], spend_ek: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(scan_ek);
        h.update(spend_ek);
        Self(*h.finalize().as_bytes())
    }
}

impl Default for TagResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl TagResolver {
    /// Create a new resolver for a single tag lookup operation.
    pub fn new() -> Self {
        Self {
            responses: HashMap::new(),
            fingerprint_counts: HashMap::new(),
        }
    }

    /// Add a response from a node. Returns the current resolution state.
    ///
    /// `node_id` must be unique per node — duplicate responses from the
    /// same node are ignored (no double-counting).
    pub fn add_response(
        &mut self,
        node_id: [u8; 32],
        response: &TagLookupResponse,
    ) -> TagResolution {
        // Deduplicate by node ID.
        if self.responses.contains_key(&node_id) {
            return self.evaluate();
        }

        match &response.result {
            None => {
                self.responses.insert(node_id, None);
            }
            Some(result) => {
                let key = ResponseKey::from_keys(&result.scan_ek, &result.spend_ek);
                self.responses.insert(node_id, Some(key.clone()));

                let entry = self.fingerprint_counts
                    .entry(key.0)
                    .or_insert_with(|| {
                        let addr = MasterStealthAddress {
                            scan_ek: result.scan_ek.clone(),
                            spend_ek: result.spend_ek.clone(),
                        };
                        (addr, result.registered_at, 0)
                    });
                entry.2 += 1;
            }
        }

        self.evaluate()
    }

    /// Total number of distinct nodes that have responded.
    pub fn response_count(&self) -> usize {
        self.responses.len()
    }

    /// Evaluate the current state of collected responses.
    fn evaluate(&self) -> TagResolution {
        if self.fingerprint_counts.is_empty() {
            if self.responses.is_empty() {
                return TagResolution::Pending { responses_so_far: 0 };
            }
            // All responses were "not found".
            return TagResolution::NotFound;
        }

        // Find the fingerprint with the most confirmations.
        let best = self.fingerprint_counts.values()
            .max_by_key(|(_, _, count)| *count)
            .unwrap();

        if best.2 >= QUORUM_THRESHOLD {
            return TagResolution::Verified {
                address: best.0.clone(),
                confirming_nodes: best.2,
                registered_at: best.1,
            };
        }

        if self.fingerprint_counts.len() > 1 {
            return TagResolution::Conflict {
                variants: self.fingerprint_counts.len(),
            };
        }

        TagResolution::Pending {
            responses_so_far: self.responses.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_protocol::TagLookupResult;

    fn make_response(scan_ek: &[u8], spend_ek: &[u8], tag: &str) -> TagLookupResponse {
        TagLookupResponse {
            tag_hash: *blake3::hash(tag.as_bytes()).as_bytes(),
            nonce: [0u8; 16],
            result: Some(TagLookupResult {
                scan_ek: scan_ek.to_vec(),
                spend_ek: spend_ek.to_vec(),
                registered_at: 1000,
                registrant_vk: Vec::new(),
                signature: Vec::new(),
                pow_nonce: [0u8; 32],
                pow_hash: Vec::new(),
            }),
        }
    }

    fn not_found_response(tag: &str) -> TagLookupResponse {
        TagLookupResponse {
            tag_hash: *blake3::hash(tag.as_bytes()).as_bytes(),
            nonce: [0u8; 16],
            result: None,
        }
    }

    #[test]
    fn quorum_reached_after_5_matching() {
        let mut resolver = TagResolver::new();
        let scan = vec![0x11; 64];
        let spend = vec![0x22; 64];
        let resp = make_response(&scan, &spend, "bob15");

        for i in 0..4u8 {
            let node_id = [i; 32];
            let result = resolver.add_response(node_id, &resp);
            assert!(matches!(result, TagResolution::Pending { .. }));
        }

        // 5th node tips quorum.
        let result = resolver.add_response([4u8; 32], &resp);
        match result {
            TagResolution::Verified { confirming_nodes, .. } => {
                assert_eq!(confirming_nodes, 5);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_node_id_not_counted() {
        let mut resolver = TagResolver::new();
        let resp = make_response(&[0x11; 64], &[0x22; 64], "alice");

        // Same node responds 10 times — only counts as 1.
        for _ in 0..10 {
            resolver.add_response([0x01; 32], &resp);
        }
        assert_eq!(resolver.response_count(), 1);
        assert!(matches!(resolver.add_response([0x01; 32], &resp), TagResolution::Pending { .. }));
    }

    #[test]
    fn conflict_detected_with_different_keys() {
        let mut resolver = TagResolver::new();
        let resp_a = make_response(&[0x11; 64], &[0x22; 64], "tag");
        let resp_b = make_response(&[0x33; 64], &[0x44; 64], "tag");

        resolver.add_response([0x01; 32], &resp_a);
        let result = resolver.add_response([0x02; 32], &resp_b);
        match result {
            TagResolution::Conflict { variants } => assert_eq!(variants, 2),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn all_not_found() {
        let mut resolver = TagResolver::new();
        let resp = not_found_response("unknown");

        resolver.add_response([0x01; 32], &resp);
        resolver.add_response([0x02; 32], &resp);
        let result = resolver.add_response([0x03; 32], &resp);
        assert!(matches!(result, TagResolution::NotFound));
    }

    #[test]
    fn quorum_with_some_not_found() {
        let mut resolver = TagResolver::new();
        let scan = vec![0x11; 64];
        let spend = vec![0x22; 64];
        let good = make_response(&scan, &spend, "bob");
        let none = not_found_response("bob");

        // 3 nodes don't have it.
        for i in 0..3u8 {
            resolver.add_response([i; 32], &none);
        }
        // 5 nodes do.
        for i in 10..15u8 {
            resolver.add_response([i; 32], &good);
        }

        let result = resolver.add_response([0xFF; 32], &good);
        match result {
            TagResolution::Verified { confirming_nodes, .. } => {
                assert!(confirming_nodes >= 5);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }
}
