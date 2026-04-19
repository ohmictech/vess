//! **Ownership Registry** — DHT-distributed registry of active bill ownership.
//!
//! The registry tracks which `mint_id` values are currently active (have a
//! living owner). Double-spend protection is simple: if a mint_id is not
//! in the registry, it cannot be spent. When a bill is consumed (via
//! split/combine reforge), its mint_id is deleted from the registry.
//!
//! Each node only stores ownership records whose `mint_id` is close to the
//! node's own ID by XOR distance. The replication factor is
//! `max(20, network_size / 1000)`.
//!
//! Each record carries only a 32-byte `proof_hash` (Blake3, PQ-safe at
//! 128-bit quantum security via Grover's bound).  Full STARK proofs are
//! verified once at genesis time and then discarded — the hash is
//! sufficient to detect tampering if a proof is ever re-presented.
//!
//! A Blake3 Merkle tree over all locally-stored mint_ids provides a compact
//! commitment root for consistency checks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vess_foundry::merkle::MerkleTree;

use crate::gossip::xor_distance;

/// Dynamic DHT replication factor based on estimated network size.
///
/// Uses a square-root curve so the replication *percentage* decreases as
/// the network grows, enabling mass scaling while maintaining high
/// redundancy at small sizes:
///
/// | Network  | Replicas | % of network |
/// |----------|----------|--------------|
/// | 1 000    |       50 | 5.0%         |
/// | 1 000 000|    1 000 | 0.1%         |
/// | 1 000 000 000| 31 623 | 0.003%    |
///
/// Returns `max(50, √network_size)`.
pub fn dht_replication_factor(estimated_network_size: usize) -> usize {
    std::cmp::max(50, (estimated_network_size as f64).sqrt() as usize)
}

/// An ownership record for a single bill in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipRecord {
    /// Permanent bill identity.
    pub mint_id: [u8; 32],
    /// Current ownership chain tip.
    pub chain_tip: [u8; 32],
    /// Blake3 hash of the current owner's ML-DSA-65 verification key.
    pub current_owner_vk_hash: [u8; 32],
    /// Full ML-DSA-65 verification key of the current owner.
    pub current_owner_vk: Vec<u8>,
    /// Denomination value for supply tracking.
    pub denomination_value: u64,
    /// Unix timestamp when this record was last updated.
    pub updated_at: u64,
    /// Blake3 hash of the serialised STARK proof bytes.  The full proof
    /// is verified once at genesis time and then discarded — only the
    /// PQ-safe hash is retained (128-bit quantum security via Grover).
    pub proof_hash: [u8; 32],
    /// VM execution digest that was proven by the STARK.
    pub digest: [u8; 32],
    /// Minting nonce baked into the STARK seed.
    pub nonce: [u8; 32],
    /// Blake3 hash of the previous owner's VK before the last transfer.
    /// Used for deterministic conflict resolution when competing claims
    /// race for the same transfer slot.
    #[serde(default)]
    pub prev_claim_vk_hash: Option<[u8; 32]>,
    /// Deterministic hash of the winning claim for the current transfer.
    /// `Blake3("vess-claim-hash-v0" || mint_id || new_owner_vk_hash || transfer_sig)`
    /// Competing claims from the same previous owner are resolved by
    /// depth-first (longest chain wins), then lowest claim_hash as tiebreaker.
    #[serde(default)]
    pub claim_hash: Option<[u8; 32]>,
    /// Number of ownership transfers since genesis. Genesis = 0, first
    /// transfer = 1, etc. Deeper chains win in conflict resolution —
    /// a bill that has been forwarded twice (depth 2) beats a fraudulent
    /// second-send from the original owner (depth 1).
    #[serde(default)]
    pub chain_depth: u64,
    /// Encrypted bill data for DHT recovery. Encrypted to the current
    /// owner's stealth address — only they can decrypt it. Stored so
    /// the owner can recover bills from the DHT if they lose their device.
    #[serde(default)]
    pub encrypted_bill: Vec<u8>,
}

/// The ownership registry — the single source of truth for bill ownership.
///
/// A bill exists in this registry if and only if it is spendable.
/// Consuming a bill (split/combine) deletes it. Transferring a bill
/// updates its ownership record in-place.
///
/// Only records whose `mint_id` is close (by XOR distance) to this node's
/// ID are stored, keeping per-node memory bounded.
#[derive(Debug, Clone)]
pub struct OwnershipRegistry {
    /// This node's 32-byte identity.
    node_id: [u8; 32],
    /// Active ownership records keyed by mint_id.
    records: HashMap<[u8; 32], OwnershipRecord>,
    /// Cached Merkle root (invalidated on mutation).
    merkle_root: Option<[u8; 32]>,
}

impl OwnershipRegistry {
    /// Create an empty registry for the given node.
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            records: HashMap::new(),
            merkle_root: None,
        }
    }

    /// Whether this node should store a record for the given `mint_id`,
    /// considering the set of known `peer_ids` and the `replication_factor`.
    ///
    /// Returns `true` if this node is among the `replication_factor`-closest
    /// to the `mint_id` by XOR distance.
    pub fn should_store(&self, mint_id: &[u8; 32], peer_ids: &[[u8; 32]], replication_factor: usize) -> bool {
        let my_distance = xor_distance(&self.node_id, mint_id);
        let closer_count = peer_ids
            .iter()
            .filter(|pid| xor_distance(pid, mint_id) < my_distance)
            .count();
        closer_count < replication_factor
    }

    /// Register a new mint_id in the registry.
    ///
    /// Returns `false` if the mint_id is already registered (duplicate).
    pub fn register(&mut self, record: OwnershipRecord) -> bool {
        let mint_id = record.mint_id;
        if self.records.contains_key(&mint_id) {
            return false;
        }
        self.records.insert(mint_id, record);
        self.merkle_root = None; // invalidate cache
        true
    }

    /// Check whether a mint_id is active (has an ownership record).
    pub fn is_active(&self, mint_id: &[u8; 32]) -> bool {
        self.records.contains_key(mint_id)
    }

    /// Get the ownership record for a mint_id, if it exists.
    pub fn get(&self, mint_id: &[u8; 32]) -> Option<&OwnershipRecord> {
        self.records.get(mint_id)
    }

    /// Get a mutable reference to an ownership record.
    pub fn get_mut(&mut self, mint_id: &[u8; 32]) -> Option<&mut OwnershipRecord> {
        self.merkle_root = None; // invalidate cache on potential mutation
        self.records.get_mut(mint_id)
    }

    /// Consume (delete) a mint_id from the registry.
    ///
    /// Used when a bill is consumed in a split/combine reforge.
    /// Returns the removed record, or None if the mint_id was not active.
    pub fn consume(&mut self, mint_id: &[u8; 32]) -> Option<OwnershipRecord> {
        let removed = self.records.remove(mint_id);
        if removed.is_some() {
            self.merkle_root = None; // invalidate cache
        }
        removed
    }

    /// Number of active mint_ids in the registry.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Compute the Merkle root over all active mint_ids.
    ///
    /// The leaves are the sorted mint_ids. This provides a compact
    /// 32-byte commitment to the entire registry state.
    pub fn merkle_root(&mut self) -> [u8; 32] {
        if let Some(root) = self.merkle_root {
            return root;
        }

        if self.records.is_empty() {
            let root = [0u8; 32];
            self.merkle_root = Some(root);
            return root;
        }

        let mut mint_ids: Vec<[u8; 32]> = self.records.keys().copied().collect();
        mint_ids.sort();

        let leaves: Vec<&[u8]> = mint_ids.iter().map(|id| id.as_slice()).collect();
        let tree = MerkleTree::build(&leaves);
        let root = tree.root();
        self.merkle_root = Some(root);
        root
    }

    /// Get all records for serialization/snapshot.
    pub fn all_records(&self) -> Vec<OwnershipRecord> {
        self.records.values().cloned().collect()
    }

    /// Restore from a list of records (snapshot loading).
    pub fn from_records(node_id: [u8; 32], records: Vec<OwnershipRecord>) -> Self {
        let map: HashMap<[u8; 32], OwnershipRecord> = records
            .into_iter()
            .map(|r| (r.mint_id, r))
            .collect();
        Self {
            node_id,
            records: map,
            merkle_root: None,
        }
    }

    /// Total supply: sum of all active denomination values.
    pub fn total_supply(&self) -> u64 {
        self.records.values().map(|r| r.denomination_value).sum()
    }
}

impl Default for OwnershipRegistry {
    fn default() -> Self {
        Self::new([0u8; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(mint_id: [u8; 32], denom: u64) -> OwnershipRecord {
        OwnershipRecord {
            mint_id,
            chain_tip: [0x11; 32],
            current_owner_vk_hash: [0x22; 32],
            current_owner_vk: vec![0x33; 64],
            denomination_value: denom,
            updated_at: 1000,
            proof_hash: blake3::hash(&[0x44; 16]).into(),
            digest: [0x55; 32],
            nonce: [0x66; 32],
            prev_claim_vk_hash: None,
            claim_hash: None,
            chain_depth: 0,
            encrypted_bill: vec![],
        }
    }

    #[test]
    fn register_and_query() {
        let mut reg = OwnershipRegistry::new([0x01; 32]);
        let record = make_record([0xAA; 32], 10);
        assert!(reg.register(record));
        assert!(reg.is_active(&[0xAA; 32]));
        assert!(!reg.is_active(&[0xBB; 32]));
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut reg = OwnershipRegistry::new([0x01; 32]);
        assert!(reg.register(make_record([0xAA; 32], 10)));
        assert!(!reg.register(make_record([0xAA; 32], 10)));
    }

    #[test]
    fn consume_removes_entry() {
        let mut reg = OwnershipRegistry::new([0x01; 32]);
        reg.register(make_record([0xAA; 32], 10));
        assert!(reg.is_active(&[0xAA; 32]));
        let removed = reg.consume(&[0xAA; 32]);
        assert!(removed.is_some());
        assert!(!reg.is_active(&[0xAA; 32]));
    }

    #[test]
    fn consume_nonexistent_returns_none() {
        let mut reg = OwnershipRegistry::new([0x01; 32]);
        assert!(reg.consume(&[0xAA; 32]).is_none());
    }

    #[test]
    fn merkle_root_changes_on_mutation() {
        let mut reg = OwnershipRegistry::new([0x01; 32]);
        reg.register(make_record([0xAA; 32], 10));
        let root1 = reg.merkle_root();

        reg.register(make_record([0xBB; 32], 20));
        let root2 = reg.merkle_root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn merkle_root_deterministic() {
        let mut reg1 = OwnershipRegistry::new([0x01; 32]);
        reg1.register(make_record([0xAA; 32], 10));
        reg1.register(make_record([0xBB; 32], 20));

        let mut reg2 = OwnershipRegistry::new([0x01; 32]);
        reg2.register(make_record([0xBB; 32], 20));
        reg2.register(make_record([0xAA; 32], 10));

        // Same records, different insertion order → same root.
        assert_eq!(reg1.merkle_root(), reg2.merkle_root());
    }

    #[test]
    fn total_supply() {
        let mut reg = OwnershipRegistry::new([0x01; 32]);
        reg.register(make_record([0xAA; 32], 10));
        reg.register(make_record([0xBB; 32], 20));
        assert_eq!(reg.total_supply(), 30);
    }

    #[test]
    fn snapshot_round_trip() {
        let mut reg = OwnershipRegistry::new([0x01; 32]);
        reg.register(make_record([0xAA; 32], 10));
        reg.register(make_record([0xBB; 32], 20));

        let records = reg.all_records();
        let mut restored = OwnershipRegistry::from_records([0x01; 32], records);

        assert_eq!(reg.merkle_root(), restored.merkle_root());
        assert_eq!(reg.total_supply(), restored.total_supply());
    }
}
