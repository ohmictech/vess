//! Distributed Hash Table for VessTag records.
//!
//! VessTag records are stored across artery nodes, keyed on
//! `Blake3(tag_string)`. Each node stores tags closest to its own
//! XOR-address with a replication factor of K.
//!
//! Freshly registered tags are **unhardened** — they have a 30-day TTL.
//! Once the owner proves they received a payment, the tag is hardened
//! and persists indefinitely.

use std::collections::{BTreeMap, BTreeSet};
use vess_tag::TagRecord;

use crate::gossip::xor_distance;

/// Local DHT shard stored by a single artery node.
///
/// Each node is responsible for tags whose DHT keys are closest
/// to this node's ID by XOR distance.
///
/// **Invariant:** Each master stealth address may map to at most one tag.
/// A reverse index `address_fingerprint → tag_dht_key` enforces this.
pub struct TagDht {
    /// This node's ID (32-byte).
    node_id: [u8; 32],
    /// Replication factor: how many closest nodes store each tag.
    k_replication: usize,
    /// Tag records stored locally, keyed by DHT key (Blake3 of tag string).
    records: BTreeMap<[u8; 32], TagRecord>,
    /// Reverse index: address fingerprint → tag DHT key.
    /// Enforces one-tag-per-address.
    addr_to_tag: BTreeMap<[u8; 32], [u8; 32]>,
    /// Bill IDs that have been used to harden tags.
    /// Prevents a single payment from hardening multiple tags.
    hardening_proofs: BTreeSet<[u8; 32]>,
}

impl TagDht {
    /// Create a new DHT shard for the given node.
    pub fn new(node_id: [u8; 32], k_replication: usize) -> Self {
        Self {
            node_id,
            k_replication,
            records: BTreeMap::new(),
            addr_to_tag: BTreeMap::new(),
            hardening_proofs: BTreeSet::new(),
        }
    }

    /// This node's ID.
    pub fn node_id(&self) -> &[u8; 32] {
        &self.node_id
    }

    /// Replication factor.
    pub fn k_replication(&self) -> usize {
        self.k_replication
    }

    /// Update the replication factor (e.g., based on estimated network size).
    pub fn set_k_replication(&mut self, k: usize) {
        self.k_replication = k;
    }

    /// Store a tag record locally.
    ///
    /// Returns `false` if:
    /// - A hardened tag already exists for this key (permanent), OR
    /// - An unhardened tag exists but is still within its 30-epoch grace period, OR
    /// - The address already has a different tag registered (one-tag-per-address).
    ///
    /// If the existing tag is unhardened AND past its grace period,
    /// it is overwritten by the new record.
    /// If the incoming record has no `grace_until_epoch` set, it defaults
    /// to `current_epoch + 30`.
    pub fn store(&mut self, mut record: TagRecord) -> bool {
        let current_epoch = vess_foundry::clock::current_epoch();
        // Set grace period if not already set
        if record.grace_until_epoch.is_none() {
            record.grace_until_epoch = Some(current_epoch + 30);
        }
        let key = record.dht_key();
        if let Some(existing) = self.records.get(&key) {
            if existing.is_hardened() {
                return false;
            }
            if !existing.can_be_overwritten(Some(current_epoch)) {
                return false;
            }
            // Grace expired, unhardened — allow overwrite (fall through)
        }
        let addr_fp = record.address_fingerprint();
        if self.addr_to_tag.contains_key(&addr_fp) {
            return false;
        }
        // Remove old addr→tag mapping if overwriting
        if let Some(old) = self.records.get(&key) {
            self.addr_to_tag.remove(&old.address_fingerprint());
        }
        self.addr_to_tag.insert(addr_fp, key);
        self.records.insert(key, record);
        true
    }

    /// Check if an address fingerprint already has a tag registered.
    pub fn has_address(&self, addr_fp: &[u8; 32]) -> bool {
        self.addr_to_tag.contains_key(addr_fp)
    }

    /// Look up a tag by its DHT key.
    pub fn get(&self, dht_key: &[u8; 32]) -> Option<&TagRecord> {
        self.records.get(dht_key)
    }

    /// Look up a tag by its string (computes DHT key internally).
    pub fn lookup(&self, tag_str: &str) -> Option<&TagRecord> {
        let key = *blake3::hash(tag_str.as_bytes()).as_bytes();
        self.records.get(&key)
    }

    /// Look up a tag by its pre-computed hash (DHT key).
    pub fn lookup_by_hash(&self, tag_hash: &[u8; 32]) -> Option<&TagRecord> {
        self.records.get(tag_hash)
    }

    /// Look up a tag by address fingerprint (reverse lookup).
    pub fn lookup_by_address(&self, addr_fp: &[u8; 32]) -> Option<&TagRecord> {
        let tag_key = self.addr_to_tag.get(addr_fp)?;
        self.records.get(tag_key)
    }

    /// Number of tag records stored locally.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Whether this node should store a given DHT key, given the known peers.
    ///
    /// Returns `true` if this node is among the K-closest to the key.
    pub fn should_store(&self, dht_key: &[u8; 32], peer_ids: &[[u8; 32]]) -> bool {
        let my_distance = xor_distance(&self.node_id, dht_key);

        let closer_count = peer_ids
            .iter()
            .filter(|pid| {
                let d = xor_distance(pid, dht_key);
                d < my_distance
            })
            .count();

        closer_count < self.k_replication
    }

    /// All stored records (for replication / migration).
    pub fn all_records(&self) -> impl Iterator<Item = &TagRecord> {
        self.records.values()
    }

    /// Remove a record (only used during DHT rebalancing, not for un-registration).
    pub fn remove(&mut self, dht_key: &[u8; 32]) -> Option<TagRecord> {
        if let Some(record) = self.records.remove(dht_key) {
            let addr_fp = record.address_fingerprint();
            self.addr_to_tag.remove(&addr_fp);
            Some(record)
        } else {
            None
        }
    }

    /// Bulk-load tag records from persistence.
    pub fn load_records(&mut self, records: BTreeMap<[u8; 32], TagRecord>) {
        self.addr_to_tag.clear();
        for (key, record) in &records {
            let addr_fp = record.address_fingerprint();
            self.addr_to_tag.insert(addr_fp, *key);
        }
        self.records = records;
    }

    /// Export all records as a BTreeMap (for persistence).
    pub fn export_records(&self) -> &BTreeMap<[u8; 32], TagRecord> {
        &self.records
    }

    /// Harden a tag by providing a bill_id as proof of payment.
    ///
    /// Returns `true` if the tag was successfully hardened.
    /// Returns `false` if the tag doesn't exist, is already hardened,
    /// or the bill_id was already used to harden another tag.
    pub fn harden(&mut self, tag_str: &str, bill_id: &[u8; 32], now: u64) -> bool {
        let key = *blake3::hash(tag_str.as_bytes()).as_bytes();
        self.harden_by_hash(&key, bill_id, now)
    }

    /// Harden a tag by hash (pre-computed DHT key).
    pub fn harden_by_hash(&mut self, tag_hash: &[u8; 32], bill_id: &[u8; 32], now: u64) -> bool {
        if self.hardening_proofs.contains(bill_id) {
            return false; // bill_id already used
        }
        if let Some(record) = self.records.get_mut(tag_hash) {
            if record.hardened_at.is_some() {
                return false; // already hardened
            }
            record.hardened_at = Some(now);
            self.hardening_proofs.insert(*bill_id);
            true
        } else {
            false
        }
    }

    /// Check if a tag is hardened.
    pub fn is_hardened(&self, tag_str: &str) -> bool {
        let key = *blake3::hash(tag_str.as_bytes()).as_bytes();
        self.records.get(&key).and_then(|r| r.hardened_at).is_some()
    }

    /// Purge unhardened tags whose registration grace period has expired.
    ///
    /// Tags are eligible for purge when BOTH:
    /// - They are unhardened, AND
    /// - Their grace_until_epoch has passed (30 epochs / 30 days).
    ///
    /// Returns the number of tags removed.
    pub fn purge_unhardened(&mut self, current_epoch: u64) -> usize {
        let expired_keys: Vec<[u8; 32]> = self
            .records
            .iter()
            .filter(|(_, r)| {
                r.hardened_at.is_none()
                    && r.grace_until_epoch.map_or(true, |g| current_epoch > g)
            })
            .map(|(k, _)| *k)
            .collect();
        let count = expired_keys.len();
        for key in expired_keys {
            self.remove(&key);
        }
        count
    }

    /// Export hardening proof bill_ids (for persistence).
    pub fn export_hardening_proofs(&self) -> Vec<[u8; 32]> {
        self.hardening_proofs.iter().copied().collect()
    }

    /// Load hardening proof bill_ids from persistence.
    pub fn load_hardening_proofs(&mut self, proofs: Vec<[u8; 32]>) {
        self.hardening_proofs = proofs.into_iter().collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_stealth::MasterStealthAddress;

    fn dummy_address() -> MasterStealthAddress {
        let (_sk, addr) = vess_stealth::generate_master_keys();
        addr
    }

    fn make_record(tag: &str) -> TagRecord {
        TagRecord {
            tag_hash: *blake3::hash(tag.as_bytes()).as_bytes(),
            master_address: dummy_address(),
            pow_nonce: rand::random(),
            pow_hash: vec![0xAA; 32],
            registered_at: 12345,
            registrant_vk: Vec::new(),
            signature: Vec::new(),
            hardened_at: None,
            grace_until_epoch: None,
        }
    }

    fn make_record_with_address(tag: &str, addr: MasterStealthAddress) -> TagRecord {
        TagRecord {
            tag_hash: *blake3::hash(tag.as_bytes()).as_bytes(),
            master_address: addr,
            pow_nonce: rand::random(),
            pow_hash: vec![0xBB; 32],
            registered_at: 12345,
            registrant_vk: Vec::new(),
            signature: Vec::new(),
            hardened_at: None,
            grace_until_epoch: None,
        }
    }

    #[test]
    fn store_and_lookup() {
        let mut dht = TagDht::new([0x00; 32], 3);
        let record = make_record("alice");

        assert!(dht.store(record));
        assert!(dht.lookup("alice").is_some());
        assert_eq!(dht.record_count(), 1);
    }

    #[test]
    fn first_broadcast_wins() {
        let mut dht = TagDht::new([0x00; 32], 3);

        assert!(dht.store(make_record("alice")));
        assert!(!dht.store(make_record("alice"))); // duplicate rejected
        assert_eq!(dht.record_count(), 1);
    }

    #[test]
    fn one_tag_per_address() {
        let mut dht = TagDht::new([0x00; 32], 3);
        let addr = dummy_address();

        // First tag for this address succeeds.
        assert!(dht.store(make_record_with_address("alice", addr.clone())));
        // Second tag with same address is rejected.
        assert!(!dht.store(make_record_with_address("bob", addr.clone())));
        assert_eq!(dht.record_count(), 1);
        assert!(dht.lookup("alice").is_some());
        assert!(dht.lookup("bob").is_none());
    }

    #[test]
    fn reverse_lookup_by_address() {
        let mut dht = TagDht::new([0x00; 32], 3);
        let addr = dummy_address();
        let addr_fp = vess_tag::address_fingerprint(&addr);

        assert!(dht.store(make_record_with_address("alice", addr)));
        let found = dht.lookup_by_address(&addr_fp);
        assert!(found.is_some());
        assert_eq!(found.unwrap().tag_hash, *blake3::hash(b"alice").as_bytes());
    }

    #[test]
    fn should_store_when_among_k_closest() {
        let node_id = [0x00; 32];
        let dht = TagDht::new(node_id, 3);

        // Tag key close to our node.
        let mut tag_key = [0x00; 32];
        tag_key[31] = 1;

        // Two peers that are farther away.
        let peer1 = [0xFF; 32];
        let peer2 = [0x80; 32];

        assert!(dht.should_store(&tag_key, &[peer1, peer2]));
    }

    #[test]
    fn harden_tag() {
        let mut dht = TagDht::new([0x00; 32], 3);
        assert!(dht.store(make_record("alice")));
        assert!(!dht.is_hardened("alice"));

        let bill_id = [0x42; 32];
        assert!(dht.harden("alice", &bill_id, 99999));
        assert!(dht.is_hardened("alice"));

        // Can't harden again.
        let bill_id2 = [0x43; 32];
        assert!(!dht.harden("alice", &bill_id2, 99999));

        // Can't reuse same bill_id for another tag.
        assert!(dht.store(make_record("bob")));
        assert!(!dht.harden("bob", &bill_id, 99999));
    }

    #[test]
    fn purge_unhardened_tags() {
        let mut dht = TagDht::new([0x00; 32], 3);

        // Alice: unhardened, grace expired at epoch 100
        let mut rec = make_record("alice");
        rec.grace_until_epoch = Some(100);
        rec.registered_at = 1;
        dht.records.insert(rec.dht_key(), rec.clone());
        dht.addr_to_tag.insert(rec.address_fingerprint(), rec.dht_key());

        // Bob: hardened at epoch 50
        let mut rec2 = make_record("bob");
        rec2.grace_until_epoch = Some(130);
        rec2.registered_at = 1;
        rec2.hardened_at = Some(50);
        dht.records.insert(rec2.dht_key(), rec2.clone());
        dht.addr_to_tag.insert(rec2.address_fingerprint(), rec2.dht_key());

        // Charlie: unhardened, grace expires at epoch 200
        let mut rec3 = make_record("charlie");
        rec3.grace_until_epoch = Some(200);
        rec3.registered_at = 50;
        dht.records.insert(rec3.dht_key(), rec3.clone());
        dht.addr_to_tag.insert(rec3.address_fingerprint(), rec3.dht_key());

        assert_eq!(dht.record_count(), 3);

        // At epoch 150: alice expired (100<150), bob hardened (kept), charlie still in grace (200>150)
        let pruned = dht.purge_unhardened(150);
        assert_eq!(pruned, 1);
        assert!(dht.lookup("alice").is_none()); // grace expired, unhardened → pruned
        assert!(dht.lookup("bob").is_some());   // hardened → kept
        assert!(dht.lookup("charlie").is_some()); // still in grace → kept
    }

    #[test]
    fn harden_nonexistent_tag() {
        let mut dht = TagDht::new([0x00; 32], 3);
        assert!(!dht.harden("nonexistent", &[0x01; 32], 99999));
    }
}
