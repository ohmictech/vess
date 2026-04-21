//! Kademlia-style routing table for artery infrastructure nodes.
//!
//! This module implements a 256-bucket XOR-distance routing table that
//! tracks **infrastructure relay nodes only** — never wallet users or
//! payment recipients. The routing table is used to find which artery
//! nodes are responsible for a given DHT region (e.g. which nodes
//! should store an ownership record for a `mint_id`).
//!
//! **Privacy invariants:**
//! - Payments are routed by ephemeral `stealth_id`, NOT by recipient node ID.
//! - No wallet identity or stealth address is stored in the routing table.
//! - Each node sees O(log N) peers out of N total — never the full network.
//! - The routing table reveals only that a peer runs artery software,
//!   not who they pay or receive from.

use crate::gossip::xor_distance;

/// Number of peers per bucket. Standard Kademlia uses K=20.
/// We use 20 to ensure robust redundancy at scale while keeping
/// memory bounded (256 buckets × 20 = 5120 entries max).
pub const K_BUCKET_SIZE: usize = 20;

/// Minimum peer age (in seconds) before a node is considered
/// "established" for gossip forwarding priority. Peers younger
/// than this are deprioritised — making ID rotation costly because
/// each fresh identity starts with zero age + zero reputation.
pub const PEER_PROBATION_SECS: u64 = 600; // 10 minutes

/// Compute an age-based trust factor in [0.1, 1.0].
///
/// New peers get 0.1 (10% influence). After `PEER_PROBATION_SECS`
/// the factor ramps linearly to 1.0. This makes Sybil ID rotation
/// expensive in terms of influence: every fresh node ID spends 10
/// minutes at reduced priority regardless of Argon2id PoW throughput.
pub fn peer_age_factor(first_seen: u64, now: u64) -> f64 {
    let age = now.saturating_sub(first_seen);
    if age >= PEER_PROBATION_SECS {
        1.0
    } else {
        0.1 + 0.9 * (age as f64 / PEER_PROBATION_SECS as f64)
    }
}

/// A peer entry in the routing table: just the Blake3 hash of the
/// iroh EndpointId and the raw endpoint bytes for connectivity.
/// No wallet metadata, no stealth addresses, no payment history.
#[derive(Clone, Debug)]
pub struct RoutingPeer {
    pub id_hash: [u8; 32],
    pub id_bytes: Vec<u8>,
    /// Monotonic timestamp of last successful communication.
    pub last_seen: u64,
    /// Timestamp when this peer was first added to the routing table.
    /// Used as a churn penalty: recently-created node IDs are
    /// deprioritised in gossip forwarding, making Sybil ID rotation
    /// costly in influence, not just compute.
    pub first_seen: u64,
}

/// Maximum peers sharing the same 2-byte ID prefix within a single
/// k-bucket.  Limits how many Sybil identities from one prefix range
/// can occupy the same distance slot, making eclipse attacks require
/// diverse (expensive) Argon2id-committed node IDs.
pub const MAX_PEERS_PER_PREFIX: usize = 2;

/// A single k-bucket holding up to `K_BUCKET_SIZE` peers at
/// a specific XOR-distance prefix from our node.
#[derive(Clone, Debug)]
struct KBucket {
    peers: Vec<RoutingPeer>,
}

impl KBucket {
    fn new() -> Self {
        Self { peers: Vec::new() }
    }

    /// Number of peers in this bucket.
    fn len(&self) -> usize {
        self.peers.len()
    }

    fn is_full(&self) -> bool {
        self.peers.len() >= K_BUCKET_SIZE
    }

    /// Count how many existing peers share the first 2 bytes of `id_hash`.
    fn prefix_count(&self, id_hash: &[u8; 32]) -> usize {
        let prefix = [id_hash[0], id_hash[1]];
        self.peers
            .iter()
            .filter(|p| p.id_hash[0] == prefix[0] && p.id_hash[1] == prefix[1])
            .count()
    }

    /// Find a peer by id_hash. Returns its index if present.
    fn position(&self, id_hash: &[u8; 32]) -> Option<usize> {
        self.peers.iter().position(|p| &p.id_hash == id_hash)
    }

    /// Insert or update a peer. If the peer exists, move it to the
    /// tail (most-recently-seen). If the bucket is full and the peer
    /// is new, returns `false` (caller should ping the head/LRU peer
    /// and evict if unresponsive).
    ///
    /// Also enforces prefix diversity: rejects a new peer if the bucket
    /// already has `MAX_PEERS_PER_PREFIX` peers sharing its 2-byte prefix.
    fn upsert(&mut self, peer: RoutingPeer) -> bool {
        if let Some(idx) = self.position(&peer.id_hash) {
            // Already present — update and move to tail (MRU).
            self.peers.remove(idx);
            self.peers.push(peer);
            true
        } else if !self.is_full() {
            // Prefix diversity check for new peers.
            if self.prefix_count(&peer.id_hash) >= MAX_PEERS_PER_PREFIX {
                return false; // too many peers with the same 2-byte prefix
            }
            self.peers.push(peer);
            true
        } else {
            false // bucket full, new peer not inserted
        }
    }

    /// Remove a peer by id_hash. Returns true if found and removed.
    fn remove(&mut self, id_hash: &[u8; 32]) -> bool {
        if let Some(idx) = self.position(id_hash) {
            self.peers.remove(idx);
            true
        } else {
            false
        }
    }

    /// Evict the least-recently-seen peer (head of the list) and
    /// insert the new peer at the tail.
    fn evict_lru_and_insert(&mut self, peer: RoutingPeer) {
        if !self.peers.is_empty() {
            self.peers.remove(0);
        }
        self.peers.push(peer);
    }

    /// Get the least-recently-seen peer (head), if any.
    fn lru(&self) -> Option<&RoutingPeer> {
        self.peers.first()
    }

    /// Return all peers in this bucket.
    fn all(&self) -> &[RoutingPeer] {
        &self.peers
    }

    /// Update the `last_seen` timestamp of a peer. Returns true if found.
    fn touch(&mut self, id_hash: &[u8; 32], now: u64) -> bool {
        if let Some(idx) = self.position(id_hash) {
            self.peers[idx].last_seen = now;
            // Move to tail (MRU) so LRU eviction targets silent peers.
            let peer = self.peers.remove(idx);
            self.peers.push(peer);
            true
        } else {
            false
        }
    }
}

/// Kademlia routing table: 256 buckets indexed by the number of
/// leading zero bits in `XOR(our_id, peer_id)`.
///
/// Bucket 0 = peers whose XOR distance has 0 leading zeros (most distant).
/// Bucket 255 = peers whose XOR distance has 255 leading zeros (closest).
///
/// This naturally distributes peers across distance ranges, ensuring
/// logarithmic routing convergence.
pub struct RoutingTable {
    /// Our own node ID (Blake3 hash).
    node_id: [u8; 32],
    /// 256 k-buckets, indexed by leading-zero count of XOR distance.
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// Create an empty routing table for the given node ID.
    pub fn new(node_id: [u8; 32]) -> Self {
        let mut buckets = Vec::with_capacity(256);
        for _ in 0..256 {
            buckets.push(KBucket::new());
        }
        Self { node_id, buckets }
    }

    /// Our node ID.
    pub fn node_id(&self) -> &[u8; 32] {
        &self.node_id
    }

    /// Determine which bucket a peer belongs in based on XOR distance.
    /// Returns the bucket index (0..256).
    fn bucket_index(&self, peer_id: &[u8; 32]) -> Option<usize> {
        let dist = xor_distance(&self.node_id, peer_id);
        let lz = leading_zeros(&dist);
        if lz == 256 {
            None // same ID as us — don't store ourselves
        } else {
            Some(lz)
        }
    }

    /// Insert or update a peer in the routing table.
    /// Returns `true` if the peer was inserted/updated,
    /// `false` if the bucket was full (peer is a candidate for
    /// replacement after pinging the LRU peer).
    pub fn insert(&mut self, peer: RoutingPeer) -> bool {
        if peer.id_hash == self.node_id {
            return false; // never store ourselves
        }
        if let Some(idx) = self.bucket_index(&peer.id_hash) {
            self.buckets[idx].upsert(peer)
        } else {
            false
        }
    }

    /// Get the LRU peer from the bucket that `peer_id` maps to.
    /// Used when a bucket is full and we need to decide whether to
    /// evict the LRU entry for a new peer.
    pub fn lru_for(&self, peer_id: &[u8; 32]) -> Option<&RoutingPeer> {
        self.bucket_index(peer_id)
            .and_then(|idx| self.buckets[idx].lru())
    }

    /// Force-insert a peer by evicting the LRU entry in its bucket.
    /// Use after confirming the LRU peer is unresponsive.
    pub fn evict_lru_and_insert(&mut self, peer: RoutingPeer) {
        if peer.id_hash == self.node_id {
            return;
        }
        if let Some(idx) = self.bucket_index(&peer.id_hash) {
            self.buckets[idx].evict_lru_and_insert(peer);
        }
    }

    /// Remove a peer from the routing table.
    pub fn remove(&mut self, peer_id: &[u8; 32]) -> bool {
        if let Some(idx) = self.bucket_index(peer_id) {
            self.buckets[idx].remove(peer_id)
        } else {
            false
        }
    }

    /// Find the K closest peers to a target (which can be any 32-byte
    /// key — a `mint_id`, a `stealth_id`, a `dht_key`, etc.).
    ///
    /// This is the core routing primitive. To replicate an ownership
    /// record for `mint_id`, call `closest_peers(&mint_id, repl_factor)`.
    /// To forward a payment by `stealth_id`, call
    /// `closest_peers(&stealth_id, k)`.
    pub fn closest_peers(&self, target: &[u8; 32], k: usize) -> Vec<RoutingPeer> {
        let mut all: Vec<(RoutingPeer, [u8; 32])> = Vec::new();
        for bucket in &self.buckets {
            for peer in bucket.all() {
                let dist = xor_distance(target, &peer.id_hash);
                all.push((peer.clone(), dist));
            }
        }
        all.sort_by(|(_, d1), (_, d2)| d1.cmp(d2));
        all.into_iter().take(k).map(|(p, _)| p).collect()
    }

    /// Return all peers in the routing table as `(id_hash, id_bytes)`.
    /// Used for persistence and PEX responses.
    pub fn all_peers(&self) -> Vec<&RoutingPeer> {
        let mut out = Vec::new();
        for bucket in &self.buckets {
            for peer in bucket.all() {
                out.push(peer);
            }
        }
        out
    }

    /// Total number of peers in the routing table.
    pub fn peer_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// Estimate the total network size from the routing table.
    ///
    /// Uses the average distance to the K closest peers to estimate
    /// density, then extrapolates. This gives a rough O(N) estimate
    /// that improves as the table fills.
    pub fn estimated_network_size(&self) -> usize {
        let closest = self.closest_peers(&self.node_id, K_BUCKET_SIZE);
        if closest.is_empty() {
            return 1; // just us
        }
        // Use the distance to the farthest of the K-closest peers.
        // In a uniform distribution of N nodes in a 256-bit space,
        // the expected distance to the k-th nearest peer is ~k/N × 2^256.
        // We use leading zeros as a proxy for log2 of the distance.
        let farthest = &closest[closest.len() - 1];
        let dist = xor_distance(&self.node_id, &farthest.id_hash);
        let lz = leading_zeros(&dist);
        // 2^(256 - lz) is the approximate distance.
        // N ≈ k × 2^256 / distance ≈ k × 2^lz
        let k = closest.len();
        let estimate = k.checked_shl(lz as u32).unwrap_or(usize::MAX);
        estimate.max(self.peer_count())
    }

    /// Check if a peer exists in the routing table.
    pub fn contains(&self, peer_id: &[u8; 32]) -> bool {
        self.bucket_index(peer_id)
            .map(|idx| self.buckets[idx].position(peer_id).is_some())
            .unwrap_or(false)
    }

    /// Update the `last_seen` timestamp for a peer after a valid message
    /// exchange. This promotes the peer to the tail of its bucket (MRU),
    /// so silent/fake Sybil nodes drift toward the LRU eviction position
    /// while active, honest peers stay protected.
    pub fn touch(&mut self, peer_id: &[u8; 32], now: u64) -> bool {
        if let Some(idx) = self.bucket_index(peer_id) {
            self.buckets[idx].touch(peer_id, now)
        } else {
            false
        }
    }

    /// Get a peer by id_hash, if present.
    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&RoutingPeer> {
        self.bucket_index(peer_id).and_then(|idx| {
            self.buckets[idx]
                .position(peer_id)
                .map(|pos| &self.buckets[idx].peers[pos])
        })
    }

    /// Look up the raw `id_bytes` for a peer by its `id_hash`.
    pub fn peer_id_bytes(&self, peer_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.get(peer_id).map(|p| p.id_bytes.clone())
    }

    /// Fill the id_bytes for a peer that was restored from persistence
    /// (where only hashes are stored). Returns true if found and updated.
    pub fn fill_id_bytes(&mut self, id_hash: &[u8; 32], id_bytes: Vec<u8>) -> bool {
        if let Some(idx) = self.bucket_index(id_hash) {
            if let Some(pos) = self.buckets[idx].position(id_hash) {
                if self.buckets[idx].peers[pos].id_bytes.is_empty() {
                    self.buckets[idx].peers[pos].id_bytes = id_bytes;
                    return true;
                }
            }
        }
        false
    }

    /// Return peers that are routable (have non-empty id_bytes) and
    /// pass the given filter (typically peer_registry verification).
    pub fn routable_peers<F>(&self, filter: F) -> Vec<RoutingPeer>
    where
        F: Fn(&[u8; 32]) -> bool,
    {
        let mut out = Vec::new();
        for bucket in &self.buckets {
            for peer in bucket.all() {
                if !peer.id_bytes.is_empty() && filter(&peer.id_hash) {
                    out.push(peer.clone());
                }
            }
        }
        out
    }

    /// Collect routable peer hashes, id_bytes, and age factors in parallel vectors
    /// (convenience for drain tasks that need all three).
    pub fn routable_peer_vecs<F>(
        &self,
        filter: F,
        now: u64,
    ) -> (Vec<[u8; 32]>, Vec<Vec<u8>>, Vec<f64>)
    where
        F: Fn(&[u8; 32]) -> bool,
    {
        let mut hashes = Vec::new();
        let mut bytes = Vec::new();
        let mut ages = Vec::new();
        for bucket in &self.buckets {
            for peer in bucket.all() {
                if !peer.id_bytes.is_empty() && filter(&peer.id_hash) {
                    hashes.push(peer.id_hash);
                    bytes.push(peer.id_bytes.clone());
                    ages.push(peer_age_factor(peer.first_seen, now));
                }
            }
        }
        (hashes, bytes, ages)
    }
}

/// Count the number of leading zero bits in a 256-bit value.
fn leading_zeros(val: &[u8; 32]) -> usize {
    let mut count = 0;
    for byte in val {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(seed: u8) -> [u8; 32] {
        *blake3::hash(&[seed]).as_bytes()
    }

    fn make_peer(seed: u8) -> RoutingPeer {
        RoutingPeer {
            id_hash: make_id(seed),
            id_bytes: vec![seed],
            last_seen: seed as u64,
            first_seen: seed as u64,
        }
    }

    #[test]
    fn insert_and_lookup() {
        let node_id = make_id(0);
        let mut table = RoutingTable::new(node_id);

        for i in 1..=50u8 {
            table.insert(make_peer(i));
        }

        assert!(table.peer_count() <= 50);
        assert!(table.peer_count() > 0);

        // Self is never stored.
        assert!(!table.contains(&node_id));

        // Closest peers to self should return some results.
        let closest = table.closest_peers(&node_id, 10);
        assert!(!closest.is_empty());
        assert!(closest.len() <= 10);
    }

    #[test]
    fn no_self_insert() {
        let node_id = make_id(42);
        let mut table = RoutingTable::new(node_id);
        let self_peer = RoutingPeer {
            id_hash: node_id,
            id_bytes: vec![42],
            last_seen: 0,
            first_seen: 0,
        };
        assert!(!table.insert(self_peer));
        assert_eq!(table.peer_count(), 0);
    }

    #[test]
    fn bucket_lru_eviction() {
        let node_id = [0u8; 32];
        let mut table = RoutingTable::new(node_id);

        // Create peers that all land in the same bucket by controlling their
        // XOR distance (they'll share leading zero count).
        // Use sequential bytes with the same high bit pattern.
        let mut peers = Vec::new();
        for i in 0..(K_BUCKET_SIZE + 5) {
            let mut id = [0xFFu8; 32];
            id[1] = i as u8;
            id[2] = (i >> 8) as u8;
            peers.push(RoutingPeer {
                id_hash: id,
                id_bytes: vec![i as u8],
                last_seen: i as u64,
                first_seen: i as u64,
            });
        }

        for p in &peers[..K_BUCKET_SIZE] {
            assert!(table.insert(p.clone()));
        }
        // Bucket should be full now; additional inserts fail.
        assert!(!table.insert(peers[K_BUCKET_SIZE].clone()));

        // Force eviction.
        table.evict_lru_and_insert(peers[K_BUCKET_SIZE].clone());
        assert!(table.contains(&peers[K_BUCKET_SIZE].id_hash));
        // The first peer (LRU) should have been evicted.
        assert!(!table.contains(&peers[0].id_hash));
    }

    #[test]
    fn closest_peers_ordered() {
        let node_id = make_id(0);
        let mut table = RoutingTable::new(node_id);

        for i in 1..=100u8 {
            table.insert(make_peer(i));
        }

        let target = make_id(50);
        let closest = table.closest_peers(&target, 5);
        assert_eq!(closest.len(), 5);

        // Verify ordering: each subsequent peer should be farther from target.
        for w in closest.windows(2) {
            let d0 = xor_distance(&target, &w[0].id_hash);
            let d1 = xor_distance(&target, &w[1].id_hash);
            assert!(d0 <= d1);
        }
    }

    #[test]
    fn estimated_network_size_grows() {
        let node_id = make_id(0);
        let mut table = RoutingTable::new(node_id);

        let est_empty = table.estimated_network_size();
        assert!(est_empty >= 1);

        for i in 1..=100u8 {
            table.insert(make_peer(i));
        }

        let est_100 = table.estimated_network_size();
        assert!(est_100 > est_empty);
    }

    #[test]
    fn remove_peer() {
        let node_id = make_id(0);
        let mut table = RoutingTable::new(node_id);
        let peer = make_peer(1);
        table.insert(peer.clone());
        assert!(table.contains(&peer.id_hash));
        table.remove(&peer.id_hash);
        assert!(!table.contains(&peer.id_hash));
    }

    #[test]
    fn routable_filter() {
        let node_id = make_id(0);
        let mut table = RoutingTable::new(node_id);

        let routable = make_peer(1);
        let mut unroutable = make_peer(2);
        unroutable.id_bytes = Vec::new(); // no id_bytes = not routable

        table.insert(routable.clone());
        table.insert(unroutable.clone());

        let filtered = table.routable_peers(|_| true);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id_hash, routable.id_hash);
    }

    #[test]
    fn leading_zeros_cases() {
        assert_eq!(leading_zeros(&[0u8; 32]), 256);
        assert_eq!(
            leading_zeros(&{
                let mut v = [0u8; 32];
                v[0] = 0x80;
                v
            }),
            0
        );
        assert_eq!(
            leading_zeros(&{
                let mut v = [0u8; 32];
                v[0] = 0x01;
                v
            }),
            7
        );
        assert_eq!(
            leading_zeros(&{
                let mut v = [0u8; 32];
                v[1] = 0x40;
                v
            }),
            9
        );
    }

    #[test]
    fn prefix_diversity_rejects_excess() {
        let node_id = [0u8; 32];
        let mut table = RoutingTable::new(node_id);

        // Create peers that share the same 2-byte prefix but differ afterward.
        let make_shared_prefix = |suffix: u8| -> RoutingPeer {
            let mut id = [0xFFu8; 32]; // same first two bytes
            id[2] = suffix;
            RoutingPeer {
                id_hash: id,
                id_bytes: vec![0xFF, 0xFF, suffix],
                last_seen: suffix as u64,
                first_seen: suffix as u64,
            }
        };

        // First MAX_PEERS_PER_PREFIX peers with the same prefix should succeed.
        for i in 0..MAX_PEERS_PER_PREFIX {
            assert!(
                table.insert(make_shared_prefix(i as u8)),
                "peer {i} with shared prefix should be accepted"
            );
        }

        // The next one should be rejected due to prefix diversity.
        assert!(
            !table.insert(make_shared_prefix(MAX_PEERS_PER_PREFIX as u8)),
            "peer beyond MAX_PEERS_PER_PREFIX should be rejected"
        );

        // A peer with a different prefix should still be accepted.
        let mut diff_prefix = [0xAAu8; 32];
        diff_prefix[2] = 0x01;
        let different = RoutingPeer {
            id_hash: diff_prefix,
            id_bytes: vec![0xAA, 0xAA, 0x01],
            last_seen: 99,
            first_seen: 99,
        };
        assert!(
            table.insert(different),
            "peer with different prefix should be accepted"
        );
    }
}
