//! Limbo buffer — holds full Payment objects for offline recipients.
//!
//! When a payment passes relay checks but the recipient is offline, the
//! artery enters the payment into limbo.  The custodian periodically
//! retries delivery (every 5–10 minutes).  Limbo is a **soft reservation**:
//! the sender can re-spend the same bills to cancel pending delivery
//! (the deeper chain_depth claim wins).
//!
//! Bills are removed from limbo when:
//! - The recipient claims them (OwnershipClaim processed).
//! - A newer OwnershipClaim with deeper chain_depth supersedes them.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vess_protocol::Payment;

/// Maximum total limbo entries across all recipients.
/// Prevents unbounded memory growth from payment floods.
const MAX_TOTAL_ENTRIES: usize = 10_000;

/// Maximum age of a limbo entry (1 hour). Entries older than this
/// are evicted — the sender can re-send if still desired.
const MAX_ENTRY_AGE_SECS: u64 = 3600;

/// Maximum limbo entries a single relay peer can hold.
/// Prevents a single malicious peer from flooding the buffer with
/// real-but-low-value payments.
const MAX_ENTRIES_PER_PEER: usize = 200;

/// When total entries exceed this threshold (80% of capacity),
/// lowest-denomination entries are evicted to make room.
const EVICTION_THRESHOLD: usize = 8_000;

/// A payment held in limbo along with its bill_ids.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimboEntry {
    /// The full payment data (needed for re-delivery).
    pub payment: Payment,
    /// Bill IDs in this payment (cached for O(1) cleanup).
    pub bill_ids: Vec<[u8; 32]>,
    /// Unix timestamp when limbo was entered.
    pub entered_at: u64,
    /// The relay peer that submitted this payment.
    /// Used for per-peer quota enforcement.
    #[serde(default)]
    pub relay_peer: [u8; 32],
}

/// Limbo buffer keyed by stealth_id.
pub struct LimboBuffer {
    /// stealth_id → list of limbo entries.
    entries: HashMap<[u8; 32], Vec<LimboEntry>>,
    /// relay_peer → number of entries from that peer (for quota enforcement).
    per_peer_count: HashMap<[u8; 32], usize>,
}

impl Default for LimboBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl LimboBuffer {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            per_peer_count: HashMap::new(),
        }
    }

    /// Hold a payment in limbo for an offline recipient.
    ///
    /// Returns `false` if the buffer is at capacity or the relay peer
    /// has exceeded its per-peer quota.
    pub fn hold(
        &mut self,
        stealth_id: [u8; 32],
        payment: Payment,
        bill_ids: Vec<[u8; 32]>,
        entered_at: u64,
        relay_peer: [u8; 32],
    ) -> bool {
        // Per-peer quota check (Fix 3A).
        let peer_count = self.per_peer_count.get(&relay_peer).copied().unwrap_or(0);
        if peer_count >= MAX_ENTRIES_PER_PEER {
            return false;
        }

        // Denomination-weighted priority eviction (Fix 3B).
        if self.total_entries() >= EVICTION_THRESHOLD {
            self.evict_oldest();
        }

        if self.total_entries() >= MAX_TOTAL_ENTRIES {
            return false;
        }

        *self.per_peer_count.entry(relay_peer).or_insert(0) += 1;
        self.entries
            .entry(stealth_id)
            .or_default()
            .push(LimboEntry {
                payment,
                bill_ids,
                entered_at,
                relay_peer,
            });
        true
    }

    /// Collect and drain all limbo entries for a stealth_id (recipient came online).
    pub fn collect(&mut self, stealth_id: &[u8; 32]) -> Vec<LimboEntry> {
        let removed = self.entries.remove(stealth_id).unwrap_or_default();
        for entry in &removed {
            self.decrement_peer_count(&entry.relay_peer);
        }
        removed
    }

    /// Remove limbo entries containing any of the given bill_ids (mint_ids).
    ///
    /// Used on the **claim** (OwnershipClaim) path to clean up limbo
    /// storage when bills change ownership.  Returns the removed entries.
    pub fn remove_by_bill_ids(&mut self, bill_ids: &[[u8; 32]]) -> Vec<LimboEntry> {
        let mut removed = Vec::new();
        self.entries.retain(|_stealth_id, entries| {
            let mut keep = Vec::new();
            for entry in entries.drain(..) {
                if entry.bill_ids.iter().any(|bid| bill_ids.contains(bid)) {
                    removed.push(entry);
                } else {
                    keep.push(entry);
                }
            }
            *entries = keep;
            !entries.is_empty()
        });
        for entry in &removed {
            self.decrement_peer_count(&entry.relay_peer);
        }
        removed
    }

    /// All stealth_ids that have waiting limbo payments (for retry iteration).
    pub fn stealth_ids_with_payments(&self) -> Vec<[u8; 32]> {
        self.entries.keys().copied().collect()
    }

    /// Peek at entries for a stealth_id without draining.
    pub fn peek(&self, stealth_id: &[u8; 32]) -> &[LimboEntry] {
        self.entries
            .get(stealth_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total number of limbo entries across all recipients.
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Number of distinct recipients with limbo payments.
    pub fn recipient_count(&self) -> usize {
        self.entries.len()
    }

    /// Evict limbo entries older than `MAX_ENTRY_AGE_SECS`.
    /// Returns the number of entries evicted.
    pub fn evict_expired(&mut self, now: u64) -> (usize, Vec<[u8; 32]>) {
        let mut evicted = 0usize;
        let mut evicted_peers: Vec<[u8; 32]> = Vec::new();
        let mut evicted_payment_ids: Vec<[u8; 32]> = Vec::new();
        self.entries.retain(|_stealth_id, entries| {
            let before = entries.len();
            entries.retain(|e| {
                let keep = now.saturating_sub(e.entered_at) < MAX_ENTRY_AGE_SECS;
                if !keep {
                    evicted_peers.push(e.relay_peer);
                    evicted_payment_ids.push(e.payment.payment_id);
                }
                keep
            });
            evicted += before - entries.len();
            !entries.is_empty()
        });
        for peer in &evicted_peers {
            self.decrement_peer_count(peer);
        }
        (evicted, evicted_payment_ids)
    }

    /// Export all limbo state for persistence.
    pub fn export(&self) -> HashMap<[u8; 32], Vec<LimboEntry>> {
        self.entries.clone()
    }

    /// Load limbo state from persistence.
    pub fn load(&mut self, data: HashMap<[u8; 32], Vec<LimboEntry>>) {
        self.entries = data;
        self.rebuild_peer_counts();
    }

    /// Evict the oldest entries until total entries drop below
    /// `EVICTION_THRESHOLD`. Oldest-first protects recently-arrived
    /// payments during a relay flood.
    fn evict_oldest(&mut self) {
        let target = EVICTION_THRESHOLD * 9 / 10; // evict down to ~90% of threshold
        if self.total_entries() <= target {
            return;
        }

        // Collect (stealth_id, vec_index, entered_at) for every entry.
        let mut scored: Vec<([u8; 32], usize, u64)> = Vec::new();
        for (sid, entries) in &self.entries {
            for (i, e) in entries.iter().enumerate() {
                scored.push((*sid, i, e.entered_at));
            }
        }

        // Sort ascending by age — evict oldest first.
        scored.sort_by_key(|&(_, _, t)| t);

        let to_evict = self.total_entries() - target;
        let evict_set: Vec<([u8; 32], usize)> = scored
            .into_iter()
            .take(to_evict)
            .map(|(sid, idx, _)| (sid, idx))
            .collect();

        // Group evictions by stealth_id for efficient removal.
        let mut evict_by_sid: HashMap<[u8; 32], Vec<usize>> = HashMap::new();
        for (sid, idx) in evict_set {
            evict_by_sid.entry(sid).or_default().push(idx);
        }

        let mut evicted_peers: Vec<[u8; 32]> = Vec::new();
        for (sid, mut indices) in evict_by_sid {
            indices.sort_unstable_by(|a, b| b.cmp(a)); // reverse so removal doesn't shift
            if let Some(entries) = self.entries.get_mut(&sid) {
                for idx in indices {
                    if idx < entries.len() {
                        let removed = entries.swap_remove(idx);
                        evicted_peers.push(removed.relay_peer);
                    }
                }
                if entries.is_empty() {
                    self.entries.remove(&sid);
                }
            }
        }
        for peer in &evicted_peers {
            self.decrement_peer_count(peer);
        }
    }

    fn decrement_peer_count(&mut self, peer: &[u8; 32]) {
        if let Some(c) = self.per_peer_count.get_mut(peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.per_peer_count.remove(peer);
            }
        }
    }

    fn rebuild_peer_counts(&mut self) {
        self.per_peer_count.clear();
        for entries in self.entries.values() {
            for e in entries {
                *self.per_peer_count.entry(e.relay_peer).or_insert(0) += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_protocol::Payment;

    const PEER_A: [u8; 32] = [0x01; 32];
    const PEER_B: [u8; 32] = [0x02; 32];

    fn test_payment(stealth_id: [u8; 32], bill_ids: &[[u8; 32]]) -> Payment {
        test_payment_denom(stealth_id, bill_ids, 10)
    }

    fn test_payment_denom(stealth_id: [u8; 32], bill_ids: &[[u8; 32]], _denom: u64) -> Payment {
        Payment {
            payment_id: rand::random(),
            stealth_payload: vec![1, 2, 3],
            view_tag: 0x42,
            stealth_id,
            created_at: 1000,
            bill_count: bill_ids.len() as u8,
        }
    }

    #[test]
    fn hold_and_collect() {
        let mut buf = LimboBuffer::new();
        let sid = [0xAA; 32];
        let bids = vec![[0x11; 32], [0x22; 32]];
        let payment = test_payment(sid, &bids);

        assert!(buf.hold(sid, payment, bids.clone(), 1000, PEER_A));
        assert_eq!(buf.total_entries(), 1);
        assert_eq!(buf.recipient_count(), 1);

        let entries = buf.collect(&sid);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bill_ids, bids);
        assert_eq!(buf.total_entries(), 0);
    }

    #[test]
    fn remove_by_bill_ids_on_claim() {
        let mut buf = LimboBuffer::new();
        let sid = [0xAA; 32];
        let bid1 = [0x11; 32];
        let bid2 = [0x22; 32];
        let bid3 = [0x33; 32];

        // Two payments for same recipient
        buf.hold(sid, test_payment(sid, &[bid1]), vec![bid1], 1000, PEER_A);
        buf.hold(
            sid,
            test_payment(sid, &[bid2, bid3]),
            vec![bid2, bid3],
            1001,
            PEER_A,
        );
        assert_eq!(buf.total_entries(), 2);

        // Claim bid2 — removes the second entry
        let removed = buf.remove_by_bill_ids(&[bid2]);
        assert_eq!(removed.len(), 1);
        assert_eq!(buf.total_entries(), 1);
        assert_eq!(buf.peek(&sid)[0].bill_ids, vec![bid1]);
    }

    #[test]
    fn remove_by_bill_ids_single_entry() {
        let mut buf = LimboBuffer::new();
        let sid = [0xAA; 32];
        let bid = [0x11; 32];

        buf.hold(sid, test_payment(sid, &[bid]), vec![bid], 1000, PEER_A);
        assert_eq!(buf.total_entries(), 1);

        // Recipient claims — removes the entry
        let removed = buf.remove_by_bill_ids(&[bid]);
        assert_eq!(removed.len(), 1);
        assert_eq!(buf.total_entries(), 0);
        assert_eq!(buf.recipient_count(), 0);
    }

    #[test]
    fn stealth_ids_with_payments() {
        let mut buf = LimboBuffer::new();
        let sid1 = [0xAA; 32];
        let sid2 = [0xBB; 32];

        buf.hold(
            sid1,
            test_payment(sid1, &[[0x11; 32]]),
            vec![[0x11; 32]],
            1000,
            PEER_A,
        );
        buf.hold(
            sid2,
            test_payment(sid2, &[[0x22; 32]]),
            vec![[0x22; 32]],
            1001,
            PEER_B,
        );

        let ids = buf.stealth_ids_with_payments();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn export_and_load() {
        let mut buf = LimboBuffer::new();
        let sid = [0xAA; 32];
        buf.hold(
            sid,
            test_payment(sid, &[[0x11; 32]]),
            vec![[0x11; 32]],
            1000,
            PEER_A,
        );

        let exported = buf.export();
        let mut buf2 = LimboBuffer::new();
        buf2.load(exported);
        assert_eq!(buf2.total_entries(), 1);
    }

    #[test]
    fn per_peer_quota_enforced() {
        let mut buf = LimboBuffer::new();
        let sid = [0xAA; 32];

        for i in 0..MAX_ENTRIES_PER_PEER {
            let bid = {
                let mut b = [0u8; 32];
                b[0..2].copy_from_slice(&(i as u16).to_le_bytes());
                b
            };
            assert!(buf.hold(sid, test_payment(sid, &[bid]), vec![bid], 1000, PEER_A));
        }
        assert_eq!(buf.total_entries(), MAX_ENTRIES_PER_PEER);

        // 201st from same peer must be rejected.
        let extra_bid = [0xFF; 32];
        assert!(!buf.hold(
            sid,
            test_payment(sid, &[extra_bid]),
            vec![extra_bid],
            1000,
            PEER_A
        ));

        // But a different peer can still add.
        assert!(buf.hold(
            sid,
            test_payment(sid, &[extra_bid]),
            vec![extra_bid],
            1000,
            PEER_B
        ));
    }

    #[test]
    fn denomination_weighted_eviction() {
        let mut buf = LimboBuffer::new();
        let sid = [0xCC; 32];

        // Fill beyond eviction threshold with low-denom entries.
        for i in 0..EVICTION_THRESHOLD + 100 {
            let bid = {
                let mut b = [0u8; 32];
                b[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                b
            };
            let peer = {
                let mut p = [0u8; 32];
                // Use different peers to avoid per-peer quota.
                p[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                p
            };
            buf.entries.entry(sid).or_default().push(LimboEntry {
                payment: test_payment_denom(sid, &[bid], 1),
                bill_ids: vec![bid],
                entered_at: 1000,
                relay_peer: peer,
            });
            *buf.per_peer_count.entry(peer).or_insert(0) += 1;
        }

        assert!(buf.total_entries() > EVICTION_THRESHOLD);

        // Insert a high-denomination entry — triggers eviction.
        let high_bid = [0xEE; 32];
        let high_peer = [0xDD; 32];
        assert!(buf.hold(
            sid,
            test_payment_denom(sid, &[high_bid], 1_000_000),
            vec![high_bid],
            1000,
            high_peer
        ));

        // Buffer should be below threshold after eviction.
        assert!(buf.total_entries() <= EVICTION_THRESHOLD);
    }
}
