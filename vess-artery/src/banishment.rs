//! Silent banishment manager for unauthorized peers.
//!
//! Peers that fail the handshake challenge (wrong or missing
//! `PROTOCOL_VERSION_HASH`) are permanently added to the ban list.
//! All subsequent traffic from a banished peer is silently dropped —
//! no error messages, no warnings sent over the wire.
//!
//! The manager is internally synchronised with [`std::sync::RwLock`] so it
//! can be shared across tasks without holding the main state `Mutex`.  Read
//! operations (the hot path — checking every inbound message) never block
//! each other.

use std::collections::HashSet;
use std::sync::RwLock;

/// Thread-safe set of banished peer identity hashes.
///
/// Designed for the hot path: `is_banished` takes a read lock, so
/// concurrent checks from multiple handler tasks never contend.
pub struct BanishmentManager {
    banned: RwLock<HashSet<[u8; 32]>>,
}

impl BanishmentManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self {
            banned: RwLock::new(HashSet::new()),
        }
    }

    /// Permanently banish a peer by their identity hash.
    pub fn banish(&self, peer_id: [u8; 32]) {
        self.banned.write().unwrap().insert(peer_id);
    }

    /// Check whether a peer is banished.
    ///
    /// This is the hot-path call — uses a read lock so concurrent checks
    /// from different handler tasks do not block each other.
    pub fn is_banished(&self, peer_id: &[u8; 32]) -> bool {
        self.banned.read().unwrap().contains(peer_id)
    }

    /// Number of currently banished peers.
    pub fn count(&self) -> usize {
        self.banned.read().unwrap().len()
    }

    /// Export all banished identity hashes (for persistence / diagnostics).
    pub fn all_banned(&self) -> Vec<[u8; 32]> {
        self.banned.read().unwrap().iter().copied().collect()
    }

    /// Bulk-import previously banished peers (e.g. from disk).
    pub fn import(&self, peers: impl IntoIterator<Item = [u8; 32]>) {
        let mut set = self.banned.write().unwrap();
        for id in peers {
            set.insert(id);
        }
    }
}

impl Default for BanishmentManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banish_and_check() {
        let mgr = BanishmentManager::new();
        let peer = [0x01; 32];

        assert!(!mgr.is_banished(&peer));
        mgr.banish(peer);
        assert!(mgr.is_banished(&peer));
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn multiple_bans() {
        let mgr = BanishmentManager::new();
        mgr.banish([0x01; 32]);
        mgr.banish([0x02; 32]);
        mgr.banish([0x03; 32]);
        assert_eq!(mgr.count(), 3);
        assert!(!mgr.is_banished(&[0x04; 32]));
    }

    #[test]
    fn duplicate_banish_is_idempotent() {
        let mgr = BanishmentManager::new();
        let peer = [0xAA; 32];
        mgr.banish(peer);
        mgr.banish(peer);
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn export_import_round_trip() {
        let mgr = BanishmentManager::new();
        mgr.banish([0x01; 32]);
        mgr.banish([0x02; 32]);

        let exported = mgr.all_banned();
        assert_eq!(exported.len(), 2);

        let mgr2 = BanishmentManager::new();
        mgr2.import(exported);
        assert!(mgr2.is_banished(&[0x01; 32]));
        assert!(mgr2.is_banished(&[0x02; 32]));
        assert!(!mgr2.is_banished(&[0x03; 32]));
    }

    #[test]
    fn concurrent_read_access() {
        use std::sync::Arc;

        let mgr = Arc::new(BanishmentManager::new());
        mgr.banish([0xFF; 32]);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let m = mgr.clone();
                std::thread::spawn(move || m.is_banished(&[0xFF; 32]))
            })
            .collect();

        for h in handles {
            assert!(h.join().unwrap());
        }
    }
}
