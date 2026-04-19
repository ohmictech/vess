//! Permanent local cache of verified VessTag → MasterStealthAddress associations.
//!
//! Once a tag has been resolved via quorum verification (5+ nodes agree),
//! the association is stored permanently in the wallet. Tags are immutable
//! in the DHT (first-broadcast-wins, never expires), so a verified
//! association never goes stale.
//!
//! The cache is serialized alongside the wallet file so it survives
//! across restarts.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use vess_stealth::MasterStealthAddress;
use vess_tag::VessTag;

/// A cached tag → address association that has been quorum-verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTag {
    /// The verified master stealth address for this tag.
    pub address: MasterStealthAddress,
    /// Number of nodes that confirmed the association during resolution.
    pub confirming_nodes: usize,
    /// When the tag was originally registered (from the DHT record).
    pub registered_at: u64,
    /// When we locally verified and cached this association.
    pub cached_at: u64,
}

/// Permanent local cache of quorum-verified tag associations.
///
/// Once a tag is verified, it never needs to be looked up again —
/// tags are immutable in the Vess protocol.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TagCache {
    entries: HashMap<String, CachedTag>,
}

impl TagCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached tag association.
    ///
    /// Returns `Some` if this tag has been previously verified via quorum.
    pub fn get(&self, tag: &VessTag) -> Option<&CachedTag> {
        self.entries.get(tag.as_str())
    }

    /// Store a verified tag association permanently.
    ///
    /// Should only be called after quorum verification succeeds.
    pub fn insert(
        &mut self,
        tag: &VessTag,
        address: MasterStealthAddress,
        confirming_nodes: usize,
        registered_at: u64,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.entries.insert(
            tag.as_str().to_owned(),
            CachedTag {
                address,
                confirming_nodes,
                registered_at,
                cached_at: now,
            },
        );
    }

    /// Check whether a tag is already cached.
    pub fn contains(&self, tag: &VessTag) -> bool {
        self.entries.contains_key(tag.as_str())
    }

    /// Number of cached tag associations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All cached entries (for persistence serialization).
    pub fn entries(&self) -> impl Iterator<Item = (&str, &CachedTag)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_address() -> MasterStealthAddress {
        MasterStealthAddress {
            scan_ek: vec![0x11; 64],
            spend_ek: vec![0x22; 64],
        }
    }

    #[test]
    fn insert_and_lookup() {
        let mut cache = TagCache::new();
        let tag = VessTag::new("alice").unwrap();
        let addr = make_address();

        assert!(!cache.contains(&tag));
        cache.insert(&tag, addr.clone(), 5, 1000);

        assert!(cache.contains(&tag));
        let cached = cache.get(&tag).unwrap();
        assert_eq!(cached.address.scan_ek, addr.scan_ek);
        assert_eq!(cached.confirming_nodes, 5);
        assert_eq!(cached.registered_at, 1000);
    }

    #[test]
    fn unknown_tag_returns_none() {
        let cache = TagCache::new();
        let tag = VessTag::new("unknown").unwrap();
        assert!(cache.get(&tag).is_none());
    }

    #[test]
    fn len_and_empty() {
        let mut cache = TagCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        cache.insert(&VessTag::new("alice").unwrap(), make_address(), 5, 1000);
        assert_eq!(cache.len(), 1);

        cache.insert(&VessTag::new("bob15").unwrap(), make_address(), 7, 2000);
        assert_eq!(cache.len(), 2);
    }
}
