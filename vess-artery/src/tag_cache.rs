//! Persistent local VessTag address book.
//!
//! Caches every verified tag → stealth address mapping the wallet has
//! looked up or paid to.  On a cache hit the RPC send handler skips the
//! DHT entirely, making repeat payments instant.
//!
//! The cache lives at `<state_dir>/tag_cache.json` and is updated
//! atomically on every write.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// A single cached tag entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTag {
    pub scan_ek: Vec<u8>,
    pub spend_ek: Vec<u8>,
    /// Unix timestamp (seconds) when this entry was first verified.
    pub verified_at: u64,
    /// Unix timestamp (seconds) of the most recent lookup / send.
    pub last_used: u64,
}

/// Persistent local VessTag address book.
pub struct TagCache {
    entries: HashMap<String, CachedTag>,
    path: PathBuf,
}

impl TagCache {
    /// Load from `<path>` if it exists, otherwise start with an empty cache.
    pub fn load_or_create(path: PathBuf) -> Self {
        let entries = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(data) => serde_json::from_str::<HashMap<String, CachedTag>>(&data)
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "tag_cache.json malformed — starting fresh");
                        HashMap::new()
                    }),
                Err(e) => {
                    warn!(error = %e, "cannot read tag_cache.json — starting fresh");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };
        Self { entries, path }
    }

    /// Look up a tag.  Updates `last_used` and saves on hit.
    pub fn get(&mut self, tag_str: &str, now: u64) -> Option<CachedTag> {
        let entry = self.entries.get_mut(tag_str)?;
        entry.last_used = now;
        let cloned = entry.clone();
        // Best-effort save; ignore errors (non-fatal cache update).
        let _ = self.save();
        Some(cloned)
    }

    /// Insert or overwrite a tag entry and persist to disk.
    pub fn insert(&mut self, tag_str: &str, scan_ek: Vec<u8>, spend_ek: Vec<u8>, now: u64) {
        self.entries.insert(
            tag_str.to_owned(),
            CachedTag {
                scan_ek,
                spend_ek,
                verified_at: now,
                last_used: now,
            },
        );
        if let Err(e) = self.save() {
            warn!(error = %e, "failed to persist tag cache");
        }
    }

    /// Remove a specific tag from the cache.  Returns `true` if it existed.
    pub fn remove(&mut self, tag_str: &str) -> bool {
        let removed = self.entries.remove(tag_str).is_some();
        if removed {
            if let Err(e) = self.save() {
                warn!(error = %e, "failed to persist tag cache after remove");
            }
        }
        removed
    }

    /// Clear the entire cache.
    pub fn clear_all(&mut self) {
        self.entries.clear();
        if let Err(e) = self.save() {
            warn!(error = %e, "failed to persist tag cache after clear");
        }
    }

    /// Returns an iterator over `(tag_str, entry)` pairs sorted by `last_used` descending.
    pub fn list_sorted(&self) -> Vec<(&str, &CachedTag)> {
        let mut pairs: Vec<(&str, &CachedTag)> = self
            .entries
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        pairs.sort_by(|a, b| b.1.last_used.cmp(&a.1.last_used));
        pairs
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Atomically write the cache to disk.
    fn save(&self) -> anyhow::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        // Ensure the parent directory exists.
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(&self.entries)?;
        fs::write(&tmp, data.as_bytes())?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Serializable view of a single tag cache entry (used in RPC responses).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TagCacheEntryView {
    pub tag: String,
    pub scan_ek: String,
    pub spend_ek: String,
    pub verified_at: u64,
    pub last_used: u64,
}

impl TagCache {
    /// Convert the cache to a list of views for RPC / CLI output.
    pub fn to_views(&self) -> Vec<TagCacheEntryView> {
        let mut views: Vec<TagCacheEntryView> = self
            .entries
            .iter()
            .map(|(tag, entry)| TagCacheEntryView {
                tag: tag.clone(),
                scan_ek: to_hex(&entry.scan_ek),
                spend_ek: to_hex(&entry.spend_ek),
                verified_at: entry.verified_at,
                last_used: entry.last_used,
            })
            .collect();
        views.sort_by(|a, b| b.last_used.cmp(&a.last_used));
        views
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let dir = std::env::temp_dir().join("vess-tag-cache-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tag_cache.json");

        let mut cache = TagCache::load_or_create(path.clone());
        cache.insert("alice", vec![1u8; 32], vec![2u8; 32], 1000);

        let entry = cache.get("alice", 2000).unwrap();
        assert_eq!(entry.scan_ek, vec![1u8; 32]);
        assert_eq!(entry.verified_at, 1000);
        assert_eq!(entry.last_used, 2000);

        // Reload from disk.
        let mut cache2 = TagCache::load_or_create(path);
        let entry2 = cache2.get("alice", 3000).unwrap();
        assert_eq!(entry2.spend_ek, vec![2u8; 32]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_and_clear() {
        let dir = std::env::temp_dir().join("vess-tag-cache-remove-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tag_cache.json");

        let mut cache = TagCache::load_or_create(path);
        cache.insert("bob", vec![3u8; 32], vec![4u8; 32], 100);
        cache.insert("carol", vec![5u8; 32], vec![6u8; 32], 200);

        assert!(cache.remove("bob"));
        assert_eq!(cache.len(), 1);

        cache.clear_all();
        assert!(cache.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
