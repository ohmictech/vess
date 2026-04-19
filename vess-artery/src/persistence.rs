//! Artery node state persistence.
//!
//! Saves and loads the full artery node state (ownership registry, tags,
//! limbo, mailbox, reputations, manifests) to disk as JSON.
//!
//! On startup the node loads from disk; on shutdown (or periodic flush)
//! it writes everything back.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use vess_tag::TagRecord;

use crate::limbo_buffer::LimboEntry;
use crate::ownership_registry::OwnershipRecord;
use crate::reputation::PeerReputation;

/// Serializable snapshot of all artery state for disk persistence.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArterySnapshot {
    /// Tag DHT records keyed by hex-encoded DHT key.
    pub tags: BTreeMap<String, TagRecord>,
    /// Legacy bill DHT records — kept for deserialization compatibility.
    /// No longer populated; sealed bills are embedded in ownership records.
    #[serde(default)]
    pub bills: BTreeMap<String, serde_json::Value>,
    /// Mailbox buffers keyed by hex-encoded stealth ID.
    pub mailbox: BTreeMap<String, Vec<serde_json::Value>>,
    /// Known peer node IDs.
    pub known_peers: Vec<[u8; 32]>,
    /// Limbo buffer entries keyed by hex-encoded stealth ID.
    #[serde(default)]
    pub limbo_entries: BTreeMap<String, Vec<LimboEntry>>,
    /// Peer reputation records: `(peer_id_hash, reputation)`.
    #[serde(default)]
    pub peer_reputations: Vec<([u8; 32], PeerReputation)>,
    /// Mint IDs used to harden tags (prevents replay).
    #[serde(default)]
    pub hardening_proofs: Vec<[u8; 32]>,
    /// Locally-banished peer IDs (persisted across restarts).
    #[serde(default)]
    pub banned_peers: Vec<[u8; 32]>,
    /// Ownership registry records.
    #[serde(default)]
    pub ownership_records: Vec<OwnershipRecord>,
    /// Encrypted wallet manifests keyed by hex-encoded DHT key.
    #[serde(default)]
    pub manifests: BTreeMap<String, Vec<u8>>,
}

impl ArterySnapshot {
    /// Create an empty snapshot.
    pub fn empty() -> Self {
        Self {
            tags: BTreeMap::new(),
            bills: BTreeMap::new(),
            mailbox: BTreeMap::new(),
            known_peers: Vec::new(),
            limbo_entries: BTreeMap::new(),
            peer_reputations: Vec::new(),
            hardening_proofs: Vec::new(),
            banned_peers: Vec::new(),
            ownership_records: Vec::new(),
            manifests: BTreeMap::new(),
        }
    }
}

/// Manages the artery node's on-disk state directory.
pub struct NodeStorage {
    dir: PathBuf,
}

impl NodeStorage {
    /// Open or create a state directory at the given path.
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)
            .with_context(|| format!("create state directory: {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Default state directory: `~/.vess-artery/`
    pub fn default_dir() -> Result<PathBuf> {
        let home = dirs_next::home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
        Ok(home.join(".vess-artery"))
    }

    /// Load the artery state snapshot from disk.
    ///
    /// Returns an empty snapshot if the state file doesn't exist yet.
    pub fn load(&self) -> Result<ArterySnapshot> {
        let state_path = self.dir.join("state.json");
        if !state_path.exists() {
            return Ok(ArterySnapshot::empty());
        }
        let data = fs::read_to_string(&state_path)
            .with_context(|| format!("read state file: {}", state_path.display()))?;
        let snapshot: ArterySnapshot = serde_json::from_str(&data)
            .context("deserialize artery state")?;
        Ok(snapshot)
    }

    /// Save the artery state snapshot to disk atomically.
    ///
    /// Writes to a temporary file then renames, preventing corruption
    /// if the process is killed during write.
    pub fn save(&self, snapshot: &ArterySnapshot) -> Result<()> {
        let state_path = self.dir.join("state.json");
        let tmp_path = self.dir.join("state.json.tmp");

        let data = serde_json::to_string_pretty(snapshot)
            .context("serialize artery state")?;
        fs::write(&tmp_path, data.as_bytes())
            .with_context(|| format!("write temp state file: {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &state_path)
            .with_context(|| format!("rename state file: {}", state_path.display()))?;
        Ok(())
    }

    /// State directory path.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Encode a 32-byte key as hex string (for JSON map keys).
pub fn hex_key(key: &[u8; 32]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string back to a 32-byte key.
pub fn unhex_key(s: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(s.len() == 64, "hex key must be 64 chars, got {}", s.len());
    let mut key = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        key[i] = (hi << 4) | lo;
    }
    Ok(key)
}

fn hex_digit(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => anyhow::bail!("invalid hex digit: {b}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let key = [0xAB; 32];
        let hex = hex_key(&key);
        let decoded = unhex_key(&hex).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("vess-artery-persist-test");
        let _ = fs::remove_dir_all(&dir);

        let storage = NodeStorage::open(&dir).unwrap();

        let mut snapshot = ArterySnapshot::empty();
        snapshot.known_peers.push([0xFF; 32]);

        storage.save(&snapshot).unwrap();
        let loaded = storage.load().unwrap();

        assert_eq!(loaded.known_peers.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_returns_empty() {
        let dir = std::env::temp_dir().join("vess-artery-persist-empty");
        let _ = fs::remove_dir_all(&dir);

        let storage = NodeStorage::open(&dir).unwrap();
        let snapshot = storage.load().unwrap();

        assert!(snapshot.tags.is_empty());
        assert!(snapshot.ownership_records.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }
}
