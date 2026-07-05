//! Node persistence — mesh seed and basic state.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Snapshot of ArteryState for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArterySnapshot {
    pub node_id: [u8; 32],
    pub peer_list: Vec<[u8; 32]>,
    #[serde(default)]
    pub known_peers: Vec<[u8; 32]>,
    #[serde(default)]
    pub peer_endpoints: Vec<String>,
    #[serde(default)]
    pub banned_peers: Vec<[u8; 32]>,
    #[serde(default)]
    pub last_sweep_epoch: Option<u64>,
}

pub struct NodeStorage {
    dir: PathBuf,
}

impl NodeStorage {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self { dir: dir.to_path_buf() })
    }
    pub fn dir(&self) -> &Path { &self.dir }
    pub fn default_dir() -> Option<PathBuf> {
        dirs_next::data_dir().map(|d| d.join("vess").join("artery"))
    }
    pub fn load(&self) -> Result<ArterySnapshot> {
        let path = self.dir.join("snapshot.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(ArterySnapshot { node_id: [0u8; 32], peer_list: vec![], known_peers: vec![], peer_endpoints: vec![], banned_peers: vec![], last_sweep_epoch: None })
        }
    }
    pub fn save(&self, snap: &ArterySnapshot) -> Result<()> {
        let path = self.dir.join("snapshot.json");
        let data = serde_json::to_string_pretty(snap)?;
        std::fs::write(&path, data)?;
        Ok(())
    }
}

pub fn hex_key(key: &[u8; 32]) -> String { hex::encode(&key[..8]) }
pub fn unhex_key(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s)?;
    let mut key = [0u8; 32];
    key[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    Ok(key)
}