//! Node persistence — mesh seed and basic state.
use anyhow::Result;
use std::path::{Path, PathBuf};

pub struct NodeStorage {
    dir: PathBuf,
}

impl NodeStorage {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self { dir: dir.to_path_buf() })
    }
    pub fn dir(&self) -> &Path { &self.dir }
}

pub fn hex_key(key: &[u8; 32]) -> String { hex::encode(&key[..8]) }
pub fn unhex_key(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s)?;
    let mut key = [0u8; 32];
    key[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    Ok(key)
}