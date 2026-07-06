//! Ownership Registry — DHT-distributed bill ownership tracking.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn dht_replication_factor(estimated_network_size: usize) -> usize {
    std::cmp::max(50, (estimated_network_size as f64).sqrt() as usize)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipRecord {
    pub mint_id: [u8; 32],
    pub chain_tip: [u8; 32],
    pub current_owner_vk_hash: [u8; 32],
    pub current_owner_vk: Vec<u8>,
    pub denomination_value: u64,
    pub updated_at: u64,
    pub proof_hash: [u8; 32],
    pub digest: [u8; 32],
    pub nonce: [u8; 32],
    #[serde(default)]
    pub prev_claim_vk_hash: Option<[u8; 32]>,
    pub claim_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub locked_until_tick: u64,
    #[serde(default)]
    pub prev_transfer_chain_tip: Option<[u8; 32]>,
    #[serde(default)]
    pub chain_depth: u64,
    #[serde(default)]
    pub encrypted_bill: Vec<u8>,
    #[serde(default)]
    pub accumulated_work: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumedRecord {
    pub reforge_id: [u8; 32],
    pub output_mint_ids: Vec<[u8; 32]>,
    pub consumed_at: u64,
    pub denomination_value: u64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct OwnershipRegistry {
    records: HashMap<[u8; 32], OwnershipRecord>,
    consumed: HashMap<[u8; 32], ConsumedRecord>,
}

impl OwnershipRegistry {
    pub fn new() -> Self {
        Self { records: HashMap::new(), consumed: HashMap::new() }
    }
    pub fn get(&self, mint_id: &[u8; 32]) -> Option<&OwnershipRecord> {
        self.records.get(mint_id)
    }
    pub fn insert(&mut self, record: OwnershipRecord) {
        self.records.insert(record.mint_id, record);
    }
    pub fn remove(&mut self, mint_id: &[u8; 32]) -> Option<OwnershipRecord> {
        self.records.remove(mint_id)
    }
    pub fn insert_consumed_record(&mut self, mint_id: [u8; 32], record: ConsumedRecord) {
        self.consumed.insert(mint_id, record);
    }
    pub fn get_consumed(&self, mint_id: &[u8; 32]) -> Option<&ConsumedRecord> {
        self.consumed.get(mint_id)
    }
    pub fn len(&self) -> usize { self.records.len() }
    pub fn is_empty(&self) -> bool { self.records.is_empty() }
    pub fn all_records(&self) -> Vec<&OwnershipRecord> {
        self.records.values().collect()
    }
    pub fn all_consumed(&self) -> Vec<(&[u8; 32], &ConsumedRecord)> {
        self.consumed.iter().map(|(k, v)| (k, v)).collect()
    }
}
