//! Vess Store — DHT-distributed Vess store with conflict resolution.
use std::collections::HashMap;
use vess_foundry::Vess;

#[derive(Debug, Clone, Default)]
pub struct VessStore {
    active: HashMap<[u8; 32], Vess>,
    consumed: HashMap<[u8; 32], u64>,
}

impl VessStore {
    pub fn upsert(&mut self, v: &Vess) -> bool {
        let id = v.compute_vess_id();
        if self.consumed.contains_key(&id) { return false; }
        if let Some(existing) = self.active.get(&id) {
            if v.chain_depth < existing.chain_depth { return false; }
            if v.chain_depth == existing.chain_depth && id >= existing.compute_vess_id() { return false; }
        }
        self.active.insert(id, v.clone());
        true
    }
    pub fn consume(&mut self, ids: &[[u8; 32]], epoch: u64) {
        for id in ids { self.active.remove(id); self.consumed.insert(*id, epoch); }
    }
    pub fn prune_consumed(&mut self, min_epoch: u64) {
        self.consumed.retain(|_, &mut e| e >= min_epoch);
    }
    pub fn is_consumed(&self, id: &[u8; 32]) -> bool { self.consumed.contains_key(id) }
    pub fn get(&self, id: &[u8; 32]) -> Option<&Vess> { self.active.get(id) }
    pub fn len(&self) -> usize { self.active.len() }
    pub fn iter(&self) -> impl Iterator<Item = &Vess> { self.active.values() }
}