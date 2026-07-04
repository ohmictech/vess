//! Vess — self-verifying UTXO with embedded ownership chain.
use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vess {
    pub amount: u64,
    pub epoch: u64,
    pub nonce: u64,
    pub initial_pk: [u8; 32],
    pub owner_vk: Vec<u8>,
    pub prev_sig: Vec<u8>,
    pub chain_depth: u64,
    #[serde(default)]
    pub consumed: Vec<[u8; 32]>,
    #[serde(default)]
    pub change_sig: Vec<u8>,
    pub chain_tip: [u8; 32],
    pub digest: [u8; 32],
    pub created_at: u64,
    pub stealth_id: [u8; 32],
    pub dht_index: u64,
}

impl Vess {
    pub fn compute_vess_id(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        if self.is_faucet() {
            h.update(b"vess-faucet-v1");
            h.update(&self.amount.to_le_bytes());
            h.update(&self.epoch.to_be_bytes());
            // NOT including initial_pk or owner_vk — one bill per epoch
        } else if self.is_mined() {
            h.update(b"vess-mined-v1");
            h.update(&self.amount.to_le_bytes());
            h.update(&self.epoch.to_le_bytes());
            h.update(&self.nonce.to_le_bytes());
            h.update(&self.initial_pk);
        } else {
            h.update(b"vess-change-v1");
            for c in &self.consumed { h.update(c); }
            h.update(&self.amount.to_le_bytes());
            h.update(&self.owner_vk);
        }
        *h.finalize().as_bytes()
    }

    pub fn is_mined(&self) -> bool { self.epoch > 0 && self.nonce > 0 && self.consumed.is_empty() }
    pub fn is_changed(&self) -> bool { !self.consumed.is_empty() && self.epoch == 0 && self.nonce == 0 }
    pub fn is_faucet(&self) -> bool { self.epoch > 0 && self.nonce == 0 && self.consumed.is_empty() }

    pub fn owner_vk_hash(&self) -> [u8; 32] { crate::spend_auth::vk_hash(&self.owner_vk) }


    pub fn change_commitment(inputs: &[[u8; 32]], outputs: &[Vess]) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"vess-change-v1");
        for inp in inputs { h.update(inp); }
        for out in outputs {
            h.update(&out.compute_vess_id());
            h.update(&out.amount.to_le_bytes());
            h.update(&out.owner_vk);
        }
        *h.finalize().as_bytes()
    }
}