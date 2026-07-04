//! **vess-foundry** — Core Vess primitives.
pub mod mine;
pub mod spend_auth;
pub mod vess;
pub use vess::Vess;
pub type Denomination = u64;

use blake3::Hasher;

pub fn advance_chain_tip_with_hash(prev: &[u8; 32], commitment: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"vess-chain-v1");
    h.update(prev);
    h.update(commitment);
    h.update(salt);
    *h.finalize().as_bytes()
}

pub fn genesis_chain_tip(mint_id: &[u8; 32], owner_vk_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"vess-chain-v1");
    h.update(mint_id);
    h.update(owner_vk_hash);
    *h.finalize().as_bytes()
}
pub fn advance_chain_tip(prev: &[u8; 32], owner_vk_hash: &[u8; 32]) -> [u8; 32] {
    genesis_chain_tip(prev, owner_vk_hash)
}

pub mod clock;
