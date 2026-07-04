//! **vess-artery** — Infrastructure node logic for the Vess protocol.
//!
//! Artery nodes are the backbone of the vascular network. They provide:
//!
//! - **Ownership Registry**: Blake3 Merkle-backed registry of active bill ownership.
//! - **Limbo Buffer**: Soft-hold payment buffer for offline recipients.
//! - **Tag DHT**: Distributed hash table for VessTag records.
//! - **Manifest Store**: Encrypted wallet manifests for seed-based recovery.
//! - **Local RPC**: JSON-over-TCP server on `127.0.0.1` for CLI interaction.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐            ┌──────────┐            ┌──────────┐
//! │ Artery A │◄──────────▶│ Artery B │◄──────────▶│ Artery C │
//! │ registry │            │ registry │            │ registry │
//! │  limbo   │            │  limbo   │            │  limbo   │
//! │  tag_dht │            │  tag_dht │            │  tag_dht │
//! │  manifest│            │  manifest│            │  manifest│
//! └──────────┘            └──────────┘            └──────────┘
//! ```

pub mod banishment;
pub mod gossip;
pub mod handshake;
pub mod kademlia;
pub mod limbo_buffer;
pub mod local_discovery;
pub mod mesh_contact;
pub mod payment_builder;
pub mod node_runner;
pub mod ownership_registry;
pub mod persistence;
pub mod rpc;
pub mod tag_cache;
pub mod tag_dht;
pub mod vess_store;
pub mod tag_resolver;

pub use banishment::BanishmentManager;
pub use gossip::GossipConfig;
pub use handshake::{compute_handshake_pow, verify_handshake_pow};
pub use handshake::{PeerRegistry, PeerState, ALLOWED_VERSIONS, PROTOCOL_VERSION_HASH};
pub use handshake::{HANDSHAKE_POW_M_COST, HANDSHAKE_POW_P_COST, HANDSHAKE_POW_T_COST};
pub use limbo_buffer::LimboBuffer;
pub use ownership_registry::{dht_replication_factor, OwnershipRegistry, OwnershipRecord, ConsumedRecord};
pub use tag_dht::TagDht;
pub use tag_resolver::{TagResolution, TagResolver, QUORUM_THRESHOLD};

/// Blinding factor for privacy-preserving DHT queries.
/// Storage keys stay as plain `mint_id`; queries use `blinded_dht_key(mint_id, blinding)`.
pub fn blinded_dht_key(base_key: &[u8; 32], blinding: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(11 + 32 + 32);
    input.extend_from_slice(b"vess-dht-query-v1");
    input.extend_from_slice(base_key);
    input.extend_from_slice(blinding);
    *blake3::hash(&input).as_bytes()
}
