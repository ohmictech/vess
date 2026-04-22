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
pub mod dns_seed;
pub mod gossip;
pub mod handshake;
pub mod kademlia;
pub mod limbo_buffer;
pub mod node_runner;
pub mod ownership_registry;
pub mod persistence;
pub mod reputation;
pub mod rpc;
pub mod tag_cache;
pub mod tag_dht;
pub mod tag_resolver;

pub use banishment::BanishmentManager;
pub use gossip::GossipConfig;
pub use handshake::{compute_handshake_pow, verify_handshake_pow};
pub use handshake::{PeerRegistry, PeerState, ALLOWED_VERSIONS, PROTOCOL_VERSION_HASH};
pub use handshake::{HANDSHAKE_POW_M_COST, HANDSHAKE_POW_P_COST, HANDSHAKE_POW_T_COST};
pub use limbo_buffer::LimboBuffer;
pub use ownership_registry::{dht_replication_factor, OwnershipRegistry};
pub use persistence::{ArterySnapshot, NodeStorage};
pub use reputation::ReputationTable;
pub use tag_dht::TagDht;
pub use tag_resolver::{TagResolution, TagResolver, QUORUM_THRESHOLD};
