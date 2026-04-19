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

pub mod ownership_registry;
pub mod gossip;
pub mod tag_dht;
pub mod tag_resolver;
pub mod persistence;
pub mod handshake;
pub mod banishment;
pub mod limbo_buffer;
pub mod reputation;
pub mod kademlia;
pub mod node_runner;
pub mod dns_seed;
pub mod rpc;

pub use ownership_registry::{OwnershipRegistry, dht_replication_factor};
pub use limbo_buffer::LimboBuffer;
pub use gossip::GossipConfig;
pub use tag_dht::TagDht;
pub use tag_resolver::{TagResolver, TagResolution, QUORUM_THRESHOLD};
pub use persistence::{ArterySnapshot, NodeStorage};
pub use handshake::{PeerRegistry, PeerState, PROTOCOL_VERSION_HASH, ALLOWED_VERSIONS};
pub use handshake::{compute_handshake_pow, verify_handshake_pow};
pub use handshake::{HANDSHAKE_POW_M_COST, HANDSHAKE_POW_T_COST, HANDSHAKE_POW_P_COST};
pub use banishment::BanishmentManager;
pub use reputation::ReputationTable;
