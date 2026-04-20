//! **vess-kloak** — Wallet and bill management for the Vess protocol.
//!
//! The Kloak ("cloak") is the wallet layer that abstracts away
//! cryptographic complexity. It manages:
//!
//! - **BillFold**: Collection of owned Vess bills with denomination tracking.
//! - **Selection**: Branch-and-bound bill selection with greedy fallback.
//! - **Consolidation**: Automatic bill consolidation (e.g. five D1s → D5).
//! - **Recovery**: 5 BIP39 words + 5-digit PIN → deterministic key derivation.
//! - **Password Cache**: Fast daily unlock via Argon2id-encrypted seed cache.
//!
//! # Usage
//!
//! ```text
//! User types: "Send 15 Vess to +alice"
//!   → Kloak selects D10 + D5 from the billfold
//!   → Prepares stealth payload for alice's master address
//!   → Broadcasts via vascular pulse
//!   → Recipient claims via OwnershipClaim
//! ```

pub mod billfold;
pub mod selection;
pub mod auto_reforge;
pub mod recovery;
pub mod persistence;
pub mod payment;
pub mod tag_cache;

pub use billfold::BillFold;
pub use selection::select_bills;
pub use auto_reforge::ConsolidationScheduler;
pub use recovery::{RecoveryPhrase, EncryptedSecrets};
pub use persistence::WalletFile;
pub use payment::{PaymentTracker, cleanup_rejected_bills};
pub use tag_cache::TagCache;
