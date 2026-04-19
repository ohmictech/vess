//! **vess-foundry** — Cryptographically proven memory-hard minting for the Vess protocol.
//!
//! This crate implements a RandomX-inspired memory-hard function whose
//! execution trace is proved via an Interactive Oracle Proof (IOP) with
//! Merkle commitments and Fiat-Shamir spot-check verification. Minting a
//! `VessBill` requires sustained memory bandwidth and computation
//! proportional to the denomination, anchoring digital value to physical
//! electricity cost.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────┐     ┌────────────┐     ┌────────────┐
//! │  mint.rs  │────▶│   vm.rs    │────▶│  proof.rs  │
//! │ (loop +   │     │ (scratchpad│     │ (Merkle +  │
//! │ difficulty│     │  + execute)│     │  IOP + FS) │
//! └───────────┘     └────────────┘     └────────────┘
//!       │                                     │
//!       └──────── VessBill { proof } ◀────────┘
//! ```
//!
//! # Modules
//!
//! - [`vm`] — RandomX-inspired memory-hard virtual machine.
//! - [`merkle`] — Blake3-based Merkle tree for commitments.
//! - [`proof`] — IOP proof generation and verification.
//! - [`mint`] — Minting loop, difficulty scaling, bill production.
//! - [`reforge`] — Split/combine reforge circuit (value conservation).
//! - [`seal`] — Bill sealing/unsealing for DHT storage.
//! - [`spend_auth`] — ML-DSA-65 spend authorization.

pub mod vm;
pub mod merkle;
pub mod proof;
pub mod mint;
pub mod reforge;
pub mod seal;
pub mod spend_auth;

use serde::{Deserialize, Serialize};

/// Bill denomination following the 1-2-5 series: any `d × 10^k` where
/// `d ∈ {1, 2, 5}` and `k ≥ 0`, up to the `u64` limit.
///
/// Examples of valid denominations: 1, 2, 5, 10, 20, 50, 100, 200, 500,
/// 1000, …, 5_000_000_000_000_000_000.
///
/// Higher denominations require exponentially more work to mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Denomination(u64);

impl Denomination {
    // ── Common constants for readability ──────────────────────────

    pub const D1: Self = Self(1);
    pub const D2: Self = Self(2);
    pub const D5: Self = Self(5);
    pub const D10: Self = Self(10);
    pub const D20: Self = Self(20);
    pub const D50: Self = Self(50);
    pub const D100: Self = Self(100);
    pub const D200: Self = Self(200);
    pub const D500: Self = Self(500);
    pub const D1000: Self = Self(1_000);
    pub const D2000: Self = Self(2_000);
    pub const D5000: Self = Self(5_000);
    pub const D10000: Self = Self(10_000);
    pub const D20000: Self = Self(20_000);
    pub const D50000: Self = Self(50_000);

    /// Check whether a u64 is a valid 1-2-5 denomination.
    ///
    /// A value is valid iff after stripping all trailing zeros the
    /// remaining digit is 1, 2, or 5.
    pub fn is_valid(v: u64) -> bool {
        if v == 0 {
            return false;
        }
        let mut n = v;
        while n.is_multiple_of(10) {
            n /= 10;
        }
        n == 1 || n == 2 || n == 5
    }

    /// Create from a raw u64, returning `None` if it is not a valid
    /// 1-2-5 denomination.
    pub fn from_value(v: u64) -> Option<Self> {
        if Self::is_valid(v) {
            Some(Self(v))
        } else {
            None
        }
    }

    /// Face value as a u64.
    pub fn value(self) -> u64 {
        self.0
    }

    /// The linear work multiplier for this denomination.
    ///
    /// A V50 bill requires 50× the VM iterations of a V1.
    pub fn multiplier(self) -> u64 {
        self.0
    }

    /// Position in the 1-2-5 series (0 for V1, 1 for V2, 2 for V5,
    /// 3 for V10, …). Used for logarithmic difficulty scaling.
    pub fn series_position(self) -> u32 {
        let mut n = self.0;
        let mut k = 0u32;
        while n.is_multiple_of(10) {
            n /= 10;
            k += 1;
        }
        let offset = match n {
            1 => 0,
            2 => 1,
            5 => 2,
            _ => 0, // unreachable for valid denominations
        };
        3 * k + offset
    }

    /// Generate the 1-2-5 series in descending order down to 1,
    /// containing every valid denomination ≤ `max`.
    pub fn series_up_to(max: u64) -> Vec<Denomination> {
        let mut values = Vec::new();
        let mut power: u64 = 1;
        loop {
            for &d in &[1u64, 2, 5] {
                if let Some(val) = d.checked_mul(power) {
                    if val <= max {
                        values.push(val);
                    }
                }
            }
            match power.checked_mul(10) {
                Some(p) => power = p,
                None => break,
            }
        }
        values.sort_unstable_by(|a, b| b.cmp(a));
        values.into_iter().map(Denomination).collect()
    }
}

impl std::fmt::Display for Denomination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "V{}", self.0)
    }
}

/// A minted Vess bill — a proof-of-work token anchored to physical energy.
///
/// Each bill contains:
/// - The **denomination** (how much it represents).
/// - The IOP **proof** bytes attesting to correct VM execution.
/// - The VM execution **digest** for quick identity checks.
/// - A **created_at** timestamp recording when the bill was minted or last reforged.
/// - A **stealth_id** binding the bill to its current owner's stealth address.
/// - A permanent **mint_id** identifying this bill across all ownership transfers.
/// - A **chain_tip** tracking the current ownership hash chain state.
///
/// Bills are stored permanently in the DHT and never expire. Consumed
/// bills (spent via the ownership registry) are deleted from the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VessBill {
    pub denomination: Denomination,
    /// Blake3 digest of the final VM register state.
    pub digest: [u8; 32],
    /// Unix timestamp (seconds) when this bill was minted or last reforged.
    pub created_at: u64,
    /// Stealth address identifier binding this bill to an owner.
    /// Derived via DKSAP + ML-KEM.
    pub stealth_id: [u8; 32],
    /// DHT storage index derived from the owner's spend seed.
    /// Used for deterministic bill recovery.
    pub dht_index: u64,
    /// Permanent bill identity derived at mint time.
    /// `mint_id = Blake3("vess-mint-id-v0" || digest || proof.nonce)`
    /// Immutable — survives all ownership transfers.
    pub mint_id: [u8; 32],
    /// Current ownership chain tip (Blake3 hash chain).
    /// Genesis: `Blake3("vess-chain-v0" || mint_id || owner_vk_hash)`
    /// Transfer: `Blake3(prev_chain_tip || new_owner_vk_hash || transfer_sig_hash)`
    pub chain_tip: [u8; 32],
    /// Number of ownership transfers since genesis. Genesis = 0, first
    /// transfer = 1, etc. Travels with the bill so the recipient can
    /// compute `chain_depth + 1` when building their OwnershipClaim.
    #[serde(default)]
    pub chain_depth: u64,
}

impl VessBill {
    /// Hex-encoded mint_id for display / indexing.
    pub fn mint_id_hex(&self) -> String {
        self.mint_id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Compute the deterministic DHT key for this bill's storage location.
    ///
    /// The key is `Blake3(spend_seed || "vess-bill-v0" || dht_index)`. Since
    /// the wallet knows `spend_seed` from the recovery phrase, it can
    /// reconstruct all DHT keys without storing any state.
    pub fn dht_key(spend_seed: &[u8; 32], index: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(spend_seed);
        h.update(b"vess-bill-v0");
        h.update(&index.to_le_bytes());
        *h.finalize().as_bytes()
    }
}

/// Derive the permanent mint identity from the STARK execution.
///
/// `mint_id = Blake3("vess-mint-id-v0" || digest || nonce)`
///
/// This is immutable — it identifies the bill across all ownership
/// transfers. The digest + nonce together uniquely identify the mining
/// event, and the owner's vk_hash is already baked into the STARK seed.
pub fn derive_mint_id(digest: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-mint-id-v0");
    h.update(digest);
    h.update(nonce);
    *h.finalize().as_bytes()
}

/// Compute the genesis ownership chain tip.
///
/// `chain[0] = Blake3("vess-chain-v0" || mint_id || owner_vk_hash)`
///
/// This is the first link in the ownership hash chain, binding the
/// genesis miner's identity to the bill's permanent ID.
pub fn genesis_chain_tip(mint_id: &[u8; 32], owner_vk_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-chain-v0");
    h.update(mint_id);
    h.update(owner_vk_hash);
    *h.finalize().as_bytes()
}

/// Advance the ownership chain by one transfer.
///
/// `chain[n] = Blake3(prev_chain_tip || new_owner_vk_hash || transfer_sig_hash)`
///
/// The `transfer_sig_hash` is `Blake3(transfer_signature)` — we hash the
/// large ML-DSA-65 signature (3293 bytes) down to 32 bytes before including
/// it in the chain. This keeps the chain tip derivation constant-size.
pub fn advance_chain_tip(
    prev_chain_tip: &[u8; 32],
    new_owner_vk_hash: &[u8; 32],
    transfer_sig: &[u8],
) -> [u8; 32] {
    let sig_hash = blake3::hash(transfer_sig);
    let mut h = blake3::Hasher::new();
    h.update(prev_chain_tip);
    h.update(new_owner_vk_hash);
    h.update(sig_hash.as_bytes());
    *h.finalize().as_bytes()
}
