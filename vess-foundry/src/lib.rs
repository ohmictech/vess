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

pub mod merkle;
pub mod mint;
pub mod proof;
pub mod reforge;
pub mod seal;
pub mod spend_auth;
pub mod vm;

use hex;
use serde::{Deserialize, Serialize};

/// Bill denomination following the 1-2-5 series: any `d × 10^k` where
/// `d ∈ {1, 2, 5}` and `k ≥ 0`, up to the `u64` limit.
///
/// Examples of valid denominations: 1, 2, 5, 10, 20, 50, 100, 200, 500,
/// 1000, …, 5_000_000_000_000_000_000.
///
/// Higher denominations require exponentially more work to mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Denomination(u64);

/// JSON uses human-readable hex strings for compatibility with wallet
/// files and RPC responses. Postcard (binary protocol) uses raw u64
/// for minimal wire size and zero-alloc decoding.
impl Serialize for Denomination {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.0.to_be_bytes()))
        } else {
            serializer.serialize_u64(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Denomination {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            if bytes.len() != 8 {
                return Err(serde::de::Error::custom("denomination hex must be 8 bytes"));
            }
            let val = u64::from_be_bytes(bytes[..8].try_into().unwrap());
            Denomination::from_value(val).ok_or_else(|| {
                serde::de::Error::custom(format!("invalid denomination value: {val}"))
            })
        } else {
            let val = u64::deserialize(deserializer)?;
            Denomination::from_value(val).ok_or_else(|| {
                serde::de::Error::custom(format!("invalid denomination value: {val}"))
            })
        }
    }
}

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

/// Compute the canonical 1-2-5 output values for a Bitcoin burn amount.
///
/// This reuses the same optimal denomination breakdown already used by
/// native Vess aggregation so there is exactly one canonical bill split
/// policy in the protocol.
pub fn bitcoin_burn_output_values(total_sats: u64) -> Vec<u64> {
    mint::optimal_breakdown(total_sats)
        .into_iter()
        .map(Denomination::value)
        .collect()
}

/// Hash the canonical output bundle for a Bitcoin burn.
///
/// `outputs_hash = Blake3("vess-burn-outputs-v1" || value_0_le || value_1_le || ...)`
pub fn bitcoin_burn_outputs_hash(output_values: &[u64]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-burn-outputs-v1");
    for value in output_values {
        h.update(&value.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// Compute the 32-byte OP_RETURN commitment payload for a Bitcoin burn.
///
/// This commits to the first owner, the total burned sat amount, and the
/// exact canonical denomination bundle.
///
/// `payload = Blake3("vess-burn-bundle-v2" || first_owner_vk_hash || burn_amount_sats_le || outputs_hash)`
pub fn bitcoin_burn_payload_commitment(
    first_owner_vk_hash: &[u8; 32],
    burn_amount_sats: u64,
    output_values: &[u64],
) -> [u8; 32] {
    let outputs_hash = bitcoin_burn_outputs_hash(output_values);
    let mut h = blake3::Hasher::new();
    h.update(b"vess-burn-bundle-v2");
    h.update(first_owner_vk_hash);
    h.update(&burn_amount_sats.to_le_bytes());
    h.update(&outputs_hash);
    *h.finalize().as_bytes()
}

/// Derive the deterministic mint_id for a Bitcoin-burn bundle output.
///
/// `mint_id = Blake3("vess-bitcoin-burn-mint-id-v1" || txid || output_index_le)`
///
/// The Bitcoin txid anchors the shared burn event, while `output_index`
/// distinguishes sibling Vess bills derived from the same burn.
pub fn bitcoin_burn_mint_id(txid: &[u8; 32], output_index: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-bitcoin-burn-mint-id-v1");
    h.update(txid);
    h.update(&output_index.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Compute the genesis ownership chain tip.
///
/// `chain[0] = Blake3("vess-chain-v0" || mint_id || owner_vk_hash)`
///
/// This is the first link in the ownership hash chain, binding the
/// genesis miner's identity to the bill's permanent ID.
pub fn genesis_chain_tip_with_commitment(
    mint_id: &[u8; 32],
    owner_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-chain-v0");
    h.update(mint_id);
    h.update(owner_commitment);
    *h.finalize().as_bytes()
}

pub fn genesis_chain_tip(mint_id: &[u8; 32], owner_vk_hash: &[u8; 32]) -> [u8; 32] {
    genesis_chain_tip_with_commitment(mint_id, owner_vk_hash)
}

/// Advance the ownership chain by one transfer.
///
/// `chain[n] = Blake3(prev_chain_tip || new_owner_vk_hash || transfer_sig_hash)`
///
/// The `transfer_sig_hash` is `Blake3(transfer_signature)` — we hash the
/// large ML-DSA-65 signature (3293 bytes) down to 32 bytes before including
/// it in the chain. This keeps the chain tip derivation constant-size.
pub fn advance_chain_tip_with_hash(
    prev_chain_tip: &[u8; 32],
    new_owner_commitment: &[u8; 32],
    witness_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(prev_chain_tip);
    h.update(new_owner_commitment);
    h.update(witness_hash);
    *h.finalize().as_bytes()
}

pub fn advance_chain_tip(
    prev_chain_tip: &[u8; 32],
    new_owner_vk_hash: &[u8; 32],
    transfer_sig: &[u8],
) -> [u8; 32] {
    let sig_hash = blake3::hash(transfer_sig);
    advance_chain_tip_with_hash(prev_chain_tip, new_owner_vk_hash, sig_hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        bitcoin_burn_mint_id, bitcoin_burn_output_values, bitcoin_burn_outputs_hash,
        bitcoin_burn_payload_commitment,
    };

    #[test]
    fn bitcoin_burn_uses_canonical_breakdown() {
        assert_eq!(
            bitcoin_burn_output_values(52_550),
            vec![50_000, 2_000, 500, 50]
        );
        assert_eq!(bitcoin_burn_output_values(3), vec![2, 1]);
    }

    #[test]
    fn bitcoin_burn_output_mint_ids_are_indexed() {
        let txid = [0x42u8; 32];
        let first = bitcoin_burn_mint_id(&txid, 0);
        let second = bitcoin_burn_mint_id(&txid, 1);

        assert_ne!(first, second);
        assert_eq!(first, bitcoin_burn_mint_id(&txid, 0));
    }

    #[test]
    fn bitcoin_burn_mint_ids_are_txid_anchored() {
        let txid = [0x42u8; 32];
        let other_txid = [0x24u8; 32];

        assert_ne!(
            bitcoin_burn_mint_id(&txid, 0),
            bitcoin_burn_mint_id(&other_txid, 0)
        );
    }

    #[test]
    fn bitcoin_burn_payload_commits_to_owner_and_outputs() {
        let owner_hash = [0x11u8; 32];
        let burn_amount_sats = 52_550;
        let outputs = vec![50_000, 2_000, 500, 50];

        let payload = bitcoin_burn_payload_commitment(&owner_hash, burn_amount_sats, &outputs);
        let outputs_hash = bitcoin_burn_outputs_hash(&outputs);

        assert_eq!(payload.len(), 32);
        assert_ne!(payload, outputs_hash);
        assert_ne!(
            payload,
            bitcoin_burn_payload_commitment(&[0x22u8; 32], burn_amount_sats, &outputs)
        );
        assert_ne!(
            payload,
            bitcoin_burn_payload_commitment(&owner_hash, burn_amount_sats + 1, &outputs)
        );
        assert_ne!(
            payload,
            bitcoin_burn_payload_commitment(&owner_hash, burn_amount_sats, &[52_550])
        );
    }
}
