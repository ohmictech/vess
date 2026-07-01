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
pub mod mine;
pub mod proof;
pub mod reforge;
pub mod seal;
pub mod spend_auth;
pub mod vm;

use hex;
use serde::{Deserialize, Serialize};

/// The asset backing a Vess bill — locked at birth and never changed.
///
/// Bills of different assets cannot be combined directly.
/// The denomination value always represents the smallest unit of the asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Asset {
    /// VHALIX — raw mined commodity (Argon2id CPU burn).
    VHALIX,
    /// Vess — time-locked VHALIX, spendable currency.
    Vess,
    /// Vichor — fixed-supply (1B) network stock.
    Vichor,
}

impl Asset {
    pub fn name(&self) -> String {
        match self {
            Asset::VHALIX => "VHALIX".to_string(),
            Asset::Vess => "vess".to_string(),
            Asset::Vichor => "vichor".to_string(),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "VHALIX" | "VHALIX" | "VHALIX" => Some(Asset::VHALIX),
            "vess" | "VESS" | "Vess" => Some(Asset::Vess),
            "vichor" | "VICHOR" | "Vichor" => Some(Asset::Vichor),
            _ => None,
        }
    }
}

impl Serialize for Asset {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name())
    }
}

impl<'de> Deserialize<'de> for Asset {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Asset::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid asset: {s}")))
    }
}

impl std::fmt::Display for Asset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Asset::VHALIX => write!(f, "VHALIX"),
            Asset::Vess => write!(f, "VESS"),
            Asset::Vichor => write!(f, "VICHOR"),
        }
    }
}

impl Default for Asset {
    fn default() -> Self { Asset::VHALIX }
}

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
    /// remaining digit is 1, 2, or 5. Any denomination in the 1-2-5
    /// series is accepted — higher denominations require proportionally
    /// more work to mint, which is self-limiting.
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

    /// The largest valid 1-2-5 denomination ≤ `chain_length`.
    ///
    /// This is the core VHALIX minting rule: a hash chain of length N
    /// produces a bill denominated at the largest 1-2-5 value ≤ N.
    /// E.g. chain length 2295 → denomination 2000.
    /// The excess proofs are the security margin — they prove the
    /// miner didn't just barely squeak past the threshold.
    pub fn max_valid_denomination(chain_length: u64) -> u64 {
        let mut best: u64 = 1;
        let mut power: u64 = 1;
        loop {
            for &d in &[1u64, 2, 5] {
                match d.checked_mul(power) {
                    Some(val) if val <= chain_length => best = val,
                    _ => return best,
                }
            }
            match power.checked_mul(10) {
                Some(p) => power = p,
                None => return best,
            }
        }
    }

    /// Round a raw u64 amount to the nearest valid 1-2-5 denomination.
    /// Ties round up. Returns `D1` for 0.
    pub fn nearest(value: u64) -> Self {
        if value == 0 {
            return Self::D1;
        }
        // Find the power-of-10 magnitude.
        let mut power: u64 = 1;
        while power <= value / 10 {
            power *= 10;
        }
        // Candidates at this power level: 1×, 2×, 5× power
        let candidates = [1 * power, 2 * power, 5 * power, 10 * power];
        let mut best = candidates[0];
        let mut best_diff = u64::MAX;
        for &c in &candidates {
            if c == 0 { continue; }
            let diff = if c >= value { c - value } else { value - c };
            if diff < best_diff {
                best_diff = diff;
                best = c;
            }
        }
        Self(best)
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
    /// Origin asset: VHALIX, vess, or vichor.
    /// Bills of different assets cannot be combined.  Defaults to VHALIX.
    /// for backward compatibility with pre-multi-asset wallets.
    #[serde(default)]
    pub asset: Asset,
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

/// Bitcoin blocks per year (365.25 days × 144 blocks/day ≈ 52,560).
pub const BLOCKS_PER_YEAR: u64 = 52_560;

/// Minimum timelock duration in blocks (~0.1 years).
pub const MIN_LOCK_BLOCKS: u64 = 5_256;

/// Maximum timelock duration in blocks (~10 years).
pub const MAX_LOCK_BLOCKS: u64 = 525_600;

/// Compute the Vess amount from locked sats and lock duration in blocks.
///
/// ```text
/// vess = locked_sats × lock_blocks / BLOCKS_PER_YEAR
/// ```
///
/// # Examples
///
/// - 100 sats × 52,560 blocks / 52,560 = 100 Vess
/// - 100 sats × 525,600 blocks / 52,560 = 1,000 Vess
/// - 100 sats × 5,256 blocks / 52,560 = 10 Vess
pub fn compute_vess_amount(locked_sats: u64, lock_blocks: u64) -> u64 {
    (locked_sats as u128 * lock_blocks as u128 / BLOCKS_PER_YEAR as u128) as u64
}

/// Compute the canonical 1-2-5 output values for a bitcoin time-lock amount.
///
/// This reuses the same optimal denomination breakdown already used by
/// native Vess aggregation so there is exactly one canonical bill split
/// policy in the protocol.
pub fn bitcoin_timelock_output_values(vess_amount: u64) -> Vec<u64> {
    mint::optimal_breakdown(vess_amount)
        .into_iter()
        .map(Denomination::value)
        .collect()
}

/// Hash the canonical output bundle for a bitcoin time-lock.
///
/// `outputs_hash = Blake3("vess-timelock-outputs-v1" || value_0_le || value_1_le || ...)`
pub fn bitcoin_timelock_outputs_hash(output_values: &[u64]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-timelock-outputs-v1");
    for value in output_values {
        h.update(&value.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// Compute the commitment payload for a bitcoin time-lock transaction.
///
/// Commits to the first owner, locked amount, lock duration, canonical
/// denomination bundle, and optionally a Vichor burn proof.
///
/// `payload = Blake3("vess-timelock-bundle-v1" || owner_vk_hash || locked_sats_le || lock_blocks_le || outputs_hash || [vichor_burn_digest])`
pub fn bitcoin_timelock_payload_commitment(
    first_owner_vk_hash: &[u8; 32],
    locked_sats: u64,
    lock_blocks: u64,
    output_values: &[u64],
    vichor_burn_digest: Option<&[u8; 32]>,
) -> [u8; 32] {
    let outputs_hash = bitcoin_timelock_outputs_hash(output_values);
    let mut h = blake3::Hasher::new();
    h.update(b"vess-timelock-bundle-v2");
    h.update(first_owner_vk_hash);
    h.update(&locked_sats.to_le_bytes());
    h.update(&lock_blocks.to_le_bytes());
    h.update(&outputs_hash);
    if let Some(d) = vichor_burn_digest {
        h.update(d);
    } else {
        h.update(&[0u8; 32]); // zeroed slot = no Vichor burned
    }
    *h.finalize().as_bytes()
}

/// Compute the signing message for a Vichor burn proof.
///
/// `msg = Blake3("vess-vichor-burn-sig-v1" || mint_ids... || total_burned || mint_commitment)`
pub fn vichor_burn_signing_message(
    burned_mint_ids: &[[u8; 32]],
    total_burned: u64,
    mint_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-vichor-burn-sig-v1");
    for id in burned_mint_ids {
        h.update(id);
    }
    h.update(&total_burned.to_le_bytes());
    h.update(mint_commitment);
    *h.finalize().as_bytes()
}

/// Compute the digest of a Vichor burn proof for commitment binding.
///
/// `digest = Blake3("vess-vichor-burn-v1" || mint_ids... || total_burned || mint_commitment)`
pub fn vichor_burn_digest(
    burned_mint_ids: &[[u8; 32]],
    total_burned: u64,
    mint_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-vichor-burn-v1");
    for id in burned_mint_ids {
        h.update(id);
    }
    h.update(&total_burned.to_le_bytes());
    h.update(mint_commitment);
    *h.finalize().as_bytes()
}

/// Derive the deterministic mint_id for a standard bitcoin time-lock bill.
///
/// `mint_id = Blake3("vess-timelock-mint-id-v1" || txid || output_index_le)`
///
/// Every Vess bill traces to a Bitcoin transaction. The txid anchors the
/// time-lock event and `output_index` distinguishes sibling bills from the
/// same lock.
pub fn bitcoin_timelock_mint_id(txid: &[u8; 32], output_index: u32) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-timelock-mint-id-v1");
    h.update(txid);
    h.update(&output_index.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Derive the deterministic mint_id for a century lock faucet bill.
///
/// `mint_id = Blake3("vess-century-mint-id-v1" || txid || output_index_le || block_hash)`
///
/// Derive the mint_id for a VHALIX bill from a miner's node ID and bill nonce.
///
/// `mint_id = Blake3("vess-VHALIX-mint-v1" || miner_node_id || bill_nonce_be)`
pub fn VHALIX_mint_id(miner_node_id: &[u8; 32], bill_nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-VHALIX-mint-v1");
    h.update(miner_node_id);
    h.update(&bill_nonce.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Derive the mint_id for a century-lock Vess bill from a lock_id and tick.
pub fn century_lock_mint_id(lock_id: &[u8; 32], tick: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-century-mint-id-v2");
    h.update(lock_id);
    h.update(&tick.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Compute the per-tick Vess amount for a century lock.
///
/// `per_tick = ceil(total_locked / TICKS_PER_YEAR)`
pub fn century_lock_per_tick_vess(total_locked: u64) -> u64 {
    const TICKS_PER_YEAR: u64 = 365 * 24 * 60 * 60 / 6;
    ((total_locked as u128 + TICKS_PER_YEAR as u128 - 1) / TICKS_PER_YEAR as u128) as u64
}

/// Compute the Vess amount from locked VHALIX and lock duration.
///
/// `vess = locked_VHALIX × lock_years` (1:1 per year, free for 1 year)
/// Extended locks (1.1–10 years) require vichor burn.
pub fn compute_vess_from_lock(locked_VHALIX: u64, lock_years_tenths: u64) -> u64 {
    // 1 year = 10 tenths.  Free tier: ≤10 tenths gives 1×.
    // Extended: proportional to years.
    let years = lock_years_tenths as f64 / 10.0;
    (locked_VHALIX as f64 * years) as u64
}

// ── Vichor genesis ──────────────────────────────────────────────────

/// Total Vichor supply — matches `vess_protocol::VICHOR_TOTAL_SUPPLY`.
pub const VICHOR_TOTAL_SUPPLY: u64 = 1_000_000_000;

/// Compute the signing message for a Vichor genesis proof.
///
/// `msg = Blake3("vess-vichor-genesis-v1" || nonce || total_supply || owner_vk_hash)`
pub fn vichor_genesis_signing_message(
    nonce: &[u8; 32],
    total_supply: u64,
    owner_vk_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-vichor-genesis-v1");
    h.update(nonce);
    h.update(&total_supply.to_le_bytes());
    h.update(owner_vk_hash);
    *h.finalize().as_bytes()
}

/// Derive the mint_id for the single Vichor genesis bill.
///
/// `mint_id = Blake3("vess-vichor-mint-id-v1" || nonce)`
pub fn vichor_genesis_mint_id(nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-vichor-mint-id-v1");
    h.update(nonce);
    *h.finalize().as_bytes()
}

/// How many Vichor are required to time-lock for a given duration.
///
/// Years must be in 0.1 increments (1.0, 1.1, 1.2, …, 10.0).
/// 10 Vichor per full year, 1 per 0.1 decimal step.
///
/// ```text
/// vichor = max(0, (years - 1.0) × 10)
/// ```
///
/// Free tier: ≤1.0 year costs 0 Vichor.
///
/// Formula: V(y) = (y − 1)² × 10  (quadratic, 0.1yr increments)
///
/// # Examples
///
/// - 0.5 years → 0 Vichor (free)
/// - 1.0 year  → 0 Vichor (free)
/// - 1.1 years → 1 Vichor
/// - 1.5 years → 2 Vichor
/// - 2.0 years → 10 Vichor
/// - 5.0 years → 160 Vichor
/// - 10.0 years → 810 Vichor
///
/// The quadratic curve makes long locks increasingly expensive —
/// marginal cost grows linearly with duration. This creates natural
/// market tiers where speculators must buy Vichor from the market,
/// funding protocol development.
pub fn vichor_required_for_years(locked_sats: u64, years: f64) -> u64 {
    // 1 Vichor per 100,000 sat-years (linear in both amount and time).
    (locked_sats as f64 * years / 100_000.0).ceil() as u64
}

/// Provably unspendable verification key hash. Any Vichor bill transferred
/// to this owner is permanently burned. Matches `vess_protocol::VICHOR_BURN_VK_HASH`.
pub const VICHOR_BURN_VK_HASH: [u8; 32] = [0u8; 32];

/// Verify that a Vichor bill has been burned — its current owner is
/// the canonical burn address.
pub fn is_vichor_burned(owner_vk_hash: &[u8; 32]) -> bool {
    owner_vk_hash == &VICHOR_BURN_VK_HASH
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
        bitcoin_timelock_mint_id, bitcoin_timelock_output_values,
        bitcoin_timelock_outputs_hash, bitcoin_timelock_payload_commitment,
        compute_vess_amount, BLOCKS_PER_YEAR, MIN_LOCK_BLOCKS, MAX_LOCK_BLOCKS,
    };

    #[test]
    fn compute_vess_amount_sat_blocks() {
        // 100 sats × 52,560 blocks = 100 Vess
        assert_eq!(compute_vess_amount(100, BLOCKS_PER_YEAR), 100);
        // 100 sats × 525,600 blocks = 1,000 Vess (10×)
        assert_eq!(compute_vess_amount(100, MAX_LOCK_BLOCKS), 1_000);
        // 100 sats × 5,256 blocks = 10 Vess (0.1×)
        assert_eq!(compute_vess_amount(100, MIN_LOCK_BLOCKS), 10);
        // 1 VHALIX × 52,560 ticks = 100,000,000 Vess
        assert_eq!(compute_vess_amount(100_000_000, BLOCKS_PER_YEAR), 100_000_000);
        // 1 sat × 1 block = 0 Vess (rounds down, need at least 526 blocks for 1 Vess per 100 sats)
        assert_eq!(compute_vess_amount(1, 1), 0);
        // 100 sats × 526 blocks = 1 Vess (minimum precision)
        assert_eq!(compute_vess_amount(100, 526), 1);
        // Min lock: 100 sats × 5,256 blocks / 52,560 = 10 Vess
        assert_eq!(compute_vess_amount(100, MIN_LOCK_BLOCKS), 10);
        // Max lock: 100 sats × 525,600 blocks / 52,560 = 1,000 Vess
        assert_eq!(compute_vess_amount(100, MAX_LOCK_BLOCKS), 1_000);
    }

    #[test]
    fn bitcoin_timelock_uses_canonical_breakdown() {
        assert_eq!(
            bitcoin_timelock_output_values(52_550),
            vec![50_000, 2_000, 500, 50]
        );
        assert_eq!(bitcoin_timelock_output_values(3), vec![2, 1]);
    }

    #[test]
    fn bitcoin_timelock_output_mint_ids_are_indexed() {
        let txid = [0x42u8; 32];
        let first = bitcoin_timelock_mint_id(&txid, 0);
        let second = bitcoin_timelock_mint_id(&txid, 1);

        assert_ne!(first, second);
        assert_eq!(first, bitcoin_timelock_mint_id(&txid, 0));
    }

    #[test]
    fn bitcoin_timelock_mint_ids_are_txid_anchored() {
        let txid = [0x42u8; 32];
        let other_txid = [0x24u8; 32];

        assert_ne!(
            bitcoin_timelock_mint_id(&txid, 0),
            bitcoin_timelock_mint_id(&other_txid, 0)
        );
    }

    #[test]
    fn bitcoin_timelock_payload_commits_to_owner_and_outputs() {
        let owner_hash = [0x11u8; 32];
        let locked_sats = 52_550;
        let outputs = vec![50_000, 2_000, 500, 50];

        let payload = bitcoin_timelock_payload_commitment(
            &owner_hash, locked_sats, BLOCKS_PER_YEAR, &outputs, None,
        );
        let outputs_hash = bitcoin_timelock_outputs_hash(&outputs);

        assert_eq!(payload.len(), 32);
        assert_ne!(payload, outputs_hash);
        assert_ne!(
            payload,
            bitcoin_timelock_payload_commitment(
                &[0x22u8; 32], locked_sats, BLOCKS_PER_YEAR, &outputs, None,
            )
        );
        assert_ne!(
            payload,
            bitcoin_timelock_payload_commitment(
                &owner_hash, locked_sats + 1, BLOCKS_PER_YEAR, &outputs, None,
            )
        );
        assert_ne!(
            payload,
            bitcoin_timelock_payload_commitment(
                &owner_hash, locked_sats, MIN_LOCK_BLOCKS, &outputs, None,
            )
        );
        assert_ne!(
            payload,
            bitcoin_timelock_payload_commitment(
                &owner_hash, locked_sats, BLOCKS_PER_YEAR, &[52_550], None,
            )
        );
    }
}
