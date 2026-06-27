//! **vess-protocol** — Wire-level message types for the Vess vascular network.
//!
//! All messages exchanged between nodes are variants of [`PulseMessage`].
//! Each message is serialized with `postcard` (compact, no-std friendly)
//! and wrapped in the vascular framing layer.
//!
//! # Message Categories
//!
//! - [`Payment`] / [`DirectPayment`] — Stealth-encrypted bill transfers.
//! - [`TagRegister`] — PoW-backed VessTag registration.
//! - [`TagLookup`] / [`TagLookupResponse`] — Tag → stealth address resolution.
//! - [`OwnershipGenesis`] / [`OwnershipClaim`] — Ownership registry operations.
//! - [`MailboxCollect`] / [`MailboxSweep`] — Offline payment delivery.
//! - [`RegistryQuery`] / [`RegistryQueryResponse`] — Ownership status lookup.
//! - [`ManifestStore`] / [`ManifestRecover`] — Wallet recovery manifests.
//! - Compute program / receipt records — programmable DHT-published compute.

use serde::{Deserialize, Serialize};
use blake3;

/// Bitcoin network identifier used by time-lock-backed bill genesis proofs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

/// Proof that a Bitcoin transaction is time-locked via OP_CHECKLOCKTIMEVERIFY.
///
/// Instead of burning BTC with OP_RETURN, the owner locks BTC to their own
/// address for a future block height. This creates **sat-block time credits**:
///
/// ```text
/// vess = locked_sats × lock_blocks / BLOCKS_PER_YEAR
/// ```
///
/// Lock 100 sats for 52,560 blocks (≈1 year) → 100 Vess.
/// Lock 100 sats for 525,600 blocks (≈10 years) → 1,000 Vess.
/// Lock 100 sats for 5,256 blocks (≈0.1 years) → 10 Vess.
///
/// The BTC is not destroyed — it returns to the owner after the CLTV
/// block height expires. The time-lock proof is verified via SPV.
///
/// # Limits
///
/// - Minimum lock: 5,256 blocks (≈0.1 years)
/// - Maximum lock: 525,600 blocks (≈10 years)
///
/// This proof is the trust anchor for Vess bill genesis. Every node MUST
/// verify it before accepting the associated bills into the DHT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTimeLockProof {
    /// Bitcoin network the lock was observed on.
    pub network: BitcoinNetwork,
    /// Transaction ID of the time-lock transaction.
    pub txid: [u8; 32],
    /// Block hash containing the time-lock transaction.
    pub block_hash: [u8; 32],
    /// Height of the containing block in the validated header chain.
    #[serde(default)]
    pub block_height: u64,
    /// Confirmations observed by the validating Bitcoin light client.
    #[serde(default)]
    pub confirmations: u32,
    /// Minimum confirmations required by the validating Bitcoin light client.
    #[serde(default)]
    pub required_confirmations: u32,
    /// Number of distinct Bitcoin peers that corroborated the tx/block data.
    #[serde(default)]
    pub corroborating_peer_count: u32,
    /// Cumulative validated chainwork at the containing block, big-endian.
    #[serde(default)]
    pub chain_work: [u8; 32],
    /// Merkle root committed by the containing block header.
    pub merkle_root: [u8; 32],
    /// Merkle branch proving `txid` inclusion in the block.
    pub merkle_proof: Vec<[u8; 32]>,
    /// Leaf index of `txid` in the block's merkle tree.
    pub merkle_index: u32,
    /// Amount of satoshis locked (not burned — returned after timelock).
    pub locked_sats: u64,
    /// Duration of the timelock in Bitcoin blocks.
    /// `lock_blocks = cltv_block_height − confirmation_block_height`
    pub lock_blocks: u64,
    /// The CLTV block height encoded in the transaction output.
    pub cltv_block_height: u64,
    /// The Vess amount this lock produces.
    /// `vess = locked_sats × lock_blocks / BLOCKS_PER_YEAR`
    pub vess_amount: u64,
    /// Full ML-DSA-65 verification key of the first Vess owner (the locker).
    pub first_owner_vk: Vec<u8>,
    /// Blake3 hash of the first owner's ML-DSA-65 verification key.
    pub first_owner_vk_hash: [u8; 32],
    /// Canonical 1-2-5 bill values for this Vess amount.
    pub output_values: Vec<u64>,
    /// Commitment payload in the CLTV output (e.g. OP_RETURN or
    /// the output script itself, committing to the owner and terms).
    pub commitment_payload: Vec<u8>,
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

/// Development-only proof for local faucet bills.
///
/// Nodes only accept this proof when local test faucet mode is explicitly
/// enabled. It is meant for same-machine/LAN development and must never be
/// treated as production monetary backing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalTestFaucetProof {
    /// Random nonce used to derive the faucet bill identity.
    pub nonce: [u8; 32],
}

/// One-time genesis proof for the Vichor supply.
///
/// Vichor is a fixed-supply (1,000,000,000) network stock token. The entire
/// supply is created in a single genesis event and held by the dev address.
/// The dev sells Vichor on the swap DHT at market rates.
///
/// # Uniqueness
///
/// Only **one** `VichorGenesis` is ever valid. Uniqueness is enforced by:
///
/// 1. **Canonical nonce** — `VICHOR_GENESIS_NONCE` is baked into the protocol.
///    Any proof with a different nonce is rejected. There is exactly one
///    valid proof, ever.
/// 2. **Dev key** — the `owner_vk` must match `VICHOR_GENESIS_VK`. Only the
///    canonical dev key can sign the genesis.
/// 3. **Total supply** — must equal `VICHOR_TOTAL_SUPPLY` (1,000,000,000).
///
/// Even the dev cannot print more Vichor — the nonce and supply are fixed
/// at the protocol level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VichorGenesisProof {
    /// Must equal [`VICHOR_GENESIS_NONCE`]. Any other value is invalid.
    pub nonce: [u8; 32],
    /// Total supply: must equal [`VICHOR_TOTAL_SUPPLY`].
    pub total_supply: u64,
    /// Must match the canonical dev key.
    pub owner_vk: Vec<u8>,
    /// Blake3 hash of owner_vk.
    pub owner_vk_hash: [u8; 32],
    /// ML-DSA-65 signature by owner_vk over the genesis message.
    pub owner_sig: Vec<u8>,
}

/// Total Vichor supply — fixed at genesis, never increases.
pub const VICHOR_TOTAL_SUPPLY: u64 = 1_000_000_000;

/// Canonical nonce for the Vichor genesis proof. Only proofs with this
/// exact nonce are valid. Changing this would create a different genesis,
/// which the network will reject.
pub const VICHOR_GENESIS_NONCE: [u8; 32] = *b"vess-vichor-genesis-v1----------";

/// Provably unspendable verification key. Any Vichor bill transferred to
/// this owner is permanently burned — no one can sign a subsequent claim.
/// `Blake3("vess-vichor-burn-v1")` → 32 bytes of nothingness.
pub const VICHOR_BURN_VK_HASH: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Proof that Vichor bills have been permanently burned.
///
/// Used to unlock time-lock durations beyond 1 year. The burn proof
/// references one or more Vichor bills in the ownership registry and
/// proves the owner authorizes their destruction. Once burned, the
/// Proof that Vichor has been burned to unlock a time-lock duration.
///
/// The burn happens **before** the BTC time-lock: Vichor bills are transferred
/// to `VICHOR_BURN_VK_HASH` via an OwnershipClaim, the DHT marks them consumed,
/// and this proof is produced. The `mint_timelock` function then references
/// this proof — it checks that `total_burned >= vichor_required(duration)`.
///
/// # Replay protection
///
/// `mint_commitment` is a random nonce generated before either the burn
/// or the time-lock exists. It links the burn proof to a specific mint
/// without requiring the txid upfront. The digest is embedded in the
/// Bitcoin OP_RETURN — reusing the same burn for a different mint would
/// require forging the commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VichorBurnProof {
    /// Mint IDs of the Vichor bills being burned. Must be active in the
    /// ownership registry and owned by `owner_vk`.
    pub burned_mint_ids: Vec<[u8; 32]>,
    /// Total Vichor amount burned (sum of burned bill denominations).
    /// The minting node checks: `total_burned >= vichor_required(duration_years)`.
    pub total_burned: u64,
    /// ML-DSA-65 verification key of the burner.
    pub owner_vk: Vec<u8>,
    /// Blake3 hash of owner_vk.
    pub owner_vk_hash: [u8; 32],
    /// ML-DSA-65 signature over the burn message.
    pub owner_sig: Vec<u8>,
    /// Random nonce linking this burn to a specific time-lock mint.
    /// Generated before either step — used in the burn proof digest and
    /// the Bitcoin OP_RETURN commitment.
    pub mint_commitment: [u8; 32],
}

/// Proof object used to justify genesis registration of a bill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenesisProof {
    /// Existing Vess-native genesis proof bytes.
    ///
    /// These bytes are further parsed by validators as one of:
    /// - single STARK proof
    /// - aggregate proof
    /// - sampled aggregate proof
    /// - reforge proof
    Vess(Vec<u8>),

    /// Bitcoin time-lock proof: CLTV-locked BTC creates sat-block Vess credits.
    BitcoinTimeLock(BitcoinTimeLockProof),

    /// Century lock: BTC burned for 100 years creates a perpetual Vess faucet.
    /// One Vess bill per Bitcoin block, amount = total_sats / 52_560 (rounded).
    CenturyLock(BitcoinTimeLockProof),

    /// One-time Vichor genesis: 1B supply held by dev, sold on swap DHT.
    VichorGenesis(VichorGenesisProof),

    /// Local testing faucet proof. Accepted only when explicitly enabled by
    /// the node operator.
    LocalTestFaucet(LocalTestFaucetProof),
}

/// Top-level pulse message envelope.
///
/// Every vascular pulse carries exactly one of these variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PulseMessage {
    /// A payment: stealth-encrypted bill(s) sent to a recipient.
    Payment(Payment),

    /// Register a VessTag by burning bills.
    TagRegister(TagRegister),

    /// Look up a VessTag's master stealth address.
    TagLookup(TagLookup),

    /// Response to a tag lookup.
    TagLookupResponse(TagLookupResponse),

    /// Collect buffered pulses from an artery mailbox.
    MailboxCollect(MailboxCollect),

    /// Response to a mailbox collect request.
    MailboxCollectResponse(MailboxCollectResponse),

    /// Exchange peer lists for discovery.
    PeerExchange(PeerExchange),

    /// Response to a peer exchange request.
    PeerExchangeResponse(PeerExchangeResponse),

    /// Ask a bootstrap/seed peer for DHT records this node should now shard.
    DhtSeedRequest(DhtSeedRequest),

    /// Response containing initial DHT shard data for a joining node.
    DhtSeedResponse(DhtSeedResponse),

    /// Handshake challenge: prove you are running an authorised protocol version.
    HandshakeChallenge(HandshakeChallenge),

    /// Handshake response: HMAC proof of the protocol version hash.
    HandshakeResponse(HandshakeResponse),

    /// Query whether specific mint_ids are active in the ownership registry.
    RegistryQuery(RegistryQuery),

    /// Response to a registry query.
    RegistryQueryResponse(RegistryQueryResponse),

    /// Announce that bill_ids have entered limbo (delivery in progress, recipient offline).
    LimboHold(LimboHold),

    /// Notify the network that limbo payments are waiting for a stealth_id.
    LimboNotify(LimboNotify),

    /// Deliver a limbo-held payment to the recipient who just came online.
    LimboDeliver(LimboDeliver),

    /// Replicate a tag record to DHT peers for redundancy.
    TagStore(TagStore),

    /// Confirm (harden) a VessTag with proof of payment.
    TagConfirm(TagConfirm),

    /// Sweep all limbo payloads from a node (wallet connects after being offline).
    MailboxSweep(MailboxSweep),

    /// Response to a mailbox sweep.
    MailboxSweepResponse(MailboxSweepResponse),

    /// Ask a shard custodian to push incoming payments to this node.
    MailboxForwardRegister(MailboxForwardRegister),

    /// Acknowledgement to a [`MailboxForwardRegister`] request.
    MailboxForwardAck(MailboxForwardAck),

    /// Claim ownership of a bill after receiving a transfer.
    OwnershipClaim(OwnershipClaim),

    /// Register a freshly minted bill in the ownership registry.
    OwnershipGenesis(OwnershipGenesis),

    /// Store an encrypted wallet manifest in the DHT for recovery.
    ManifestStore(ManifestStore),

    /// Recover an encrypted wallet manifest from the DHT.
    ManifestRecover(ManifestRecover),

    /// Response to a ManifestRecover request.
    ManifestRecoverResponse(ManifestRecoverResponse),

    /// Fetch full ownership records (including sealed payloads) by mint_id.
    OwnershipFetch(OwnershipFetch),

    /// Response to an OwnershipFetch request.
    OwnershipFetchResponse(OwnershipFetchResponse),

    /// Direct peer-to-peer payment (bypasses artery relay).
    DirectPayment(DirectPayment),

    /// Response to a direct peer-to-peer payment.
    DirectPaymentResponse(DirectPaymentResponse),

    /// Cryptographic receipt proving the recipient decrypted and claimed
    /// a payment.  Signed with the recipient's spend_sk so the sender can
    /// verify locally without waiting for DHT gossip.
    PaymentReceipt(PaymentReceipt),

    /// Privacy-preserving acknowledgment that a payment has been stored
    /// in a limbo buffer on a peer in the recipient's K-nearest DHT shard.
    /// Encrypted with Blake3(payment_id || stealth_id) so only the sender
    /// and gossip-path peers can decrypt it.
    LimboAck(LimboAck),

    /// Kademlia FIND_NODE: ask a peer for the K closest nodes to a target.
    /// Used for iterative routing table population — never for locating
    /// wallet users or payment recipients.
    FindNode(FindNode),

    /// Response to a FindNode request: the K closest peers known.
    FindNodeResponse(FindNodeResponse),

    /// Attest that input bills have been consumed in a split/combine reforge.
    /// Artery nodes verify the owner's signature over each consumed mint_id
    /// and delete them from the registry, preventing double-spend of inputs.
    ReforgeAttestation(ReforgeAttestation),

    /// Request network-level statistics (peer count, latency metrics).
    NetworkStats(NetworkStats),

    /// Response to a [`NetworkStats`] request.
    NetworkStatsResponse(NetworkStatsResponse),

    /// Network-wide banishment proof: evidence that a peer misbehaved.
    /// Carries cryptographic proof (not just accusation). Every node
    /// verifies independently and banishes if valid.
    BanishmentProof(BanishmentProof),

    /// Two-hop relay payment: sender → intermediate node → DHT shard.
    /// The intermediate node unwraps and forwards the inner [`Payment`]
    /// to the K-nearest peers of `target_shard_key`, breaking the direct
    /// sender-recipient link at the network layer.
    RelayPayment(RelayPayment),

    /// Atomic swap offer for trustless cross-asset exchange.
    /// Stored in the DHT keyed by Blake3("vess-swap-v0" || asset_a || asset_b).
    SwapOffer(SwapOffer),

    /// Response to a swap offer query.
    SwapOfferResponse(SwapOfferResponse),
}

// ── Payment ──────────────────────────────────────────────────────────

/// Two-hop payment relay wrapper.
///
/// The sender encrypts a regular [`Payment`] and picks a random verified
/// peer to act as intermediary. The intermediary unwraps and forwards the
/// inner payment to the DHT shard keyed by `target_shard_key`, making it
/// impossible for any single hop to correlate sender with recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPayment {
    /// The inner payment (opaque to the relay node).
    pub payment: Payment,
    /// DHT routing key for the destination shard (typically `mailbox_key`).
    pub target_shard_key: [u8; 32],
    /// Remaining relay hops before the payment reaches the destination shard.
    /// Each relay decrements; when 0 the payment is forwarded to the shard.
    #[serde(default)]
    pub ttl: u8,
}

/// A stealth-encrypted payment from sender to recipient.
///
/// The stealth payload carries all bill data encrypted to the recipient.
/// Relay metadata is intentionally minimal to prevent passive traffic
/// analysis. Use `bill_count` for relay-side accounting without revealing
/// bill identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    /// Unique payment ID for tracking in-flight state.
    pub payment_id: [u8; 32],
    /// The stealth payload (KEM ciphertexts + AEAD-encrypted bills).
    /// Opaque to intermediary nodes.
    pub stealth_payload: Vec<u8>,
    /// View tag for efficient recipient scanning (1 byte).
    pub view_tag: u8,
    /// Stealth ID the payment is addressed to.
    pub stealth_id: [u8; 32],
    /// Unix timestamp when payment was created.
    pub created_at: u64,
    /// Number of bills in this payment (relay-safe metadata).
    ///
    /// Relays use this for lightweight accounting and rate limiting
    /// without learning which specific bills are being transferred.
    #[serde(default)]
    pub bill_count: u8,

    /// Optional DHT routing key for mailbox sharding.
    ///
    /// Derived by the sender as `BLAKE3("vess-mailbox-v1" || spend_ek_bytes)`
    /// from the recipient's public spend encapsulation key.  When present,
    /// relay nodes store this payment in limbo tagged with this key, and
    /// the recipient issues a targeted [`MailboxSweep`] with the matching
    /// key to retrieve only their own payments — no trial-decryption of
    /// unrelated payloads.
    ///
    /// Both sender and recipient derive the same key from the same public
    /// spend_ek, so no additional out-of-band communication is needed.
    #[serde(default)]
    pub mailbox_key: Option<[u8; 32]>,

    /// Optional tag hash requiring a signed direct-payment receipt.
    ///
    /// Direct senders set this to bind the recipient's acknowledgement to the
    /// resolved VessTag and this payment's `stealth_id`. Relay paths leave it
    /// empty because fire-and-forget relays do not consume responses.
    #[serde(default)]
    pub direct_receipt_tag_hash: Option<[u8; 32]>,

    /// Optional program receipt authorizing the recipient to attempt a
    /// Optional hash lock for atomic swaps. When set, the recipient must
    /// include the Blake3 preimage in their OwnershipClaim to unlock.
    #[serde(default)]
    pub hash_lock: Option<[u8; 32]>,
}

impl Default for Payment {
    fn default() -> Self {
        Self {
            payment_id: [0u8; 32],
            stealth_payload: Vec::new(),
            view_tag: 0,
            stealth_id: [0u8; 32],
            created_at: 0,
            bill_count: 0,
            mailbox_key: None,
            direct_receipt_tag_hash: None,
            hash_lock: None,
        }
    }
}

// ── Tag Operations ───────────────────────────────────────────────────

/// Register a VessTag by computing an Argon2id proof-of-work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRegister {
    /// Blake3 hash of the tag string (plaintext never leaves the client).
    pub tag_hash: [u8; 32],
    /// Scan encapsulation key (public).
    pub scan_ek: Vec<u8>,
    /// Spend encapsulation key (public).
    pub spend_ek: Vec<u8>,
    /// Random 32-byte nonce (salt) for the Argon2id PoW.
    pub pow_nonce: [u8; 32],
    /// 32-byte Argon2id output hash (proof-of-work).
    pub pow_hash: Vec<u8>,
    /// Unix timestamp.
    pub timestamp: u64,
    /// ML-DSA-65 verification key of the registrant.
    #[serde(default)]
    pub registrant_vk: Vec<u8>,
    /// ML-DSA-65 signature over the tag record digest.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Query a VessTag's associated stealth address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagLookup {
    /// Blake3 hash of the tag to look up (plaintext never sent over wire).
    pub tag_hash: [u8; 32],
    /// Nonce for request deduplication.
    pub nonce: [u8; 16],
    /// Optional proof that the requester owns a Vess bill (from burn or
    /// transfer). Nodes require this to prevent Sybil-based tag enumeration.
    /// Absent in testnet mode.
    #[serde(default)]
    pub burn_proof: Option<ProofOfVessOwnership>,
}

/// Cryptographic proof that a tag lookup requester is a real Vess user
/// who owns at least one bill (from a Bitcoin burn or a prior transfer).
/// Nodes verify this before serving a [`TagLookup`], making mass
/// enumeration economically infeasible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfVessOwnership {
    /// Bitcoin time-lock proof (if this bill came from a time-lock).
    /// At least one of `timelock` or `mint_id` must be present.
    #[serde(default)]
    pub timelock: Option<BitcoinTimeLockProof>,
    /// Mint ID of a Vess bill the requester owns (for non-burn bills).
    #[serde(default)]
    pub mint_id: Option<[u8; 32]>,
    /// ML-DSA-65 public key of the bill owner.
    pub owner_vk: Vec<u8>,
    /// ML-DSA-65 signature over
    /// `Blake3("vess-tag-lookup-proof-v0" || tag_hash || nonce)`
    /// proving the requester owns the bill and authorizes this lookup.
    pub owner_sig: Vec<u8>,
}

/// Response to a tag lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagLookupResponse {
    /// Blake3 hash of the tag that was queried.
    pub tag_hash: [u8; 32],
    /// The lookup nonce (echoed).
    pub nonce: [u8; 16],
    /// The result — None if tag not found or proof is required.
    pub result: Option<TagLookupResult>,
    /// True when the tag exists but the requester needs a valid
    /// [`ProofOfVessOwnership`] to receive the full result.
    /// Allows existence checks without bill ownership.
    #[serde(default)]
    pub requires_proof: bool,
}

/// A successful tag lookup result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagLookupResult {
    pub scan_ek: Vec<u8>,
    pub spend_ek: Vec<u8>,
    pub registered_at: u64,
    /// Random 32-byte nonce used as salt for the Argon2id PoW.
    #[serde(default)]
    pub pow_nonce: [u8; 32],
    /// 32-byte Argon2id output hash (proof-of-work).
    #[serde(default)]
    pub pow_hash: Vec<u8>,
    /// ML-DSA-65 verification key of the registrant.
    #[serde(default)]
    pub registrant_vk: Vec<u8>,
    /// ML-DSA-65 signature over the tag record digest.
    #[serde(default)]
    pub signature: Vec<u8>,
}

// ── Mailbox Operations ───────────────────────────────────────────────

/// Request to collect buffered pulses from an artery mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxCollect {
    /// The stealth ID to collect for.
    pub stealth_id: [u8; 32],
}

/// Response containing buffered pulses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxCollectResponse {
    /// The stealth ID this response is for.
    pub stealth_id: [u8; 32],
    /// Buffered encrypted payloads.
    pub payloads: Vec<Vec<u8>>,
}

/// Request all limbo stealth_payloads from a node.
///
/// Used by wallets reconnecting after being offline. The wallet will
/// attempt to decrypt each returned payload locally — only those
/// encrypted to this wallet's keys will succeed.
///
/// Rate-limited per peer on the artery side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxSweep {
    /// Random nonce to prevent response replay.
    pub nonce: [u8; 16],

    /// Optional mailbox key filter (see [`Payment::mailbox_key`]).
    ///
    /// When present the relay returns only limbo payloads whose
    /// stored `mailbox_key` matches.  When absent the relay returns
    /// ALL payloads (legacy behaviour, backwards compatible).
    #[serde(default)]
    pub mailbox_key: Option<[u8; 32]>,
}

/// Response to a [`MailboxSweep`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxSweepResponse {
    /// Echoed nonce from the request.
    pub nonce: [u8; 16],
    /// All stealth_payloads currently in limbo (opaque AEAD blobs).
    pub payloads: Vec<Vec<u8>>,
}

// ── Mailbox Forward Subscription ─────────────────────────────────────

/// Ask a shard custodian to push any incoming payments matching
/// `mailbox_key` to this node via [`LimboDeliver`].
///
/// The subscribing peer is identified by its transport-layer mesh contact
/// (i.e. whoever sent this message). A new registration for the same
/// key replaces any prior subscription (last-writer wins).
///
/// Subscriptions expire after `ttl_secs` seconds (capped server-side at
/// 3 600 s / 1 h).  Nodes should re-register before expiry.
///
/// On acceptance the custodian immediately forwards any already-waiting
/// payments for the key, so the subscriber does not need a separate sweep.
///
/// **Privacy:** the custodian learns which node subscribes to this hash,
/// but payment content remains end-to-end encrypted regardless.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxForwardRegister {
    /// Mailbox shard key to subscribe to
    /// (`BLAKE3("vess-mailbox-v1" || spend_ek)`).
    pub mailbox_key: [u8; 32],
    /// Unix timestamp at creation time (stale requests are rejected).
    pub timestamp: u64,
    /// Requested subscription lifetime in seconds.
    /// Capped server-side at 3 600 s.
    pub ttl_secs: u32,
    /// Anti-replay nonce, echoed in the acknowledgement.
    pub nonce: [u8; 16],
}

/// Acknowledgement from a custodian that processed a
/// [`MailboxForwardRegister`] request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxForwardAck {
    /// Echoed nonce from the corresponding [`MailboxForwardRegister`].
    pub nonce: [u8; 16],
    /// `true` when the subscription was stored; `false` when rejected
    /// (rate-limited, stale timestamp, etc.).
    pub accepted: bool,
    /// Number of already-waiting payments forwarded immediately on
    /// registration via [`LimboDeliver`].
    pub queued_forwarded: u32,
}

// ── Registry Query ───────────────────────────────────────────────────

/// Query whether specific mint_ids are active in the ownership registry.
///
/// Relay nodes send this to their neighbors to check bill ownership
/// status before forwarding a payment. Each entry is a mint_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryQuery {
    /// Mint IDs to check.
    pub mint_ids: Vec<[u8; 32]>,
}

/// Response to a [`RegistryQuery`].
///
/// Each boolean in `active` corresponds positionally to the queried
/// `mint_ids` — `true` means the mint_id has an active ownership record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryQueryResponse {
    /// Parallel to the request's `mint_ids`.
    pub active: Vec<bool>,
}

// ── Peer Exchange ────────────────────────────────────────────────────

/// Request a peer's known peer list for discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchange {
    /// The sender's mesh node ID bytes (32 bytes).
    pub sender_id: Vec<u8>,
}

/// Response with known peers' serialized mesh contact bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchangeResponse {
    /// Serialized mesh contacts of known peers (up to 10).
    pub peers: Vec<Vec<u8>>,
}

// ── DHT Seed Sync ───────────────────────────────────────────────────

/// Request initial DHT shard data from a seed/bootstrap peer.
///
/// A joining node sends this after the mesh handshake. The responder returns
/// records whose DHT keys fall into the requester's shard area according to
/// the responder's current routing-table view. This gives the first few test
/// nodes DHT continuity before normal gossip has enough peers to converge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedRequest {
    /// Requester's mesh node ID. Responders reject requests where this does not
    /// match the authenticated transport peer.
    pub requester_node_id: [u8; 32],
    /// Exclusive cursor for paginating tag records by tag hash.
    #[serde(default)]
    pub after_tag_hash: Option<[u8; 32]>,
    /// Exclusive cursor for paginating manifest records by DHT key.
    #[serde(default)]
    pub after_manifest_key: Option<[u8; 32]>,
    /// Exclusive cursor for paginating ownership records by mint_id.
    #[serde(default)]
    pub after_ownership_mint_id: Option<[u8; 32]>,
    /// Exclusive cursor for paginating consumed tombstones by mint_id.
    #[serde(default)]
    pub after_consumed_mint_id: Option<[u8; 32]>,
    /// Maximum tag records to return.
    pub max_tags: u16,
    /// Maximum encrypted manifest records to return.
    pub max_manifests: u16,
    /// Maximum ownership records to return.
    #[serde(default)]
    pub max_ownership_records: u16,
    /// Maximum consumed-record tombstones to return.
    #[serde(default)]
    pub max_consumed_records: u16,
    /// Proof that the requester owns a Vess bill (prevents Sybil-based
    /// DHT shard collection during bootstrap). Absent in testnet mode.
    #[serde(default)]
    pub burn_proof: Option<ProofOfVessOwnership>,
}

/// A tag DHT record transferred during seed sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedTagRecord {
    /// Blake3 hash of the tag string.
    pub tag_hash: [u8; 32],
    /// Scan encapsulation key.
    pub scan_ek: Vec<u8>,
    /// Spend encapsulation key.
    pub spend_ek: Vec<u8>,
    /// PoW nonce.
    pub pow_nonce: [u8; 32],
    /// PoW hash.
    pub pow_hash: Vec<u8>,
    /// Registration timestamp.
    pub registered_at: u64,
    /// Registrant verification key.
    pub registrant_vk: Vec<u8>,
    /// Registrant signature over the tag record digest.
    pub signature: Vec<u8>,
    /// Hardened timestamp, if this tag has already been hardened.
    #[serde(default)]
    pub hardened_at: Option<u64>,
}

/// An ownership registry record transferred during seed sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedOwnershipRecord {
    /// Permanent bill identity.
    pub mint_id: [u8; 32],
    /// Current ownership chain tip.
    pub chain_tip: [u8; 32],
    /// Blake3 hash of the current owner's verification key.
    pub current_owner_vk_hash: [u8; 32],
    /// Full current owner verification key.
    pub current_owner_vk: Vec<u8>,
    /// Denomination value for supply tracking.
    pub denomination_value: u64,
    /// Unix timestamp when this record was last updated.
    pub updated_at: u64,
    /// Blake3 hash of the verified genesis proof bytes, if known.
    pub proof_hash: [u8; 32],
    /// Genesis or burn commitment digest.
    pub digest: [u8; 32],
    /// Minting nonce or equivalent derived nonce, if known.
    pub nonce: [u8; 32],
    /// Previous owner vk hash from the winning claim, if any.
    #[serde(default)]
    pub prev_claim_vk_hash: Option<[u8; 32]>,
    /// Deterministic hash of the winning claim, if any.
    #[serde(default)]
    pub claim_hash: Option<[u8; 32]>,
    /// Pre-transfer chain tip for the current transfer slot, if known.
    #[serde(default)]
    pub prev_transfer_chain_tip: Option<[u8; 32]>,
    /// Number of transfers since genesis.
    #[serde(default)]
    pub chain_depth: u64,
    /// Encrypted bill recovery payload for the current owner.
    #[serde(default)]
    pub encrypted_bill: Vec<u8>,
}

/// A consumed-bill tombstone transferred during seed sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedConsumedRecord {
    /// Mint ID that was consumed by a reforge.
    pub mint_id: [u8; 32],
    /// Reforge event identifier.
    pub reforge_id: [u8; 32],
    /// Output mint IDs produced by the reforge.
    pub output_mint_ids: Vec<[u8; 32]>,
    /// Unix timestamp when the bill was consumed.
    pub consumed_at: u64,
    /// Denomination value of the consumed bill, if known.
    #[serde(default)]
    pub denomination_value: u64,
    /// Original bill digest, if known.
    #[serde(default)]
    pub digest: [u8; 32],
}

/// Initial DHT data returned by a seed/bootstrap peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedResponse {
    /// Responder mesh node ID.
    pub responder_node_id: [u8; 32],
    /// Tag records the requester should store.
    pub tags: Vec<DhtSeedTagRecord>,
    /// Encrypted wallet manifests the requester should store.
    pub manifests: Vec<ManifestStore>,
    /// Ownership records the requester should store.
    #[serde(default)]
    pub ownership_records: Vec<DhtSeedOwnershipRecord>,
    /// Consumed-bill tombstones the requester should store.
    #[serde(default)]
    pub consumed_records: Vec<DhtSeedConsumedRecord>,
}

// ── Kademlia FIND_NODE ───────────────────────────────────────────────

/// Kademlia FIND_NODE request: ask a peer for the K closest
/// infrastructure nodes to a 32-byte target hash.
///
/// **Privacy:** The target can be any DHT key (mint_id, tag hash, etc.)
/// or a random node ID for routing table refresh. It never reveals
/// wallet identities or payment recipients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNode {
    /// The 32-byte target to find closest peers for.
    pub target: [u8; 32],
    /// The requester's mesh node ID bytes (so the responder can add us
    /// to their routing table).
    pub sender_id: Vec<u8>,
}

/// Response to a [`FindNode`] request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNodeResponse {
    /// Serialized mesh contacts of the K closest peers the responder knows.
    pub peers: Vec<Vec<u8>>,
}

// ── Handshake ────────────────────────────────────────────────────────

/// Challenge a peer to prove they are running an authorised protocol build.
///
/// The challenger generates a random 32-byte nonce and sends it to the peer.
/// The peer must respond with `HMAC-Blake3(PROTOCOL_VERSION_HASH, nonce)`
/// **and** an Argon2id proof-of-work over the nonce to make Sybil node
/// creation expensive (~2-5 seconds + 256 MiB per handshake).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeChallenge {
    /// Random 32-byte nonce for the challenge.
    pub nonce: [u8; 32],
}

/// Response to a [`HandshakeChallenge`].
///
/// Contains `blake3::keyed_hash(PROTOCOL_VERSION_HASH, nonce)` which proves
/// the responder possesses the correct build-time version hash. The mesh
/// transport already binds the session to the responder's mesh identity, so
/// no additional signature is required here.
///
/// Also contains an Argon2id proof-of-work over the nonce. This forces
/// each connecting node to spend ~2-5 seconds + 256 MiB RAM, making
/// Sybil attacks economically expensive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// HMAC-Blake3 proof: `keyed_hash(PROTOCOL_VERSION_HASH, nonce)`.
    pub hmac: [u8; 32],
    /// Argon2id hash over `Blake3("vess-handshake-pow-v0" || node_id || nonce)`.
    /// The challenger verifies this to ensure the responder invested real
    /// computational resources.
    #[serde(default)]
    pub pow_hash: Vec<u8>,
}

// ── Banishment ──────────────────────────────────────────────────────

/// Type of protocol violation that triggered a banishment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BanishmentOffense {
    /// Peer sent two conflicting OwnershipClaims for the same mint_id.
    DoubleSpend,
    /// Peer sent an OwnershipClaim with an invalid signature.
    InvalidClaimSignature,
    /// Peer sent a ReforgeAttestation that fails proof verification.
    InvalidReforgeProof,
    /// Peer sent a HandshakeResponse with an HMAC that doesn't match
    /// any allowed protocol version.
    ProtocolVersionMismatch,
    /// Peer exceeded per-peer rate limits repeatedly (spam/flood).
    RateLimitAbuse,
    /// Generic: peer sent a pulse that failed validation.
    InvalidMessage { reason: String },
}

/// Network-wide banishment proof.
///
/// Carries cryptographic evidence that a peer misbehaved. Every node
/// that receives this message independently verifies the evidence and
/// banishes the peer if valid. Sybils cannot fabricate evidence against
/// honest nodes because the evidence requires the victim's signature
/// or cryptographic proof of protocol violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanishmentProof {
    /// The peer being accused.
    pub peer_id: [u8; 32],
    /// What they did.
    pub offense: BanishmentOffense,
    /// Cryptographic evidence (e.g. the conflicting claim, invalid
    /// signature, or reforge proof that failed verification).
    pub evidence: Vec<u8>,
    /// The reporting node's signature over `(peer_id || offense || evidence_hash)`.
    /// Prevents Sybils from generating fake reports en masse.
    pub reporter_vk: Vec<u8>,
    /// ML-DSA-65 signature by the reporter.
    pub reporter_signature: Vec<u8>,
    /// Unix timestamp when the offense was observed.
    pub observed_at: u64,
}

// ── Limbo ────────────────────────────────────────────────────────────

/// Announce that specific bills have entered limbo.
///
/// Sent by a custodian node to its neighbors when a payment passes all
/// relay checks but the recipient is offline. This is a soft reservation;
/// the sender can re-spend the bill to cancel the pending delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimboHold {
    /// Bill IDs entering limbo.
    pub bill_ids: Vec<[u8; 32]>,
    /// Stealth ID of the intended recipient.
    pub stealth_id: [u8; 32],
    /// Unix timestamp when limbo was entered.
    pub entered_at: u64,
}

/// Lightweight notification that limbo payments exist for a stealth_id.
///
/// Periodically broadcast by custodian nodes (every 5–10 minutes) so that
/// a recipient connecting to any artery can discover waiting payments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimboNotify {
    /// Stealth ID that has waiting payments.
    pub stealth_id: [u8; 32],
    /// Number of payments waiting.
    pub count: u32,
    /// Node ID of the custodian holding the payments.
    pub custodian_id: [u8; 32],
}

/// Deliver a limbo-held payment to the recipient.
///
/// When the recipient comes online and is reachable, the custodian
/// sends the original payment data so the recipient can reforge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimboDeliver {
    /// The original payment that was held in limbo.
    pub payment: Payment,
}

// ── Tag Replication ───────────────────────────────────────────────

/// Replicate a tag record to peer DHT nodes for redundancy.
///
/// After a `TagRegister` is accepted, the artery node gossips
/// `TagStore` to K-nearest peers by XOR distance to the tag's
/// DHT key, achieving 16× replication like bills.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagStore {
    /// Blake3 hash of the tag string (plaintext never sent over wire).
    pub tag_hash: [u8; 32],
    /// Scan encapsulation key (from the master stealth address).
    pub scan_ek: Vec<u8>,
    /// Spend encapsulation key (from the master stealth address).
    pub spend_ek: Vec<u8>,
    /// Random 32-byte nonce (salt) for the Argon2id PoW.
    pub pow_nonce: [u8; 32],
    /// 32-byte Argon2id output hash (proof-of-work).
    pub pow_hash: Vec<u8>,
    /// Registration timestamp.
    pub registered_at: u64,
    /// Remaining gossip hops (decremented each forward).
    pub hops_remaining: u8,
    /// ML-DSA-65 verification key of the registrant.
    #[serde(default)]
    pub registrant_vk: Vec<u8>,
    /// ML-DSA-65 signature over the tag record digest.
    #[serde(default)]
    pub signature: Vec<u8>,
}

// ── Tag Confirmation (Hardening) ──────────────────────────────────

/// Confirm (harden) a VessTag by proving payment receipt.
///
/// The tag owner submits a `mint_id` from the ownership registry (proving
/// a real spend occurred) along with an ML-DSA signature from the same
/// `registrant_vk` used during registration. This proves the registrant
/// is an active participant who receives real payments.
///
/// Once hardened, the tag persists indefinitely. Unhardened tags are
/// pruned after 30 days.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagConfirm {
    /// Blake3 hash of the tag to confirm/harden.
    pub tag_hash: [u8; 32],
    /// A mint_id that exists in the ownership registry (proof a real spend happened).
    pub mint_id: [u8; 32],
    /// ML-DSA-65 verification key of the registrant (must match the tag record).
    pub registrant_vk: Vec<u8>,
    /// ML-DSA-65 signature over `Blake3("vess-tag-confirm-v1" || tag_hash || mint_id)`.
    pub signature: Vec<u8>,
    /// Remaining gossip hops (decremented each forward).
    pub hops_remaining: u8,
}

// ── Serialization ────────────────────────────────────────────────────

// ── Ownership ────────────────────────────────────────────────────────

/// Register a freshly minted bill in the artery ownership registry.
///
/// Sent by the minter after a successful mint. The artery verifies the
/// STARK proof and seeds the ownership registry with the genesis chain tip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipGenesis {
    /// Permanent bill identity: `Blake3("vess-mint-id-v0" || digest || nonce)`.
    pub mint_id: [u8; 32],
    /// Genesis chain tip: `Blake3("vess-chain-v0" || mint_id || owner_vk_hash)`.
    pub chain_tip: [u8; 32],
    /// Blake3 hash of the minter's ML-DSA-65 verification key.
    pub owner_vk_hash: [u8; 32],
    /// Full ML-DSA-65 verification key of the minter (for future transfer verification).
    pub owner_vk: Vec<u8>,
    /// Denomination value for supply tracking.
    pub denomination_value: u64,
    /// Typed genesis proof for this bill.
    pub genesis_proof: GenesisProof,
    /// Genesis commitment hash.
    ///
    /// For Vess-native bills this is the VM or compound proof digest.
    /// For Bitcoin-burned bills this is the burn bundle commitment hash.
    pub digest: [u8; 32],
    /// Remaining gossip hops (decremented at each relay, stops at 0).
    pub hops_remaining: u8,
    /// Chain depth at genesis is always 0.
    #[serde(default)]
    pub chain_depth: u64,
    /// Output index within a split/combine reforge (0-based).
    /// Set to 0 for regular minted bills. Used by verifiers to derive
    /// and confirm the `mint_id` of a reforge output without a random nonce.
    #[serde(default)]
    pub output_index: u32,
    /// Argon2id PoW nonce for genesis anti-spam.
    #[serde(default)]
    pub pow_nonce: Option<[u8; 32]>,
    /// Argon2id PoW hash.
    #[serde(default)]
    pub pow_hash: Option<[u8; 32]>,
    /// Accumulated propagation work.
    #[serde(default)]
    pub accumulated_work: Option<u64>,
}

impl Default for OwnershipGenesis {
    fn default() -> Self {
        Self {
            mint_id: [0u8; 32],
            chain_tip: [0u8; 32],
            owner_vk_hash: [0u8; 32],
            owner_vk: Vec::new(),
            denomination_value: 0,
            genesis_proof: GenesisProof::Vess(Vec::new()),
            digest: [0u8; 32],
            hops_remaining: 0,
            chain_depth: 0,
            output_index: 0,
            pow_nonce: None,
            pow_hash: None,
            accumulated_work: None,
        }
    }
}

/// Claim ownership of a bill after receiving a transfer.
///
/// The receiver broadcasts this to rotate ownership in the artery registry.
/// The artery verifies the previous owner's transfer signature, computes
/// the expected new chain tip, and updates the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipClaim {
    /// Permanent bill identity.
    pub mint_id: [u8; 32],
    /// Stealth ID the transfer was addressed to (included in transfer_message).
    pub stealth_id: [u8; 32],
    /// Full ML-DSA-65 verification key of the PREVIOUS owner.
    /// The artery checks `Blake3(prev_owner_vk) == stored current_owner_vk_hash`.
    #[serde(default)]
    pub prev_owner_vk: Vec<u8>,
    /// Transfer authorization signature from the previous owner.
    /// Signs `transfer_message(mint_id, stealth_id, timestamp)`.
    #[serde(default)]
    pub transfer_sig: Vec<u8>,
    /// Blake3 hash of the NEW owner's ML-DSA-65 verification key.
    pub new_owner_vk_hash: [u8; 32],
    /// Full ML-DSA-65 verification key of the new owner (stored for next transfer).
    #[serde(default)]
    pub new_owner_vk: Vec<u8>,
    /// Expected new chain tip: `Blake3(prev_chain_tip || new_owner_vk_hash || sig_hash)`.
    pub new_chain_tip: [u8; 32],
    /// Unix timestamp (must match the signed transfer message).
    pub timestamp: u64,
    /// Remaining gossip hops (decremented at each relay, stops at 0).
    pub hops_remaining: u8,
    /// Chain depth after this transfer. Must equal the previous depth + 1.
    /// Deeper chains win in conflict resolution — this makes bills
    /// "harder to dispute" with every successive transfer.
    #[serde(default)]
    pub chain_depth: u64,
    /// Encrypted bill data for DHT recovery. The bill is encrypted to the
    /// new owner's stealth address — only they can decrypt it. Artery nodes
    /// store this opaque blob so the recipient can recover the bill from
    /// the DHT if they lose their local copy.
    #[serde(default)]
    pub encrypted_bill: Vec<u8>,
    /// Argon2id PoW nonce for claim anti-spam.
    #[serde(default)]
    pub pow_nonce: Option<[u8; 32]>,
    /// Argon2id PoW hash.
    #[serde(default)]
    pub pow_hash: Option<[u8; 32]>,
    /// Accumulated propagation work.
    #[serde(default)]
    pub accumulated_work: Option<u64>,
    /// Optional preimage for hash-locked payments (atomic swaps).
    /// Must satisfy Blake3(preimage) == Payment.hash_lock.
    #[serde(default)]
    pub hash_preimage: Option<[u8; 32]>,
}

impl Default for OwnershipClaim {
    fn default() -> Self {
        Self {
            mint_id: [0u8; 32],
            stealth_id: [0u8; 32],
            prev_owner_vk: Vec::new(),
            transfer_sig: Vec::new(),
            new_owner_vk_hash: [0u8; 32],
            new_owner_vk: Vec::new(),
            new_chain_tip: [0u8; 32],
            timestamp: 0,
            hops_remaining: 0,
            chain_depth: 0,
            encrypted_bill: Vec::new(),
            pow_nonce: None,
            pow_hash: None,
            accumulated_work: None,
            hash_preimage: None,
        }
    }
}

// ── Atomic Swap ─────────────────────────────────────────────────────

/// A posted offer to swap one asset for another via atomic hash-locked
/// payments. Stored in the DHT at Blake3("vess-swap-v0" || min(a,b) || max(a,b)).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOffer {
    pub offer_asset: String,
    pub offer_amount: u64,
    pub want_asset: String,
    pub want_amount: u64,
    pub recipient: String,
    pub hash_lock: [u8; 32],
    pub expires_at: u64,
    pub offerer_node_id: Vec<u8>,
}

impl SwapOffer {
    pub fn dht_key(&self) -> [u8; 32] {
        swap_dht_key(&self.offer_asset, &self.want_asset)
    }
}

pub fn swap_dht_key(a: &str, b: &str) -> [u8; 32] {
    let (first, second) = if a < b { (a, b) } else { (b, a) };
    let mut h = blake3::Hasher::new();
    h.update(b"vess-swap-v0");
    h.update(first.as_bytes());
    h.update(b"|");
    h.update(second.as_bytes());
    *h.finalize().as_bytes()
}

/// Response to a SwapOffer query. Returns matching offers stored by this node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOfferResponse {
    /// Matching swap offers for the requested pair.
    pub offers: Vec<SwapOffer>,
}

// ── Reforge Attestation ──────────────────────────────────────────────

/// Attest that input bills have been consumed in a split/combine reforge.
///
/// The wallet broadcasts this after performing a reforge (split or combine).
/// Artery nodes verify that the sender owns each consumed input, then delete
/// those mint_ids from the registry. The new output bills are registered
/// separately via [`OwnershipGenesis`] messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReforgeAttestation {
    /// Mint IDs of the bills consumed (split apart or combined).
    pub consumed_mint_ids: Vec<[u8; 32]>,
    /// ML-DSA-65 verification key of the owner who performed the reforge.
    pub owner_vk: Vec<u8>,
    /// One signature per consumed mint_id, proving the owner authorised
    /// the consumption. Signs `Blake3("vess-reforge-consume-v0" || mint_id || reforge_id)`.
    pub consume_sigs: Vec<Vec<u8>>,
    /// Deterministic reforge identity: ties the consumption to a specific
    /// reforge event. `Blake3("vess-reforge-id-v0" || sorted consumed_mint_ids)`.
    pub reforge_id: [u8; 32],
    /// Mint IDs of the new output bills created by this reforge.
    ///
    /// Included so nodes that held records for the consumed bills can store
    /// tombstones pointing to the new bills, enabling wallets to trace funds
    /// through split/combine operations.
    #[serde(default)]
    pub output_mint_ids: Vec<[u8; 32]>,
    /// Remaining gossip hops (decremented at each relay, stops at 0).
    pub hops_remaining: u8,
}

// ── Network Statistics ───────────────────────────────────────────────

/// Request network-level statistics from an artery node.
///
/// The response includes the node's local peer count and recent
/// payment latency observations (time from payment relay to ownership
/// confirmation back to the sender).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Optional nonce for request/response correlation.
    pub nonce: [u8; 32],
}

/// Response to a [`NetworkStats`] request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatsResponse {
    /// Echo of the request nonce for correlation.
    pub nonce: [u8; 32],
    /// Number of peers in this node's routing table.
    pub peer_count: u64,
    /// Number of verified peers (passed handshake).
    pub verified_peer_count: u64,
    /// Estimated total network size (from Kademlia density heuristic).
    pub estimated_network_size: u64,
    /// Number of bills currently in limbo (payments in flight).
    pub limbo_count: u64,
    /// Median payment latency in milliseconds over the recent observation
    /// window (0 if no observations yet).
    pub median_payment_latency_ms: u64,
    /// 95th-percentile payment latency in milliseconds (0 if no data).
    pub p95_payment_latency_ms: u64,
    /// Number of latency samples in the current window.
    pub latency_sample_count: u64,
}

// ── Manifest (Recovery) ──────────────────────────────────────────────

/// Store an encrypted wallet manifest in the DHT for recovery.
///
/// The manifest is a ChaCha20Poly1305-encrypted list of (mint_id, dht_index)
/// pairs. Its DHT key is `Blake3(spend_seed || "vess-manifest-v0")`, so
/// only the wallet owner can compute it and decrypt it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestStore {
    /// DHT key: `Blake3(spend_seed || "vess-manifest-v0")`.
    pub dht_key: [u8; 32],
    /// ChaCha20Poly1305-encrypted manifest bytes.
    pub encrypted_manifest: Vec<u8>,
    /// Gossip hop counter.
    pub hops_remaining: u8,
}

/// Request an encrypted wallet manifest from DHT nodes by its key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRecover {
    /// The deterministic DHT key to look up.
    pub dht_key: [u8; 32],
}

/// Response to a [`ManifestRecover`] request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRecoverResponse {
    /// The requested DHT key.
    pub dht_key: [u8; 32],
    /// The encrypted manifest bytes (empty if not found).
    pub encrypted_manifest: Vec<u8>,
    /// Whether the node had the manifest.
    pub found: bool,
}

// ── Ownership Fetch ──────────────────────────────────────────────────

/// Fetch full ownership records by mint_id (used during recovery).
///
/// After decrypting the manifest, the wallet sends this to retrieve
/// the sealed bill payloads stored on each ownership record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipFetch {
    /// Mint IDs to fetch records for.
    pub mint_ids: Vec<[u8; 32]>,
}

/// A fetched ownership record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchedRecord {
    /// The requested mint_id.
    pub mint_id: [u8; 32],
    /// Whether the record was found.
    pub found: bool,
    /// Denomination value.
    pub denomination_value: u64,
    /// Current ownership chain tip (for recovery).
    pub chain_tip: [u8; 32],
    /// VM execution digest (for recovery).
    pub digest: [u8; 32],
}

/// Response to an [`OwnershipFetch`] request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipFetchResponse {
    /// Fetched records (parallel to the request's `mint_ids`).
    pub records: Vec<FetchedRecord>,
}

// ── Century Lock ─────────────────────────────────────────────────────

/// The number of Bitcoin blocks in 100 years (144 × 365.25 × 100).
pub const CENTURY_LOCK_BLOCKS: u64 = 5_256_000;

/// Standard Bitcoin blocks per year (144 × 365.25).

/// State for an active century-lock faucet.
///
/// When BTC is burned for 100 years, it creates a perpetual Vess faucet
/// that mints one bill per Bitcoin block. Each bill is valued at
/// `total_sats / BLOCKS_PER_YEAR` (rounded down).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CenturyLockState {
    /// Unique identifier: `Blake3("vess-century-lock-v0" || burn_txid)`.
    pub lock_id: [u8; 32],
    /// The Bitcoin burn proof that created this lock.
    pub burn_proof: BitcoinTimeLockProof,
    /// Total satoshis burned (from burn_proof.locked_sats).
    pub total_sats: u64,
    /// Vess amount per Bitcoin block: `total_sats / BLOCKS_PER_YEAR`.
    pub per_block_vess: u64,
    /// Bitcoin block height when the lock starts (burn confirmation height).
    pub start_block: u64,
    /// Bitcoin block height when the lock expires (start + CENTURY_LOCK_BLOCKS).
    pub end_block: u64,
    /// Last Bitcoin block height for which a bill was minted.
    /// Increments by 1 each time a bill is successfully claimed.
    pub last_claimed_block: u64,
    /// The node ID of the wallet that owns this century lock.
    pub owner_node_id: [u8; 32],
    /// Unix timestamp when this lock was created.
    pub created_at: u64,
}

impl CenturyLockState {
    /// Create a new century lock state from a burn proof.
    pub fn new(burn_proof: BitcoinTimeLockProof, owner_node_id: [u8; 32], created_at: u64) -> Self {
        let total_sats = burn_proof.locked_sats;
        let per_block_vess = (total_sats + BLOCKS_PER_YEAR - 1) / BLOCKS_PER_YEAR;
        let start_block = burn_proof.block_height;
        let end_block = start_block.saturating_add(CENTURY_LOCK_BLOCKS);
        let lock_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-century-lock-v0");
            h.update(&burn_proof.txid);
            *h.finalize().as_bytes()
        };
        Self {
            lock_id,
            burn_proof,
            total_sats,
            per_block_vess,
            start_block,
            end_block,
            last_claimed_block: start_block.saturating_sub(1), // nothing claimed yet
            owner_node_id,
            created_at,
        }
    }

    /// How many blocks remain unclaimed.
    pub fn unclaimed_blocks(&self, current_block: u64) -> u64 {
        if current_block <= self.last_claimed_block {
            return 0;
        }
        let max_claimable = self.end_block.min(current_block);
        max_claimable.saturating_sub(self.last_claimed_block)
    }

    /// Remaining Vess that can be minted from this lock.
    pub fn remaining_vess(&self, current_block: u64) -> u64 {
        self.unclaimed_blocks(current_block) * self.per_block_vess
    }

    /// Whether this lock is still active.
    pub fn is_active(&self, current_block: u64) -> bool {
        current_block < self.end_block && self.last_claimed_block < self.end_block
    }
}

// ── Direct Peer-to-Peer Payment ──────────────────────────────────────

/// Direct payment sent over a direct mesh session between two wallets.
///
/// Bypasses artery relay nodes entirely — the receiver verifies proofs
/// inline and claims ownership locally, broadcasting [`OwnershipClaim`]
/// messages when artery connectivity is available.
///
/// The direct mesh transport provides encryption, so no stealth wrapping is
/// needed. The `transfer_payload` is a serialized `TransferPayload`
/// (defined in `vess-kloak`) containing the bills, sender verification
/// keys, and transfer authorization signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPayment {
    /// Unique payment identifier.
    pub payment_id: [u8; 32],
    /// Serialized `TransferPayload` (bills + sender VKs + transfer sigs).
    pub transfer_payload: Vec<u8>,
    /// Stealth ID the transfer is addressed to (binds the signatures).
    pub recipient_stealth_id: [u8; 32],
    /// Public bill identifiers (parallel arrays for inline verification).
    pub mint_ids: Vec<[u8; 32]>,
    /// Denomination values of each bill.
    pub denomination_values: Vec<u64>,
    /// Unix timestamp when payment was created.
    pub created_at: u64,
}

/// Response to a [`DirectPayment`].
///
/// Returned over the same direct mesh session. If `accepted` is `true`, the
/// receiver has verified the proofs and will broadcast ownership claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPaymentResponse {
    /// Echoed payment ID.
    pub payment_id: [u8; 32],
    /// Whether the payment was accepted.
    pub accepted: bool,
    /// Signed acceptance receipt, required when `accepted` is true for direct payments.
    #[serde(default)]
    pub receipt: Option<DirectPaymentReceipt>,
    /// Human-readable rejection reason (empty if accepted).
    #[serde(default)]
    pub reason: String,
}

/// Recipient-signed proof that a direct payment was accepted for a specific tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPaymentReceipt {
    /// Echoed payment ID.
    pub payment_id: [u8; 32],
    /// Blake3 hash of the recipient tag the sender resolved.
    pub tag_hash: [u8; 32],
    /// Stealth ID from the encrypted payment payload.
    pub recipient_stealth_id: [u8; 32],
    /// Mint IDs accepted by the recipient.
    pub claimed_mint_ids: Vec<[u8; 32]>,
    /// Total accepted amount.
    pub total_amount: u64,
    /// Recipient's fresh owner verification key for the first claimed bill.
    pub recipient_owner_vk: Vec<u8>,
    /// ML-DSA-65 signature over the receipt digest.
    pub signature: Vec<u8>,
}

/// Recipient-signed cryptographic proof of payment receipt.
///
/// The recipient signs this after decrypting and claiming the payment.
/// The sender verifies locally — no DHT gossip needed for confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Echoed payment ID from the original Payment message.
    pub payment_id: [u8; 32],
    /// Mint IDs claimed by the recipient.
    pub claimed_mint_ids: Vec<[u8; 32]>,
    /// Total value received.
    pub total_amount: u64,
    /// Unix timestamp.
    pub timestamp: u64,
    /// ML-DSA-65 signature over the receipt digest:
    /// `Blake3("vess-receipt-v0" || payment_id || claimed_mint_ids || total_amount || timestamp)`
    pub signature: Vec<u8>,
}

/// Encrypted acknowledgment from a limbo-holding peer to the sender.
///
/// When a peer stores a payment in limbo for a recipient's mailbox key,
/// it sends this back so the sender knows their payment reached the right
/// DHT neighborhood — without waiting for the recipient to decrypt.
///
/// The payload is ChaCha20Poly1305-encrypted with a key derived from
/// `Blake3("vess-limbo-ack-v1" || payment_id)`, so only the sender
/// and gossip-path peers (who saw the Payment message) can decrypt it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimboAck {
    /// Random nonce for the AEAD encryption.
    pub nonce: [u8; 12],
    /// Encrypted LimboAckPayload (ChaCha20Poly1305).
    pub ciphertext: Vec<u8>,
}

/// Decrypted contents of a LimboAck.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimboAckPayload {
    /// Echoed payment ID from the original Payment.
    pub payment_id: [u8; 32],
    /// Node ID of the peer that stored the payment in limbo.
    pub holder_peer_id: [u8; 32],
    /// Unix timestamp.
    pub timestamp: u64,
}

impl PulseMessage {
    /// Serialize this message to bytes using postcard.
    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }

    /// Deserialize a message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn payment_round_trip() {
        let msg = PulseMessage::Payment(Payment {
            payment_id: [0xAA; 32],
            stealth_payload: vec![1, 2, 3, 4],
            view_tag: 0x42,
            stealth_id: [0xBB; 32],
            created_at: 1000,
            bill_count: 1,
            mailbox_key: None,
            direct_receipt_tag_hash: None,
            hash_lock: None,
        });
        let bytes = msg.to_bytes().unwrap();
        let decoded = PulseMessage::from_bytes(&bytes).unwrap();
        match decoded {
            PulseMessage::Payment(p) => {
                assert_eq!(p.payment_id, [0xAA; 32]);
                assert_eq!(p.view_tag, 0x42);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tag_lookup_round_trip() {
        let tag_hash = *blake3::hash(b"alice").as_bytes();
        let msg = PulseMessage::TagLookup(TagLookup {
            tag_hash,
            nonce: [0xFF; 16],
            burn_proof: None,
        });
        let bytes = msg.to_bytes().unwrap();
        let decoded = PulseMessage::from_bytes(&bytes).unwrap();
        match decoded {
            PulseMessage::TagLookup(t) => assert_eq!(t.tag_hash, tag_hash),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn dht_seed_request_round_trip_with_cursors() {
        let msg = PulseMessage::DhtSeedRequest(DhtSeedRequest {
            requester_node_id: [0x11; 32],
            after_tag_hash: Some([0x22; 32]),
            after_manifest_key: Some([0x33; 32]),
            after_ownership_mint_id: Some([0x44; 32]),
            after_consumed_mint_id: Some([0x55; 32]),
            max_tags: 10,
            max_manifests: 11,
            max_ownership_records: 12,
            max_consumed_records: 13,
            burn_proof: None,
        });
        let bytes = msg.to_bytes().unwrap();
        let decoded = PulseMessage::from_bytes(&bytes).unwrap();
        match decoded {
            PulseMessage::DhtSeedRequest(req) => {
                assert_eq!(req.requester_node_id, [0x11; 32]);
                assert_eq!(req.after_tag_hash, Some([0x22; 32]));
                assert_eq!(req.after_manifest_key, Some([0x33; 32]));
                assert_eq!(req.after_ownership_mint_id, Some([0x44; 32]));
                assert_eq!(req.after_consumed_mint_id, Some([0x55; 32]));
                assert_eq!(req.max_tags, 10);
                assert_eq!(req.max_manifests, 11);
                assert_eq!(req.max_ownership_records, 12);
                assert_eq!(req.max_consumed_records, 13);
            }
            _ => panic!("wrong variant"),
        }
    }

    proptest! {
        #[test]
        fn pulse_message_truncated_payloads_fail_cleanly(
            stealth_payload in proptest::collection::vec(any::<u8>(), 0..256),
            created_at in any::<u64>(),
            bill_count in any::<u8>(),
            cutoff in 0usize..256,
        ) {
            let msg = PulseMessage::Payment(Payment {
                payment_id: [0xAB; 32],
                stealth_payload,
                view_tag: 0x42,
                stealth_id: [0xCD; 32],
                created_at,
                bill_count,
                mailbox_key: None,
                direct_receipt_tag_hash: None,
            hash_lock: None,
        });
            let bytes = msg.to_bytes().unwrap();
            prop_assume!(!bytes.is_empty());
            let truncate_at = cutoff % bytes.len();
            let truncated = &bytes[..truncate_at];

            prop_assert!(PulseMessage::from_bytes(truncated).is_err());
        }

        #[test]
        fn pulse_message_parser_handles_arbitrary_bytes(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
            if let Ok(msg) = PulseMessage::from_bytes(&payload) {
                let reencoded = msg.to_bytes().unwrap();
                prop_assert!(PulseMessage::from_bytes(&reencoded).is_ok());
            }
        }
    }
}
