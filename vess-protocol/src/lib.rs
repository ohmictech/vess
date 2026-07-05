//! **vess-protocol** — Wire-level message types for the Vess vascular network.
//!
//! All messages exchanged between nodes are variants of [`PulseMessage`].
//! Each message is serialized with `postcard` (compact, no-std friendly)
//! and wrapped in the vascular framing layer.
//!
//! # Message Categories
//!
//! - [`Payment`] — Stealth-encrypted bill transfers.
//! - [`TagRegister`] / [`TagLookup`] — VessTag registration and resolution.
//! - [`MailboxCollect`] / [`MailboxSweep`] — Offline payment delivery.
//! - [`RegistryQuery`] / [`RegistryQueryResponse`] — Ownership status lookup.
//! - [`ManifestStore`] / [`ManifestRecover`] — Wallet recovery manifests.
//! - [`Mint`] / [`VessSubmit`] — Vess bill minting and transfer.
//! - [`DhtResponse`] — Signed DHT response with Vess ownership proof.

use serde::{Deserialize, Serialize};
use vess_foundry::Vess;

// ── Dev faucet ──────────────────────────────────────────────────────

/// Dev subsidy per epoch.
pub const DEV_FAUCET_AMOUNT: u64 = 30_000;

/// Canonical dev ML-DSA-65 verification key (hardcoded, public).
/// Every node verifies faucet signatures against this key.
pub const DEV_VK: [u8; 1953] = [
    0x00; 1953 // PLACEHOLDER — replace with actual dev VK before launch
];

// ── DHT trust ───────────────────────────────────────────────────────

/// Signed DHT response — proves the responder owns real Vess.
///
/// The responder picks one Vess from its wallet, signs with its spend key.
/// The requester verifies by looking up `proof_vess_id` in its local
/// VessStore and checking `responder_sig` against that Vess's `owner_vk`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDhtResponse {
    /// Opaque serialized query results.
    pub results: Vec<u8>,
    /// Vess ID the responder is proving ownership of.
    pub proof_vess_id: [u8; 32],
    /// ML-DSA-65 signature: `sign(Blake3("vess-dht-v1" || results || proof_vess_id))`.
    pub responder_sig: Vec<u8>,
}

/// Top-level pulse message envelope.
///
/// Every vascular pulse carries exactly one of these variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PulseMessage {
    /// A payment: stealth-encrypted bill(s) sent to a recipient.
    Payment(Payment),

    /// Submit a transfer/change Vess for DHT storage.
    VessSubmit(Vess),

    /// Dev faucet submission — one per epoch, cryptographically verified.
    FaucetSubmit(Vess),

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

    /// Push a Vess to a DHT shard peer for replication.
    DhtStoreVess(Vess),

    /// Push an encrypted wallet manifest to a DHT shard peer.
    DhtStoreManifest(ManifestStore),

    /// Query a DHT peer for data (tag, Vess, mailbox, manifest).
    DhtQuery(DhtQuery),

    /// Response from a DHT peer to a query.
    DhtQueryResponse(DhtQueryResponse),

    /// Handshake challenge: prove you are running an authorised protocol version.
    HandshakeChallenge(HandshakeChallenge),

    /// Handshake response: HMAC proof of the protocol version hash.
    HandshakeResponse(HandshakeResponse),

    /// Query whether specific mint_ids are active in the ownership registry.
    RegistryQuery(RegistryQuery),

    /// Signed DHT query response — responder proves Vess ownership.
    DhtResponse(SignedDhtResponse),

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

    /// Register a freshly minted bill in the ownership registry.

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

    /// Response to a direct peer-to-peer payment.

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

    /// Onion-routed payment: 3-hop DKSAP-layered forwarding.
    /// Each relay decrypts one layer and forwards the inner packet.
    /// No single hop knows both sender and recipient.
    OnionRoute(OnionRoute),

    /// Atomic swap offer for trustless cross-asset exchange.
    /// Stored in the DHT keyed by Blake3("vess-swap-v0" || asset_a || asset_b).

    /// Response to a swap offer query.

    /// Clock state gossip: a peer shares its current hash-tick clock.
    /// Used for network-time computation and lock verification.
    ClockGossip(ClockGossip),

    /// Request a tick proof from a peer for a specific tick number.
    ClockProofRequest(ClockProofRequest),

    /// Response with a Merkle proof linking a tick to the peer's genesis.
    ClockProofResponse(ClockProofResponse),

}

// ── Hash Clock ──────────────────────────────────────────────────────

/// A peer's clock state shared via gossip for network-time computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockGossip {
    /// The node that owns this clock.
    pub node_id: [u8; 32],
    /// Genesis hash: blake3(node_id || "vess-clock-genesis-v1").
    pub genesis_hash: [u8; 32],
    /// Current tick number.
    pub current_tick: u64,
    /// Hash at the current tick.
    pub current_hash: [u8; 32],
    /// When this clock was started (wall time ms, for drift estimation).
    pub started_at_ms: u64,
    /// When the current tick was created.
    pub last_tick_at_ms: u64,
}

/// Request a Merkle proof for a specific tick from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockProofRequest {
    /// Tick number to prove.
    pub tick: u64,
}

/// A Merkle proof linking a tick to a peer's clock genesis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockProofResponse {
    /// The node this proof belongs to.
    pub node_id: [u8; 32],
    /// The tick number being proven.
    pub tick: u64,
    /// Hash at this tick.
    pub tick_hash: [u8; 32],
    /// Merkle path from tick_hash to checkpoint root.
    /// Each entry is (sibling_hash, is_left).
    pub merkle_path: Vec<([u8; 32], bool)>,
    /// The checkpoint that anchors this proof.
    pub checkpoint_tick: u64,
    /// Merkle root at the checkpoint.
    pub checkpoint_root: [u8; 32],
    /// Genesis hash of the clock.
    pub genesis_hash: [u8; 32],
    /// Wall time when this proof was generated.
    pub proof_time_ms: u64,
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

// ── Onion Routing ────────────────────────────────────────────────────

/// A single encrypted layer of an onion-routed payment.
///
/// Each relay hop receives one `OnionLayer`. The relay trial-decrypts
/// using its own DKSAP keys (same scan mechanism as regular payments),
/// then either forwards the inner packet or delivers the payment.
///
/// The sender builds the onion inside-out:
///   1. Wrap the `Payment` in `OnionPayload::Deliver`, encrypt to exit relay
///   2. Wrap exit layer in `OnionPayload::Forward`, encrypt to middle relay
///   3. Wrap middle layer in `OnionPayload::Forward`, encrypt to entry relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    /// DHT key of the *next* hop: a relay node ID, a shard key, or
    /// the final mailbox key. The decrypting relay uses this to route.
    pub next_hop: [u8; 32],
    /// ML-KEM-768 ciphertext encapsulated to this relay's scan_ek.
    pub ct_scan: Vec<u8>,
    /// ML-KEM-768 ciphertext encapsulated to this relay's spend_ek.
    pub ct_spend: Vec<u8>,
    /// View tag for this relay: `Blake3(ss_scan)[0]`.
    pub view_tag: u8,
    /// AEAD nonce (96 bits).
    pub nonce: [u8; 12],
    /// AEAD ciphertext — decrypts to bincode-serialized `OnionPayload`.
    pub ciphertext: Vec<u8>,
}

/// What a relay finds after decrypting its `OnionLayer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnionPayload {
    /// There are more hops — forward the inner layer to `next_hop`.
    Forward {
        /// The next onion layer, encrypted to the following relay.
        inner: Box<OnionLayer>,
    },
    /// This is the final relay — deliver the payment to the DHT shard.
    Deliver {
        /// The actual payment, stealth-encrypted to the recipient.
        payment: Payment,
        /// DHT shard key for mailbox delivery.
        shard_key: [u8; 32],
    },
}

/// Top-level onion-routed payment message.
///
/// The sender sends this to the entry relay. The entry relay decrypts
/// the outer layer, extracts the next hop, and forwards the inner packet.
/// After 3 hops, the exit relay delivers the payment to the DHT shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionRoute {
    /// The outermost onion layer — entry relay decrypts this first.
    pub outer: OnionLayer,
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
/// who owns at least one bill.  Nodes verify this before serving a
/// [`TagLookup`], making mass enumeration economically infeasible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfVessOwnership {
    /// Mint ID of a Vess bill the requester owns.
    pub mint_id: [u8; 32],
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
    /// Tick-lock value carried from the ownership record.
    #[serde(default)]
    pub locked_until_tick: u64,
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

/// Query to a DHT peer for specific data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtQuery {
    /// What kind of data is being queried.
    pub query_kind: DhtQueryKind,
    /// The DHT key being queried (tag_hash, mailbox_key, vess_id, manifest_dht_key).
    pub dht_key: [u8; 32],
    /// Random nonce to match response to request.
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtQueryKind {
    TagLookup,
    MailboxSweep,
    VessLookup,
    ManifestLookup,
}

/// Response from a DHT peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtQueryResponse {
    /// Echoed nonce from the request.
    pub nonce: [u8; 16],
    /// The kind of data being returned.
    pub query_kind: DhtQueryKind,
    /// Found tag records (for TagLookup).
    #[serde(default)]
    pub tags: Vec<Vec<u8>>,
    /// Found stealth payloads (for MailboxSweep).
    #[serde(default)]
    pub payloads: Vec<Vec<u8>>,
    /// Found Vess bills (for VessLookup).
    #[serde(default)]
    pub vess: Vec<Vec<u8>>,
    /// Found manifest blobs (for ManifestLookup).
    #[serde(default)]
    pub manifests: Vec<Vec<u8>>,
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
    /// Optional relay encapsulation key (ML-KEM-768) for onion routing.
    /// Nodes that are willing to relay onion payments include this so
    /// senders can encrypt onion layers to them. This is the node's
    /// mesh identity scan_ek — separate from any wallet stealth address.
    #[serde(default)]
    pub relay_ek: Option<Vec<u8>>,
    /// Known peer contacts (serialized mesh contact bytes) for hydra
    /// bootstrapping. The responder includes up to 20 routable peers
    /// so the challenger can rapidly populate its routing table without
    /// an extra round trip.
    #[serde(default)]
    pub known_peers: Vec<Vec<u8>>,
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

// ── Direct Peer-to-Peer Payment ──────────────────────────────────────

/// Direct payment sent over a direct mesh session between two wallets.
///
/// Bypasses artery relay nodes entirely — the receiver verifies proofs
/// inline and claims ownership locally, broadcasting [`OwnershipClaim`]
/// messages when artery connectivity is available.
///
/// The direct mesh transport provides encryption, so no stealth wrapping is
/// needed.

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
