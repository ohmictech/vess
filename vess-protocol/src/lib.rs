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

use serde::{Deserialize, Serialize};

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
}

// ── Payment ──────────────────────────────────────────────────────────

/// A stealth-encrypted payment from sender to recipient.
///
/// The stealth payload carries all bill data encrypted to the recipient.
/// Relay metadata is intentionally minimal to prevent passive traffic
/// analysis — `mint_ids` and `denomination_values` are **deprecated**
/// (privacy leak) and should be left empty.  Use `bill_count` for
/// relay-side accounting without revealing bill identities.
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
    /// **Deprecated — privacy leak.**  Cleartext bill identifiers allow
    /// relay nodes to track bill movements across transfers.  Leave empty;
    /// relay nodes should use `bill_count` and `payment_id` instead.
    #[serde(default)]
    pub mint_ids: Vec<[u8; 32]>,
    /// **Deprecated — privacy leak.**  Cleartext denomination values
    /// expose exact payment amounts to every relay.  Leave empty.
    #[serde(default)]
    pub denomination_values: Vec<u64>,
    /// Number of bills in this payment (relay-safe metadata).
    ///
    /// Relays use this for lightweight accounting and rate limiting
    /// without learning which specific bills are being transferred.
    #[serde(default)]
    pub bill_count: u8,
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
}

/// Response to a tag lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagLookupResponse {
    /// Blake3 hash of the tag that was queried.
    pub tag_hash: [u8; 32],
    /// The lookup nonce (echoed).
    pub nonce: [u8; 16],
    /// The result — None if tag not found.
    pub result: Option<TagLookupResult>,
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
}

/// Response to a [`MailboxSweep`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxSweepResponse {
    /// Echoed nonce from the request.
    pub nonce: [u8; 16],
    /// All stealth_payloads currently in limbo (opaque AEAD blobs).
    pub payloads: Vec<Vec<u8>>,
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
    /// The sender's endpoint ID bytes (32 bytes).
    pub sender_id: Vec<u8>,
}

/// Response with known peers' endpoint ID bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchangeResponse {
    /// Endpoint ID bytes of known peers (up to 10).
    pub peers: Vec<Vec<u8>>,
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
    /// The requester's endpoint ID bytes (so the responder can add us
    /// to their routing table).
    pub sender_id: Vec<u8>,
}

/// Response to a [`FindNode`] request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindNodeResponse {
    /// Endpoint ID bytes of the K closest peers the responder knows.
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
/// the responder possesses the correct build-time version hash.  The QUIC
/// transport already authenticates the peer's identity (ed25519), so no
/// additional signature is required.
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
    /// Serialised STARK proof bytes (for artery to verify the bill is real).
    pub proof: Vec<u8>,
    /// VM execution digest.
    pub digest: [u8; 32],
    /// Remaining gossip hops (decremented at each relay, stops at 0).
    pub hops_remaining: u8,
    /// Chain depth at genesis is always 0.
    #[serde(default)]
    pub chain_depth: u64,
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
    pub prev_owner_vk: Vec<u8>,
    /// Transfer authorization signature from the previous owner.
    /// Signs `transfer_message(mint_id, stealth_id, timestamp)`.
    pub transfer_sig: Vec<u8>,
    /// Blake3 hash of the NEW owner's ML-DSA-65 verification key.
    pub new_owner_vk_hash: [u8; 32],
    /// Full ML-DSA-65 verification key of the new owner (stored for next transfer).
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

// ── Direct Peer-to-Peer Payment ──────────────────────────────────────

/// Direct payment sent over a QUIC bi-stream between two wallets.
///
/// Bypasses artery relay nodes entirely — the receiver verifies proofs
/// inline and claims ownership locally, broadcasting [`OwnershipClaim`]
/// messages when artery connectivity is available.
///
/// The QUIC transport provides encryption, so no stealth wrapping is
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
/// Returned over the same QUIC bi-stream. If `accepted` is `true`, the
/// receiver has verified the proofs and will broadcast ownership claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectPaymentResponse {
    /// Echoed payment ID.
    pub payment_id: [u8; 32],
    /// Whether the payment was accepted.
    pub accepted: bool,
    /// Human-readable rejection reason (empty if accepted).
    #[serde(default)]
    pub reason: String,
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

    #[test]
    fn payment_round_trip() {
        let msg = PulseMessage::Payment(Payment {
            payment_id: [0xAA; 32],
            stealth_payload: vec![1, 2, 3, 4],
            view_tag: 0x42,
            stealth_id: [0xBB; 32],
            created_at: 1000,
            mint_ids: vec![[0x11; 32]],
            denomination_values: vec![10],
            bill_count: 1,
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
        });
        let bytes = msg.to_bytes().unwrap();
        let decoded = PulseMessage::from_bytes(&bytes).unwrap();
        match decoded {
            PulseMessage::TagLookup(t) => assert_eq!(t.tag_hash, tag_hash),
            _ => panic!("wrong variant"),
        }
    }
}
