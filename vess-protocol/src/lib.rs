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

pub use vess_compute::{
    ComputeJobRequest, ComputeJobResult, ComputeReceipt, ProgramAddress, ProgramDefinition,
    ProgramId, ProgramManifest, ProgramName, ProgramOwnershipCondition,
    ProgramSpendWitness, ProofSystem, StarkProofEnvelope, StoredProgram,
};

/// Bitcoin network identifier used by burn-backed bill genesis proofs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

/// Shared proof for all Vess bills derived from a single Bitcoin burn.
///
/// The burn commits atomically to the first Vess owner and the exact
/// canonical 1-2-5 bill decomposition of the burned satoshi amount.
/// Each resulting bill carries this bundle proof plus its `output_index`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinBurnBundleProof {
    /// Bitcoin network the burn was observed on.
    pub network: BitcoinNetwork,
    /// Transaction ID of the burn transaction.
    pub txid: [u8; 32],
    /// Block hash containing the burn transaction.
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
    /// Number of distinct Bitcoin peers that corroborated the tx/block data
    /// used to assemble this burn proof.
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
    /// Total irreversibly burned amount in satoshis.
    pub burn_amount_sats: u64,
    /// Full ML-DSA-65 verification key of the first Vess owner.
    pub first_owner_vk: Vec<u8>,
    /// Blake3 hash of the first owner's ML-DSA-65 verification key.
    pub first_owner_vk_hash: [u8; 32],
    /// Canonical 1-2-5 bill values for this burn amount.
    pub output_values: Vec<u64>,
    /// 32-byte OP_RETURN payload committing to the first owner, the total
    /// burned sat amount, and the canonical largest-first 1-2-5 denomination
    /// bundle.
    pub burn_commitment_payload: Vec<u8>,
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

    /// Bitcoin burn bundle proof shared across all outputs of one burn.
    BitcoinBurn(BitcoinBurnBundleProof),

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

    /// Store an immutable compute program in the DHT.
    ProgramStore(ProgramStore),

    /// Fetch an immutable compute program by `prog_id`.
    ProgramFetch(ProgramFetch),

    /// Response to a [`ProgramFetch`] request.
    ProgramFetchResponse(ProgramFetchResponse),

    /// Store a mutable compute program manifest / name record in the DHT.
    ProgramManifestStore(ProgramManifestStore),

    /// Resolve a human-facing program name.
    ProgramManifestResolve(ProgramManifestResolve),

    /// Response to a [`ProgramManifestResolve`] request.
    ProgramManifestResolveResponse(ProgramManifestResolveResponse),

    /// Reserved program-execution job request message.
    ComputeJobRequest(ComputeJobRequest),

    /// Reserved response to a [`ComputeJobRequest`] message.
    ComputeJobResult(ComputeJobResult),

    /// Store a compute receipt in the DHT.
    ComputeReceiptStore(ComputeReceiptStore),

    /// Fetch a compute receipt by receipt ID.
    ComputeReceiptFetch(ComputeReceiptFetch),

    /// Response to a [`ComputeReceiptFetch`] request.
    ComputeReceiptFetchResponse(ComputeReceiptFetchResponse),

    /// List receipt IDs tied to one immutable program.
    ProgramReceiptList(ProgramReceiptList),

    /// Response to a [`ProgramReceiptList`] request.
    ProgramReceiptListResponse(ProgramReceiptListResponse),

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

// ── Compute ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramStore {
    pub program: StoredProgram,
    pub hops_remaining: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramFetch {
    pub prog_id: ProgramId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramFetchResponse {
    pub program: Option<StoredProgram>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramManifestStore {
    pub manifest: ProgramManifest,
    pub hops_remaining: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramManifestResolve {
    pub name: ProgramName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramManifestResolveResponse {
    pub manifest: Option<ProgramManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeReceiptStore {
    pub receipt: ComputeReceipt,
    pub hops_remaining: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeReceiptFetch {
    pub receipt_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeReceiptFetchResponse {
    pub receipt: Option<ComputeReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramReceiptList {
    pub prog_id: ProgramId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramReceiptListResponse {
    pub receipt_ids: Vec<[u8; 32]>,
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
    /// Exclusive cursor for paginating immutable compute programs by `prog_id`.
    #[serde(default)]
    pub after_program_id: Option<[u8; 32]>,
    /// Exclusive cursor for paginating program manifests by alias DHT key.
    #[serde(default)]
    pub after_program_manifest_key: Option<[u8; 32]>,
    /// Exclusive cursor for paginating compute receipts by receipt ID.
    #[serde(default)]
    pub after_compute_receipt_id: Option<[u8; 32]>,
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
    /// Maximum immutable compute programs to return.
    #[serde(default)]
    pub max_programs: u16,
    /// Maximum mutable program manifests to return.
    #[serde(default)]
    pub max_program_manifests: u16,
    /// Maximum compute receipts to return.
    #[serde(default)]
    pub max_compute_receipts: u16,
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
    /// Optional program predicate that currently owns the bill.
    #[serde(default)]
    pub current_owner_program: Option<ProgramOwnershipCondition>,
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

/// An immutable program record transferred during seed sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedProgramRecord {
    pub prog_id: ProgramId,
    pub program: StoredProgram,
}

/// A program manifest record transferred during seed sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedProgramManifestRecord {
    pub dht_key: [u8; 32],
    pub manifest: ProgramManifest,
}

/// A compute receipt record transferred during seed sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtSeedComputeReceiptRecord {
    pub receipt_id: [u8; 32],
    pub receipt: ComputeReceipt,
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
    /// Immutable compute programs the requester should store.
    #[serde(default)]
    pub programs: Vec<DhtSeedProgramRecord>,
    /// Program manifests the requester should store.
    #[serde(default)]
    pub program_manifests: Vec<DhtSeedProgramManifestRecord>,
    /// Compute receipts the requester should store.
    #[serde(default)]
    pub compute_receipts: Vec<DhtSeedComputeReceiptRecord>,
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
    /// Optional program predicate that owns the bill from genesis.
    #[serde(default)]
    pub program_owner: Option<ProgramOwnershipCondition>,
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
            program_owner: None,
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
/// the expected new chain tip, and updates the registry. For program-owned
/// bills this is also the main proof-verification path: the claim carries
/// `prev_owner_program` plus an optional `program_spend_witness`, and nodes
/// verify that witness while distributing the claim.
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
    /// Optional program predicate that currently owns the bill.
    #[serde(default)]
    pub prev_owner_program: Option<ProgramOwnershipCondition>,
    /// Transfer authorization signature from the previous owner.
    /// Signs `transfer_message(mint_id, stealth_id, timestamp)`.
    #[serde(default)]
    pub transfer_sig: Vec<u8>,
    /// Blake3 hash of the NEW owner's ML-DSA-65 verification key.
    pub new_owner_vk_hash: [u8; 32],
    /// Full ML-DSA-65 verification key of the new owner (stored for next transfer).
    #[serde(default)]
    pub new_owner_vk: Vec<u8>,
    /// Optional program predicate that becomes the new owner.
    #[serde(default)]
    pub new_owner_program: Option<ProgramOwnershipCondition>,
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
    /// Optional compute receipt witness authorizing a program-owned bill move.
    /// When present, nodes validate it as part of `OwnershipClaim`
    /// distribution before accepting the ownership rotation.
    #[serde(default)]
    pub program_spend_witness: Option<ProgramSpendWitness>,
    /// Argon2id PoW nonce for claim anti-spam.
    #[serde(default)]
    pub pow_nonce: Option<[u8; 32]>,
    /// Argon2id PoW hash.
    #[serde(default)]
    pub pow_hash: Option<[u8; 32]>,
    /// Accumulated propagation work.
    #[serde(default)]
    pub accumulated_work: Option<u64>,
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

/// Blinding factor for privacy-preserving DHT queries.
/// Derived from a shared secret between querier and DHT node.
pub fn blinded_dht_key(base_key: &[u8; 32], blinding: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-dht-query-v1");
    h.update(base_key);
    h.update(blinding);
    *h.finalize().as_bytes()
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

    #[test]
    fn dht_seed_request_round_trip_with_cursors() {
        let msg = PulseMessage::DhtSeedRequest(DhtSeedRequest {
            requester_node_id: [0x11; 32],
            after_tag_hash: Some([0x22; 32]),
            after_manifest_key: Some([0x33; 32]),
            after_ownership_mint_id: Some([0x44; 32]),
            after_consumed_mint_id: Some([0x55; 32]),
            after_program_id: Some([0x66; 32]),
            after_program_manifest_key: Some([0x77; 32]),
            after_compute_receipt_id: Some([0x88; 32]),
            max_tags: 10,
            max_manifests: 11,
            max_ownership_records: 12,
            max_consumed_records: 13,
            max_programs: 14,
            max_program_manifests: 15,
            max_compute_receipts: 16,
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
                assert_eq!(req.after_program_id, Some([0x66; 32]));
                assert_eq!(req.after_program_manifest_key, Some([0x77; 32]));
                assert_eq!(req.after_compute_receipt_id, Some([0x88; 32]));
                assert_eq!(req.max_tags, 10);
                assert_eq!(req.max_manifests, 11);
                assert_eq!(req.max_ownership_records, 12);
                assert_eq!(req.max_consumed_records, 13);
                assert_eq!(req.max_programs, 14);
                assert_eq!(req.max_program_manifests, 15);
                assert_eq!(req.max_compute_receipts, 16);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn program_fetch_round_trip() {
        let msg = PulseMessage::ProgramFetch(ProgramFetch {
            prog_id: ProgramId([0x42; 32]),
        });
        let bytes = msg.to_bytes().unwrap();
        let decoded = PulseMessage::from_bytes(&bytes).unwrap();
        match decoded {
            PulseMessage::ProgramFetch(req) => {
                assert_eq!(req.prog_id, ProgramId([0x42; 32]));
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
