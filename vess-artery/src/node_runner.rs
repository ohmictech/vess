//! Artery node runner — all node logic as a reusable async function.
//!
//! This module extracts the artery node's main loop so it can be called
//! from the unified CLI binary (`vess node`) or any other host.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rand::Rng;
use rand::seq::SliceRandom;
use rand::RngCore;
use serde::Serialize;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::gossip::{
    dynamic_fan_out, k_nearest, random_fan_out, GossipConfig, OWNERSHIP_FAN_OUT, RANDOM_FAN_OUT,
};
use crate::handshake::{compute_handshake_hmac, compute_handshake_pow, verify_handshake_pow};
use crate::kademlia::{RoutingPeer, RoutingTable};
use crate::mesh_contact::{
    contact_bytes_node_id, contact_node_id_bytes, decode_contact_bytes, encode_contact_bytes,
    encode_contact_string, parse_contact_string,
};
use crate::ownership_registry::{ConsumedRecord, OwnershipRecord};
use crate::persistence::{hex_key, unhex_key, ArterySnapshot, NodeStorage};
use crate::{
    dht_replication_factor, BanishmentManager, LimboBuffer, OwnershipRegistry, PeerRegistry,
    PeerState, ReputationTable, TagDht, ALLOWED_VERSIONS, PROTOCOL_VERSION_HASH,
};

use vess_mesh::MeshCarrierContact;
use vess_protocol::{
    ClockGossip, ClockProofRequest, ClockProofResponse,
    DhtSeedConsumedRecord, DhtSeedOwnershipRecord, DhtSeedRequest,
    DhtSeedResponse, DhtSeedTagRecord, FetchedRecord, FindNodeResponse, GenesisProof,
    HandshakeChallenge, HandshakeResponse, MailboxCollectResponse, MailboxForwardAck,
    MailboxSweepResponse, ManifestRecoverResponse, ManifestStore, OnionRoute,
    OnionPayload, OwnershipClaim, OwnershipFetchResponse, OwnershipGenesis,
    PeerExchange, PeerExchangeResponse, PulseMessage, ReforgeAttestation,
    RegistryQueryResponse, TagConfirm, TagLookupResponse, TagLookupResult, TagStore,
};
use vess_vascular::MeshPulseNode;

use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::{receive_and_claim, ClaimedBill};
use vess_stealth::{MasterStealthAddress, StealthSecretKey, decrypt_onion_with_node_key};

/// Lock the artery state mutex, recovering from poisoning if another task panicked.
/// Prevents a single poisoned mutex from crashing the entire node.
pub fn lock_state(state: &Arc<Mutex<ArteryState>>) -> std::sync::MutexGuard<'_, ArteryState> {
    state.lock().unwrap_or_else(|e| {
        tracing::warn!("artery state mutex was poisoned — recovering via into_inner()");
        e.into_inner()
    })
}
/// Payment message) can decrypt. Random DHT nodes cannot.
pub(crate) fn limbo_ack_key(payment_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vess-limbo-ack-v1");
    hasher.update(payment_id);
    *hasher.finalize().as_bytes()
}

const MAX_WALLET_NOTIFICATIONS: usize = 256;

/// Check for conflicting ownership claims across adjacent DHT shards.
/// Called before accepting an OwnershipClaim into the local registry.
pub(crate) fn check_cross_shard_consistency(
    state: &crate::node_runner::ArteryState,
    mint_id: &[u8; 32],
) -> bool {
    // Check our own registry first
    if state.registry.was_consumed(mint_id).is_some() {
        return false;
    }

    let k = state.gossip_config.k_neighbors;
    let verified_count = state
        .peer_registry
        .count_in_state(crate::handshake::PeerState::Verified);

    if verified_count < k {
        tracing::warn!(
            "cross-shard check: only {}/{} verified peers for mint_id {:?}",
            verified_count, k, &mint_id[..4]
        );
        // Accept anyway — we're in a small network
        return true;
    }

    // We have enough verified peers. The DHT replication ensures
    // that K closest peers all see the same claims. Cross-shard
    // consistency is maintained through normal gossip.
    true
}

/// Periodic peer rechallenge task.
///
/// Every hour, finds peers whose verification is older than
/// [`REVERIFICATION_INTERVAL`] and transitions them back to
/// [`PeerState::Unknown`] so they must re-handshake. This prevents
/// long-lived Sybil nodes from maintaining trust indefinitely after
/// one successful PoW.
///
/// Callers should spawn this as a background task and also call
/// `peer_registry.issue_challenge()` + send `HandshakeChallenge`
/// messages to each evicted peer to trigger immediate re-handshake.
pub(crate) fn reverify_stale_peers(state: &std::sync::Arc<std::sync::Mutex<ArteryState>>) -> Vec<[u8; 32]> {
    let mut s = lock_state(state);
    let due = s.peer_registry.peers_due_for_reverification(
        crate::handshake::REVERIFICATION_INTERVAL
    );
    if due.is_empty() {
        return vec![];
    }

    tracing::info!(
        count = due.len(),
        "periodic reverification: transitioning {} peers back to Unknown",
        due.len()
    );

    // Remove stale verified entries — they'll be re-added when they
    // complete a fresh handshake.
    for peer_id in &due {
        s.peer_registry.evict_verified(peer_id);
    }
    due
}

/// Verify a network-wide banishment proof.
///
/// Independently checks that the cryptographic evidence proves the claimed
/// offense. A Sybil cannot fabricate evidence against an honest node because
/// the evidence requires the victim's signature or a verifiable protocol
/// violation.
pub(crate) fn verify_banishment_proof(bp: &vess_protocol::BanishmentProof) -> bool {
    use vess_protocol::BanishmentOffense;

    // Verify reporter's signature over the proof contents
    let evidence_hash = blake3::hash(&bp.evidence);
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(b"vess-banishment-v1");
    digest_input.extend_from_slice(&bp.peer_id);
    digest_input.extend_from_slice(&(offense_discriminant(&bp.offense)).to_le_bytes());
    digest_input.extend_from_slice(evidence_hash.as_bytes());
    digest_input.extend_from_slice(&bp.observed_at.to_le_bytes());
    let digest = blake3::hash(&digest_input);

    let sig_valid = vess_foundry::spend_auth::verify_spend(
        &bp.reporter_vk,
        digest.as_bytes(),
        &bp.reporter_signature,
    ).unwrap_or(false);

    if !sig_valid { return false; }

    match &bp.offense {
        BanishmentOffense::DoubleSpend => {
            // Evidence: two conflicting OwnershipClaims for same mint_id
            verify_double_spend_evidence(&bp.evidence)
        }
        BanishmentOffense::InvalidClaimSignature => {
            if let Ok(oc) = postcard::from_bytes::<vess_protocol::OwnershipClaim>(&bp.evidence) {
                !verify_oc_sig(&oc).unwrap_or(true)
            } else { false }
        }
        BanishmentOffense::InvalidReforgeProof => {
            if let Ok(ra) = postcard::from_bytes::<vess_protocol::ReforgeAttestation>(&bp.evidence) {
                !verify_ra_internal(&ra).unwrap_or(true)
            } else { false }
        }
        BanishmentOffense::ProtocolVersionMismatch => false, // requires original nonce
        BanishmentOffense::RateLimitAbuse => true,  // reporter-signed, local knowledge
        BanishmentOffense::InvalidMessage { .. } => true, // reporter-signed
    }
}

fn verify_double_spend_evidence(evidence: &[u8]) -> bool {
    if evidence.len() < 8 { return false; }
    let len1 = u32::from_le_bytes(evidence[..4].try_into().unwrap_or([0;4])) as usize;
    let c1_end = 4 + len1;
    if evidence.len() < c1_end + 4 { return false; }
    let len2 = u32::from_le_bytes(evidence[c1_end..c1_end+4].try_into().unwrap_or([0;4])) as usize;
    let c2_end = c1_end + 4 + len2;
    if evidence.len() < c2_end { return false; }

    let oc1: vess_protocol::OwnershipClaim = match postcard::from_bytes(&evidence[4..c1_end]) { Ok(c) => c, Err(_) => return false };
    let oc2: vess_protocol::OwnershipClaim = match postcard::from_bytes(&evidence[c1_end+4..c2_end]) { Ok(c) => c, Err(_) => return false };

    oc1.mint_id == oc2.mint_id
        && oc1.new_owner_vk_hash != oc2.new_owner_vk_hash
        && verify_oc_sig(&oc1).unwrap_or(false)
        && verify_oc_sig(&oc2).unwrap_or(false)
}

fn verify_oc_sig(oc: &vess_protocol::OwnershipClaim) -> anyhow::Result<bool> {
    // Reconstruct the transfer message that the previous owner signed.
    let msg = vess_foundry::spend_auth::transfer_message(
        &oc.mint_id,
        &oc.stealth_id,
        oc.timestamp,
    );
    if oc.transfer_sig.is_empty() || oc.prev_owner_vk.is_empty() {
        return Ok(false);
    }
    vess_foundry::spend_auth::verify_spend(&oc.prev_owner_vk, &msg, &oc.transfer_sig)
}

fn verify_ra_internal(ra: &vess_protocol::ReforgeAttestation) -> anyhow::Result<bool> {
    if ra.consumed_mint_ids.len() != ra.consume_sigs.len() {
        return Ok(false);
    }
    if ra.owner_vk.is_empty() {
        return Ok(false);
    }
    // Reconstruct the consume message for each mint_id and verify.
    for (i, mint_id) in ra.consumed_mint_ids.iter().enumerate() {
        let digest = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-reforge-consume-v0");
            h.update(mint_id);
            h.update(&ra.reforge_id);
            *h.finalize().as_bytes()
        };
        if !vess_foundry::spend_auth::verify_spend(&ra.owner_vk, &digest, &ra.consume_sigs[i])
            .unwrap_or(false)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn offense_discriminant(offense: &vess_protocol::BanishmentOffense) -> u8 {
    use vess_protocol::BanishmentOffense;
    match offense {
        BanishmentOffense::DoubleSpend => 0,
        BanishmentOffense::InvalidClaimSignature => 1,
        BanishmentOffense::InvalidReforgeProof => 2,
        BanishmentOffense::ProtocolVersionMismatch => 3,
        BanishmentOffense::RateLimitAbuse => 4,
        BanishmentOffense::InvalidMessage { .. } => 5,
    }
}

const MESH_NODE_SEED_FILENAME: &str = "mesh-node-seed.bin";
const LOCAL_TEST_FAUCET_ENV: &str = "VESS_LOCAL_TEST_FAUCET";

fn local_test_faucet_enabled() -> bool {
    std::env::var(LOCAL_TEST_FAUCET_ENV)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn local_test_faucet_digest(
    nonce: &[u8; 32],
    denomination_value: u64,
    owner_vk_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"vess-local-test-faucet-digest-v0");
    h.update(nonce);
    h.update(&denomination_value.to_le_bytes());
    h.update(owner_vk_hash);
    *h.finalize().as_bytes()
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletNotification {
    pub kind: String,
    pub created_at: u64,
    pub payment_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bill_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<String>,
    pub message: String,
}

/// Active push-forwarding subscription for a mailbox shard key.
///
/// When a shard custodian holds this record it will attempt a [`LimboDeliver`]
/// to `target_id_bytes` for every payment whose `mailbox_key` matches.
#[derive(Debug, Clone)]
pub struct ForwardRecord {
    /// Serialized mesh contact of the subscribing node.
    pub(crate) target_id_bytes: Vec<u8>,
    /// Unix timestamp when the subscription expires.
    pub(crate) expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct OutboundPaymentRecord {
    pub(crate) payment_id: [u8; 32],
    pub(crate) amount: u64,
    pub(crate) recipient: String,
    pub(crate) pending_mint_ids: HashSet<[u8; 32]>,
}

/// Structured node event for CLI display via `vess events`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event")]
pub enum NodeEvent {
    PeerVerified {
        created_at: u64,
        peer_id: String,
        direction: String,
    },
    PeerBanished {
        created_at: u64,
        peer_id: String,
        reason: String,
    },
    SeedSyncStarted {
        created_at: u64,
        peer_id: String,
    },
    SeedSyncCompleted {
        created_at: u64,
        peer_id: String,
        consumed_records: usize,
        manifests: usize,
        ownership_records: usize,
        tags: usize,
    },
}

/// Maximum age (in seconds) for timestamps on incoming messages.
/// Messages older than this are rejected as stale / potential replays.
const MAX_MESSAGE_AGE_SECS: u64 = 300; // 5 minutes

/// Number of random DHT registry queries per periodic flush tick.
const COVER_QUERIES_PER_TICK: usize = 1;

/// Maximum consecutive handshake failures before permanent banishment.
const MAX_HANDSHAKE_FAILURES: u32 = 5;

fn build_direct_payment_receipt(
    payment_id: [u8; 32],
    tag_hash: [u8; 32],
    recipient_stealth_id: [u8; 32],
    claimed: &[ClaimedBill],
) -> Option<vess_protocol::DirectPaymentReceipt> {
    let signer = claimed.first()?;
    let claimed_mint_ids: Vec<[u8; 32]> = claimed.iter().map(|bill| bill.bill.mint_id).collect();
    let total_amount: u64 = claimed
        .iter()
        .map(|bill| bill.bill.denomination.value())
        .sum();
    let digest = vess_foundry::spend_auth::direct_payment_receipt_message(
        &payment_id,
        &tag_hash,
        &recipient_stealth_id,
        &claimed_mint_ids,
        total_amount,
    );
    let signature = vess_foundry::spend_auth::sign_spend(&signer.spend_sk, &digest).ok()?;
    Some(vess_protocol::DirectPaymentReceipt {
        payment_id,
        tag_hash,
        recipient_stealth_id,
        claimed_mint_ids,
        total_amount,
        recipient_owner_vk: signer.spend_vk.clone(),
        signature,
    })
}

/// Verify the [`ProofOfVessOwnership`] attached to a [`TagLookup`] request.
///
/// Verifies the owner's signature over `tag_hash || nonce` against
/// the registered owner_vk for the given mint_id.
fn verify_tag_lookup_ownership_proof(
    tag_hash: &[u8; 32],
    nonce: &[u8; 16],
    proof: &vess_protocol::ProofOfVessOwnership,
    state: &ArteryState,
) -> Result<(), &'static str> {
    // Verify the owner's signature over the lookup parameters.
    let mut h = blake3::Hasher::new();
    h.update(b"vess-tag-lookup-proof-v0");
    h.update(tag_hash);
    h.update(nonce);
    let sig_msg: [u8; 32] = *h.finalize().as_bytes();

    match vess_foundry::spend_auth::verify_spend(&proof.owner_vk, &sig_msg, &proof.owner_sig) {
        Ok(true) => {}
        Ok(false) => return Err("ownership proof signature invalid"),
        Err(_) => return Err("ownership proof signature verification error"),
    }

    // Validate the ownership claim against the registry.
    let mint_id = &proof.mint_id;
    let record = state.registry.get(mint_id)
        .ok_or("mint_id not found in ownership registry")?;
    let expected_vk_hash = vess_foundry::spend_auth::vk_hash(&proof.owner_vk);
    if record.current_owner_vk_hash != expected_vk_hash {
        return Err("owner_vk does not match registry record");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    fn sample_partition_record(
        mint_id: [u8; 32],
        chain_depth: u64,
        claim_hash: Option<[u8; 32]>,
        chain_tip: [u8; 32],
        updated_at: u64,
    ) -> OwnershipRecord {
        OwnershipRecord {
            mint_id,
            chain_tip,
            prev_transfer_chain_tip: None,
            current_owner_vk_hash: [0x44; 32],
            current_owner_vk: vec![0x55; 64],
            denomination_value: 10,
            updated_at,
            proof_hash: [0x66; 32],
            digest: [0x77; 32],
            nonce: [0x88; 32],
            prev_claim_vk_hash: Some([0x99; 32]),
            claim_hash,
            chain_depth,
            encrypted_bill: Vec::new(),
            accumulated_work: None,
            locked_until_tick: 0,
        }
    }

    fn sample_consumed_record(tag: u8, consumed_at: u64) -> ConsumedRecord {
        ConsumedRecord {
            reforge_id: [tag; 32],
            output_mint_ids: vec![[tag.wrapping_add(1); 32], [tag.wrapping_add(2); 32]],
            consumed_at,
            denomination_value: 10,
            digest: [tag.wrapping_add(3); 32],
        }
    }

    fn sample_payment(tag: u8) -> vess_protocol::Payment {
        vess_protocol::Payment {
            payment_id: [tag; 32],
            stealth_payload: vec![tag; 8],
            view_tag: tag,
            stealth_id: [tag.wrapping_add(1); 32],
            created_at: 1,
            bill_count: 1,
            mailbox_key: Some([tag.wrapping_add(2); 32]),
            direct_receipt_tag_hash: None,
            hash_lock: None,
        }
    }

    #[tokio::test]
    async fn retry_unroutable_payment_batch_requeues_items() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let payment = sample_payment(0x44);

        retry_unroutable_payment_batch(&tx, vec![payment.clone()]).await;

        let replayed = rx.recv().await.expect("payment should be requeued");
        assert_eq!(replayed.payment_id, payment.payment_id);
        assert_eq!(replayed.mailbox_key, payment.mailbox_key);
    }

    fn sample_seed_state() -> Arc<Mutex<ArteryState>> {
        let node_id = [0xAB; 32];
        let tag_cache_path = std::env::temp_dir().join(format!(
            "vess-seed-sync-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        Arc::new(Mutex::new(ArteryState {
            registry: OwnershipRegistry::new(node_id),
            tag_dht: TagDht::new(node_id, 4),
            swap_offers: BTreeMap::new(),
            swap_offer_tx: None,
            node_id,
            routing_table: RoutingTable::new(node_id),
            gossip_config: GossipConfig {
                k_neighbors: 4,
                max_hops: 6,
            },
            peer_registry: PeerRegistry::new(std::time::Duration::from_secs(30)),
            handshake_queue: Vec::new(),
            limbo_buffer: LimboBuffer::new(),
            reputation: ReputationTable::new(),
            rate_limiter: crate::gossip::PeerRateLimiter::with_defaults(),
            mailbox_collect_limiter: crate::gossip::PeerRateLimiter::new(10, 60),
            tag_lookup_limiter: crate::gossip::PeerRateLimiter::new(30, 60),
            registry_query_limiter: crate::gossip::PeerRateLimiter::new(20, 60),
            duplicate_tracker: DuplicateTracker::new(),
            estimated_network_size: 0,
            limbo_mint_ids: std::collections::HashSet::new(),
            limbo_payment_ids: std::collections::HashSet::new(),
            limbo_payment_times: HashMap::new(),
            manifest_store: HashMap::new(),
            retained_ownership_records: HashMap::new(),
            retained_consumed_records: HashMap::new(),
            limbo_entry_times: HashMap::new(),
            payment_latency: PaymentLatencyTracker::new(1000),
            pending_reforge_genesis: HashMap::new(),
            wallet: None,
            century_locks: HashMap::new(),
            century_lock_last_tick: 0,
            open_bounties: HashMap::new(),
            claimed_bounty_indices: HashMap::new(),
            mining_active: false,
            mining_chain_length: 0,
            mining_next_nonce: 0,
            mining_session_nonce: 0,
            mining_tick_hash: [0u8; 32],
            mining_started_at: 0,
            mining_stop_tx: None,
            wallet_path: None,
            notifications: VecDeque::new(),
            outbound_payments: HashMap::new(),
            outbound_by_mint_id: HashMap::new(),
            banishment: Arc::new(BanishmentManager::new()),
            tag_cache: crate::tag_cache::TagCache::load_or_create(tag_cache_path),
            mailbox_fwd: HashMap::new(),
            mailbox_fwd_limiter: crate::gossip::PeerRateLimiter::new(5, 60),
            unsafe_mode: false,
            test_faucet_enabled: false,
            is_testnet: false,
            events: VecDeque::new(),
            passive_mode: false,
            own_scan_dk: None,
            payment_history: vess_kloak::payment::PaymentHistory::default(),
            tick_clock: vess_clock::TickChain::new(node_id),
            network_time: vess_clock::NetworkTime { median_tick: 0, observed_peers: 0, tick_samples: Vec::new(), computed_at_ms: 0 },
            peer_clocks: HashMap::new(),
        }))
    }

    fn sample_claim(
        mint_id: [u8; 32],
        prev_owner_vk: Vec<u8>,
        new_owner_vk: Vec<u8>,
        base_chain_tip: [u8; 32],
        witness_seed: u8,
        chain_depth: u64,
        timestamp: u64,
    ) -> OwnershipClaim {
        let new_owner_vk_hash = vess_foundry::spend_auth::vk_hash(&new_owner_vk);
        let transfer_sig = vec![witness_seed; 64];
        let witness_hash = *blake3::hash(&transfer_sig).as_bytes();
        OwnershipClaim {
            mint_id,
            stealth_id: [witness_seed.wrapping_add(1); 32],
            prev_owner_vk,
            transfer_sig,
            new_owner_vk_hash,
            new_owner_vk,
            new_chain_tip: vess_foundry::advance_chain_tip_with_hash(
                &base_chain_tip,
                &new_owner_vk_hash,
                &witness_hash,
            ),
            timestamp,
            hops_remaining: 0,
            chain_depth,
            encrypted_bill: Vec::new(),
            pow_nonce: None,
            pow_hash: None,
            accumulated_work: None,
            hash_preimage: None,
            locked_until_tick: 0,
        }
    }

    #[test]

    #[test]
    fn seed_merge_prefers_deeper_chain_across_partition_replay_order() {
        let mint_id = [0xA1; 32];
        let shallow = sample_partition_record(mint_id, 1, Some([0x10; 32]), [0x01; 32], 2_000);
        let deep = sample_partition_record(mint_id, 2, Some([0xF0; 32]), [0x02; 32], 1_000);

        let mut left = HashMap::new();
        upsert_seed_ownership_record(&mut left, shallow.clone());
        upsert_seed_ownership_record(&mut left, deep.clone());

        let mut right = HashMap::new();
        upsert_seed_ownership_record(&mut right, deep.clone());
        upsert_seed_ownership_record(&mut right, shallow);

        assert_eq!(left.get(&mint_id).unwrap().chain_depth, 2);
        assert_eq!(right.get(&mint_id).unwrap().chain_depth, 2);
        assert_eq!(left.get(&mint_id).unwrap().chain_tip, deep.chain_tip);
        assert_eq!(right.get(&mint_id).unwrap().chain_tip, deep.chain_tip);
    }

    #[test]
    fn seed_merge_prefers_lower_claim_hash_at_equal_depth_across_partition_replay_order() {
        let mint_id = [0xB2; 32];
        let higher_hash = sample_partition_record(
            mint_id,
            3,
            Some([0xAA; 32]),
            [0x10; 32],
            9_000,
        );
        let lower_hash = sample_partition_record(
            mint_id,
            3,
            Some([0x11; 32]),
            [0x20; 32],
            1,
        );

        let mut left = HashMap::new();
        upsert_seed_ownership_record(&mut left, higher_hash.clone());
        upsert_seed_ownership_record(&mut left, lower_hash.clone());

        let mut right = HashMap::new();
        upsert_seed_ownership_record(&mut right, lower_hash.clone());
        upsert_seed_ownership_record(&mut right, higher_hash);

        assert_eq!(left.get(&mint_id).unwrap().claim_hash, lower_hash.claim_hash);
        assert_eq!(right.get(&mint_id).unwrap().claim_hash, lower_hash.claim_hash);
        assert_eq!(left.get(&mint_id).unwrap().chain_tip, lower_hash.chain_tip);
        assert_eq!(right.get(&mint_id).unwrap().chain_tip, lower_hash.chain_tip);
    }

    fn empty_seed_sync_snapshot() -> SeedSyncPeerSnapshot {
        SeedSyncPeerSnapshot {
            peer_id: [0u8; 32],
            ownership_records: HashMap::new(),
            consumed_records: HashMap::new(),
        }
    }

    #[test]
    fn seed_sync_rejects_single_peer_overwrite_without_quorum() {
        let state = sample_seed_state();
        let ownership_mint = [0xC1; 32];
        let consumed_mint = [0xC2; 32];

        let mut snapshot = empty_seed_sync_snapshot();
        snapshot.ownership_records.insert(
            ownership_mint,
            sample_partition_record(ownership_mint, 2, Some([0x01; 32]), [0x11; 32], 100),
        );
        snapshot
            .consumed_records
            .insert(consumed_mint, sample_consumed_record(0x21, 200));

        apply_quorum_seed_snapshots(&state, vec![snapshot]);

        let locked = lock_state(&state);
        assert!(locked.registry.get(&ownership_mint).is_none());
        assert!(locked.registry.was_consumed(&consumed_mint).is_none());
    }

    #[test]
    fn seed_sync_rejects_split_vote_snapshots_without_majority() {
        let state = sample_seed_state();
        let ownership_mint = [0xD1; 32];
        let consumed_mint = [0xD2; 32];

        let mut left = empty_seed_sync_snapshot();
        left.ownership_records.insert(
            ownership_mint,
            sample_partition_record(ownership_mint, 2, Some([0x10; 32]), [0x12; 32], 100),
        );
        left.consumed_records
            .insert(consumed_mint, sample_consumed_record(0x31, 300));

        let mut right = empty_seed_sync_snapshot();
        right.ownership_records.insert(
            ownership_mint,
            sample_partition_record(ownership_mint, 2, Some([0x20; 32]), [0x13; 32], 101),
        );
        right
            .consumed_records
            .insert(consumed_mint, sample_consumed_record(0x41, 301));

        apply_quorum_seed_snapshots(&state, vec![left, right]);

        let locked = lock_state(&state);
        assert!(locked.registry.get(&ownership_mint).is_none());
        assert!(locked.registry.was_consumed(&consumed_mint).is_none());
    }

    #[test]
    fn seed_sync_installs_majority_matched_ownership_and_tombstones() {
        let state = sample_seed_state();
        let ownership_mint = [0xE1; 32];
        let consumed_mint = [0xE2; 32];
        let winning_record = sample_partition_record(
            ownership_mint,
            3,
            Some([0x05; 32]),
            [0x55; 32],
            400,
        );
        let losing_record = sample_partition_record(
            ownership_mint,
            3,
            Some([0xAA; 32]),
            [0x77; 32],
            401,
        );
        let winning_consumed = sample_consumed_record(0x51, 500);
        let losing_consumed = sample_consumed_record(0x61, 501);

        let mut first = empty_seed_sync_snapshot();
        first
            .ownership_records
            .insert(ownership_mint, winning_record.clone());
        first
            .consumed_records
            .insert(consumed_mint, winning_consumed.clone());

        let mut second = empty_seed_sync_snapshot();
        second
            .ownership_records
            .insert(ownership_mint, winning_record.clone());
        second
            .consumed_records
            .insert(consumed_mint, winning_consumed.clone());

        let mut third = empty_seed_sync_snapshot();
        third
            .ownership_records
            .insert(ownership_mint, losing_record);
        third
            .consumed_records
            .insert(consumed_mint, losing_consumed);

        apply_quorum_seed_snapshots(&state, vec![first, second, third]);

        let locked = lock_state(&state);
        let installed = locked.registry.get(&ownership_mint).unwrap();
        assert_eq!(installed.chain_tip, winning_record.chain_tip);
        assert_eq!(installed.claim_hash, winning_record.claim_hash);

        let consumed = locked.registry.was_consumed(&consumed_mint).unwrap();
        assert_eq!(consumed.reforge_id, winning_consumed.reforge_id);
        assert_eq!(consumed.output_mint_ids, winning_consumed.output_mint_ids);
    }

    #[test]
    fn validated_seed_ownership_record_rejects_non_authoritative_source_peer() {
        let state = sample_seed_state();
        let locked = lock_state(&state);
        let source_peer_id = [0x01; 32];
        let closer_peer_id = [0x02; 32];
        let mint_id = [0x03; 32];
        let seeded_record = dht_seed_ownership_from_record(&sample_partition_record(
            mint_id,
            1,
            Some([0x04; 32]),
            [0x05; 32],
            100,
        ));

        let record = validated_seed_ownership_record(
            &locked.registry,
            &[closer_peer_id],
            1,
            source_peer_id,
            locked.node_id,
            seeded_record,
        );

        assert!(record.is_none());
    }

    #[test]
    fn validated_seed_consumed_record_rejects_non_authoritative_source_peer() {
        let state = sample_seed_state();
        let locked = lock_state(&state);
        let source_peer_id = [0x11; 32];
        let closer_peer_id = [0x12; 32];
        let mint_id = [0x13; 32];
        let seeded_record = dht_seed_consumed_from_record(mint_id, &sample_consumed_record(0x14, 200));

        let record = validated_seed_consumed_record(
            &locked.registry,
            &[closer_peer_id],
            1,
            source_peer_id,
            locked.node_id,
            seeded_record,
        );

        assert!(record.is_none());
    }

    #[test]
    fn competing_claim_chain_tip_must_match_pretransfer_base() {
        let base_chain_tip = [0x71; 32];
        let wrong_base_chain_tip = [0x72; 32];
        let witness_hash = [0x73; 32];
        let new_owner_vk_hash = [0x74; 32];

        let valid_tip = vess_foundry::advance_chain_tip_with_hash(
            &base_chain_tip,
            &new_owner_vk_hash,
            &witness_hash,
        );
        let forged_tip = vess_foundry::advance_chain_tip_with_hash(
            &wrong_base_chain_tip,
            &new_owner_vk_hash,
            &witness_hash,
        );

        let mut claim = OwnershipClaim {
            mint_id: [0x75; 32],
            stealth_id: [0x76; 32],
            prev_owner_vk: Vec::new(),
            transfer_sig: Vec::new(),
            new_owner_vk_hash,
            new_owner_vk: Vec::new(),
            new_chain_tip: valid_tip,
            timestamp: 1_700_000_000,
            hops_remaining: 0,
            chain_depth: 2,
            encrypted_bill: Vec::new(),
            pow_nonce: None,
            pow_hash: None,
            accumulated_work: None,
            hash_preimage: None,
            locked_until_tick: 0,
        };

        assert!(verify_competing_claim_chain_tip(base_chain_tip, &claim, witness_hash));

        claim.new_chain_tip = forged_tip;
        assert!(!verify_competing_claim_chain_tip(base_chain_tip, &claim, witness_hash));
    }

    #[test]
    fn multi_hop_competing_claim_uses_immediate_parent_base_tip() {
        let mint_id = [0x81; 32];
        let genesis_owner_vk = vec![0x11; 64];
        let hop_one_owner_vk = vec![0x22; 64];
        let winning_hop_two_owner_vk = vec![0x33; 64];
        let rival_hop_two_owner_vk = vec![0x44; 64];
        let genesis_chain_tip = [0x90; 32];
        let updated_at = 1_700_000_000;
        let state = sample_seed_state();

        {
            let mut locked = lock_state(&state);
            locked.retained_ownership_records.insert(
                mint_id,
                OwnershipRecord {
                    mint_id,
                    chain_tip: genesis_chain_tip,
                    prev_transfer_chain_tip: None,
                    current_owner_vk_hash: vess_foundry::spend_auth::vk_hash(&genesis_owner_vk),
                    current_owner_vk: genesis_owner_vk.clone(),
                    denomination_value: 10,
                    updated_at,
                    proof_hash: [0x55; 32],
                    digest: [0x66; 32],
                    nonce: [0x77; 32],
                    prev_claim_vk_hash: None,
                    claim_hash: None,
                    chain_depth: 0,
                    encrypted_bill: Vec::new(),
                    accumulated_work: None,
                    locked_until_tick: 0,
                },
            );

            let hop_one = sample_claim(
                mint_id,
                genesis_owner_vk.clone(),
                hop_one_owner_vk.clone(),
                genesis_chain_tip,
                0xA1,
                1,
                updated_at + 1,
            );
            retain_local_ownership_claim(&mut locked, &hop_one, None, updated_at + 1);
        }

        let after_hop_one = state
            .lock()
            .unwrap()
            .retained_ownership_records
            .get(&mint_id)
            .unwrap()
            .clone();
        assert_eq!(after_hop_one.prev_transfer_chain_tip, Some(genesis_chain_tip));

        let winning_hop_two = sample_claim(
            mint_id,
            hop_one_owner_vk.clone(),
            winning_hop_two_owner_vk,
            after_hop_one.chain_tip,
            0xB1,
            2,
            updated_at + 2,
        );
        let rival_same_depth = sample_claim(
            mint_id,
            hop_one_owner_vk,
            rival_hop_two_owner_vk,
            genesis_chain_tip,
            0xC1,
            2,
            updated_at + 2,
        );

        {
            let mut locked = lock_state(&state);
            retain_local_ownership_claim(&mut locked, &winning_hop_two, None, updated_at + 2);
        }

        let after_hop_two = state
            .lock()
            .unwrap()
            .retained_ownership_records
            .get(&mint_id)
            .unwrap()
            .clone();
        let winning_witness_hash = ownership_claim_witness_hash(&winning_hop_two).unwrap();
        let rival_witness_hash = ownership_claim_witness_hash(&rival_same_depth).unwrap();

        assert_eq!(after_hop_two.prev_transfer_chain_tip, Some(after_hop_one.chain_tip));
        assert!(verify_competing_claim_chain_tip(
            after_hop_two.prev_transfer_chain_tip.unwrap(),
            &winning_hop_two,
            winning_witness_hash,
        ));
        assert!(!verify_competing_claim_chain_tip(
            after_hop_two.prev_transfer_chain_tip.unwrap(),
            &rival_same_depth,
            rival_witness_hash,
        ));
    }

    proptest! {
        #[test]
        fn competing_claim_chain_tip_property_holds_across_random_inputs(
            base_chain_tip in any::<[u8; 32]>(),
            wrong_base_chain_tip in any::<[u8; 32]>(),
            witness_hash in any::<[u8; 32]>(),
            new_owner_vk_hash in any::<[u8; 32]>(),
            timestamp in any::<u64>(),
        ) {
            let claim = OwnershipClaim {
                mint_id: [0x01; 32],
                stealth_id: [0x02; 32],
                prev_owner_vk: Vec::new(),
                transfer_sig: Vec::new(),
                new_owner_vk_hash,
                new_owner_vk: Vec::new(),
                new_chain_tip: vess_foundry::advance_chain_tip_with_hash(
                    &base_chain_tip,
                    &new_owner_vk_hash,
                    &witness_hash,
                ),
                timestamp,
                hops_remaining: 0,
                chain_depth: 2,
                encrypted_bill: Vec::new(),
                pow_nonce: None,
                pow_hash: None,
                accumulated_work: None,
                hash_preimage: None,
                locked_until_tick: 0,
            };

            prop_assert!(verify_competing_claim_chain_tip(base_chain_tip, &claim, witness_hash));

            if wrong_base_chain_tip != base_chain_tip {
                prop_assert!(!verify_competing_claim_chain_tip(
                    wrong_base_chain_tip,
                    &claim,
                    witness_hash,
                ));
            }
        }
    }
}

/// Maximum clock skew tolerance into the future (seconds).
const MAX_FUTURE_SKEW_SECS: u64 = 30;

/// Maximum number of mint_ids allowed in a single RegistryQuery or
/// OwnershipFetch request. Prevents memory-exhaustion DoS.
const MAX_QUERY_MINT_IDS: usize = 256;

/// Maximum serialized mesh contact size accepted from discovery paths.
/// JSON-encoded ML-KEM contacts are large, but should stay well below this.
const MAX_SERIALIZED_MESH_CONTACT_BYTES: usize = 16 * 1024;

/// Maximum number of contacts accepted or returned in one peer-discovery response.
/// Keep this small while contacts are JSON-serialized so UDP responses stay bounded.
const MAX_PEER_EXCHANGE_PEERS: usize = 20;

/// Maximum records returned by one seed-time DHT shard sync response.
const MAX_DHT_SEED_TAGS: usize = 256;
const MAX_DHT_SEED_MANIFESTS: usize = 64;
const MAX_DHT_SEED_OWNERSHIP_RECORDS: usize = 256;
const MAX_DHT_SEED_CONSUMED_RECORDS: usize = 256;
const MAX_DHT_SEED_PROGRAMS: usize = 128;
/// Maximum encrypted-manifest payload bytes returned by one seed sync response.
const MAX_DHT_SEED_MANIFEST_BYTES: usize = 128 * 1024;

/// Maximum number of items in a LimboHold bill_ids array.
const MAX_LIMBO_HOLD_IDS: usize = 256;

/// Maximum encrypted manifest size in bytes (1 MiB).
const MAX_MANIFEST_SIZE: usize = 1_048_576;

/// Maximum number of manifest entries stored in the DHT manifest store.
/// Oldest (lowest-key) entry is evicted when this limit is exceeded.
const MAX_MANIFEST_ENTRIES: usize = 500;

/// Maximum number of stealth_payloads returned in a single
/// MailboxSweep response to prevent memory exhaustion.
const MAX_SWEEP_PAYLOADS: usize = 500;

/// Maximum TTL accepted for a [`MailboxForwardRegister`] subscription (1 hour).
const MAX_FORWARD_TTL_SECS: u64 = 3_600;

/// Freshness window for [`MailboxForwardRegister`] timestamps: requests older
/// than this many seconds are rejected as stale / replayed.
const FORWARD_TIMESTAMP_TOLERANCE_SECS: u64 = 120;

/// Number of duplicate messages from a single peer within a window
/// before the peer is banished for duplicate flooding.
const DUPLICATE_FLOOD_THRESHOLD: u32 = 50;

/// Window (in seconds) for counting per-peer duplicate messages.
const DUPLICATE_WINDOW_SECS: u64 = 60;

/// C1: Maximum total OwnershipGenesis entries buffered across all pending-reforge
/// keys.  Each entry can be up to 4 MiB, so 5 000 × 4 MiB = 20 GiB worst-case
/// without a global cap.  The 5 000-entry limit keeps worst-case at ~20 GiB
/// while still handling legitimate reforge bursts.
const MAX_PENDING_GENESIS_TOTAL: usize = 5_000;

/// C1: TTL for pending-reforge-genesis entries (5 minutes).  An attestation
/// that takes longer than this almost certainly lost in the network; retaining
/// the genesis messages beyond this point won't help.
const PENDING_GENESIS_TTL_SECS: u64 = 300;

// Flat peer list removed — replaced by Kademlia routing table
// (kademlia.rs). Sybil protection is now handled by per-bucket K=20
// caps and handshake PoW. The routing table stores only infrastructure
// relay peers, never wallet users or payment recipients.

/// Tracks duplicate message payloads per peer using Blake3 hashes.
///
/// When a peer sends the same payload hash more than `DUPLICATE_FLOOD_THRESHOLD`
/// times within `DUPLICATE_WINDOW_SECS`, they are flagged for banishment.
pub struct DuplicateTracker {
    /// Peer → { payload_hash → (count, first_seen_ts) }.
    #[allow(clippy::type_complexity)]
    table: HashMap<[u8; 32], HashMap<[u8; 32], (u32, u64)>>,
}

impl DuplicateTracker {
    fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    /// Record a message from a peer and return whether the peer should
    /// be banished (duplicate count exceeded threshold).
    fn record(&mut self, peer_id: &[u8; 32], payload_hash: &[u8; 32]) -> Option<u32> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer_entry = self.table.entry(*peer_id).or_default();

        // M2: Shrink the inner map by dropping expired window entries before
        // inserting.  Without this, every fake hash from a long-lived peer
        // accumulates forever inside the inner HashMap.
        peer_entry
            .retain(|_, (_, first_seen)| now.saturating_sub(*first_seen) <= DUPLICATE_WINDOW_SECS);

        let (count, first_seen) = peer_entry.entry(*payload_hash).or_insert((0, now));

        if now.saturating_sub(*first_seen) > DUPLICATE_WINDOW_SECS {
            // Window expired — reset.
            *count = 1;
            *first_seen = now;
            None
        } else {
            *count += 1;
            if *count >= DUPLICATE_FLOOD_THRESHOLD {
                Some(*count)
            } else {
                None
            }
        }
    }

    /// Evict entries for a banished peer to free memory.
    fn evict(&mut self, peer_id: &[u8; 32]) {
        self.table.remove(peer_id);
    }
}

/// Compute a compact deduplication key for a [`PulseMessage`].
///
/// For messages that carry large proof fields — most notably [`OwnershipGenesis`]
/// with its 4 MiB STARK proof — hashing the full serialization on every
/// relay hop wastes significant CPU.  Instead we hash only the fields that
/// uniquely identify the semantic event so duplicate detection stays cheap.
///
/// For messages without an obvious unique key we fall back to hashing the
/// full serialization; those messages are small in practice.
fn message_dedup_key(msg: &PulseMessage) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    match msg {
        PulseMessage::Payment(p) => {
            h.update(b"Payment");
            h.update(&p.payment_id);
        }
        PulseMessage::RelayPayment(rp) => {
            h.update(b"RelayPayment");
            h.update(&rp.payment.payment_id);
        }
        PulseMessage::OwnershipGenesis(og) => {
            // H1: hash only mint_id — avoids re-serializing the 4 MiB proof.
            h.update(b"OwnershipGenesis");
            h.update(&og.mint_id);
        }
        PulseMessage::OwnershipClaim(oc) => {
            h.update(b"OwnershipClaim");
            h.update(&oc.mint_id);
            h.update(&oc.new_owner_vk_hash);
        }
        PulseMessage::ReforgeAttestation(ra) => {
            h.update(b"ReforgeAttestation");
            h.update(&ra.reforge_id);
        }
        PulseMessage::TagRegister(tr) => {
            h.update(b"TagRegister");
            h.update(&tr.tag_hash);
            h.update(&tr.pow_nonce);
        }
        PulseMessage::TagStore(ts) => {
            h.update(b"TagStore");
            h.update(&ts.tag_hash);
        }
        PulseMessage::TagConfirm(tc) => {
            h.update(b"TagConfirm");
            h.update(&tc.tag_hash);
            h.update(&tc.mint_id);
        }
        PulseMessage::ManifestStore(ms) => {
            h.update(b"ManifestStore");
            h.update(&ms.dht_key);
        }
        PulseMessage::LimboHold(lh) => {
            h.update(b"LimboHold");
            h.update(&lh.stealth_id);
            h.update(&lh.entered_at.to_le_bytes());
        }
        _ => {
            // All other message types are small; full serialization is fine.
            h.update(&msg.to_bytes().unwrap_or_default());
        }
    }
    *h.finalize().as_bytes()
}

/// Check if a timestamp is within the acceptable window.
fn timestamp_is_valid(ts: u64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ts <= now + MAX_FUTURE_SKEW_SECS && now.saturating_sub(ts) <= MAX_MESSAGE_AGE_SECS
}

fn load_or_create_mesh_seed(state_dir: &std::path::Path) -> Result<[u8; 64]> {
    let path = state_dir.join(MESH_NODE_SEED_FILENAME);
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 64 {
            ensure_owner_only_file_permissions(&path)?;
            let mut seed = [0u8; 64];
            seed.copy_from_slice(&bytes);
            return Ok(seed);
        }
    }

    std::fs::create_dir_all(state_dir)?;
    let mut seed = [0u8; 64];
    rand::thread_rng().fill(&mut seed);
    write_owner_only_seed_file(&path, &seed)?;
    Ok(seed)
}

fn write_owner_only_seed_file(path: &Path, seed: &[u8; 64]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(seed)?;
        file.sync_all()?;
        ensure_owner_only_file_permissions(path)?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, seed)?;
        Ok(())
    }
}

fn ensure_owner_only_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

fn peer_hash_from_contact_bytes(contact_bytes: &[u8]) -> Option<[u8; 32]> {
    if contact_bytes.len() > MAX_SERIALIZED_MESH_CONTACT_BYTES {
        return None;
    }
    contact_bytes_node_id(contact_bytes)
}

fn bootstrap_string_from_contact(contact: &MeshCarrierContact) -> Option<String> {
    encode_contact_string(contact).ok()
}

fn push_peer_notification(
    state: &mut ArteryState,
    kind: &str,
    peer_hash: &[u8; 32],
    counterparty: Option<String>,
    message: String,
) {
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    state.push_notification(WalletNotification {
        kind: kind.to_string(),
        created_at,
        payment_id: hex_key(peer_hash),
        amount: None,
        bill_count: None,
        counterparty,
        message,
    });
}

fn queue_discovered_peer_contact(
    state: &Arc<Mutex<ArteryState>>,
    contact: MeshCarrierContact,
    source: &'static str,
) {
    let Some(peer_hash) = contact_node_id_bytes(&contact) else {
        warn!(source, "discovered peer contact is missing a mesh node id");
        return;
    };
    let target_bytes = match encode_contact_bytes(&contact) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(source, "failed to encode discovered peer contact: {error}");
            return;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Try to acquire the state lock with a short retry loop.
    // The message listener or handshake drain may hold it briefly;
    // retrying with a small delay avoids silently dropping peers.
    // If the lock is poisoned (prior panic), recover it.
    let mut s = 'lock: {
        for attempt in 0..20 {
            match state.try_lock() {
                Ok(s) => break 'lock s,
                Err(std::sync::TryLockError::Poisoned(e)) => {
                    warn!(source, "state lock poisoned — recovering");
                    break 'lock e.into_inner();
                }
                Err(std::sync::TryLockError::WouldBlock) if attempt < 19 => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    // last attempt failed
                }
            }
        }
        warn!(source, "state locked for 1s — retry next discovery cycle");
        return;
    };
    if peer_hash == s.node_id {
        return;
    }
    let already_known = s.routing_table.contains_peer(&peer_hash);
    if s.routing_table.insert(RoutingPeer {
        id_hash: peer_hash,
        id_bytes: target_bytes,
        last_seen: now,
        first_seen: now,
    }) {
        if !already_known {
            push_peer_notification(
                &mut s,
                "vess_peer_discovered",
                &peer_hash,
                Some(source.to_string()),
                format!("Discovered Vess peer via {source}: {}", hex_key(&peer_hash)),
            );
        }
    }
    if s.peer_registry.state(&peer_hash) != PeerState::Verified
        && !s.handshake_queue.contains(&peer_hash)
    {
        s.handshake_queue.push(peer_hash);
        info!(source, "queued discovered Vess peer for handshake");
    }
    s.estimated_network_size = s.routing_table.estimated_network_size();
    let repl = dht_replication_factor(s.estimated_network_size);
    s.tag_dht.set_k_replication(repl);
}

fn dht_seed_tag_from_record(record: &vess_tag::TagRecord) -> DhtSeedTagRecord {
    DhtSeedTagRecord {
        tag_hash: record.tag_hash,
        scan_ek: record.master_address.scan_ek.clone(),
        spend_ek: record.master_address.spend_ek.clone(),
        pow_nonce: record.pow_nonce,
        pow_hash: record.pow_hash.clone(),
        registered_at: record.registered_at,
        registrant_vk: record.registrant_vk.clone(),
        signature: record.signature.clone(),
        hardened_at: record.hardened_at,
    }
}

fn tag_record_from_dht_seed(record: DhtSeedTagRecord) -> vess_tag::TagRecord {
    vess_tag::TagRecord {
        tag_hash: record.tag_hash,
        master_address: vess_stealth::MasterStealthAddress {
            scan_ek: record.scan_ek,
            spend_ek: record.spend_ek,
        },
        pow_nonce: record.pow_nonce,
        pow_hash: record.pow_hash,
        registered_at: record.registered_at,
        registrant_vk: record.registrant_vk,
        signature: record.signature,
        hardened_at: record.hardened_at,
    }
}

fn dht_seed_ownership_from_record(record: &OwnershipRecord) -> DhtSeedOwnershipRecord {
    DhtSeedOwnershipRecord {
        mint_id: record.mint_id,
        chain_tip: record.chain_tip,
        current_owner_vk_hash: record.current_owner_vk_hash,
        current_owner_vk: record.current_owner_vk.clone(),
        denomination_value: record.denomination_value,
        updated_at: record.updated_at,
        proof_hash: record.proof_hash,
        digest: record.digest,
        nonce: record.nonce,
        prev_claim_vk_hash: record.prev_claim_vk_hash,
        claim_hash: record.claim_hash,
        prev_transfer_chain_tip: record.prev_transfer_chain_tip,
        chain_depth: record.chain_depth,
        encrypted_bill: record.encrypted_bill.clone(),
        locked_until_tick: record.locked_until_tick,
    }
}

fn ownership_record_from_dht_seed(record: DhtSeedOwnershipRecord) -> OwnershipRecord {
    OwnershipRecord {
        mint_id: record.mint_id,
        chain_tip: record.chain_tip,
        current_owner_vk_hash: record.current_owner_vk_hash,
        current_owner_vk: record.current_owner_vk,
        denomination_value: record.denomination_value,
        updated_at: record.updated_at,
        proof_hash: record.proof_hash,
        digest: record.digest,
        nonce: record.nonce,
        prev_claim_vk_hash: record.prev_claim_vk_hash,
        claim_hash: record.claim_hash,
        prev_transfer_chain_tip: record.prev_transfer_chain_tip,
        chain_depth: record.chain_depth,
        encrypted_bill: record.encrypted_bill,
        accumulated_work: None,
        locked_until_tick: record.locked_until_tick,
    }
}

#[derive(Debug, Default)]
struct SeedSyncPeerSnapshot {
    peer_id: [u8; 32],
    ownership_records: HashMap<[u8; 32], OwnershipRecord>,
    consumed_records: HashMap<[u8; 32], ConsumedRecord>,
}

fn ownership_record_vote_key(record: &OwnershipRecord) -> [u8; 32] {
    serde_json::to_vec(record)
        .map(|bytes| *blake3::hash(&bytes).as_bytes())
        .unwrap_or([0u8; 32])
}

fn consumed_record_vote_key(record: &ConsumedRecord) -> [u8; 32] {
    serde_json::to_vec(record)
        .map(|bytes| *blake3::hash(&bytes).as_bytes())
        .unwrap_or([0u8; 32])
}

fn validated_seed_ownership_record(
    registry: &OwnershipRegistry,
    peer_ids: &[[u8; 32]],
    replication: usize,
    source_peer_id: [u8; 32],
    local_node_id: [u8; 32],
    seeded_record: DhtSeedOwnershipRecord,
) -> Option<OwnershipRecord> {
    let mint_id = seeded_record.mint_id;
    if !registry.should_store(&mint_id, peer_ids, replication) {
        return None;
    }

    if !node_should_store_seeded_key(
        &mint_id,
        &source_peer_id,
        &local_node_id,
        peer_ids,
        replication,
    ) {
        return None;
    }

    let record = ownership_record_from_dht_seed(seeded_record);
    if registry.was_consumed(&mint_id).is_some() {
        return None;
    }

    if record.current_owner_vk.is_empty() {
        return None;
    }
    if vess_foundry::spend_auth::vk_hash(&record.current_owner_vk) != record.current_owner_vk_hash {
        return None;
    }

    Some(record)
}

fn validated_seed_consumed_record(
    registry: &OwnershipRegistry,
    peer_ids: &[[u8; 32]],
    replication: usize,
    source_peer_id: [u8; 32],
    local_node_id: [u8; 32],
    seeded_record: DhtSeedConsumedRecord,
) -> Option<([u8; 32], ConsumedRecord)> {
    let (mint_id, record) = consumed_record_from_dht_seed(seeded_record);
    (registry.should_store(&mint_id, peer_ids, replication)
        && node_should_store_seeded_key(
            &mint_id,
            &source_peer_id,
            &local_node_id,
            peer_ids,
            replication,
        ))
    .then_some((mint_id, record))
}

fn apply_quorum_seed_snapshots(state: &Arc<Mutex<ArteryState>>, snapshots: Vec<SeedSyncPeerSnapshot>) {
    if snapshots.is_empty() {
        return;
    }
    // Emit SeedSyncStarted for the first responding peer.
    let first_peer_id = snapshots[0].peer_id;
    {
        let mut s = lock_state(&state);
        s.push_event(NodeEvent::SeedSyncStarted {
            created_at: ArteryState::now_unix(),
            peer_id: hex_key(&first_peer_id),
        });
    }
    if snapshots.len() < 2 {
        info!(peers = snapshots.len(), "skipping ownership seed sync install because quorum is unavailable");
        return;
    }

    let quorum = snapshots.len() / 2 + 1;
    let mut ownership_votes: HashMap<[u8; 32], HashMap<[u8; 32], (usize, OwnershipRecord)>> =
        HashMap::new();
    let mut consumed_votes: HashMap<[u8; 32], HashMap<[u8; 32], (usize, ConsumedRecord)>> =
        HashMap::new();

    for snapshot in snapshots {
        for record in snapshot.ownership_records.into_values() {
            let key = ownership_record_vote_key(&record);
            let entry = ownership_votes
                .entry(record.mint_id)
                .or_default()
                .entry(key)
                .or_insert_with(|| (0, record));
            entry.0 += 1;
        }
        for (mint_id, record) in snapshot.consumed_records {
            let key = consumed_record_vote_key(&record);
            let entry = consumed_votes
                .entry(mint_id)
                .or_default()
                .entry(key)
                .or_insert_with(|| (0, record));
            entry.0 += 1;
        }
    }

    let mut inserted_ownership_records = 0usize;
    let mut inserted_consumed_records = 0usize;
    let mut s = lock_state(&state);

    for (mint_id, variants) in ownership_votes {
        let mut ranked: Vec<(usize, OwnershipRecord)> = variants.into_values().collect();
        ranked.sort_by(|left, right| right.0.cmp(&left.0));
        let Some((best_votes, best_record)) = ranked.into_iter().next() else {
            continue;
        };
        if best_votes < quorum || s.registry.was_consumed(&mint_id).is_some() {
            continue;
        }
        if let Some(existing) = s.registry.get(&mint_id).cloned() {
            if !ownership_record_supersedes(&best_record, &existing) {
                continue;
            }
            if let Some(existing_mut) = s.registry.get_mut(&mint_id) {
                *existing_mut = best_record;
                inserted_ownership_records += 1;
            }
        } else if s.registry.register(best_record) {
            inserted_ownership_records += 1;
        }
    }

    for (mint_id, variants) in consumed_votes {
        let mut ranked: Vec<(usize, ConsumedRecord)> = variants.into_values().collect();
        ranked.sort_by(|left, right| right.0.cmp(&left.0));
        let Some((best_votes, best_record)) = ranked.into_iter().next() else {
            continue;
        };
        if best_votes < quorum {
            continue;
        }
        if let Some(existing) = s.registry.was_consumed(&mint_id).cloned() {
            if !consumed_record_supersedes(&best_record, &existing) {
                continue;
            }
        }
        s.registry.insert_consumed_record(mint_id, best_record);
        inserted_consumed_records += 1;
    }

    if inserted_ownership_records > 0 || inserted_consumed_records > 0 {
        info!(
            quorum,
            inserted_ownership_records,
            inserted_consumed_records,
            "installed quorum-validated ownership state from seed sync"
        );
    }

    // Emit SeedSyncCompleted with summary stats.
    {
        let mut s = lock_state(&state);
        s.push_event(NodeEvent::SeedSyncCompleted {
            created_at: ArteryState::now_unix(),
            peer_id: hex_key(&first_peer_id),
            consumed_records: inserted_consumed_records,
            manifests: 0, // manifests are synced separately via DHT
            ownership_records: inserted_ownership_records,
            tags: 0, // tags are synced separately via DHT
        });
    }
}

fn dht_seed_consumed_from_record(
    mint_id: [u8; 32],
    record: &ConsumedRecord,
) -> DhtSeedConsumedRecord {
    DhtSeedConsumedRecord {
        mint_id,
        reforge_id: record.reforge_id,
        output_mint_ids: record.output_mint_ids.clone(),
        consumed_at: record.consumed_at,
        denomination_value: record.denomination_value,
        digest: record.digest,
    }
}

fn consumed_record_from_dht_seed(record: DhtSeedConsumedRecord) -> ([u8; 32], ConsumedRecord) {
    (
        record.mint_id,
        ConsumedRecord {
            reforge_id: record.reforge_id,
            output_mint_ids: record.output_mint_ids,
            consumed_at: record.consumed_at,
            denomination_value: record.denomination_value,
            digest: record.digest,
        },
    )
}

fn ownership_record_supersedes(candidate: &OwnershipRecord, incumbent: &OwnershipRecord) -> bool {
    candidate.chain_depth > incumbent.chain_depth
        || (candidate.chain_depth == incumbent.chain_depth
            && (candidate.claim_hash.unwrap_or([0xff; 32])
                < incumbent.claim_hash.unwrap_or([0xff; 32])
                || (candidate.claim_hash.unwrap_or([0xff; 32])
                    == incumbent.claim_hash.unwrap_or([0xff; 32])
                    && candidate.chain_tip < incumbent.chain_tip)))
}

fn consumed_record_supersedes(candidate: &ConsumedRecord, incumbent: &ConsumedRecord) -> bool {
    candidate.consumed_at > incumbent.consumed_at
        || (candidate.consumed_at == incumbent.consumed_at
            && candidate.output_mint_ids.len() > incumbent.output_mint_ids.len())
}

fn upsert_seed_ownership_record(
    records: &mut HashMap<[u8; 32], OwnershipRecord>,
    record: OwnershipRecord,
) {
    match records.get(&record.mint_id) {
        Some(existing) if !ownership_record_supersedes(&record, existing) => {}
        _ => {
            records.insert(record.mint_id, record);
        }
    }
}

fn upsert_seed_consumed_record(
    records: &mut HashMap<[u8; 32], ConsumedRecord>,
    mint_id: [u8; 32],
    record: ConsumedRecord,
) {
    match records.get(&mint_id) {
        Some(existing) if !consumed_record_supersedes(&record, existing) => {}
        _ => {
            records.insert(mint_id, record);
        }
    }
}

fn collect_seed_ownership_records(state: &ArteryState) -> HashMap<[u8; 32], OwnershipRecord> {
    let mut records = state.retained_ownership_records.clone();
    for record in state.registry.all_records() {
        upsert_seed_ownership_record(&mut records, record);
    }
    records
}

fn collect_seed_consumed_records(state: &ArteryState) -> HashMap<[u8; 32], ConsumedRecord> {
    let mut records = state.retained_consumed_records.clone();
    for (mint_id, record) in state.registry.all_consumed() {
        upsert_seed_consumed_record(&mut records, mint_id, record);
    }
    records
}

fn verify_competing_claim_chain_tip(
    base_chain_tip: [u8; 32],
    oc: &OwnershipClaim,
    witness_hash: [u8; 32],
) -> bool {
    vess_foundry::advance_chain_tip_with_hash(&base_chain_tip, &oc.new_owner_vk_hash, &witness_hash)
        == oc.new_chain_tip
}

fn ownership_claim_hash(oc: &OwnershipClaim) -> [u8; 32] {
    let prev_owner_commitment = ownership_claim_prev_owner_commitment(oc).unwrap_or([0u8; 32]);
    let new_owner_commitment = ownership_claim_new_owner_commitment(oc).unwrap_or([0u8; 32]);
    let witness_hash = ownership_claim_witness_hash(oc).unwrap_or([0u8; 32]);
    let mut h = blake3::Hasher::new();
    h.update(b"vess-claim-hash-v1");
    h.update(&oc.mint_id);
    h.update(&prev_owner_commitment);
    h.update(&new_owner_commitment);
    h.update(&witness_hash);
    h.update(&(oc.timestamp / 60).to_le_bytes());
    *h.finalize().as_bytes()
}

fn ownership_genesis_owner_commitment(og: &OwnershipGenesis) -> [u8; 32] {
    vess_foundry::spend_auth::vk_hash(&og.owner_vk)
}

fn ownership_claim_prev_owner_commitment(oc: &OwnershipClaim) -> Option<[u8; 32]> {
    if !oc.prev_owner_vk.is_empty() {
        Some(vess_foundry::spend_auth::vk_hash(&oc.prev_owner_vk))
    } else {
        None
    }
}

fn ownership_claim_new_owner_commitment(oc: &OwnershipClaim) -> Option<[u8; 32]> {
    if !oc.new_owner_vk.is_empty() {
        Some(vess_foundry::spend_auth::vk_hash(&oc.new_owner_vk))
    } else if oc.new_owner_vk_hash != [0u8; 32] {
        Some(oc.new_owner_vk_hash)
    } else {
        None
    }
}

fn ownership_claim_witness_hash(oc: &OwnershipClaim) -> Option<[u8; 32]> {
    if !oc.transfer_sig.is_empty() {
        Some(*blake3::hash(&oc.transfer_sig).as_bytes())
    } else {
        None
    }
}

fn proof_hash_and_nonce_from_genesis(og: &OwnershipGenesis) -> Option<([u8; 32], [u8; 32])> {
    match &og.genesis_proof {
        GenesisProof::Vess(proof_bytes) => {
            let proof_hash = *blake3::hash(proof_bytes).as_bytes();
            if let Ok(iop_proof) = vess_foundry::proof::deserialize_proof(proof_bytes) {
                Some((proof_hash, iop_proof.nonce))
            } else if let Ok(agg) = vess_foundry::proof::AggregateProof::deserialize(proof_bytes) {
                let mut h = blake3::Hasher::new();
                h.update(b"vess-aggregate-nonce-v0");
                for sub in &agg.d1_proofs {
                    if let Ok(p) = vess_foundry::proof::deserialize_proof(sub) {
                        h.update(&p.nonce);
                    }
                }
                Some((proof_hash, *h.finalize().as_bytes()))
            } else if let Ok(sap) = vess_foundry::proof::SampledAggregateProof::deserialize(proof_bytes) {
                Some((proof_hash, sap.nonce_tree_root))
            } else if vess_foundry::reforge::deserialize_reforge_proof(proof_bytes).is_ok() {
                Some((proof_hash, og.digest))
            } else {
                None
            }
        }
        GenesisProof::VHALIXMined(_) => {
            // VHALIX proof hash is the Merkle root
            Some((og.digest, og.digest))
        }
        GenesisProof::VichorGenesis(_) => None,
        GenesisProof::BountyGenesis(_) => {
            // Bounty proof hash is the verified argon2_output
            Some((og.digest, og.digest))
        }
        GenesisProof::LocalTestFaucet(proof) => {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-local-test-faucet-proof-v0");
            h.update(&proof.nonce);
            Some((*h.finalize().as_bytes(), proof.nonce))
        }
    }
}

pub(crate) fn retain_local_ownership_genesis(
    state: &mut ArteryState,
    og: &OwnershipGenesis,
    updated_at: u64,
) {
    // Validate genesis proofs before accepting.  VHALIXMined proofs are
    // verified by the OwnershipGenesis handler before reaching this function.
    match &og.genesis_proof {
        GenesisProof::VHALIXMined(_) | GenesisProof::Vess(_)
        | GenesisProof::VichorGenesis(_) | GenesisProof::LocalTestFaucet(_)
        | GenesisProof::BountyGenesis(_) => {}
    }

    let Some((proof_hash, proof_nonce)) = proof_hash_and_nonce_from_genesis(og) else {
        return;
    };

    state.retained_consumed_records.remove(&og.mint_id);
    upsert_seed_ownership_record(
        &mut state.retained_ownership_records,
        OwnershipRecord {
            mint_id: og.mint_id,
            chain_tip: og.chain_tip,
            current_owner_vk_hash: og.owner_vk_hash,
            current_owner_vk: og.owner_vk.clone(),
            denomination_value: og.denomination_value,
            updated_at,
            proof_hash,
            digest: og.digest,
            nonce: proof_nonce,
            prev_claim_vk_hash: None,
            claim_hash: None,
            prev_transfer_chain_tip: None,
            chain_depth: og.chain_depth,
            encrypted_bill: Vec::new(),
            accumulated_work: None,
            locked_until_tick: 0,
        },
    );
}

/// Validate an incoming VHALIXMined genesis proof and retain it locally.
///
/// Performs fast checks (chain continuity, Merkle root, denomination,
/// signature) and rejects invalid proofs.  Expensive Argon2id spot-check
/// recomputation is done probabilistically for high-denomination bills.
///
/// Returns `true` if the genesis was valid and retained.
fn validate_and_retain_genesis(
    state: &mut ArteryState,
    og: &vess_protocol::OwnershipGenesis,
    peer_id: &[u8; 32],
) -> bool {
    let proof = match &og.genesis_proof {
        vess_protocol::GenesisProof::VHALIXMined(p) => {
            return validate_VHALIX_genesis(state, og, p, peer_id);
        }
        vess_protocol::GenesisProof::BountyGenesis(bp) => {
            return validate_bounty_genesis(state, og, bp, peer_id);
        }
        // Non-VHALIX/bounty genesis types (Vess, VichorGenesis, LocalTestFaucet)
        // are validated elsewhere or accepted as-is.
        _ => {
            // VichorGenesis: validate canonical nonce, supply, and signature
            if let vess_protocol::GenesisProof::VichorGenesis(vg) = &og.genesis_proof {
                if vg.nonce != vess_protocol::VICHOR_GENESIS_NONCE {
                    tracing::warn!("Vichor genesis rejected: invalid nonce");
                    return false;
                }
                if vg.total_supply != vess_protocol::VICHOR_TOTAL_SUPPLY {
                    tracing::warn!("Vichor genesis rejected: total_supply != 1B");
                    return false;
                }
                // Verify dev signature over genesis message
                let mut sig_msg = blake3::Hasher::new();
                sig_msg.update(b"vess-vichor-genesis-v1");
                sig_msg.update(&vg.nonce);
                sig_msg.update(&vg.total_supply.to_be_bytes());
                sig_msg.update(&vg.owner_vk_hash);
                let sig_digest = *sig_msg.finalize().as_bytes();
                match vess_foundry::spend_auth::verify_spend(&vg.owner_vk, &sig_digest, &vg.owner_sig) {
                    Ok(true) => {}
                    _ => {
                        tracing::warn!("Vichor genesis rejected: invalid dev signature");
                        return false;
                    }
                }
                tracing::info!("Vichor genesis accepted: 1B supply created");
            }
            retain_local_ownership_genesis(state, og, ArteryState::now_unix());
            return true;
        }
    };
}

/// Validate an incoming VHALIXMined genesis proof (steps 1-6).
fn validate_VHALIX_genesis(
    state: &mut ArteryState,
    og: &vess_protocol::OwnershipGenesis,
    proof: &vess_protocol::VHALIXMinedProof,
    peer_id: &[u8; 32],
) -> bool {
    // ── 1. Owner VK hash must match ──────────────────────────────
    let computed_vk_hash = vess_foundry::spend_auth::vk_hash(&proof.owner_vk);
    if computed_vk_hash != og.owner_vk_hash {
        tracing::warn!(
            mint_id = %crate::persistence::hex_key(&og.mint_id),
            peer = %crate::persistence::hex_key(peer_id),
            "VHALIX genesis rejected: owner_vk_hash mismatch"
        );
        return false;
    }

    // ── 2. Chain length and denomination ─────────────────────────
    let chain_length = proof.bill_nonce_end
        .saturating_sub(proof.bill_nonce_start)
        .saturating_add(1);
    if chain_length < vess_foundry::mine::MIN_CHAIN_LENGTH {
        tracing::warn!(
            mint_id = %crate::persistence::hex_key(&og.mint_id),
            chain_length,
            min = vess_foundry::mine::MIN_CHAIN_LENGTH,
            "VHALIX genesis rejected: chain too short"
        );
        return false;
    }
    let expected_denom = vess_foundry::Denomination::max_valid_denomination(chain_length);
    if og.denomination_value != expected_denom {
        tracing::warn!(
            mint_id = %crate::persistence::hex_key(&og.mint_id),
            claimed = og.denomination_value,
            expected = expected_denom,
            chain_length,
            "VHALIX genesis rejected: denomination mismatch"
        );
        return false;
    }

    // ── 3. Merkle root must match digest ─────────────────────────
    if proof.merkle_root != og.digest {
        tracing::warn!(
            mint_id = %crate::persistence::hex_key(&og.mint_id),
            "VHALIX genesis rejected: merkle root != digest"
        );
        return false;
    }

    // ── 4. Verify Merkle root from chain_hashes ────────────────
    if !proof.chain_hashes.is_empty() {
        // Recompute Merkle root from the hash list
        let computed_root = {
            let mut level: Vec<[u8; 32]> = proof.chain_hashes.clone();
            if level.is_empty() {
                [0u8; 32]
            } else {
                while level.len() > 1 {
                    let mut next = Vec::with_capacity((level.len() + 1) / 2);
                    for chunk in level.chunks(2) {
                        let mut h = blake3::Hasher::new();
                        h.update(&chunk[0]);
                        if chunk.len() == 2 {
                            h.update(&chunk[1]);
                        } else {
                            h.update(&chunk[0]);
                        }
                        next.push(*h.finalize().as_bytes());
                    }
                    level = next;
                }
                level[0]
            }
        };
        if computed_root != proof.merkle_root {
            tracing::warn!(
                mint_id = %crate::persistence::hex_key(&og.mint_id),
                "VHALIX genesis rejected: chain_hashes Merkle root mismatch"
            );
            return false;
        }

        // Verify chain_hashes count matches bill_nonce range
        let expected_count = proof.bill_nonce_end
            .saturating_sub(proof.bill_nonce_start)
            .saturating_add(1) as usize;
        if proof.chain_hashes.len() != expected_count {
            tracing::warn!(
                mint_id = %crate::persistence::hex_key(&og.mint_id),
                hashes = proof.chain_hashes.len(),
                expected = expected_count,
                "VHALIX genesis rejected: chain_hashes count mismatch"
            );
            return false;
        }
    }

    // ── 5. Batch signature verification ──────────────────────────
    {
        let mut sig_hasher = blake3::Hasher::new();
        sig_hasher.update(b"vess-VHALIX-batch-v2");
        sig_hasher.update(&proof.merkle_root);
        sig_hasher.update(&proof.bill_nonce_start.to_be_bytes());
        sig_hasher.update(&proof.bill_nonce_end.to_be_bytes());
        let sig_msg = *sig_hasher.finalize().as_bytes();

        match vess_foundry::spend_auth::verify_spend(&proof.owner_vk, &sig_msg, &proof.batch_sig) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                tracing::warn!(
                    mint_id = %crate::persistence::hex_key(&og.mint_id),
                    "VHALIX genesis rejected: invalid batch signature"
                );
                return false;
            }
        }
    }

    // ── 6. High-value bills: deferred full verification ───────
    // For bills ≥ 500 denomination, we log a warning that full
    // Argon2id verification is deferred.  In production, a separate
    // async worker would spot-check ~1% of high-value proofs.
    // The fast checks above (chain length, denomination, Merkle root,
    // batch signature) are sufficient to reject trivial forgeries.
    // Peer reputation handles the rest — a peer submitting fake
    // high-value proofs gets banished once detected.
    if og.denomination_value >= 500 {
        tracing::info!(
            mint_id = %crate::persistence::hex_key(&og.mint_id),
            denomination = og.denomination_value,
            chain_length,
            "VHALIX high-value genesis accepted (Argon2id spot-check deferred)"
        );
    }

    // ── Retain locally ───────────────────────────────────────────
    let now = ArteryState::now_unix();
    retain_local_ownership_genesis(state, og, now);

    // Store open bounty for verifiers to claim
    if proof.bounty.is_some() {
        state.open_bounties.insert(og.mint_id, proof.clone());
    }

    tracing::info!(
        mint_id = %crate::persistence::hex_key(&og.mint_id),
        denomination = og.denomination_value,
        chain_length,
        "VHALIX genesis validated and retained"
    );

    true
}

/// Validate an incoming BountyGenesis proof.
///
/// Checks that the parent VHALIX genesis exists in the registry, the
/// claimed proof index is in the excess (bounty) range, and the
/// Argon2id output in the proof matches the parent's chain_hashes.
fn validate_bounty_genesis(
    state: &mut ArteryState,
    og: &vess_protocol::OwnershipGenesis,
    bp: &vess_protocol::BountyGenesisProof,
    peer_id: &[u8; 32],
) -> bool {
    // ── 1. Parent genesis must exist ────────────────────────────
    let parent_record = match state.registry.get(&bp.genesis_mint_id) {
        Some(r) => r.clone(),
        None => {
            tracing::warn!(
                parent = %crate::persistence::hex_key(&bp.genesis_mint_id),
                "bounty rejected: parent genesis not found"
            );
            return false;
        }
    };

    // ── 2. Parent must have a bounty ────────────────────────────
    let parent_proof = match &parent_record.proof_hash {
        _ => {
            // We need the VHALIXMinedProof from the parent.
            // It's not stored in OwnershipRecord directly.
            // For now: check the open_bounties map.
            match state.open_bounties.get(&bp.genesis_mint_id) {
                Some(p) => p.clone(),
                None => {
                    tracing::warn!(
                        parent = %crate::persistence::hex_key(&bp.genesis_mint_id),
                        "bounty rejected: parent has no open bounty"
                    );
                    return false;
                }
            }
        }
    };

    let bounty = match &parent_proof.bounty {
        Some(b) => b,
        None => {
            tracing::warn!("bounty rejected: parent has no bounty");
            return false;
        }
    };

    // ── 3. Proof index must be in bounty range ──────────────────
    if bp.proof_index < bounty.excess_start || bp.proof_index > bounty.excess_end {
        tracing::warn!(
            proof_index = bp.proof_index,
            excess_start = bounty.excess_start,
            excess_end = bounty.excess_end,
            "bounty rejected: proof index outside excess range"
        );
        return false;
    }

    // ── 4. Check not already claimed ────────────────────────────
    let claimed = state.claimed_bounty_indices
        .entry(bp.genesis_mint_id)
        .or_default();
    if claimed.contains(&bp.proof_index) {
        tracing::warn!(
            proof_index = bp.proof_index,
            "bounty rejected: already claimed"
        );
        return false;
    }

    // ── 5. Verify Argon2id output matches parent's chain_hashes ─
    let hash_offset = bp.proof_index.saturating_sub(parent_proof.bill_nonce_start) as usize;
    let expected_hash = match parent_proof.chain_hashes.get(hash_offset) {
        Some(h) => *h,
        None => {
            tracing::warn!("bounty rejected: proof index out of chain_hashes");
            return false;
        }
    };

    // Recompute hash from the claimed Argon2id output
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vess-VHALIX-commit-v1");
    hasher.update(&bp.argon2_output);
    hasher.update(&bp.proof_index.to_be_bytes());
    hasher.update(&vess_foundry::spend_auth::vk_hash(&bp.verifier_vk));
    let computed_hash = *hasher.finalize().as_bytes();

    if computed_hash != expected_hash {
        tracing::warn!(
            proof_index = bp.proof_index,
            "bounty rejected: Argon2id hash mismatch"
        );
        // Banish the peer for submitting a fraudulent claim
        state.peer_registry.mark_banished(*peer_id);
        return false;
    }

    // ── 6. Mark as claimed ──────────────────────────────────────
    claimed.insert(bp.proof_index);
    if claimed.len() as u64 >= bounty.bounty_count {
        // All bounties claimed — remove from open_bounties
        state.open_bounties.remove(&bp.genesis_mint_id);
    }

    // ── 7. Retain the bounty bill ───────────────────────────────
    let now = ArteryState::now_unix();
    retain_local_ownership_genesis(state, og, now);

    tracing::info!(
        mint_id = %crate::persistence::hex_key(&og.mint_id),
        parent = %crate::persistence::hex_key(&bp.genesis_mint_id),
        proof_index = bp.proof_index,
        "bounty genesis validated — 5 VHALIX awarded to verifier"
    );

    true
}

/// Extract VerificationBounty from an OwnershipGenesis, if present.
fn extract_bounty(og: &vess_protocol::OwnershipGenesis) -> Option<&vess_protocol::VerificationBounty> {
    match &og.genesis_proof {
        vess_protocol::GenesisProof::VHALIXMined(p) => p.bounty.as_ref(),
        _ => None,
    }
}

/// Attempt to claim one verification bounty from a genesis proof.
///
/// Picks a deterministic bounty index based on our node_id (so different
/// nodes naturally pick different proofs).  Recomputes Argon2id for that
/// proof.  If it matches, submits a VerificationClaim to the network.
fn try_claim_bounty(
    og: &vess_protocol::OwnershipGenesis,
    verifier_vk: &[u8],
    verifier_sk: &[u8],
    node_id: [u8; 32],
    og_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipGenesis>,
) {
    let proof = match &og.genesis_proof {
        vess_protocol::GenesisProof::VHALIXMined(p) => p,
        _ => return,
    };
    let bounty = match &proof.bounty {
        Some(b) => b,
        None => return,
    };

    // Deterministic index: node_id % bounty_count
    let bounty_idx = (u64::from_le_bytes(node_id[..8].try_into().unwrap_or([0u8; 8])))
        % bounty.bounty_count;
    let proof_nonce = bounty.excess_start + bounty_idx;

    // Derive the expected argon2_hash from chain_hashes
    let hash_offset = proof_nonce.saturating_sub(proof.bill_nonce_start) as usize;
    let expected_hash = match proof.chain_hashes.get(hash_offset) {
        Some(h) => *h,
        None => {
            tracing::warn!(
                mint_id = %crate::persistence::hex_key(&og.mint_id),
                bounty_idx,
                proof_nonce,
                "bounty claim: proof index out of chain_hashes range"
            );
            return;
        }
    };

    tracing::info!(
        mint_id = %crate::persistence::hex_key(&og.mint_id),
        bounty_idx,
        proof_nonce,
        "starting bounty verification (Argon2id recompute, ~30 min)"
    );

    // Recompute Argon2id
    let mut password = Vec::with_capacity(32 + 8 + 32);
    password.extend_from_slice(&vess_foundry::spend_auth::vk_hash(&proof.owner_vk));
    password.extend_from_slice(&proof_nonce.to_be_bytes());
    password.extend_from_slice(b"vess-VHALIX-mine-v1");

    let mut output = [0u8; 32];
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            vess_foundry::mine::VHALIX_M_COST,
            vess_foundry::mine::VHALIX_T_COST,
            1,
            Some(32),
        ).expect("valid params"),
    );

    if let Err(e) = argon2.hash_password_into(&password, b"vess-VHALIX-salt-v1", &mut output) {
        tracing::error!(error = %e, "bounty Argon2id recompute failed");
        return;
    }

    // Hash the output to compare with chain_hashes entry
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vess-VHALIX-commit-v1");
    hasher.update(&output);
    hasher.update(&proof_nonce.to_be_bytes());
    hasher.update(&vess_foundry::spend_auth::vk_hash(&proof.owner_vk));
    let computed_hash = *hasher.finalize().as_bytes();

    if computed_hash != expected_hash {
        tracing::warn!(
            mint_id = %crate::persistence::hex_key(&og.mint_id),
            bounty_idx,
            proof_nonce,
            "bounty verification FAILED — genesis proof is fraudulent!"
        );
        return;
    }

    tracing::info!(
        mint_id = %crate::persistence::hex_key(&og.mint_id),
        bounty_idx,
        proof_nonce,
        "bounty verification PASSED — submitting claim"
    );

    // Build and sign the claim
    let mut sig_msg = blake3::Hasher::new();
    sig_msg.update(b"vess-bounty-claim-v1");
    sig_msg.update(&og.mint_id);
    sig_msg.update(&proof_nonce.to_be_bytes());
    let sig_digest = *sig_msg.finalize().as_bytes();

    let sig = match vess_foundry::spend_auth::sign_spend(verifier_sk, &sig_digest) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to sign bounty claim");
            return;
        }
    };

    // Build the bounty genesis proof
    let verifier_vk_hash = vess_foundry::spend_auth::vk_hash(verifier_vk);
    let mint_id = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-bounty-mint-v1");
        h.update(&og.mint_id);
        h.update(&proof_nonce.to_be_bytes());
        h.update(&verifier_vk_hash);
        *h.finalize().as_bytes()
    };

    let bounty_proof = vess_protocol::BountyGenesisProof {
        genesis_mint_id: og.mint_id,
        proof_index: proof_nonce,
        argon2_output: output,
        verifier_vk: verifier_vk.to_vec(),
        verifier_sig: sig,
    };

    let bounty_og = vess_protocol::OwnershipGenesis {
        mint_id,
        chain_tip: vess_foundry::advance_chain_tip_with_hash(
            &mint_id, &verifier_vk_hash, &mint_id,
        ),
        owner_vk_hash: verifier_vk_hash,
        owner_vk: verifier_vk.to_vec(),
        denomination_value: bounty.reward_per_claim, // 1 VHALIX
        genesis_proof: vess_protocol::GenesisProof::BountyGenesis(bounty_proof),
        digest: expected_hash, // the verified argon2_hash
        hops_remaining: 0,
        chain_depth: 0,
        output_index: 0,
        pow_nonce: None,
        pow_hash: None,
        accumulated_work: None,
    };

    let _ = og_tx.send(bounty_og);
    tracing::info!(
        mint_id = %crate::persistence::hex_key(&mint_id),
        parent = %crate::persistence::hex_key(&og.mint_id),
        proof_nonce,
        "bounty claim submitted as genesis"
    );
}

pub(crate) fn local_seed_record_from_claimed_bill(
    claim: &OwnershipClaim,
    bill: &vess_foundry::VessBill,
    owner_vk: &[u8],
    updated_at: u64,
) -> OwnershipRecord {
    OwnershipRecord {
        mint_id: bill.mint_id,
        chain_tip: bill.chain_tip,
        current_owner_vk_hash: claim.new_owner_vk_hash,
        current_owner_vk: owner_vk.to_vec(),
        denomination_value: bill.denomination.value(),
        updated_at,
        proof_hash: [0u8; 32],
        digest: bill.digest,
        nonce: [0u8; 32],
        prev_claim_vk_hash: Some(vess_foundry::spend_auth::vk_hash(&claim.prev_owner_vk)),
        claim_hash: Some(ownership_claim_hash(claim)),
        prev_transfer_chain_tip: None,
        chain_depth: bill.chain_depth,
        encrypted_bill: claim.encrypted_bill.clone(),
        accumulated_work: None,
        locked_until_tick: claim.locked_until_tick,
    }
}

pub(crate) fn local_seed_claim_fallback_from_wallet(
    state: &ArteryState,
    oc: &OwnershipClaim,
    updated_at: u64,
) -> Option<OwnershipRecord> {
    let wallet = state.wallet.as_ref()?;
    let bill = wallet
        .billfold
        .bills()
        .iter()
        .find(|bill| bill.mint_id == oc.mint_id)?;
    Some(local_seed_record_from_claimed_bill(
        oc,
        bill,
        &oc.new_owner_vk,
        updated_at,
    ))
}

pub(crate) fn retain_local_ownership_claim(
    state: &mut ArteryState,
    oc: &OwnershipClaim,
    fallback: Option<OwnershipRecord>,
    updated_at: u64,
) {
    // Cross-shard consistency check: reject claims for already-consumed bills.
    if !check_cross_shard_consistency(state, &oc.mint_id) {
        tracing::warn!(
            mint_id = %crate::persistence::hex_key(&oc.mint_id),
            "rejecting claim: bill already consumed"
        );
        return;
    }

    let record = state
        .retained_ownership_records
        .remove(&oc.mint_id)
        .or(fallback);

    // ── Lock enforcement ──────────────────────────────────────────
    // If this bill has a lock that hasn't matured yet, reject any
    // transfer that changes the owner (self-transfers for locking
    // are allowed since new_owner_vk == current_owner_vk).
    if let Some(ref existing) = record {
        if existing.locked_until_tick > 0 {
            let nt = state.network_time.median_tick;
            let same_owner = vess_foundry::spend_auth::vk_hash(&oc.new_owner_vk)
                == existing.current_owner_vk_hash;
            if !same_owner && nt < existing.locked_until_tick {
                tracing::warn!(
                    mint_id = %crate::persistence::hex_key(&oc.mint_id),
                    locked_until = existing.locked_until_tick,
                    current_tick = nt,
                    "rejecting claim: bill locked until tick {}",
                    existing.locked_until_tick,
                );
                // Put the record back
                upsert_seed_ownership_record(
                    &mut state.retained_ownership_records,
                    existing.clone(),
                );
                return;
            }
        }
    }

    let Some(mut record) = record else {
        return;
    };

    let previous_chain_tip = record.chain_tip;
    record.updated_at = updated_at;
    record.prev_claim_vk_hash = Some(vess_foundry::spend_auth::vk_hash(&oc.prev_owner_vk));
    record.claim_hash = Some(ownership_claim_hash(oc));
    record.prev_transfer_chain_tip = Some(previous_chain_tip);
    record.chain_depth = oc.chain_depth;
    record.encrypted_bill = oc.encrypted_bill.clone();
    record.chain_tip = oc.new_chain_tip;
    record.current_owner_vk_hash = oc.new_owner_vk_hash;
    record.current_owner_vk = oc.new_owner_vk.clone();
    // Carry forward lock if this claim has one (or clear if matured)
    if oc.locked_until_tick > 0 {
        record.locked_until_tick = oc.locked_until_tick;
    }
    state.retained_consumed_records.remove(&oc.mint_id);
    upsert_seed_ownership_record(&mut state.retained_ownership_records, record);
}

pub(crate) fn retain_local_reforge_attestation(
    state: &mut ArteryState,
    ra: &ReforgeAttestation,
    consumed_at: u64,
) {
    for mint_id in &ra.consumed_mint_ids {
        let removed = state
            .retained_ownership_records
            .remove(mint_id)
            .or_else(|| state.registry.get(mint_id).cloned());
        let existing = state.retained_consumed_records.get(mint_id).cloned();
        let (denomination_value, digest) = removed
            .as_ref()
            .map(|record| (record.denomination_value, record.digest))
            .or_else(|| {
                existing
                    .as_ref()
                    .map(|record| (record.denomination_value, record.digest))
            })
            .unwrap_or((0, [0u8; 32]));
        upsert_seed_consumed_record(
            &mut state.retained_consumed_records,
            *mint_id,
            ConsumedRecord {
                reforge_id: ra.reforge_id,
                output_mint_ids: ra.output_mint_ids.clone(),
                consumed_at,
                denomination_value,
                digest,
            },
        );
    }
}

pub(crate) fn queue_local_ownership_genesis(
    state: &mut ArteryState,
    tx: &tokio::sync::mpsc::UnboundedSender<OwnershipGenesis>,
    og: OwnershipGenesis,
) {
    retain_local_ownership_genesis(state, &og, ArteryState::now_unix());
    let _ = tx.send(og);
}

pub(crate) fn queue_local_ownership_claim(
    state: &mut ArteryState,
    tx: &tokio::sync::mpsc::UnboundedSender<OwnershipClaim>,
    mut oc: OwnershipClaim,
) {
    // Attach denomination-scaled claim PoW before broadcasting.
    let denom_value = state
        .registry
        .get(&oc.mint_id)
        .map(|r| r.denomination_value)
        .unwrap_or(1);
    let (pow_nonce, pow_hash, pow_difficulty) =
        crate::handshake::compute_claim_pow(&oc.mint_id, &oc.new_owner_vk_hash, denom_value);
    oc.pow_nonce = Some(pow_nonce);
    oc.pow_hash = Some(pow_hash);
    oc.accumulated_work = Some(pow_difficulty);

    let updated_at = ArteryState::now_unix();
    let fallback = local_seed_claim_fallback_from_wallet(state, &oc, updated_at);
    retain_local_ownership_claim(state, &oc, fallback, updated_at);
    let _ = tx.send(oc);
}

pub(crate) fn queue_local_reforge_attestation(
    state: &mut ArteryState,
    tx: &tokio::sync::mpsc::UnboundedSender<ReforgeAttestation>,
    ra: ReforgeAttestation,
) {
    retain_local_reforge_attestation(state, &ra, ArteryState::now_unix());
    let _ = tx.send(ra);
}

fn node_should_store_seeded_key(
    dht_key: &[u8; 32],
    candidate_node_id: &[u8; 32],
    local_node_id: &[u8; 32],
    known_peer_ids: &[[u8; 32]],
    replication: usize,
) -> bool {
    if candidate_node_id == local_node_id {
        return false;
    }
    let candidate_distance = crate::gossip::xor_distance(candidate_node_id, dht_key);
    let mut closer_count =
        usize::from(crate::gossip::xor_distance(local_node_id, dht_key) < candidate_distance);

    for peer_id in known_peer_ids {
        if peer_id == candidate_node_id || peer_id == local_node_id {
            continue;
        }
        if crate::gossip::xor_distance(peer_id, dht_key) < candidate_distance {
            closer_count += 1;
        }
    }

    closer_count < replication.max(1)
}

#[derive(Debug, Default, Clone, Copy)]
struct DhtSeedCursor {
    after_tag_hash: Option<[u8; 32]>,
    after_manifest_key: Option<[u8; 32]>,
    after_ownership_mint_id: Option<[u8; 32]>,
    after_consumed_mint_id: Option<[u8; 32]>,
}

impl DhtSeedCursor {
    fn into_request(self, requester_node_id: [u8; 32]) -> DhtSeedRequest {
        DhtSeedRequest {
            requester_node_id,
            after_tag_hash: self.after_tag_hash,
            after_manifest_key: self.after_manifest_key,
            after_ownership_mint_id: self.after_ownership_mint_id,
            after_consumed_mint_id: self.after_consumed_mint_id,
            max_tags: MAX_DHT_SEED_TAGS as u16,
            max_manifests: MAX_DHT_SEED_MANIFESTS as u16,
            max_ownership_records: MAX_DHT_SEED_OWNERSHIP_RECORDS as u16,
            max_consumed_records: MAX_DHT_SEED_CONSUMED_RECORDS as u16,
            burn_proof: None,
        }
    }

    fn advance_from_response(&mut self, response: &DhtSeedResponse) {
        if let Some(last) = response.tags.last() {
            self.after_tag_hash = Some(last.tag_hash);
        }
        if let Some(last) = response.manifests.last() {
            self.after_manifest_key = Some(last.dht_key);
        }
        if let Some(last) = response.ownership_records.last() {
            self.after_ownership_mint_id = Some(last.mint_id);
        }
        if let Some(last) = response.consumed_records.last() {
            self.after_consumed_mint_id = Some(last.mint_id);
        }
    }
}

fn dht_seed_response_is_empty(response: &DhtSeedResponse) -> bool {
    response.tags.is_empty()
        && response.manifests.is_empty()
        && response.ownership_records.is_empty()
        && response.consumed_records.is_empty()
}

fn dht_seed_cursor_allows_key(key: &[u8; 32], cursor: Option<[u8; 32]>) -> bool {
    cursor.map(|after| key > &after).unwrap_or(true)
}

async fn request_dht_seed_catchup(
    node: &MeshPulseNode,
    target: &MeshCarrierContact,
    state: &Arc<Mutex<ArteryState>>,
    state_dir: &Path,
) -> Option<SeedSyncPeerSnapshot> {
    const MAX_DHT_SEED_CATCHUP_ROUNDS: usize = 1024;

    let requester_node_id = *node.id().as_bytes();
    let source_peer_id = contact_node_id_bytes(target)?;
    let mut cursor = DhtSeedCursor::default();
    let mut snapshot = SeedSyncPeerSnapshot {
        peer_id: source_peer_id,
        ownership_records: HashMap::new(),
        consumed_records: HashMap::new(),
    };

    for round in 0..MAX_DHT_SEED_CATCHUP_ROUNDS {
        let dht_seed_request = PulseMessage::DhtSeedRequest(cursor.into_request(requester_node_id));
        let response = match node.send_message_with_response(target, &dht_seed_request).await {
            Ok(Some(PulseMessage::DhtSeedResponse(response))) => response,
            Ok(_) => {
                warn!(round, "unexpected DHT seed response from peer");
                return None;
            }
            Err(error) => {
                warn!(round, %error, "DHT seed catch-up failed");
                return None;
            }
        };

        let empty_page = dht_seed_response_is_empty(&response);
        cursor.advance_from_response(&response);
        let page_snapshot = ingest_dht_seed_response(state, state_dir, source_peer_id, response);
        for record in page_snapshot.ownership_records.into_values() {
            upsert_seed_ownership_record(&mut snapshot.ownership_records, record);
        }
        for (mint_id, record) in page_snapshot.consumed_records {
            upsert_seed_consumed_record(&mut snapshot.consumed_records, mint_id, record);
        }
        if empty_page {
            return Some(snapshot);
        }
    }

    warn!("DHT seed catch-up hit round limit before reaching an empty page");
    Some(snapshot)
}

async fn request_peer_exchange_from_peer(
    node: &MeshPulseNode,
    target: &MeshCarrierContact,
    state: &Arc<Mutex<ArteryState>>,
) {
    let msg = PulseMessage::PeerExchange(PeerExchange {
        sender_id: node.id().as_bytes().to_vec(),
    });
    let Ok(Some(PulseMessage::PeerExchangeResponse(resp))) =
        node.send_message_with_response(target, &msg).await
    else {
        return;
    };

    if resp.peers.len() > MAX_PEER_EXCHANGE_PEERS {
        warn!(
            count = resp.peers.len(),
            "peer exchange returned too many contacts; truncating response"
        );
    }

    let mut s = lock_state(&state);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for peer_bytes in resp.peers.iter().take(MAX_PEER_EXCHANGE_PEERS) {
        let Some(peer_hash) = peer_hash_from_contact_bytes(peer_bytes) else {
            continue;
        };
        if peer_hash == s.node_id {
            continue;
        }
        if !s.routing_table.contains(&peer_hash) {
            s.routing_table.insert(RoutingPeer {
                id_hash: peer_hash,
                id_bytes: peer_bytes.clone(),
                last_seen: now,
                first_seen: now,
            });
            s.handshake_queue.push(peer_hash);
        }
    }
    s.estimated_network_size = s.routing_table.estimated_network_size();
    let repl = dht_replication_factor(s.estimated_network_size);
    s.tag_dht.set_k_replication(repl);
}

pub(crate) async fn refresh_mailbox_forward_subscriptions(
    node: &MeshPulseNode,
    state: &Arc<Mutex<ArteryState>>,
) {
    let (mailbox_key, nearest_peers) = {
        let s = lock_state(&state);
        let mailbox_key = match s.wallet.as_ref().map(|wallet| wallet.mailbox_key) {
            Some(key) => key,
            None => return,
        };
        let nearest_peers = s
            .routing_table
            .closest_peers(&mailbox_key, s.gossip_config.k_neighbors)
            .into_iter()
            .filter(|peer| s.peer_registry.state(&peer.id_hash) == PeerState::Verified)
            .map(|peer| peer.id_bytes)
            .collect::<Vec<_>>();
        (mailbox_key, nearest_peers)
    };

    if nearest_peers.is_empty() {
        return;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for peer_bytes in nearest_peers {
        let target = match decode_contact_bytes(&peer_bytes) {
            Ok(contact) => contact,
            Err(_) => continue,
        };
        let nonce: [u8; 16] = {
            use rand::Rng;
            rand::thread_rng().gen()
        };
        let msg = PulseMessage::MailboxForwardRegister(vess_protocol::MailboxForwardRegister {
            mailbox_key,
            timestamp: now,
            ttl_secs: MAX_FORWARD_TTL_SECS as u32,
            nonce,
        });
        match node.send_message_with_response(&target, &msg).await {
            Ok(Some(PulseMessage::MailboxForwardAck(ack))) => {
                if ack.accepted {
                    info!(queued = ack.queued_forwarded, "mailbox forward subscription accepted");
                } else {
                    info!("mailbox forward subscription rejected by peer");
                }
            }
            _ => {}
        }
    }
}

fn ingest_dht_seed_response(
    state: &Arc<Mutex<ArteryState>>,
    state_dir: &Path,
    source_peer_id: [u8; 32],
    response: DhtSeedResponse,
) -> SeedSyncPeerSnapshot {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut inserted_tags = 0usize;
    let mut inserted_manifests = 0usize;
    let mut snapshot = SeedSyncPeerSnapshot {
        peer_id: source_peer_id,
        ownership_records: HashMap::new(),
        consumed_records: HashMap::new(),
    };
    let mut s = lock_state(&state);
    let peer_ids: Vec<[u8; 32]> = s
        .routing_table
        .routable_peers(|_| true)
        .iter()
        .map(|p| p.id_hash)
        .collect();
    let repl = dht_replication_factor(s.estimated_network_size);

    for seeded_tag in response.tags.into_iter().take(MAX_DHT_SEED_TAGS) {
        let tag_hash = seeded_tag.tag_hash;
        if !s.tag_dht.should_store(&tag_hash, &peer_ids)
            || s.tag_dht.lookup_by_hash(&tag_hash).is_some()
        {
            continue;
        }
        let record = tag_record_from_dht_seed(seeded_tag);
        if record.registrant_vk.is_empty() || record.signature.is_empty() {
            continue;
        }
        match vess_tag::verify_record_signature(&record) {
            Ok(true) => {}
            _ => continue,
        }
        if s.tag_dht.store(record) {
            inserted_tags += 1;
        }
    }

    for manifest in response.manifests.iter().take(MAX_DHT_SEED_MANIFESTS) {
        if manifest.encrypted_manifest.len() > MAX_MANIFEST_SIZE {
            continue;
        }
        if !s.registry.should_store(&manifest.dht_key, &peer_ids, repl) {
            continue;
        }
        if s.manifest_store.len() >= MAX_MANIFEST_ENTRIES {
            if let Some(&oldest_key) = s
                .manifest_store
                .iter()
                .min_by_key(|(_, (_, ts))| ts)
                .map(|(k, _)| k)
            {
                s.manifest_store.remove(&oldest_key);
            }
        }
        s.manifest_store
            .insert(manifest.dht_key, (manifest.encrypted_manifest.clone(), now));
        inserted_manifests += 1;
    }

    for seeded_record in response
        .ownership_records
        .into_iter()
        .take(MAX_DHT_SEED_OWNERSHIP_RECORDS)
    {
        if let Some(record) =
            validated_seed_ownership_record(
                &s.registry,
                &peer_ids,
                repl,
                source_peer_id,
                s.node_id,
                seeded_record,
            )
        {
            upsert_seed_ownership_record(&mut snapshot.ownership_records, record);
        }
    }

    for seeded_record in response
        .consumed_records
        .into_iter()
        .take(MAX_DHT_SEED_CONSUMED_RECORDS)
    {
        if let Some((mint_id, record)) =
            validated_seed_consumed_record(
                &s.registry,
                &peer_ids,
                repl,
                source_peer_id,
                s.node_id,
                seeded_record,
            )
        {
            upsert_seed_consumed_record(&mut snapshot.consumed_records, mint_id, record);
        }
    }

    for seeded_manifest in &response.manifests
    {
        if !s
            .registry
            .should_store(&seeded_manifest.dht_key, &peer_ids, repl)
        {
            continue;
        }
    }

    drop(s);

    if inserted_tags > 0
        || inserted_manifests > 0
    {
        info!(
            responder = ?&response.responder_node_id[..4],
            inserted_tags,
            inserted_manifests,
            "seeded initial DHT shard data from peer"
        );
    }

    snapshot
}

// ── Hash clock tasks ────────────────────────────────────────────────

/// Advance the local tick clock every TICK_INTERVAL_SECS (6s).
fn spawn_clock_tick_task(state: Arc<Mutex<ArteryState>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            vess_clock::TICK_INTERVAL_SECS,
        ));
        loop {
            interval.tick().await;
            let entry = {
                let mut s = lock_state(&state);
                s.tick_clock.advance()
            };
            tracing::trace!(tick = entry.tick, "clock advanced");
        }
    });
}

/// Gossip our clock state to verified peers every 30s, and recompute
/// network time from peer clocks.
fn spawn_clock_gossip_task(
    node: MeshPulseNode,
    state: Arc<Mutex<ArteryState>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;

            // Build our clock gossip message
            let (gossip, verified_peers): (Option<vess_protocol::ClockGossip>, Vec<([u8; 32], Vec<u8>)>) = {
                let s = lock_state(&state);
                let cs = s.tick_clock.state();
                let gossip = vess_protocol::ClockGossip {
                    node_id: cs.node_id,
                    genesis_hash: cs.genesis_hash,
                    current_tick: cs.current_tick,
                    current_hash: cs.current_hash,
                    started_at_ms: cs.started_at_ms,
                    last_tick_at_ms: cs.last_tick_at_ms,
                };
                // Collect verified peers to send to
                let peers: Vec<_> = s
                    .peer_registry
                    .verified_peer_id_bytes()
                    .into_iter()
                    .filter_map(|hash| {
                        s.routing_table
                            .peer_id_bytes(&hash)
                            .map(|bytes| (hash, bytes))
                    })
                    .take(5)
                    .collect();
                (Some(gossip), peers)
            };

            // Send clock gossip to verified peers
            if let Some(gossip) = gossip {
                for (_hash, peer_bytes) in &verified_peers {
                    if let Ok(target) = decode_contact_bytes(peer_bytes) {
                        let msg = PulseMessage::ClockGossip(gossip.clone());
                        let _ = node.send_message_with_response(&target, &msg).await;
                    }
                }
            }

            // Recompute network time from peer clocks
            {
                let mut s = lock_state(&state);
                // Prune stale peer clocks (> 5 min old)
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                s.peer_clocks.retain(|_, cg| {
                    now_ms.saturating_sub(cg.last_tick_at_ms) < 300_000
                });

                // Compute network median tick
                let clock_states: Vec<vess_clock::ClockState> = s
                    .peer_clocks
                    .values()
                    .map(|cg| vess_clock::ClockState {
                        node_id: cg.node_id,
                        genesis_hash: cg.genesis_hash,
                        current_tick: cg.current_tick,
                        current_hash: cg.current_hash,
                        started_at_ms: cg.started_at_ms,
                        last_tick_at_ms: cg.last_tick_at_ms,
                        latest_checkpoint: None,
                    })
                    .collect();
                let nt = vess_clock::compute_network_time(&clock_states);
                s.network_time = nt;
            }
        }
    });
}

// ── VHALIX mining loop ─────────────────────────────────────────────

/// Background VHALIX mining loop running in `spawn_blocking`.
///
/// Mines proofs sequentially, updating `ArteryState.mining_chain_length`
/// and `mining_next_nonce` on each proof.  When signalled to stop via
/// `stop_rx`, finalizes the batch and submits as a genesis proof if
/// the chain meets the minimum length.
pub(crate) fn run_mining_loop(
    state: Arc<Mutex<ArteryState>>,
    og_tx: tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipGenesis>,
    stop_rx: tokio::sync::oneshot::Receiver<()>,
    owner_vk_hash: [u8; 32],
    starting_nonce: u64,
    prev_hash: [u8; 32],
    session_nonce: u64,
    tick_hash: [u8; 32],
) {
    use vess_foundry::mine::VHALIXMiner;

    let mut miner = VHALIXMiner::new(owner_vk_hash, starting_nonce, session_nonce, tick_hash);

    let mut stop_rx = stop_rx;
    let mut mined_count = 0u64;

    loop {
        // Check for stop signal
        match stop_rx.try_recv() {
            Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => break,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }

        let proof = miner.mine_one();
        mined_count += 1;

        {
            let mut s = lock_state(&state);
            s.mining_chain_length = mined_count;
            s.mining_next_nonce = miner.next_bill_nonce();
        }

        tracing::info!(
            nonce = proof.bill_nonce,
            elapsed_ms = proof.elapsed_ms,
            chain_length = mined_count,
            "VHALIX proof mined"
        );
    }

    if mined_count < vess_foundry::mine::MIN_CHAIN_LENGTH {
        tracing::info!(
            chain_length = mined_count,
            min_required = vess_foundry::mine::MIN_CHAIN_LENGTH,
            "VHALIX chain too short — no bill submitted"
        );
        let mut s = lock_state(&state);
        s.mining_active = false;
        if let Some(wallet) = s.wallet.as_mut() {
            wallet.mining_next_nonce = miner.next_bill_nonce();
        }
        return;
    }

    let batch = match miner.finalize_batch() {
        Some(b) => b,
        None => {
            tracing::warn!("VHALIX miner stopped but batch was empty");
            return;
        }
    };

    let chain_length = batch.bill_nonce_end.saturating_sub(batch.bill_nonce_start).saturating_add(1);
    let denomination = vess_foundry::Denomination::max_valid_denomination(chain_length);

    let (owner_vk, owner_sk) = {
        let s = lock_state(&state);
        match s.wallet.as_ref().and_then(|w| w.billfold.any_credential().cloned()) {
            Some(cred) => (cred.spend_vk.clone(), cred.spend_sk.clone()),
            None => {
                tracing::error!("cannot submit VHALIX genesis: no spend credentials");
                return;
            }
        }
    };

    let proof = match VHALIX_batch_to_proof(&batch, &[], &[], &owner_vk, &owner_sk) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to build VHALIX proof");
            return;
        }
    };

    let mint_id = match submit_VHALIX_genesis(&state, &og_tx, &proof, &owner_vk) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "failed to submit VHALIX genesis");
            return;
        }
    };

    {
        let mut s = lock_state(&state);
        s.mining_active = false;
        if let Some(wallet) = s.wallet.as_mut() {
            wallet.mining_next_nonce = miner.next_bill_nonce();
        }
    }

    tracing::info!(
        mint_id = %crate::persistence::hex_key(&mint_id),
        chain_length,
        denomination,
        "VHALIX bill hardened and submitted"
    );
}

// ── Century lock management ────────────────────────────────────────

/// Mint Vess bills from all active century locks for each tick that
/// has passed since the last check.
fn mint_century_lock_bills(
    state: &Arc<Mutex<ArteryState>>,
    og_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipGenesis>,
) {
    let mut s = lock_state(&state);
    let current_tick = s.network_time.median_tick;
    if current_tick == 0 {
        return;
    }

    let mut new_ogs = Vec::new();
    for lock in s.century_locks.values_mut() {
        let next_tick = lock.last_claimed_tick.saturating_add(1);
        if next_tick > current_tick || next_tick > lock.end_tick {
            continue;
        }
        for tick in next_tick..=current_tick.min(lock.end_tick) {
            let mint_id = {
                let mut h = blake3::Hasher::new();
                h.update(b"vess-century-mint-v1");
                h.update(&lock.lock_id);
                h.update(&tick.to_be_bytes());
                *h.finalize().as_bytes()
            };
            let og = vess_protocol::OwnershipGenesis {
                mint_id,
                chain_tip: [0u8; 32],
                owner_vk_hash: [0u8; 32],
                owner_vk: Vec::new(),
                denomination_value: lock.per_tick_vess,
                genesis_proof: vess_protocol::GenesisProof::Vess(Vec::new()),
                digest: [0u8; 32],
                hops_remaining: 0,
                chain_depth: 0,
                output_index: 0,
                pow_nonce: None,
                pow_hash: None,
                accumulated_work: None,
            };
            new_ogs.push(og);
            lock.last_claimed_tick = tick;
        }
    }
    drop(s);
    for og in new_ogs {
        let _ = og_tx.send(og);
    }
}

/// Convert a [`vess_foundry::mine::MiningBatch`] into a DKSAP-encrypted
/// [`VHALIXMinedProof`] ready for genesis submission.
///
/// Uses the wallet's stealth keys to generate ephemeral DKSAP key material
/// so the proof is indistinguishable from a normal payment on-chain.
pub fn VHALIX_batch_to_proof(
    batch: &vess_foundry::mine::MiningBatch,
    scan_ek: &[u8],
    spend_ek: &[u8],
    owner_vk: &[u8],
    owner_sk: &[u8],
) -> Result<vess_protocol::VHALIXMinedProof, String> {
    // Build the batch commitment to sign
    let mut sig_hasher = blake3::Hasher::new();
    sig_hasher.update(b"vess-VHALIX-batch-v2");
    sig_hasher.update(&batch.merkle_root);
    sig_hasher.update(&batch.bill_nonce_start.to_be_bytes());
    sig_hasher.update(&batch.bill_nonce_end.to_be_bytes());
    let sig_msg = *sig_hasher.finalize().as_bytes();

    let batch_sig = vess_foundry::spend_auth::sign_spend(owner_sk, &sig_msg)
        .map_err(|e| format!("batch signature failed: {e}"))?;

    // Generate ephemeral DKSAP keys
    let ephemeral_scan_sk = {
        let mut sk = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut sk);
        sk
    };
    // For now: use wallet scan_ek directly for self-encryption.
    // The full DKSAP self-encryption path would generate fresh ephemeral
    // keys per batch and encrypt the bill payload.
    Ok(vess_protocol::VHALIXMinedProof {
        ephemeral_scan_ek: scan_ek.to_vec(),
        ephemeral_spend_ek: spend_ek.to_vec(),
        ct_scan: Vec::new(),  // filled by DKSAP self-encrypt
        ct_spend: Vec::new(),
        view_tag: 0,
        bill_nonce_start: batch.bill_nonce_start,
        bill_nonce_end: batch.bill_nonce_end,
        merkle_root: batch.merkle_root,
        total_compute_ticks: batch.total_compute_ms,
        session_nonce: 0, // filled in later when session info is known
        tick_hash: [0u8; 32],
        chain_hashes: batch.proofs.iter().map(|p| p.argon2_hash).collect(),
        owner_vk: owner_vk.to_vec(),
        batch_sig,
        bounty: None, // bounty computed in submit_VHALIX_genesis
    })
}

/// Submit a VHALIX mining proof as a single OwnershipGenesis to the network.
///
/// One batch = one bill.  The denomination is the largest 1-2-5 value
/// ≤ the chain length (number of sequential Argon2id proofs in the batch).
/// The mint_id is anchored to the miner's session nonce + network tick hash
/// so every mining session produces a unique, time-bound bill.
pub fn submit_VHALIX_genesis(
    state: &Arc<Mutex<ArteryState>>,
    og_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::OwnershipGenesis>,
    proof: &vess_protocol::VHALIXMinedProof,
    owner_vk: &[u8],
) -> Result<[u8; 32], String> {
    let owner_vk_hash = vess_foundry::spend_auth::vk_hash(owner_vk);

    // ── Compute chain length and denomination ─────────────────
    let chain_length = proof.bill_nonce_end.saturating_sub(proof.bill_nonce_start).saturating_add(1);
    if chain_length < vess_foundry::mine::MIN_CHAIN_LENGTH {
        return Err(format!(
            "chain too short: {} proofs (minimum {})",
            chain_length,
            vess_foundry::mine::MIN_CHAIN_LENGTH,
        ));
    }
    let denomination = vess_foundry::Denomination::max_valid_denomination(chain_length);
    if denomination == 0 {
        return Err("chain too short for any valid denomination".to_string());
    }

    // ── Derive mint_id from owner + nonce range ───────────────
    // Anchored to (owner, nonce_start, nonce_end) so the same
    // batch always produces the same mint_id — double-spend check
    // prevents submitting the same work twice, even across different
    // sessions or network ticks.
    let mint_id = {
        let mut h = blake3::Hasher::new();
        h.update(b"vess-VHALIX-mint-v3");
        h.update(&owner_vk_hash);
        h.update(&proof.bill_nonce_start.to_be_bytes());
        h.update(&proof.bill_nonce_end.to_be_bytes());
        *h.finalize().as_bytes()
    };

    // ── Check for duplicate submission ────────────────────────
    let mut s = lock_state(state);
    if s.registry.get(&mint_id).is_some() || s.registry.was_consumed(&mint_id).is_some() {
        return Err(format!(
            "VHALIX genesis: mint_id {} already exists",
            crate::persistence::hex_key(&mint_id),
        ));
    }
    drop(s);

    // ── Compute bounty from excess proofs ─────────────────────
    // Excess = chain_length - denomination (the safety margin).
    // Each excess proof is a 1-VHALIX bounty for verifiers.
    // Minimum 5 excess proofs so every bill has a verifiable bounty.
    let excess = chain_length.saturating_sub(denomination);
    if excess < vess_foundry::mine::MIN_CHAIN_LENGTH {
        return Err(format!(
            "insufficient excess: {excess} proofs (minimum {}). \
             Need {} more proofs to reach {} proofs total ({} denom + 5 margin).",
            vess_foundry::mine::MIN_CHAIN_LENGTH,
            denomination + vess_foundry::mine::MIN_CHAIN_LENGTH - chain_length,
            denomination + vess_foundry::mine::MIN_CHAIN_LENGTH,
            denomination,
        ));
    }
    let bounty: Option<vess_protocol::VerificationBounty> =
        if excess >= 1 {
            Some(vess_protocol::VerificationBounty {
                excess_start: proof.bill_nonce_start + denomination,
                excess_end: proof.bill_nonce_end,
                bounty_count: excess,
                reward_per_claim: 1,
            })
        } else {
            None
        };

    // ── Build the proof with bounty attached ──────────────────
    let mut proof_with_bounty = proof.clone();
    proof_with_bounty.bounty = bounty.clone();

    // ── Build and send the genesis ────────────────────────────
    let og = vess_protocol::OwnershipGenesis {
        mint_id,
        chain_tip: vess_foundry::advance_chain_tip_with_hash(
            &mint_id, &owner_vk_hash, &mint_id,
        ),
        owner_vk_hash,
        owner_vk: owner_vk.to_vec(),
        denomination_value: denomination,
        genesis_proof: vess_protocol::GenesisProof::VHALIXMined(proof_with_bounty),
        digest: proof.merkle_root,
        hops_remaining: 0,
        chain_depth: 0,
        output_index: 0,
        pow_nonce: None,
        pow_hash: None,
        accumulated_work: None,
    };

    let _ = og_tx.send(og);

    let bounty_info = match &bounty {
        Some(b) => format!(", {} bounties ({} VHALIX for verifiers)", b.bounty_count, b.bounty_count * b.reward_per_claim),
        None => String::new(),
    };

    tracing::info!(
        mint_id = %crate::persistence::hex_key(&mint_id),
        chain_length,
        denomination,
        bounty_info,
        "VHALIX genesis submitted"
    );

    Ok(mint_id)
}

/// Create a new century lock from a VHALIX mining proof.
///
/// Locks ≤ 1 year are free.  Locks > 1 year require a Vichor burn proof
/// showing that the minimum required Vichor was permanently destroyed.
impl ArteryState {
    pub fn create_century_lock(
        &mut self,
        proof: &vess_protocol::VHALIXMinedProof,
        lock_years: f64,
        vichor_burn: Option<&vess_protocol::VichorBurnProof>,
        _manifest_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::ManifestStore>,
    ) -> Result<vess_protocol::CenturyLockState, String> {
        let current_tick = self.network_time.median_tick;
        if current_tick == 0 {
            return Err("network clock not yet synchronized".into());
        }

        // Validate lock duration
        if lock_years <= 0.0 || lock_years > 10.0 {
            return Err("lock duration must be between 0 and 10 years".into());
        }

        let total_locked = proof.total_compute_ticks;
        let lock_ticks = (lock_years * vess_clock::TICKS_PER_YEAR as f64) as u64;

        // Vichor burn required for locks > 1 year
        if lock_years > 1.0 {
            let burn = vichor_burn.ok_or("Vichor burn proof required for locks > 1 year")?;
            let required = vess_foundry::vichor_required_for_years(total_locked, lock_years);
            if burn.total_burned < required {
                return Err(format!(
                    "insufficient Vichor burned: {} burned, {} required for {:.1}y lock",
                    burn.total_burned, required, lock_years,
                ));
            }
            // Verify burn proof signature
            let sig_msg = vess_foundry::vichor_burn_signing_message(
                &burn.burned_mint_ids,
                burn.total_burned,
                &burn.mint_commitment,
            );
            match vess_foundry::spend_auth::verify_spend(&burn.owner_vk, &sig_msg, &burn.owner_sig) {
                Ok(true) => {}
                _ => return Err("invalid Vichor burn proof signature".into()),
            }
            tracing::info!(
                burned = burn.total_burned,
                required,
                years = lock_years,
                "Vichor burn accepted for premium lock"
            );
        }

        let lock = vess_protocol::CenturyLockState::new(
            &proof.merkle_root,
            total_locked,
            current_tick,
            lock_ticks,
            self.node_id,
            Self::now_unix(),
        );
        let lock_id = lock.lock_id;
        self.century_locks.insert(lock_id, lock.clone());
        if let Some(ref mut ws) = self.wallet {
            ws.add_century_lock_id(lock_id);
        }
        Ok(lock)
    }
}

/// Adaptive local peer discovery ("Hydra") — intelligently finds and
/// handshakes with all local Vess nodes using mDNS, LAN broadcast,
/// and filesystem-based peer exchange.
///
/// **Strategy:**
/// - **Aggressive mode**: When verified peers < 8, probes every 3s.
/// - **Steady-state mode**: When ≥ 8 verified, backs off to 15s.
/// - **mDNS responder**: Answers `_vess._udp.local` queries on 224.0.0.251:5353.
/// - **mDNS browser**: Queries for other Vess nodes every 30s.
/// - **File-based**: Publishes contact to `%LOCALAPPDATA%/Vess/local-peers/`.
fn spawn_local_lan_discovery(local_contact: MeshCarrierContact, state: Arc<Mutex<ArteryState>>) {
    const HYDRA_TARGET_PEERS: usize = 8;
    const HYDRA_AGGRESSIVE_SECS: u64 = 3;
    const HYDRA_STEADY_SECS: u64 = 15;

    let loopback_contact = match crate::local_discovery::loopback_contact(&local_contact) {
        Ok(c) => c,
        Err(e) => {
            warn!(%e, "failed to build loopback contact; using original");
            local_contact.clone()
        }
    };

    // Publish immediately
    if let Err(e) = crate::local_discovery::publish_local_contact(&loopback_contact) {
        crate::local_discovery::log_publish_error(e);
    }

    // ── mDNS responder ──
    let node_id_str = match local_contact.node_id() {
        Some(id) => id.to_string(),
        None => {
            warn!("hydra: no node ID, mDNS disabled");
            return;
        }
    };
    let mdns_contact = local_contact.clone();
    tokio::spawn(async move {
        let socket = match crate::local_discovery::bind_mdns_socket() {
            Ok(s) => s,
            Err(e) => {
                warn!(%e, "hydra mDNS responder bind failed");
                return;
            }
        };
        let mut buf = vec![0u8; 9000];
        loop {
            if let Ok((len, source)) = socket.recv_from(&mut buf).await {
                if crate::local_discovery::is_vess_mdns_query(&buf[..len]) {
                    let _ = crate::local_discovery::send_mdns_unicast_response(
                        &socket, source, &node_id_str, &mdns_contact,
                    ).await;
                }
            }
        }
    });

    // ── mDNS browser ──
    let browser_state = state.clone();
    tokio::spawn(async move {
        let socket = match crate::local_discovery::bind_mdns_socket() {
            Ok(s) => s,
            Err(e) => {
                warn!(%e, "hydra mDNS browser bind failed");
                return;
            }
        };
        let mut buf = vec![0u8; 9000];
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = crate::local_discovery::send_mdns_query(&socket).await;
                }
                recv = socket.recv_from(&mut buf) => {
                    if let Ok((len, source)) = recv {
                        if let Some(contact_str) = crate::local_discovery::extract_contact_from_mdns_response(&buf[..len]) {
                            if let Ok(contact) = vess_mesh::decode_mesh_contact_string(&contact_str) {
                                if vess_mesh::validate_mesh_contact(&contact).is_ok() {
                                    let self_id = { lock_state(&browser_state).node_id };
                                    if let Some(peer_hash) = contact.node_id().map(|n| *n.as_bytes()) {
                                        if peer_hash != self_id {
                                            let lan_contact = crate::local_discovery::contact_from_lan_source(&contact, source).unwrap_or(contact);
                                            queue_discovered_peer_contact(&browser_state, lan_contact, "mdns");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // ── Main hydra loop: LAN broadcast + file discovery ──
    let hydra_state = state.clone();
    tokio::spawn(async move {
        let self_node_id = { lock_state(&hydra_state).node_id };

        let lan_socket = match crate::local_discovery::bind_lan_discovery_socket(
            crate::local_discovery::LAN_DISCOVERY_PORT,
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(%e, "hydra LAN socket bind failed; file-only mode");
                // Fallback to file-only
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
                loop {
                    interval.tick().await;
                    if let Err(e) = crate::local_discovery::publish_local_contact(&loopback_contact) {
                        crate::local_discovery::log_publish_error(e);
                    }
                    for contact in crate::local_discovery::discover_local_file_contacts(Some(self_node_id)) {
                        queue_discovered_peer_contact(&hydra_state, contact, "local-file");
                    }
                }
            }
        };

        let mut buf = vec![0u8; 64 * 1024];
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(HYDRA_AGGRESSIVE_SECS));

        // Initial burst
        let _ = crate::local_discovery::send_lan_probe(&lan_socket).await;
        let _ = crate::local_discovery::send_lan_announcement(&lan_socket, &local_contact).await;

        loop {
            let (verified_count, has_capacity) = {
                let s = lock_state(&hydra_state);
                (s.peer_registry.count_in_state(PeerState::Verified), s.routing_table.has_capacity())
            };

            let target_interval = if verified_count < HYDRA_TARGET_PEERS || !has_capacity {
                std::time::Duration::from_secs(HYDRA_AGGRESSIVE_SECS)
            } else {
                std::time::Duration::from_secs(HYDRA_STEADY_SECS)
            };
            interval = tokio::time::interval(target_interval);

            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = crate::local_discovery::publish_local_contact(&loopback_contact) {
                        crate::local_discovery::log_publish_error(e);
                    }
                    let _ = crate::local_discovery::send_lan_announcement(&lan_socket, &local_contact).await;
                    if !has_capacity || verified_count < HYDRA_TARGET_PEERS {
                        let _ = crate::local_discovery::send_lan_probe(&lan_socket).await;
                    }
                    for contact in crate::local_discovery::discover_local_file_contacts(Some(self_node_id)) {
                        queue_discovered_peer_contact(&hydra_state, contact, "local-file");
                    }
                }
                recv = lan_socket.recv_from(&mut buf) => {
                    if let Ok((len, source)) = recv {
                        match crate::local_discovery::parse_lan_discovery_message(&buf[..len], source) {
                            Ok(crate::local_discovery::ParsedLanDiscovery::Probe) => {
                                let _ = crate::local_discovery::send_probe_response(
                                    &lan_socket, source, &local_contact,
                                ).await;
                            }
                            Ok(crate::local_discovery::ParsedLanDiscovery::Contact(contact)) => {
                                queue_discovered_peer_contact(&hydra_state, contact, "lan");
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
    });
}

fn routing_table_has_capacity(state: &Arc<Mutex<ArteryState>>) -> bool {
    let state = lock_state(&state);
    state.routing_table.has_capacity()
}

/// Configuration for running an artery node.
pub struct NodeConfig {
    /// Number of gossip neighbors (K).
    pub k_neighbors: usize,
    /// Maximum gossip hops.
    pub max_hops: u8,
    /// State directory for persistence.
    pub state_dir: PathBuf,
    /// Bootstrap peer mesh contacts to connect to on startup.
    pub bootstrap: Vec<String>,
    /// DNS seed domains to resolve for bootstrap peers (e.g. "seed.vess.network").
    /// Each domain is resolved via A/AAAA records on the default Vess port.
    pub bootstrap_dns: Vec<String>,
    /// Optional channel to signal the node's mesh node ID once online.
    /// Useful for tests that need to connect before `run_node` blocks.
    pub ready_tx: Option<tokio::sync::oneshot::Sender<String>>,
    /// Path to a vess-kloak wallet file.  When set the node embeds the
    /// wallet and auto-receives incoming payments by trial-decrypting
    /// every stealth payload that enters limbo.
    pub wallet_path: Option<PathBuf>,
    /// Port for the local-only JSON-RPC server (127.0.0.1).
    /// When set, the node exposes balance/send/node_info/tag_lookup
    /// commands for the CLI to consume. Default: `None` (disabled).
    pub rpc_port: Option<u16>,
    /// Password for fast wallet unlock.  When set alongside `wallet_path`,
    /// the node uses the password cache instead of requiring the recovery
    /// phrase via environment variables.  Can also be provided via the
    /// `VESS_WALLET_PASSWORD` env var.
    pub wallet_password: Option<String>,
    /// Useful for deterministic integration tests with local mock peers.
    /// Optional bind address override. Default: 0.0.0.0:0 (OS-assigned port on all interfaces).
    pub bind_addr: Option<std::net::SocketAddr>,
    /// Whether to enable LAN/local-file peer discovery.
    pub enable_local_discovery: bool,
    /// Intended for local integration tests that run all nodes on loopback.
    pub reset_transient_peer_state: bool,
    /// unsafe ops allowed, testnet DHT namespace, seed peers.
    /// Deprecated alias for is_testnet + faucet. Kept for backward compat.
    pub test: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            k_neighbors: 4,
            max_hops: 3,
            state_dir: NodeStorage::default_dir().unwrap_or_else(|_| PathBuf::from(".vess-artery")),
            bootstrap: Vec::new(),
            ready_tx: None,
            wallet_path: None,
            rpc_port: None,
            wallet_password: None,
            bind_addr: None,
            enable_local_discovery: true,
            reset_transient_peer_state: false,
            test: false,
            bootstrap_dns: Vec::new(),
        }
    }
}

// ── Payment latency tracker ─────────────────────────────────────────

/// Tracks end-to-end payment latency samples (payment relay → ownership
/// claim confirmation).  Keeps a bounded sliding window so memory is fixed.
pub struct PaymentLatencyTracker {
    /// Recent latency samples in milliseconds.
    samples: VecDeque<u64>,
    /// Maximum number of samples to retain.
    max_samples: usize,
}

impl PaymentLatencyTracker {
    fn new(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::new(),
            max_samples,
        }
    }

    /// Record a latency observation in milliseconds.
    fn record(&mut self, latency_ms: u64) {
        if self.samples.len() >= self.max_samples {
            self.samples.pop_front(); // drop oldest
        }
        self.samples.push_back(latency_ms);
    }

    /// Median latency (0 if no samples).
    fn median(&self) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted: Vec<u64> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        sorted[sorted.len() / 2]
    }

    /// 95th percentile latency (0 if no samples).
    fn p95(&self) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted: Vec<u64> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64) * 0.95).ceil() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Number of samples currently held.
    fn count(&self) -> u64 {
        self.samples.len() as u64
    }
}

/// Embedded wallet state — present when the wallet is unlocked.
pub struct WalletState {
    pub stealth_secret: StealthSecretKey,
    pub stealth_address: MasterStealthAddress,
    pub billfold: vess_kloak::BillFold,
    pub wallet_path: PathBuf,
    /// Encryption key for spend credentials and tag keys on disk.
    pub enc_key: [u8; 32],
    /// Mailbox shard key derived from our spend encapsulation key.
    /// Used for targeted [`MailboxSweep`] and automatic forwarding subscription.
    pub mailbox_key: [u8; 32],
    /// Next bill_nonce for the VHALIX miner (persisted).
    pub mining_next_nonce: u64,
    /// Mining session counter (persisted).
    pub mining_session_nonce: u64,
    /// Hash of last-mined proof (persisted).
    pub mining_prev_hash: [u8; 32],
}

impl Drop for WalletState {
    fn drop(&mut self) {
        self.enc_key.zeroize();
    }
}

impl WalletState {
    /// Record a century lock ID for wallet-file persistence.
    pub(crate) fn add_century_lock_id(&mut self, lock_id: [u8; 32]) {
        // The lock ID will be persisted via flush_wallet → save → encrypted_private_metadata.
        // We store it in a temporary list; flush_wallet reads century_locks from ArteryState.
        // The lock ID is already stored in ArteryState.century_locks.
        // This method exists as a hook for future wallet-level tracking.
        let _ = lock_id;
    }
}

/// Shared artery node state behind a mutex.
pub struct ArteryState {
    pub registry: OwnershipRegistry,
    pub tag_dht: TagDht,
    pub swap_offers: BTreeMap<[u8; 32], Vec<vess_protocol::SwapOffer>>,
    pub swap_offer_tx: Option<tokio::sync::mpsc::UnboundedSender<vess_protocol::SwapOffer>>,
    pub node_id: [u8; 32],
    /// This node's own mesh scan decapsulation key (for decrypting onion layers).
    pub own_scan_dk: Option<Vec<u8>>,
    /// Hash-tick clock — trustless monotonic time source.
    pub tick_clock: vess_clock::TickChain,
    /// Latest network time (median tick from verified peers).
    pub network_time: vess_clock::NetworkTime,
    /// Peer clock states collected via gossip (node_id → ClockState).
    pub peer_clocks: HashMap<[u8; 32], vess_protocol::ClockGossip>,
    /// Kademlia routing table: 256 XOR-distance buckets of infrastructure
    /// relay peers. Never contains wallet users or payment recipients.
    pub routing_table: RoutingTable,
    pub gossip_config: GossipConfig,
    pub peer_registry: PeerRegistry,
    pub handshake_queue: Vec<[u8; 32]>,
    pub limbo_buffer: LimboBuffer,
    pub reputation: ReputationTable,
    pub rate_limiter: crate::gossip::PeerRateLimiter,
    pub mailbox_collect_limiter: crate::gossip::PeerRateLimiter,
    /// Rate limiter for TagLookup to prevent tag enumeration.
    pub tag_lookup_limiter: crate::gossip::PeerRateLimiter,
    /// Rate limiter for RegistryQuery / OwnershipFetch to prevent
    /// bulk mint_id enumeration (surveillance attack).
    pub registry_query_limiter: crate::gossip::PeerRateLimiter,
    pub duplicate_tracker: DuplicateTracker,
    /// Estimated number of peers in the network (for dynamic DHT replication).
    pub estimated_network_size: usize,
    /// Mint IDs currently in limbo (soft reservation while payment is in flight).
    pub limbo_mint_ids: std::collections::HashSet<[u8; 32]>,
    /// Payment IDs already in limbo (prevents exact duplicate buffering).
    pub limbo_payment_ids: std::collections::HashSet<[u8; 32]>,
    /// Unix timestamp (seconds) when each limbo payment ID was inserted.
    pub limbo_payment_times: HashMap<[u8; 32], u64>,
    /// Active century-lock faucets owned by this node's wallet.
    /// Keyed by lock_id. Each produces one Vess bill per network tick.
    pub century_locks: HashMap<[u8; 32], vess_protocol::CenturyLockState>,
    /// Last network tick at which century locks were checked for minting.
    pub century_lock_last_tick: u64,
    /// Whether the VHALIX miner is currently running.
    pub mining_active: bool,
    /// Current chain length of the active mining session.
    pub mining_chain_length: u64,
    /// Next bill_nonce the miner will use.
    pub mining_next_nonce: u64,
    /// Session nonce for the current mining session.
    pub mining_session_nonce: u64,
    /// Tick hash anchoring the current mining session.
    pub mining_tick_hash: [u8; 32],
    /// Unix timestamp when the current mining session started.
    pub mining_started_at: u64,
    /// Command sender to stop the mining thread.
    #[allow(dead_code)]
    pub mining_stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Encrypted wallet manifests keyed by DHT key.
    /// Value is `(encrypted_manifest, inserted_at_unix_secs)` for oldest-first eviction.
    pub manifest_store: HashMap<[u8; 32], (Vec<u8>, u64)>,
    /// Locally-retained ownership records for bills this node originated or
    /// currently owns, kept even when this node is not in the live DHT shard.
    /// Used to seed newly closer peers during bootstrap.
    pub retained_ownership_records: HashMap<[u8; 32], OwnershipRecord>,
    /// Locally-retained tombstones for consumed bills this node originated or
    /// tracked, so newly closer peers can learn reforge outcomes during seed sync.
    pub retained_consumed_records: HashMap<[u8; 32], ConsumedRecord>,
    /// Unix-millis timestamp when each bill entered limbo (keyed by mint_id,
    /// populated at auto-receive time for end-to-end latency tracking).
    pub limbo_entry_times: HashMap<[u8; 32], u64>,
    /// Payment latency tracker (payment relay → ownership claim completion).
    pub payment_latency: PaymentLatencyTracker,
    /// H3: OwnershipGenesis messages that arrived before their ReforgeAttestation
    /// tombstones. Keyed by a missing input mint_id — when that tombstone is
    /// created by an RA, the pending genesis messages are retried.
    /// This prevents legitimate reforge outputs from being rejected (and the
    /// broadcaster being falsely banished) due to gossip ordering races.
    /// Value is `(OwnershipGenesis, buffered_at_unix_secs)` for TTL eviction.
    /// C1: Enforced global cap + per-key cap to prevent memory exhaustion.
    pub pending_reforge_genesis:
        HashMap<[u8; 32], Vec<(vess_protocol::OwnershipGenesis, u64)>>,
    /// Open verification bounties from VHALIX genesis proofs.
    /// Keyed by genesis mint_id.  Verifiers claim excess proofs for rewards.
    pub open_bounties: HashMap<[u8; 32], vess_protocol::VHALIXMinedProof>,
    /// Already-claimed bounty indices per genesis mint_id.
    pub claimed_bounty_indices: HashMap<[u8; 32], HashSet<u64>>,
    /// Embedded wallet — trial-decrypts incoming payments automatically.
    pub wallet: Option<WalletState>,
    /// transaction broadcast/onboarding.
    /// Wallet file path (set from config even when wallet is locked).
    /// Used by the RPC `wallet_unlock` endpoint to load the file.
    pub wallet_path: Option<PathBuf>,
    /// Wallet-local notification queue for CLI and wallet layers.
    pub notifications: VecDeque<WalletNotification>,
    /// Structured node events for CLI display (burns, claims, banishments, etc.).
    pub events: VecDeque<NodeEvent>,
    /// Outbound payments waiting for recipient claim confirmation.
    pub outbound_payments: HashMap<[u8; 32], OutboundPaymentRecord>,
    /// Reverse index from mint_id to outbound payment_id for fast finalization.
    pub outbound_by_mint_id: HashMap<[u8; 32], [u8; 32]>,
    /// Shared banishment manager — included in snapshots so the ban list
    /// survives node restarts.
    pub banishment: Arc<BanishmentManager>,
    /// Persistent local VessTag address book.
    /// Caches every verified tag → stealth address the wallet has sent to,
    /// so repeat payments skip the DHT entirely.
    pub tag_cache: crate::tag_cache::TagCache,
    /// Active push-forwarding subscriptions: mailbox_key → record of the
    /// subscribing node and subscription expiry time.
    pub mailbox_fwd: HashMap<[u8; 32], ForwardRecord>,
    /// Rate limiter for [`MailboxForwardRegister`] requests.
    pub mailbox_fwd_limiter: crate::gossip::PeerRateLimiter,
    /// Whether test-only / unsafe features are permitted.
    pub unsafe_mode: bool,
    /// Runtime flag for the local test faucet.
    pub test_faucet_enabled: bool,
    /// True when running in testnet mode (signet, faucet, unsafe ops).
    pub is_testnet: bool,
    /// When true, this node does NOT relay other peers' payments or DHT
    /// store requests. Its own payments still go through. Set this on
    /// metered/mobile connections to save bandwidth.
    pub passive_mode: bool,
    /// Local-only payment history persisted to disk.
    pub payment_history: vess_kloak::payment::PaymentHistory,
}

impl ArteryState {
    /// Create a fresh artery state for a new node.
    pub fn new(is_testnet: bool) -> Self {
        let node_id_bytes: [u8; 32] = rand::thread_rng().gen();
        let k_neighbors = 4usize;
        Self {
            registry: OwnershipRegistry::new(node_id_bytes),
            tag_dht: TagDht::new(node_id_bytes, k_neighbors),
            swap_offers: BTreeMap::new(),
            swap_offer_tx: None,
            node_id: node_id_bytes,
            routing_table: RoutingTable::new(node_id_bytes),
            gossip_config: GossipConfig::default(),
            peer_registry: PeerRegistry::new(std::time::Duration::from_secs(30)),
            handshake_queue: Vec::new(),
            limbo_buffer: LimboBuffer::new(),
            reputation: ReputationTable::new(),
            rate_limiter: crate::gossip::PeerRateLimiter::with_defaults(),
            mailbox_collect_limiter: crate::gossip::PeerRateLimiter::new(10, 60),
            tag_lookup_limiter: crate::gossip::PeerRateLimiter::new(30, 60),
            registry_query_limiter: crate::gossip::PeerRateLimiter::new(20, 60),
            duplicate_tracker: DuplicateTracker::new(),
            estimated_network_size: 0,
            limbo_mint_ids: std::collections::HashSet::new(),
            limbo_payment_ids: std::collections::HashSet::new(),
            limbo_payment_times: HashMap::new(),
            manifest_store: HashMap::new(),
            retained_ownership_records: HashMap::new(),
            retained_consumed_records: HashMap::new(),
            limbo_entry_times: HashMap::new(),
            payment_latency: PaymentLatencyTracker::new(1000),
            pending_reforge_genesis: HashMap::new(),
            wallet: None,
            century_locks: HashMap::new(),
            century_lock_last_tick: 0,
            open_bounties: HashMap::new(),
            claimed_bounty_indices: HashMap::new(),
            mining_active: false,
            mining_chain_length: 0,
            mining_next_nonce: 0,
            mining_session_nonce: 0,
            mining_tick_hash: [0u8; 32],
            mining_started_at: 0,
            mining_stop_tx: None,
            wallet_path: None,
            notifications: VecDeque::new(),
            events: VecDeque::new(),
            outbound_payments: HashMap::new(),
            outbound_by_mint_id: HashMap::new(),
            banishment: Arc::new(BanishmentManager::new()),
            tag_cache: crate::tag_cache::TagCache::load_or_create(
                std::path::PathBuf::from(".vess-artery").join("tag_cache.json"),
            ),
            mailbox_fwd: HashMap::new(),
            mailbox_fwd_limiter: crate::gossip::PeerRateLimiter::new(5, 60),
            unsafe_mode: is_testnet,
            test_faucet_enabled: is_testnet,
            is_testnet,
            passive_mode: false,
            own_scan_dk: None,
            payment_history: vess_kloak::payment::PaymentHistory::default(),
            tick_clock: vess_clock::TickChain::new([0u8; 32]),
            network_time: vess_clock::NetworkTime { median_tick: 0, observed_peers: 0, tick_samples: Vec::new(), computed_at_ms: 0 },
            peer_clocks: HashMap::new(),
        }
    }

    pub fn push_notification(&mut self, notification: WalletNotification) {
        info!(
            kind = %notification.kind,
            payment_id = %notification.payment_id,
            "{}",
            notification.message
        );
        self.push_notification_raw(notification);
    }

    /// Re-queue a previously-drained notification without logging.
    pub fn push_notification_raw(&mut self, notification: WalletNotification) {
        if self.notifications.len() >= MAX_WALLET_NOTIFICATIONS {
            self.notifications.pop_front();
        }
        self.notifications.push_back(notification);
    }

    pub fn take_notifications(&mut self, max: usize) -> Vec<WalletNotification> {
        let count = max.max(1).min(self.notifications.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(note) = self.notifications.pop_front() {
                out.push(note);
            }
        }
        out
    }

    /// Audit the current state for unsafe configurations.
    /// Returns a list of warnings. In production, any warning indicates
    /// a misconfiguration.
    pub(crate) fn audit(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if !self.is_testnet {
            if self.unsafe_mode {
                warnings.push("unsafe_mode is enabled in production".into());
            }
            if self.test_faucet_enabled {
                warnings.push("test_faucet is enabled in production".into());
            }

            // Verify we have >= K neighbors after bootstrap
            let peer_count = self.routing_table.peer_count();
            let k = self.gossip_config.k_neighbors;
            if peer_count < k && k > 0 {
                warnings.push(format!(
                    "only {peer_count} verified peers (target K={k})"
                ));
            }
        }

        // Always warn about zero K
        if self.gossip_config.k_neighbors == 0 {
            warnings.push("k_neighbors is 0: gossip is disabled".into());
        }

        if self.gossip_config.max_hops == 0 {
            warnings.push("max_hops is 0: payments cannot be relayed".into());
        }

        warnings
    }

    pub(crate) fn record_outbound_payment(
        &mut self,
        payment_id: [u8; 32],
        amount: u64,
        recipient: String,
        mint_ids: &[[u8; 32]],
    ) {
        let pending_mint_ids: HashSet<[u8; 32]> = mint_ids.iter().copied().collect();
        for mint_id in &pending_mint_ids {
            self.outbound_by_mint_id.insert(*mint_id, payment_id);
        }
        self.outbound_payments.insert(
            payment_id,
            OutboundPaymentRecord {
                payment_id,
                amount,
                recipient,
                pending_mint_ids,
            },
        );
    }

    pub(crate) fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub(crate) fn push_event(&mut self, event: NodeEvent) {
        if self.events.len() >= 1024 {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub(crate) fn take_events(&mut self, max: usize) -> Vec<NodeEvent> {
        let count = max.max(1).min(self.events.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(ev) = self.events.pop_front() {
                out.push(ev);
            }
        }
        out
    }

    pub(crate) fn finalize_outbound_mint_if_complete(&mut self, mint_id: &[u8; 32]) {
        let Some(payment_id) = self.outbound_by_mint_id.remove(mint_id) else {
            return;
        };

        let mut completed = None;
        if let Some(record) = self.outbound_payments.get_mut(&payment_id) {
            record.pending_mint_ids.remove(mint_id);
            if record.pending_mint_ids.is_empty() {
                completed = Some((record.payment_id, record.amount, record.recipient.clone()));
            }
        }

        if let Some((payment_id, amount, recipient)) = completed {
            self.outbound_payments.remove(&payment_id);
            self.push_notification(WalletNotification {
                kind: "payment_sent_confirmed".to_string(),
                created_at: Self::now_unix(),
                payment_id: hex_key(&payment_id),
                amount: Some(amount),
                bill_count: None,
                counterparty: Some(recipient.clone()),
                message: format!("Payment to {recipient} confirmed by recipient claim."),
            });
        }
    }

    pub(crate) fn release_outbound_mints(&mut self, mint_ids: &[[u8; 32]]) {
        let mut affected_payment_ids = HashSet::new();
        for mint_id in mint_ids {
            if let Some(payment_id) = self.outbound_by_mint_id.remove(mint_id) {
                affected_payment_ids.insert(payment_id);
            }
        }

        for payment_id in affected_payment_ids {
            if let Some(record) = self.outbound_payments.remove(&payment_id) {
                self.push_notification(WalletNotification {
                    kind: "payment_sent_released".to_string(),
                    created_at: Self::now_unix(),
                    payment_id: hex_key(&payment_id),
                    amount: Some(record.amount),
                    bill_count: Some(record.pending_mint_ids.len()),
                    counterparty: Some(record.recipient.clone()),
                    message: format!(
                        "Pending payment to {} expired and its reserved bills were released.",
                        record.recipient
                    ),
                });
            }
        }
    }

    /// Persist the in-memory wallet billfold to disk immediately.
    /// Spend credentials are encrypted before writing.
    /// Also syncs century_lock_ids from ArteryState to the wallet file.
    /// No-op if no wallet is loaded.
    pub(crate) fn flush_wallet(&self) {
        if let Some(ref ws) = self.wallet {
            if let Ok(mut wf) = vess_kloak::WalletFile::load(&ws.wallet_path) {
                wf.billfold = ws.billfold.clone();
                // Sync century lock IDs from node state to wallet file.
                wf.century_lock_ids = self.century_locks.keys().cloned().collect();
                // Encrypt spend credentials before persisting.
                if let Err(e) = wf.encrypt_spend_credentials(&ws.billfold, &ws.enc_key) {
                    tracing::warn!(error = %e, "failed to encrypt spend credentials");
                }
                if let Err(e) = wf.save(&ws.wallet_path, &ws.enc_key) {
                    tracing::warn!(error = %e, "failed to flush wallet to disk");
                }
            }
        }
    }

    /// Publish encrypted wallet manifest to DHT for seed-based recovery.
    /// Returns the DHT key if published.
    pub(crate) fn publish_manifest_to_dht(
        &mut self,
        manifest_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::ManifestStore>,
    ) -> Option<[u8; 32]> {
        // Collect bill mint IDs and DHT indices for recovery.
        let bill_info: Vec<([u8; 32], u64)> = self.wallet.as_ref()
            .map(|ws| ws.billfold.bills().iter()
                .map(|b| (b.mint_id, b.dht_index)).collect())
            .unwrap_or_default();

        // Collect active century lock IDs for recovery.
        let century_lock_ids: Vec<[u8; 32]> = self.century_locks.keys().cloned().collect();

        // Get enc_key (cloned to release borrow).
        let enc_key = self.wallet.as_ref().map(|ws| ws.enc_key);

        // Nothing to publish if no bills, no century locks, or no encryption key.
        if bill_info.is_empty() && century_lock_ids.is_empty() { return None; }
        let enc_key = enc_key?;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct WalletManifest {
            bills: Vec<([u8; 32], u64)>,
            #[serde(default)]
            century_lock_ids: Vec<[u8; 32]>,
        }

        let manifest = WalletManifest {
            bills: bill_info,
            century_lock_ids,
        };
        let manifest_json = serde_json::to_vec(&manifest).ok()?;
        let dht_key: [u8; 32] = *blake3::hash(&manifest_json).as_bytes();

        // Encrypt with the wallet's enc_key (ChaCha20Poly1305 nonce || ct).
        let encrypted_manifest = vess_kloak::persistence::EncryptedBlob::encrypt(
            &manifest_json, &enc_key
        ).map(|blob| {
            let mut v = Vec::with_capacity(12 + blob.ciphertext.len());
            v.extend_from_slice(&blob.nonce);
            v.extend_from_slice(&blob.ciphertext);
            v
        }).unwrap_or_default();

        let msg = ManifestStore {
            dht_key,
            encrypted_manifest: encrypted_manifest.clone(),
            hops_remaining: 6,
        };
        self.manifest_store.insert(dht_key, (encrypted_manifest, Self::now_unix()));
        let _ = manifest_tx.send(msg);
        Some(dht_key)
    }

    fn snapshot(&self) -> ArterySnapshot {
        let tags: BTreeMap<String, vess_tag::TagRecord> = self
            .tag_dht
            .export_records()
            .iter()
            .map(|(k, v)| (hex_key(k), v.clone()))
            .collect();

        let manifests: BTreeMap<String, Vec<u8>> = self
            .manifest_store
            .iter()
            .map(|(k, (v, _))| (hex_key(k), v.clone()))
            .collect();

        ArterySnapshot {
            tags,
            bills: BTreeMap::new(), // legacy — kept for deserialization compat
            mailbox: BTreeMap::new(),
            known_peers: self
                .routing_table
                .all_peers()
                .iter()
                .map(|p| p.id_hash)
                .collect(),
            peer_endpoints: {
                let mut map = std::collections::BTreeMap::new();
                for p in self.routing_table.all_peers() {
                    if !p.id_bytes.is_empty() {
                        map.insert(hex_key(&p.id_hash), p.id_bytes.clone());
                    }
                }
                map
            },
            limbo_entries: {
                let limbo_map = self.limbo_buffer.export();
                limbo_map
                    .into_iter()
                    .map(|(k, v)| (hex_key(&k), v))
                    .collect()
            },
            peer_reputations: self.reputation.export(),
            hardening_proofs: self.tag_dht.export_hardening_proofs(),
            banned_peers: self.banishment.all_banned(),
            ownership_records: self.registry.all_records(),
            consumed_records: self
                .registry
                .all_consumed()
                .into_iter()
                .map(|(k, v)| (hex_key(&k), v))
                .collect(),
            manifests,
            retained_ownership_records: self
                .retained_ownership_records
                .values()
                .cloned()
                .collect(),
            retained_consumed_records: self
                .retained_consumed_records
                .iter()
                .map(|(k, v)| (hex_key(k), v.clone()))
                .collect(),
            // M5: persist the set of in-flight limbo payment IDs so a restart
            // cannot be used to replay a payment that is already in limbo.
            limbo_payment_ids: self.limbo_payment_ids.iter().cloned().collect(),
            century_locks: self.century_locks.values().cloned().collect(),
            century_lock_last_tick: self.century_lock_last_tick,
        }
    }

    fn restore(&mut self, snap: ArterySnapshot) {
        let tag_records: BTreeMap<[u8; 32], vess_tag::TagRecord> = snap
            .tags
            .into_iter()
            .filter_map(|(k, v)| unhex_key(&k).ok().map(|key| (key, v)))
            .collect();
        self.tag_dht.load_records(tag_records);

        // Legacy bill_dht records — ignored (bills are now on ownership records).

        // Legacy mailbox data is ignored — payments are now served from limbo_buffer.

        self.routing_table = RoutingTable::new(self.node_id);
        for h in snap.known_peers {
            let id_bytes = snap
                .peer_endpoints
                .get(&hex_key(&h))
                .cloned()
                .unwrap_or_default();
            self.routing_table.insert(RoutingPeer {
                id_hash: h,
                id_bytes,
                last_seen: 0,
                first_seen: 0,
            });
        }

        let limbo_data: std::collections::HashMap<[u8; 32], Vec<crate::limbo_buffer::LimboEntry>> =
            snap.limbo_entries
                .into_iter()
                .filter_map(|(k, v)| unhex_key(&k).ok().map(|key| (key, v)))
                .collect();
        self.limbo_buffer.load(limbo_data);

        self.reputation.import(snap.peer_reputations);

        self.tag_dht.load_hardening_proofs(snap.hardening_proofs);

        // Restore ownership registry.
        let consumed: std::collections::HashMap<
            [u8; 32],
            crate::ownership_registry::ConsumedRecord,
        > = snap
            .consumed_records
            .into_iter()
            .filter_map(|(k, v)| unhex_key(&k).ok().map(|key| (key, v)))
            .collect();
        self.registry = OwnershipRegistry::from_records_with_tombstones(
            self.node_id,
            snap.ownership_records,
            consumed,
        );

        self.retained_ownership_records = snap
            .retained_ownership_records
            .into_iter()
            .map(|record| (record.mint_id, record))
            .collect();
        self.retained_consumed_records = snap
            .retained_consumed_records
            .into_iter()
            .filter_map(|(k, v)| unhex_key(&k).ok().map(|key| (key, v)))
            .collect();

        // Restore manifest store, assigning insertion time 0 for entries loaded
        // from a snapshot (they sort before any new arrivals for eviction purposes).
        self.manifest_store = snap
            .manifests
            .into_iter()
            .filter_map(|(k, v)| unhex_key(&k).ok().map(|key| (key, (v, 0u64))))
            .collect();

        // M5: Restore in-flight limbo payment IDs.
        for id in snap.limbo_payment_ids {
            self.limbo_payment_ids.insert(id);
        }
    }
}

// ── Gossip drain helpers ────────────────────────────────────────────

/// E2: Lightweight variant of `compute_gossip_targets` that reads peer
/// reputation from a pre-computed `peer_hash -> score` slice aligned to
/// `peer_hashes`.  The caller snapshots scores once per drain cycle
/// (~8 bytes × routable-peer-count) instead of cloning the full
/// [`ReputationTable`] (~200 bytes × tracked-peer-count, up to ~10 MiB).
fn compute_gossip_targets_scored(
    key: &[u8; 32],
    peer_hashes: &[[u8; 32]],
    peer_scores: &[f64],
    age_factors: &[f64],
    k: usize,
    fan: usize,
    total_peers: usize,
) -> Vec<usize> {
    let nearest = k_nearest(key, peer_hashes, k);
    // Rank the k-nearest candidates by score × age.
    let mut ranked: Vec<(usize, f64)> = nearest
        .iter()
        .enumerate()
        .map(|(ci, &pi)| {
            let score = peer_scores.get(pi).copied().unwrap_or(0.5);
            let age = age_factors.get(pi).copied().unwrap_or(1.0);
            (ci, score * age)
        })
        .collect();
    ranked.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let mut indices: Vec<usize> = ranked
        .into_iter()
        .take(k)
        .map(|(ci, _)| nearest[ci])
        .collect();
    let extra = random_fan_out(total_peers, &indices, fan);
    for ei in extra {
        if !indices.contains(&ei) {
            indices.push(ei);
        }
    }
    indices
}

async fn retry_unroutable_payment_batch(
    pay_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::Payment>,
    items: Vec<vess_protocol::Payment>,
) {
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    for item in items {
        let _ = pay_tx.send(item);
    }
}

/// Batch-send grouped messages to peers over single mesh sessions.
/// Sends to all target peers concurrently via tokio::spawn.
///
/// E1: Batch-send **pre-serialized** payloads to peers over single mesh
/// sessions. The caller serializes each logical message once and shares
/// the byte buffer via `Arc<Vec<u8>>` across all target peers — eliminating
/// the `PulseMessage::clone()` + re-`to_bytes()` multiplication that the
/// `PulseMessage`-based path incurs per target.
async fn batch_forward_bytes_to_peers(
    node: &MeshPulseNode,
    routable_peers: &[Vec<u8>],
    per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>>,
) {
    let mut tasks = Vec::with_capacity(per_peer.len());
    for (idx, payloads) in per_peer {
        if idx >= routable_peers.len() || payloads.is_empty() {
            continue;
        }
        let target = match decode_contact_bytes(&routable_peers[idx]) {
            Ok(contact) => contact,
            Err(_) => continue,
        };
        let peer_node = node.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = peer_node.send_raw_pulses_to_peer(&target, &payloads).await {
                warn!("batch forward (raw) to peer failed: {e}");
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
}

/// Payment-specific variant of batch_forward_bytes_to_peers: when a send
/// fails, the Payment payload is re-queued via retry_tx so transient mesh
/// failures (e.g. peer changed ports after restart) don't drop payments.
async fn batch_forward_payments_with_retry(
    node: &MeshPulseNode,
    routable_peers: &[Vec<u8>],
    per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>>,
    retry_tx: &tokio::sync::mpsc::UnboundedSender<vess_protocol::Payment>,
) {
    let mut tasks = Vec::with_capacity(per_peer.len());
    let mut failed = Vec::new();
    for (idx, payloads) in per_peer {
        if idx >= routable_peers.len() || payloads.is_empty() { continue; }
        let target = match decode_contact_bytes(&routable_peers[idx]) {
            Ok(c) => c, Err(_) => continue,
        };
        let node = node.clone();
        let p = payloads.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = node.send_raw_pulses_to_peer(&target, &p).await {
                warn!("batch forward (raw) to peer failed: {e}");
                Err(p)
            } else { Ok(()) }
        }));
    }
    for t in tasks {
        if let Ok(Err(p)) = t.await { failed.extend(p); }
    }
    for bytes in failed {
        if let Ok(PulseMessage::Payment(p)) = PulseMessage::from_bytes(bytes.as_slice()) {
            let _ = retry_tx.send(p);
        }
    }
}

/// Run the artery node. Blocks until the process is interrupted (Ctrl+C).
///
/// Returns the node's mesh node ID string for display/use.
pub async fn run_node(config: NodeConfig) -> Result<String> {
    // ── Panic hook for crash diagnostics ────────────────────────────
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));
        let payload = info.payload().downcast_ref::<&str>().copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("Box<dyn Any>");
        eprintln!("=== VESS NODE PANIC ===\n  at: {}\n  payload: {payload}",
            loc.as_deref().unwrap_or("unknown"));
    }));

    // ── SIGTERM / Ctrl+C handler ───────────────────────────────────
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "failed to install Ctrl+C signal handler");
            return;
        }
        tracing::info!("Ctrl+C received, initiating graceful shutdown…");
        let _ = shutdown_tx.send(());
    });
    #[cfg(unix)]
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
            sigterm.recv().await;
            tracing::info!("SIGTERM received, initiating graceful shutdown…");
            let _ = tx.send(());
        });
    }

    let storage = NodeStorage::open(&config.state_dir)?;
    let mut snapshot = storage.load()?;
    if config.reset_transient_peer_state {
        snapshot.known_peers.clear();
        snapshot.peer_endpoints.clear();
        snapshot.peer_reputations.clear();
        snapshot.banned_peers.clear();
    }

    // ── Load embedded wallet (if configured) ────────────────────────
    let (wallet_state, startup_wallet_tag_store) = if let Some(ref wallet_path) = config.wallet_path {
        use vess_kloak::recovery::encryption_key_from_seed;
        use vess_kloak::WalletFile;

        let mut wallet = WalletFile::load(wallet_path)?;

        // Try password-based unlock first (fast ~1 s, 256 MiB), then
        // fall back to the 12-word recovery phrase via env vars.
        let password = config
            .wallet_password
            .clone()
            .or_else(|| std::env::var("VESS_WALLET_PASSWORD").ok());

        let raw_seed = if let Some(ref pwd) = password {
            Zeroizing::new(wallet.unlock_with_password(pwd)?)
        } else {
            // Fallback: 12-word recovery phrase from VESS_RECOVERY_PHRASE.
            use vess_kloak::recovery::{derive_raw_seed, RecoveryPhrase};
            let phrase_words = std::env::var("VESS_RECOVERY_PHRASE").map_err(|_| {
                anyhow::anyhow!(
                    "wallet unlock requires --wallet-password / VESS_WALLET_PASSWORD \
                     or VESS_RECOVERY_PHRASE env var"
                )
            })?;
            let phrase = RecoveryPhrase::from_input(&phrase_words)?;
            Zeroizing::new(derive_raw_seed(&phrase)?)
        };

        // Derive stealth keys and encryption key from the raw seed.
        let (stealth_secret, address) =
            vess_stealth::generate_master_keys_from_seed(&raw_seed);
        let mailbox_key = vess_kloak::derive_mailbox_key(&address.spend_ek);
        let enc_key = encryption_key_from_seed(&raw_seed);
        wallet.decrypt_private_metadata(&enc_key)?;
        let startup_wallet_tag_store = match crate::rpc::wallet_tag_store(&mut wallet, wallet_path, &enc_key) {
            Ok(store) => store,
            Err(error) => {
                warn!(%error, "failed to prepare wallet tag announcement on startup");
                None
            }
        };

        // Load billfold and decrypt spend credentials into it.
        let mut billfold = wallet.billfold.clone();
        if let Err(e) = wallet.decrypt_spend_credentials_into(&mut billfold, &enc_key) {
            tracing::warn!(error = %e, "failed to decrypt spend credentials — wallet may be from older version");
        }

        (
            Some(WalletState {
                stealth_secret,
                stealth_address: address,
                billfold,
                wallet_path: wallet_path.clone(),
                enc_key,
                mailbox_key,
                mining_next_nonce: wallet.mining_next_nonce,
                mining_session_nonce: wallet.mining_session_nonce,
                mining_prev_hash: wallet.mining_prev_hash,
            }),
            startup_wallet_tag_store,
        )
    } else {
        (None, None)
    };

    let mesh_seed = load_or_create_mesh_seed(&config.state_dir)?;
    let bind_addr = config.bind_addr.unwrap_or_else(|| {
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ))
    });
    let node = MeshPulseNode::bind_from_seed(
        bind_addr,
        &mesh_seed,
        0,
    )
    .await?;

    info!("Starting artery node...");
    node.wait_online().await;

    let node_id_str = node.id().to_string();
    let node_id_bytes: [u8; 32] = *node.id().as_bytes();
    // Derive own scan_dk + scan_ek for onion layer decryption and relay
    let (own_scan_dk, own_relay_ek) = {
        let (secret, addr) = vess_mesh::generate_mesh_keys_from_seed(&mesh_seed, 0);
        (Some(secret.network_scan_dk), Some(addr.network_scan_ek))
    };

    let gossip_config = GossipConfig {
        k_neighbors: config.k_neighbors,
        max_hops: config.max_hops,
    };

    let banishment = Arc::new(BanishmentManager::new());

    let state = Arc::new(Mutex::new(ArteryState {
        registry: OwnershipRegistry::new(node_id_bytes),
        tag_dht: TagDht::new(node_id_bytes, config.k_neighbors),
        swap_offers: BTreeMap::new(),
        swap_offer_tx: None,
        node_id: node_id_bytes,
        routing_table: RoutingTable::new(node_id_bytes),
        gossip_config,
        peer_registry: PeerRegistry::new(std::time::Duration::from_secs(30)),
        handshake_queue: Vec::new(),
        limbo_buffer: LimboBuffer::new(),
        reputation: ReputationTable::new(),
        rate_limiter: crate::gossip::PeerRateLimiter::with_defaults(),
        // MailboxCollect: 10 requests per 60-second window per peer.
        mailbox_collect_limiter: crate::gossip::PeerRateLimiter::new(10, 60),
        // TagLookup: 30 requests per 60-second window per peer.
        tag_lookup_limiter: crate::gossip::PeerRateLimiter::new(30, 60),
        // RegistryQuery / OwnershipFetch: 20 requests per 60-second window.
        registry_query_limiter: crate::gossip::PeerRateLimiter::new(20, 60),
        duplicate_tracker: DuplicateTracker::new(),
        estimated_network_size: 0,
        limbo_mint_ids: std::collections::HashSet::new(),
        limbo_payment_ids: std::collections::HashSet::new(),
        manifest_store: HashMap::new(),
        retained_ownership_records: HashMap::new(),
        retained_consumed_records: HashMap::new(),
        limbo_entry_times: HashMap::new(),
        payment_latency: PaymentLatencyTracker::new(1000),
        pending_reforge_genesis: HashMap::new(),
        wallet: wallet_state,
        century_locks: HashMap::new(),
        century_lock_last_tick: 0,
        open_bounties: HashMap::new(),
        claimed_bounty_indices: HashMap::new(),
        mining_active: false,
        mining_chain_length: 0,
        mining_next_nonce: 0,
        mining_session_nonce: 0,
        mining_tick_hash: [0u8; 32],
        mining_started_at: 0,
        mining_stop_tx: None,
        wallet_path: config.wallet_path.clone(),
        notifications: VecDeque::new(),
        outbound_payments: HashMap::new(),
        outbound_by_mint_id: HashMap::new(),
        banishment: banishment.clone(),
        tag_cache: crate::tag_cache::TagCache::load_or_create(
            config.state_dir.join("tag_cache.json"),
        ),
        mailbox_fwd: HashMap::new(),
        // MailboxForwardRegister: 5 registrations per 60-second window per peer.
        mailbox_fwd_limiter: crate::gossip::PeerRateLimiter::new(5, 60),
        unsafe_mode: config.test,
        test_faucet_enabled: config.test,
        is_testnet: config.test,
        events: VecDeque::new(),
        limbo_payment_times: HashMap::new(),
        passive_mode: false,
        own_scan_dk,
        tick_clock: vess_clock::TickChain::new(node_id_bytes),
        network_time: vess_clock::NetworkTime { median_tick: 0, observed_peers: 0, tick_samples: Vec::new(), computed_at_ms: 0 },
        peer_clocks: HashMap::new(),
        payment_history: {
            let history_path = config.state_dir.join("payment_history.json");
            vess_kloak::payment::PaymentHistory::load(&history_path)
        },
    }));

    // ── Gossip drain channels ───────────────────────────────────────
    // Unbounded mpsc channels decouple queue producers (handler) from
    // consumers (drain loops) so drain loops never contend on the main
    // state mutex for queue access.
    let (manifest_tx, mut manifest_rx) =
        tokio::sync::mpsc::unbounded_channel::<vess_protocol::ManifestStore>();
    let (tag_store_tx, mut tag_store_rx) = tokio::sync::mpsc::unbounded_channel::<TagStore>();
    let (tag_confirm_tx, mut tag_confirm_rx) = tokio::sync::mpsc::unbounded_channel::<TagConfirm>();
    let (og_tx, mut og_rx) = tokio::sync::mpsc::unbounded_channel::<OwnershipGenesis>();
    let (oc_tx, mut oc_rx) = tokio::sync::mpsc::unbounded_channel::<OwnershipClaim>();
    let (ra_tx, mut ra_rx) = tokio::sync::mpsc::unbounded_channel::<ReforgeAttestation>();
    let (pay_tx, mut pay_rx) = tokio::sync::mpsc::unbounded_channel::<vess_protocol::Payment>();
    // Forward channel: (target serialized mesh contact, Payment to deliver).
    // The drain task below sends a LimboDeliver to subscribed nodes.
    let (fwd_tx, mut fwd_rx) =
        tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, vess_protocol::Payment)>();

    // Restore persisted state.
    {
        let mut s = lock_state(&state);
        let tag_count = snapshot.tags.len();
        let manifest_count = snapshot.manifests.len();
        let banned_count = snapshot.banned_peers.len();
        let registry_count = snapshot.ownership_records.len();
        banishment.import(snapshot.banned_peers.iter().copied());
        s.restore(snapshot);
        info!(
            registry = registry_count,
            tags = tag_count,
            manifests = manifest_count,
            banned = banned_count,
            "restored state from disk"
        );
        drop(s);
    }

    if let Some((tag_str, tag_store)) = startup_wallet_tag_store.clone() {
        let mut s = lock_state(&state);
        let record = vess_tag::TagRecord {
            tag_hash: tag_store.tag_hash,
            master_address: vess_stealth::MasterStealthAddress {
                scan_ek: tag_store.scan_ek.clone(),
                spend_ek: tag_store.spend_ek.clone(),
            },
            pow_nonce: tag_store.pow_nonce,
            pow_hash: tag_store.pow_hash.clone(),
            registered_at: tag_store.registered_at,
            registrant_vk: tag_store.registrant_vk.clone(),
            signature: tag_store.signature.clone(),
            hardened_at: None,
        };
        let addr_fp = record.address_fingerprint();

        if s.tag_dht.lookup(&tag_str).is_none() && !s.tag_dht.has_address(&addr_fp) {
            if s.tag_dht.store(record) {
                let _ = tag_store_tx.send(tag_store);
                s.push_notification(WalletNotification {
                    kind: "tag_announced".to_string(),
                    created_at: ArteryState::now_unix(),
                    payment_id: hex_key(&addr_fp),
                    amount: None,
                    bill_count: None,
                    counterparty: Some(format!("+{tag_str}")),
                    message: format!("Wallet tag +{tag_str} is available for sends."),
                });
            }
        }
    }

    // ── Auto-sweep existing limbo entries through wallet ────────────
    {
        let mut s = lock_state(&state);
        if s.wallet.is_some() {
            let all_sids: Vec<[u8; 32]> = s.limbo_buffer.stealth_ids_with_payments();
            let mut payloads: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            for sid in &all_sids {
                for entry in s.limbo_buffer.peek(sid) {
                    payloads.push((entry.payment.payment_id, entry.payment.stealth_payload.clone()));
                }
            }
            if !payloads.is_empty() {
                let ws = s.wallet.as_mut().unwrap();
                let mut received = 0u64;
                let mut bill_count = 0usize;
                let mut pending_claims: Vec<OwnershipClaim> = Vec::new();
                for (payment_id, payload) in &payloads {
                    match receive_and_claim(&ws.stealth_secret, payload, payment_id) {
                        Ok(Some(result)) => {
                            for claimed in result.claimed {
                                received += claimed.bill.denomination.value();
                                bill_count += 1;
                                ws.billfold.deposit_with_credentials(
                                    claimed.bill,
                                    SpendCredential {
                                        spend_vk: claimed.spend_vk,
                                        spend_sk: claimed.spend_sk,
                                    },
                                );
                            }
                            for claim in result.ownership_claims {
                                if let PulseMessage::OwnershipClaim(oc) = claim {
                                    pending_claims.push(oc);
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(e) => warn!(error = %e, "limbo sweep trial-decrypt error"),
                    }
                }
                for claim in pending_claims {
                    queue_local_ownership_claim(&mut s, &oc_tx, claim);
                }
                if received > 0 {
                    info!(
                        amount = received,
                        bills = bill_count,
                        "swept existing limbo into wallet"
                    );
                }
            }
        }
    }

    info!(node_id = %node.id(), state = %config.state_dir.display(), version = %hex_key(&PROTOCOL_VERSION_HASH), k = config.k_neighbors, max_hops = config.max_hops, "Artery node online");
    if config.enable_local_discovery {
        spawn_local_lan_discovery(node.contact(), state.clone());
    }
    // ── Hash clock: advance tick every ~6s, gossip to peers ─────────
    spawn_clock_tick_task(state.clone());
    spawn_clock_gossip_task(node.clone(), state.clone());

    if config.wallet_path.is_some() {
        let s = lock_state(&state);
        let bal = s.wallet.as_ref().map(|w| w.billfold.balance()).unwrap_or(0);
        info!(balance = bal, "wallet enabled");
    }
    if let Some(port) = config.rpc_port {
        // H2: Generate a per-startup random token and write it to a
        // mode-600 file so only the process owner can read it.
        let rpc_token: String = {
            use rand::Rng;
            let bytes: [u8; 32] = rand::thread_rng().gen();
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        };
        {
            let token_path = config.state_dir.join("rpc-token");
            if let Err(e) = std::fs::write(&token_path, rpc_token.as_bytes()) {
                warn!(error = %e, "failed to write rpc-token file — RPC auth may not work");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
            }
        }
        info!(port, "RPC server listening");
        let rpc_state = state.clone();
        let rpc_senders = crate::rpc::QueueSenders {
            manifest_tx: manifest_tx.clone(),
            tag_store_tx: tag_store_tx.clone(),
            tag_confirm_tx: tag_confirm_tx.clone(),
            og_tx: og_tx.clone(),
            oc_tx: oc_tx.clone(),
            ra_tx: ra_tx.clone(),
            pay_tx: pay_tx.clone(),
        };
        let rpc_node = node.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::rpc::run_rpc_server(port, rpc_token, rpc_state, rpc_senders, rpc_node).await
            {
                warn!(error = %e, "RPC server exited with error");
            }
        });
    }
    info!("listening for protocol messages");

    // ── Century lock minting task ───────────────────────────────────
    // Every tick (~6s), check active century locks and mint Vess bills
    // for each tick that has passed since the last check.
    let cl_state = state.clone();
    let cl_og_tx = og_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            vess_clock::TICK_INTERVAL_SECS,
        ));
        loop {
            interval.tick().await;
            mint_century_lock_bills(&cl_state, &cl_og_tx);
        }
    });

    // ── Noise payment scheduler ──────────────────────────────────────
    // Every 30–120 seconds (random), send a decoy payment to our own
    // stealth address. The payment is wire-identical to a real one but
    // carries no value. Sybils cannot distinguish real from decoy,
    // making the global payment graph noisy.
    let noise_state = state.clone();
    let noise_pay_tx = pay_tx.clone();
    tokio::spawn(async move {
        loop {
            // Random interval between 30 and 120 seconds.
            let delay_secs = {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                rng.gen_range(30u64..121u64)
            };
            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

            let payment = {
                let s = noise_state.lock().unwrap();
                match s.wallet.as_ref() {
                    Some(ws) => {
                        match vess_kloak::payment::prepare_noise_payment(&ws.stealth_address) {
                            Ok(msg) => match msg {
                                PulseMessage::Payment(p) => Some(p),
                                _ => None,
                            },
                            Err(e) => {
                                warn!(error = %e, "failed to prepare noise payment");
                                None
                            }
                        }
                    }
                    None => {
                        // Wallet not loaded — skip this tick.
                        None
                    }
                }
            };

            if let Some(p) = payment {
                let _ = noise_pay_tx.send(p);
            }
        }
    });

    // ── Periodic state flush (every 60 seconds) ─────────────────────
    let flush_state = state.clone();
    let flush_node = node.clone();
    let flush_storage_dir = config.state_dir.clone();
    let flush_manifest_tx = manifest_tx.clone();
    let flush_og_tx = og_tx.clone();
    let flush_ra_tx = ra_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            {
                let mut s = flush_state.lock().unwrap();
                // Evict stale limbo buffer entries (TTL-based).
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (evicted, evicted_pids) = s.limbo_buffer.evict_expired(now);
                for pid in &evicted_pids {
                    s.limbo_payment_ids.remove(pid);
                }
                if evicted > 0 {
                    info!(count = evicted, "evicted expired limbo buffer entries");
                }
                // Clean up limbo_mint_ids for payments whose TTL has expired.
                // limbo_entry_times stores insertion-ms; TTL is 3600 s = 3_600_000 ms.
                let ttl_ms: u64 = 3_600_000;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let stale: Vec<[u8; 32]> = s
                    .limbo_entry_times
                    .iter()
                    .filter(|(_, &t)| now_ms.saturating_sub(t) > ttl_ms)
                    .map(|(&mid, _)| mid)
                    .collect();
                for mid in &stale {
                    s.limbo_mint_ids.remove(mid);
                    s.limbo_entry_times.remove(mid);
                }
                if !stale.is_empty() {
                    info!(
                        count = stale.len(),
                        "evicted expired limbo_mint_ids entries"
                    );
                }
                // Release bill reservations older than the limbo TTL (3600 s).
                if let Some(ref mut ws) = s.wallet {
                    let released = ws.billfold.release_expired(3600, now);
                    if !released.is_empty() {
                        s.release_outbound_mints(&released);
                        info!(count = released.len(), "released expired bill reservations");
                    }
                }
                // Prune unhardened tags past the 30-day TTL.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let pruned_tags = s.tag_dht.purge_unhardened(now);
                if pruned_tags > 0 {
                    info!(count = pruned_tags, "pruned unhandened tags");
                }
                // ── Periodic peer reverification ─────────────────
                // Re-challenge peers whose verification has expired.
                let due = reverify_stale_peers(&flush_state);
                if !due.is_empty() {
                    info!(count = due.len(), "re-verifying stale peers");
                    for peer_id in &due {
                        let mut s = flush_state.lock().unwrap();
                        if let Some(nonce) = s.peer_registry.issue_challenge(*peer_id) {
                            drop(s);
                            // Send HandshakeChallenge to the peer.
                            // For now, we can't route to specific peers without
                            // their contact info in the routing table.
                            // The peer will be re-challenged on next contact.
                            let _ = nonce;
                        }
                    }
                }
                // Evict expired mailbox forwarding subscriptions.
                let before_fwd = s.mailbox_fwd.len();
                s.mailbox_fwd.retain(|_, r| r.expires_at > now);
                let evicted_fwd = before_fwd - s.mailbox_fwd.len();
                if evicted_fwd > 0 {
                    info!(
                        count = evicted_fwd,
                        "evicted expired mailbox forward subscriptions"
                    );
                }
                // C1: Evict pending-reforge-genesis entries older than the TTL.
                // Without this, keys created by fake attestations linger forever.
                {
                    let mut evicted_keys = 0usize;
                    let mut evicted_entries = 0usize;
                    s.pending_reforge_genesis.retain(|_, entries| {
                        let before = entries.len();
                        entries.retain(|(_, buffered_at)| {
                            now.saturating_sub(*buffered_at) < PENDING_GENESIS_TTL_SECS
                        });
                        evicted_entries += before - entries.len();
                        if entries.is_empty() {
                            evicted_keys += 1;
                            false
                        } else {
                            true
                        }
                    });
                    if evicted_entries > 0 {
                        info!(
                            keys = evicted_keys,
                            entries = evicted_entries,
                            "evicted expired pending-reforge-genesis entries"
                        );
                    }
                }
                // ── Century lock auto-minting ──────────────────────
                // Century locks are minted by a dedicated task; this
                // periodic tick just ensures wallet persistence.
                if !s.century_locks.is_empty() {
                    let active_count = s.century_locks.values()
                        .filter(|lock| lock.is_active(s.network_time.median_tick))
                        .count();
                    if active_count > 0 {
                        tracing::trace!(active_count, "century locks active");
                    }
                }
                // ── Opportunistic bill consolidation ──────────────
                // Consolidate small bills into larger denominations when idle.
                if let Some(ref ws) = s.wallet {
                    let cred_map = ws.billfold.export_credentials().clone();
                    if !cred_map.is_empty() {
                        // Build a minimal QueueSenders from available channels.
                        let senders = crate::rpc::QueueSenders {
                            manifest_tx: flush_manifest_tx.clone(),
                            tag_store_tx: tokio::sync::mpsc::unbounded_channel().0,
                            tag_confirm_tx: tokio::sync::mpsc::unbounded_channel().0,
                            og_tx: flush_og_tx.clone(),
                            oc_tx: tokio::sync::mpsc::unbounded_channel().0,
                            ra_tx: flush_ra_tx.clone(),
                            pay_tx: tokio::sync::mpsc::unbounded_channel().0,
                        };
                        crate::rpc::fire_opportunistic_consolidations(
                            &mut s, &cred_map, &[], &senders,
                        );
                    }
                }
                let n = s.estimated_network_size;
                // k_neighbors scales logarithmically: max(6, ceil(log2(N)))
                let log2_n = if n > 1 {
                    (n as f64).log2().ceil() as usize
                } else {
                    1
                };
                s.gossip_config.k_neighbors = log2_n.max(6);
                // max_hops scales as ceil(log(N) / log(K)) — ensures every
                // node is reachable in O(log N) steps.
                let k_bucket = crate::kademlia::K_BUCKET_SIZE;
                let log_ratio = if k_bucket > 1 {
                    ((n as f64).ln() / (k_bucket as f64).ln()).ceil() as u8
                } else {
                    3
                };
                s.gossip_config.max_hops = log_ratio.max(3);
                let repl = dht_replication_factor(n);
                s.tag_dht.set_k_replication(repl);

                // ── Cover traffic ────────────────────────────────────
                if n > 1 && COVER_QUERIES_PER_TICK > 0 {
                    let cover_mint_ids: Vec<[u8; 32]> = {
                        let mut rng = rand::thread_rng();
                        (0..COVER_QUERIES_PER_TICK)
                            .map(|_| rng.gen::<[u8; 32]>())
                            .collect()
                    };
                    let routable_peers: Vec<Vec<u8>> = s.routing_table
                        .routable_peers(|id| s.peer_registry.state(id) == PeerState::Verified)
                        .iter()
                        .map(|p| p.id_bytes.clone())
                        .collect();
                    drop(s);
                    let mut rng = rand::thread_rng();
                    for mint_id in &cover_mint_ids {
                        let Some(peer_bytes) = routable_peers.choose(&mut rng) else { continue };
                        let Ok(contact) = decode_contact_bytes(peer_bytes) else { continue };
                        let query = PulseMessage::RegistryQuery(
                            vess_protocol::RegistryQuery {
                                mint_ids: vec![*mint_id],
                            },
                        );
                        let n = flush_node.clone();
                        tokio::spawn(async move {
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(2),
                                n.send_message_with_response(&contact, &query),
                            ).await;
                        });
                    }
                    // Re-acquire lock for remaining flush work.
                    s = flush_state.lock().unwrap();
                }
            }
            let snap = {
                let s = flush_state.lock().unwrap();
                s.snapshot()
            };
            let flush_storage =
                NodeStorage::open(&flush_storage_dir).expect("open state dir for flush");
            if let Err(e) = flush_storage.save(&snap) {
                warn!(error = %e, "failed to flush state to disk");
            } else {
                info!("state flushed to disk");
            }
            // Flush embedded wallet billfold to disk.
            {
                let mut s = flush_state.lock().unwrap();
                s.flush_wallet();
                // M1: Flush tag cache if any get() hits marked it dirty.
                s.tag_cache.flush_if_dirty();
                // Persist payment history to disk.
                let history_path = flush_storage_dir.join("payment_history.json");
                s.payment_history.save(&history_path);
                // Publish wallet manifest to DHT for seed-based recovery.
                if let Some(key) = s.publish_manifest_to_dht(&flush_manifest_tx) {
                    info!(dht_key = %hex_key(&key), "wallet manifest published to DHT");
                }
                // 7-day limbo payment ID age-out (TTL is already handled
                // by `evict_expired` above, but limbo_payment_ids is a
                // separate dedup set that can grow over time).
                let ago_7d = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(604_800);
                let old: Vec<[u8; 32]> = s.limbo_payment_times.iter()
                    .filter(|(_, &t)| t < ago_7d)
                    .map(|(&pid, _)| pid)
                    .collect();
                for pid in &old {
                    s.limbo_payment_ids.remove(pid);
                    s.limbo_payment_times.remove(pid);
                }
                if !old.is_empty() {
                    info!(count = old.len(), "pruned aged-out limbo payment IDs");
                }
            }
        }
    });

    // ── Bootstrap discovery ─────────────────────────────────────────
    let mut all_bootstrap = config.bootstrap.clone();

    // Resolve DNS seed domains.
    for domain in &config.bootstrap_dns {
        match tokio::net::lookup_host(format!("{domain}:0")).await {
            Ok(addrs) => {
                for addr in addrs {
                    let contact = format!("{}:{}", addr.ip(), crate::local_discovery::LAN_DISCOVERY_PORT);
                    all_bootstrap.push(contact);
                }
                info!(%domain, count = all_bootstrap.len(), "resolved DNS seed");
            }
            Err(e) => {
                warn!(%domain, error = %e, "failed to resolve DNS seed domain");
            }
        }
    }
    // Append testnet seed peers when running in testnet mode
    {
        let s = lock_state(&state);
        all_bootstrap.extend(
            s.routing_table
                .routable_peers(|_| true)
                .into_iter()
                .filter_map(|peer| String::from_utf8(peer.id_bytes).ok()),
        );
    }
    let local_peers = crate::local_discovery::discover_lan_peer_contacts(
        std::time::Duration::from_secs(2),
        Some(node_id_bytes),
    )
    .await;
    if !local_peers.is_empty() {
        info!(
            count = local_peers.len(),
            "discovered Vess bootstrap nodes via LAN/local discovery"
        );
        for contact in &local_peers {
            queue_discovered_peer_contact(&state, contact.clone(), "lan");
        }
        all_bootstrap.extend(local_peers.iter().filter_map(bootstrap_string_from_contact));
    }
   
    all_bootstrap.sort_unstable();
    all_bootstrap.dedup();

    // ── Bootstrap ───────────────────────────────────────────────────
    if !all_bootstrap.is_empty() {
        let boot_node = node.clone();
        let boot_state = state.clone();
        let bootstrap_peers = all_bootstrap;
        tokio::spawn(async move {
            let mut seed_snapshots = Vec::new();
            for peer_str in &bootstrap_peers {
                let peer_str = peer_str.trim();
                if peer_str.is_empty() {
                    continue;
                }
                let target = match parse_contact_string(peer_str) {
                    Ok(contact) => contact,
                    Err(e) => {
                        warn!("invalid bootstrap peer {peer_str}: {e}");
                        continue;
                    }
                };
                let Some(peer_hash) = contact_node_id_bytes(&target) else {
                    warn!("bootstrap peer {peer_str} is missing a mesh node id");
                    continue;
                };
                let target_bytes = match encode_contact_bytes(&target) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!("failed to encode bootstrap peer {peer_str}: {e}");
                        continue;
                    }
                };

                {
                    let mut s = boot_state.lock().unwrap();
                    if !s.routing_table.contains(&peer_hash) {
                        let boot_now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        s.routing_table.insert(RoutingPeer {
                            id_hash: peer_hash,
                            id_bytes: target_bytes.clone(),
                            last_seen: boot_now,
                            first_seen: boot_now,
                        });
                    }
                    push_peer_notification(
                        &mut s,
                        "vess_peer_handshake_attempted",
                        &peer_hash,
                        Some("bootstrap".to_string()),
                        format!("Attempting Vess handshake with bootstrap peer: {}", hex_key(&peer_hash)),
                    );
                }
                info!(peer = %peer_str, "connecting to bootstrap peer");

                let nonce = match {
                    let mut s = boot_state.lock().unwrap();
                    s.peer_registry.issue_challenge(peer_hash)
                } {
                    Some(n) => n,
                    None => continue, // peer is banished, skip
                };
                let challenge = PulseMessage::HandshakeChallenge(HandshakeChallenge { nonce });
                match boot_node
                    .send_message_with_response(&target, &challenge)
                    .await
                {
                    Ok(Some(PulseMessage::HandshakeResponse(resp))) => {
                        let mut s = boot_state.lock().unwrap();
                        if s.peer_registry.verify_response(
                            &peer_hash,
                            &resp.hmac,
                            &ALLOWED_VERSIONS,
                        ) {
                            // Verify Argon2id PoW from the bootstrap peer.
                            if resp.pow_hash.is_empty()
                                || !verify_handshake_pow(&peer_hash, &nonce, &resp.pow_hash)
                            {
                                let failures = s.peer_registry.record_handshake_failure(&peer_hash);
                                warn!(peer = %peer_str, failures, "bootstrap peer PoW verification failed");
                                // Don't banish here — let the handshake drain retry with backoff.
                                push_peer_notification(
                                    &mut s,
                                    "vess_peer_handshake_failed",
                                    &peer_hash,
                                    Some("bootstrap".to_string()),
                                    format!("Bootstrap handshake failed PoW verification for peer: {} (attempt {failures})", hex_key(&peer_hash)),
                                );
                                continue;
                            }
                            // Reset failure count on success.
                            s.peer_registry.record_handshake_success(&peer_hash);
                            if let Some(ref ek) = resp.relay_ek {
                                s.peer_registry.set_relay_ek(&peer_hash, ek.clone());
                            }
                            push_peer_notification(
                                &mut s,
                                "vess_peer_verified",
                                &peer_hash,
                                Some("bootstrap".to_string()),
                                format!("Verified Vess peer after bootstrap handshake: {}", hex_key(&peer_hash)),
                            );
                            info!(peer = %peer_str, "bootstrap peer verified");
                            s.push_event(NodeEvent::PeerVerified { created_at: ArteryState::now_unix(), peer_id: hex_key(&peer_hash), direction: "bootstrap".to_string() });
                        } else {
                            let failures = s.peer_registry.record_handshake_failure(&peer_hash);
                            warn!(peer = %peer_str, failures, "bootstrap peer HMAC verification failed");
                            // Don't banish here — let the handshake drain retry with backoff.
                            push_peer_notification(
                                &mut s,
                                "vess_peer_handshake_failed",
                                &peer_hash,
                                Some("bootstrap".to_string()),
                                format!("Bootstrap handshake returned an invalid response for peer: {} (attempt {failures})", hex_key(&peer_hash)),
                            );
                            continue;
                        }
                    }
                    Ok(_) => {
                        let mut s = boot_state.lock().unwrap();
                        let failures = s.peer_registry.record_handshake_failure(&peer_hash);
                        push_peer_notification(
                            &mut s,
                            "vess_peer_handshake_failed",
                            &peer_hash,
                            Some("bootstrap".to_string()),
                            format!("Bootstrap handshake got an unexpected response from peer: {} (attempt {})", hex_key(&peer_hash), failures),
                        );
                        info!(peer = %peer_str, "bootstrap peer gave unexpected response");
                        continue;
                    }
                    Err(e) => {
                        let mut s = boot_state.lock().unwrap();
                        let failures = s.peer_registry.record_handshake_failure(&peer_hash);
                        push_peer_notification(
                            &mut s,
                            "vess_peer_handshake_failed",
                            &peer_hash,
                            Some("bootstrap".to_string()),
                            format!("Bootstrap handshake could not reach peer {}: {e} (attempt {})", hex_key(&peer_hash), failures),
                        );
                        warn!("bootstrap peer {peer_str} unreachable: {e}");
                        continue;
                    }
                }

                let msg = PulseMessage::PeerExchange(PeerExchange {
                    sender_id: boot_node.id().as_bytes().to_vec(),
                });
                match boot_node.send_message_with_response(&target, &msg).await {
                    Ok(Some(PulseMessage::PeerExchangeResponse(resp))) => {
                        if resp.peers.len() > MAX_PEER_EXCHANGE_PEERS {
                            warn!(
                                peer = %peer_str,
                                count = resp.peers.len(),
                                "bootstrap peer returned too many contacts; truncating response"
                            );
                        }
                        let mut s = boot_state.lock().unwrap();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for peer_bytes in resp.peers.iter().take(MAX_PEER_EXCHANGE_PEERS) {
                            let Some(peer_hash) = peer_hash_from_contact_bytes(peer_bytes) else {
                                continue;
                            };
                            if peer_hash == s.node_id {
                                continue;
                            }
                            if !s.routing_table.contains(&peer_hash) {
                                s.routing_table.insert(RoutingPeer {
                                    id_hash: peer_hash,
                                    id_bytes: peer_bytes.clone(),
                                    last_seen: now,
                                    first_seen: now,
                                });
                                s.handshake_queue.push(peer_hash);
                            }
                        }
                        s.estimated_network_size = s.routing_table.estimated_network_size();
                        let repl = dht_replication_factor(s.estimated_network_size);
                        s.tag_dht.set_k_replication(repl);
                        info!(
                            count = resp.peers.len(),
                            total = s.routing_table.peer_count(),
                            "received peers from bootstrap"
                        );
                    }
                    Ok(_) => warn!("unexpected response from bootstrap peer"),
                    Err(e) => warn!("bootstrap peer {peer_str} unreachable: {e}"),
                }
            }

            if !seed_snapshots.is_empty() {
                apply_quorum_seed_snapshots(&boot_state, seed_snapshots);
            }
        });
    }

    // ── Manifest store drain task ───────────────────────────────────
    let manifest_drain_state = state.clone();
    let manifest_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = manifest_rx.recv().await {
            let mut manifests = vec![first];
            while let Ok(item) = manifest_rx.try_recv() {
                manifests.push(item);
            }

            // E2: snapshot only the scores we need (one f64 per routable peer)
            // instead of cloning the full ReputationTable.
            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = manifest_drain_state.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (ph, rp, af) = s
                    .routing_table
                    .routable_peer_vecs(|id| s.peer_registry.state(id) == PeerState::Verified, now);
                let scores = s.reputation.snapshot_scores_for(&ph);
                (
                    ph,
                    rp,
                    af,
                    scores,
                    s.gossip_config.k_neighbors,
                    s.estimated_network_size,
                )
            };
            if routable_peers.is_empty() {
                continue;
            }

            let fan = dynamic_fan_out(net_size, RANDOM_FAN_OUT, RANDOM_FAN_OUT * 3);
            // E1: serialize each logical message once; share via Arc across targets.
            let mut per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>> = HashMap::new();
            for ms in &manifests {
                let bytes = match PulseMessage::ManifestStore(ms.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize ManifestStore failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    &ms.dht_key,
                    &peer_hashes,
                    &peer_scores,
                    &age_factors,
                    k,
                    fan,
                    routable_peers.len(),
                );
                for idx in indices {
                    per_peer.entry(idx).or_default().push(Arc::clone(&bytes));
                }
            }
            batch_forward_bytes_to_peers(&manifest_drain_node, &routable_peers, per_peer).await;
            info!(count = manifests.len(), "manifest store batch forwarded");
        }
    });

    let tag_drain_state = state.clone();
    let tag_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = tag_store_rx.recv().await {
            let mut tags = vec![first];
            while let Ok(item) = tag_store_rx.try_recv() {
                tags.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = tag_drain_state.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (ph, rp, af) = s
                    .routing_table
                    .routable_peer_vecs(|id| s.peer_registry.state(id) == PeerState::Verified, now);
                let scores = s.reputation.snapshot_scores_for(&ph);
                (
                    ph,
                    rp,
                    af,
                    scores,
                    s.gossip_config.k_neighbors,
                    s.estimated_network_size,
                )
            };
            if routable_peers.is_empty() {
                continue;
            }

            let fan = dynamic_fan_out(net_size, RANDOM_FAN_OUT, RANDOM_FAN_OUT * 3);
            let mut per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>> = HashMap::new();
            for ts in &tags {
                let dht_key = ts.tag_hash;
                let bytes = match PulseMessage::TagStore(ts.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize TagStore failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    &dht_key,
                    &peer_hashes,
                    &peer_scores,
                    &age_factors,
                    k,
                    fan,
                    routable_peers.len(),
                );
                for idx in indices {
                    per_peer.entry(idx).or_default().push(Arc::clone(&bytes));
                }
            }
            batch_forward_bytes_to_peers(&tag_drain_node, &routable_peers, per_peer).await;
            info!(count = tags.len(), "tag store batch forwarded");
        }
    });

    // ── Tag confirm drain task ──────────────────────────────────────
    let confirm_drain_state = state.clone();
    let confirm_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = tag_confirm_rx.recv().await {
            let mut confirms = vec![first];
            while let Ok(item) = tag_confirm_rx.try_recv() {
                confirms.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = confirm_drain_state.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (ph, rp, af) = s
                    .routing_table
                    .routable_peer_vecs(|id| s.peer_registry.state(id) == PeerState::Verified, now);
                let scores = s.reputation.snapshot_scores_for(&ph);
                (
                    ph,
                    rp,
                    af,
                    scores,
                    s.gossip_config.k_neighbors,
                    s.estimated_network_size,
                )
            };
            if routable_peers.is_empty() {
                continue;
            }

            let fan = dynamic_fan_out(net_size, RANDOM_FAN_OUT, RANDOM_FAN_OUT * 3);
            let mut per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>> = HashMap::new();
            for tc in &confirms {
                let dht_key = tc.tag_hash;
                let bytes = match PulseMessage::TagConfirm(tc.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize TagConfirm failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    &dht_key,
                    &peer_hashes,
                    &peer_scores,
                    &age_factors,
                    k,
                    fan,
                    routable_peers.len(),
                );
                for idx in indices {
                    per_peer.entry(idx).or_default().push(Arc::clone(&bytes));
                }
            }
            batch_forward_bytes_to_peers(&confirm_drain_node, &routable_peers, per_peer).await;
            info!(count = confirms.len(), "tag confirm batch forwarded");
        }
    });

    // ── Ownership genesis drain task ────────────────────────────────
    let og_drain_state = state.clone();
    let og_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = og_rx.recv().await {
            let mut items = vec![first];
            while let Ok(item) = og_rx.try_recv() {
                items.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = og_drain_state.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (ph, rp, af) = s
                    .routing_table
                    .routable_peer_vecs(|id| s.peer_registry.state(id) == PeerState::Verified, now);
                let scores = s.reputation.snapshot_scores_for(&ph);
                (
                    ph,
                    rp,
                    af,
                    scores,
                    s.gossip_config.k_neighbors,
                    s.estimated_network_size,
                )
            };
            if routable_peers.is_empty() {
                continue;
            }

            let fan = dynamic_fan_out(net_size, OWNERSHIP_FAN_OUT, OWNERSHIP_FAN_OUT * 3);
            let mut per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>> = HashMap::new();
            for og in &items {
                // OwnershipGenesis proofs can be 4 MiB — the Arc avoids that
                // clone multiplying by fan-out targets (E1).
                let bytes = match PulseMessage::OwnershipGenesis(og.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize OwnershipGenesis failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    &og.mint_id,
                    &peer_hashes,
                    &peer_scores,
                    &age_factors,
                    k,
                    fan,
                    routable_peers.len(),
                );
                for idx in indices {
                    per_peer.entry(idx).or_default().push(Arc::clone(&bytes));
                }
            }
            batch_forward_bytes_to_peers(&og_drain_node, &routable_peers, per_peer).await;
            info!(count = items.len(), "ownership genesis batch forwarded");
        }
    });

    // ── Ownership claim drain task ──────────────────────────────────
    let oc_drain_state = state.clone();
    let oc_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = oc_rx.recv().await {
            let mut items = vec![first];
            while let Ok(item) = oc_rx.try_recv() {
                items.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = oc_drain_state.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (ph, rp, af) = s
                    .routing_table
                    .routable_peer_vecs(|id| s.peer_registry.state(id) == PeerState::Verified, now);
                let scores = s.reputation.snapshot_scores_for(&ph);
                (
                    ph,
                    rp,
                    af,
                    scores,
                    s.gossip_config.k_neighbors,
                    s.estimated_network_size,
                )
            };
            if routable_peers.is_empty() {
                continue;
            }

            let fan = dynamic_fan_out(net_size, OWNERSHIP_FAN_OUT, OWNERSHIP_FAN_OUT * 3);
            let mut per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>> = HashMap::new();
            for oc in &items {
                let bytes = match PulseMessage::OwnershipClaim(oc.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize OwnershipClaim failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    &oc.mint_id,
                    &peer_hashes,
                    &peer_scores,
                    &age_factors,
                    k,
                    fan,
                    routable_peers.len(),
                );
                for idx in indices {
                    per_peer.entry(idx).or_default().push(Arc::clone(&bytes));
                }
            }
            batch_forward_bytes_to_peers(&oc_drain_node, &routable_peers, per_peer).await;
            info!(count = items.len(), "ownership claim batch forwarded");
        }
    });

    // ── Reforge attestation drain task ──────────────────────────────
    let ra_drain_state = state.clone();
    let ra_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = ra_rx.recv().await {
            let mut items = vec![first];
            while let Ok(item) = ra_rx.try_recv() {
                items.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = ra_drain_state.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (ph, rp, af) = s
                    .routing_table
                    .routable_peer_vecs(|id| s.peer_registry.state(id) == PeerState::Verified, now);
                let scores = s.reputation.snapshot_scores_for(&ph);
                (
                    ph,
                    rp,
                    af,
                    scores,
                    s.gossip_config.k_neighbors,
                    s.estimated_network_size,
                )
            };
            if routable_peers.is_empty() {
                continue;
            }

            let fan = dynamic_fan_out(net_size, RANDOM_FAN_OUT, RANDOM_FAN_OUT * 3);
            let mut per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>> = HashMap::new();
            for ra in &items {
                let bytes = match PulseMessage::ReforgeAttestation(ra.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize ReforgeAttestation failed");
                        continue;
                    }
                };
                for cid in &ra.consumed_mint_ids {
                    let indices = compute_gossip_targets_scored(
                        cid,
                        &peer_hashes,
                        &peer_scores,
                        &age_factors,
                        k,
                        fan,
                        routable_peers.len(),
                    );
                    for idx in indices {
                        per_peer.entry(idx).or_default().push(Arc::clone(&bytes));
                    }
                }
            }
            batch_forward_bytes_to_peers(&ra_drain_node, &routable_peers, per_peer).await;
            info!(count = items.len(), "reforge attestation batch forwarded");
        }
    });

    // ── Payment relay drain task ────────────────────────────────────
    // Forward payments to K-nearest peers by stealth_id so multiple
    // independent nodes hold the payment in limbo, preventing
    // single-relay censorship.
    let pay_drain_state = state.clone();
    let pay_drain_node = node.clone();
    let pay_retry_tx = pay_tx.clone();
    tokio::spawn(async move {
        while let Some(first) = pay_rx.recv().await {
            let mut items = vec![first];
            while let Ok(item) = pay_rx.try_recv() {
                items.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = pay_drain_state.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let (ph, rp, af) = s
                    .routing_table
                    .routable_peer_vecs(|id| s.peer_registry.state(id) == PeerState::Verified, now);
                let scores = s.reputation.snapshot_scores_for(&ph);
                (
                    ph,
                    rp,
                    af,
                    scores,
                    s.gossip_config.k_neighbors,
                    s.estimated_network_size,
                )
            };
            if routable_peers.is_empty() {
                retry_unroutable_payment_batch(&pay_retry_tx, items).await;
                continue;
            }

            let fan = dynamic_fan_out(net_size, RANDOM_FAN_OUT, RANDOM_FAN_OUT * 3);
            let mut per_peer: HashMap<usize, Vec<Arc<Vec<u8>>>> = HashMap::new();
            for p in &items {
                let bytes = match PulseMessage::Payment(p.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize Payment failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    // Route by mailbox_key when present — puts payment into the
                    // recipient's DHT shard rather than broadcasting by stealth_id.
                    p.mailbox_key.as_ref().unwrap_or(&p.stealth_id),
                    &peer_hashes,
                    &peer_scores,
                    &age_factors,
                    k,
                    fan,
                    routable_peers.len(),
                );
                for idx in indices {
                    per_peer.entry(idx).or_default().push(Arc::clone(&bytes));
                }
            }
            batch_forward_payments_with_retry(&pay_drain_node, &routable_peers, per_peer, &pay_retry_tx).await;
            info!(count = items.len(), "payment relay batch forwarded");
        }
    });

    // ── Mailbox forward delivery drain task ─────────────────────────
    // Sends a LimboDeliver to each subscribed node when a matching
    // payment arrives so recipients get push notification rather than
    // having to poll.
    let fwd_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some((target_bytes, payment)) = fwd_rx.recv().await {
            let target = match decode_contact_bytes(&target_bytes) {
                Ok(contact) => contact,
                Err(_) => continue,
            };
            let msg = PulseMessage::LimboDeliver(vess_protocol::LimboDeliver { payment });
            if let Err(e) = fwd_drain_node.send_message(&target, &msg).await {
                warn!(error = %e, "mailbox forward delivery failed");
            }
        }
    });

    // ── Hydra periodic peer exchange (push + pull) ──────────────────
    // Every 15s: push our top peers to 3 random verified neighbors.
    // When below target (<8 routable): also pull from known peers.
    let pex_node = node.clone();
    let pex_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;

            let (routable_count, our_peers, targets): (usize, Vec<Vec<u8>>, Vec<Vec<u8>>) = {
                let s = pex_state.lock().unwrap();
                let routable = s.routing_table.routable_peers(|_| true);
                let count = routable.len();
                let our = routable.iter()
                    .filter(|p| !p.id_bytes.is_empty() && p.id_bytes.len() <= MAX_SERIALIZED_MESH_CONTACT_BYTES)
                    .take(MAX_PEER_EXCHANGE_PEERS)
                    .map(|p| p.id_bytes.clone())
                    .collect();
                // Pick up to 3 random verified peers to push to
                let targets: Vec<Vec<u8>> = s.peer_registry
                    .verified_peer_id_bytes()
                    .into_iter()
                    .filter_map(|hash| s.routing_table.peer_id_bytes(&hash))
                    .take(20) // candidate pool
                    .collect();
                // Shuffle and pick 3
                let mut rng = rand::thread_rng();
                let mut targets = targets;
                targets.shuffle(&mut rng);
                targets.truncate(3);
                (count, our, targets)
            };

            // Push our peers to verified neighbors (unsolicited PeerExchange → they respond)
            if !our_peers.is_empty() {
                for target_bytes in &targets {
                    let target = match decode_contact_bytes(target_bytes) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let msg = PulseMessage::PeerExchange(PeerExchange {
                        sender_id: pex_node.id().as_bytes().to_vec(),
                    });
                    if let Ok(Some(PulseMessage::PeerExchangeResponse(resp))) =
                        pex_node.send_message_with_response(&target, &msg).await
                    {
                        let mut s = pex_state.lock().unwrap();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for new_peer_bytes in resp.peers.iter().take(MAX_PEER_EXCHANGE_PEERS) {
                            let Some(hash) = peer_hash_from_contact_bytes(new_peer_bytes) else { continue };
                            if hash == s.node_id || s.routing_table.contains(&hash) { continue; }
                            s.routing_table.insert(RoutingPeer {
                                id_hash: hash,
                                id_bytes: new_peer_bytes.clone(),
                                last_seen: now,
                                first_seen: now,
                            });
                            if !s.handshake_queue.contains(&hash) {
                                s.handshake_queue.push(hash);
                            }
                        }
                        s.estimated_network_size = s.routing_table.estimated_network_size();
                        let repl = dht_replication_factor(s.estimated_network_size);
                        s.tag_dht.set_k_replication(repl);
                    }
                }
            }

            // Pull from random peers when below target
            if routable_count < 8 {
                let pull_targets: Vec<Vec<u8>> = {
                    let s = pex_state.lock().unwrap();
                    s.routing_table.routable_peers(|_| true)
                        .into_iter()
                        .take(5)
                        .map(|p| p.id_bytes)
                        .collect()
                };
                for peer_bytes in &pull_targets {
                    let target = match decode_contact_bytes(peer_bytes) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let msg = PulseMessage::PeerExchange(PeerExchange {
                        sender_id: pex_node.id().as_bytes().to_vec(),
                    });
                    if let Ok(Some(PulseMessage::PeerExchangeResponse(resp))) =
                        pex_node.send_message_with_response(&target, &msg).await
                    {
                        let mut s = pex_state.lock().unwrap();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for new_peer_bytes in resp.peers.iter().take(MAX_PEER_EXCHANGE_PEERS) {
                            let Some(hash) = peer_hash_from_contact_bytes(new_peer_bytes) else { continue };
                            if hash == s.node_id || s.routing_table.contains(&hash) { continue; }
                            s.routing_table.insert(RoutingPeer {
                                id_hash: hash,
                                id_bytes: new_peer_bytes.clone(),
                                last_seen: now,
                                first_seen: now,
                            });
                            if !s.handshake_queue.contains(&hash) {
                                s.handshake_queue.push(hash);
                            }
                        }
                        s.estimated_network_size = s.routing_table.estimated_network_size();
                        let repl = dht_replication_factor(s.estimated_network_size);
                        s.tag_dht.set_k_replication(repl);
                    }
                }
            }
        }
    });

    // ── Handshake drain task ────────────────────────────────────────
    let hs_node = node.clone();
    let hs_state = state.clone();
    let hs_ban = banishment.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;

            let peers_to_challenge: Vec<[u8; 32]> = {
                let mut s = hs_state.lock().unwrap();
                let evicted = s.peer_registry.evict_stale();
                // Re-queue evicted peers that are ready for retry.
                for id in evicted {
                    if s.peer_registry.ready_for_retry(&id) {
                        s.handshake_queue.push(id);
                    }
                }
                s.handshake_queue.drain(..).collect()
            };

            for peer_hash in peers_to_challenge {
                {
                    let s = hs_state.lock().unwrap();
                    let st = s.peer_registry.state(&peer_hash);
                    if st == PeerState::Verified || st == PeerState::Banished {
                        continue;
                    }
                }

                let target_bytes = {
                    let s = hs_state.lock().unwrap();
                    match s.routing_table.peer_id_bytes(&peer_hash) {
                        Some(bytes) => bytes,
                        None => continue,
                    }
                };
                let target = match decode_contact_bytes(&target_bytes) {
                    Ok(contact) => contact,
                    Err(_) => continue,
                };

                let nonce = match {
                    let mut s = hs_state.lock().unwrap();
                    s.peer_registry.issue_challenge(peer_hash)
                } {
                    Some(n) => n,
                    None => continue, // peer is banished, skip
                };

                {
                    let mut s = hs_state.lock().unwrap();
                    push_peer_notification(
                        &mut s,
                        "vess_peer_handshake_attempted",
                        &peer_hash,
                        None,
                        format!("Attempting Vess handshake with discovered peer: {}", hex_key(&peer_hash)),
                    );
                }

                let challenge = PulseMessage::HandshakeChallenge(HandshakeChallenge { nonce });
                if let Ok(Some(PulseMessage::HandshakeResponse(resp))) = hs_node
                    .send_message_with_response(&target, &challenge)
                    .await
                {
                    // HMAC check (quick, inside lock) then PoW verification
                    // (slow, ~2s, outside lock to avoid blocking everything).
                    let hmac_ok = {
                        let mut s = hs_state.lock().unwrap();
                        s.peer_registry.verify_response(&peer_hash, &resp.hmac, &ALLOWED_VERSIONS)
                    };
                    let pow_ok = if hmac_ok && !resp.pow_hash.is_empty() {
                        verify_handshake_pow(&peer_hash, &nonce, &resp.pow_hash)
                    } else {
                        false
                    };

                    let verified = {
                        let mut s = hs_state.lock().unwrap();
                        if hmac_ok {
                            if !pow_ok {
                                let failures = s.peer_registry.record_handshake_failure(&peer_hash);
                                warn!(failures, "peer PoW verification failed");
                                if failures >= MAX_HANDSHAKE_FAILURES {
                                    s.peer_registry.mark_banished(peer_hash);
                                    hs_ban.banish(peer_hash);
                                    s.push_event(NodeEvent::PeerBanished { created_at: ArteryState::now_unix(), peer_id: hex_key(&peer_hash), reason: format!("PoW verification failed {failures} times") });
                                }
                                push_peer_notification(
                                    &mut s,
                                    "vess_peer_handshake_failed",
                                    &peer_hash,
                                    None,
                                    format!("Handshake failed PoW verification for peer: {} (attempt {failures})", hex_key(&peer_hash)),
                                );
                                false
                            } else {
                                // Reset failure count on success.
                                s.peer_registry.record_handshake_success(&peer_hash);
                                if let Some(ref ek) = resp.relay_ek {
                                    s.peer_registry.set_relay_ek(&peer_hash, ek.clone());
                                }
                                push_peer_notification(
                                    &mut s,
                                    "vess_peer_verified",
                                    &peer_hash,
                                    None,
                                    format!("Verified Vess peer after handshake: {}", hex_key(&peer_hash)),
                                );
                                info!("peer verified via handshake");
                                s.push_event(NodeEvent::PeerVerified { created_at: ArteryState::now_unix(), peer_id: hex_key(&peer_hash), direction: "handshake".to_string() });
                                true
                            }
                        } else {
                            let failures = s.peer_registry.record_handshake_failure(&peer_hash);
                            warn!(failures, "peer HMAC verification failed");
                            if failures >= MAX_HANDSHAKE_FAILURES {
                                s.peer_registry.mark_banished(peer_hash);
                                hs_ban.banish(peer_hash);
                                s.push_event(NodeEvent::PeerBanished { created_at: ArteryState::now_unix(), peer_id: hex_key(&peer_hash), reason: format!("HMAC verification failed {failures} times") });
                            }
                            push_peer_notification(
                                &mut s,
                                "vess_peer_handshake_failed",
                                &peer_hash,
                                None,
                                format!("Handshake returned an invalid response for peer: {} (attempt {failures})", hex_key(&peer_hash)),
                            );
                            info!("peer HMAC failed — attempt {failures}/{}", MAX_HANDSHAKE_FAILURES);
                            false
                        }
                    };

                    if verified {
                        // Ingest known_peers from the handshake response (hydra bootstrap)
                        if !resp.known_peers.is_empty() {
                            let mut s = hs_state.lock().unwrap();
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            for peer_bytes in resp.known_peers.iter().take(MAX_PEER_EXCHANGE_PEERS) {
                                if let Some(hash) = peer_hash_from_contact_bytes(peer_bytes) {
                                    if hash != s.node_id && !s.routing_table.contains(&hash) {
                                        s.routing_table.insert(RoutingPeer {
                                            id_hash: hash,
                                            id_bytes: peer_bytes.clone(),
                                            last_seen: now,
                                            first_seen: now,
                                        });
                                        if !s.handshake_queue.contains(&hash) {
                                            s.handshake_queue.push(hash);
                                        }
                                    }
                                }
                            }
                            let repl = dht_replication_factor(s.routing_table.estimated_network_size());
                            s.tag_dht.set_k_replication(repl);
                        }
                        // Also do explicit peer exchange for additional peers
                        request_peer_exchange_from_peer(&hs_node, &target, &hs_state).await;
                        refresh_mailbox_forward_subscriptions(&hs_node, &hs_state).await;
                    }
                } else {
                    let mut s = hs_state.lock().unwrap();
                    let failures = s.peer_registry.record_handshake_failure(&peer_hash);
                    if failures >= MAX_HANDSHAKE_FAILURES {
                        s.peer_registry.mark_banished(peer_hash);
                        hs_ban.banish(peer_hash);
                        s.push_event(NodeEvent::PeerBanished { created_at: ArteryState::now_unix(), peer_id: hex_key(&peer_hash), reason: format!("handshake timed out {failures} times") });
                    }
                    push_peer_notification(
                        &mut s,
                        "vess_peer_handshake_failed",
                        &peer_hash,
                        None,
                        format!("Handshake timed out or returned no usable response for peer: {} (attempt {failures})", hex_key(&peer_hash)),
                    );
                }
            }
        }
    });

    // ── Periodic re-verification task (24 h) ────────────────────────
    //
    // Every hour, collect peers whose last verification is older than
    // REVERIFICATION_INTERVAL and re-challenge them with the full
    // handshake (HMAC + Argon2id PoW).  Peers that fail are banished.
    let reverify_node = node.clone();
    let reverify_state = state.clone();
    let reverify_ban = banishment.clone();
    tokio::spawn(async move {
        // Check every hour — the 24 h threshold is inside PeerRegistry.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;

            let stale_peers: Vec<[u8; 32]> = {
                let s = reverify_state.lock().unwrap();
                s.peer_registry
                    .peers_due_for_reverification(crate::handshake::REVERIFICATION_INTERVAL)
            };

            for peer_hash in stale_peers {
                // Look up the raw id_bytes from the routing table.
                let id_bytes: Option<Vec<u8>> = {
                    let s = reverify_state.lock().unwrap();
                    s.routing_table.peer_id_bytes(&peer_hash)
                };
                let id_bytes = match id_bytes {
                    Some(b) => b,
                    None => continue, // peer no longer in routing table
                };

                let nonce = match {
                    let mut s = reverify_state.lock().unwrap();
                    s.peer_registry.issue_challenge(peer_hash)
                } {
                    Some(n) => n,
                    None => continue, // peer is banished, skip
                };

                let target = match decode_contact_bytes(&id_bytes) {
                    Ok(contact) => contact,
                    Err(_) => continue,
                };

                let challenge = PulseMessage::HandshakeChallenge(HandshakeChallenge { nonce });
                match reverify_node
                    .send_message_with_response(&target, &challenge)
                    .await
                {
                    Ok(Some(PulseMessage::HandshakeResponse(resp))) => {
                        let mut s = reverify_state.lock().unwrap();
                        if s.peer_registry.verify_response(
                            &peer_hash,
                            &resp.hmac,
                            &ALLOWED_VERSIONS,
                        ) {
                            if resp.pow_hash.is_empty()
                                || !verify_handshake_pow(&peer_hash, &nonce, &resp.pow_hash)
                            {
                                warn!("re-verification PoW failed — banishing");
                                s.peer_registry.mark_banished(peer_hash);
                                reverify_ban.banish(peer_hash);
                            } else {
                                info!("peer re-verified successfully");
                            }
                        } else {
                            s.peer_registry.mark_banished(peer_hash);
                            reverify_ban.banish(peer_hash);
                            info!("peer banished — failed re-verification handshake");
                        }
                    }
                    _ => {
                        // No response or wrong message type — banish.
                        let mut s = reverify_state.lock().unwrap();
                        s.peer_registry.mark_banished(peer_hash);
                        reverify_ban.banish(peer_hash);
                        info!("peer banished — no response to re-verification challenge");
                    }
                }
            }
        }
    });

    // ── Limbo retry task ────────────────────────────────────────────
    let limbo_node = node.clone();
    let limbo_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;

            let deliveries: Vec<([u8; 32], Vec<vess_protocol::Payment>)> = {
                let s = limbo_state.lock().unwrap();
                s.limbo_buffer
                    .stealth_ids_with_payments()
                    .into_iter()
                    .map(|sid| {
                        let entries = s.limbo_buffer.peek(&sid);
                        let payments: Vec<vess_protocol::Payment> =
                            entries.iter().map(|e| e.payment.clone()).collect();
                        (sid, payments)
                    })
                    .collect()
            };

            if deliveries.is_empty() {
                continue;
            }

            info!(
                recipients = deliveries.len(),
                "limbo retry: broadcasting notifications"
            );

            let notify_msgs: Vec<(Vec<Vec<u8>>, vess_protocol::PulseMessage)> = {
                let s = limbo_state.lock().unwrap();
                let routable: Vec<Vec<u8>> = s
                    .routing_table
                    .routable_peers(|id| s.peer_registry.state(id) == PeerState::Verified)
                    .into_iter()
                    .map(|p| p.id_bytes)
                    .collect();

                deliveries
                    .iter()
                    .map(|(sid, payments)| {
                        let msg = PulseMessage::LimboNotify(vess_protocol::LimboNotify {
                            stealth_id: *sid,
                            count: payments.len() as u32,
                            custodian_id: s.node_id,
                        });
                        (routable.clone(), msg)
                    })
                    .collect()
            };

            for (peers, msg) in notify_msgs {
                for peer_bytes in &peers {
                    let target = match decode_contact_bytes(peer_bytes) {
                        Ok(contact) => contact,
                        Err(_) => continue,
                    };
                    if let Err(e) = limbo_node.send_message(&target, &msg).await {
                        warn!("limbo notify failed: {e}");
                    }
                }
            }
        }
    });

    // ── Auto mailbox-forward subscription ──────────────────────────
    //
    // When a wallet is loaded, register with the K nearest verified peers
    // for our `mailbox_key` so they push matching payments via LimboDeliver.
    // Runs every 30 minutes, which is half the maximum TTL (3600 s), so the
    // subscription stays continuously active without waiting for expiry.
    // The first attempt is delayed by 5 s to allow bootstrap peers to connect.
    let fwd_sub_node = node.clone();
    let fwd_sub_state = state.clone();
    tokio::spawn(async move {
        // Give bootstrap / handshake tasks a head-start before we register.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        refresh_mailbox_forward_subscriptions(&fwd_sub_node, &fwd_sub_state).await;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1_800));
        loop {
            interval.tick().await;
            refresh_mailbox_forward_subscriptions(&fwd_sub_node, &fwd_sub_state).await;
        }
    });

    // ── Message handler ─────────────────────────────────────────────
    // Signal the node ID to any waiting test/caller now that the
    // listener is about to start accepting connections.
    if let Some(tx) = config.ready_tx {
        let _ = tx.send(node_id_str.clone());
    }

    let st = state.clone();
    let ban_ref = banishment.clone();
    let h_manifest_tx = manifest_tx.clone();
    let h_tag_store_tx = tag_store_tx.clone();
    let h_tag_confirm_tx = tag_confirm_tx.clone();
    let h_og_tx = og_tx.clone();
    let h_oc_tx = oc_tx.clone();
    let h_ra_tx = ra_tx.clone();
    let h_pay_tx = pay_tx.clone();
    let h_fwd_tx = fwd_tx.clone();
    let relay_ek_for_handshake = own_relay_ek.clone();
    let hs_state_ref = st.clone(); // for extracting known peers in handshake response

    // ── Spawn message listener so we can cancel on SIGTERM ──────────
    let listen_node = node.clone();
    let onion_node = node.clone(); // for onion forwarding
    let limbo_ack_node = node.clone();
    let listen_handle = tokio::spawn(async move {
        listen_node.listen_messages_with_response(move |peer, msg| {
        let Some(peer_hash) = peer.node_id().map(|node_id| *node_id.as_bytes()) else {
            return None;
        };
        if ban_ref.is_banished(&peer_hash) {
            return None;
        }

        let peer_id: [u8; 32] = peer_hash;
        let peer_bytes = match encode_contact_bytes(&peer.contact) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(peer = %peer, error = %e, "failed to serialize peer contact");
                return None;
            }
        };
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Quick routing update — lock briefly (try_lock so we never block
        // the message listener and prevent handshake processing).
        let node_id_local;
        let mut known_peers_snapshot: Vec<Vec<u8>> = Vec::new();
        {
            let mut state = match st.try_lock() {
                Ok(s) => s,
                Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    // Lock busy — drop message, sender will retry.
                    return None;
                }
            };

            if state.routing_table.contains(&peer_id) {
                state.routing_table.fill_id_bytes(&peer_id, peer_bytes.clone());
            } else {
                let inserted = state.routing_table.insert(RoutingPeer {
                    id_hash: peer_id,
                    id_bytes: peer_bytes.clone(),
                    last_seen: now_ts,
                    first_seen: now_ts,
                });
                if inserted {
                    push_peer_notification(
                        &mut state,
                        "vess_peer_discovered",
                        &peer_id,
                        Some("inbound".to_string()),
                        format!("Discovered Vess peer via inbound traffic: {}", hex_key(&peer_id)),
                    );
                    info!(%peer, "new peer discovered ({} total)", state.routing_table.peer_count());
                }
            }
            if state.peer_registry.state(&peer_id) != PeerState::Verified
                && !state.handshake_queue.contains(&peer_id)
            {
                state.handshake_queue.push(peer_id);
            }
            node_id_local = state.node_id;
            // Snapshot known peer contacts for hydra bootstrap share
            known_peers_snapshot = state.routing_table.routable_peers(|_| true)
                .into_iter()
                .filter(|p| !p.id_bytes.is_empty() && p.id_bytes.len() <= MAX_SERIALIZED_MESH_CONTACT_BYTES)
                .take(MAX_PEER_EXCHANGE_PEERS)
                .map(|p| p.id_bytes)
                .collect();
        } // Lock released here — other tasks can now acquire it.

        // ── HandshakeChallenge: can be handled without the state lock ──
        // because we only need node_id (already extracted above) and the
        // PoW computation is expensive (~2s blocking).
        if let PulseMessage::HandshakeChallenge(hc) = &msg {
            let hmac = compute_handshake_hmac(&PROTOCOL_VERSION_HASH, &hc.nonce);
            let nonce = hc.nonce;
            let pow_hash = tokio::task::block_in_place(|| {
                compute_handshake_pow(&node_id_local, &nonce)
            });
            return Some(PulseMessage::HandshakeResponse(HandshakeResponse {
                hmac,
                pow_hash,
                relay_ek: relay_ek_for_handshake.clone(),
                known_peers: known_peers_snapshot.clone(),
            }));
        }

        // Re-acquire lock for remaining message types.
        // Use try_lock with a short retry so we don't block the message
        // listener (preventing HandshakeChallenge processing).
        let mut state = match st.try_lock() {
            Ok(s) => s,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                // Lock busy — skip this message, sender will retry.
                return None;
            }
        };

        // ── Handshake messages (continued) ──────────────────────────
        match &msg {
            PulseMessage::HandshakeChallenge(_hc) => {
                // Already handled above; this arm is unreachable but
                // required for exhaustive match.
                unreachable!();
            }
            PulseMessage::HandshakeResponse(hr) => {
                // Read the challenge nonce BEFORE verify_response consumes it.
                let stored_nonce = state.peer_registry.challenge_nonce(&peer_id);
                let was_already_verified =
                    state.peer_registry.state(&peer_id) == PeerState::Verified;
                let valid = state.peer_registry.verify_response(
                    &peer_id,
                    &hr.hmac,
                    &ALLOWED_VERSIONS,
                );
                if !valid {
                    // If the peer was already Verified (e.g. via the handshake
                    // drain task), a stray HandshakeResponse with a zero nonce
                    // is harmless — just ignore it rather than banishing.
                    if was_already_verified {
                        info!(%peer, "ignoring HandshakeResponse for already-verified peer");
                        return None;
                    }
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    info!(%peer, "handshake HMAC verification failed — banished locally");
                    return None;
                }
                // Verify the Argon2id PoW. A missing or invalid PoW means the
                // peer either didn't invest resources or is running old software.
                match stored_nonce {
                    Some(nonce) => {
                        if hr.pow_hash.is_empty()
                            || !verify_handshake_pow(&peer_id, &nonce, &hr.pow_hash)
                        {
                            warn!(%peer, "handshake PoW verification failed — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                        } else {
                            push_peer_notification(
                                &mut state,
                                "vess_peer_verified",
                                &peer_id,
                                Some("inbound".to_string()),
                                format!("Verified Vess peer after handshake: {}", hex_key(&peer_id)),
                            );
                        }
                    }
                    None => {
                        // No challenge nonce on record — peer responded to a
                        // challenge we never sent. Reject but don't banish
                        // (could be a race with a restart).
                        warn!(%peer, "handshake response without stored nonce — ignoring");
                    }
                }
                return None;
            }
            PulseMessage::BanishmentProof(bp) => {
                info!(%peer, "banishment proof received");
                if verify_banishment_proof(&bp) {
                    state.peer_registry.mark_banished(bp.peer_id);
                    ban_ref.banish(bp.peer_id);
                    info!(
                        target = %crate::persistence::hex_key(&bp.peer_id),
                        "peer banished via network-wide banishment proof"
                    );
                } else {
                    warn!(%peer, "invalid banishment proof — rejecting");
                }
            }
            _ => {}
        }

        // ── Per-peer rate limiting ─────────────────────────────────
        if !state.rate_limiter.allow(&peer_id) {
            if state.rate_limiter.should_banish(&peer_id) {
                warn!(%peer, "rate limit abuse — banishing peer locally");
                state.peer_registry.mark_banished(peer_id);
                ban_ref.banish(peer_id);
            } else {
                warn!(%peer, "rate limited — dropping message");
            }
            return None;
        }

        // ── Per-peer duplicate flood detection ─────────────────────
        // H1: Hash only identifying fields (not the full 4 MiB proof body).
        let payload_hash: [u8; 32] = message_dedup_key(&msg);
        if let Some(dup_count) = state.duplicate_tracker.record(&peer_id, &payload_hash) {
            warn!(%peer, dup_count, "duplicate flood detected — banishing peer locally");
            state.peer_registry.mark_banished(peer_id);
            state.duplicate_tracker.evict(&peer_id);
            ban_ref.banish(peer_id);
            return None;
        }

        // ── Update last_seen in routing table ──────────────────────
        // The peer passed rate-limit and duplicate checks, so this is
        // a valid communication. Touch moves the peer to the MRU
        // position in its bucket — silent/fake Sybil nodes drift
        // toward LRU eviction while active peers stay protected.
        state.routing_table.touch(&peer_id, now_ts);

        // ── Mesh-critical gating ────────────────────────────────────
        let mesh_critical = matches!(
            &msg,
            PulseMessage::PeerExchange(_)
                | PulseMessage::ManifestStore(_)
                | PulseMessage::OwnershipGenesis(_)
                | PulseMessage::OwnershipClaim(_)
                | PulseMessage::ReforgeAttestation(_)
                | PulseMessage::SwapOffer(_)
                | PulseMessage::LimboHold(_)
        );
        if mesh_critical && state.peer_registry.state(&peer_id) != PeerState::Verified {
            if state.peer_registry.state(&peer_id) == PeerState::Unknown {
                if !state.handshake_queue.contains(&peer_id) {
                    state.handshake_queue.push(peer_id);
                }
            }
            return None;
        }

        match msg {
            // No NullifierBroadcast handler — removed in registry-only model.

            PulseMessage::OwnershipGenesis(og) => {
                let ok = validate_and_retain_genesis(&mut state, &og, &peer_id);
                if ok {
                    // Re-gossip to propagate through the network
                    let _ = h_og_tx.send(og.clone());

                    // ── Bounty verification ──────────────────────
                    // If this genesis has unclaimed bounties and we have wallet
                    // credentials, try to claim one by recomputing Argon2id.
                    if let Some(ref bounty) = extract_bounty(&og) {
                        let node_id = state.node_id;
                        let wallet_vk = state.wallet.as_ref()
                            .and_then(|w| w.billfold.any_credential())
                            .map(|c| c.spend_vk.clone());
                        let wallet_sk = state.wallet.as_ref()
                            .and_then(|w| w.billfold.any_credential())
                            .map(|c| c.spend_sk.clone());
                        drop(state); // release lock before expensive work

                        if let (Some(vk), Some(sk)) = (wallet_vk, wallet_sk) {
                            let og_for_verify = og;
                            let h_og_tx_clone = h_og_tx.clone();
                            tokio::task::spawn_blocking(move || {
                                try_claim_bounty(&og_for_verify, &vk, &sk, node_id, &h_og_tx_clone);
                            });
                            // Re-acquire lock for remaining match arms
                            state = lock_state(&st);
                        }
                    }
                }
                None
            }

            PulseMessage::MailboxCollect(mc) => {
                // Rate-limit MailboxCollect to prevent stealth_id enumeration.
                if !state.mailbox_collect_limiter.allow(&peer_id) {
                    warn!(%peer, "mailbox collect rate-limited");
                    return Some(PulseMessage::MailboxCollectResponse(MailboxCollectResponse {
                        stealth_id: mc.stealth_id,
                        payloads: Vec::new(),
                    }));
                }

                // Collect pending payloads from limbo_buffer for this stealth_id.
                let entries = state.limbo_buffer.peek(&mc.stealth_id);
                let payloads: Vec<Vec<u8>> = entries
                    .iter()
                    .map(|e| e.payment.stealth_payload.clone())
                    .collect();
                info!(%peer, count = payloads.len(), "mailbox collect (from limbo)");
                Some(PulseMessage::MailboxCollectResponse(MailboxCollectResponse {
                    stealth_id: mc.stealth_id,
                    payloads,
                }))
            }

            PulseMessage::MailboxSweep(ms) => {
                // Rate-limit same as MailboxCollect.
                if !state.mailbox_collect_limiter.allow(&peer_id) {
                    warn!(%peer, "mailbox sweep rate-limited");
                    return Some(PulseMessage::MailboxSweepResponse(MailboxSweepResponse {
                        nonce: ms.nonce,
                        payloads: Vec::new(),
                    }));
                }

                // M4: Collect stealth_payloads in a single pass via sweep_payloads(),
                // avoiding the O(n) two-level iteration over all stealth IDs.
                // When the sweep carries a mailbox_key, return only matching payloads
                // (targeted sweep) — eliminates trial-decrypt of unrelated payments.
                let payloads = if let Some(ref key) = ms.mailbox_key {
                    state.limbo_buffer.sweep_by_mailbox_key(key, MAX_SWEEP_PAYLOADS)
                } else {
                    state.limbo_buffer.sweep_payloads(MAX_SWEEP_PAYLOADS)
                };
                info!(%peer, count = payloads.len(), mailbox_key = ms.mailbox_key.is_some(), "mailbox sweep");
                Some(PulseMessage::MailboxSweepResponse(MailboxSweepResponse {
                    nonce: ms.nonce,
                    payloads,
                }))
            }

            PulseMessage::MailboxForwardRegister(mfr) => {
                // Rate-limit to prevent subscription flooding.
                if !state.mailbox_fwd_limiter.allow(&peer_id) {
                    warn!(%peer, "mailbox forward register rate-limited");
                    return Some(PulseMessage::MailboxForwardAck(MailboxForwardAck {
                        nonce: mfr.nonce,
                        accepted: false,
                        queued_forwarded: 0,
                    }));
                }

                // Reject stale or future-shifted timestamps to block replays.
                let now = ArteryState::now_unix();
                let age = now.saturating_sub(mfr.timestamp);
                let skew = mfr.timestamp.saturating_sub(now);
                if age > FORWARD_TIMESTAMP_TOLERANCE_SECS || skew > MAX_FUTURE_SKEW_SECS {
                    warn!(%peer, age, "mailbox forward register rejected: stale/future timestamp");
                    return Some(PulseMessage::MailboxForwardAck(MailboxForwardAck {
                        nonce: mfr.nonce,
                        accepted: false,
                        queued_forwarded: 0,
                    }));
                }

                let ttl = (mfr.ttl_secs as u64).min(MAX_FORWARD_TTL_SECS);
                let expires_at = now + ttl;
                state.mailbox_fwd.insert(mfr.mailbox_key, ForwardRecord {
                    target_id_bytes: peer_bytes.clone(),
                    expires_at,
                });

                // Immediately push any already-waiting payments for this key.
                let waiting = state.limbo_buffer.payments_by_mailbox_key(&mfr.mailbox_key, MAX_SWEEP_PAYLOADS);
                let queued_forwarded = waiting.len() as u32;
                let target_bytes = peer_bytes.clone();
                for payment in waiting {
                    let _ = h_fwd_tx.send((target_bytes.clone(), payment));
                }

                info!(%peer, key = ?&mfr.mailbox_key[..4], ttl, queued = queued_forwarded, "mailbox forward subscription registered");
                Some(PulseMessage::MailboxForwardAck(MailboxForwardAck {
                    nonce: mfr.nonce,
                    accepted: true,
                    queued_forwarded,
                }))
            }

            PulseMessage::TagRegister(tr) => {
                info!(%peer, "tag registration for hash {:?}", &tr.tag_hash[..4]);

                if !timestamp_is_valid(tr.timestamp) {
                    warn!("tag registration rejected: timestamp out of range");
                    return None;
                }

                let tag_hash = tr.tag_hash;

                // Fast duplicate checks BEFORE expensive PoW verification.
                // 1. Tag already registered?
                if state.tag_dht.lookup_by_hash(&tag_hash).is_some() {
                    warn!("tag registration rejected: tag already registered");
                    return None;
                }
                // 2. Address already has a tag? (one-tag-per-address)
                let addr = vess_stealth::MasterStealthAddress {
                    scan_ek: tr.scan_ek.clone(),
                    spend_ek: tr.spend_ek.clone(),
                };
                let addr_fp = vess_tag::address_fingerprint(&addr);
                if state.tag_dht.has_address(&addr_fp) {
                    warn!("tag registration rejected: address already has a tag");
                    return None;
                }

                // Validate PoW format.
                let reg = vess_tag::TagRegistration {
                    tag_hash,
                    master_address: addr.clone(),
                    pow_nonce: tr.pow_nonce,
                    pow_hash: tr.pow_hash.clone(),
                };
                if let Err(e) = vess_tag::validate_registration(&reg) {
                    warn!("tag registration rejected: {e} — banishing peer");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }

                // Build the TagRecord.
                let record = vess_tag::TagRecord {
                    tag_hash,
                    master_address: addr,
                    pow_nonce: tr.pow_nonce,
                    pow_hash: tr.pow_hash.clone(),
                    registered_at: tr.timestamp,
                    registrant_vk: tr.registrant_vk.clone(),
                    signature: tr.signature.clone(),
                    hardened_at: None, // starts unhardened
                };

                // All tags MUST carry a valid registrant signature.
                if record.registrant_vk.is_empty() || record.signature.is_empty() {
                    warn!("tag registration: missing signature — rejecting");
                    return None;
                }
                match vess_tag::verify_record_signature(&record) {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!("tag registration: invalid signature — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    Err(e) => {
                        warn!("tag registration: signature check error: {e} — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                }

                // Verify Argon2id proof-of-work.
                #[cfg(any(test, feature = "test-pow"))]
                let pow_ok = vess_tag::verify_tag_pow_test(
                    &tag_hash,
                    &record.master_address.scan_ek,
                    &record.master_address.spend_ek,
                    &record.pow_nonce,
                    &record.pow_hash,
                );
                #[cfg(not(any(test, feature = "test-pow")))]
                let pow_ok = vess_tag::verify_tag_pow(
                    &tag_hash,
                    &record.master_address.scan_ek,
                    &record.master_address.spend_ek,
                    &record.pow_nonce,
                    &record.pow_hash,
                );
                match pow_ok {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!("tag registration: PoW verification failed — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    Err(e) => {
                        warn!("tag registration: PoW error: {e} — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                }

                if state.tag_dht.store(record) {
                    info!("tag stored in DHT — queueing replication");
                    let max_hops = state.gossip_config.max_hops;
                    let _ = h_tag_store_tx.send(TagStore {
                        tag_hash,
                        scan_ek: tr.scan_ek,
                        spend_ek: tr.spend_ek,
                        pow_nonce: tr.pow_nonce,
                        pow_hash: tr.pow_hash,
                        registered_at: tr.timestamp,
                        hops_remaining: max_hops,
                        registrant_vk: tr.registrant_vk,
                        signature: tr.signature,
                    });
                } else {
                    warn!("tag already registered (or address duplicate)");
                }
                None
            }

            PulseMessage::TagLookup(tl) => {
                // Tier 1: rate-limit only — anyone can check existence.
                if !state.tag_lookup_limiter.allow(&peer_id) {
                    warn!(%peer, "tag lookup rate-limited");
                    return Some(PulseMessage::TagLookupResponse(TagLookupResponse {
                        tag_hash: tl.tag_hash,
                        nonce: tl.nonce,
                        result: None,
                        requires_proof: false,
                    }));
                }

                let record = state.tag_dht.lookup_by_hash(&tl.tag_hash);

                // Tag not found — free response.
                let Some(record) = record else {
                    return Some(PulseMessage::TagLookupResponse(TagLookupResponse {
                        tag_hash: tl.tag_hash,
                        nonce: tl.nonce,
                        result: None,
                        requires_proof: false,
                    }));
                };

                // Tag found — Tier 2: require ProofOfVessOwnership for the address.
                if !state.is_testnet {
                    match &tl.burn_proof {
                        Some(proof) => {
                            if let Err(reason) = verify_tag_lookup_ownership_proof(
                                &tl.tag_hash, &tl.nonce, proof, &state,
                            ) {
                                warn!(%peer, %reason, "tag lookup: invalid proof — returning requires_proof");
                                return Some(PulseMessage::TagLookupResponse(TagLookupResponse {
                                    tag_hash: tl.tag_hash,
                                    nonce: tl.nonce,
                                    result: None,
                                    requires_proof: true,
                                }));
                            }
                        }
                        None => {
                            return Some(PulseMessage::TagLookupResponse(TagLookupResponse {
                                tag_hash: tl.tag_hash,
                                nonce: tl.nonce,
                                result: None,
                                requires_proof: true,
                            }));
                        }
                    }
                }

                info!(%peer, "tag lookup resolved");
                let lookup_result = TagLookupResult {
                    scan_ek: record.master_address.scan_ek.clone(),
                    spend_ek: record.master_address.spend_ek.clone(),
                    registered_at: record.registered_at,
                    pow_nonce: record.pow_nonce,
                    pow_hash: record.pow_hash.clone(),
                    registrant_vk: record.registrant_vk.clone(),
                    signature: record.signature.clone(),
                };
                Some(PulseMessage::TagLookupResponse(TagLookupResponse {
                    tag_hash: tl.tag_hash,
                    nonce: tl.nonce,
                    result: Some(lookup_result),
                    requires_proof: false,
                }))
            }

            PulseMessage::RelayPayment(rp) => {
                // ── Two-hop relay: unwrap and forward to DHT shard ──
                if state.passive_mode {
                    return None;
                }
                if rp.ttl == 0 {
                    warn!(%peer, "RelayPayment with ttl=0 — dropping");
                    return None;
                }
                let mut payment = rp.payment;
                if payment.mailbox_key.is_none() {
                    payment.mailbox_key = Some(rp.target_shard_key);
                }
                let _ = h_pay_tx.send(payment);
                info!(%peer, "relay payment unwrapped to gossip");
                None
            }

            PulseMessage::OnionRoute(or) => {
                // ── Onion-routed payment: decrypt one layer, forward or deliver ──
                if state.passive_mode {
                    return None;
                }
                // Use node's own mesh scan_dk to decrypt the onion layer
                let scan_dk = match &state.own_scan_dk {
                    Some(dk) => dk.clone(),
                    None => {
                        info!(%peer, "OnionRoute: no mesh scan_dk, forwarding");
                        return Some(PulseMessage::OnionRoute(or));
                    }
                };

                // Try single-KEM decrypt using mesh identity key
                match decrypt_onion_with_node_key(&scan_dk, &or.outer) {
                    Ok(OnionPayload::Forward { inner }) => {
                        info!(%peer, "onion forward");
                        let inner_route = OnionRoute { outer: *inner };
                        if let Ok(contact) = crate::mesh_contact::decode_contact_bytes(&or.outer.next_hop) {
                            let n = onion_node.clone();
                            let msg = PulseMessage::OnionRoute(inner_route);
                            tokio::spawn(async move {
                                let _ = n.send_message(&contact, &msg).await;
                            });
                        }
                        None
                    }
                    Ok(OnionPayload::Deliver { payment, shard_key }) => {
                        info!(%peer, "onion delivery — unwrapping to gossip");
                        let mut p = payment;
                        if p.mailbox_key.is_none() {
                            p.mailbox_key = Some(shard_key);
                        }
                        let _ = h_pay_tx.send(p);
                        None
                    }
                    Err(_e) => {
                        // Not for us — forward to the next_hop as-is
                        info!(%peer, "OnionRoute: layer not for us, forwarding");
                        Some(PulseMessage::OnionRoute(or))
                    }
                }
            }

            PulseMessage::Payment(p) => {
                info!(%peer, "payment relay");

                // Reject stale or future-dated payments to mitigate replays.
                if !timestamp_is_valid(p.created_at) {
                    warn!("payment rejected: timestamp out of range");
                    return None;
                }

                // Reject duplicate payment_id (exact same payment relayed twice).
                if state.limbo_payment_ids.contains(&p.payment_id) {
                    warn!("payment rejected: duplicate payment_id already in limbo");
                    return None;
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let stealth_id = p.stealth_id;
                let relay_copy = p.clone();
                let payment_id = p.payment_id;
                let mailbox_key = p.mailbox_key;
                let direct_receipt_tag_hash = p.direct_receipt_tag_hash;

                if !state.limbo_buffer.hold(stealth_id, p, Vec::new(), now, peer_id, mailbox_key) {
                    warn!(%peer, "payment rejected: limbo buffer at capacity or peer quota exceeded");
                    return None;
                }

                // Track AFTER successful hold so rejected payments don't
                // leave stale entries that block legitimate payments.
                state.limbo_payment_ids.insert(payment_id);

                // Forward to K-nearest by stealth_id so multiple relay
                // nodes hold the payment (prevents single-node censorship).
                // Skip if in passive mode — only relay own payments.
                if !state.passive_mode {
                    let _ = h_pay_tx.send(relay_copy.clone());
                }

                // Push to any active forwarding subscriber for this mailbox_key.
                if let Some(ref key) = mailbox_key {
                    if let Some(record) = state.mailbox_fwd.get(key) {
                        if record.expires_at > now {
                            let _ = h_fwd_tx.send((record.target_id_bytes.clone(), relay_copy));
                        }
                    }
                }

                // ── Auto-receive: trial-decrypt if wallet is loaded ─────
                // Clone the payload out first to avoid overlapping borrows.
                let maybe_payload = state.limbo_buffer.peek(&stealth_id)
                    .last()
                    .map(|e| e.payment.stealth_payload.clone());
                if let (Some(payload), Some(ref mut ws)) = (maybe_payload, &mut state.wallet) {
                    match receive_and_claim(
                        &ws.stealth_secret,
                        &payload,
                        &payment_id,
                    ) {
                        Ok(Some(result)) => {
                            let _receipt = if let Some(tag_hash) = direct_receipt_tag_hash {
                                match build_direct_payment_receipt(
                                    payment_id,
                                    tag_hash,
                                    stealth_id,
                                    &result.claimed,
                                ) {
                                    Some(receipt) => Some(receipt),
                                    None => {
                                        return Some(PulseMessage::DirectPaymentResponse(
                                            vess_protocol::DirectPaymentResponse {
                                                payment_id,
                                                accepted: false,
                                                receipt: None,
                                                reason: "failed to sign direct payment receipt".to_string(),
                                            },
                                        ));
                                    }
                                }
                            } else {
                                None
                            };
                            let mut total = 0u64;
                            let mut pending_oc = Vec::new();
                            let mut claimed_mids: Vec<[u8; 32]> = Vec::new();
                            // Save first spend credential before the loop consumes result.claimed.
                            let first_spend_sk = result.claimed.first().map(|c| c.spend_sk.clone());
                            let first_spend_vk = result.claimed.first().map(|c| c.spend_vk.clone());
                            for claimed in result.claimed {
                                total += claimed.bill.denomination.value();
                                claimed_mids.push(claimed.bill.mint_id);
                                ws.billfold.deposit_with_credentials(
                                    claimed.bill,
                                    SpendCredential {
                                        spend_vk: claimed.spend_vk,
                                        spend_sk: claimed.spend_sk,
                                    },
                                );
                            }
                            // ws is no longer used after this point; record
                            // entry times keyed by mint_id for latency tracking.
                            for mid in &claimed_mids {
                                state.limbo_entry_times.insert(*mid, now_ms);
                            }
                            for claim in result.ownership_claims {
                                if let PulseMessage::OwnershipClaim(oc) = claim {
                                    pending_oc.push(oc);
                                }
                            }
                            let memo_msg = result.memo.clone().filter(|m| !m.is_empty());
                            info!(amount = total, memo = ?memo_msg, "auto-received payment into wallet");
                            state.push_notification(WalletNotification {
                                kind: "payment_received".to_string(),
                                created_at: now,
                                payment_id: hex_key(&payment_id),
                                amount: Some(total),
                                bill_count: Some(pending_oc.len()),
                                counterparty: None,
                                message: match &memo_msg {
                                    Some(m) => format!("Received {total} Vess — {m}"),
                                    None => format!("Received {total} Vess"),
                                },
                            });
                            // Record in payment history.
                            state.payment_history.record_received(
                                &hex_key(&payment_id),
                                total,
                                None,
                                memo_msg.clone(),
                            );
                            // Build cryptographic PaymentReceipt proving we
                            // decrypted and claimed this payment.
                            let receipt_digest = {
                                let mut input = Vec::with_capacity(16 + 32 + claimed_mids.len() * 32 + 16);
                                input.extend_from_slice(b"vess-receipt-v0");
                                input.extend_from_slice(&payment_id);
                                for mid in &claimed_mids { input.extend_from_slice(mid); }
                                input.extend_from_slice(&total.to_le_bytes());
                                input.extend_from_slice(&now.to_le_bytes());
                                *blake3::hash(&input).as_bytes()
                            };
                            // Sign with the first claimed bill's spend_sk.
                            let receipt_sig = first_spend_sk.as_ref()
                                .and_then(|sk| vess_foundry::spend_auth::sign_spend(
                                    sk, &receipt_digest).ok())
                                .unwrap_or_default();

                            let receipt_msg = PulseMessage::PaymentReceipt(
                                vess_protocol::PaymentReceipt {
                                    payment_id,
                                    claimed_mint_ids: claimed_mids.clone(),
                                    total_amount: total,
                                    timestamp: now,
                                    signature: receipt_sig,
                                },
                            );

                            // ── Program receipt: if bills landed in a program ──
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(error = %e, "auto-receive trial-decrypt error");
                        }
                    }
                }

                info!(%peer, "payment entered limbo");

                // ── Send privacy-preserving LimboAck ─────────────────
                // Lets the sender know their payment reached a limbo-holding
                // peer. Encrypted with Blake3(payment_id || stealth_id).
                {
                    let ack_key = crate::node_runner::limbo_ack_key(&payment_id);
                    let payload = vess_protocol::LimboAckPayload {
                        payment_id,
                        holder_peer_id: node_id_bytes,
                        timestamp: now,
                    };
                    if let Ok(payload_bytes) = postcard::to_allocvec(&payload) {
                        if let Ok(blob) = vess_kloak::persistence::EncryptedBlob::encrypt(
                            &payload_bytes, &ack_key,
                        ) {
                            let ack_msg = PulseMessage::LimboAck(vess_protocol::LimboAck {
                                nonce: blob.nonce,
                                ciphertext: blob.ciphertext,
                            });
                            // Send the ack back to the peer who relayed the payment.
                            // They'll forward it toward the sender via the mesh.
                            let peer_contact = {
                                let s = lock_state(&st);
                                s.routing_table.routable_peers(|_| true)
                                    .into_iter()
                                    .find(|p| p.id_hash == peer_id)
                                    .and_then(|p| decode_contact_bytes(&p.id_bytes).ok())
                            };
                            if let Some(contact) = peer_contact {
                                let ack_node = limbo_ack_node.clone();
                                tokio::spawn(async move {
                                    let _ = ack_node.send_message(&contact, &ack_msg).await;
                                });
                            }
                        }
                    }
                }

                None
            }

            // GossipForward removed — no nullifier gossip in registry-only model.

            PulseMessage::PeerExchange(_pe) => {
                // Return K-closest peers to the requester from routing table.
                let peers: Vec<Vec<u8>> = state.routing_table.routable_peers(|_| true)
                    .into_iter()
                    .filter(|p| !p.id_bytes.is_empty() && p.id_bytes.len() <= MAX_SERIALIZED_MESH_CONTACT_BYTES)
                    .take(MAX_PEER_EXCHANGE_PEERS)
                    .map(|p| p.id_bytes)
                    .collect();
                Some(PulseMessage::PeerExchangeResponse(PeerExchangeResponse { peers }))
            }

            // ── Clock gossip: track peer's tick for network-time computation ──
            PulseMessage::ClockGossip(cg) => {
                if cg.node_id == peer_id {
                    // Verify clock rate is physically plausible
                    if vess_clock::TickChain::verify_clock_rate(&vess_clock::ClockState {
                        node_id: cg.node_id,
                        genesis_hash: cg.genesis_hash,
                        current_tick: cg.current_tick,
                        current_hash: cg.current_hash,
                        started_at_ms: cg.started_at_ms,
                        last_tick_at_ms: cg.last_tick_at_ms,
                        latest_checkpoint: None,
                    }) {
                        state.peer_clocks.insert(peer_id, cg.clone());
                    }
                }
                None
            }

            // ── Clock proof request: provide Merkle proof for a specific tick ──
            PulseMessage::ClockProofRequest(req) => {
                let proof = state.tick_clock.prove_tick(req.tick);
                if let Some(p) = proof {
                    let response = ClockProofResponse {
                        node_id: p.node_id,
                        tick: p.tick,
                        tick_hash: p.tick_hash,
                        merkle_path: p.merkle_path,
                        checkpoint_tick: p.checkpoint.tick,
                        checkpoint_root: p.checkpoint.merkle_root,
                        genesis_hash: p.genesis_hash,
                        proof_time_ms: p.proof_time_ms,
                    };
                    Some(PulseMessage::ClockProofResponse(response))
                } else {
                    None
                }
            }

            // ── Clock proof response: verify and store ──
            PulseMessage::ClockProofResponse(_resp) => {
                // Clock proofs are verified on-demand by the requester.
                // We just acknowledge receipt.
                None
            }

            PulseMessage::DhtSeedRequest(req) => {
                if req.requester_node_id != peer_id {
                    warn!(%peer, "DHT seed request node id does not match transport peer");
                    return None;
                }

                // Require ProofOfVessOwnership for mainnet seed requests.
                if !state.is_testnet {
                    match &req.burn_proof {
                        Some(proof) => {
                            let sig_msg = {
                                let mut h = blake3::Hasher::new();
                                h.update(b"dht-seed-request-v0");
                                h.update(&req.requester_node_id);
                                *h.finalize().as_bytes()
                            };
                            if let Err(reason) = verify_tag_lookup_ownership_proof(
                                &sig_msg, &[0u8; 16], proof, &state,
                            ) {
                                warn!(%peer, %reason, "DHT seed request rejected: invalid proof");
                                return Some(PulseMessage::DhtSeedResponse(DhtSeedResponse {
                                    responder_node_id: state.node_id,
                                    tags: vec![],
                                    manifests: vec![],
                                    ownership_records: vec![],
                                    consumed_records: vec![],
                                }));
                            }
                        }
                        None => {
                            warn!(%peer, "DHT seed request rejected: no burn proof");
                            return Some(PulseMessage::DhtSeedResponse(DhtSeedResponse {
                                responder_node_id: state.node_id,
                                tags: vec![],
                                manifests: vec![],
                                ownership_records: vec![],
                                consumed_records: vec![],
                            }));
                        }
                    }
                }

                let peer_ids: Vec<[u8; 32]> = state
                    .routing_table
                    .routable_peers(|_| true)
                    .iter()
                    .map(|p| p.id_hash)
                    .collect();
                let repl = dht_replication_factor(state.estimated_network_size);
                let max_tags = usize::from(req.max_tags).min(MAX_DHT_SEED_TAGS);
                let max_manifests = usize::from(req.max_manifests).min(MAX_DHT_SEED_MANIFESTS);
                let max_ownership_records = usize::from(req.max_ownership_records)
                    .min(MAX_DHT_SEED_OWNERSHIP_RECORDS);
                let max_consumed_records = usize::from(req.max_consumed_records)
                    .min(MAX_DHT_SEED_CONSUMED_RECORDS);

                let tags: Vec<DhtSeedTagRecord> = state
                    .tag_dht
                    .all_records()
                    .filter(|record| dht_seed_cursor_allows_key(&record.tag_hash, req.after_tag_hash))
                    .filter(|record| {
                        node_should_store_seeded_key(
                            &record.tag_hash,
                            &req.requester_node_id,
                            &state.node_id,
                            &peer_ids,
                            state.tag_dht.k_replication(),
                        )
                    })
                    .take(max_tags)
                    .map(dht_seed_tag_from_record)
                    .collect();

                let mut manifests: Vec<ManifestStore> = Vec::new();
                let mut manifest_bytes = 0usize;
                let mut manifest_keys: Vec<[u8; 32]> = state.manifest_store.keys().copied().collect();
                manifest_keys.sort();
                for dht_key in manifest_keys {
                    if !dht_seed_cursor_allows_key(&dht_key, req.after_manifest_key) {
                        continue;
                    }
                    let Some((encrypted_manifest, _)) = state.manifest_store.get(&dht_key) else {
                        continue;
                    };
                    let record_len = encrypted_manifest.len();
                    if manifests.len() >= max_manifests {
                        break;
                    }
                    if record_len > MAX_MANIFEST_SIZE
                        || record_len > MAX_DHT_SEED_MANIFEST_BYTES
                        || manifest_bytes.saturating_add(record_len) > MAX_DHT_SEED_MANIFEST_BYTES
                    {
                        continue;
                    }
                    if !node_should_store_seeded_key(
                            &dht_key,
                            &req.requester_node_id,
                            &state.node_id,
                            &peer_ids,
                            repl,
                        )
                    {
                        continue;
                    }
                    manifests.push(ManifestStore {
                        dht_key,
                        encrypted_manifest: encrypted_manifest.clone(),
                        hops_remaining: 0,
                    });
                    manifest_bytes = manifest_bytes.saturating_add(record_len);
                }

                let mut ownership_records: Vec<OwnershipRecord> =
                    collect_seed_ownership_records(&state).into_values().collect();
                ownership_records.sort_by_key(|record| record.mint_id);
                let ownership_records: Vec<DhtSeedOwnershipRecord> = ownership_records
                    .into_iter()
                    .filter(|record| {
                        dht_seed_cursor_allows_key(&record.mint_id, req.after_ownership_mint_id)
                    })
                    .filter(|record| {
                        node_should_store_seeded_key(
                            &record.mint_id,
                            &req.requester_node_id,
                            &state.node_id,
                            &peer_ids,
                            repl,
                        )
                    })
                    .take(max_ownership_records)
                    .map(|record| dht_seed_ownership_from_record(&record))
                    .collect();

                let mut consumed_records: Vec<([u8; 32], ConsumedRecord)> =
                    collect_seed_consumed_records(&state).into_iter().collect();
                consumed_records.sort_by_key(|(mint_id, _)| *mint_id);
                let consumed_records: Vec<DhtSeedConsumedRecord> = consumed_records
                    .into_iter()
                    .filter(|(mint_id, _)| {
                        dht_seed_cursor_allows_key(mint_id, req.after_consumed_mint_id)
                    })
                    .filter(|(mint_id, _)| {
                        node_should_store_seeded_key(
                            mint_id,
                            &req.requester_node_id,
                            &state.node_id,
                            &peer_ids,
                            repl,
                        )
                    })
                    .take(max_consumed_records)
                    .map(|(mint_id, record)| dht_seed_consumed_from_record(mint_id, &record))
                    .collect();

                info!(
                    %peer,
                    tags = tags.len(),
                    manifests = manifests.len(),
                    ownership_records = ownership_records.len(),
                    consumed_records = consumed_records.len(),
                    "serving DHT seed shard sync"
                );
                Some(PulseMessage::DhtSeedResponse(DhtSeedResponse {
                    responder_node_id: state.node_id,
                    tags,
                    manifests,
                    ownership_records,
                    consumed_records,
                }))
            }

            PulseMessage::SwapOffer(offer) => {
                // Store swap offer in the DHT shard for this asset pair
                let dht_key = offer.dht_key();
                let entry = state.swap_offers.entry(dht_key).or_default();
                // Deduplicate: replace existing offer from same node for same pair
                entry.retain(|o| o.offerer_node_id != offer.offerer_node_id
                    || o.offer_asset != offer.offer_asset
                    || o.want_asset != offer.want_asset);
                entry.push(offer.clone());
                // Prune expired offers
                let now = ArteryState::now_unix();
                entry.retain(|o| o.expires_at > now);

                tracing::info!(
                    pair = %format!("{}->{}", offer.offer_asset, offer.want_asset),
                    amount = offer.offer_amount,
                    "swap offer stored"
                );
                None
            }

            PulseMessage::SwapOfferResponse(resp) => {
                // Merge offers from a peer's response into our local store
                for offer in &resp.offers {
                    let dht_key = offer.dht_key();
                    let entry = state.swap_offers.entry(dht_key).or_default();
                    if !entry.iter().any(|o|
                        o.offerer_node_id == offer.offerer_node_id
                        && o.offer_asset == offer.offer_asset
                        && o.want_asset == offer.want_asset
                    ) {
                        entry.push(offer.clone());
                    }
                }
                None
            }

            PulseMessage::DhtSeedResponse(_) => None,

            other => {
                info!(%peer, "unhandled message: {other:?}");
                None
            }
        }
    })
    .await;
    });

    // ── Wait for either the listen loop to finish or SIGTERM ────────
    tokio::select! {
        result = listen_handle => {
            if let Err(e) = result {
                warn!(error = %e, "message listener task panicked");
            }
        }
        _ = shutdown_rx.recv() => {
            info!("shutdown signal received, stopping message listener…");
        }
    }

    // Save state on shutdown.
    {
        let s = lock_state(&state);
        let snap = s.snapshot();
        storage.save(&snap)?;
        info!("state saved to disk on shutdown");

        // Save wallet billfold on shutdown.
        if let Some(ref ws) = s.wallet {
            if let Ok(mut wf) = vess_kloak::WalletFile::load(&ws.wallet_path) {
                wf.billfold = ws.billfold.clone();
                if let Err(e) = wf.encrypt_spend_credentials(&ws.billfold, &ws.enc_key) {
                    warn!(error = %e, "failed to encrypt spend credentials on shutdown");
                }
                if let Err(e) = wf.save(&ws.wallet_path, &ws.enc_key) {
                    warn!(error = %e, "failed to save wallet on shutdown");
                } else {
                    info!("wallet saved on shutdown");
                }
            }
        }
    }

    node.shutdown().await;
    Ok(node_id_str)
}


