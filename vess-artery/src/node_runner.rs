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
use bitcoin::hashes::Hash;
use rand::Rng;
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

use vess_compute::{ComputeDht, ProgramId, PROGRAM_PRUNE_SECS};
use vess_mesh::MeshCarrierContact;
use vess_protocol::{
    BitcoinNetwork, ComputeReceiptFetch, ComputeReceiptFetchResponse, ComputeReceiptStore,
    DhtSeedComputeReceiptRecord, DhtSeedConsumedRecord, DhtSeedOwnershipRecord,
    DhtSeedProgramManifestRecord, DhtSeedProgramRecord, DhtSeedRequest, DhtSeedResponse,
    DhtSeedTagRecord, FetchedRecord, FindNodeResponse, GenesisProof, HandshakeChallenge,
    HandshakeResponse, MailboxCollectResponse, MailboxForwardAck, MailboxSweepResponse,
    ManifestRecoverResponse, ManifestStore, OwnershipClaim, OwnershipFetchResponse,
    OwnershipGenesis, PeerExchange, PeerExchangeResponse, ProgramFetch, ProgramFetchResponse,
    ProgramManifestResolve, ProgramManifestResolveResponse, ProgramManifestStore,
    ProgramReceiptList, ProgramReceiptListResponse, ProgramStore, PulseMessage,
    ReforgeAttestation, RegistryQueryResponse, TagConfirm, TagLookupResponse, TagLookupResult,
    TagStore,
};
use vess_vascular::MeshPulseNode;

use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::{receive_and_claim, ClaimedBill};
use vess_stealth::StealthSecretKey;

const MAX_WALLET_NOTIFICATIONS: usize = 256;
const AUTO_BURN_FEE_SATS: u64 = 500;
const AUTO_BURN_RETRY_SECS: u64 = 30;
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
pub(crate) struct ForwardRecord {
    /// Serialized mesh contact of the subscribing node.
    pub(crate) target_id_bytes: Vec<u8>,
    /// Unix timestamp when the subscription expires.
    pub(crate) expires_at: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct OutboundPaymentRecord {
    pub(crate) payment_id: [u8; 32],
    pub(crate) amount: u64,
    pub(crate) recipient: String,
    pub(crate) pending_mint_ids: HashSet<[u8; 32]>,
}

/// Structured node event for CLI display via `vess events`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event")]
pub(crate) enum NodeEvent {
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

fn bitcoin_network_tag(network: BitcoinNetwork) -> &'static [u8] {
    match network {
        BitcoinNetwork::Mainnet => b"bitcoin-mainnet",
        BitcoinNetwork::Testnet => b"bitcoin-testnet",
        BitcoinNetwork::Signet => b"bitcoin-signet",
        BitcoinNetwork::Regtest => b"bitcoin-regtest",
    }
}

fn bitcoin_burn_bundle_commitment(burn: &vess_protocol::BitcoinBurnBundleProof) -> [u8; 32] {
    let payload_hash = blake3::hash(&burn.burn_commitment_payload);
    let mut h = blake3::Hasher::new();
    h.update(b"vess-bitcoin-burn-bundle-v0");
    h.update(bitcoin_network_tag(burn.network));
    h.update(&burn.txid);
    h.update(&burn.block_hash);
    h.update(&burn.merkle_root);
    h.update(&burn.merkle_index.to_le_bytes());
    h.update(&burn.burn_amount_sats.to_le_bytes());
    h.update(&burn.first_owner_vk_hash);
    for node in &burn.merkle_proof {
        h.update(node);
    }
    for value in &burn.output_values {
        h.update(&value.to_le_bytes());
    }
    h.update(payload_hash.as_bytes());
    *h.finalize().as_bytes()
}

fn expected_bitcoin_burn_payload(burn: &vess_protocol::BitcoinBurnBundleProof) -> [u8; 32] {
    vess_foundry::bitcoin_burn_payload_commitment(
        &burn.first_owner_vk_hash,
        burn.burn_amount_sats,
        &burn.output_values,
    )
}

fn min_bitcoin_burn_confirmations(network: BitcoinNetwork) -> u32 {
    match network {
        BitcoinNetwork::Mainnet | BitcoinNetwork::Testnet | BitcoinNetwork::Signet => 6,
        BitcoinNetwork::Regtest => 1,
    }
}

fn min_bitcoin_burn_corroborating_peers(network: BitcoinNetwork) -> u32 {
    match network {
        BitcoinNetwork::Mainnet | BitcoinNetwork::Testnet | BitcoinNetwork::Signet => 2,
        BitcoinNetwork::Regtest => 1,
    }
}

fn bitcoin_burn_merkle_root(burn: &vess_protocol::BitcoinBurnBundleProof) -> [u8; 32] {
    let mut current = burn.txid;
    let mut index = burn.merkle_index;
    for sibling in &burn.merkle_proof {
        let mut data = Vec::with_capacity(64);
        if index % 2 == 0 {
            data.extend_from_slice(&current);
            data.extend_from_slice(sibling);
        } else {
            data.extend_from_slice(sibling);
            data.extend_from_slice(&current);
        }
        current = *bitcoin::hashes::sha256d::Hash::hash(&data).as_byte_array();
        index /= 2;
    }
    current
}

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

fn protocol_bitcoin_network(network: vess_bitcoin::BitcoinNetwork) -> BitcoinNetwork {
    match network {
        vess_bitcoin::BitcoinNetwork::Mainnet => BitcoinNetwork::Mainnet,
        vess_bitcoin::BitcoinNetwork::Testnet => BitcoinNetwork::Testnet,
        vess_bitcoin::BitcoinNetwork::Signet => BitcoinNetwork::Signet,
        vess_bitcoin::BitcoinNetwork::Regtest => BitcoinNetwork::Regtest,
    }
}

fn confirmed_burn_outputs(
    pending: &vess_bitcoin::PendingBurn,
    confirmation: &vess_bitcoin::BurnConfirmationProof,
    network: vess_bitcoin::BitcoinNetwork,
    hops_remaining: u8,
) -> Result<(Vec<OwnershipGenesis>, Vec<vess_foundry::VessBill>)> {
    let output_values = vess_foundry::bitcoin_burn_output_values(pending.burn_amount_sats);
    let burn = vess_protocol::BitcoinBurnBundleProof {
        network: protocol_bitcoin_network(network),
        txid: *pending.txid.as_byte_array(),
        block_hash: *confirmation.block_hash.as_byte_array(),
        block_height: confirmation.block_height,
        confirmations: confirmation.confirmations,
        required_confirmations: confirmation.required_confirmations,
        corroborating_peer_count: confirmation.corroborating_peer_count,
        chain_work: confirmation.chain_work,
        merkle_root: *confirmation.merkle_root.as_byte_array(),
        merkle_proof: confirmation.merkle_proof.clone(),
        merkle_index: confirmation.merkle_index,
        burn_amount_sats: pending.burn_amount_sats,
        first_owner_vk: pending.first_owner_vk.clone(),
        first_owner_vk_hash: pending.first_owner_vk_hash,
        output_values: output_values.clone(),
        burn_commitment_payload: vess_foundry::bitcoin_burn_payload_commitment(
            &pending.first_owner_vk_hash,
            pending.burn_amount_sats,
            &output_values,
        )
        .to_vec(),
    };
    let digest = bitcoin_burn_bundle_commitment(&burn);
    let created_at = confirmation.header_time as u64;

    let mut genesis_records = Vec::with_capacity(output_values.len());
    let mut bills = Vec::with_capacity(output_values.len());
    for (output_index, denomination_value) in output_values.iter().copied().enumerate() {
        let mint_id = vess_foundry::bitcoin_burn_mint_id(&burn.txid, output_index as u32);
        let chain_tip = vess_foundry::genesis_chain_tip(&mint_id, &pending.first_owner_vk_hash);
        let denomination =
            vess_foundry::Denomination::from_value(denomination_value).ok_or_else(|| {
                anyhow::anyhow!("invalid Vess denomination value {denomination_value}")
            })?;

        genesis_records.push(OwnershipGenesis {
            mint_id,
            chain_tip,
            owner_vk_hash: pending.first_owner_vk_hash,
            owner_vk: pending.first_owner_vk.clone(),
            program_owner: None,
            denomination_value,
            genesis_proof: GenesisProof::BitcoinBurn(burn.clone()),
            digest,
            hops_remaining,
            chain_depth: 0,
            output_index: output_index as u32,
        });

        bills.push(vess_foundry::VessBill {
            denomination,
            digest,
            created_at,
            stealth_id: [0u8; 32],
            dht_index: 0,
            mint_id,
            chain_tip,
            chain_depth: 0,
        });
    }

    Ok((genesis_records, bills))
}

fn validate_bitcoin_burn_genesis(
    og: &OwnershipGenesis,
    burn: &vess_protocol::BitcoinBurnBundleProof,
) -> std::result::Result<[u8; 32], &'static str> {
    const MAX_BURN_OUTPUTS: usize = 64;
    const BURN_PAYLOAD_BYTES: usize = 32;
    const MAX_BURN_MERKLE_DEPTH: usize = 64;
    const MAX_OWNER_VK_BYTES: usize = 4096;

    if burn.burn_amount_sats == 0 {
        return Err("zero-value bitcoin burn");
    }

    let minimum_confirmations = min_bitcoin_burn_confirmations(burn.network);
    if burn.required_confirmations < minimum_confirmations
        || burn.confirmations < burn.required_confirmations
    {
        return Err("bitcoin burn confirmation depth insufficient");
    }

    if burn.corroborating_peer_count < min_bitcoin_burn_corroborating_peers(burn.network) {
        return Err("bitcoin burn corroboration insufficient");
    }

    if burn.chain_work == [0u8; 32] {
        return Err("bitcoin burn proof missing chainwork");
    }

    if burn.output_values.is_empty() || burn.output_values.len() > MAX_BURN_OUTPUTS {
        return Err("invalid bitcoin burn output count");
    }

    if burn.burn_commitment_payload.len() != BURN_PAYLOAD_BYTES
        || burn.merkle_proof.len() > MAX_BURN_MERKLE_DEPTH
        || burn.first_owner_vk.len() > MAX_OWNER_VK_BYTES
    {
        return Err("bitcoin burn proof exceeds size limits");
    }

    if bitcoin_burn_merkle_root(burn) != burn.merkle_root {
        return Err("bitcoin burn merkle proof mismatch");
    }

    if burn.first_owner_vk != og.owner_vk {
        return Err("bitcoin burn first owner key mismatch");
    }

    let expected_payload = expected_bitcoin_burn_payload(burn);
    if burn.burn_commitment_payload.as_slice() != expected_payload {
        return Err("bitcoin burn OP_RETURN payload mismatch");
    }

    if burn.first_owner_vk_hash != og.owner_vk_hash {
        return Err("bitcoin burn owner_vk_hash mismatch");
    }

    let canonical_output_values = vess_foundry::bitcoin_burn_output_values(burn.burn_amount_sats);
    if burn.output_values != canonical_output_values {
        return Err("bitcoin burn output decomposition is not canonical");
    }

    let output_index = og.output_index as usize;
    if output_index >= burn.output_values.len() {
        return Err("bitcoin burn output_index out of bounds");
    }

    if burn.output_values[output_index] != og.denomination_value {
        return Err("bitcoin burn denomination mismatch");
    }

    let bundle_commitment = bitcoin_burn_bundle_commitment(burn);
    if bundle_commitment != og.digest {
        return Err("bitcoin burn commitment mismatch");
    }

    let expected_mint_id = vess_foundry::bitcoin_burn_mint_id(&burn.txid, og.output_index);
    if expected_mint_id != og.mint_id {
        return Err("bitcoin burn mint_id derivation mismatch");
    }

    Ok(bundle_commitment)
}

pub(crate) fn load_bitcoin_wallet_state(
    wallet: &vess_kloak::WalletFile,
    raw_seed: &[u8; 64],
    enc_key: &[u8; 32],
) -> Result<(vess_bitcoin::BitcoinWallet, String)> {
    let persisted_state = Zeroizing::new(wallet.decrypt_bitcoin_wallet_state(enc_key)?);
        let mut bitcoin_wallet = vess_bitcoin::BitcoinWallet::from_vess_seed_with_state(
            vess_bitcoin::BitcoinNetwork::Mainnet,
            raw_seed,
            persisted_state.as_deref(),
        )?;
    let bitcoin_receive_address = bitcoin_wallet.ensure_receive_address()?.address.to_string();
    Ok((bitcoin_wallet, bitcoin_receive_address))
}

fn queue_auto_burn_if_needed(state: &mut ArteryState) -> Vec<vess_bitcoin::PendingBurn> {
    let now = ArteryState::now_unix();
    let pending = match state.wallet.as_mut() {
        Some(ws) => match ws
            .bitcoin_wallet
            .queue_auto_burn_if_needed(AUTO_BURN_FEE_SATS, now)
        {
            Ok(pending) => pending,
            Err(e) => {
                warn!(error = %e, "failed to queue automatic bitcoin burn");
                None
            }
        },
        None => None,
    };

    if let Some(ref pending_burn) = pending {
        state.push_notification(WalletNotification {
            kind: "bitcoin_burn_queued".to_string(),
            created_at: now,
            payment_id: pending_burn.txid.to_string(),
            amount: Some(pending_burn.burn_amount_sats),
            bill_count: Some(pending_burn.transaction.output.len()),
            counterparty: None,
            message: format!(
                "Queued automatic Bitcoin burn {} for {} sats.",
                pending_burn.txid, pending_burn.burn_amount_sats
            ),
        });
    }

    pending.into_iter().collect()
}

async fn broadcast_pending_burns(
    state: Arc<Mutex<ArteryState>>,
    client: vess_bitcoin::BitcoinLightClient,
    pending_burns: Vec<vess_bitcoin::PendingBurn>,
) {
    for pending in pending_burns {
        let first_attempt = pending.last_broadcast_at.is_none();
        match client
            .broadcast_transaction(pending.transaction.clone())
            .await
        {
            Ok(txid) => {
                let now = ArteryState::now_unix();
                let mut s = state.lock().unwrap();
                if let Some(ws) = s.wallet.as_mut() {
                    ws.bitcoin_wallet
                        .mark_pending_burn_broadcast_success(&pending.txid, now);
                }
                if first_attempt {
                    s.push_notification(WalletNotification {
                        kind: "bitcoin_burn_broadcast".to_string(),
                        created_at: now,
                        payment_id: txid.to_string(),
                        amount: Some(pending.burn_amount_sats),
                        bill_count: Some(pending.transaction.output.len()),
                        counterparty: None,
                        message: format!(
                            "Broadcast automatic Bitcoin burn {} for {} sats.",
                            txid, pending.burn_amount_sats
                        ),
                    });
                }
                s.flush_wallet();
            }
            Err(e) => {
                warn!(txid = %pending.txid, error = %e, "failed to broadcast automatic bitcoin burn");
                let now = ArteryState::now_unix();
                let mut s = state.lock().unwrap();
                if let Some(ws) = s.wallet.as_mut() {
                    ws.bitcoin_wallet.mark_pending_burn_broadcast_failure(
                        &pending.txid,
                        now,
                        e.to_string(),
                    );
                }
                if first_attempt {
                    s.push_notification(WalletNotification {
                        kind: "bitcoin_burn_broadcast_failed".to_string(),
                        created_at: now,
                        payment_id: pending.txid.to_string(),
                        amount: Some(pending.burn_amount_sats),
                        bill_count: Some(pending.transaction.output.len()),
                        counterparty: None,
                        message: format!(
                            "Initial automatic Bitcoin burn broadcast failed for {}.",
                            pending.txid
                        ),
                    });
                }
                s.flush_wallet();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    fn sample_burn_bundle() -> (vess_protocol::BitcoinBurnBundleProof, OwnershipGenesis) {
        let txid = [0x11; 32];
        let owner_vk = vec![0x42; 64];
        let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&owner_vk);
        let burn_amount_sats = 17;
        let output_values = vess_foundry::bitcoin_burn_output_values(burn_amount_sats);
        let burn = vess_protocol::BitcoinBurnBundleProof {
            network: BitcoinNetwork::Regtest,
            txid,
            block_hash: [0x22; 32],
            block_height: 12,
            confirmations: 1,
            required_confirmations: 1,
            corroborating_peer_count: 1,
            chain_work: [0x33; 32],
            merkle_root: txid,
            merkle_proof: Vec::new(),
            merkle_index: 0,
            burn_amount_sats,
            first_owner_vk: owner_vk.clone(),
            first_owner_vk_hash: owner_vk_hash,
            output_values: output_values.clone(),
            burn_commitment_payload: vess_foundry::bitcoin_burn_payload_commitment(
                &owner_vk_hash,
                burn_amount_sats,
                &output_values,
            )
            .to_vec(),
        };
        let digest = bitcoin_burn_bundle_commitment(&burn);
        let mint_id = vess_foundry::bitcoin_burn_mint_id(&txid, 0);
        let og = OwnershipGenesis {
            mint_id,
            chain_tip: vess_foundry::genesis_chain_tip(&mint_id, &owner_vk_hash),
            owner_vk_hash,
            owner_vk,
            program_owner: None,
            denomination_value: output_values[0],
            genesis_proof: GenesisProof::BitcoinBurn(burn.clone()),
            digest,
            hops_remaining: 0,
            chain_depth: 0,
            output_index: 0,
        };
        (burn, og)
    }

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
            current_owner_program: None,
            denomination_value: 10,
            updated_at,
            proof_hash: [0x66; 32],
            digest: [0x77; 32],
            nonce: [0x88; 32],
            prev_claim_vk_hash: Some([0x99; 32]),
            claim_hash,
            chain_depth,
            encrypted_bill: Vec::new(),
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
            compute_dht: ComputeDht::new(),
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
            manifest_store: HashMap::new(),
            retained_ownership_records: HashMap::new(),
            retained_consumed_records: HashMap::new(),
            limbo_entry_times: HashMap::new(),
            payment_latency: PaymentLatencyTracker::new(1000),
            pending_reforge_genesis: HashMap::new(),
            wallet: None,
            bitcoin_client: None,
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
            events: VecDeque::new(),
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
            prev_owner_program: None,
            transfer_sig,
            new_owner_vk_hash,
            new_owner_vk,
            new_owner_program: None,
            new_chain_tip: vess_foundry::advance_chain_tip_with_hash(
                &base_chain_tip,
                &new_owner_vk_hash,
                &witness_hash,
            ),
            timestamp,
            hops_remaining: 0,
            chain_depth,
            encrypted_bill: Vec::new(),
            program_spend_witness: None,
        }
    }

    #[test]
    fn bitcoin_burn_bundle_accepts_canonical_genesis_binding() {
        let (burn, og) = sample_burn_bundle();
        let bundle_commitment = validate_bitcoin_burn_genesis(&og, &burn).unwrap();
        assert_eq!(bundle_commitment, og.digest);
    }

    #[test]
    fn bitcoin_burn_bundle_rejects_reorg_like_confirmation_regression() {
        let (mut burn, og) = sample_burn_bundle();
        burn.network = BitcoinNetwork::Testnet;
        burn.required_confirmations = 6;
        burn.confirmations = 5;

        let error = validate_bitcoin_burn_genesis(&og, &burn).unwrap_err();
        assert_eq!(error, "bitcoin burn confirmation depth insufficient");
    }

    #[test]
    fn bitcoin_burn_bundle_rejects_payload_mismatch() {
        let (mut burn, og) = sample_burn_bundle();
        burn.burn_commitment_payload[0] ^= 0xff;

        let error = validate_bitcoin_burn_genesis(&og, &burn).unwrap_err();
        assert_eq!(error, "bitcoin burn OP_RETURN payload mismatch");
    }

    #[test]
    fn bitcoin_burn_bundle_rejects_insufficient_corroboration() {
        let (mut burn, og) = sample_burn_bundle();
        burn.network = BitcoinNetwork::Mainnet;
        burn.required_confirmations = 6;
        burn.confirmations = 6;
        burn.corroborating_peer_count = 1;

        let error = validate_bitcoin_burn_genesis(&og, &burn).unwrap_err();
        assert_eq!(error, "bitcoin burn corroboration insufficient");
    }

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

    #[test]
    fn seed_sync_rejects_single_peer_overwrite_without_quorum() {
        let state = sample_seed_state();
        let ownership_mint = [0xC1; 32];
        let consumed_mint = [0xC2; 32];

        let mut snapshot = SeedSyncPeerSnapshot::default();
        snapshot.ownership_records.insert(
            ownership_mint,
            sample_partition_record(ownership_mint, 2, Some([0x01; 32]), [0x11; 32], 100),
        );
        snapshot
            .consumed_records
            .insert(consumed_mint, sample_consumed_record(0x21, 200));

        apply_quorum_seed_snapshots(&state, vec![snapshot]);

        let locked = state.lock().unwrap();
        assert!(locked.registry.get(&ownership_mint).is_none());
        assert!(locked.registry.was_consumed(&consumed_mint).is_none());
    }

    #[test]
    fn seed_sync_rejects_split_vote_snapshots_without_majority() {
        let state = sample_seed_state();
        let ownership_mint = [0xD1; 32];
        let consumed_mint = [0xD2; 32];

        let mut left = SeedSyncPeerSnapshot::default();
        left.ownership_records.insert(
            ownership_mint,
            sample_partition_record(ownership_mint, 2, Some([0x10; 32]), [0x12; 32], 100),
        );
        left.consumed_records
            .insert(consumed_mint, sample_consumed_record(0x31, 300));

        let mut right = SeedSyncPeerSnapshot::default();
        right.ownership_records.insert(
            ownership_mint,
            sample_partition_record(ownership_mint, 2, Some([0x20; 32]), [0x13; 32], 101),
        );
        right
            .consumed_records
            .insert(consumed_mint, sample_consumed_record(0x41, 301));

        apply_quorum_seed_snapshots(&state, vec![left, right]);

        let locked = state.lock().unwrap();
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

        let mut first = SeedSyncPeerSnapshot::default();
        first
            .ownership_records
            .insert(ownership_mint, winning_record.clone());
        first
            .consumed_records
            .insert(consumed_mint, winning_consumed.clone());

        let mut second = SeedSyncPeerSnapshot::default();
        second
            .ownership_records
            .insert(ownership_mint, winning_record.clone());
        second
            .consumed_records
            .insert(consumed_mint, winning_consumed.clone());

        let mut third = SeedSyncPeerSnapshot::default();
        third
            .ownership_records
            .insert(ownership_mint, losing_record);
        third
            .consumed_records
            .insert(consumed_mint, losing_consumed);

        apply_quorum_seed_snapshots(&state, vec![first, second, third]);

        let locked = state.lock().unwrap();
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
        let locked = state.lock().unwrap();
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
        let locked = state.lock().unwrap();
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
            prev_owner_program: None,
            transfer_sig: Vec::new(),
            new_owner_vk_hash,
            new_owner_vk: Vec::new(),
            new_owner_program: None,
            new_chain_tip: valid_tip,
            timestamp: 1_700_000_000,
            hops_remaining: 0,
            chain_depth: 2,
            encrypted_bill: Vec::new(),
            program_spend_witness: None,
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
            let mut locked = state.lock().unwrap();
            locked.retained_ownership_records.insert(
                mint_id,
                OwnershipRecord {
                    mint_id,
                    chain_tip: genesis_chain_tip,
                    prev_transfer_chain_tip: None,
                    current_owner_vk_hash: vess_foundry::spend_auth::vk_hash(&genesis_owner_vk),
                    current_owner_vk: genesis_owner_vk.clone(),
                    current_owner_program: None,
                    denomination_value: 10,
                    updated_at,
                    proof_hash: [0x55; 32],
                    digest: [0x66; 32],
                    nonce: [0x77; 32],
                    prev_claim_vk_hash: None,
                    claim_hash: None,
                    chain_depth: 0,
                    encrypted_bill: Vec::new(),
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
            let mut locked = state.lock().unwrap();
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
                prev_owner_program: None,
                transfer_sig: Vec::new(),
                new_owner_vk_hash,
                new_owner_vk: Vec::new(),
                new_owner_program: None,
                new_chain_tip: vess_foundry::advance_chain_tip_with_hash(
                    &base_chain_tip,
                    &new_owner_vk_hash,
                    &witness_hash,
                ),
                timestamp,
                hops_remaining: 0,
                chain_depth: 2,
                encrypted_bill: Vec::new(),
                program_spend_witness: None,
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
const MAX_PEER_EXCHANGE_PEERS: usize = 4;

/// Maximum records returned by one seed-time DHT shard sync response.
const MAX_DHT_SEED_TAGS: usize = 256;
const MAX_DHT_SEED_MANIFESTS: usize = 64;
const MAX_DHT_SEED_OWNERSHIP_RECORDS: usize = 256;
const MAX_DHT_SEED_CONSUMED_RECORDS: usize = 256;
const MAX_DHT_SEED_PROGRAMS: usize = 128;
const MAX_DHT_SEED_PROGRAM_MANIFESTS: usize = 128;
const MAX_DHT_SEED_COMPUTE_RECEIPTS: usize = 256;
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
pub(crate) struct DuplicateTracker {
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
        PulseMessage::ProgramStore(ps) => {
            h.update(b"ProgramStore");
            h.update(ps.program.prog_id().as_bytes());
        }
        PulseMessage::ProgramManifestStore(pms) => {
            h.update(b"ProgramManifestStore");
            h.update(&pms.manifest.dht_key());
        }
        PulseMessage::ComputeReceiptStore(crs) => {
            h.update(b"ComputeReceiptStore");
            h.update(&crs.receipt.receipt_id);
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

fn mirror_compute_receipt_text(state_dir: &Path, receipt: &vess_protocol::ComputeReceipt) {
    let receipts_dir = state_dir.join("receipts");
    if let Err(error) = std::fs::create_dir_all(&receipts_dir) {
        warn!(error = %error, path = %receipts_dir.display(), "failed to create receipts directory");
        return;
    }

    let receipt_path = receipts_dir.join(format!("{}.txt", hex_key(&receipt.receipt_id)));
    let parent_receipts = if receipt.parent_receipt_ids.is_empty() {
        "none".to_string()
    } else {
        receipt
            .parent_receipt_ids
            .iter()
            .map(hex_key)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let json = match serde_json::to_string_pretty(receipt) {
        Ok(json) => json,
        Err(error) => {
            warn!(error = %error, receipt_id = %hex_key(&receipt.receipt_id), "failed to serialize compute receipt text mirror");
            return;
        }
    };
    let contents = format!(
        "Receipt ID: {}\nProgram ID: {}\nJob ID: {}\nCreated At: {}\nParent Receipts:\n{}\n\nJSON:\n{}\n",
        hex_key(&receipt.receipt_id),
        hex_key(receipt.prog_id.as_bytes()),
        hex_key(&receipt.job_id),
        receipt.created_at,
        parent_receipts,
        json,
    );

    if let Err(error) = std::fs::write(&receipt_path, contents) {
        warn!(error = %error, path = %receipt_path.display(), "failed to write compute receipt text file");
    }
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
    let mut s = state.lock().unwrap();
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
        current_owner_program: record.current_owner_program.clone(),
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
    }
}

fn ownership_record_from_dht_seed(record: DhtSeedOwnershipRecord) -> OwnershipRecord {
    OwnershipRecord {
        mint_id: record.mint_id,
        chain_tip: record.chain_tip,
        current_owner_vk_hash: record.current_owner_vk_hash,
        current_owner_vk: record.current_owner_vk,
        current_owner_program: record.current_owner_program,
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
    }
}

#[derive(Debug, Default)]
struct SeedSyncPeerSnapshot {
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

    if let Some(program_owner) = &record.current_owner_program {
        if record.current_owner_vk_hash != program_owner.owner_commitment() {
            return None;
        }
    } else {
        if record.current_owner_vk.is_empty() {
            return None;
        }
        if vess_foundry::spend_auth::vk_hash(&record.current_owner_vk) != record.current_owner_vk_hash {
            return None;
        }
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
    let mut s = state.lock().unwrap();

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
}

fn dht_seed_program_from_record(
    prog_id: vess_protocol::ProgramId,
    program: vess_protocol::StoredProgram,
) -> DhtSeedProgramRecord {
    DhtSeedProgramRecord { prog_id, program }
}

fn dht_seed_program_manifest_from_record(
    dht_key: [u8; 32],
    manifest: vess_protocol::ProgramManifest,
) -> DhtSeedProgramManifestRecord {
    DhtSeedProgramManifestRecord { dht_key, manifest }
}

fn dht_seed_compute_receipt_from_record(
    receipt_id: [u8; 32],
    receipt: vess_protocol::ComputeReceipt,
) -> DhtSeedComputeReceiptRecord {
    DhtSeedComputeReceiptRecord { receipt_id, receipt }
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
    og.program_owner
        .as_ref()
        .map(|condition| condition.owner_commitment())
        .unwrap_or_else(|| vess_foundry::spend_auth::vk_hash(&og.owner_vk))
}

fn ownership_claim_prev_owner_commitment(oc: &OwnershipClaim) -> Option<[u8; 32]> {
    if let Some(condition) = &oc.prev_owner_program {
        Some(condition.owner_commitment())
    } else if !oc.prev_owner_vk.is_empty() {
        Some(vess_foundry::spend_auth::vk_hash(&oc.prev_owner_vk))
    } else {
        None
    }
}

fn ownership_claim_new_owner_commitment(oc: &OwnershipClaim) -> Option<[u8; 32]> {
    if let Some(condition) = &oc.new_owner_program {
        Some(condition.owner_commitment())
    } else if !oc.new_owner_vk.is_empty() {
        Some(vess_foundry::spend_auth::vk_hash(&oc.new_owner_vk))
    } else if oc.new_owner_vk_hash != [0u8; 32] {
        Some(oc.new_owner_vk_hash)
    } else {
        None
    }
}

fn ownership_claim_witness_hash(oc: &OwnershipClaim) -> Option<[u8; 32]> {
    if let Some(witness) = &oc.program_spend_witness {
        Some(witness.witness_hash())
    } else if !oc.transfer_sig.is_empty() {
        Some(*blake3::hash(&oc.transfer_sig).as_bytes())
    } else {
        None
    }
}

fn program_ids_with_live_owned_bills(state: &ArteryState) -> BTreeSet<ProgramId> {
    state
        .registry
        .all_records()
        .into_iter()
        .filter_map(|record| record.current_owner_program.map(|owner| owner.controller.prog_id))
        .collect()
}

fn note_program_bill_activity(state: &mut ArteryState, prog_id: ProgramId, sent_at: u64) {
    let _ = state.compute_dht.mark_bill_sent_to_program(prog_id, sent_at);
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
        GenesisProof::BitcoinBurn(_) => Some((og.digest, og.digest)),
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
            current_owner_program: og.program_owner.clone(),
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
        },
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
        current_owner_program: claim.new_owner_program.clone(),
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
    let record = state
        .retained_ownership_records
        .remove(&oc.mint_id)
        .or(fallback);
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
    record.current_owner_program = oc.new_owner_program.clone();
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
    oc: OwnershipClaim,
) {
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
    after_program_id: Option<[u8; 32]>,
    after_program_manifest_key: Option<[u8; 32]>,
    after_compute_receipt_id: Option<[u8; 32]>,
}

impl DhtSeedCursor {
    fn into_request(self, requester_node_id: [u8; 32]) -> DhtSeedRequest {
        DhtSeedRequest {
            requester_node_id,
            after_tag_hash: self.after_tag_hash,
            after_manifest_key: self.after_manifest_key,
            after_ownership_mint_id: self.after_ownership_mint_id,
            after_consumed_mint_id: self.after_consumed_mint_id,
            after_program_id: self.after_program_id,
            after_program_manifest_key: self.after_program_manifest_key,
            after_compute_receipt_id: self.after_compute_receipt_id,
            max_tags: MAX_DHT_SEED_TAGS as u16,
            max_manifests: MAX_DHT_SEED_MANIFESTS as u16,
            max_ownership_records: MAX_DHT_SEED_OWNERSHIP_RECORDS as u16,
            max_consumed_records: MAX_DHT_SEED_CONSUMED_RECORDS as u16,
            max_programs: MAX_DHT_SEED_PROGRAMS as u16,
            max_program_manifests: MAX_DHT_SEED_PROGRAM_MANIFESTS as u16,
            max_compute_receipts: MAX_DHT_SEED_COMPUTE_RECEIPTS as u16,
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
        if let Some(last) = response.programs.last() {
            self.after_program_id = Some(*last.prog_id.as_bytes());
        }
        if let Some(last) = response.program_manifests.last() {
            self.after_program_manifest_key = Some(last.dht_key);
        }
        if let Some(last) = response.compute_receipts.last() {
            self.after_compute_receipt_id = Some(last.receipt_id);
        }
    }
}

fn dht_seed_response_is_empty(response: &DhtSeedResponse) -> bool {
    response.tags.is_empty()
        && response.manifests.is_empty()
        && response.ownership_records.is_empty()
        && response.consumed_records.is_empty()
        && response.programs.is_empty()
        && response.program_manifests.is_empty()
        && response.compute_receipts.is_empty()
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
    let mut snapshot = SeedSyncPeerSnapshot::default();

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

    let mut s = state.lock().unwrap();
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
        let s = state.lock().unwrap();
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
    let mut inserted_programs = 0usize;
    let mut inserted_program_manifests = 0usize;
    let mut inserted_compute_receipts = 0usize;
    let mut mirrored_receipts = Vec::new();
    let mut snapshot = SeedSyncPeerSnapshot::default();
    let mut s = state.lock().unwrap();
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

    for manifest in response.manifests.into_iter().take(MAX_DHT_SEED_MANIFESTS) {
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
            .insert(manifest.dht_key, (manifest.encrypted_manifest, now));
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

    for seeded_program in response.programs.into_iter().take(MAX_DHT_SEED_PROGRAMS) {
        if !s
            .registry
            .should_store(seeded_program.prog_id.as_bytes(), &peer_ids, repl)
        {
            continue;
        }
        if s.compute_dht.store_program(seeded_program.program).unwrap_or(false) {
            inserted_programs += 1;
        }
    }

    for seeded_manifest in response
        .program_manifests
        .into_iter()
        .take(MAX_DHT_SEED_PROGRAM_MANIFESTS)
    {
        if !s
            .registry
            .should_store(&seeded_manifest.dht_key, &peer_ids, repl)
        {
            continue;
        }
        if s.compute_dht.store_manifest(seeded_manifest.manifest).unwrap_or(false) {
            inserted_program_manifests += 1;
        }
    }

    for seeded_receipt in response
        .compute_receipts
        .into_iter()
        .take(MAX_DHT_SEED_COMPUTE_RECEIPTS)
    {
        if !s
            .registry
            .should_store(&seeded_receipt.receipt_id, &peer_ids, repl)
        {
            continue;
        }
        if s.compute_dht.store_receipt(seeded_receipt.receipt.clone()).unwrap_or(false) {
            mirrored_receipts.push(seeded_receipt.receipt);
            inserted_compute_receipts += 1;
        }
    }

    drop(s);
    for receipt in mirrored_receipts {
        mirror_compute_receipt_text(state_dir, &receipt);
    }

    if inserted_tags > 0
        || inserted_manifests > 0
        || inserted_programs > 0
        || inserted_program_manifests > 0
        || inserted_compute_receipts > 0
    {
        info!(
            responder = ?&response.responder_node_id[..4],
            inserted_tags,
            inserted_manifests,
            inserted_programs,
            inserted_program_manifests,
            inserted_compute_receipts,
            "seeded initial DHT shard data from peer"
        );
    }

    snapshot
}

fn spawn_local_lan_discovery(local_contact: MeshCarrierContact, state: Arc<Mutex<ArteryState>>) {
    let loopback_contact = match crate::local_discovery::loopback_contact(&local_contact) {
        Ok(contact) => contact,
        Err(error) => {
            warn!(%error, "failed to build loopback Vess contact for local discovery");
            local_contact.clone()
        }
    };

    if let Err(error) = crate::local_discovery::publish_local_contact(&loopback_contact) {
        crate::local_discovery::log_publish_error(error);
    }

    tokio::spawn(async move {
        let self_node_id = {
            let s = state.lock().unwrap();
            s.node_id
        };
        let socket = match crate::local_discovery::bind_lan_discovery_socket(
            crate::local_discovery::LAN_DISCOVERY_PORT,
        ) {
            Ok(socket) => Some(socket),
            Err(error) => {
                warn!(%error, "LAN Vess discovery listener unavailable; same-PC file discovery remains enabled");
                None
            }
        };
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

        if let Some(socket) = socket {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(error) = crate::local_discovery::publish_local_contact(&loopback_contact) {
                            crate::local_discovery::log_publish_error(error);
                        }
                        if let Err(error) = crate::local_discovery::send_lan_announcement(&socket, &local_contact).await {
                            warn!(%error, "failed to send Vess LAN discovery announcement");
                        }
                        if routing_table_has_capacity(&state) {
                            if let Err(error) = crate::local_discovery::send_lan_probe(&socket).await {
                                warn!(%error, "failed to send Vess LAN discovery probe");
                            }
                        }
                        for contact in crate::local_discovery::discover_local_file_contacts(Some(self_node_id)) {
                            queue_discovered_peer_contact(&state, contact, "local-file");
                        }
                    }
                    recv = socket.recv_from(&mut buffer) => {
                        let Ok((len, source)) = recv else {
                            continue;
                        };
                        match crate::local_discovery::parse_lan_discovery_message(&buffer[..len], source) {
                            Ok(crate::local_discovery::ParsedLanDiscovery::Probe) => {
                                if let Err(error) = crate::local_discovery::send_probe_response(&socket, source, &local_contact).await {
                                    warn!(%error, "failed to send Vess LAN discovery probe response");
                                }
                            }
                            Ok(crate::local_discovery::ParsedLanDiscovery::Contact(contact)) => {
                                queue_discovered_peer_contact(&state, contact, "lan");
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        } else {
            loop {
                interval.tick().await;
                if let Err(error) = crate::local_discovery::publish_local_contact(&loopback_contact)
                {
                    crate::local_discovery::log_publish_error(error);
                }
                for contact in
                    crate::local_discovery::discover_local_file_contacts(Some(self_node_id))
                {
                    queue_discovered_peer_contact(&state, contact, "local-file");
                }
            }
        }
    });
}

fn routing_table_has_capacity(state: &Arc<Mutex<ArteryState>>) -> bool {
    let state = state.lock().unwrap();
    state.routing_table.has_capacity()
}

fn spawn_bitcoin_vess_discovery(
    client: vess_bitcoin::BitcoinLightClient,
    state: Arc<Mutex<ArteryState>>,
) {
    tokio::spawn(async move {
        loop {
            if !routing_table_has_capacity(&state) {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            let connected = client
                .wait_for_peers(1, std::time::Duration::from_secs(30))
                .await;
            if connected == 0 {
                info!("still waiting for Bitcoin peers for Vess bootstrap discovery");
                continue;
            }

            let discovered = client.discover_vess_nodes().await;
            if discovered.is_empty() {
                info!(
                    connected,
                    "no Vess bootstrap nodes found yet through Bitcoin peers; still waiting"
                );
            }
            for node in discovered {
                match parse_contact_string(&node.contact) {
                    Ok(contact) => queue_discovered_peer_contact(&state, contact, "bitcoin"),
                    Err(error) => {
                        warn!(node_id = %node.node_id, "Bitcoin-discovered Vess contact rejected: {error}")
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    });
}

fn spawn_bitcoin_peer_notifications(
    client: vess_bitcoin::BitcoinLightClient,
    state: Arc<Mutex<ArteryState>>,
) {
    tokio::spawn(async move {
        let mut announced = HashSet::new();
        loop {
            let current: HashSet<_> = client.active_peers().into_iter().collect();
            let newly_connected: Vec<_> = current.difference(&announced).copied().collect();
            if !newly_connected.is_empty() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut s = state.lock().unwrap();
                for peer in newly_connected {
                    s.push_notification(WalletNotification {
                        kind: "bitcoin_peer_connected".to_string(),
                        created_at: now,
                        payment_id: peer.to_string(),
                        amount: None,
                        bill_count: None,
                        counterparty: Some(peer.to_string()),
                        message: format!("Bitcoin peer connected: {peer}"),
                    });
                }
            }
            announced.retain(|peer| current.contains(peer));
            announced.extend(current);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
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
    /// Optional override for the embedded Bitcoin light client configuration.
    /// Useful for deterministic integration tests with local mock peers.
    pub bitcoin_config: Option<vess_bitcoin::BitcoinConfig>,
    /// Whether to enable LAN/local-file peer discovery.
    pub enable_local_discovery: bool,
    /// Allow advertising a non-public mesh contact into Bitcoin-side Vess seed discovery.
    /// Intended for local integration tests that run all nodes on loopback.
    pub allow_private_bitcoin_seed_contact: bool,
    /// When true, discard persisted peer cache / reputation / ban state on startup.
    /// Useful for ephemeral interactive CLI nodes that reuse slot directories.
    pub reset_transient_peer_state: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            k_neighbors: 6,
            max_hops: 3,
            state_dir: NodeStorage::default_dir().unwrap_or_else(|_| PathBuf::from(".vess-artery")),
            bootstrap: Vec::new(),
            ready_tx: None,
            wallet_path: None,
            rpc_port: None,
            wallet_password: None,
            bitcoin_config: None,
            enable_local_discovery: true,
            allow_private_bitcoin_seed_contact: false,
            reset_transient_peer_state: false,
        }
    }
}

// ── Payment latency tracker ─────────────────────────────────────────

/// Tracks end-to-end payment latency samples (payment relay → ownership
/// claim confirmation).  Keeps a bounded sliding window so memory is fixed.
pub(crate) struct PaymentLatencyTracker {
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
pub(crate) struct WalletState {
    pub(crate) stealth_secret: StealthSecretKey,
    pub(crate) billfold: vess_kloak::BillFold,
    pub(crate) bitcoin_wallet: vess_bitcoin::BitcoinWallet,
    pub(crate) bitcoin_receive_address: String,
    pub(crate) wallet_path: PathBuf,
    /// Encryption key for spend credentials and tag keys on disk.
    pub(crate) enc_key: [u8; 32],
    /// Mailbox shard key derived from our spend encapsulation key.
    /// Used for targeted [`MailboxSweep`] and automatic forwarding subscription.
    pub(crate) mailbox_key: [u8; 32],
    /// Spend seed for DHT manifest encryption and wallet recovery.
    /// `None` for older wallets that haven't been migrated yet.
    pub(crate) spend_seed: Option<[u8; 32]>,
}

impl Drop for WalletState {
    fn drop(&mut self) {
        self.enc_key.zeroize();
    }
}

/// Shared artery node state behind a mutex.
pub(crate) struct ArteryState {
    pub(crate) registry: OwnershipRegistry,
    pub(crate) tag_dht: TagDht,
    pub(crate) compute_dht: ComputeDht,
    pub(crate) node_id: [u8; 32],
    /// Kademlia routing table: 256 XOR-distance buckets of infrastructure
    /// relay peers. Never contains wallet users or payment recipients.
    pub(crate) routing_table: RoutingTable,
    pub(crate) gossip_config: GossipConfig,
    pub(crate) peer_registry: PeerRegistry,
    pub(crate) handshake_queue: Vec<[u8; 32]>,
    pub(crate) limbo_buffer: LimboBuffer,
    pub(crate) reputation: ReputationTable,
    pub(crate) rate_limiter: crate::gossip::PeerRateLimiter,
    pub(crate) mailbox_collect_limiter: crate::gossip::PeerRateLimiter,
    /// Rate limiter for TagLookup to prevent tag enumeration.
    pub(crate) tag_lookup_limiter: crate::gossip::PeerRateLimiter,
    /// Rate limiter for RegistryQuery / OwnershipFetch to prevent
    /// bulk mint_id enumeration (surveillance attack).
    pub(crate) registry_query_limiter: crate::gossip::PeerRateLimiter,
    pub(crate) duplicate_tracker: DuplicateTracker,
    /// Estimated number of peers in the network (for dynamic DHT replication).
    pub(crate) estimated_network_size: usize,
    /// Mint IDs currently in limbo (soft reservation while payment is in flight).
    pub(crate) limbo_mint_ids: std::collections::HashSet<[u8; 32]>,
    /// Payment IDs already in limbo (prevents exact duplicate buffering).
    pub(crate) limbo_payment_ids: std::collections::HashSet<[u8; 32]>,
    /// Encrypted wallet manifests keyed by DHT key.
    /// Value is `(encrypted_manifest, inserted_at_unix_secs)` for oldest-first eviction.
    pub(crate) manifest_store: HashMap<[u8; 32], (Vec<u8>, u64)>,
    /// Locally-retained ownership records for bills this node originated or
    /// currently owns, kept even when this node is not in the live DHT shard.
    /// Used to seed newly closer peers during bootstrap.
    pub(crate) retained_ownership_records: HashMap<[u8; 32], OwnershipRecord>,
    /// Locally-retained tombstones for consumed bills this node originated or
    /// tracked, so newly closer peers can learn reforge outcomes during seed sync.
    pub(crate) retained_consumed_records: HashMap<[u8; 32], ConsumedRecord>,
    /// Unix-millis timestamp when each bill entered limbo (keyed by mint_id,
    /// populated at auto-receive time for end-to-end latency tracking).
    pub(crate) limbo_entry_times: HashMap<[u8; 32], u64>,
    /// Payment latency tracker (payment relay → ownership claim completion).
    pub(crate) payment_latency: PaymentLatencyTracker,
    /// H3: OwnershipGenesis messages that arrived before their ReforgeAttestation
    /// tombstones. Keyed by a missing input mint_id — when that tombstone is
    /// created by an RA, the pending genesis messages are retried.
    /// This prevents legitimate reforge outputs from being rejected (and the
    /// broadcaster being falsely banished) due to gossip ordering races.
    /// Value is `(OwnershipGenesis, buffered_at_unix_secs)` for TTL eviction.
    /// C1: Enforced global cap + per-key cap to prevent memory exhaustion.
    pub(crate) pending_reforge_genesis:
        HashMap<[u8; 32], Vec<(vess_protocol::OwnershipGenesis, u64)>>,
    /// Embedded wallet — trial-decrypts incoming payments automatically.
    pub(crate) wallet: Option<WalletState>,
    /// Background Bitcoin light client used for burn verification and
    /// transaction broadcast/onboarding.
    pub(crate) bitcoin_client: Option<vess_bitcoin::BitcoinLightClient>,
    /// Wallet file path (set from config even when wallet is locked).
    /// Used by the RPC `wallet_unlock` endpoint to load the file.
    pub(crate) wallet_path: Option<PathBuf>,
    /// Wallet-local notification queue for CLI and wallet layers.
    pub(crate) notifications: VecDeque<WalletNotification>,
    /// Structured node events for CLI display (burns, claims, banishments, etc.).
    pub(crate) events: VecDeque<NodeEvent>,
    /// Outbound payments waiting for recipient claim confirmation.
    pub(crate) outbound_payments: HashMap<[u8; 32], OutboundPaymentRecord>,
    /// Reverse index from mint_id to outbound payment_id for fast finalization.
    pub(crate) outbound_by_mint_id: HashMap<[u8; 32], [u8; 32]>,
    /// Shared banishment manager — included in snapshots so the ban list
    /// survives node restarts.
    pub(crate) banishment: Arc<BanishmentManager>,
    /// Persistent local VessTag address book.
    /// Caches every verified tag → stealth address the wallet has sent to,
    /// so repeat payments skip the DHT entirely.
    pub(crate) tag_cache: crate::tag_cache::TagCache,
    /// Active push-forwarding subscriptions: mailbox_key → record of the
    /// subscribing node and subscription expiry time.
    pub(crate) mailbox_fwd: HashMap<[u8; 32], ForwardRecord>,
    /// Rate limiter for [`MailboxForwardRegister`] requests.
    pub(crate) mailbox_fwd_limiter: crate::gossip::PeerRateLimiter,
    /// Whether test-only / unsafe features are permitted.
    pub(crate) unsafe_mode: bool,
    /// Runtime flag for the local test faucet.
    pub(crate) test_faucet_enabled: bool,
}

impl ArteryState {
    pub(crate) fn push_notification(&mut self, notification: WalletNotification) {
        info!(
            kind = %notification.kind,
            payment_id = %notification.payment_id,
            "{}",
            notification.message
        );
        if self.notifications.len() >= MAX_WALLET_NOTIFICATIONS {
            self.notifications.pop_front();
        }
        self.notifications.push_back(notification);
    }

    pub(crate) fn take_notifications(&mut self, max: usize) -> Vec<WalletNotification> {
        let count = max.max(1).min(self.notifications.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(note) = self.notifications.pop_front() {
                out.push(note);
            }
        }
        out
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

    fn now_unix() -> u64 {
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
    /// No-op if no wallet is loaded.
    pub(crate) fn flush_wallet(&self) {
        if let Some(ref ws) = self.wallet {
            if let Ok(mut wf) = vess_kloak::WalletFile::load(&ws.wallet_path) {
                wf.billfold = ws.billfold.clone();
                // Encrypt spend credentials before persisting.
                if let Err(e) = wf.encrypt_spend_credentials(&ws.billfold, &ws.enc_key) {
                    tracing::warn!(error = %e, "failed to encrypt spend credentials");
                }
                match ws.bitcoin_wallet.export_state_bytes() {
                    Ok(state_bytes) => {
                        if let Err(e) =
                            wf.set_encrypted_bitcoin_wallet_state(&state_bytes, &ws.enc_key)
                        {
                            tracing::warn!(error = %e, "failed to encrypt bitcoin wallet state");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to serialize bitcoin wallet state");
                    }
                }
                if let Err(e) = wf.save(&ws.wallet_path, &ws.enc_key) {
                    tracing::warn!(error = %e, "failed to flush wallet to disk");
                }
            }
        }
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

        let compute_programs: BTreeMap<String, vess_protocol::StoredProgram> = self
            .compute_dht
            .all_programs()
            .into_iter()
            .map(|(prog_id, program)| (hex_key(prog_id.as_bytes()), program))
            .collect();
        let compute_program_manifests: BTreeMap<String, vess_protocol::ProgramManifest> = self
            .compute_dht
            .all_manifests()
            .into_iter()
            .map(|(dht_key, manifest)| (hex_key(&dht_key), manifest))
            .collect();
        let compute_receipts: BTreeMap<String, vess_protocol::ComputeReceipt> = self
            .compute_dht
            .all_receipts()
            .into_iter()
            .map(|(receipt_id, receipt)| (hex_key(&receipt_id), receipt))
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
            compute_programs,
            compute_program_manifests,
            compute_receipts,
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

        self.compute_dht = ComputeDht::new();
        for (_, program) in snap.compute_programs.into_iter().filter_map(|(k, v)| {
            unhex_key(&k)
                .ok()
                .map(vess_protocol::ProgramId)
                .map(|key| (key, v))
        }) {
            let _ = self.compute_dht.store_program(program);
        }
        for (_, manifest) in snap.compute_program_manifests.into_iter().filter_map(|(k, v)| {
            unhex_key(&k).ok().map(|key| (key, v))
        }) {
            let _ = self.compute_dht.store_manifest(manifest);
        }
        for (_, receipt) in snap.compute_receipts.into_iter().filter_map(|(k, v)| {
            unhex_key(&k).ok().map(|key| (key, v))
        }) {
            let _ = self.compute_dht.store_receipt(receipt);
        }

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

        let (bitcoin_wallet, bitcoin_receive_address) =
            load_bitcoin_wallet_state(&wallet, &raw_seed, &enc_key)?;

        info!(
            path = %wallet_path.display(),
            bitcoin_receive_address = %bitcoin_receive_address,
            "wallet loaded — auto-receive enabled"
        );
        (
            Some(WalletState {
                stealth_secret,
                billfold,
                bitcoin_wallet,
                bitcoin_receive_address,
                wallet_path: wallet_path.clone(),
                enc_key,
                mailbox_key,
                spend_seed: None,
            }),
            startup_wallet_tag_store,
        )
    } else {
        (None, None)
    };

    info!("Starting Bitcoin peer discovery before Vess mesh bootstrap...");
    let bitcoin_client = match vess_bitcoin::BitcoinLightClient::spawn(
        config.bitcoin_config.clone().unwrap_or_default(),
    )
    .await
    {
        Ok(client) => {
            info!(
                peers = client.connected_peers(),
                "bitcoin light client started"
            );
            Some(client)
        }
        Err(e) => {
            warn!("bitcoin light client failed to start: {e}");
            None
        }
    };
    let bitcoin_seed_client = bitcoin_client.clone();

    let mesh_seed = load_or_create_mesh_seed(&config.state_dir)?;
    let node = MeshPulseNode::bind_from_seed(
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )),
        &mesh_seed,
        0,
    )
    .await?;

    info!("Starting artery node...");
    node.wait_online().await;

    let node_id_str = node.id().to_string();
    let node_id_bytes: [u8; 32] = *node.id().as_bytes();
    if let Some(client) = &bitcoin_seed_client {
        let local_contact = node.contact();
        let allow_private = config.allow_private_bitcoin_seed_contact;
        match vess_mesh::validate_public_mesh_contact(&local_contact) {
            Ok(()) => {
                let local_contact = encode_contact_string(&local_contact)?;
                let (seed_auth_sk, seed_auth_vk) = vess_bitcoin::derive_vess_seed_auth_keypair(&mesh_seed);
                client.set_local_vess_seed_node(node_id_str.clone(), local_contact, seed_auth_sk, seed_auth_vk);
            }
            Err(error) => {
                if allow_private {
                    let loopback_contact = crate::local_discovery::loopback_contact(&local_contact)
                        .unwrap_or_else(|_| local_contact.clone());
                    let local_contact = encode_contact_string(&loopback_contact)?;
                    let (seed_auth_sk, seed_auth_vk) = vess_bitcoin::derive_vess_seed_auth_keypair(&mesh_seed);
                    client.set_local_vess_seed_node(node_id_str.clone(), local_contact, seed_auth_sk, seed_auth_vk);
                    warn!(%error, "local mesh contact is not public-routable; advertising it anyway for test-only Bitcoin seed discovery");
                } else {
                    warn!(%error, "local mesh contact is not public-routable; skipping Bitcoin seed advertisement");
                }
            }
        }
    }

    let gossip_config = GossipConfig {
        k_neighbors: config.k_neighbors,
        max_hops: config.max_hops,
    };

    let banishment = Arc::new(BanishmentManager::new());

    let state = Arc::new(Mutex::new(ArteryState {
        registry: OwnershipRegistry::new(node_id_bytes),
        tag_dht: TagDht::new(node_id_bytes, config.k_neighbors),
        compute_dht: ComputeDht::new(),
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
        bitcoin_client,
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
        unsafe_mode: false,
        test_faucet_enabled: false,
        events: VecDeque::new(),
    }));
    let receipt_text_state_dir = config.state_dir.clone();

    if let Some(client) = {
        let s = state.lock().unwrap();
        s.bitcoin_client.clone()
    } {
        spawn_bitcoin_peer_notifications(client.clone(), state.clone());
        let state_for_bitcoin = state.clone();
        let retry_state = state.clone();
        let retry_client = client.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(AUTO_BURN_RETRY_SECS));
            loop {
                interval.tick().await;
                let pending_burns = {
                    let mut s = retry_state.lock().unwrap();
                    let mut pending_burns = queue_auto_burn_if_needed(&mut s);
                    if let Some(ws) = s.wallet.as_ref() {
                        pending_burns.extend(ws.bitcoin_wallet.pending_burns_ready_for_broadcast(
                            ArteryState::now_unix(),
                            AUTO_BURN_RETRY_SECS,
                        ));
                    }
                    if !pending_burns.is_empty() {
                        s.flush_wallet();
                    }
                    pending_burns
                };

                if !pending_burns.is_empty() {
                    broadcast_pending_burns(
                        retry_state.clone(),
                        retry_client.clone(),
                        pending_burns,
                    )
                    .await;
                }
            }
        });

        let subscriber_client = client.clone();
        tokio::spawn(async move {
            let mut rx = subscriber_client.subscribe_transactions();
            loop {
                match rx.recv().await {
                    Ok(observed) => {
                        let pending_burns = {
                            let mut s = state_for_bitcoin.lock().unwrap();
                            let mut active_receive_address = None;
                            let mut rotated_receive_address = None;
                            let mut update = None;
                            if let Some(ws) = s.wallet.as_mut() {
                                active_receive_address = Some(ws.bitcoin_receive_address.clone());
                                let current_receive_address = ws.bitcoin_receive_address.clone();
                                let wallet_update =
                                    ws.bitcoin_wallet.record_transaction(&observed.transaction);
                                let used_current_receive_address =
                                    wallet_update.discovered_utxos.iter().any(|utxo| {
                                        utxo.address.to_string() == current_receive_address
                                    });
                                if used_current_receive_address {
                                    match ws.bitcoin_wallet.issue_receive_address() {
                                        Ok(next_receive_address) => {
                                            ws.bitcoin_receive_address =
                                                next_receive_address.address.to_string();
                                            rotated_receive_address =
                                                Some(ws.bitcoin_receive_address.clone());
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "failed to rotate bitcoin receive address after first tracked use");
                                        }
                                    }
                                }
                                update = Some(wallet_update);
                            }

                            if let Some(ref update) = update {
                                if !update.discovered_utxos.is_empty() {
                                    let received_sats: u64 = update
                                        .discovered_utxos
                                        .iter()
                                        .map(|utxo| utxo.value_sats)
                                        .sum();
                                    s.push_notification(WalletNotification {
                                        kind: "bitcoin_received".to_string(),
                                        created_at: ArteryState::now_unix(),
                                        payment_id: observed.txid.to_string(),
                                        amount: Some(received_sats),
                                        bill_count: Some(update.discovered_utxos.len()),
                                        counterparty: Some(observed.peer.to_string()),
                                        message: format!(
                                            "Tracked {} sat(s) to {} Bitcoin output(s) in {} for receive address {}.",
                                            received_sats,
                                            update.discovered_utxos.len(),
                                            observed.txid,
                                            active_receive_address.unwrap_or_else(|| "<unknown>".to_string())
                                        ),
                                    });
                                    if let Some(ref next_receive_address) = rotated_receive_address
                                    {
                                        s.push_notification(WalletNotification {
                                            kind: "bitcoin_receive_address_rotated".to_string(),
                                            created_at: ArteryState::now_unix(),
                                            payment_id: observed.txid.to_string(),
                                            amount: None,
                                            bill_count: None,
                                            counterparty: None,
                                            message: format!(
                                                "Rotated Bitcoin receive address after {}. New receive address: {}.",
                                                observed.txid, next_receive_address
                                            ),
                                        });
                                    }
                                }
                                for pending_txid in &update.seen_pending_burns {
                                    s.push_notification(WalletNotification {
                                        kind: "bitcoin_burn_seen".to_string(),
                                        created_at: ArteryState::now_unix(),
                                        payment_id: pending_txid.to_string(),
                                        amount: None,
                                        bill_count: None,
                                        counterparty: Some(observed.peer.to_string()),
                                        message: format!(
                                            "Observed pending Bitcoin burn {} from peer {}.",
                                            pending_txid, observed.peer
                                        ),
                                    });
                                }
                                for pending_txid in &update.conflicted_pending_burns {
                                    s.push_notification(WalletNotification {
                                        kind: "bitcoin_burn_conflicted".to_string(),
                                        created_at: ArteryState::now_unix(),
                                        payment_id: pending_txid.to_string(),
                                        amount: None,
                                        bill_count: None,
                                        counterparty: Some(observed.peer.to_string()),
                                        message: format!(
                                            "Pending Bitcoin burn {} conflicted with observed transaction {}.",
                                            pending_txid, observed.txid
                                        ),
                                    });
                                }
                            }

                            let pending_burns = queue_auto_burn_if_needed(&mut s);
                            if let Some(ref update) = update {
                                if update.has_state_change() || !pending_burns.is_empty() {
                                    s.flush_wallet();
                                }
                            } else if !pending_burns.is_empty() {
                                s.flush_wallet();
                            }
                            pending_burns
                        };

                        if !pending_burns.is_empty() {
                            broadcast_pending_burns(
                                state_for_bitcoin.clone(),
                                subscriber_client.clone(),
                                pending_burns,
                            )
                            .await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "bitcoin transaction subscriber lagged behind");
                    }
                }
            }
        });
    }

    // ── Gossip drain channels ───────────────────────────────────────
    // Unbounded mpsc channels decouple queue producers (handler) from
    // consumers (drain loops) so drain loops never contend on the main
    // state mutex for queue access.
    let (manifest_tx, mut manifest_rx) =
        tokio::sync::mpsc::unbounded_channel::<vess_protocol::ManifestStore>();
    let (program_tx, mut program_rx) = tokio::sync::mpsc::unbounded_channel::<ProgramStore>();
    let (program_manifest_tx, mut program_manifest_rx) =
        tokio::sync::mpsc::unbounded_channel::<ProgramManifestStore>();
    let (compute_receipt_tx, mut compute_receipt_rx) =
        tokio::sync::mpsc::unbounded_channel::<ComputeReceiptStore>();
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
        let restored_receipts = snapshot.compute_receipts.values().cloned().collect::<Vec<_>>();
        let mut s = state.lock().unwrap();
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
        for receipt in restored_receipts {
            mirror_compute_receipt_text(&receipt_text_state_dir, &receipt);
        }
    }

    if let Some((tag_str, tag_store)) = startup_wallet_tag_store.clone() {
        let mut s = state.lock().unwrap();
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
        let mut s = state.lock().unwrap();
        if s.wallet.is_some() {
            let all_sids: Vec<[u8; 32]> = s.limbo_buffer.stealth_ids_with_payments();
            let mut payloads: Vec<Vec<u8>> = Vec::new();
            for sid in &all_sids {
                for entry in s.limbo_buffer.peek(sid) {
                    payloads.push(entry.payment.stealth_payload.clone());
                }
            }
            if !payloads.is_empty() {
                let ws = s.wallet.as_mut().unwrap();
                let mut received = 0u64;
                let mut bill_count = 0usize;
                let mut pending_claims: Vec<OwnershipClaim> = Vec::new();
                for payload in &payloads {
                    match receive_and_claim(&ws.stealth_secret, payload) {
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
    if let Some(client) = bitcoin_seed_client.clone() {
        spawn_bitcoin_vess_discovery(client, state.clone());
    }
    if config.wallet_path.is_some() {
        let s = state.lock().unwrap();
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
            program_tx: program_tx.clone(),
            program_manifest_tx: program_manifest_tx.clone(),
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

    if let Some(confirm_client) = {
        let s = state.lock().unwrap();
        s.bitcoin_client.clone()
    } {
        let confirm_state = state.clone();
        let confirm_og_tx = og_tx.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(AUTO_BURN_RETRY_SECS));
            loop {
                interval.tick().await;

                let (pending_burns, hops_remaining) = {
                    let s = confirm_state.lock().unwrap();
                    let pending_burns = s
                        .wallet
                        .as_ref()
                        .map(|ws| ws.bitcoin_wallet.pending_burns())
                        .unwrap_or_default();
                    (pending_burns, s.gossip_config.max_hops)
                };

                for pending in pending_burns {
                    let confirmation = match confirm_client
                        .request_burn_confirmation(pending.txid, pending.created_at)
                        .await
                    {
                        Ok(Some(confirmation)) => confirmation,
                        Ok(None) => continue,
                        Err(e) => {
                            warn!(txid = %pending.txid, error = %e, "failed to confirm automatic bitcoin burn");
                            continue;
                        }
                    };

                    let (genesis_records, bills) = match confirmed_burn_outputs(
                        &pending,
                        &confirmation,
                        vess_bitcoin::BitcoinNetwork::Mainnet,
                        hops_remaining,
                    ) {
                        Ok(outputs) => outputs,
                        Err(e) => {
                            warn!(txid = %pending.txid, error = %e, "failed to assemble bitcoin burn ownership genesis records");
                            continue;
                        }
                    };

                    let minted_total: u64 =
                        bills.iter().map(|bill| bill.denomination.value()).sum();
                    let bill_count = bills.len();
                    let spend_credential = SpendCredential {
                        spend_vk: pending.first_owner_vk.clone(),
                        spend_sk: pending.first_owner_sk.clone(),
                    };

                    let should_gossip = {
                        let mut s = confirm_state.lock().unwrap();
                        let removed = if let Some(ws) = s.wallet.as_mut() {
                            if ws
                                .bitcoin_wallet
                                .remove_pending_burn(&pending.txid)
                                .is_none()
                            {
                                false
                            } else {
                                for bill in &bills {
                                    ws.billfold.deposit_with_credentials(
                                        bill.clone(),
                                        SpendCredential {
                                            spend_vk: spend_credential.spend_vk.clone(),
                                            spend_sk: spend_credential.spend_sk.clone(),
                                        },
                                    );
                                }
                                true
                            }
                        } else {
                            false
                        };

                        if removed {
                            s.push_notification(WalletNotification {
                                kind: "bitcoin_burn_confirmed".to_string(),
                                created_at: ArteryState::now_unix(),
                                payment_id: pending.txid.to_string(),
                                amount: Some(minted_total),
                                bill_count: Some(bill_count),
                                counterparty: Some(confirmation.block_hash.to_string()),
                                message: format!(
                                    "Confirmed Bitcoin burn {} in block {} and minted {} Vess bill(s) for {} sats.",
                                    pending.txid,
                                    confirmation.block_hash,
                                    bill_count,
                                    minted_total
                                ),
                            });
                            s.flush_wallet();
                            info!(
                                txid = %pending.txid,
                                block_hash = %confirmation.block_hash,
                                minted_total,
                                bill_count,
                                "confirmed automatic bitcoin burn and generated ownership genesis"
                            );
                        }

                        removed
                    };

                    if should_gossip {
                        let mut s = confirm_state.lock().unwrap();
                        for og in genesis_records {
                            queue_local_ownership_genesis(&mut s, &confirm_og_tx, og);
                        }
                    }
                }
            }
        });
    }

    // ── Periodic state flush (every 60 seconds) ─────────────────────
    let flush_state = state.clone();
    let flush_storage_dir = config.state_dir.clone();
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
                    info!(count = pruned_tags, "pruned unhardened tags");
                }
                let active_program_ids = program_ids_with_live_owned_bills(&s);
                let pruned_programs = s
                    .compute_dht
                    .prune_inactive_programs(now, &active_program_ids);
                if !pruned_programs.pruned_program_ids.is_empty() {
                    info!(
                        count = pruned_programs.pruned_program_ids.len(),
                        pruned_manifest_count = pruned_programs.pruned_manifest_count,
                        pruned_receipt_count = pruned_programs.pruned_receipt_count,
                        ttl_secs = PROGRAM_PRUNE_SECS,
                        "pruned inactive programs"
                    );
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
                // Re-estimate network size from routing table and scale
                // gossip parameters dynamically.
                s.estimated_network_size = s.routing_table.estimated_network_size();
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
            }
        }
    });

    // ── Bootstrap discovery ─────────────────────────────────────────
    let mut all_bootstrap = config.bootstrap.clone();
    {
        let s = state.lock().unwrap();
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
    if let Some(client) = &bitcoin_seed_client {
        let discovered = client
            .discover_vess_nodes()
            .await;
        if !discovered.is_empty() {
            info!(
                count = discovered.len(),
                "discovered Vess bootstrap nodes via Bitcoin peers"
            );
            for node in discovered {
                all_bootstrap.push(node.contact.clone());
                match parse_contact_string(&node.contact) {
                    Ok(contact) => queue_discovered_peer_contact(&state, contact, "bitcoin"),
                    Err(error) => {
                        warn!(node_id = %node.node_id, "Bitcoin-discovered Vess contact rejected: {error}")
                    }
                }
            }
        }
    }
    all_bootstrap.sort_unstable();
    all_bootstrap.dedup();

    // ── Bootstrap ───────────────────────────────────────────────────
    if !all_bootstrap.is_empty() {
        let boot_node = node.clone();
        let boot_state = state.clone();
        let boot_ban = banishment.clone();
        let boot_receipt_text_state_dir = receipt_text_state_dir.clone();
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

                let nonce = {
                    let mut s = boot_state.lock().unwrap();
                    s.peer_registry.issue_challenge(peer_hash)
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
                                warn!(peer = %peer_str, "bootstrap peer PoW verification failed — banishing");
                                s.peer_registry.mark_banished(peer_hash);
                                boot_ban.banish(peer_hash);
                                push_peer_notification(
                                    &mut s,
                                    "vess_peer_handshake_failed",
                                    &peer_hash,
                                    Some("bootstrap".to_string()),
                                    format!("Bootstrap handshake failed PoW verification for peer: {}", hex_key(&peer_hash)),
                                );
                                continue;
                            }
                            push_peer_notification(
                                &mut s,
                                "vess_peer_verified",
                                &peer_hash,
                                Some("bootstrap".to_string()),
                                format!("Verified Vess peer after bootstrap handshake: {}", hex_key(&peer_hash)),
                            );
                            info!(peer = %peer_str, "bootstrap peer verified");
                        } else {
                            s.peer_registry.mark_banished(peer_hash);
                            boot_ban.banish(peer_hash);
                            push_peer_notification(
                                &mut s,
                                "vess_peer_handshake_failed",
                                &peer_hash,
                                Some("bootstrap".to_string()),
                                format!("Bootstrap handshake returned an invalid response for peer: {}", hex_key(&peer_hash)),
                            );
                            info!(peer = %peer_str, "bootstrap peer banished — bad handshake");
                            continue;
                        }
                    }
                    Ok(_) => {
                        let mut s = boot_state.lock().unwrap();
                        push_peer_notification(
                            &mut s,
                            "vess_peer_handshake_failed",
                            &peer_hash,
                            Some("bootstrap".to_string()),
                            format!("Bootstrap handshake got an unexpected response from peer: {}", hex_key(&peer_hash)),
                        );
                        info!(peer = %peer_str, "bootstrap peer gave unexpected response");
                        continue;
                    }
                    Err(e) => {
                        let mut s = boot_state.lock().unwrap();
                        push_peer_notification(
                            &mut s,
                            "vess_peer_handshake_failed",
                            &peer_hash,
                            Some("bootstrap".to_string()),
                            format!("Bootstrap handshake could not reach peer {}: {e}", hex_key(&peer_hash)),
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

                if let Some(snapshot) =
                    request_dht_seed_catchup(&boot_node, &target, &boot_state, &boot_receipt_text_state_dir).await
                {
                    seed_snapshots.push(snapshot);
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

    // ── Program store drain task ────────────────────────────────────
    let program_drain_state = state.clone();
    let program_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = program_rx.recv().await {
            let mut programs = vec![first];
            while let Ok(item) = program_rx.try_recv() {
                programs.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = program_drain_state.lock().unwrap();
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
            for ps in &programs {
                let bytes = match PulseMessage::ProgramStore(ps.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize ProgramStore failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    ps.program.prog_id().as_bytes(),
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
            batch_forward_bytes_to_peers(&program_drain_node, &routable_peers, per_peer).await;
            info!(count = programs.len(), "program store batch forwarded");
        }
    });

    // ── Program manifest store drain task ──────────────────────────
    let program_manifest_drain_state = state.clone();
    let program_manifest_drain_node = node.clone();
    tokio::spawn(async move {
        while let Some(first) = program_manifest_rx.recv().await {
            let mut manifests = vec![first];
            while let Ok(item) = program_manifest_rx.try_recv() {
                manifests.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = program_manifest_drain_state.lock().unwrap();
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
            for pms in &manifests {
                let dht_key = pms.manifest.dht_key();
                let bytes = match PulseMessage::ProgramManifestStore(pms.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize ProgramManifestStore failed");
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
            batch_forward_bytes_to_peers(&program_manifest_drain_node, &routable_peers, per_peer)
                .await;
            info!(count = manifests.len(), "program manifest store batch forwarded");
        }
    });

    // ── Compute receipt store drain task ────────────────────────────
    let compute_receipt_drain_state = state.clone();
    let compute_receipt_drain_node = node.clone();
    let compute_receipt_text_dir = receipt_text_state_dir.clone();
    tokio::spawn(async move {
        while let Some(first) = compute_receipt_rx.recv().await {
            let mut receipts = vec![first];
            while let Ok(item) = compute_receipt_rx.try_recv() {
                receipts.push(item);
            }

            let (peer_hashes, routable_peers, age_factors, peer_scores, k, net_size) = {
                let s = compute_receipt_drain_state.lock().unwrap();
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
            for crs in &receipts {
                mirror_compute_receipt_text(&compute_receipt_text_dir, &crs.receipt);
                let bytes = match PulseMessage::ComputeReceiptStore(crs.clone()).to_bytes() {
                    Ok(b) => Arc::new(b),
                    Err(e) => {
                        warn!(error = %e, "serialize ComputeReceiptStore failed");
                        continue;
                    }
                };
                let indices = compute_gossip_targets_scored(
                    &crs.receipt.receipt_id,
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
            batch_forward_bytes_to_peers(&compute_receipt_drain_node, &routable_peers, per_peer)
                .await;
            info!(count = receipts.len(), "compute receipt batch forwarded");
        }
    });

    // ── Tag store drain task ────────────────────────────────────────
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

    // ── Periodic peer exchange ──────────────────────────────────────
    let pex_node = node.clone();
    let pex_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;

            let routable_count = {
                let s = pex_state.lock().unwrap();
                s.routing_table.routable_peers(|_| true).len()
            };

            if routable_count < 3 {
                let peers_to_ask: Vec<Vec<u8>> = {
                    let s = pex_state.lock().unwrap();
                    s.routing_table
                        .routable_peers(|_| true)
                        .into_iter()
                        .take(3)
                        .map(|p| p.id_bytes)
                        .collect()
                };

                for peer_bytes in peers_to_ask {
                    let target = match decode_contact_bytes(&peer_bytes) {
                        Ok(contact) => contact,
                        Err(_) => continue,
                    };
                    let msg = PulseMessage::PeerExchange(PeerExchange {
                        sender_id: pex_node.id().as_bytes().to_vec(),
                    });
                    if let Ok(Some(PulseMessage::PeerExchangeResponse(resp))) =
                        pex_node.send_message_with_response(&target, &msg).await
                    {
                        if resp.peers.len() > MAX_PEER_EXCHANGE_PEERS {
                            warn!(
                                count = resp.peers.len(),
                                "peer exchange returned too many contacts; truncating response"
                            );
                        }
                        let mut s = pex_state.lock().unwrap();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for new_peer_bytes in resp.peers.iter().take(MAX_PEER_EXCHANGE_PEERS) {
                            let Some(hash) = peer_hash_from_contact_bytes(new_peer_bytes) else {
                                continue;
                            };
                            if hash == s.node_id {
                                continue;
                            }
                            if !s.routing_table.contains(&hash) {
                                s.routing_table.insert(RoutingPeer {
                                    id_hash: hash,
                                    id_bytes: new_peer_bytes.clone(),
                                    last_seen: now,
                                    first_seen: now,
                                });
                                s.handshake_queue.push(hash);
                            }
                        }
                    }
                }
            }
        }
    });

    // ── Handshake drain task ────────────────────────────────────────
    let hs_node = node.clone();
    let hs_state = state.clone();
    let hs_ban = banishment.clone();
    let hs_receipt_text_state_dir = receipt_text_state_dir.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;

            let peers_to_challenge: Vec<[u8; 32]> = {
                let mut s = hs_state.lock().unwrap();
                s.peer_registry.evict_stale();
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

                let nonce = {
                    let mut s = hs_state.lock().unwrap();
                    s.peer_registry.issue_challenge(peer_hash)
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
                    let verified = {
                        let mut s = hs_state.lock().unwrap();
                        if s.peer_registry.verify_response(
                            &peer_hash,
                            &resp.hmac,
                            &ALLOWED_VERSIONS,
                        ) {
                            // Verify Argon2id PoW from the peer.
                            if resp.pow_hash.is_empty()
                                || !verify_handshake_pow(&peer_hash, &nonce, &resp.pow_hash)
                            {
                                warn!("peer PoW verification failed — banishing");
                                s.peer_registry.mark_banished(peer_hash);
                                hs_ban.banish(peer_hash);
                                push_peer_notification(
                                    &mut s,
                                    "vess_peer_handshake_failed",
                                    &peer_hash,
                                    None,
                                    format!("Handshake failed PoW verification for peer: {}", hex_key(&peer_hash)),
                                );
                                false
                            } else {
                                push_peer_notification(
                                    &mut s,
                                    "vess_peer_verified",
                                    &peer_hash,
                                    None,
                                    format!("Verified Vess peer after handshake: {}", hex_key(&peer_hash)),
                                );
                                info!("peer verified via handshake");
                                true
                            }
                        } else {
                            s.peer_registry.mark_banished(peer_hash);
                            hs_ban.banish(peer_hash);
                            push_peer_notification(
                                &mut s,
                                "vess_peer_handshake_failed",
                                &peer_hash,
                                None,
                                format!("Handshake returned an invalid response for peer: {}", hex_key(&peer_hash)),
                            );
                            info!("peer banished — invalid handshake response");
                            false
                        }
                    };

                    if verified {
                        request_peer_exchange_from_peer(&hs_node, &target, &hs_state).await;
                        request_dht_seed_catchup(&hs_node, &target, &hs_state, &hs_receipt_text_state_dir).await;
                        refresh_mailbox_forward_subscriptions(&hs_node, &hs_state).await;
                    }
                } else {
                    let mut s = hs_state.lock().unwrap();
                    push_peer_notification(
                        &mut s,
                        "vess_peer_handshake_failed",
                        &peer_hash,
                        None,
                        format!("Handshake timed out or returned no usable response for peer: {}", hex_key(&peer_hash)),
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

                let nonce = {
                    let mut s = reverify_state.lock().unwrap();
                    s.peer_registry.issue_challenge(peer_hash)
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
    let h_program_tx = program_tx.clone();
    let h_program_manifest_tx = program_manifest_tx.clone();
    let h_compute_receipt_tx = compute_receipt_tx.clone();
    let h_tag_store_tx = tag_store_tx.clone();
    let h_tag_confirm_tx = tag_confirm_tx.clone();
    let h_og_tx = og_tx.clone();
    let h_oc_tx = oc_tx.clone();
    let h_ra_tx = ra_tx.clone();
    let h_pay_tx = pay_tx.clone();
    let h_fwd_tx = fwd_tx.clone();
    node.listen_messages_with_response(move |peer, msg| {
        let Some(peer_hash) = peer.node_id().map(|node_id| *node_id.as_bytes()) else {
            return None;
        };
        if ban_ref.is_banished(&peer_hash) {
            return None;
        }

        // Use into_inner() to recover from a poisoned mutex — if another task
        // panicked while holding the lock, we still need to keep processing
        // messages rather than crashing the entire process.
        let mut state = st.lock().unwrap_or_else(|e| e.into_inner());

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

        // ── Handshake messages ──────────────────────────────────────
        match &msg {
            PulseMessage::HandshakeChallenge(hc) => {
                let hmac = compute_handshake_hmac(&PROTOCOL_VERSION_HASH, &hc.nonce);
                // Compute Argon2id PoW over (our node_id, nonce) to prove we invested
                // real resources. This makes Sybil node creation expensive.
                let pow_hash = compute_handshake_pow(&state.node_id, &hc.nonce);
                return Some(PulseMessage::HandshakeResponse(HandshakeResponse {
                    hmac,
                    pow_hash,
                }));
            }
            PulseMessage::HandshakeResponse(hr) => {
                // Read the challenge nonce BEFORE verify_response consumes it.
                let stored_nonce = state.peer_registry.challenge_nonce(&peer_id);
                let valid = state.peer_registry.verify_response(
                    &peer_id,
                    &hr.hmac,
                    &ALLOWED_VERSIONS,
                );
                if !valid {
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
                | PulseMessage::ProgramStore(_)
                | PulseMessage::ProgramManifestStore(_)
                | PulseMessage::ComputeReceiptStore(_)
                | PulseMessage::OwnershipGenesis(_)
                | PulseMessage::OwnershipClaim(_)
                | PulseMessage::ReforgeAttestation(_)
                | PulseMessage::LimboHold(_)  // M3: gate on verified to prevent unbounded HashSet growth
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
                // Rate-limit TagLookup to prevent tag enumeration.
                if !state.tag_lookup_limiter.allow(&peer_id) {
                    warn!(%peer, "tag lookup rate-limited");
                    return Some(PulseMessage::TagLookupResponse(TagLookupResponse {
                        tag_hash: tl.tag_hash,
                        nonce: tl.nonce,
                        result: None,
                    }));
                }
                info!(%peer, "tag lookup");
                let result = state.tag_dht.lookup_by_hash(&tl.tag_hash);
                let lookup_result = result.map(|record| TagLookupResult {
                    scan_ek: record.master_address.scan_ek.clone(),
                    spend_ek: record.master_address.spend_ek.clone(),
                    registered_at: record.registered_at,
                    pow_nonce: record.pow_nonce,
                    pow_hash: record.pow_hash.clone(),
                    registrant_vk: record.registrant_vk.clone(),
                    signature: record.signature.clone(),
                });
                Some(PulseMessage::TagLookupResponse(TagLookupResponse {
                    tag_hash: tl.tag_hash,
                    nonce: tl.nonce,
                    result: lookup_result,
                }))
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
                let _ = h_pay_tx.send(relay_copy.clone());

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
                    ) {
                        Ok(Some(result)) => {
                            let receipt = if let Some(tag_hash) = direct_receipt_tag_hash {
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
                            info!(amount = total, "auto-received payment into wallet");
                            state.push_notification(WalletNotification {
                                kind: "payment_received".to_string(),
                                created_at: now,
                                payment_id: hex_key(&payment_id),
                                amount: Some(total),
                                bill_count: Some(pending_oc.len()),
                                counterparty: None,
                                message: format!("Received {total} Vess and claimed ownership."),
                            });
                            for oc in pending_oc {
                                queue_local_ownership_claim(&mut state, &h_oc_tx, oc);
                            }
                            // Wallet is persisted by the periodic flush task
                            // (every 60s); avoid blocking disk I/O in the
                            // payment-receive hot path. At worst a crash
                            // within the flush window replays the OC from the
                            // gossip log on restart.

                            // Return acknowledgment so direct senders get
                            // instant confirmation. Relay nodes use fire-and-
                            // forget so this response is harmlessly dropped.
                            return Some(PulseMessage::DirectPaymentResponse(
                                vess_protocol::DirectPaymentResponse {
                                    payment_id,
                                    accepted: true,
                                    receipt,
                                    reason: String::new(),
                                },
                            ));
                        }
                        Ok(None) => {} // Not for us — normal relay.
                        Err(e) => {
                            warn!(error = %e, "auto-receive trial-decrypt error");
                        }
                    }
                }

                info!(%peer, "payment entered limbo");
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

            PulseMessage::DhtSeedRequest(req) => {
                if req.requester_node_id != peer_id {
                    warn!(%peer, "DHT seed request node id does not match transport peer");
                    return None;
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
                let max_programs = usize::from(req.max_programs).min(MAX_DHT_SEED_PROGRAMS);
                let max_program_manifests = usize::from(req.max_program_manifests)
                    .min(MAX_DHT_SEED_PROGRAM_MANIFESTS);
                let max_compute_receipts = usize::from(req.max_compute_receipts)
                    .min(MAX_DHT_SEED_COMPUTE_RECEIPTS);

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

                let mut programs = state.compute_dht.all_programs();
                programs.sort_by_key(|(prog_id, _)| *prog_id.as_bytes());
                let programs: Vec<DhtSeedProgramRecord> = programs
                    .into_iter()
                    .filter(|(prog_id, _)| {
                        dht_seed_cursor_allows_key(prog_id.as_bytes(), req.after_program_id)
                    })
                    .filter(|(prog_id, _)| {
                        node_should_store_seeded_key(
                            prog_id.as_bytes(),
                            &req.requester_node_id,
                            &state.node_id,
                            &peer_ids,
                            repl,
                        )
                    })
                    .take(max_programs)
                    .map(|(prog_id, program)| dht_seed_program_from_record(prog_id, program))
                    .collect();

                let mut program_manifests = state.compute_dht.all_manifests();
                program_manifests.sort_by_key(|(dht_key, _)| *dht_key);
                let program_manifests: Vec<DhtSeedProgramManifestRecord> = program_manifests
                    .into_iter()
                    .filter(|(dht_key, _)| {
                        dht_seed_cursor_allows_key(dht_key, req.after_program_manifest_key)
                    })
                    .filter(|(dht_key, _)| {
                        node_should_store_seeded_key(
                            dht_key,
                            &req.requester_node_id,
                            &state.node_id,
                            &peer_ids,
                            repl,
                        )
                    })
                    .take(max_program_manifests)
                    .map(|(dht_key, manifest)| {
                        dht_seed_program_manifest_from_record(dht_key, manifest)
                    })
                    .collect();

                let mut compute_receipts = state.compute_dht.all_receipts();
                compute_receipts.sort_by_key(|(receipt_id, _)| *receipt_id);
                let compute_receipts: Vec<DhtSeedComputeReceiptRecord> = compute_receipts
                    .into_iter()
                    .filter(|(receipt_id, _)| {
                        dht_seed_cursor_allows_key(receipt_id, req.after_compute_receipt_id)
                    })
                    .filter(|(receipt_id, _)| {
                        node_should_store_seeded_key(
                            receipt_id,
                            &req.requester_node_id,
                            &state.node_id,
                            &peer_ids,
                            repl,
                        )
                    })
                    .take(max_compute_receipts)
                    .map(|(receipt_id, receipt)| {
                        dht_seed_compute_receipt_from_record(receipt_id, receipt)
                    })
                    .collect();

                info!(
                    %peer,
                    tags = tags.len(),
                    manifests = manifests.len(),
                    ownership_records = ownership_records.len(),
                    consumed_records = consumed_records.len(),
                    programs = programs.len(),
                    program_manifests = program_manifests.len(),
                    compute_receipts = compute_receipts.len(),
                    "serving DHT seed shard sync"
                );
                Some(PulseMessage::DhtSeedResponse(DhtSeedResponse {
                    responder_node_id: state.node_id,
                    tags,
                    manifests,
                    ownership_records,
                    consumed_records,
                    programs,
                    program_manifests,
                    compute_receipts,
                }))
            }

            PulseMessage::DhtSeedResponse(_) => None,

            PulseMessage::ProgramStore(ps) => {
                let prog_id = ps.program.prog_id();
                let peer_ids: Vec<[u8; 32]> = state.routing_table.routable_peers(|_| true)
                    .iter().map(|p| p.id_hash).collect();
                let repl = dht_replication_factor(state.estimated_network_size);
                if state.registry.should_store(prog_id.as_bytes(), &peer_ids, repl) {
                    let _ = state.compute_dht.store_program(ps.program.clone());
                }
                if ps.hops_remaining > 0 {
                    let mut fwd = ps.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_program_tx.send(fwd);
                }
                None
            }

            PulseMessage::ProgramFetch(ProgramFetch { prog_id }) => {
                Some(PulseMessage::ProgramFetchResponse(ProgramFetchResponse {
                    program: state.compute_dht.fetch_program(prog_id).cloned(),
                }))
            }

            PulseMessage::ProgramFetchResponse(_) => None,

            PulseMessage::ProgramManifestStore(pms) => {
                let dht_key = pms.manifest.dht_key();
                let peer_ids: Vec<[u8; 32]> = state.routing_table.routable_peers(|_| true)
                    .iter().map(|p| p.id_hash).collect();
                let repl = dht_replication_factor(state.estimated_network_size);
                if state.registry.should_store(&dht_key, &peer_ids, repl) {
                    let _ = state.compute_dht.store_manifest(pms.manifest.clone());
                }
                if pms.hops_remaining > 0 {
                    let mut fwd = pms.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_program_manifest_tx.send(fwd);
                }
                None
            }

            PulseMessage::ProgramManifestResolve(ProgramManifestResolve { name }) => {
                Some(PulseMessage::ProgramManifestResolveResponse(
                    ProgramManifestResolveResponse {
                        manifest: state.compute_dht.resolve_manifest(&name).cloned(),
                    },
                ))
            }

            PulseMessage::ProgramManifestResolveResponse(_) => None,

            PulseMessage::ComputeJobRequest(req) => Some(PulseMessage::ComputeJobResult(
                vess_protocol::ComputeJobResult {
                    job_id: req.job_id,
                    accepted: false,
                    output_bytes: Vec::new(),
                    receipt: None,
                    error: Some(
                        "remote compute jobs are not supported; program interaction is self-submitted via ownership-claim witnesses"
                            .to_string(),
                    ),
                },
            )),

            PulseMessage::ComputeJobResult(_) => None,

            PulseMessage::ComputeReceiptStore(crs) => {
                let peer_ids: Vec<[u8; 32]> = state.routing_table.routable_peers(|_| true)
                    .iter().map(|p| p.id_hash).collect();
                let repl = dht_replication_factor(state.estimated_network_size);
                if state.registry.should_store(&crs.receipt.receipt_id, &peer_ids, repl) {
                    if state.compute_dht.store_receipt(crs.receipt.clone()).is_ok() {
                        mirror_compute_receipt_text(&receipt_text_state_dir, &crs.receipt);
                    }
                }
                if crs.hops_remaining > 0 {
                    let mut fwd = crs.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_compute_receipt_tx.send(fwd);
                }
                None
            }

            PulseMessage::ComputeReceiptFetch(ComputeReceiptFetch { receipt_id }) => {
                Some(PulseMessage::ComputeReceiptFetchResponse(
                    ComputeReceiptFetchResponse {
                        receipt: state.compute_dht.fetch_receipt(&receipt_id).cloned(),
                    },
                ))
            }

            PulseMessage::ComputeReceiptFetchResponse(_) => None,

            PulseMessage::ProgramReceiptList(ProgramReceiptList { prog_id }) => {
                Some(PulseMessage::ProgramReceiptListResponse(
                    ProgramReceiptListResponse {
                        receipt_ids: state.compute_dht.receipts_for_program(prog_id),
                    },
                ))
            }

            PulseMessage::ProgramReceiptListResponse(_) => None,

            PulseMessage::FindNode(fn_req) => {
                // Kademlia FIND_NODE: return K-closest peers to the target.
                let closest = state.routing_table.closest_peers(&fn_req.target, crate::kademlia::K_BUCKET_SIZE);
                let peers: Vec<Vec<u8>> = closest.into_iter()
                    .filter(|p| !p.id_bytes.is_empty() && p.id_bytes.len() <= MAX_SERIALIZED_MESH_CONTACT_BYTES)
                    .take(MAX_PEER_EXCHANGE_PEERS)
                    .map(|p| p.id_bytes)
                    .collect();
                Some(PulseMessage::FindNodeResponse(FindNodeResponse { peers }))
            }

            PulseMessage::RegistryQuery(rq) => {
                if !state.registry_query_limiter.allow(&peer_id) {
                    warn!(%peer, "registry query rate limited");
                    return None;
                }
                if rq.mint_ids.len() > MAX_QUERY_MINT_IDS {
                    warn!(%peer, count = rq.mint_ids.len(), "registry query exceeds max — banishing");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }
                info!(%peer, count = rq.mint_ids.len(), "registry query");
                let active: Vec<bool> = rq.mint_ids.iter()
                    .map(|id| state.registry.is_active(id))
                    .collect();
                Some(PulseMessage::RegistryQueryResponse(RegistryQueryResponse { active }))
            }

            PulseMessage::RegistryQueryResponse(_) => None,

            PulseMessage::LimboHold(lh) => {
                if lh.bill_ids.len() > MAX_LIMBO_HOLD_IDS {
                    warn!(%peer, count = lh.bill_ids.len(), "limbo hold exceeds max — ignoring");
                    return None;
                }
                info!(%peer, count = lh.bill_ids.len(), "limbo hold received");
                for mid in &lh.bill_ids {
                    state.limbo_mint_ids.insert(*mid);
                }
                None
            }

            PulseMessage::LimboNotify(ln) => {
                info!(%peer, stealth_id = hex_key(&ln.stealth_id), count = ln.count, "limbo notify");
                None
            }

            PulseMessage::LimboDeliver(ld) => {
                info!(%peer, "limbo deliver");
                let p = &ld.payment;

                // Apply the same validation as the Payment handler.
                if !timestamp_is_valid(p.created_at) {
                    warn!("limbo deliver rejected: timestamp out of range");
                    return None;
                }

                // Reject duplicate payment_id.
                if state.limbo_payment_ids.contains(&p.payment_id) {
                    warn!("limbo deliver rejected: duplicate payment_id");
                    return None;
                }

                // Registry-only model: no inline STARK verification.

                let stealth_id = p.stealth_id;
                let payment_id = p.payment_id;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mailbox_key = p.mailbox_key;
                let deliver_payment = ld.payment;

                if !state.limbo_buffer.hold(stealth_id, deliver_payment.clone(), Vec::new(), now, peer_id, mailbox_key) {
                    warn!(%peer, "limbo deliver rejected: buffer at capacity");
                    return None;
                }

                // Track AFTER successful hold.
                state.limbo_payment_ids.insert(payment_id);

                // Push to any active forwarding subscriber for this mailbox_key.
                if let Some(ref key) = mailbox_key {
                    if let Some(record) = state.mailbox_fwd.get(key) {
                        if record.expires_at > now {
                            let _ = h_fwd_tx.send((record.target_id_bytes.clone(), deliver_payment.clone()));
                        }
                    }
                }

                // Auto-receive trial-decrypt for LimboDeliver too.
                let maybe_payload = state.limbo_buffer.peek(&stealth_id)
                    .last()
                    .map(|e| e.payment.stealth_payload.clone());
                if let (Some(payload), Some(ref mut ws)) = (maybe_payload, &mut state.wallet) {
                    match receive_and_claim(
                        &ws.stealth_secret,
                        &payload,
                    ) {
                        Ok(Some(result)) => {
                            let mut total = 0u64;
                            let mut pending_oc = Vec::new();
                            for claimed in result.claimed {
                                total += claimed.bill.denomination.value();
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
                                    pending_oc.push(oc);
                                }
                            }
                            info!(amount = total, "auto-received limbo-deliver payment");
                            for oc in pending_oc {
                                queue_local_ownership_claim(&mut state, &h_oc_tx, oc);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(error = %e, "auto-receive limbo-deliver error");
                        }
                    }
                }

                None
            }



            PulseMessage::ManifestStore(ms) => {
                // Reject oversized manifests to prevent bandwidth/storage DoS.
                if ms.encrypted_manifest.len() > MAX_MANIFEST_SIZE {
                    warn!(%peer, size = ms.encrypted_manifest.len(), "manifest exceeds max size — rejecting");
                    return None;
                }
                // Store encrypted manifest if we're among the K-closest.
                let peer_ids: Vec<[u8; 32]> = state.routing_table.routable_peers(|_| true)
                    .iter().map(|p| p.id_hash).collect();
                let repl = dht_replication_factor(state.estimated_network_size);
                if state.registry.should_store(&ms.dht_key, &peer_ids, repl) {
                    // M3: Evict the entry with the oldest insertion timestamp so
                    // long-held manifests are dropped first (not an arbitrary key).
                    if state.manifest_store.len() >= MAX_MANIFEST_ENTRIES {
                        if let Some(&oldest_key) = state
                            .manifest_store
                            .iter()
                            .min_by_key(|(_, (_, ts))| ts)
                            .map(|(k, _)| k)
                        {
                            state.manifest_store.remove(&oldest_key);
                        }
                    }
                    state.manifest_store.insert(ms.dht_key, (ms.encrypted_manifest.clone(), now_ts));
                    info!("manifest stored in DHT");
                }
                if ms.hops_remaining > 0 {
                    let mut fwd = ms.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_manifest_tx.send(fwd);
                }
                None
            }

            PulseMessage::ManifestRecover(mr) => {
                if let Some((data, _)) = state.manifest_store.get(&mr.dht_key) {
                    info!("ManifestRecover: returning manifest");
                    Some(PulseMessage::ManifestRecoverResponse(ManifestRecoverResponse {
                        dht_key: mr.dht_key,
                        encrypted_manifest: data.clone(),
                        found: true,
                    }))
                } else {
                    Some(PulseMessage::ManifestRecoverResponse(ManifestRecoverResponse {
                        dht_key: mr.dht_key,
                        encrypted_manifest: Vec::new(),
                        found: false,
                    }))
                }
            }

            PulseMessage::ManifestRecoverResponse(_) => None,

            PulseMessage::OwnershipFetch(of) => {
                if !state.registry_query_limiter.allow(&peer_id) {
                    warn!(%peer, "ownership fetch rate limited");
                    return None;
                }
                if of.mint_ids.len() > MAX_QUERY_MINT_IDS {
                    warn!(%peer, count = of.mint_ids.len(), "ownership fetch exceeds max — banishing");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }
                let records: Vec<FetchedRecord> = of.mint_ids.iter().map(|mint_id| {
                    if let Some(rec) = state.registry.get(mint_id) {
                        FetchedRecord {
                            mint_id: *mint_id,
                            found: true,
                            denomination_value: rec.denomination_value,
                            chain_tip: rec.chain_tip,
                            digest: rec.digest,
                        }
                    } else {
                        FetchedRecord {
                            mint_id: *mint_id,
                            found: false,
                            denomination_value: 0,
                            chain_tip: [0u8; 32],
                            digest: [0u8; 32],
                        }
                    }
                }).collect();
                Some(PulseMessage::OwnershipFetchResponse(OwnershipFetchResponse { records }))
            }

            PulseMessage::OwnershipFetchResponse(_) => None,


            PulseMessage::TagStore(ts) => {
                let dht_key = ts.tag_hash;
                let peer_ids: Vec<[u8; 32]> = state.routing_table.routable_peers(|_| true)
                    .iter().map(|p| p.id_hash).collect();

                // Reject relay if tag or address is already registered locally.
                let addr = vess_stealth::MasterStealthAddress {
                    scan_ek: ts.scan_ek.clone(),
                    spend_ek: ts.spend_ek.clone(),
                };
                let addr_fp = vess_tag::address_fingerprint(&addr);
                if state.tag_dht.lookup_by_hash(&dht_key).is_some() {
                    // Tag already stored — skip.
                    if ts.hops_remaining > 0 {
                        let mut fwd = ts.clone();
                        fwd.hops_remaining -= 1;
                        let _ = h_tag_store_tx.send(fwd);
                    }
                    return None;
                }
                if state.tag_dht.has_address(&addr_fp) {
                    warn!("TagStore: address already has a tag — rejecting relay");
                    return None;
                }

                if state.tag_dht.should_store(&dht_key, &peer_ids) {
                    let record = vess_tag::TagRecord {
                        tag_hash: dht_key,
                        master_address: addr,
                        pow_nonce: ts.pow_nonce,
                        pow_hash: ts.pow_hash.clone(),
                        registered_at: ts.registered_at,
                        registrant_vk: ts.registrant_vk.clone(),
                        signature: ts.signature.clone(),
                        hardened_at: None, // starts unhardened from gossip
                    };
                    // All replicated tags MUST carry a valid registrant signature.
                    if record.registrant_vk.is_empty() || record.signature.is_empty() {
                        warn!("TagStore: unsigned tag — rejecting and banishing");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    match vess_tag::verify_record_signature(&record) {
                        Ok(true) => {}
                        _ => {
                            warn!("TagStore: invalid signature on replicated tag — banishing peer");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                    if state.tag_dht.store(record) {
                        info!("tag replicated via TagStore gossip");
                    }
                }
                if ts.hops_remaining > 0 {
                    let mut fwd = ts.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_tag_store_tx.send(fwd);
                }
                None
            }

            PulseMessage::TagConfirm(tc) => {
                info!(%peer, "tag confirm (harden) for hash {:?}", &tc.tag_hash[..4]);

                let tag_hash = tc.tag_hash;

                // 2. The tag must exist and be unhardened.
                let record = match state.tag_dht.lookup_by_hash(&tag_hash) {
                    Some(r) => r.clone(),
                    None => {
                        // We don't have this tag — relay if hops remain.
                        if tc.hops_remaining > 0 {
                            let mut fwd = tc.clone();
                            fwd.hops_remaining -= 1;
                            let _ = h_tag_confirm_tx.send(fwd);
                        }
                        return None;
                    }
                };

                if record.hardened_at.is_some() {
                    // Already hardened — just relay.
                    if tc.hops_remaining > 0 {
                        let mut fwd = tc.clone();
                        fwd.hops_remaining -= 1;
                        let _ = h_tag_confirm_tx.send(fwd);
                    }
                    return None;
                }

                // 3. Verify the signature matches the record's registrant_vk.
                if tc.registrant_vk != record.registrant_vk {
                    warn!("TagConfirm: registrant_vk mismatch — banishing peer");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }
                if tc.registrant_vk.is_empty() || tc.signature.is_empty() {
                    warn!("TagConfirm: missing vk or signature — banishing peer");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }
                let confirm_digest = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"vess-tag-confirm-v1");
                    h.update(&tag_hash);
                    h.update(&tc.mint_id);
                    *h.finalize().as_bytes()
                };
                match vess_foundry::spend_auth::verify_spend(
                    &tc.registrant_vk,
                    &confirm_digest,
                    &tc.signature,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!("TagConfirm: invalid signature — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    Err(e) => {
                        warn!("TagConfirm: signature error: {e} — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                }

                // 4. Check that the mint_id is active in the registry AND that
                //    the registrant_vk is the current owner of that bill.
                //    Without the ownership check, anyone can harden any tag
                //    using an arbitrary active bill observed from the network.
                if !state.registry.is_active(&tc.mint_id) {
                    warn!("TagConfirm: mint_id not active in registry");
                    return None;
                }
                if let Some(rec) = state.registry.get(&tc.mint_id) {
                    let confirmor_vk_hash = vess_foundry::spend_auth::vk_hash(&tc.registrant_vk);
                    if rec.current_owner_vk_hash != confirmor_vk_hash {
                        warn!("TagConfirm: registrant_vk is not the current bill owner — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                }

                // 5. Harden the tag.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if state.tag_dht.harden_by_hash(&tag_hash, &tc.mint_id, now) {
                    info!("tag hardened successfully for hash {:?}", &tag_hash[..4]);
                } else {
                    warn!("TagConfirm: harden failed (bill_id reuse or already hardened)");
                }

                // 6. Relay to peers.
                if tc.hops_remaining > 0 {
                    let mut fwd = tc.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_tag_confirm_tx.send(fwd);
                }
                None
            }

            PulseMessage::OwnershipGenesis(og) => {
                info!(%peer, "ownership genesis for mint_id {:?}", &og.mint_id[..4]);

                // 0b. Reject genesis for a bill that was already consumed via reforge.
                //     Without this check, a replayed OwnershipGenesis for a spent bill
                //     would re-register it as active, polluting the registry.
                if state.registry.was_consumed(&og.mint_id).is_some() {
                    warn!("ownership genesis: mint_id {:?} is already consumed (tombstone exists) — ignoring", &og.mint_id[..4]);
                    return None;
                }

                // 1. Check if already registered (idempotent).
                if state.registry.is_active(&og.mint_id) {
                    if og.hops_remaining > 0 {
                        let mut fwd = og.clone();
                        fwd.hops_remaining -= 1;
                        let _ = h_og_tx.send(fwd);
                    }
                    return None;
                }

                // 2. Verify proof — supports STARK, aggregate, and reforge proofs.
                //    Native Vess proof bytes cover STARK, aggregate, sampled aggregate,
                //    and reforge outputs. Bitcoin burns use a shared bundle proof where
                //    every output bill commits to one indexed slice of the burned amount.
                let proof_nonce: [u8; 32];
                let proof_hash: [u8; 32];
                // Set to true when the ReforgeProof branch already verified mint_id
                // (uses different derivation formula from minted bills).
                let mut mint_id_pre_verified = false;
                match &og.genesis_proof {
                    GenesisProof::Vess(proof_bytes) => {
                        // Reject oversized native proofs before any deserialization attempt.
                        const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
                        if proof_bytes.len() > MAX_PROOF_BYTES {
                            warn!(
                                "ownership genesis: proof exceeds size limit ({} bytes) — banishing peer",
                                proof_bytes.len()
                            );
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                        proof_hash = blake3::hash(proof_bytes).into();

                        if let Ok(iop_proof) = vess_foundry::proof::deserialize_proof(proof_bytes) {
                            // ── Single STARK path ──
                            if let Err(e) = vess_foundry::proof::verify_proof(&iop_proof, &og.digest) {
                                warn!("ownership genesis: STARK verification failed: {e:?} — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            if iop_proof.owner_vk_hash != og.owner_vk_hash {
                                warn!("ownership genesis: proof owner_vk_hash mismatch — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            if iop_proof.denomination.value() != og.denomination_value {
                                warn!(
                                    "ownership genesis: denomination mismatch (proof={}, claimed={}) — banishing peer",
                                    iop_proof.denomination.value(),
                                    og.denomination_value
                                );
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            let required_diff = vess_foundry::mint::difficulty_bits_for(iop_proof.denomination);
                            if !vess_foundry::mint::meets_difficulty_pub(&og.digest, required_diff) {
                                warn!("ownership genesis: digest does not meet difficulty ({required_diff} bits) — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            proof_nonce = iop_proof.nonce;
                        } else if let Ok(agg) = vess_foundry::proof::AggregateProof::deserialize(proof_bytes) {
                            // ── Aggregate proof path ──
                            if let Err(e) = vess_foundry::proof::verify_aggregate_proof(&agg, &og.digest, og.denomination_value) {
                                warn!("ownership genesis: aggregate verification failed: {e:?} — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            if agg.owner_vk_hash != og.owner_vk_hash {
                                warn!("ownership genesis: aggregate owner_vk_hash mismatch — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            let mut h = blake3::Hasher::new();
                            h.update(b"vess-aggregate-nonce-v0");
                            for sub in &agg.d1_proofs {
                                if let Ok(p) = vess_foundry::proof::deserialize_proof(sub) {
                                    h.update(&p.nonce);
                                }
                            }
                            proof_nonce = *h.finalize().as_bytes();
                        } else if let Ok(sap) = vess_foundry::proof::SampledAggregateProof::deserialize(proof_bytes) {
                            // ── Sampled aggregate proof path (>80 solves) ──
                            if let Err(e) = vess_foundry::proof::verify_sampled_aggregate(&sap, &og.digest, og.denomination_value) {
                                warn!("ownership genesis: sampled aggregate verification failed: {e:?} — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            if sap.owner_vk_hash != og.owner_vk_hash {
                                warn!("ownership genesis: sampled aggregate owner_vk_hash mismatch — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            proof_nonce = sap.nonce_tree_root;
                        } else if let Ok(rp) = vess_foundry::reforge::deserialize_reforge_proof(proof_bytes) {
                            // ── Reforge output genesis (split / combine) ──────────────────
                            let re_serialized = vess_foundry::reforge::serialize_reforge_proof(&rp);
                            let compound_digest: [u8; 32] = {
                                let mut h = blake3::Hasher::new();
                                h.update(b"vess-reforge-digest-v0");
                                h.update(&re_serialized);
                                *h.finalize().as_bytes()
                            };
                            if compound_digest != og.digest {
                                warn!("ownership genesis: reforge compound_digest mismatch — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }

                            let input_sum: u64 = rp.input_denominations.iter().map(|d| d.value()).sum();
                            let output_sum: u64 = rp.output_denominations.iter().map(|d| d.value()).sum();
                            if input_sum != output_sum {
                                warn!("ownership genesis: reforge value not conserved (in={input_sum}, out={output_sum}) — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }

                            let output_index = og.output_index as usize;
                            if output_index >= rp.output_denominations.len() {
                                warn!("ownership genesis: output_index {output_index} out of bounds — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }
                            if rp.output_denominations[output_index].value() != og.denomination_value {
                                warn!("ownership genesis: reforge denomination mismatch at index {output_index} — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }

                            let expected_mint_id = vess_foundry::reforge::reforge_mint_id(&compound_digest, output_index);
                            if expected_mint_id != og.mint_id {
                                warn!("ownership genesis: reforge mint_id derivation mismatch — banishing peer");
                                state.peer_registry.mark_banished(peer_id);
                                ban_ref.banish(peer_id);
                                return None;
                            }

                            for (idx, input_mint_id) in rp.input_mint_ids.iter().enumerate() {
                                if state.registry.is_active(input_mint_id) {
                                    warn!(
                                        "ownership genesis: reforge input {:?} still active — \
                                         dropping (ReforgeAttestation may not have arrived yet)",
                                        &input_mint_id[..4]
                                    );
                                    return None;
                                }
                                let tombstone = match state.registry.was_consumed(input_mint_id) {
                                    Some(t) => t,
                                    None => {
                                        const MAX_PENDING_GENESIS_PER_KEY: usize = 200;
                                        let global_total: usize = state
                                            .pending_reforge_genesis
                                            .values()
                                            .map(|v| v.len())
                                            .sum();
                                        if global_total < MAX_PENDING_GENESIS_TOTAL {
                                            let pending = state.pending_reforge_genesis
                                                .entry(*input_mint_id)
                                                .or_default();
                                            if pending.len() < MAX_PENDING_GENESIS_PER_KEY {
                                                pending.push((og.clone(), now_ts));
                                            }
                                        }
                                        return None;
                                    }
                                };
                                if tombstone.denomination_value != 0 {
                                    if let Some(claimed_denom) = rp.input_denominations.get(idx) {
                                        if claimed_denom.value() != tombstone.denomination_value {
                                            warn!(
                                                "ownership genesis: reforge input {:?} denomination \
                                                 mismatch (claimed={}, stored={}) — inflation attack — \
                                                 banishing peer",
                                                &input_mint_id[..4],
                                                claimed_denom.value(),
                                                tombstone.denomination_value
                                            );
                                            state.peer_registry.mark_banished(peer_id);
                                            ban_ref.banish(peer_id);
                                            return None;
                                        }
                                    }
                                }
                                let zero = [0u8; 32];
                                if tombstone.digest != zero {
                                    if let Some(claimed_digest) = rp.input_digests.get(idx) {
                                        if claimed_digest != &tombstone.digest {
                                            warn!(
                                                "ownership genesis: reforge input {:?} digest mismatch — \
                                                 banishing peer",
                                                &input_mint_id[..4]
                                            );
                                            state.peer_registry.mark_banished(peer_id);
                                            ban_ref.banish(peer_id);
                                            return None;
                                        }
                                    }
                                }
                            }

                            proof_nonce = compound_digest;
                            mint_id_pre_verified = true;
                        } else {
                            warn!("ownership genesis: malformed proof (neither STARK nor aggregate) — banishing peer");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                    GenesisProof::BitcoinBurn(burn) => match validate_bitcoin_burn_genesis(&og, burn) {
                        Ok(bundle_commitment) => {
                            proof_nonce = bundle_commitment;
                            proof_hash = bundle_commitment;
                            mint_id_pre_verified = true;
                        }
                        Err(reason) => {
                            warn!("ownership genesis: {reason} — banishing peer");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    },
                    GenesisProof::LocalTestFaucet(proof) => {
                        if !local_test_faucet_enabled() {
                            warn!(
                                "ownership genesis: local test faucet proof ignored because {LOCAL_TEST_FAUCET_ENV}=1 is not set"
                            );
                            return None;
                        }
                        if vess_foundry::Denomination::from_value(og.denomination_value).is_none() {
                            warn!("ownership genesis: invalid local test faucet denomination — banishing peer");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                        let expected_digest = local_test_faucet_digest(
                            &proof.nonce,
                            og.denomination_value,
                            &og.owner_vk_hash,
                        );
                        if expected_digest != og.digest {
                            warn!("ownership genesis: local test faucet digest mismatch — banishing peer");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                        let mut h = blake3::Hasher::new();
                        h.update(b"vess-local-test-faucet-proof-v0");
                        h.update(&proof.nonce);
                        proof_hash = *h.finalize().as_bytes();
                        proof_nonce = proof.nonce;
                    }
                }

                // 3. Verify owner_vk_hash matches the claimed verification key.
                let owner_commitment = ownership_genesis_owner_commitment(&og);
                if owner_commitment != og.owner_vk_hash {
                    warn!("ownership genesis: owner commitment mismatch — banishing peer");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }

                // 4. Verify mint_id derivation (skipped for reforge outputs — already verified above).
                if !mint_id_pre_verified {
                    let expected_mint_id = vess_foundry::derive_mint_id(&og.digest, &proof_nonce);
                    if expected_mint_id != og.mint_id {
                        warn!("ownership genesis: mint_id derivation mismatch — banishing peer");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                }

                // 5. Verify genesis chain_tip.
                let expected_tip =
                    vess_foundry::genesis_chain_tip_with_commitment(&og.mint_id, &owner_commitment);
                if expected_tip != og.chain_tip {
                    warn!("ownership genesis: chain_tip mismatch — banishing peer");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }

                // 6. Store locally only if this node is among the K-closest to mint_id.
                let peer_ids: Vec<[u8; 32]> = state.routing_table.routable_peers(|_| true)
                    .iter().map(|p| p.id_hash).collect();
                let repl = dht_replication_factor(state.estimated_network_size);
                if state.registry.should_store(&og.mint_id, &peer_ids, repl) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    state.registry.register(OwnershipRecord {
                        mint_id: og.mint_id,
                        chain_tip: og.chain_tip,
                        prev_transfer_chain_tip: None,
                        current_owner_vk_hash: og.owner_vk_hash,
                        current_owner_vk: og.owner_vk.clone(),
                        current_owner_program: og.program_owner.clone(),
                        denomination_value: og.denomination_value,
                        updated_at: now,
                        proof_hash,
                        digest: og.digest,
                        nonce: proof_nonce,
                        prev_claim_vk_hash: None,
                        claim_hash: None,
                        chain_depth: 0,
                        encrypted_bill: vec![],
                    });
                    info!("ownership genesis stored for mint_id {:?}", &og.mint_id[..4]);
                }
                if let Some(program_owner) = &og.program_owner {
                    note_program_bill_activity(
                        &mut state,
                        program_owner.controller.prog_id,
                        now_ts,
                    );
                }

                // 7. Forward to K-nearest peers if hops remain.
                if og.hops_remaining > 0 {
                    let mut fwd = og.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_og_tx.send(fwd);
                }
                None
            }

            PulseMessage::OwnershipClaim(oc) => {
                info!(%peer, "ownership claim for mint_id {:?}", &oc.mint_id[..4]);

                // 0. Reforge-wins rule (highest priority):
                //    If this bill was consumed by a valid split/combine, no
                //    subsequent OwnershipClaim is valid — the value literally
                //    no longer exists at this mint_id.
                //
                //    We don't banish the peer because they may not have
                //    received the ReforgeAttestation yet.
                if let Some(tombstone) = state.registry.was_consumed(&oc.mint_id) {
                    warn!(
                        "ownership claim rejected: mint_id {:?} was consumed via \
                         reforge {:?} (outputs: {})",
                        &oc.mint_id[..4],
                        &tombstone.reforge_id[..4],
                        tombstone.output_mint_ids.len(),
                    );
                    return None;
                }

                // 1. Look up existing ownership record.
                // If we don't have this mint_id locally (it lives on another
                // DHT node), we still validate and forward.
                let record_opt = state.registry.get(&oc.mint_id).cloned();

                let Some(prev_owner_commitment) = ownership_claim_prev_owner_commitment(&oc) else {
                    warn!("ownership claim: missing previous owner authorization path — banishing");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                };
                let Some(new_owner_commitment) = ownership_claim_new_owner_commitment(&oc) else {
                    warn!("ownership claim: missing new owner authorization path — banishing");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                };
                if new_owner_commitment != oc.new_owner_vk_hash {
                    warn!("ownership claim: new owner commitment mismatch — banishing");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }

                if let Some(ref record) = record_opt {
                    if prev_owner_commitment != record.current_owner_vk_hash
                        && record.prev_claim_vk_hash != Some(prev_owner_commitment)
                    {
                        warn!("ownership claim: previous owner commitment doesn't match current or previous owner — banishing");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    if let Some(program_owner) = &record.current_owner_program {
                        if prev_owner_commitment == record.current_owner_vk_hash
                            && oc.prev_owner_program.as_ref() != Some(program_owner)
                        {
                            warn!("ownership claim: previous program owner mismatch — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                }

                let witness_hash = if let Some(witness) = &oc.program_spend_witness {
                    let Some(prev_program) = oc.prev_owner_program.as_ref() else {
                        warn!("ownership claim: program witness missing prev_owner_program — banishing");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    };
                    if witness.receipt.prog_id != prev_program.controller.prog_id {
                        warn!("ownership claim: program witness receipt targets wrong program — banishing");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    if !witness.authorized_mint_ids.contains(&oc.mint_id) {
                        warn!("ownership claim: program witness does not authorize mint_id — banishing");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    if witness.next_owner_commitment != oc.new_owner_vk_hash {
                        warn!("ownership claim: program witness next owner mismatch — banishing");
                        state.peer_registry.mark_banished(peer_id);
                        ban_ref.banish(peer_id);
                        return None;
                    }
                    if let Some(proof) = &witness.receipt.proof {
                        if proof.proof_hash() != witness.receipt.proof_hash {
                            warn!("ownership claim: program witness proof hash mismatch — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                    if let Some(program) = state.compute_dht.fetch_program(witness.receipt.prog_id) {
                        if let Err(error) = witness.validates_condition(prev_program, &program.definition)
                        {
                            warn!(error = %error, "ownership claim: invalid program witness — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                    witness.witness_hash()
                } else {
                    let transfer_msg = vess_foundry::spend_auth::transfer_message(
                        &oc.mint_id,
                        &oc.stealth_id,
                        oc.timestamp,
                    );
                    match vess_foundry::spend_auth::verify_spend(
                        &oc.prev_owner_vk,
                        &transfer_msg,
                        &oc.transfer_sig,
                    ) {
                        Ok(true) => *blake3::hash(&oc.transfer_sig).as_bytes(),
                        Ok(false) => {
                            warn!("ownership claim: invalid transfer signature — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                        Err(e) => {
                            warn!("ownership claim: signature error: {e} — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                };

                // 5. Verify the claimed new_chain_tip (only if we hold the record
                //    AND the claim is from the current owner — skip for competing
                //    claims where the record was already updated by a rival).
                if let Some(ref record) = record_opt {
                    if prev_owner_commitment == record.current_owner_vk_hash {
                        let expected_tip = vess_foundry::advance_chain_tip_with_hash(
                            &record.chain_tip,
                            &oc.new_owner_vk_hash,
                            &witness_hash,
                        );
                        if expected_tip != oc.new_chain_tip {
                            warn!("ownership claim: chain_tip mismatch — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                    // For competing claims (prev_owner_commitment == prev_claim_vk_hash),
                    // chain_tip verification is deferred to conflict resolution.
                }

                // 6. Timestamp skip for OwnershipClaim.
                //
                // The 5-minute staleness check is intentionally OMITTED here.
                // The limbo buffer holds payments for up to 3600 s; recipients
                // who are offline longer than 5 minutes would lose payments
                // permanently if we enforced MAX_MESSAGE_AGE_SECS. The
                // transfer_sig already cryptographically binds the timestamp,
                // so there is no replay risk in accepting older claims.

                // 7. Update ownership registry if stored locally.
                //    Deterministic conflict resolution:
                //    - Deeper chain_depth always wins (longest chain).
                //    - At equal depth, lowest claim_hash wins.
                //    All K replicas converge on the same winner independently.
                if record_opt.is_some() {
                    let claim_hash = ownership_claim_hash(&oc);

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if let Some(rec) = state.registry.get_mut(&oc.mint_id) {
                        // Validate chain_depth: must be exactly one more than the
                        // current record. This prevents depth-inflation attacks where
                        // an attacker claims an arbitrary depth to override legitimate
                        // transfers.
                        if oc.chain_depth != rec.chain_depth + 1 {
                            // Exception: competing claim at the same depth is allowed
                            // (two recipients of a double-spend racing for the same slot).
                            if oc.chain_depth != rec.chain_depth
                                || prev_owner_commitment == rec.current_owner_vk_hash
                            {
                                warn!("ownership claim: chain_depth {} is not current+1 ({}) — rejecting",
                                      oc.chain_depth, rec.chain_depth);
                                return None;
                            }
                        }

                        if oc.chain_depth == rec.chain_depth + 1 {
                            // Normal transfer: depth is exactly current + 1.
                            let previous_chain_tip = rec.chain_tip;
                            rec.prev_claim_vk_hash = Some(prev_owner_commitment);
                            rec.claim_hash = Some(claim_hash);
                            rec.prev_transfer_chain_tip = Some(previous_chain_tip);
                            rec.chain_depth = oc.chain_depth;
                            rec.chain_tip = oc.new_chain_tip;
                            rec.current_owner_vk_hash = oc.new_owner_vk_hash;
                            rec.current_owner_vk = oc.new_owner_vk.clone();
                            rec.current_owner_program = oc.new_owner_program.clone();
                            rec.updated_at = now;
                            rec.encrypted_bill = oc.encrypted_bill.clone();
                            info!("ownership transferred (depth {}) for mint_id {:?}", oc.chain_depth, &oc.mint_id[..4]);

                            // Record payment latency if this bill came through limbo.
                            if let Some(entry_ms) = state.limbo_entry_times.remove(&oc.mint_id) {
                                let now_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64;
                                let latency = now_ms.saturating_sub(entry_ms);
                                state.payment_latency.record(latency);
                            }
                            // Clear limbo state for this mint_id.
                            state.limbo_mint_ids.remove(&oc.mint_id);

                            // If this mint_id is in our billfold and reserved,
                            // the recipient has claimed it — permanently remove it.
                            if let Some(ref mut ws) = state.wallet {
                                if ws.billfold.is_reserved(&oc.mint_id) {
                                    ws.billfold.withdraw(&oc.mint_id);
                                    ws.billfold.release(&[oc.mint_id]);
                                    info!("bill permanently withdrawn after claim: {:?}", &oc.mint_id[..4]);
                                }
                            }
                            state.finalize_outbound_mint_if_complete(&oc.mint_id);
                            if let Some(new_owner_program) = &oc.new_owner_program {
                                note_program_bill_activity(
                                    &mut state,
                                    new_owner_program.controller.prog_id,
                                    oc.timestamp,
                                );
                            }
                        } else if oc.chain_depth == rec.chain_depth {
                            // Same depth — check if this is a competing claim
                            // for the same transfer slot.
                            if prev_owner_commitment != rec.current_owner_vk_hash {
                                // Competing claim at same depth — lowest hash wins.
                                if rec.prev_claim_vk_hash == Some(prev_owner_commitment) {
                                    let Some(base_chain_tip) = rec.prev_transfer_chain_tip else {
                                        warn!("ownership claim: competing claim missing pre-transfer base tip — rejecting");
                                        return None;
                                    };
                                    if !verify_competing_claim_chain_tip(base_chain_tip, &oc, witness_hash) {
                                        warn!("ownership claim: competing claim chain_tip mismatch — banishing");
                                        state.peer_registry.mark_banished(peer_id);
                                        ban_ref.banish(peer_id);
                                        return None;
                                    }
                                    if let Some(existing_hash) = rec.claim_hash {
                                        if claim_hash < existing_hash {
                                            rec.chain_tip = oc.new_chain_tip;
                                            rec.current_owner_vk_hash = oc.new_owner_vk_hash;
                                            rec.current_owner_vk = oc.new_owner_vk.clone();
                                            rec.current_owner_program = oc.new_owner_program.clone();
                                            rec.updated_at = now;
                                            rec.claim_hash = Some(claim_hash);
                                            rec.prev_transfer_chain_tip = Some(base_chain_tip);
                                            rec.encrypted_bill = oc.encrypted_bill.clone();
                                            if let Some(new_owner_program) = &oc.new_owner_program {
                                                note_program_bill_activity(
                                                    &mut state,
                                                    new_owner_program.controller.prog_id,
                                                    oc.timestamp,
                                                );
                                            }
                                            info!("ownership conflict at depth {} resolved (lower hash wins) for mint_id {:?}", oc.chain_depth, &oc.mint_id[..4]);
                                        } else {
                                            info!("ownership conflict at depth {}: existing claim has lower hash for mint_id {:?}", oc.chain_depth, &oc.mint_id[..4]);
                                        }
                                    }
                                }
                            } else {
                                // Same depth, prev_owner matches current owner.
                                // This shouldn't happen — if prev_owner == current_owner
                                // then chain_depth should be current+1, not current.
                                // Reject to prevent confusion.
                                warn!("ownership claim: same depth with matching prev_owner — rejecting");
                            }
                        }
                    }
                }

                // 8. Forward to K-nearest peers if hops remain.
                if oc.hops_remaining > 0 {
                    let mut fwd = oc.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_oc_tx.send(fwd);
                }
                None
            }

            PulseMessage::ReforgeAttestation(ra) => {
                info!(%peer, "reforge attestation for {} consumed mint_ids", ra.consumed_mint_ids.len());

                // 1. Basic sanity checks.
                if ra.consumed_mint_ids.is_empty() {
                    warn!("reforge attestation: empty consumed list — ignoring");
                    return None;
                }
                if ra.consume_sigs.len() != ra.consumed_mint_ids.len() {
                    warn!("reforge attestation: sig count mismatch — banishing");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }

                // 2. Verify reforge_id derivation.
                let mut sorted_ids = ra.consumed_mint_ids.clone();
                sorted_ids.sort();
                let expected_reforge_id = {
                    let mut h = blake3::Hasher::new();
                    h.update(b"vess-reforge-id-v0");
                    for id in &sorted_ids {
                        h.update(id);
                    }
                    *h.finalize().as_bytes()
                };
                if expected_reforge_id != ra.reforge_id {
                    warn!("reforge attestation: reforge_id mismatch — banishing");
                    state.peer_registry.mark_banished(peer_id);
                    ban_ref.banish(peer_id);
                    return None;
                }

                // 3. Verify owner_vk_hash matches each consumed record
                //    and verify each consume signature.
                let owner_vk_hash = vess_foundry::spend_auth::vk_hash(&ra.owner_vk);
                for (i, mint_id) in ra.consumed_mint_ids.iter().enumerate() {
                    // Verify ownership if we hold the record.
                    if let Some(rec) = state.registry.get(mint_id) {
                        if rec.current_owner_vk_hash != owner_vk_hash {
                            warn!("reforge attestation: owner mismatch for mint_id {:?} — banishing", &mint_id[..4]);
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }

                    // Verify consume signature: signs Blake3("vess-reforge-consume-v0" || mint_id || reforge_id).
                    let consume_msg = {
                        let mut h = blake3::Hasher::new();
                        h.update(b"vess-reforge-consume-v0");
                        h.update(mint_id);
                        h.update(&ra.reforge_id);
                        *h.finalize().as_bytes()
                    };
                    match vess_foundry::spend_auth::verify_spend(
                        &ra.owner_vk,
                        &consume_msg,
                        &ra.consume_sigs[i],
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!("reforge attestation: invalid consume sig for mint_id {:?} — banishing", &mint_id[..4]);
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                        Err(e) => {
                            warn!("reforge attestation: consume sig error: {e} — banishing");
                            state.peer_registry.mark_banished(peer_id);
                            ban_ref.banish(peer_id);
                            return None;
                        }
                    }
                }

                // 4. Consume (delete) all input mint_ids and store tombstones.
                //
                // The tombstone maps old mint_id → reforge_id + output_mint_ids,
                // so that:
                //   a. Future OwnershipClaims for these bills are rejected (reforge-wins rule).
                //   b. Wallets can trace where the value went after a split/combine.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                for mint_id in &ra.consumed_mint_ids {
                    let was_active =
                        state.registry.mark_consumed(
                            mint_id,
                            ra.reforge_id,
                            ra.output_mint_ids.clone(),
                            now,
                        ).is_some();
                    if was_active {
                        info!("reforge consumed mint_id {:?}", &mint_id[..4]);
                    }
                }

                // H3: Drain any OwnershipGenesis messages that were buffered waiting
                // for these tombstones to materialise, and re-inject them for processing.
                for mint_id in &ra.consumed_mint_ids {
                    if let Some(pending) = state.pending_reforge_genesis.remove(mint_id) {
                        for (pending_og, _buffered_at) in pending {
                            let _ = h_og_tx.send(pending_og);
                        }
                    }
                }

                // 5. Forward to K-nearest peers if hops remain.
                if ra.hops_remaining > 0 {
                    let mut fwd = ra.clone();
                    fwd.hops_remaining -= 1;
                    let _ = h_ra_tx.send(fwd);
                }
                None
            }

            PulseMessage::NetworkStats(ns) => {
                info!(%peer, "network stats request");
                let peer_count = state.routing_table.peer_count() as u64;
                let verified_peer_count = state.peer_registry.count_in_state(PeerState::Verified) as u64;
                let estimated = state.routing_table.estimated_network_size() as u64;
                let limbo_count = state.limbo_mint_ids.len() as u64;
                let median = state.payment_latency.median();
                let p95 = state.payment_latency.p95();
                let sample_count = state.payment_latency.count();
                Some(PulseMessage::NetworkStatsResponse(
                    vess_protocol::NetworkStatsResponse {
                        nonce: ns.nonce,
                        peer_count,
                        verified_peer_count,
                        estimated_network_size: estimated,
                        limbo_count,
                        median_payment_latency_ms: median,
                        p95_payment_latency_ms: p95,
                        latency_sample_count: sample_count,
                    },
                ))
            }

            other => {
                info!(%peer, "unhandled message: {other:?}");
                None
            }
        }
    })
    .await?;

    // Save state on shutdown.
    {
        let s = state.lock().unwrap();
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
