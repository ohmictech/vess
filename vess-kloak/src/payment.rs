//! End-to-end payment flow.
//!
//! Orchestrates the full lifecycle of a Vess payment:
//!
//! 1. **Sender** selects bills, prepares stealth payload, sends via pulse.
//! 2. **Recipient** scans view tags, opens matching payloads.
//! 3. **Recipient** claims ownership via `OwnershipClaim` (chain_depth + 1).
//!
//! If the recipient never claims, the sender still owns the bill (deepest
//! chain wins). The sender can re-spend the bill to cancel.

use anyhow::{anyhow, Result};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::billfold::SpendCredential;
use vess_compute::{ProgramOwnershipCondition, ProgramSpendWitness};
use vess_foundry::spend_auth;
use vess_foundry::VessBill;
use vess_protocol::{Payment, PulseMessage};

/// Payload encrypted inside stealth addressing for ownership transfers.
///
/// The sender encrypts this for the recipient. It contains the bills
/// plus the transfer authorization signatures needed to claim ownership,
/// and an optional plaintext memo visible only to sender and recipient.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransferPayload {
    /// The bills being transferred.
    pub bills: Vec<VessBill>,
    /// ML-DSA-65 verification key of the sender (one per bill).
    pub sender_vks: Vec<Vec<u8>>,
    /// Transfer authorization signatures (one per bill).
    /// Each signs `transfer_message(mint_id, recipient_stealth_id, timestamp)`.
    pub transfer_sigs: Vec<Vec<u8>>,
    /// Unix timestamp of the transfer.
    pub timestamp: u64,
    /// Optional end-to-end encrypted memo (e.g. order ID, invoice ref, note).
    /// Visible only to sender and recipient. Max 256 bytes.
    #[serde(default)]
    pub memo: Option<String>,
}
use vess_stealth::{
    open_stealth_payload, MasterStealthAddress,
    StealthPayload, StealthSecretKey,
};

use crate::billfold::BillFold;
use crate::selection::select_bills;

/// Magic prefix prepended to noise/decoy payment plaintext.
/// Recipients recognize this and silently discard the payment.
const NOISE_MAGIC: &[u8] = b"VESS_NOISE_V0";

/// In-flight payment state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentState {
    /// Payment sent, waiting for recipient to claim ownership.
    InFlight {
        /// Unix timestamp when payment was sent.
        sent_at: u64,
        /// Mint IDs of the bills in this payment.
        bill_mint_ids: Vec<[u8; 32]>,
    },
    /// Recipient claimed ownership — payment is settled.
    Final {
        /// When the attestation was received.
        finalized_at: u64,
    },
}

/// A tracked payment in the wallet.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrackedPayment {
    pub payment_id: [u8; 32],
    pub amount: u64,
    pub state: PaymentState,
    pub recipient_stealth_id: [u8; 32],
    /// Spend credentials for the bills, keyed by mint_id.
    #[serde(default)]
    pub spend_credentials: HashMap<[u8; 32], SpendCredential>,
}

/// Outbound payment manager — tracks in-flight and finalized payments.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PaymentTracker {
    payments: HashMap<[u8; 32], TrackedPayment>,
}

impl PaymentTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new in-flight payment.
    pub fn record_sent(
        &mut self,
        payment_id: [u8; 32],
        amount: u64,
        bill_mint_ids: Vec<[u8; 32]>,
        recipient_stealth_id: [u8; 32],
        spend_credentials: HashMap<[u8; 32], SpendCredential>,
    ) {
        let now = now_unix();
        self.payments.insert(
            payment_id,
            TrackedPayment {
                payment_id,
                amount,
                state: PaymentState::InFlight {
                    sent_at: now,
                    bill_mint_ids,
                },
                recipient_stealth_id,
                spend_credentials,
            },
        );
    }

    /// Mark a payment as finalized after receiving an attestation.
    pub fn finalize(&mut self, payment_id: &[u8; 32]) -> Result<()> {
        let payment = self
            .payments
            .get_mut(payment_id)
            .ok_or_else(|| anyhow!("unknown payment"))?;

        payment.state = PaymentState::Final {
            finalized_at: now_unix(),
        };
        Ok(())
    }

    /// Get a payment by ID.
    pub fn get(&self, payment_id: &[u8; 32]) -> Option<&TrackedPayment> {
        self.payments.get(payment_id)
    }

    /// All in-flight payments.
    pub fn in_flight(&self) -> Vec<&TrackedPayment> {
        self.payments
            .values()
            .filter(|p| matches!(p.state, PaymentState::InFlight { .. }))
            .collect()
    }
}

// ── Mailbox shard key derivation ────────────────────────────────────

/// Derive the deterministic mailbox routing key from a recipient's
/// spend encapsulation key.
///
/// Both the **sender** (who has the recipient's public `spend_ek`) and the
/// **recipient** (who generates it from their own key) derive the same key
/// independently — no extra out-of-band communication is needed.
///
/// The key is used in two ways:
/// 1. The sender attaches it to the [`Payment`] so relay nodes store the
///    payment under the correct shard (via [`LimboEntry::mailbox_key`]).
/// 2. The recipient sends a targeted [`MailboxSweep`] with this key so
///    each relay returns only their own payloads — eliminating
///    trial-decryption of every stranger's payment.
///
/// Relay routing uses the key instead of `stealth_id` so multiple relay
/// nodes in the K-nearest neighbourhood of the key all hold the payment,
/// matching the cluster the recipient will sweep.
pub fn derive_mailbox_key(spend_ek: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"vess-mailbox-v1");
    h.update(spend_ek);
    *h.finalize().as_bytes()
}

/// Check whether a decrypted payment plaintext is a noise/decoy payment.
///
/// Noise payments carry [`NOISE_MAGIC`] followed by random padding.
/// Recipients should silently discard matches.
pub fn is_noise_payment(plaintext: &[u8]) -> bool {
    plaintext.starts_with(NOISE_MAGIC)
}

/// Prepare a noise (decoy) payment to your own stealth address.
///
/// This creates a [`PulseMessage::Payment`] that is **wire-identical** to a
/// real payment — same stealth structure, same view tag scheme, same size
/// profile. The plaintext contains [`NOISE_MAGIC`] so the recipient
/// (yourself) recognizes it as noise and silently discards.
///
/// Noise payments have `bill_count: 0` and carry no real value.
/// They exist solely to add entropy to the payment graph, making it
/// impossible for passive observers (Sybils) to distinguish real
/// transactions from decoys.
pub fn prepare_noise_payment(own_address: &MasterStealthAddress) -> Result<PulseMessage> {
    let payment_id: [u8; 32] = rand::random();

    // Build noise plaintext: magic prefix + random padding bytes.
    // The payload looks like random ciphertext to any observer.
    let noise_body_len: usize = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        32 + (rng.gen_range(0u8..65u8) as usize) // 32..=96 bytes of noise body
    };
    let mut noise_body = vec![0u8; NOISE_MAGIC.len() + noise_body_len];
    noise_body[..NOISE_MAGIC.len()].copy_from_slice(NOISE_MAGIC);
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut noise_body[NOISE_MAGIC.len()..]);
    }

    // Pad to uniform size so noise payments are byte-identical to real ones.
    let plaintext = vess_stealth::pad_plaintext(&noise_body);

    let stealth =
        vess_stealth::prepare_stealth_payload_with_tag(own_address, &plaintext, &payment_id)?;

    let mailbox_key = derive_mailbox_key(&own_address.spend_ek);

    Ok(PulseMessage::Payment(Payment {
        payment_id,
        stealth_payload: postcard::to_allocvec(&stealth)
            .map_err(|e| anyhow!("serialize stealth payload: {e}"))?,
        view_tag: stealth.view_tag,
        stealth_id: stealth.stealth_id,
        created_at: now_unix(),
        bill_count: 0,
        mailbox_key: Some(mailbox_key),
        direct_receipt_tag_hash: None,
        program_receipt: None,
    }))
}

// ── Sender-side operations ───────────────────────────────────────────

/// Prepare a payment: select bills, build stealth payload, produce wire message.
///
/// Returns the `PulseMessage` to send and the payment ID for tracking.
pub fn prepare_payment(
    billfold: &BillFold,
    amount: u64,
    recipient: &MasterStealthAddress,
) -> Result<(PulseMessage, [u8; 32], Vec<usize>)> {
    let selection = select_bills(billfold.bills(), amount)?;

    // Collect relay metadata from the selected bills.
    let bill_data: Vec<&VessBill> = selection
        .send_indices
        .iter()
        .map(|&i| &billfold.bills()[i])
        .collect();

    let bill_count = bill_data.len() as u8;

    // Serialize bill data for the stealth payload.
    let plaintext =
        postcard::to_allocvec(&bill_data).map_err(|e| anyhow!("serialize bills: {e}"))?;

    // Pad to uniform size — kills bill_count observable on the wire.
    let plaintext = vess_stealth::pad_plaintext(&plaintext);

    // Generate payment_id first so it can be bound into the view tag
    // for per-payment unlinkability.
    let payment_id: [u8; 32] = rand::random();
    let stealth = vess_stealth::prepare_stealth_payload_with_tag(recipient, &plaintext, &payment_id)?;

    let msg = PulseMessage::Payment(Payment {
        payment_id,
        stealth_payload: postcard::to_allocvec(&stealth)
            .map_err(|e| anyhow!("serialize stealth payload: {e}"))?,
        view_tag: stealth.view_tag,
        stealth_id: stealth.stealth_id,
        created_at: now_unix(),
        bill_count,
        mailbox_key: Some(derive_mailbox_key(&recipient.spend_ek)),
        direct_receipt_tag_hash: None,
        program_receipt: None,
    });

    Ok((msg, payment_id, selection.send_indices))
}

/// Prepare a payment with transfer authorization signatures.
///
/// Like `prepare_payment`, but encrypts a [`TransferPayload`] containing
/// the sender's ML-DSA-65 verification keys and transfer authorization
/// signatures for each bill. The recipient uses these to construct an
/// [`OwnershipClaim`] and rotate the ownership chain.
///
/// `credentials` maps bill mint_id → (spend_vk, spend_sk).
pub fn prepare_payment_with_transfer(
    billfold: &BillFold,
    amount: u64,
    recipient: &MasterStealthAddress,
    credentials: &HashMap<[u8; 32], crate::billfold::SpendCredential>,
    memo: Option<String>,
) -> Result<(PulseMessage, [u8; 32], Vec<usize>)> {
    let selection = select_bills(billfold.bills(), amount)?;

    let bill_data: Vec<&VessBill> = selection
        .send_indices
        .iter()
        .map(|&i| &billfold.bills()[i])
        .collect();

    let bill_count = bill_data.len() as u8;

    // Build transfer auth: sign transfer_message per bill.
    // Use two-phase stealth API so the stealth_id used for signing
    // is the same one embedded in the final payload.
    let bills_owned: Vec<VessBill> = bill_data.iter().map(|b| (*b).clone()).collect();

    // Generate payment_id first so the view tag binds to it
    let payment_id: [u8; 32] = rand::random();
    let stealth_ctx = vess_stealth::generate_stealth_context_with_tag(recipient, &payment_id)?;
    let recipient_stealth_id = stealth_ctx.stealth_id;

    let timestamp = now_unix();
    let mut sender_vks = Vec::with_capacity(bills_owned.len());
    let mut transfer_sigs = Vec::with_capacity(bills_owned.len());

    for bill in &bills_owned {
        let cred = credentials
            .get(&bill.mint_id)
            .ok_or_else(|| anyhow!("missing spend credential for bill mint_id"))?;

        let msg = spend_auth::transfer_message(&bill.mint_id, &recipient_stealth_id, timestamp);
        let sig = spend_auth::sign_spend(&cred.spend_sk, &msg)?;

        sender_vks.push(cred.spend_vk.clone());
        transfer_sigs.push(sig);
    }

    let transfer_payload = TransferPayload {
        bills: bills_owned,
        sender_vks,
        transfer_sigs,
        timestamp,
        memo: memo.clone(),
    };

    let plaintext = postcard::to_allocvec(&transfer_payload)
        .map_err(|e| anyhow!("serialize transfer payload: {e}"))?;

    // Pad to uniform size.
    let plaintext = vess_stealth::pad_plaintext(&plaintext);

    let stealth = stealth_ctx.encrypt(&plaintext)?;
    let payment_id = derive_payment_id(&stealth);

    let msg = PulseMessage::Payment(Payment {
        payment_id,
        stealth_payload: postcard::to_allocvec(&stealth)
            .map_err(|e| anyhow!("serialize stealth payload: {e}"))?,
        view_tag: stealth.view_tag,
        stealth_id: stealth.stealth_id,
        created_at: timestamp,
        bill_count,
        mailbox_key: Some(derive_mailbox_key(&recipient.spend_ek)),
        direct_receipt_tag_hash: None,
        program_receipt: None,
    });

    Ok((msg, payment_id, selection.send_indices))
}

/// Max plaintext size (before padding) that fits in a uniform payment.
const MAX_PLAINTEXT: usize = vess_stealth::PADDED_PLAINTEXT_SIZE - 2;

/// Prepare a payment, automatically splitting into multiple payments if the
/// transfer-auth payload exceeds the uniform size limit.
///
/// Returns one or more `(PulseMessage, payment_id)` pairs. The caller should
/// send each message through the normal gossip pipeline. Each split payment
/// is a complete, independent payment with its own stealth payload.
pub fn prepare_payment_split(
    billfold: &BillFold,
    amount: u64,
    recipient: &MasterStealthAddress,
    credentials: &HashMap<[u8; 32], crate::billfold::SpendCredential>,
    memo: Option<String>,
) -> Result<Vec<(PulseMessage, [u8; 32])>> {
    let selection = select_bills(billfold.bills(), amount)?;
    let all_bills: Vec<VessBill> = selection
        .send_indices
        .iter()
        .map(|&i| billfold.bills()[i].clone())
        .collect();

    // Quick check: small payments always fit.
    if all_bills.len() <= 8 {
        return prepare_payment_from_bills(&all_bills, recipient, credentials, memo)
            .map(|(msg, pid)| vec![(msg, pid)]);
    }

    // Build TransferPayload to measure exact serialized size.
    let payment_id: [u8; 32] = rand::random();
    let stealth_ctx = vess_stealth::generate_stealth_context_with_tag(recipient, &payment_id)?;
    let timestamp = now_unix();

    let mut sender_vks = Vec::with_capacity(all_bills.len());
    let mut transfer_sigs = Vec::with_capacity(all_bills.len());
    for bill in &all_bills {
        let cred = credentials
            .get(&bill.mint_id)
            .ok_or_else(|| anyhow!("missing spend credential for bill"))?;
        let msg = spend_auth::transfer_message(&bill.mint_id, &stealth_ctx.stealth_id, timestamp);
        let sig = spend_auth::sign_spend(&cred.spend_sk, &msg)?;
        sender_vks.push(cred.spend_vk.clone());
        transfer_sigs.push(sig);
    }

    let tp = TransferPayload {
        bills: all_bills.clone(),
        sender_vks,
        transfer_sigs,
        timestamp,
        memo: memo.clone(),
    };
    let serialized = postcard::to_allocvec(&tp)
        .map_err(|e| anyhow!("serialize transfer payload: {e}"))?;

    if serialized.len() <= MAX_PLAINTEXT {
        // Fits — single payment.
        return prepare_payment_from_bills(&all_bills, recipient, credentials, memo)
            .map(|(msg, pid)| vec![(msg, pid)]);
    }

    // Too large: split bills into two halves and recurse.
    let mid = all_bills.len() / 2;
    let left: Vec<VessBill> = all_bills[..mid].to_vec();
    let right: Vec<VessBill> = all_bills[mid..].to_vec();

    let mut results = Vec::new();
    results.extend(prepare_payment_from_bills_split(&left, recipient, credentials, memo.clone())?);
    results.extend(prepare_payment_from_bills_split(&right, recipient, credentials, memo)?);
    Ok(results)
}

/// Split-aware variant of [`prepare_payment_from_bills`] — automatically
/// splits into multiple payments if the transfer-auth payload exceeds
/// the uniform size limit.
pub fn prepare_payment_from_bills_split(
    bills: &[VessBill],
    recipient: &MasterStealthAddress,
    credentials: &HashMap<[u8; 32], crate::billfold::SpendCredential>,
    memo: Option<String>,
) -> Result<Vec<(PulseMessage, [u8; 32])>> {
    if bills.len() <= 8 {
        return prepare_payment_from_bills(bills, recipient, credentials, memo)
            .map(|(msg, pid)| vec![(msg, pid)]);
    }

    // Build TransferPayload to check size.
    let payment_id: [u8; 32] = rand::random();
    let stealth_ctx = vess_stealth::generate_stealth_context_with_tag(recipient, &payment_id)?;
    let timestamp = now_unix();

    let mut sender_vks = Vec::with_capacity(bills.len());
    let mut transfer_sigs = Vec::with_capacity(bills.len());
    for bill in bills {
        let cred = credentials
            .get(&bill.mint_id)
            .ok_or_else(|| anyhow!("missing spend credential for bill"))?;
        let msg = spend_auth::transfer_message(&bill.mint_id, &stealth_ctx.stealth_id, timestamp);
        let sig = spend_auth::sign_spend(&cred.spend_sk, &msg)?;
        sender_vks.push(cred.spend_vk.clone());
        transfer_sigs.push(sig);
    }

    let tp = TransferPayload {
        bills: bills.to_vec(),
        sender_vks,
        transfer_sigs,
        timestamp,
        memo: memo.clone(),
    };
    let serialized = postcard::to_allocvec(&tp)
        .map_err(|e| anyhow!("serialize transfer payload: {e}"))?;

    if serialized.len() <= MAX_PLAINTEXT {
        return prepare_payment_from_bills(bills, recipient, credentials, memo)
            .map(|(msg, pid)| vec![(msg, pid)]);
    }

    // Split in half and recurse.
    let mid = bills.len() / 2;
    let mut results = Vec::new();
    results.extend(prepare_payment_from_bills_split(&bills[..mid], recipient, credentials, memo.clone())?);
    results.extend(prepare_payment_from_bills_split(&bills[mid..], recipient, credentials, memo)?);
    Ok(results)
}

/// Prepare a payment from explicit bills (no selection).
///
/// Used after reforge-based change splitting, where the caller has
/// already produced the exact bills to send.
pub fn prepare_payment_from_bills(
    bills: &[VessBill],
    recipient: &MasterStealthAddress,
    credentials: &HashMap<[u8; 32], crate::billfold::SpendCredential>,
    memo: Option<String>,
) -> Result<(PulseMessage, [u8; 32])> {
    let bill_count = bills.len() as u8;

    // Generate payment_id first so the view tag binds to it
    let payment_id: [u8; 32] = rand::random();
    let stealth_ctx = vess_stealth::generate_stealth_context_with_tag(recipient, &payment_id)?;
    let recipient_stealth_id = stealth_ctx.stealth_id;

    let timestamp = now_unix();
    let mut sender_vks = Vec::with_capacity(bills.len());
    let mut transfer_sigs = Vec::with_capacity(bills.len());

    for bill in bills {
        let cred = credentials
            .get(&bill.mint_id)
            .ok_or_else(|| anyhow!("missing spend credential for bill mint_id"))?;

        let msg = spend_auth::transfer_message(&bill.mint_id, &recipient_stealth_id, timestamp);
        let sig = spend_auth::sign_spend(&cred.spend_sk, &msg)?;

        sender_vks.push(cred.spend_vk.clone());
        transfer_sigs.push(sig);
    }

    let transfer_payload = TransferPayload {
        bills: bills.to_vec(),
        sender_vks,
        transfer_sigs,
        timestamp,
        memo,
    };

    let plaintext = postcard::to_allocvec(&transfer_payload)
        .map_err(|e| anyhow!("serialize transfer payload: {e}"))?;

    // Pad to uniform size.
    let plaintext = vess_stealth::pad_plaintext(&plaintext);

    let stealth = stealth_ctx.encrypt(&plaintext)?;
    let payment_id = derive_payment_id(&stealth);

    let msg = PulseMessage::Payment(Payment {
        payment_id,
        stealth_payload: postcard::to_allocvec(&stealth)
            .map_err(|e| anyhow!("serialize stealth payload: {e}"))?,
        view_tag: stealth.view_tag,
        stealth_id: stealth.stealth_id,
        created_at: timestamp,
        bill_count,
        mailbox_key: Some(derive_mailbox_key(&recipient.spend_ek)),
        direct_receipt_tag_hash: None,
        program_receipt: None,
    });

    Ok((msg, payment_id))
}

// ── Direct P2P payment ──────────────────────────────────────────────

/// Prepare a direct peer-to-peer payment (bypasses artery relay).
///
/// Selects bills from the billfold, signs transfer authorizations, and
/// builds a [`DirectPayment`] message that can be sent over a direct
/// mesh session to the recipient. The recipient verifies proofs inline.
///
/// `recipient_stealth_id` is the receiver's stealth address identifier
/// (e.g. derived from their `MasterStealthAddress` or exchanged out-of-band).
pub fn prepare_direct_payment(
    billfold: &BillFold,
    amount: u64,
    recipient_stealth_id: [u8; 32],
    credentials: &HashMap<[u8; 32], crate::billfold::SpendCredential>,
) -> Result<(PulseMessage, [u8; 32], Vec<usize>)> {
    let selection = select_bills(billfold.bills(), amount)?;

    let bill_data: Vec<&VessBill> = selection
        .send_indices
        .iter()
        .map(|&i| &billfold.bills()[i])
        .collect();

    let mint_ids: Vec<[u8; 32]> = bill_data.iter().map(|b| b.mint_id).collect();
    let denomination_values: Vec<u64> = bill_data.iter().map(|b| b.denomination.value()).collect();

    let bills_owned: Vec<VessBill> = bill_data.iter().map(|b| (*b).clone()).collect();

    let timestamp = now_unix();
    let mut sender_vks = Vec::with_capacity(bills_owned.len());
    let mut transfer_sigs = Vec::with_capacity(bills_owned.len());

    for bill in &bills_owned {
        let cred = credentials
            .get(&bill.mint_id)
            .ok_or_else(|| anyhow!("missing spend credential for bill mint_id"))?;

        let msg = spend_auth::transfer_message(&bill.mint_id, &recipient_stealth_id, timestamp);
        let sig = spend_auth::sign_spend(&cred.spend_sk, &msg)?;

        sender_vks.push(cred.spend_vk.clone());
        transfer_sigs.push(sig);
    }

    let transfer_payload = TransferPayload {
        bills: bills_owned,
        sender_vks,
        transfer_sigs,
        timestamp,
        memo: None,
    };

    let tp_bytes = postcard::to_allocvec(&transfer_payload)
        .map_err(|e| anyhow!("serialize transfer payload: {e}"))?;

    let payment_id = {
        let mut h = Hasher::new();
        h.update(b"vess-direct-payment-v0");
        h.update(&recipient_stealth_id);
        h.update(&tp_bytes[..32.min(tp_bytes.len())]);
        *h.finalize().as_bytes()
    };

    let msg = PulseMessage::DirectPayment(vess_protocol::DirectPayment {
        payment_id,
        transfer_payload: tp_bytes,
        recipient_stealth_id,
        mint_ids,
        denomination_values,
        created_at: timestamp,
    });

    Ok((msg, payment_id, selection.send_indices))
}

/// Receive and verify a direct peer-to-peer payment.
///
/// Verifies transfer authorization signatures, claims the bills with
/// fresh spend keypairs, and returns [`OwnershipClaim`] messages to
/// broadcast when artery connectivity is available.
///
/// STARK proofs are NOT verified here — they were verified once at
/// OwnershipGenesis time. The receiver trusts the registry.
pub fn receive_direct_payment(dp: &vess_protocol::DirectPayment) -> Result<TransferClaimResult> {
    // Deserialize the TransferPayload.
    let payload: TransferPayload = postcard::from_bytes(&dp.transfer_payload)
        .map_err(|e| anyhow!("deserialize transfer payload: {e}"))?;

    // Sanity: array lengths must match.
    if payload.bills.len() != dp.mint_ids.len()
        || payload.bills.len() != dp.denomination_values.len()
    {
        anyhow::bail!("direct payment: array length mismatch");
    }

    // Registry-only model: STARK proofs were verified at OwnershipGenesis
    // time. No inline proof verification needed.

    // Delegate to the existing claim logic (verifies transfer sigs + generates new keypairs).
    claim_transfer_bills(payload, dp.recipient_stealth_id, None)
}

// ── Recipient-side operations ────────────────────────────────────────

/// Try to receive a payment: scan view tag, decrypt, return bills.
pub fn try_receive_payment(
    secret: &StealthSecretKey,
    payment: &Payment,
) -> Result<Option<Vec<VessBill>>> {
    try_decrypt_stealth_payload(secret, &payment.stealth_payload, &payment.payment_id)
}

/// Try to decrypt a raw stealth_payload blob into bills.
///
/// Used by both `try_receive_payment` (live Payment messages) and
/// MailboxCollect (offline limbo payloads) to avoid duplicating logic.
pub fn try_decrypt_stealth_payload(
    secret: &StealthSecretKey,
    stealth_payload: &[u8],
    payment_id: &[u8; 32],
) -> Result<Option<Vec<VessBill>>> {
    // Deserialize the stealth payload.
    let stealth: StealthPayload = postcard::from_bytes(stealth_payload)
        .map_err(|e| anyhow!("deserialize stealth payload: {e}"))?;

    // Quick scan with per-payment tag context for unlinkable view tags.
    if !vess_stealth::scan_view_tag_with_context(secret, &stealth.ct_scan, stealth.view_tag, payment_id)? {
        return Ok(None);
    }

    // Full decrypt.
    let (padded, _stealth_id, _recovery_key) = open_stealth_payload(secret, &stealth)?;

    // Strip uniform-size padding.
    let plaintext = match vess_stealth::unpad_plaintext(&padded) {
        Some(pt) => pt,
        None => {
            // Legacy unpadded format: use as-is.
            &padded
        }
    };

    // Silently discard noise/decoy payments.
    if is_noise_payment(plaintext) {
        return Ok(None);
    }

    let bills: Vec<VessBill> =
        postcard::from_bytes(plaintext).map_err(|e| anyhow!("deserialize bills: {e}"))?;

    Ok(Some(bills))
}

/// Try to decrypt a stealth payload as a [`TransferPayload`].
///
/// Returns `None` if the view tag doesn't match (not for us).
/// Falls back to legacy format (plain `Vec<VessBill>`) if the new format
/// doesn't parse.
pub fn try_decrypt_transfer_payload(
    secret: &StealthSecretKey,
    stealth_payload: &[u8],
    payment_id: &[u8; 32],
) -> Result<Option<DecryptedTransfer>> {
    let stealth: StealthPayload = postcard::from_bytes(stealth_payload)
        .map_err(|e| anyhow!("deserialize stealth payload: {e}"))?;

    if !vess_stealth::scan_view_tag_with_context(secret, &stealth.ct_scan, stealth.view_tag, payment_id)? {
        return Ok(None);
    }

    // Full decrypt.
    let (padded, stealth_id, recovery_key) = open_stealth_payload(secret, &stealth)?;

    // Strip uniform-size padding.
    let plaintext = match vess_stealth::unpad_plaintext(&padded) {
        Some(pt) => pt,
        None => &padded,
    };

    // Silently discard noise/decoy payments.
    if is_noise_payment(plaintext) {
        return Ok(None);
    }

    let tp = postcard::from_bytes::<TransferPayload>(plaintext)
        .map_err(|e| anyhow!("stealth payload decrypted but not a valid TransferPayload: {e}"))?;
    Ok(Some(DecryptedTransfer::WithAuth(
        tp,
        stealth_id,
        recovery_key,
    )))
}

/// Result of decrypting a stealth payload.
#[derive(Debug, Clone)]
pub enum DecryptedTransfer {
    /// Transfer with authorization signatures and ownership chain data.
    WithAuth(TransferPayload, [u8; 32], [u8; 32]),
}

/// Claimed bill output: bill + spend keypair.
#[derive(Debug, Clone)]
pub struct ClaimedBill {
    /// The bill with updated ownership chain.
    pub bill: VessBill,
    /// ML-DSA-65 verification key for this bill.
    pub spend_vk: Vec<u8>,
    /// ML-DSA-65 signing key for this bill.
    pub spend_sk: Vec<u8>,
}

/// Result of claiming a transfer-auth payment (with ownership chain data).
#[derive(Debug, Clone)]
pub struct TransferClaimResult {
    /// Claimed bills with new spend credentials.
    pub claimed: Vec<ClaimedBill>,
    /// OwnershipClaim messages to broadcast to artery.
    pub ownership_claims: Vec<PulseMessage>,
    /// Optional memo from the sender (e.g. order ID, invoice ref, note).
    pub memo: Option<String>,
}

fn encrypt_bill_for_recovery(bill: &VessBill, recovery_key: Option<[u8; 32]>) -> Vec<u8> {
    match recovery_key {
        Some(key) => {
            use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
            let nonce_bytes = {
                let mut h = blake3::Hasher::new();
                h.update(&key);
                h.update(&bill.mint_id);
                h.update(b"vess-claim-nonce-v1");
                let hash = h.finalize();
                let mut n = [0u8; 12];
                n.copy_from_slice(&hash.as_bytes()[..12]);
                n
            };
            let bill_bytes = postcard::to_allocvec(bill).unwrap_or_default();
            let cipher = ChaCha20Poly1305::new((&key).into());
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            cipher.encrypt(nonce, bill_bytes.as_ref()).unwrap_or_default()
        }
        None => vec![],
    }
}

/// Claim received bills from a [`TransferPayload`] (new ownership chain format).
///
/// For each bill:
/// 1. Verify the IOP proof (recipient-side).
/// 2. Verify the sender's transfer authorization signature.
/// 3. Generate a fresh ML-DSA-65 spend keypair for the recipient.
/// 4. Compute the new ownership chain tip.
/// 5. Build an [`OwnershipClaim`] message for artery broadcast.
///
/// Unlike `claim_received_bills`, this does NOT reforge — the bill is
/// permanent. Only the ownership binding rotates.
pub fn claim_transfer_bills(
    payload: TransferPayload,
    stealth_id: [u8; 32],
    recovery_key: Option<[u8; 32]>,
) -> Result<TransferClaimResult> {
    let memo = payload.memo.clone();
    if payload.bills.len() != payload.sender_vks.len()
        || payload.bills.len() != payload.transfer_sigs.len()
    {
        anyhow::bail!("transfer payload: array length mismatch");
    }

    let mut claimed = Vec::with_capacity(payload.bills.len());
    let mut ownership_claims = Vec::with_capacity(payload.bills.len());

    for (i, bill) in payload.bills.into_iter().enumerate() {
        // 1. Verify sender's transfer authorization signature.
        let transfer_msg =
            spend_auth::transfer_message(&bill.mint_id, &stealth_id, payload.timestamp);
        match spend_auth::verify_spend(
            &payload.sender_vks[i],
            &transfer_msg,
            &payload.transfer_sigs[i],
        ) {
            Ok(true) => {}
            Ok(false) => anyhow::bail!("transfer bill {i}: invalid transfer signature from sender"),
            Err(e) => anyhow::bail!("transfer bill {i}: transfer signature error: {e}"),
        }

        // 2. Generate fresh ML-DSA-65 spend keypair for the recipient.
        let (new_vk, new_sk) = spend_auth::generate_spend_keypair();
        let new_vk_hash = spend_auth::vk_hash(&new_vk);

        // 3. Compute new ownership chain tip.
        let new_chain_tip = vess_foundry::advance_chain_tip(
            &bill.chain_tip,
            &new_vk_hash,
            &payload.transfer_sigs[i],
        );

        // 4. Build OwnershipClaim message.
        //    chain_depth = bill's current depth + 1 (this is one more transfer).
        let new_depth = bill.chain_depth + 1;
        //    encrypted_bill = AEAD-encrypted postcard(bill) using ChaCha20Poly1305 with
        //    the per-payment KEM recovery key (derived from DKSAP scan shared secret).
        //    Only the recipient can re-derive this key — it is NOT in the claim message.
        //    Falls back to an empty blob when no recovery key is available (e.g. direct payment).
        let encrypted_bill = encrypt_bill_for_recovery(&bill, recovery_key);
        let claim = PulseMessage::OwnershipClaim(vess_protocol::OwnershipClaim {
            mint_id: bill.mint_id,
            stealth_id,
            prev_owner_vk: payload.sender_vks[i].clone(),
            prev_owner_program: None,
            transfer_sig: payload.transfer_sigs[i].clone(),
            new_owner_vk_hash: new_vk_hash,
            new_owner_vk: new_vk.clone(),
            new_owner_program: None,
            new_chain_tip,
            timestamp: payload.timestamp,
            hops_remaining: 6,
            chain_depth: new_depth,
            encrypted_bill,
            program_spend_witness: None,
            pow_nonce: None,
            pow_hash: None,
            accumulated_work: None,
        });
        ownership_claims.push(claim);

        // Update the bill's chain_tip and chain_depth to reflect new ownership.
        let mut updated_bill = bill;
        updated_bill.chain_tip = new_chain_tip;
        updated_bill.chain_depth = new_depth;

        claimed.push(ClaimedBill {
            bill: updated_bill,
            spend_vk: new_vk,
            spend_sk: new_sk,
        });
    }

    Ok(TransferClaimResult {
        claimed,
        ownership_claims,
        memo,
    })
}

// ── Auto-genesis (minting) ───────────────────────────────────────────

/// Build `OwnershipGenesis` pulse messages for freshly minted bills.
///
/// Takes the `(VessBill, proof_bytes)` pairs returned by
/// [`vess_foundry::mint::aggregate_solves`] and the minter's ML-DSA-65
/// spend credential.  Returns one `PulseMessage::OwnershipGenesis` per
/// bill, ready to broadcast to the artery network.
pub fn build_genesis_messages(bills: &[(VessBill, Vec<u8>)], owner_vk: &[u8]) -> Vec<PulseMessage> {
    let owner_vk_hash = spend_auth::vk_hash(owner_vk);
    bills
        .iter()
        .map(|(bill, proof_bytes)| {
            PulseMessage::OwnershipGenesis(vess_protocol::OwnershipGenesis {
                mint_id: bill.mint_id,
                chain_tip: bill.chain_tip,
                owner_vk_hash,
                owner_vk: owner_vk.to_vec(),
                program_owner: None,
                denomination_value: bill.denomination.value(),
                genesis_proof: vess_protocol::GenesisProof::Vess(proof_bytes.clone()),
                digest: bill.digest,
                hops_remaining: 6,
                chain_depth: 0,
                output_index: 0,
                ..Default::default()
            })
        })
        .collect()
}

// ── Auto-claim (receiving) ──────────────────────────────────────────

/// Decrypt a stealth payment and claim ownership in one step.
///
/// Combines [`try_decrypt_transfer_payload`] + [`claim_transfer_bills`]
/// into a single call.  Returns `Ok(None)` if the payment isn't for us
/// (view-tag mismatch).  On success returns the claimed bills with
/// fresh spend credentials and the `OwnershipClaim` messages to
/// broadcast to the artery.
pub fn receive_and_claim(
    secret: &StealthSecretKey,
    stealth_payload: &[u8],
    payment_id: &[u8; 32],
) -> Result<Option<TransferClaimResult>> {
    match try_decrypt_transfer_payload(secret, stealth_payload, payment_id)? {
        Some(DecryptedTransfer::WithAuth(tp, stealth_id, recovery_key)) => {
            let result = claim_transfer_bills(tp, stealth_id, Some(recovery_key))?;
            Ok(Some(result))
        }
        None => Ok(None),
    }
}

/// Build ownership claims that lock bills to a program-owned condition.
pub fn build_program_lock_claims(
    bills: &[VessBill],
    credentials: &HashMap<[u8; 32], SpendCredential>,
    condition: &ProgramOwnershipCondition,
) -> Result<Vec<PulseMessage>> {
    let timestamp = now_unix();
    let destination = condition.controller.address_id();
    let new_owner_commitment = condition.owner_commitment();
    let mut claims = Vec::with_capacity(bills.len());

    for bill in bills {
        let cred = credentials
            .get(&bill.mint_id)
            .ok_or_else(|| anyhow!("missing spend credential for bill mint_id"))?;
        let msg = spend_auth::transfer_message(&bill.mint_id, &destination, timestamp);
        let sig = spend_auth::sign_spend(&cred.spend_sk, &msg)?;
        let new_chain_tip = vess_foundry::advance_chain_tip(
            &bill.chain_tip,
            &new_owner_commitment,
            &sig,
        );
        claims.push(PulseMessage::OwnershipClaim(vess_protocol::OwnershipClaim {
            mint_id: bill.mint_id,
            stealth_id: destination,
            prev_owner_vk: cred.spend_vk.clone(),
            prev_owner_program: None,
            transfer_sig: sig,
            new_owner_vk_hash: new_owner_commitment,
            new_owner_vk: Vec::new(),
            new_owner_program: Some(condition.clone()),
            new_chain_tip,
            timestamp,
            hops_remaining: 6,
            chain_depth: bill.chain_depth + 1,
            encrypted_bill: Vec::new(),
            program_spend_witness: None,
            pow_nonce: None,
            pow_hash: None,
            accumulated_work: None,
        }));
    }

    Ok(claims)
}

/// Claim bills currently owned by a program predicate using a compute receipt witness.
pub fn build_program_unlock_claims(
    bills: &[VessBill],
    previous_condition: &ProgramOwnershipCondition,
    witness: &ProgramSpendWitness,
    recipient_stealth_id: [u8; 32],
    next_owner: &SpendCredential,
    recovery_key: Option<[u8; 32]>,
) -> Result<TransferClaimResult> {
    let next_owner_vk_hash = spend_auth::vk_hash(&next_owner.spend_vk);
    if next_owner_vk_hash != witness.next_owner_commitment {
        anyhow::bail!("program spend witness next owner commitment does not match supplied spend key");
    }

    let mut claimed = Vec::with_capacity(bills.len());
    let mut ownership_claims = Vec::with_capacity(bills.len());
    let witness_hash = witness.witness_hash();

    for bill in bills {
        if !witness.authorized_mint_ids.contains(&bill.mint_id) {
            anyhow::bail!("program spend witness does not authorize mint_id");
        }

        let new_depth = bill.chain_depth + 1;
        let new_chain_tip = vess_foundry::advance_chain_tip_with_hash(
            &bill.chain_tip,
            &next_owner_vk_hash,
            &witness_hash,
        );
        let encrypted_bill = encrypt_bill_for_recovery(bill, recovery_key);

        ownership_claims.push(PulseMessage::OwnershipClaim(vess_protocol::OwnershipClaim {
            mint_id: bill.mint_id,
            stealth_id: recipient_stealth_id,
            prev_owner_vk: Vec::new(),
            prev_owner_program: Some(previous_condition.clone()),
            transfer_sig: Vec::new(),
            new_owner_vk_hash: next_owner_vk_hash,
            new_owner_vk: next_owner.spend_vk.clone(),
            new_owner_program: None,
            new_chain_tip,
            timestamp: witness.receipt.created_at,
            hops_remaining: 6,
            chain_depth: new_depth,
            encrypted_bill,
            program_spend_witness: Some(witness.clone()),
            pow_nonce: None,
            pow_hash: None,
            accumulated_work: None,
        }));

        let mut updated_bill = bill.clone();
        updated_bill.chain_tip = new_chain_tip;
        updated_bill.chain_depth = new_depth;
        claimed.push(ClaimedBill {
            bill: updated_bill,
            spend_vk: next_owner.spend_vk.clone(),
            spend_sk: next_owner.spend_sk.clone(),
        });
    }

    Ok(TransferClaimResult {
        claimed,
        ownership_claims,
        memo: None,
    })
}

// ── Bill Verification ───────────────────────────────────────────────

/// Extract mint_ids from a slice of OwnershipClaim messages.
///
/// Filters for `PulseMessage::OwnershipClaim` variants and extracts their
/// mint_ids for use in registry queries.
pub fn extract_mint_ids_from_claims(claims: &[PulseMessage]) -> Vec<[u8; 32]> {
    claims
        .iter()
        .filter_map(|msg| {
            if let PulseMessage::OwnershipClaim(claim) = msg {
                Some(claim.mint_id)
            } else {
                None
            }
        })
        .collect()
}

/// Verify deposited bills against the registry and silently remove any
/// that were rejected (not active in DHT).
///
/// Call this after:
/// 1. Depositing bills to the billfold
/// 2. Broadcasting OwnershipClaim messages
/// 3. Waiting for DHT convergence (e.g., 500ms)
///
/// If all K nodes rejected a bill's ownership claim (bill is inactive in
/// registry), it means:
/// - Sender may have already spent the bill (deeper chain_depth)
/// - Bill was fake/forged
/// - Another recipient beat us to claiming it
///
/// We silently remove it from the billfold to prevent user confusion
/// (seeing money that's unspendable).
///
/// # Arguments
///
/// - `billfold`: The wallet's billfold (mutably modified if removals needed)
/// - `deposited_mint_ids`: The set of mint_ids that were just claimed
/// - `active`: Parallel bool array from [`RegistryQueryResponse`], where
///   `active[i]` corresponds to `deposited_mint_ids[i]`
///
/// # Returns
///
/// Vector of mint_ids that were silently removed (rejected claims).
///
/// # Example
///
/// ```no_run
/// # use vess_kloak::payment::cleanup_rejected_bills;
/// # use vess_kloak::billfold::BillFold;
/// let deposited_ids = vec![[0x01; 32], [0x02; 32]];
/// let active_response = vec![true, false]; // Bill 2 was rejected
///
/// let mut billfold = BillFold::new();
/// let removed = cleanup_rejected_bills(&mut billfold, &deposited_ids, &active_response);
/// assert!(!removed.is_empty()); // [0x02; 32] was removed
/// ```
pub fn cleanup_rejected_bills(
    billfold: &mut BillFold,
    deposited_mint_ids: &[[u8; 32]],
    active: &[bool],
) -> Vec<[u8; 32]> {
    let mut removed = Vec::new();

    for (i, &mint_id) in deposited_mint_ids.iter().enumerate() {
        // Safety: active should have same length as deposited_mint_ids from protocol
        if i >= active.len() {
            // Malformed response; log warning but continue
            tracing::warn!(
                deposits = deposited_mint_ids.len(),
                statuses = active.len(),
                "registry response mismatch"
            );
            continue;
        }

        if !active[i] {
            // Bill is inactive in registry — ownership claim was rejected.
            // Silently remove from billfold.
            if billfold.withdraw(&mint_id).is_some() {
                removed.push(mint_id);
            }
        }
    }

    removed
}

// ── Helpers ──────────────────────────────────────────────────────────

fn derive_payment_id(stealth: &StealthPayload) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"vess-payment-id-v0");
    h.update(&stealth.stealth_id);
    h.update(&stealth.ct_scan[..32.min(stealth.ct_scan.len())]);
    *h.finalize().as_bytes()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Payment history ──────────────────────────────────────────────────

/// A single entry in the wallet's local payment history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentHistoryEntry {
    /// Payment ID.
    pub payment_id: String,
    /// Unix timestamp when the payment was sent or received.
    pub timestamp: u64,
    /// Amount in Vess.
    pub amount: u64,
    /// "sent" or "received".
    pub direction: String,
    /// Counterparty tag or address.
    #[serde(default)]
    pub counterparty: Option<String>,
    /// Optional memo attached to the payment.
    #[serde(default)]
    pub memo: Option<String>,
    /// Payment status: "pending", "confirmed", "cancelled", or "refunded".
    #[serde(default)]
    pub status: String,
}

/// Local-only payment history persisted to a JSON file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PaymentHistory {
    entries: Vec<PaymentHistoryEntry>,
}

impl PaymentHistory {
    /// Load payment history from disk, or return an empty one.
    pub fn load(path: &std::path::Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save payment history to disk.
    pub fn save(&self, path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(data) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, data);
        }
    }

    /// Record a sent payment.
    pub fn record_sent(
        &mut self,
        payment_id: &str,
        amount: u64,
        counterparty: Option<String>,
        memo: Option<String>,
    ) {
        self.entries.push(PaymentHistoryEntry {
            payment_id: payment_id.to_string(),
            timestamp: now_unix(),
            amount,
            direction: "sent".to_string(),
            counterparty,
            memo,
            status: "pending".to_string(),
        });
    }

    /// Record a received payment.
    pub fn record_received(
        &mut self,
        payment_id: &str,
        amount: u64,
        counterparty: Option<String>,
        memo: Option<String>,
    ) {
        self.entries.push(PaymentHistoryEntry {
            payment_id: payment_id.to_string(),
            timestamp: now_unix(),
            amount,
            direction: "received".to_string(),
            counterparty,
            memo,
            status: "confirmed".to_string(),
        });
    }

    /// Mark a sent payment as confirmed.
    pub fn confirm(&mut self, payment_id: &str) {
        for entry in &mut self.entries {
            if entry.payment_id == payment_id && entry.direction == "sent" {
                entry.status = "confirmed".to_string();
            }
        }
    }

    /// Mark a payment as cancelled/refunded.
    pub fn mark_cancelled(&mut self, payment_id: &str) {
        for entry in &mut self.entries {
            if entry.payment_id == payment_id {
                entry.status = "cancelled".to_string();
            }
        }
    }

    /// Return all entries, newest first.
    pub fn all(&self) -> &[PaymentHistoryEntry] {
        &self.entries
    }

    /// Return entries in chronological order, newest first.
    pub fn list(&self) -> Vec<&PaymentHistoryEntry> {
        let mut entries: Vec<&PaymentHistoryEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_foundry::Denomination;
    use vess_stealth::generate_master_keys;

    fn test_bill(denom: Denomination) -> VessBill {
        VessBill {
            denomination: denom,
            digest: rand::random(),
            created_at: now_unix(),
            stealth_id: rand::random(),
            dht_index: 0,
            mint_id: rand::random(),
            chain_tip: rand::random(),
            chain_depth: 0,
        }
    }

    #[test]
    fn test_cleanup_rejected_bills() {
        use crate::billfold::SpendCredential;

        let mut billfold = BillFold::new();

        // Create 3 test bills
        let bill1 = test_bill(Denomination::D1);
        let bill2 = test_bill(Denomination::D5);
        let bill3 = test_bill(Denomination::D10);

        let id1 = bill1.mint_id;
        let id2 = bill2.mint_id;
        let id3 = bill3.mint_id;

        // Deposit all three
        billfold.deposit_with_credentials(
            bill1,
            SpendCredential {
                spend_vk: vec![0xAA; 32],
                spend_sk: vec![0xBB; 32],
            },
        );
        billfold.deposit_with_credentials(
            bill2,
            SpendCredential {
                spend_vk: vec![0xCC; 32],
                spend_sk: vec![0xDD; 32],
            },
        );
        billfold.deposit_with_credentials(
            bill3,
            SpendCredential {
                spend_vk: vec![0xEE; 32],
                spend_sk: vec![0xFF; 32],
            },
        );

        assert_eq!(billfold.count(), 3);
        assert_eq!(billfold.balance(), 16); // 1 + 5 + 10

        // Simulate registry response: bill1 active, bill2 REJECTED, bill3 active
        let deposited = vec![id1, id2, id3];
        let active = vec![true, false, true];

        let removed = cleanup_rejected_bills(&mut billfold, &deposited, &active);

        // Should have removed only bill2
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], id2);

        // Billfold should have 2 bills left (1 + 10 = 11 value)
        assert_eq!(billfold.count(), 2);
        assert_eq!(billfold.balance(), 11);

        // Verify the remaining bills are correct
        let remaining_ids: Vec<_> = billfold.bills().iter().map(|b| b.mint_id).collect();
        assert!(remaining_ids.contains(&id1));
        assert!(!remaining_ids.contains(&id2)); // Removed
        assert!(remaining_ids.contains(&id3));
    }

    #[test]
    fn payment_tracker_lifecycle() {
        let mut tracker = PaymentTracker::new();
        let pid = [0xAA; 32];
        let mint_ids = vec![[0x01; 32]];

        tracker.record_sent(pid, 10, mint_ids.clone(), [0xBB; 32], HashMap::new());

        assert!(tracker.get(&pid).is_some());
        assert!(matches!(
            tracker.get(&pid).unwrap().state,
            PaymentState::InFlight { .. }
        ));

        // Finalize.
        tracker.finalize(&pid).unwrap();
        assert!(matches!(
            tracker.get(&pid).unwrap().state,
            PaymentState::Final { .. }
        ));

        assert!(tracker.in_flight().is_empty());
    }

    #[test]
    fn prepare_and_receive_payment() {
        let (secret, address) = generate_master_keys();
        let mut billfold = BillFold::new();
        billfold.deposit(test_bill(Denomination::D10));
        billfold.deposit(test_bill(Denomination::D5));

        let (msg, _pid, indices) = prepare_payment(&billfold, 10, &address).unwrap();
        assert!(!indices.is_empty());

        // Extract the Payment from the message.
        let payment = match msg {
            PulseMessage::Payment(p) => p,
            _ => panic!("expected Payment"),
        };

        let bills = try_receive_payment(&secret, &payment).unwrap();
        assert!(bills.is_some());
        let received = bills.unwrap();
        assert!(!received.is_empty());
    }

    #[test]
    fn noise_payment_round_trip() {
        // 1. Recipient generates keys.
        let (secret, address) = generate_master_keys();

        // 2. Create a noise payment to self.
        let msg = prepare_noise_payment(&address).unwrap();
        let payment = match &msg {
            PulseMessage::Payment(p) => p.clone(),
            _ => panic!("expected Payment"),
        };

        // 3. Noise payment looks like a real payment on the wire.
        assert_eq!(payment.bill_count, 0);
        assert!(!payment.stealth_payload.is_empty());
        assert!(payment.mailbox_key.is_some());

        // 4. Serialize/deserialize round-trip (wire format).
        let bytes = msg.to_bytes().unwrap();
        let decoded = PulseMessage::from_bytes(&bytes).unwrap();
        let decoded_payment = match &decoded {
            PulseMessage::Payment(p) => p,
            _ => panic!("expected Payment"),
        };
        assert_eq!(decoded_payment.payment_id, payment.payment_id);

        // 5. Recipient tries to receive — should be silently discarded as noise.
        let result = try_receive_payment(&secret, &payment).unwrap();
        assert!(result.is_none(), "noise payment should be silently discarded");

        // 6. is_noise_payment helper works on raw plaintext.
        assert!(is_noise_payment(b"VESS_NOISE_V0\x00\x01\x02"));
        assert!(is_noise_payment(b"VESS_NOISE_V0"));
        assert!(!is_noise_payment(b"VESS_BILL"));
        assert!(!is_noise_payment(b""));
    }
}
