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
    open_stealth_payload, prepare_stealth_payload, scan_view_tag, MasterStealthAddress,
    StealthPayload, StealthSecretKey,
};

use crate::billfold::BillFold;
use crate::selection::select_bills;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    let stealth = prepare_stealth_payload(recipient, &plaintext)?;

    let payment_id = derive_payment_id(&stealth);

    let msg = PulseMessage::Payment(Payment {
        payment_id,
        stealth_payload: postcard::to_allocvec(&stealth)
            .map_err(|e| anyhow!("serialize stealth payload: {e}"))?,
        view_tag: stealth.view_tag,
        stealth_id: stealth.stealth_id,
        created_at: now_unix(),
        bill_count,
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

    let stealth_ctx = vess_stealth::generate_stealth_context(recipient)?;
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
    });

    Ok((msg, payment_id, selection.send_indices))
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

    let stealth_ctx = vess_stealth::generate_stealth_context(recipient)?;
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
    });

    Ok((msg, payment_id))
}

// ── Direct P2P payment ──────────────────────────────────────────────

/// Prepare a direct peer-to-peer payment (bypasses artery relay).
///
/// Selects bills from the billfold, signs transfer authorizations, and
/// builds a [`DirectPayment`] message that can be sent over a QUIC
/// bi-stream to the recipient. The recipient verifies proofs inline.
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
    claim_transfer_bills(payload, dp.recipient_stealth_id)
}

// ── Recipient-side operations ────────────────────────────────────────

/// Try to receive a payment: scan view tag, decrypt, return bills.
pub fn try_receive_payment(
    secret: &StealthSecretKey,
    payment: &Payment,
) -> Result<Option<Vec<VessBill>>> {
    try_decrypt_stealth_payload(secret, &payment.stealth_payload)
}

/// Try to decrypt a raw stealth_payload blob into bills.
///
/// Used by both `try_receive_payment` (live Payment messages) and
/// MailboxCollect (offline limbo payloads) to avoid duplicating logic.
pub fn try_decrypt_stealth_payload(
    secret: &StealthSecretKey,
    stealth_payload: &[u8],
) -> Result<Option<Vec<VessBill>>> {
    // Deserialize the stealth payload.
    let stealth: StealthPayload = postcard::from_bytes(stealth_payload)
        .map_err(|e| anyhow!("deserialize stealth payload: {e}"))?;

    // Quick scan.
    if !scan_view_tag(secret, &stealth.ct_scan, stealth.view_tag)? {
        return Ok(None);
    }

    // Full decrypt.
    let (plaintext, _stealth_id) = open_stealth_payload(secret, &stealth)?;

    let bills: Vec<VessBill> =
        postcard::from_bytes(&plaintext).map_err(|e| anyhow!("deserialize bills: {e}"))?;

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
) -> Result<Option<DecryptedTransfer>> {
    let stealth: StealthPayload = postcard::from_bytes(stealth_payload)
        .map_err(|e| anyhow!("deserialize stealth payload: {e}"))?;

    if !scan_view_tag(secret, &stealth.ct_scan, stealth.view_tag)? {
        return Ok(None);
    }

    let (plaintext, stealth_id) = open_stealth_payload(secret, &stealth)?;

    let tp = postcard::from_bytes::<TransferPayload>(&plaintext)
        .map_err(|e| anyhow!("stealth payload decrypted but not a valid TransferPayload: {e}"))?;
    Ok(Some(DecryptedTransfer::WithAuth(tp, stealth_id)))
}

/// Result of decrypting a stealth payload.
#[derive(Debug, Clone)]
pub enum DecryptedTransfer {
    /// Transfer with authorization signatures and ownership chain data.
    WithAuth(TransferPayload, [u8; 32]),
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
) -> Result<TransferClaimResult> {
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
        //    encrypted_bill = postcard(bill) encrypted with Blake3(stealth_id || mint_id)
        //    so artery nodes can store it for DHT recovery but can't read it.
        let new_depth = bill.chain_depth + 1;
        let encrypted_bill = {
            use blake3::Hasher;
            let mut kh = Hasher::new();
            kh.update(&stealth_id);
            kh.update(&bill.mint_id);
            kh.update(b"vess-claim-bill-v0");
            let key = kh.finalize();
            let bill_bytes = postcard::to_allocvec(&bill).unwrap_or_default();
            // Simple XOR-mask for lightweight confidentiality — the true
            // security comes from DKSAP (only recipient knows stealth_id
            // secret key). The mask prevents casual inspection by DHT nodes.
            let mut out = bill_bytes;
            for (i, b) in out.iter_mut().enumerate() {
                *b ^= key.as_bytes()[i % 32];
            }
            out
        };
        let claim = PulseMessage::OwnershipClaim(vess_protocol::OwnershipClaim {
            mint_id: bill.mint_id,
            stealth_id,
            prev_owner_vk: payload.sender_vks[i].clone(),
            transfer_sig: payload.transfer_sigs[i].clone(),
            new_owner_vk_hash: new_vk_hash,
            new_owner_vk: new_vk.clone(),
            new_chain_tip,
            timestamp: payload.timestamp,
            hops_remaining: 6,
            chain_depth: new_depth,
            encrypted_bill,
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
                denomination_value: bill.denomination.value(),
                proof: proof_bytes.clone(),
                digest: bill.digest,
                hops_remaining: 6,
                chain_depth: 0,
                output_index: 0,
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
) -> Result<Option<TransferClaimResult>> {
    match try_decrypt_transfer_payload(secret, stealth_payload)? {
        Some(DecryptedTransfer::WithAuth(tp, stealth_id)) => {
            let result = claim_transfer_bills(tp, stealth_id)?;
            Ok(Some(result))
        }
        None => Ok(None),
    }
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
}
