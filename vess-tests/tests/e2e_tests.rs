//! End-to-end integration tests for the Vess protocol.
//!
//! Covers: payment with memo, noise payments, cancel/refund,
//! payment splitting, relay wrapping, and tag DHT operations.

use vess_foundry::spend_auth::generate_spend_keypair;
use vess_foundry::{Denomination, VessBill};
use vess_kloak::billfold::BillFold;
use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::{
    claim_transfer_bills, is_noise_payment, prepare_noise_payment,
    prepare_payment, prepare_payment_from_bills_split,
    prepare_payment_with_transfer,
};
use vess_protocol::{PulseMessage, RelayPayment};
use vess_stealth::{generate_master_keys, open_stealth_payload};
use vess_stealth::StealthPayload;
use vess_kloak::payment::TransferPayload;
use vess_artery::TagDht;
use blake3;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fresh_bill(denom: Denomination) -> VessBill {
    VessBill {
        denomination: denom,
        digest: rand::random(),
        created_at: now_unix(),
        stealth_id: rand::random(),
        dht_index: 0,
        mint_id: rand::random(),
        chain_tip: rand::random(),
        chain_depth: 0,
        asset: vess_foundry::Asset::Btc,
    }
}

// ── Payment with transfer auth + memo ────────────────────────────────

#[test]
fn payment_with_memo_round_trip() {
    let (recipient_secret, recipient_address) = generate_master_keys();
    let mut sender_billfold = BillFold::new();
    let mut creds = std::collections::HashMap::new();

    for _ in 0..3 {
        let (vk, sk) = generate_spend_keypair();
        let bill = fresh_bill(Denomination::D10);
        let mint_id = bill.mint_id;
        creds.insert(mint_id, SpendCredential {
            spend_vk: vk,
            spend_sk: sk,
        });
        sender_billfold.deposit_with_credentials(bill, creds[&mint_id].clone());
    }

    let memo = "invoice #42".to_string();
    let (msg, _pid, _indices) = prepare_payment_with_transfer(
        &sender_billfold,
        10,
        &recipient_address,
        &creds,
        Some(memo.clone()),
    )
    .unwrap();

    let payment = match &msg {
        PulseMessage::Payment(p) => p,
        _ => panic!("expected Payment"),
    };

    // Recipient decrypts.
    let payload = &payment.stealth_payload;
    let stealth: StealthPayload = postcard::from_bytes(payload).unwrap();
    let (plaintext, stealth_id, recovery_key) =
        open_stealth_payload(&recipient_secret, &stealth).unwrap();

    // Unpad and check memo.
    let unpadded = vess_stealth::unpad_plaintext(&plaintext).unwrap();
    let tp: TransferPayload = postcard::from_bytes(unpadded).unwrap();
    assert_eq!(tp.memo.as_deref(), Some("invoice #42"));

    // Claim the transfer.
    let result = claim_transfer_bills(tp, stealth_id, Some(recovery_key)).unwrap();
    assert_eq!(result.claimed.len(), 1);
    assert_eq!(result.memo.as_deref(), Some("invoice #42"));
}

// ── Noise payment silent discard ─────────────────────────────────────

#[test]
fn noise_payment_silently_discarded() {
    let (_recipient_secret, recipient_address) = generate_master_keys();

    let msg = prepare_noise_payment(&recipient_address).unwrap();
    let payment = match &msg {
        PulseMessage::Payment(p) => p.clone(),
        _ => panic!("expected Payment"),
    };

    // Looks like a real payment on the wire.
    assert_eq!(payment.bill_count, 0);
    assert!(!payment.stealth_payload.is_empty());
    assert!(payment.mailbox_key.is_some());

    // Serialize round-trip.
    let bytes = msg.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    assert!(matches!(decoded, PulseMessage::Payment(_)));

    // is_noise_payment helper.
    assert!(is_noise_payment(b"VESS_NOISE_V0extra"));
    assert!(!is_noise_payment(b"real bills here"));
}

// ── Payment cancel (refund) flow ─────────────────────────────────────

#[test]
fn payment_cancel_releases_bills() {
    let mut billfold = BillFold::new();

    let (vk1, sk1) = generate_spend_keypair();
    let (vk2, sk2) = generate_spend_keypair();
    let bill1 = fresh_bill(Denomination::D10);
    let bill2 = fresh_bill(Denomination::D5);
    let mint1 = bill1.mint_id;
    let mint2 = bill2.mint_id;

    billfold.deposit_with_credentials(bill1, SpendCredential { spend_vk: vk1, spend_sk: sk1 });
    billfold.deposit_with_credentials(bill2, SpendCredential { spend_vk: vk2, spend_sk: sk2 });

    let initial_spendable = billfold.spendable_balance();
    assert_eq!(initial_spendable, 15);

    // Reserve bills like a real send would.
    let mint_ids = vec![mint1, mint2];
    let now = now_unix();
    billfold.reserve(&mint_ids, now);

    // After reservation, spendable drops.
    assert_eq!(billfold.spendable_balance(), 0);

    // Cancel: release back.
    billfold.release(&mint_ids);

    // Balance restored.
    assert_eq!(billfold.spendable_balance(), initial_spendable);
}

// ── Payment split when exceeding bill limit ──────────────────────────

#[test]
fn payment_split_large_bill_count() {
    let (recipient_secret, recipient_address) = generate_master_keys();
    let mut billfold = BillFold::new();
    let mut creds = std::collections::HashMap::new();

    // Create 20 small bills (well above the auto-split threshold of 8).
    for _ in 0..20 {
        let (vk, sk) = generate_spend_keypair();
        let bill = fresh_bill(Denomination::D1);
        let mint_id = bill.mint_id;
        creds.insert(mint_id, SpendCredential {
            spend_vk: vk,
            spend_sk: sk,
        });
        billfold.deposit_with_credentials(bill, creds[&mint_id].clone());
    }

    let memo = Some("split test".to_string());
    let payments = prepare_payment_from_bills_split(
        &billfold.bills(),
        &recipient_address,
        &creds,
        memo.clone(),
    )
    .unwrap();

    // With 20 bills, should split into multiple payments.
    assert!(payments.len() >= 2, "20 bills should trigger split");

    let mut total_value: u64 = 0;
    for (msg, _) in &payments {
        if let PulseMessage::Payment(p) = msg {
            let payload: StealthPayload = postcard::from_bytes(&p.stealth_payload).unwrap();
            let (pt, _, _) = open_stealth_payload(&recipient_secret, &payload).unwrap();
            let unpadded = vess_stealth::unpad_plaintext(&pt).unwrap();
            let tp: TransferPayload = postcard::from_bytes(unpadded).unwrap();
            total_value += tp.bills.iter().map(|b| b.denomination.value()).sum::<u64>();
        }
    }

    // All value accounted for.
    assert_eq!(total_value, 20);
}

// ── RelayPayment wrap/unwrap ─────────────────────────────────────────

#[test]
fn relay_payment_round_trip() {
    let (_recipient_secret, recipient_address) = generate_master_keys();
    let mut billfold = BillFold::new();
    billfold.deposit(fresh_bill(Denomination::D10));

    // Create a real payment.
    let (msg, _pid, _indices) =
        prepare_payment(&billfold, 10, &recipient_address).unwrap();
    let payment = match msg {
        PulseMessage::Payment(p) => p,
        _ => panic!("expected Payment"),
    };

    // Wrap in RelayPayment.
    let mailbox_key = payment.mailbox_key.unwrap_or(payment.stealth_id);
    let relay = RelayPayment {
        payment: payment.clone(),
        target_shard_key: mailbox_key,
        ttl: 1,
    };
    let relay_msg = PulseMessage::RelayPayment(relay.clone());

    // Serialize → deserialize round-trip.
    let bytes = relay_msg.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    let unwrapped = match decoded {
        PulseMessage::RelayPayment(rp) => rp,
        _ => panic!("expected RelayPayment"),
    };

    assert_eq!(unwrapped.payment.payment_id, payment.payment_id);
    assert_eq!(unwrapped.target_shard_key, mailbox_key);
    assert_eq!(unwrapped.ttl, 1);
}

// ── Tag DHT store + lookup ──────────────────────────────────────────

#[test]
fn tag_dht_store_and_lookup() {
    let node_id = [0x42u8; 32];
    let mut dht = TagDht::new(node_id, 4);

    let (_secret, address) = generate_master_keys();
    let tag_hash = *blake3::hash(b"alice").as_bytes();

    let record = vess_tag::TagRecord {
        tag_hash,
        master_address: address.clone(),
        pow_nonce: [0xAB; 32],
        pow_hash: vec![0xCD; 32],
        registered_at: now_unix(),
        registrant_vk: vec![0x01; 1952],
        signature: vec![0x02; 3300],
        hardened_at: None,
    };

    // Store it.
    assert!(dht.store(record.clone()));
    // Duplicate should be rejected.
    assert!(!dht.store(record.clone()));

    // Lookup by hash.
    let found = dht.lookup_by_hash(&tag_hash);
    assert!(found.is_some());
    let r = found.unwrap();
    assert_eq!(r.master_address.scan_ek, address.scan_ek);
    assert_eq!(r.master_address.spend_ek, address.spend_ek);
}
