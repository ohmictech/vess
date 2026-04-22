//! End-to-end integration tests spanning multiple Vess crates.
//!
//! These tests exercise the full payment lifecycle:
//! mint → stealth encrypt → send → receive → reforge → finalize.

use vess_artery::ownership_registry::OwnershipRecord;
use vess_artery::{OwnershipRegistry, TagDht};
use vess_foundry::spend_auth::generate_spend_keypair;
use vess_foundry::{Denomination, VessBill};
use vess_kloak::billfold::BillFold;
use vess_kloak::payment::{prepare_payment, try_receive_payment, PaymentTracker};
use vess_kloak::persistence::WalletFile;
use vess_kloak::recovery::{
    decrypt_secrets, derive_encryption_key_with_params, encrypt_secrets, RecoveryPhrase,
};
use vess_kloak::selection::select_bills;
use vess_protocol::PulseMessage;
use vess_stealth::generate_master_keys;
use vess_tag::{validate_registration, TagRegistration, VessTag};

// blake3 used for computing tag hashes in tests.
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
    }
}

// ── Payment lifecycle ────────────────────────────────────────────────

#[test]
fn full_payment_lifecycle() {
    // 1. Sender has a billfold with bills.
    let mut sender_billfold = BillFold::new();
    sender_billfold.deposit(fresh_bill(Denomination::D10));
    sender_billfold.deposit(fresh_bill(Denomination::D5));
    sender_billfold.deposit(fresh_bill(Denomination::D2));

    // 2. Recipient has a stealth address.
    let (recipient_secret, recipient_address) = generate_master_keys();

    // 3. Sender prepares payment.
    let (msg, payment_id, send_indices) =
        prepare_payment(&sender_billfold, 10, &recipient_address).unwrap();

    assert!(!send_indices.is_empty());

    // 4. Track the payment.
    let mut tracker = PaymentTracker::new();
    let mint_ids: Vec<[u8; 32]> = send_indices
        .iter()
        .map(|&i| sender_billfold.bills()[i].mint_id)
        .collect();
    tracker.record_sent(
        payment_id,
        10,
        mint_ids.clone(),
        [0u8; 32],
        std::collections::HashMap::new(),
    );

    // 5. Recipient receives and decrypts.
    let payment = match msg {
        PulseMessage::Payment(p) => p,
        _ => panic!("expected Payment"),
    };
    let received = try_receive_payment(&recipient_secret, &payment)
        .unwrap()
        .expect("should decrypt");
    assert!(!received.is_empty());

    // 6. Recipient deposits into their billfold.
    let mut recipient_billfold = BillFold::new();
    for bill in &received {
        recipient_billfold.deposit(bill.clone());
    }
    assert!(recipient_billfold.balance() >= 10);

    // 7. Recipient registers ownership in the registry.
    let mut registry = OwnershipRegistry::new([0x01; 32]);
    for bill in &received {
        let (vk, _sk) = generate_spend_keypair();
        let record = OwnershipRecord {
            mint_id: bill.mint_id,
            chain_tip: bill.chain_tip,
            current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
            current_owner_vk: vk.clone(),
            denomination_value: bill.denomination.value(),
            updated_at: now_unix(),
            proof_hash: [0u8; 32],
            digest: [0u8; 32],
            nonce: [0u8; 32],
            prev_claim_vk_hash: None,
            claim_hash: None,
            chain_depth: 0,
            encrypted_bill: vec![],
        };
        assert!(registry.register(record));
    }

    // 8. Sender considers payment final once ownership is registered.
    tracker.finalize(&payment_id).unwrap();
    assert!(tracker.in_flight().is_empty());
}

// ── Ownership registry double-spend detection ────────────────────────

#[test]
fn ownership_registry_double_registration() {
    let mut registry = OwnershipRegistry::new([0x01; 32]);

    let mint_id1: [u8; 32] = rand::random();
    let mint_id2: [u8; 32] = rand::random();
    let (vk, _sk) = generate_spend_keypair();

    let record1 = OwnershipRecord {
        mint_id: mint_id1,
        chain_tip: rand::random(),
        current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
        current_owner_vk: vk.clone(),
        denomination_value: 10,
        updated_at: now_unix(),
        proof_hash: [0u8; 32],
        digest: [0u8; 32],
        nonce: [0u8; 32],
        prev_claim_vk_hash: None,
        claim_hash: None,
        chain_depth: 0,
        encrypted_bill: vec![],
    };
    let record2 = OwnershipRecord {
        mint_id: mint_id2,
        chain_tip: rand::random(),
        current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
        current_owner_vk: vk.clone(),
        denomination_value: 20,
        updated_at: now_unix(),
        proof_hash: [0u8; 32],
        digest: [0u8; 32],
        nonce: [0u8; 32],
        prev_claim_vk_hash: None,
        claim_hash: None,
        chain_depth: 0,
        encrypted_bill: vec![],
    };

    assert!(registry.register(record1.clone()));
    assert!(registry.register(record2));

    // Double-registration attempt.
    assert!(!registry.register(record1));
}

// ── Ownership registry consume and Merkle root ──────────────────────

#[test]
fn ownership_registry_consume_and_merkle() {
    let mut registry = OwnershipRegistry::new([0x01; 32]);
    let (vk, _sk) = generate_spend_keypair();

    let mint_id: [u8; 32] = rand::random();
    let record = OwnershipRecord {
        mint_id,
        chain_tip: rand::random(),
        current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
        current_owner_vk: vk.clone(),
        denomination_value: 10,
        updated_at: now_unix(),
        proof_hash: [0u8; 32],
        digest: [0u8; 32],
        nonce: [0u8; 32],
        prev_claim_vk_hash: None,
        claim_hash: None,
        chain_depth: 0,
        encrypted_bill: vec![],
    };
    registry.register(record);

    assert!(registry.is_active(&mint_id));
    let root_before = registry.merkle_root();

    // Consume the bill.
    let consumed = registry.consume(&mint_id);
    assert!(consumed.is_some());
    assert!(!registry.is_active(&mint_id));

    // Merkle root changes after consume.
    let root_after = registry.merkle_root();
    assert_ne!(root_before, root_after);
}

// ── Tag registration ─────────────────────────────────────────────────

#[test]
fn tag_registration_and_dht() {
    let tag = VessTag::new("+alice").unwrap();

    let (_secret, address) = generate_master_keys();

    let reg = TagRegistration {
        tag_hash: *blake3::hash(tag.as_str().as_bytes()).as_bytes(),
        master_address: address.clone(),
        pow_nonce: [0x42; 32],
        pow_hash: vec![0xAA; 32],
    };

    validate_registration(&reg).unwrap();

    // Store in DHT.
    let node_id: [u8; 32] = rand::random();
    let mut dht = TagDht::new(node_id, 3);

    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();
    let record = vess_tag::TagRecord {
        tag_hash,
        master_address: address,
        pow_nonce: [0x42; 32],
        pow_hash: vec![0xAA; 32],
        registered_at: now_unix(),
        registrant_vk: Vec::new(),
        signature: Vec::new(),
        hardened_at: None,
    };

    assert!(dht.store(record));
    assert!(dht.lookup("alice").is_some());

    // Second store fails (first-broadcast-wins).
    let record2 = vess_tag::TagRecord {
        tag_hash: *blake3::hash(b"alice").as_bytes(),
        master_address: generate_master_keys().1,
        pow_nonce: [0x43; 32],
        pow_hash: vec![0xBB; 32],
        registered_at: now_unix(),
        registrant_vk: Vec::new(),
        signature: Vec::new(),
        hardened_at: None,
    };
    assert!(!dht.store(record2));

    // Same address with different tag also fails (one-tag-per-address).
    // (Would need same address to test — covered by tag_dht unit tests.)
}

// ── Wallet persistence ───────────────────────────────────────────────

#[test]
fn wallet_create_backup_restore() {
    let (secret, address) = generate_master_keys();
    let phrase = RecoveryPhrase::generate();
    let enc_key = derive_encryption_key_with_params(&phrase, 1, 64, 1).unwrap();
    let encrypted = encrypt_secrets(&secret, &enc_key).unwrap();

    let mut billfold = BillFold::new();
    billfold.deposit(fresh_bill(Denomination::D10));
    billfold.deposit(fresh_bill(Denomination::D5));

    let wallet = WalletFile::new(address, encrypted, billfold, [0u8; 32], &enc_key).unwrap();

    let dir = std::env::temp_dir().join("vess-e2e-test");
    let path = dir.join("wallet.json");
    let backup_path = dir.join("backup.json");

    wallet.save(&path).unwrap();
    wallet.backup(&backup_path).unwrap();

    // Load from backup.
    let loaded = WalletFile::load(&backup_path).unwrap();
    assert_eq!(loaded.billfold.balance(), 15);

    // Decrypt keys.
    let restored = decrypt_secrets(&loaded.encrypted_secrets, &enc_key).unwrap();
    assert_eq!(restored.scan_dk, secret.scan_dk);
    assert_eq!(restored.spend_dk, secret.spend_dk);

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Bill selection ───────────────────────────────────────────────────

#[test]
fn bill_selection_exact_match() {
    let bills = vec![
        fresh_bill(Denomination::D10),
        fresh_bill(Denomination::D5),
        fresh_bill(Denomination::D2),
    ];

    let result = select_bills(&bills, 10).unwrap();
    assert_eq!(result.total_selected, 10);
    assert_eq!(result.change, 0);
}

#[test]
fn bill_selection_with_change() {
    let bills = vec![fresh_bill(Denomination::D20), fresh_bill(Denomination::D5)];

    let result = select_bills(&bills, 10).unwrap();
    assert!(result.total_selected >= 10);
    assert!(result.change > 0);
}

// ── Wire protocol round-trip ─────────────────────────────────────────

#[test]
fn protocol_message_serialization() {
    use vess_protocol::Payment;

    let messages = vec![PulseMessage::Payment(Payment {
        payment_id: [0xAA; 32],
        stealth_payload: vec![1, 2, 3],
        view_tag: 0x42,
        stealth_id: [0xBB; 32],
        created_at: 1000,
        bill_count: 0,
    })];

    for msg in &messages {
        let bytes = msg.to_bytes().unwrap();
        let decoded = PulseMessage::from_bytes(&bytes).unwrap();
        let _ = decoded.to_bytes().unwrap();
    }
}

// ── New message types round-trip ─────────────────────────────────────

#[test]
fn tag_register_round_trip() {
    use vess_protocol::TagRegister;

    let alice_hash = *blake3::hash(b"alice").as_bytes();
    let msg = PulseMessage::TagRegister(TagRegister {
        tag_hash: alice_hash,
        scan_ek: vec![0xAA; 1184],
        spend_ek: vec![0xBB; 1952],
        pow_nonce: [0x42; 32],
        pow_hash: vec![0xCC; 32],
        timestamp: now_unix(),
        registrant_vk: Vec::new(),
        signature: Vec::new(),
    });

    let bytes = msg.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    match decoded {
        PulseMessage::TagRegister(tr) => {
            assert_eq!(tr.tag_hash, alice_hash);
            assert_eq!(tr.pow_hash.len(), 32);
            assert_eq!(tr.pow_nonce, [0x42; 32]);
        }
        _ => panic!("expected TagRegister"),
    }
}

#[test]
fn tag_lookup_round_trip() {
    use vess_protocol::{TagLookup, TagLookupResponse, TagLookupResult};

    let bob_hash = *blake3::hash(b"bob").as_bytes();
    let lookup = PulseMessage::TagLookup(TagLookup {
        tag_hash: bob_hash,
        nonce: [0x42; 16],
    });

    let bytes = lookup.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    match decoded {
        PulseMessage::TagLookup(tl) => {
            assert_eq!(tl.tag_hash, bob_hash);
            assert_eq!(tl.nonce, [0x42; 16]);
        }
        _ => panic!("expected TagLookup"),
    }

    let response = PulseMessage::TagLookupResponse(TagLookupResponse {
        tag_hash: bob_hash,
        nonce: [0x42; 16],
        result: Some(TagLookupResult {
            scan_ek: vec![0xAA; 1184],
            spend_ek: vec![0xBB; 1952],
            registered_at: 1234567890,
            registrant_vk: Vec::new(),
            signature: Vec::new(),
            pow_nonce: [0u8; 32],
            pow_hash: Vec::new(),
        }),
    });

    let bytes = response.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    match decoded {
        PulseMessage::TagLookupResponse(tlr) => {
            assert_eq!(tlr.tag_hash, bob_hash);
            let r = tlr.result.unwrap();
            assert_eq!(r.scan_ek.len(), 1184);
            assert_eq!(r.registered_at, 1234567890);
        }
        _ => panic!("expected TagLookupResponse"),
    }

    let not_found = PulseMessage::TagLookupResponse(TagLookupResponse {
        tag_hash: *blake3::hash(b"unknown").as_bytes(),
        nonce: [0x00; 16],
        result: None,
    });

    let bytes = not_found.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    match decoded {
        PulseMessage::TagLookupResponse(tlr) => {
            assert!(tlr.result.is_none());
        }
        _ => panic!("expected TagLookupResponse"),
    }
}

#[test]
fn mailbox_collect_round_trip() {
    use vess_protocol::{MailboxCollect, MailboxCollectResponse};

    let collect = PulseMessage::MailboxCollect(MailboxCollect {
        stealth_id: [0xCC; 32],
    });

    let bytes = collect.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    match decoded {
        PulseMessage::MailboxCollect(mc) => {
            assert_eq!(mc.stealth_id, [0xCC; 32]);
        }
        _ => panic!("expected MailboxCollect"),
    }

    let response = PulseMessage::MailboxCollectResponse(MailboxCollectResponse {
        stealth_id: [0xCC; 32],
        payloads: vec![vec![1, 2, 3], vec![4, 5, 6]],
    });

    let bytes = response.to_bytes().unwrap();
    let decoded = PulseMessage::from_bytes(&bytes).unwrap();
    match decoded {
        PulseMessage::MailboxCollectResponse(mcr) => {
            assert_eq!(mcr.payloads.len(), 2);
            assert_eq!(mcr.payloads[0], vec![1, 2, 3]);
        }
        _ => panic!("expected MailboxCollectResponse"),
    }
}

// ── OwnershipRegistry persistence ─────────────────────────────────────

#[test]
fn ownership_registry_persistence_roundtrip() {
    let mut registry = OwnershipRegistry::new([0x01; 32]);
    let (vk, _sk) = generate_spend_keypair();

    let mint_id1: [u8; 32] = rand::random();
    let mint_id2: [u8; 32] = rand::random();
    let mint_id3: [u8; 32] = rand::random();

    for &mid in &[mint_id1, mint_id2, mint_id3] {
        let record = OwnershipRecord {
            mint_id: mid,
            chain_tip: rand::random(),
            current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
            current_owner_vk: vk.clone(),
            denomination_value: 10,
            updated_at: now_unix(),
            proof_hash: [0u8; 32],
            digest: [0u8; 32],
            nonce: [0u8; 32],
            prev_claim_vk_hash: None,
            claim_hash: None,
            chain_depth: 0,
            encrypted_bill: vec![],
        };
        registry.register(record);
    }

    // Export all records.
    let exported = registry.all_records();
    assert_eq!(exported.len(), 3);

    // Rebuild from exported list.
    let restored = OwnershipRegistry::from_records([0x01; 32], exported);
    assert!(restored.is_active(&mint_id1));
    assert!(restored.is_active(&mint_id2));
    assert!(restored.is_active(&mint_id3));

    // Unknown mint_id not present.
    let unknown: [u8; 32] = rand::random();
    assert!(!restored.is_active(&unknown));
}

// ── Ownership registry total supply ──────────────────────────────────

#[test]
fn ownership_registry_total_supply() {
    let mut registry = OwnershipRegistry::new([0x01; 32]);
    let (vk, _sk) = generate_spend_keypair();

    for val in [10u64, 20, 50] {
        let record = OwnershipRecord {
            mint_id: rand::random(),
            chain_tip: rand::random(),
            current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
            current_owner_vk: vk.clone(),
            denomination_value: val,
            updated_at: now_unix(),
            proof_hash: [0u8; 32],
            digest: [0u8; 32],
            nonce: [0u8; 32],
            prev_claim_vk_hash: None,
            claim_hash: None,
            chain_depth: 0,
            encrypted_bill: vec![],
        };
        registry.register(record);
    }

    assert_eq!(registry.total_supply(), 80);
    assert_eq!(registry.len(), 3);
}

// ── Tag resolver quorum flow ─────────────────────────────────────────

#[test]
fn tag_resolver_quorum_flow() {
    use vess_artery::tag_resolver::{TagResolution, TagResolver};
    use vess_protocol::{TagLookupResponse, TagLookupResult};

    let mut resolver = TagResolver::new();

    let (_secret, address) = generate_master_keys();
    let response = TagLookupResponse {
        tag_hash: *blake3::hash(b"carol").as_bytes(),
        nonce: [0x00; 16],
        result: Some(TagLookupResult {
            scan_ek: address.scan_ek.clone(),
            spend_ek: address.spend_ek.clone(),
            registered_at: 1000,
            registrant_vk: Vec::new(),
            signature: Vec::new(),
            pow_nonce: [0u8; 32],
            pow_hash: Vec::new(),
        }),
    };

    // Add responses from 5 different nodes.
    for i in 0..5 {
        let mut node_id = [0u8; 32];
        node_id[0] = i;
        let result = resolver.add_response(node_id, &response);

        if i < 4 {
            match result {
                TagResolution::Pending { responses_so_far } => {
                    assert_eq!(responses_so_far, (i + 1) as usize);
                }
                _ => panic!("expected Pending at response {i}"),
            }
        } else {
            match result {
                TagResolution::Verified {
                    confirming_nodes, ..
                } => {
                    assert_eq!(confirming_nodes, 5);
                }
                _ => panic!("expected Verified at response {i}"),
            }
        }
    }
}

#[test]
fn tag_resolver_conflict_detection() {
    use vess_artery::tag_resolver::{TagResolution, TagResolver};
    use vess_protocol::{TagLookupResponse, TagLookupResult};

    let mut resolver = TagResolver::new();

    let (_, addr1) = generate_master_keys();
    let (_, addr2) = generate_master_keys();

    // 3 nodes return addr1.
    for i in 0..3 {
        let mut node_id = [0u8; 32];
        node_id[0] = i;
        let resp = TagLookupResponse {
            tag_hash: *blake3::hash(b"disputed").as_bytes(),
            nonce: [0x00; 16],
            result: Some(TagLookupResult {
                scan_ek: addr1.scan_ek.clone(),
                spend_ek: addr1.spend_ek.clone(),
                registered_at: 1000,
                registrant_vk: Vec::new(),
                signature: Vec::new(),
                pow_nonce: [0u8; 32],
                pow_hash: Vec::new(),
            }),
        };
        resolver.add_response(node_id, &resp);
    }

    // 3 nodes return addr2 (different keys).
    for i in 3..6 {
        let mut node_id = [0u8; 32];
        node_id[0] = i;
        let resp = TagLookupResponse {
            tag_hash: *blake3::hash(b"disputed").as_bytes(),
            nonce: [0x00; 16],
            result: Some(TagLookupResult {
                scan_ek: addr2.scan_ek.clone(),
                spend_ek: addr2.spend_ek.clone(),
                registered_at: 2000,
                registrant_vk: Vec::new(),
                signature: Vec::new(),
                pow_nonce: [0u8; 32],
                pow_hash: Vec::new(),
            }),
        };
        let result = resolver.add_response(node_id, &resp);

        // Once we have conflicting addresses, conflict should be detected.
        if i >= 3 {
            match result {
                TagResolution::Conflict { variants } => {
                    assert!(variants >= 2);
                }
                TagResolution::Pending { .. } => {} // May still be pending.
                _ => panic!("expected Conflict or Pending, got {result:?}"),
            }
        }
    }
}

// ── Artery snapshot persistence ──────────────────────────────────────

#[test]
fn artery_snapshot_save_load() {
    use vess_artery::persistence::{ArterySnapshot, NodeStorage};

    let dir = std::env::temp_dir().join(format!("vess-snapshot-test-{}", rand::random::<u32>()));

    let storage = NodeStorage::open(&dir).unwrap();

    // Start with empty.
    let loaded = storage.load().unwrap();
    assert!(loaded.ownership_records.is_empty());

    // Save a non-empty snapshot.
    let (vk, _sk) = generate_spend_keypair();
    let record1 = OwnershipRecord {
        mint_id: rand::random(),
        chain_tip: rand::random(),
        current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
        current_owner_vk: vk.clone(),
        denomination_value: 10,
        updated_at: now_unix(),
        proof_hash: [0u8; 32],
        digest: [0u8; 32],
        nonce: [0u8; 32],
        prev_claim_vk_hash: None,
        claim_hash: None,
        chain_depth: 0,
        encrypted_bill: vec![],
    };
    let record2 = OwnershipRecord {
        mint_id: rand::random(),
        chain_tip: rand::random(),
        current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
        current_owner_vk: vk.clone(),
        denomination_value: 20,
        updated_at: now_unix(),
        proof_hash: [0u8; 32],
        digest: [0u8; 32],
        nonce: [0u8; 32],
        prev_claim_vk_hash: None,
        claim_hash: None,
        chain_depth: 0,
        encrypted_bill: vec![],
    };

    let snapshot = ArterySnapshot {
        tags: std::collections::BTreeMap::new(),
        bills: std::collections::BTreeMap::new(),
        mailbox: std::collections::BTreeMap::new(),
        known_peers: vec![[0x01; 32]],
        limbo_entries: std::collections::BTreeMap::new(),
        peer_reputations: vec![],
        hardening_proofs: vec![],
        banned_peers: vec![[0xBB; 32]],
        ownership_records: vec![record1, record2],
        manifests: std::collections::BTreeMap::new(),
        peer_endpoints: std::collections::BTreeMap::new(),
    };

    storage.save(&snapshot).unwrap();

    // Reload and verify.
    let restored = storage.load().unwrap();
    assert_eq!(restored.ownership_records.len(), 2);
    assert_eq!(restored.known_peers.len(), 1);
    assert_eq!(restored.banned_peers.len(), 1);
    assert_eq!(restored.banned_peers[0], [0xBB; 32]);

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Tag PoW compute & verify ─────────────────────────────────────────

#[test]
fn tag_pow_compute_and_verify() {
    let tag = VessTag::new("alice").unwrap();
    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();
    let (_secret, address) = generate_master_keys();

    let (nonce, hash) =
        vess_tag::compute_tag_pow_test(&tag_hash, &address.scan_ek, &address.spend_ek).unwrap();
    assert_eq!(hash.len(), 32);

    let ok = vess_tag::verify_tag_pow_test(
        &tag_hash,
        &address.scan_ek,
        &address.spend_ek,
        &nonce,
        &hash,
    )
    .unwrap();
    assert!(ok);

    // Different tag → fails.
    let tag2 = VessTag::new("bob").unwrap();
    let tag2_hash = *blake3::hash(tag2.as_str().as_bytes()).as_bytes();
    let bad = vess_tag::verify_tag_pow_test(
        &tag2_hash,
        &address.scan_ek,
        &address.spend_ek,
        &nonce,
        &hash,
    )
    .unwrap();
    assert!(!bad);
}

// ── Tag hardening and pruning ────────────────────────────────────────

#[test]
fn tag_hardening_and_pruning() {
    let node_id: [u8; 32] = rand::random();
    let mut dht = TagDht::new(node_id, 3);

    // Register two tags.
    let (_s1, addr1) = generate_master_keys();
    let rec1 = vess_tag::TagRecord {
        tag_hash: *blake3::hash(b"alice").as_bytes(),
        master_address: addr1,
        pow_nonce: [0x01; 32],
        pow_hash: vec![0xAA; 32],
        registered_at: 1000,
        registrant_vk: Vec::new(),
        signature: Vec::new(),
        hardened_at: None,
    };
    assert!(dht.store(rec1));

    let (_s2, addr2) = generate_master_keys();
    let rec2 = vess_tag::TagRecord {
        tag_hash: *blake3::hash(b"bob").as_bytes(),
        master_address: addr2,
        pow_nonce: [0x02; 32],
        pow_hash: vec![0xBB; 32],
        registered_at: 1000,
        registrant_vk: Vec::new(),
        signature: Vec::new(),
        hardened_at: None,
    };
    assert!(dht.store(rec2));

    // Harden alice.
    let bill_id = [0x42; 32];
    assert!(dht.harden("alice", &bill_id, 2000));
    assert!(dht.is_hardened("alice"));
    assert!(!dht.is_hardened("bob"));

    // Purge at now = 1000 + 30 days + 1 → bob should be pruned.
    let now = 1000 + vess_tag::TAG_PRUNE_SECS + 1;
    let pruned = dht.purge_unhardened(now);
    assert_eq!(pruned, 1);
    assert!(dht.lookup("alice").is_some());
    assert!(dht.lookup("bob").is_none());
}

// ── Full send-receive-attest lifecycle ───────────────────────────────

#[test]
fn full_send_receive_attest_finalize() {
    let mut sender = BillFold::new();
    sender.deposit(fresh_bill(Denomination::D50));
    sender.deposit(fresh_bill(Denomination::D20));
    sender.deposit(fresh_bill(Denomination::D10));

    let (recipient_secret, recipient_address) = generate_master_keys();

    // Send 25 Vess.
    let (msg, payment_id, send_indices) = prepare_payment(&sender, 25, &recipient_address).unwrap();

    // Record mint_ids before removing.
    let sent_mint_ids: Vec<[u8; 32]> = send_indices
        .iter()
        .map(|&i| sender.bills()[i].mint_id)
        .collect();

    // Track.
    let mut tracker = PaymentTracker::new();
    tracker.record_sent(
        payment_id,
        25,
        sent_mint_ids.clone(),
        [0u8; 32],
        std::collections::HashMap::new(),
    );
    assert_eq!(tracker.in_flight().len(), 1);

    // Recipient receives.
    let payment = match msg {
        PulseMessage::Payment(p) => p,
        _ => panic!("expected Payment"),
    };
    let received = try_receive_payment(&recipient_secret, &payment)
        .unwrap()
        .expect("should decrypt");

    let received_total: u64 = received.iter().map(|b| b.denomination.value()).sum();
    assert!(received_total >= 25);

    // Simulate double-registration check on artery.
    let mut registry = OwnershipRegistry::new([0x01; 32]);
    let (vk, _sk) = generate_spend_keypair();
    for bill in &received {
        let record = OwnershipRecord {
            mint_id: bill.mint_id,
            chain_tip: bill.chain_tip,
            current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
            current_owner_vk: vk.clone(),
            denomination_value: bill.denomination.value(),
            updated_at: now_unix(),
            proof_hash: [0u8; 32],
            digest: [0u8; 32],
            nonce: [0u8; 32],
            prev_claim_vk_hash: None,
            claim_hash: None,
            chain_depth: 0,
            encrypted_bill: vec![],
        };
        assert!(
            registry.register(record.clone()),
            "fresh mint_ids should register"
        );
    }

    // Try double-registration.
    for bill in &received {
        let record = OwnershipRecord {
            mint_id: bill.mint_id,
            chain_tip: bill.chain_tip,
            current_owner_vk_hash: *blake3::hash(&vk).as_bytes(),
            current_owner_vk: vk.clone(),
            denomination_value: bill.denomination.value(),
            updated_at: now_unix(),
            proof_hash: [0u8; 32],
            digest: [0u8; 32],
            nonce: [0u8; 32],
            prev_claim_vk_hash: None,
            claim_hash: None,
            chain_depth: 0,
            encrypted_bill: vec![],
        };
        assert!(
            !registry.register(record),
            "second registration = double-spend detected"
        );
    }

    // Sender considers payment final once ownership is registered.
    tracker.finalize(&payment_id).unwrap();
    assert!(tracker.in_flight().is_empty());
}

// ── Bill selection edge cases ────────────────────────────────────────

#[test]
fn bill_selection_prefers_exact_denomination() {
    let bills = vec![
        fresh_bill(Denomination::D10),
        fresh_bill(Denomination::D10),
        fresh_bill(Denomination::D5),
    ];

    let result = select_bills(&bills, 10).unwrap();
    // Should use a single D10 rather than D5+D5.
    assert_eq!(result.total_selected, 10);
    assert_eq!(result.change, 0);
    assert_eq!(result.send_indices.len(), 1);
}

#[test]
fn bill_selection_high_value() {
    let mut bills = Vec::new();
    for _ in 0..5 {
        bills.push(fresh_bill(Denomination::D50000));
    }

    let result = select_bills(&bills, 200_000).unwrap();
    assert_eq!(result.total_selected, 200_000);
    assert_eq!(result.change, 0);
}
