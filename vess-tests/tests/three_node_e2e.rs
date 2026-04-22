//! End-to-end test: tag registration → mint → send → receive → claim → forward.
//!
//! Requires the `test-mint` feature on vess-foundry (enabled by default
//! in vess-tests/Cargo.toml) so minting completes in seconds rather than
//! minutes.
//!
//! Uses VessNode instances to simulate a live artery network: one
//! artery-like node (with OwnershipRegistry + TagDht + proof verification)
//! and three client nodes for Alice, Bob, and Charlie.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vess_artery::ownership_registry::OwnershipRecord;
use vess_artery::OwnershipRegistry;
use vess_artery::TagDht;
use vess_foundry::spend_auth;
use vess_foundry::Denomination;
use vess_kloak::billfold::{BillFold, SpendCredential};
use vess_kloak::payment::{
    claim_transfer_bills, cleanup_rejected_bills, extract_mint_ids_from_claims,
    prepare_payment_with_transfer, try_decrypt_transfer_payload, DecryptedTransfer,
};
use vess_protocol::{
    OwnershipClaim, OwnershipGenesis, PulseMessage, RegistryQuery, RegistryQueryResponse,
    TagLookup, TagLookupResponse, TagLookupResult, TagRegister,
};
use vess_stealth::{generate_master_keys, MasterStealthAddress};
use vess_tag::TagRecord;
use vess_vascular::VessNode;

/// A lightweight test participant: stealth keys + spend credentials + billfold.
struct Participant {
    name: String,
    secret: vess_stealth::StealthSecretKey,
    address: vess_stealth::MasterStealthAddress,
    billfold: BillFold,
    credentials: HashMap<[u8; 32], SpendCredential>,
}

impl Participant {
    fn new(name: &str) -> Self {
        let (secret, address) = generate_master_keys();
        Self {
            name: name.to_string(),
            secret,
            address,
            billfold: BillFold::new(),
            credentials: HashMap::new(),
        }
    }

    /// Build a TagRegister message using test-friendly PoW parameters.
    fn tag_register_msg(&self) -> PulseMessage {
        let tag_hash = *blake3::hash(self.name.as_bytes()).as_bytes();
        let (pow_nonce, pow_hash) = vess_tag::compute_tag_pow_test(
            &tag_hash,
            &self.address.scan_ek,
            &self.address.spend_ek,
        )
        .expect("compute test PoW");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PulseMessage::TagRegister(TagRegister {
            tag_hash,
            scan_ek: self.address.scan_ek.to_vec(),
            spend_ek: self.address.spend_ek.to_vec(),
            pow_nonce,
            pow_hash,
            timestamp: now,
            registrant_vk: Vec::new(),
            signature: Vec::new(),
        })
    }
}

#[tokio::test]
async fn three_node_mint_send_claim() {
    // ── 1. Spin up an artery-like VessNode with a real OwnershipRegistry ─
    let artery_node = VessNode::spawn().await.unwrap();
    artery_node.wait_online().await;
    let artery_addr = artery_node.addr();

    let node_id_bytes: [u8; 32] = *blake3::hash(artery_node.id().as_bytes()).as_bytes();
    let registry = Arc::new(Mutex::new(OwnershipRegistry::new(node_id_bytes)));
    let tag_dht = Arc::new(Mutex::new(TagDht::new(node_id_bytes, 3)));

    // Spawn the artery handler — mirrors the real node_runner logic for
    // OwnershipGenesis, OwnershipClaim, and RegistryQuery messages.
    let reg = registry.clone();
    let tags = tag_dht.clone();
    let artery_handle = tokio::spawn({
        let artery_node = artery_node.clone();
        async move {
            artery_node
                .listen_messages_with_response(move |_peer, msg| match msg {
                    PulseMessage::OwnershipGenesis(og) => {
                        let mut state = reg.lock().unwrap();
                        handle_ownership_genesis(&mut state, og);
                        None
                    }
                    PulseMessage::OwnershipClaim(oc) => {
                        let mut state = reg.lock().unwrap();
                        handle_ownership_claim(&mut state, oc);
                        None
                    }
                    PulseMessage::RegistryQuery(rq) => {
                        let state = reg.lock().unwrap();
                        let active = rq.mint_ids.iter().map(|mid| state.is_active(mid)).collect();
                        Some(PulseMessage::RegistryQueryResponse(RegistryQueryResponse {
                            active,
                        }))
                    }
                    PulseMessage::TagRegister(tr) => {
                        handle_tag_register(&tags, tr);
                        None
                    }
                    PulseMessage::TagLookup(tl) => {
                        let dht = tags.lock().unwrap();
                        let result =
                            dht.lookup_by_hash(&tl.tag_hash)
                                .map(|record| TagLookupResult {
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
                            result,
                        }))
                    }
                    _ => None,
                })
                .await
                .ok();
        }
    });

    // ── 2. Create three participants: Alice, Bob, Charlie ───────────
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");
    let mut charlie = Participant::new("charlie");

    // ── 3. Spin up client nodes and register tags ───────────────────
    let client_a = VessNode::spawn().await.unwrap();
    client_a.wait_online().await;
    let client_b = VessNode::spawn().await.unwrap();
    client_b.wait_online().await;
    let client_c = VessNode::spawn().await.unwrap();
    client_c.wait_online().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    client_a
        .send_message(artery_addr.clone(), &alice.tag_register_msg())
        .await
        .expect("register tag: alice");
    client_b
        .send_message(artery_addr.clone(), &bob.tag_register_msg())
        .await
        .expect("register tag: bob");
    client_c
        .send_message(artery_addr.clone(), &charlie.tag_register_msg())
        .await
        .expect("register tag: charlie");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    println!("Tags registered: +alice, +bob, +charlie");

    // ── 4. Alice mints a D1 bill ────────────────────────────────────
    //    With test-mint: ~1 MiB scratchpad, 1024 iterations, 4-bit difficulty.
    let (alice_spend_vk, alice_spend_sk) = spend_auth::generate_spend_keypair();
    let alice_vk_hash = spend_auth::vk_hash(&alice_spend_vk);

    println!("Minting a D1 bill (test-mint params)…");
    let start = std::time::Instant::now();
    let vk_hash_copy = alice_vk_hash;
    let (bill, proof_bytes) = tokio::task::spawn_blocking(move || {
        vess_foundry::mint::mint_blocking(Denomination::D1, &vk_hash_copy)
    })
    .await
    .unwrap();
    let elapsed = start.elapsed();
    println!("Minted in {elapsed:.2?}");

    // Deposit into Alice's billfold.
    let mint_id = bill.mint_id;
    alice.billfold.deposit_with_credentials(
        bill.clone(),
        SpendCredential {
            spend_vk: alice_spend_vk.clone(),
            spend_sk: alice_spend_sk.clone(),
        },
    );
    alice.credentials.insert(
        mint_id,
        SpendCredential {
            spend_vk: alice_spend_vk.clone(),
            spend_sk: alice_spend_sk.clone(),
        },
    );
    assert_eq!(alice.billfold.balance(), 1);

    // ── 5. Alice broadcasts OwnershipGenesis to the artery ──────────
    let genesis_msg = PulseMessage::OwnershipGenesis(OwnershipGenesis {
        mint_id: bill.mint_id,
        chain_tip: bill.chain_tip,
        owner_vk_hash: alice_vk_hash,
        owner_vk: alice_spend_vk.clone(),
        denomination_value: Denomination::D1.value(),
        proof: proof_bytes,
        digest: bill.digest,
        hops_remaining: 3,
        chain_depth: 0,
        output_index: 0,
    });

    client_a
        .send_message(artery_addr.clone(), &genesis_msg)
        .await
        .expect("send OwnershipGenesis");

    // Give the artery time to process the genesis.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Verify the genesis was registered.
    let query = PulseMessage::RegistryQuery(RegistryQuery {
        mint_ids: vec![bill.mint_id],
    });
    let resp = client_a
        .send_message_with_response(artery_addr.clone(), &query)
        .await
        .expect("registry query");

    match resp {
        Some(PulseMessage::RegistryQueryResponse(rqr)) => {
            assert_eq!(rqr.active.len(), 1);
            assert!(
                rqr.active[0],
                "bill should be registered after OwnershipGenesis"
            );
        }
        other => panic!("expected RegistryQueryResponse, got: {other:?}"),
    }
    println!("OwnershipGenesis verified on artery.");

    // ── 6. Look up Bob's tag to resolve his stealth address ─────────
    let bob_lookup = PulseMessage::TagLookup(TagLookup {
        tag_hash: *blake3::hash(b"bob").as_bytes(),
        nonce: [0u8; 16],
    });
    let bob_resp = client_a
        .send_message_with_response(artery_addr.clone(), &bob_lookup)
        .await
        .expect("tag lookup: bob");
    let bob_address = match bob_resp {
        Some(PulseMessage::TagLookupResponse(tlr)) => {
            let res = tlr.result.expect("bob tag should be registered");
            MasterStealthAddress {
                scan_ek: res.scan_ek,
                spend_ek: res.spend_ek,
            }
        }
        other => panic!("expected TagLookupResponse, got: {other:?}"),
    };

    // ── 7. Alice sends payment to Bob ───────────────────────────────
    let (payment_msg, _payment_id, send_indices) =
        prepare_payment_with_transfer(&alice.billfold, 1, &bob_address, &alice.credentials, None)
            .expect("prepare payment Alice → Bob");

    // Remove sent bills from Alice's billfold.
    let sent_mint_ids: Vec<[u8; 32]> = send_indices
        .iter()
        .map(|&i| alice.billfold.bills()[i].mint_id)
        .collect();
    for mid in &sent_mint_ids {
        alice.billfold.withdraw(mid);
    }
    assert_eq!(alice.billfold.balance(), 0);

    // ── 8. Bob receives and decrypts the payment ────────────────────
    let stealth_payload = match &payment_msg {
        PulseMessage::Payment(p) => &p.stealth_payload,
        _ => panic!("expected Payment message"),
    };

    let decrypted = try_decrypt_transfer_payload(&bob.secret, stealth_payload)
        .expect("decrypt should not error")
        .expect("should decrypt (view tag match)");

    let (transfer_payload, stealth_id) = match decrypted {
        DecryptedTransfer::WithAuth(tp, sid) => (tp, sid),
    };

    assert_eq!(transfer_payload.bills.len(), 1);
    assert_eq!(transfer_payload.bills[0].mint_id, mint_id);

    // ── 9. Bob claims the transfer ──────────────────────────────────
    let claim_result =
        claim_transfer_bills(transfer_payload, stealth_id).expect("claim transfer bills");

    assert_eq!(claim_result.claimed.len(), 1);
    assert_eq!(claim_result.ownership_claims.len(), 1);

    // Deposit into Bob's billfold.
    for cb in &claim_result.claimed {
        bob.billfold.deposit_with_credentials(
            cb.bill.clone(),
            SpendCredential {
                spend_vk: cb.spend_vk.clone(),
                spend_sk: cb.spend_sk.clone(),
            },
        );
        bob.credentials.insert(
            cb.bill.mint_id,
            SpendCredential {
                spend_vk: cb.spend_vk.clone(),
                spend_sk: cb.spend_sk.clone(),
            },
        );
    }
    assert_eq!(bob.billfold.balance(), 1);

    // ── 10. Bob broadcasts OwnershipClaim and auto-verifies ──────────
    let bill_ids_to_verify = extract_mint_ids_from_claims(&claim_result.ownership_claims);

    for claim_msg in &claim_result.ownership_claims {
        client_b
            .send_message(artery_addr.clone(), claim_msg)
            .await
            .expect("send OwnershipClaim (Bob)");
    }

    // Wait for DHT convergence
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Automatically verify and clean up rejected bills
    let query = PulseMessage::RegistryQuery(RegistryQuery {
        mint_ids: bill_ids_to_verify.clone(),
    });
    let resp = client_b
        .send_message_with_response(artery_addr.clone(), &query)
        .await
        .expect("registry query after Bob claim");

    match resp {
        Some(PulseMessage::RegistryQueryResponse(rqr)) => {
            assert!(
                rqr.active[0],
                "bill should still be active after ownership transfer"
            );
            // Silently remove any rejected bills
            let removed =
                cleanup_rejected_bills(&mut bob.billfold, &bill_ids_to_verify, &rqr.active);
            if !removed.is_empty() {
                eprintln!(
                    "WARNING: {} bills were rejected and removed from wallet",
                    removed.len()
                );
            }
        }
        other => panic!("expected RegistryQueryResponse, got: {other:?}"),
    }
    println!("OwnershipClaim (Alice → Bob) verified on artery.");

    // ── 11. Look up Charlie's tag to resolve his stealth address ────
    let charlie_lookup = PulseMessage::TagLookup(TagLookup {
        tag_hash: *blake3::hash(b"charlie").as_bytes(),
        nonce: [1u8; 16],
    });
    let charlie_resp = client_b
        .send_message_with_response(artery_addr.clone(), &charlie_lookup)
        .await
        .expect("tag lookup: charlie");
    let charlie_address = match charlie_resp {
        Some(PulseMessage::TagLookupResponse(tlr)) => {
            let res = tlr.result.expect("charlie tag should be registered");
            MasterStealthAddress {
                scan_ek: res.scan_ek,
                spend_ek: res.spend_ek,
            }
        }
        other => panic!("expected TagLookupResponse, got: {other:?}"),
    };

    // ── 12. Bob sends payment to Charlie ────────────────────────────
    let (payment_msg_2, _pid2, send_indices_2) =
        prepare_payment_with_transfer(&bob.billfold, 1, &charlie_address, &bob.credentials, None)
            .expect("prepare payment Bob → Charlie");

    let sent_mint_ids_2: Vec<[u8; 32]> = send_indices_2
        .iter()
        .map(|&i| bob.billfold.bills()[i].mint_id)
        .collect();
    for mid in &sent_mint_ids_2 {
        bob.billfold.withdraw(mid);
    }
    assert_eq!(bob.billfold.balance(), 0);

    // ── 13. Charlie receives, decrypts, and claims ─────────────────
    let stealth_payload_2 = match &payment_msg_2 {
        PulseMessage::Payment(p) => &p.stealth_payload,
        _ => panic!("expected Payment message"),
    };

    let decrypted_2 = try_decrypt_transfer_payload(&charlie.secret, stealth_payload_2)
        .expect("decrypt should not error")
        .expect("should decrypt (view tag match)");

    let (tp2, sid2) = match decrypted_2 {
        DecryptedTransfer::WithAuth(tp, sid) => (tp, sid),
    };

    let claim_result_2 = claim_transfer_bills(tp2, sid2).expect("claim transfer bills (Charlie)");

    for cb in &claim_result_2.claimed {
        charlie.billfold.deposit_with_credentials(
            cb.bill.clone(),
            SpendCredential {
                spend_vk: cb.spend_vk.clone(),
                spend_sk: cb.spend_sk.clone(),
            },
        );
        charlie.credentials.insert(
            cb.bill.mint_id,
            SpendCredential {
                spend_vk: cb.spend_vk.clone(),
                spend_sk: cb.spend_sk.clone(),
            },
        );
    }
    assert_eq!(charlie.billfold.balance(), 1);

    // ── 14. Charlie broadcasts OwnershipClaim and auto-verifies ──────
    let bill_ids_to_verify_2 = extract_mint_ids_from_claims(&claim_result_2.ownership_claims);

    for claim_msg in &claim_result_2.ownership_claims {
        client_c
            .send_message(artery_addr.clone(), claim_msg)
            .await
            .expect("send OwnershipClaim (Charlie)");
    }

    // Wait for DHT convergence
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // ── 15. Auto-verify and cleanup ─────────────────────────────────
    let query_2 = PulseMessage::RegistryQuery(RegistryQuery {
        mint_ids: bill_ids_to_verify_2.clone(),
    });
    let resp = client_c
        .send_message_with_response(artery_addr.clone(), &query_2)
        .await
        .expect("final registry query");

    match resp {
        Some(PulseMessage::RegistryQueryResponse(rqr)) => {
            assert!(
                rqr.active[0],
                "bill should still be active after second transfer"
            );
            // Silently remove any rejected bills
            let removed =
                cleanup_rejected_bills(&mut charlie.billfold, &bill_ids_to_verify_2, &rqr.active);
            if !removed.is_empty() {
                eprintln!(
                    "WARNING: {} bills were rejected and removed from wallet",
                    removed.len()
                );
            }
        }
        other => panic!("expected RegistryQueryResponse, got: {other:?}"),
    }

    // Also verify the actual ownership state from the Arc<Mutex<>> registry.
    {
        let reg = registry.lock().unwrap();
        let record = reg.get(&mint_id).expect("record should exist");
        let charlie_vk_hash = spend_auth::vk_hash(&claim_result_2.claimed[0].spend_vk);
        assert_eq!(
            record.current_owner_vk_hash, charlie_vk_hash,
            "final owner should be Charlie"
        );
        assert_eq!(
            record.chain_depth, 2,
            "depth should be 2 (genesis→bob→charlie)"
        );
    }

    println!("OwnershipClaim (Bob → Charlie) verified on artery.");
    println!(
        "Full pipeline: tags → mint → genesis → lookup → send → claim → lookup → send → claim ✓"
    );

    // ── Cleanup ─────────────────────────────────────────────────────
    client_a.shutdown().await;
    client_b.shutdown().await;
    client_c.shutdown().await;
    artery_node.shutdown().await;
    artery_handle.abort();
}

// ── Artery handler helpers ──────────────────────────────────────────
// Simplified versions of the real node_runner handlers, exercising the
// same proof-verification and ownership-chain logic.

fn handle_tag_register(dht: &Arc<Mutex<TagDht>>, tr: TagRegister) {
    let tag_hash = tr.tag_hash;
    let addr = MasterStealthAddress {
        scan_ek: tr.scan_ek.clone(),
        spend_ek: tr.spend_ek.clone(),
    };

    let ok = vess_tag::verify_tag_pow_test(
        &tag_hash,
        &tr.scan_ek,
        &tr.spend_ek,
        &tr.pow_nonce,
        &tr.pow_hash,
    )
    .expect("tag PoW verification error");
    assert!(ok, "tag PoW verification failed for hash {:?}", tag_hash);

    let record = TagRecord {
        tag_hash,
        master_address: addr,
        pow_nonce: tr.pow_nonce,
        pow_hash: tr.pow_hash,
        registered_at: tr.timestamp,
        registrant_vk: tr.registrant_vk,
        signature: tr.signature,
        hardened_at: None,
    };

    let mut dht = dht.lock().unwrap();
    let stored = dht.store(record);
    assert!(stored, "tag store should succeed for hash {:?}", tag_hash);
}

fn handle_ownership_genesis(registry: &mut OwnershipRegistry, og: OwnershipGenesis) {
    if registry.is_active(&og.mint_id) {
        return;
    }

    // Verify STARK proof — supports single, aggregate, and sampled.
    let proof_nonce: [u8; 32];
    if let Ok(iop_proof) = vess_foundry::proof::deserialize_proof(&og.proof) {
        if let Err(e) = vess_foundry::proof::verify_proof(&iop_proof, &og.digest) {
            panic!("STARK verification failed: {e:?}");
        }
        if iop_proof.owner_vk_hash != og.owner_vk_hash {
            panic!("proof owner_vk_hash mismatch");
        }
        // Verify denomination matches the proof.
        assert_eq!(
            iop_proof.denomination.value(),
            og.denomination_value,
            "denomination mismatch: proof={}, claimed={}",
            iop_proof.denomination.value(),
            og.denomination_value,
        );
        // Verify PoW difficulty.
        let required_diff = vess_foundry::mint::difficulty_bits_for(iop_proof.denomination);
        assert!(
            vess_foundry::mint::meets_difficulty_pub(&og.digest, required_diff),
            "digest does not meet difficulty ({required_diff} bits)",
        );
        proof_nonce = iop_proof.nonce;
    } else if let Ok(agg) = vess_foundry::proof::AggregateProof::deserialize(&og.proof) {
        if let Err(e) =
            vess_foundry::proof::verify_aggregate_proof(&agg, &og.digest, og.denomination_value)
        {
            panic!("aggregate proof verification failed: {e:?}");
        }
        if agg.owner_vk_hash != og.owner_vk_hash {
            panic!("aggregate proof owner_vk_hash mismatch");
        }
        let mut h = blake3::Hasher::new();
        h.update(b"vess-aggregate-nonce-v0");
        for sub in &agg.d1_proofs {
            if let Ok(p) = vess_foundry::proof::deserialize_proof(sub) {
                h.update(&p.nonce);
            }
        }
        proof_nonce = *h.finalize().as_bytes();
    } else if let Ok(sap) = vess_foundry::proof::SampledAggregateProof::deserialize(&og.proof) {
        if let Err(e) =
            vess_foundry::proof::verify_sampled_aggregate(&sap, &og.digest, og.denomination_value)
        {
            panic!("sampled aggregate proof verification failed: {e:?}");
        }
        if sap.owner_vk_hash != og.owner_vk_hash {
            panic!("sampled aggregate proof owner_vk_hash mismatch");
        }
        proof_nonce = sap.nonce_tree_root;
    } else {
        panic!("malformed proof");
    }

    let claimed_vk_hash = vess_foundry::spend_auth::vk_hash(&og.owner_vk);
    assert_eq!(claimed_vk_hash, og.owner_vk_hash, "vk_hash mismatch");

    let expected_mint_id = vess_foundry::derive_mint_id(&og.digest, &proof_nonce);
    assert_eq!(expected_mint_id, og.mint_id, "mint_id derivation mismatch");

    let expected_tip = vess_foundry::genesis_chain_tip(&og.mint_id, &og.owner_vk_hash);
    assert_eq!(expected_tip, og.chain_tip, "chain_tip mismatch");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    registry.register(OwnershipRecord {
        mint_id: og.mint_id,
        chain_tip: og.chain_tip,
        current_owner_vk_hash: og.owner_vk_hash,
        current_owner_vk: og.owner_vk,
        denomination_value: og.denomination_value,
        updated_at: now,
        proof_hash: blake3::hash(&og.proof).into(),
        digest: og.digest,
        nonce: proof_nonce,
        prev_claim_vk_hash: None,
        claim_hash: None,
        chain_depth: 0,
        encrypted_bill: vec![],
    });
}

fn handle_ownership_claim(registry: &mut OwnershipRegistry, oc: OwnershipClaim) {
    // Verify transfer signature.
    let transfer_msg =
        vess_foundry::spend_auth::transfer_message(&oc.mint_id, &oc.stealth_id, oc.timestamp);
    match vess_foundry::spend_auth::verify_spend(&oc.prev_owner_vk, &transfer_msg, &oc.transfer_sig)
    {
        Ok(true) => {}
        Ok(false) => panic!("invalid transfer signature"),
        Err(e) => panic!("transfer signature error: {e}"),
    }

    // Verify new_owner_vk_hash.
    let computed_new_hash = vess_foundry::spend_auth::vk_hash(&oc.new_owner_vk);
    assert_eq!(
        computed_new_hash, oc.new_owner_vk_hash,
        "new_owner_vk_hash mismatch"
    );

    // Verify chain_tip advancement and chain_depth.
    if let Some(rec) = registry.get(&oc.mint_id) {
        let prev_vk_hash = vess_foundry::spend_auth::vk_hash(&oc.prev_owner_vk);
        if prev_vk_hash == rec.current_owner_vk_hash {
            assert_eq!(
                oc.chain_depth,
                rec.chain_depth + 1,
                "chain_depth must be current+1 (got {}, expected {})",
                oc.chain_depth,
                rec.chain_depth + 1,
            );
            let expected_tip = vess_foundry::advance_chain_tip(
                &rec.chain_tip,
                &oc.new_owner_vk_hash,
                &oc.transfer_sig,
            );
            assert_eq!(expected_tip, oc.new_chain_tip, "chain_tip mismatch");
        }
    }

    // Update registry (deeper chain wins).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(rec) = registry.get_mut(&oc.mint_id) {
        if oc.chain_depth > rec.chain_depth
            || (oc.chain_depth == rec.chain_depth
                && vess_foundry::spend_auth::vk_hash(&oc.prev_owner_vk)
                    == rec.current_owner_vk_hash)
        {
            rec.chain_tip = oc.new_chain_tip;
            rec.current_owner_vk_hash = oc.new_owner_vk_hash;
            rec.current_owner_vk = oc.new_owner_vk;
            rec.chain_depth = oc.chain_depth;
            rec.updated_at = now;
        }
    }
}
