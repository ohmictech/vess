//! End-to-end test: mint → register → send → receive → claim → forward.
//!
//! Requires the `test-mint` feature on vess-foundry (enabled by default
//! in vess-tests/Cargo.toml) so minting completes in seconds rather than
//! minutes.
//!
//! Uses VessNode instances to simulate a live artery network: one
//! artery-like node (with OwnershipRegistry + proof verification) and
//! three client nodes for Alice, Bob, and Charlie.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vess_artery::OwnershipRegistry;
use vess_artery::ownership_registry::OwnershipRecord;
use vess_foundry::spend_auth;
use vess_foundry::Denomination;
use vess_kloak::billfold::{BillFold, SpendCredential};
use vess_kloak::payment::{
    claim_transfer_bills, prepare_payment_with_transfer, try_decrypt_transfer_payload,
    DecryptedTransfer,
};
use vess_protocol::{
    OwnershipClaim, OwnershipGenesis, PulseMessage, RegistryQuery, RegistryQueryResponse,
};
use vess_stealth::generate_master_keys;
use vess_vascular::VessNode;

/// A lightweight test participant: stealth keys + spend credentials + billfold.
struct Participant {
    secret: vess_stealth::StealthSecretKey,
    address: vess_stealth::MasterStealthAddress,
    billfold: BillFold,
    credentials: HashMap<[u8; 32], SpendCredential>,
}

impl Participant {
    fn new() -> Self {
        let (secret, address) = generate_master_keys();
        Self {
            secret,
            address,
            billfold: BillFold::new(),
            credentials: HashMap::new(),
        }
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

    // Spawn the artery handler — mirrors the real node_runner logic for
    // OwnershipGenesis, OwnershipClaim, and RegistryQuery messages.
    let reg = registry.clone();
    let artery_handle = tokio::spawn({
        let artery_node = artery_node.clone();
        async move {
            artery_node.listen_messages_with_response(move |_peer, msg| {
                let mut state = reg.lock().unwrap();
                match msg {
                    PulseMessage::OwnershipGenesis(og) => {
                        handle_ownership_genesis(&mut state, og);
                        None
                    }
                    PulseMessage::OwnershipClaim(oc) => {
                        handle_ownership_claim(&mut state, oc);
                        None
                    }
                    PulseMessage::RegistryQuery(rq) => {
                        let active = rq.mint_ids.iter()
                            .map(|mid| state.is_active(mid))
                            .collect();
                        Some(PulseMessage::RegistryQueryResponse(RegistryQueryResponse { active }))
                    }
                    _ => None,
                }
            }).await.ok();
        }
    });

    // ── 2. Create three participants: Alice, Bob, Charlie ───────────
    let mut alice = Participant::new();
    let mut bob = Participant::new();
    let mut charlie = Participant::new();

    // ── 3. Alice mints a D1 bill ────────────────────────────────────
    //    With test-mint: ~1 MiB scratchpad, 1024 iterations, 4-bit difficulty.
    let (alice_spend_vk, alice_spend_sk) = spend_auth::generate_spend_keypair();
    let alice_vk_hash = spend_auth::vk_hash(&alice_spend_vk);

    println!("Minting a D1 bill (test-mint params)…");
    let start = std::time::Instant::now();
    let vk_hash_copy = alice_vk_hash;
    let (bill, proof_bytes) =
        tokio::task::spawn_blocking(move || {
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
    alice.credentials.insert(mint_id, SpendCredential {
        spend_vk: alice_spend_vk.clone(),
        spend_sk: alice_spend_sk.clone(),
    });
    assert_eq!(alice.billfold.balance(), 1);

    // ── 4. Alice broadcasts OwnershipGenesis to the artery ──────────
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
    });

    let client_a = VessNode::spawn().await.unwrap();
    client_a.wait_online().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

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
            assert!(rqr.active[0], "bill should be registered after OwnershipGenesis");
        }
        other => panic!("expected RegistryQueryResponse, got: {other:?}"),
    }
    println!("OwnershipGenesis verified on artery.");

    // ── 5. Alice sends payment to Bob ───────────────────────────────
    let (payment_msg, _payment_id, send_indices) = prepare_payment_with_transfer(
        &alice.billfold,
        1,
        &bob.address,
        &alice.credentials,
    )
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

    // ── 6. Bob receives and decrypts the payment ────────────────────
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

    // ── 7. Bob claims the transfer ──────────────────────────────────
    let claim_result = claim_transfer_bills(transfer_payload, stealth_id)
        .expect("claim transfer bills");

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
        bob.credentials.insert(cb.bill.mint_id, SpendCredential {
            spend_vk: cb.spend_vk.clone(),
            spend_sk: cb.spend_sk.clone(),
        });
    }
    assert_eq!(bob.billfold.balance(), 1);

    // ── 8. Bob broadcasts OwnershipClaim to the artery ──────────────
    let client_b = VessNode::spawn().await.unwrap();
    client_b.wait_online().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    for claim_msg in &claim_result.ownership_claims {
        client_b
            .send_message(artery_addr.clone(), claim_msg)
            .await
            .expect("send OwnershipClaim (Bob)");
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Verify ownership transferred to Bob on artery.
    let resp = client_b
        .send_message_with_response(artery_addr.clone(), &query)
        .await
        .expect("registry query after Bob claim");

    match resp {
        Some(PulseMessage::RegistryQueryResponse(rqr)) => {
            assert!(rqr.active[0], "bill should still be active after ownership transfer");
        }
        other => panic!("expected RegistryQueryResponse, got: {other:?}"),
    }
    println!("OwnershipClaim (Alice → Bob) verified on artery.");

    // ── 9. Bob sends payment to Charlie ─────────────────────────────
    let (payment_msg_2, _pid2, send_indices_2) = prepare_payment_with_transfer(
        &bob.billfold,
        1,
        &charlie.address,
        &bob.credentials,
    )
    .expect("prepare payment Bob → Charlie");

    let sent_mint_ids_2: Vec<[u8; 32]> = send_indices_2
        .iter()
        .map(|&i| bob.billfold.bills()[i].mint_id)
        .collect();
    for mid in &sent_mint_ids_2 {
        bob.billfold.withdraw(mid);
    }
    assert_eq!(bob.billfold.balance(), 0);

    // ── 10. Charlie receives, decrypts, and claims ──────────────────
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

    let claim_result_2 = claim_transfer_bills(tp2, sid2)
        .expect("claim transfer bills (Charlie)");

    for cb in &claim_result_2.claimed {
        charlie.billfold.deposit_with_credentials(
            cb.bill.clone(),
            SpendCredential {
                spend_vk: cb.spend_vk.clone(),
                spend_sk: cb.spend_sk.clone(),
            },
        );
        charlie.credentials.insert(cb.bill.mint_id, SpendCredential {
            spend_vk: cb.spend_vk.clone(),
            spend_sk: cb.spend_sk.clone(),
        });
    }
    assert_eq!(charlie.billfold.balance(), 1);

    // ── 11. Charlie broadcasts OwnershipClaim ───────────────────────
    let client_c = VessNode::spawn().await.unwrap();
    client_c.wait_online().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    for claim_msg in &claim_result_2.ownership_claims {
        client_c
            .send_message(artery_addr.clone(), claim_msg)
            .await
            .expect("send OwnershipClaim (Charlie)");
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // ── 12. Verify final state ──────────────────────────────────────
    let resp = client_c
        .send_message_with_response(artery_addr.clone(), &query)
        .await
        .expect("final registry query");

    match resp {
        Some(PulseMessage::RegistryQueryResponse(rqr)) => {
            assert!(rqr.active[0], "bill should still be active after second transfer");
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
        assert_eq!(record.chain_depth, 2, "depth should be 2 (genesis→bob→charlie)");
    }

    println!("OwnershipClaim (Bob → Charlie) verified on artery.");
    println!("Full pipeline: mint → genesis → send → claim → send → claim ✓");

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
            iop_proof.denomination.value(), og.denomination_value,
            "denomination mismatch: proof={}, claimed={}",
            iop_proof.denomination.value(), og.denomination_value,
        );
        // Verify PoW difficulty.
        let required_diff = vess_foundry::mint::difficulty_bits_for(iop_proof.denomination);
        assert!(
            vess_foundry::mint::meets_difficulty_pub(&og.digest, required_diff),
            "digest does not meet difficulty ({required_diff} bits)",
        );
        proof_nonce = iop_proof.nonce;
    } else if let Ok(agg) = vess_foundry::proof::AggregateProof::deserialize(&og.proof) {
        if let Err(e) = vess_foundry::proof::verify_aggregate_proof(&agg, &og.digest, og.denomination_value) {
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
        if let Err(e) = vess_foundry::proof::verify_sampled_aggregate(&sap, &og.digest, og.denomination_value) {
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
        Ok(true) => {}
        Ok(false) => panic!("invalid transfer signature"),
        Err(e) => panic!("transfer signature error: {e}"),
    }

    // Verify new_owner_vk_hash.
    let computed_new_hash = vess_foundry::spend_auth::vk_hash(&oc.new_owner_vk);
    assert_eq!(computed_new_hash, oc.new_owner_vk_hash, "new_owner_vk_hash mismatch");

    // Verify chain_tip advancement and chain_depth.
    if let Some(rec) = registry.get(&oc.mint_id) {
        let prev_vk_hash = vess_foundry::spend_auth::vk_hash(&oc.prev_owner_vk);
        if prev_vk_hash == rec.current_owner_vk_hash {
            assert_eq!(
                oc.chain_depth, rec.chain_depth + 1,
                "chain_depth must be current+1 (got {}, expected {})",
                oc.chain_depth, rec.chain_depth + 1,
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
                && vess_foundry::spend_auth::vk_hash(&oc.prev_owner_vk) == rec.current_owner_vk_hash)
        {
            rec.chain_tip = oc.new_chain_tip;
            rec.current_owner_vk_hash = oc.new_owner_vk_hash;
            rec.current_owner_vk = oc.new_owner_vk;
            rec.chain_depth = oc.chain_depth;
            rec.updated_at = now;
        }
    }
}
