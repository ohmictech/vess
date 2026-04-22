//! Full network stress test: 5 honest nodes + 1 evil node.
//!
//! Exercises:
//! - Tag registration for all 5 participants
//! - Heavy minting (20 D1 bills across 5 nodes)
//! - Large denomination creation via reforge combinations (D2, D5, D10)
//! - Denomination splitting (D10→D5+D5, D5→D2+D2+D1, D2→D1+D1)
//! - Post-reforge payments with mixed denominations
//! - Chain payments (A→B→C→D→E→A) exercising deep ownership chains
//! - Supply conservation verified after every operation
//!
//! Evil node attacks:
//! - Fake payment with garbage stealth payload
//! - Counterfeit bill (fabricated mint_id, no PoW)
//! - Double-spend attempt (claim with wrong transfer signature)
//! - Bad ReforgeAttestation (forged consume signatures)
//! - Inflated denomination genesis (vk_hash mismatch)
//! - Replay genesis for an existing bill
//!
//! Requires the `test-mint` feature on vess-foundry.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vess_artery::ownership_registry::OwnershipRecord;
use vess_artery::OwnershipRegistry;
use vess_artery::TagDht;
use vess_foundry::reforge::{reforge, ReforgeRequest};
use vess_foundry::spend_auth;
use vess_foundry::Denomination;
use vess_kloak::billfold::{BillFold, SpendCredential};
use vess_kloak::payment::{
    claim_transfer_bills, prepare_payment_with_transfer, try_decrypt_transfer_payload,
    DecryptedTransfer,
};
use vess_protocol::{
    OwnershipClaim, OwnershipGenesis, PulseMessage, ReforgeAttestation, RegistryQueryResponse,
    TagLookupResponse, TagLookupResult, TagRegister,
};
use vess_stealth::{generate_master_keys, MasterStealthAddress};
use vess_tag::TagRecord;
use vess_vascular::VessNode;

// ─────────────────────────────────────────────────────────────────────
// Test participant
// ─────────────────────────────────────────────────────────────────────

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

    fn tag_hash(&self) -> [u8; 32] {
        *blake3::hash(self.name.as_bytes()).as_bytes()
    }

    fn tag_register_msg(&self) -> PulseMessage {
        let tag_hash = self.tag_hash();
        let (pow_nonce, pow_hash) = vess_tag::compute_tag_pow_test(
            &tag_hash,
            &self.address.scan_ek,
            &self.address.spend_ek,
        )
        .expect("compute test PoW");

        PulseMessage::TagRegister(TagRegister {
            tag_hash,
            scan_ek: self.address.scan_ek.to_vec(),
            spend_ek: self.address.spend_ek.to_vec(),
            pow_nonce,
            pow_hash,
            timestamp: now_unix(),
            registrant_vk: Vec::new(),
            signature: Vec::new(),
        })
    }

    /// Mint `count` D1 bills and deposit them.
    async fn mint_bills(&mut self, count: usize) {
        for i in 0..count {
            let (vk, sk) = spend_auth::generate_spend_keypair();
            let vk_hash = spend_auth::vk_hash(&vk);

            let vkh = vk_hash;
            let (bill, _proof_bytes) = tokio::task::spawn_blocking(move || {
                vess_foundry::mint::mint_blocking(Denomination::D1, &vkh)
            })
            .await
            .unwrap();

            self.billfold.deposit_with_credentials(
                bill.clone(),
                SpendCredential {
                    spend_vk: vk.clone(),
                    spend_sk: sk.clone(),
                },
            );
            self.credentials.insert(
                bill.mint_id,
                SpendCredential {
                    spend_vk: vk,
                    spend_sk: sk,
                },
            );
            println!(
                "  {} minted bill #{} (mint_id: {:02x}{:02x}…)",
                self.name,
                i + 1,
                bill.mint_id[0],
                bill.mint_id[1]
            );
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────
// Reforge helper
// ─────────────────────────────────────────────────────────────────────

fn do_reforge(
    participant: &mut Participant,
    input_indices: &[usize],
    output_denoms: Vec<Denomination>,
    registry: &Arc<Mutex<OwnershipRegistry>>,
    label: &str,
) {
    let input_bills: Vec<_> = input_indices
        .iter()
        .map(|&i| participant.billfold.bills()[i].clone())
        .collect();
    let stealth_id = input_bills[0].stealth_id;

    let result = reforge(ReforgeRequest {
        inputs: input_bills,
        output_denominations: output_denoms.clone(),
        output_stealth_ids: output_denoms.iter().map(|_| stealth_id).collect(),
    })
    .expect(label);

    // Remove consumed bills.
    for mid in &result.consumed_mint_ids {
        participant.billfold.withdraw(mid);
        participant.credentials.remove(mid);
    }

    // Deposit new bills with fresh credentials.
    let mut reforged_creds: HashMap<[u8; 32], SpendCredential> = HashMap::new();
    for (bill, _) in &result.outputs {
        let (vk, sk) = spend_auth::generate_spend_keypair();
        let cred = SpendCredential {
            spend_vk: vk,
            spend_sk: sk,
        };
        participant
            .billfold
            .deposit_with_credentials(bill.clone(), cred.clone());
        participant.credentials.insert(bill.mint_id, cred.clone());
        reforged_creds.insert(bill.mint_id, cred);
    }

    // Update registry: consume old, register new.
    let mut reg = registry.lock().unwrap();
    for mid in &result.consumed_mint_ids {
        reg.consume(mid);
    }
    let now = now_unix();
    for (bill, _) in &result.outputs {
        let cred = reforged_creds.get(&bill.mint_id).unwrap();
        let vk_hash = spend_auth::vk_hash(&cred.spend_vk);
        reg.register(OwnershipRecord {
            mint_id: bill.mint_id,
            chain_tip: bill.chain_tip,
            current_owner_vk_hash: vk_hash,
            current_owner_vk: cred.spend_vk.clone(),
            denomination_value: bill.denomination.value(),
            updated_at: now,
            proof_hash: blake3::hash(&bill.digest).into(),
            digest: bill.digest,
            nonce: [0u8; 32],
            prev_claim_vk_hash: None,
            claim_hash: None,
            chain_depth: 0,
            encrypted_bill: vec![],
        });
    }

    let out_str: Vec<String> = output_denoms
        .iter()
        .map(|d| format!("D{}", d.value()))
        .collect();
    println!(
        "  {}: {} -> [{}] (balance: {})",
        participant.name,
        label,
        out_str.join("+"),
        participant.billfold.balance()
    );
}

// ─────────────────────────────────────────────────────────────────────
// Transfer helper
// ─────────────────────────────────────────────────────────────────────

async fn transfer_and_claim(
    sender: &mut Participant,
    receiver: &mut Participant,
    amount: u64,
    _sender_client: &VessNode,
    receiver_client: &VessNode,
    artery_addr: &iroh::EndpointAddr,
    registry: &Arc<Mutex<OwnershipRegistry>>,
) -> usize {
    let receiver_address = receiver.address.clone();

    let (payment_msg, payment_id, send_indices) = prepare_payment_with_transfer(
        &sender.billfold,
        amount,
        &receiver_address,
        &sender.credentials,
        Some(format!(
            "{} -> {}: {} Vess",
            sender.name, receiver.name, amount
        )),
    )
    .expect("prepare payment");

    // Withdraw sent bills from sender.
    let sent_mints: Vec<[u8; 32]> = send_indices
        .iter()
        .map(|&i| sender.billfold.bills()[i].mint_id)
        .collect();
    for mid in &sent_mints {
        sender.billfold.withdraw(mid);
        sender.credentials.remove(mid);
    }

    // Receiver decrypts.
    let stealth_payload = match &payment_msg {
        PulseMessage::Payment(p) => &p.stealth_payload,
        _ => panic!("expected Payment"),
    };

    let decrypted = try_decrypt_transfer_payload(&receiver.secret, stealth_payload)
        .expect("decrypt error")
        .expect("view tag mismatch");

    let (transfer_payload, stealth_id) = match decrypted {
        DecryptedTransfer::WithAuth(tp, sid) => (tp, sid),
    };

    assert_eq!(
        transfer_payload.memo.as_deref(),
        Some(format!("{} -> {}: {} Vess", sender.name, receiver.name, amount).as_str()),
    );

    let claim_result =
        claim_transfer_bills(transfer_payload, stealth_id).expect("claim transfer bills");

    let num_bills = claim_result.claimed.len();

    for cb in &claim_result.claimed {
        receiver.billfold.deposit_with_credentials(
            cb.bill.clone(),
            SpendCredential {
                spend_vk: cb.spend_vk.clone(),
                spend_sk: cb.spend_sk.clone(),
            },
        );
        receiver.credentials.insert(
            cb.bill.mint_id,
            SpendCredential {
                spend_vk: cb.spend_vk.clone(),
                spend_sk: cb.spend_sk.clone(),
            },
        );
    }

    // Broadcast OwnershipClaims.
    for claim_msg in &claim_result.ownership_claims {
        receiver_client
            .send_message(artery_addr.clone(), claim_msg)
            .await
            .expect("send OwnershipClaim");
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Verify registry updated.
    for cb in &claim_result.claimed {
        let reg = registry.lock().unwrap();
        if let Some(record) = reg.get(&cb.bill.mint_id) {
            let expected_hash = spend_auth::vk_hash(&cb.spend_vk);
            assert_eq!(
                record.current_owner_vk_hash, expected_hash,
                "registry should reflect new owner after claim"
            );
        }
    }

    println!(
        "  {} -> {}: {} Vess ({} bill{}) [pid: {:02x}{:02x}...]",
        sender.name,
        receiver.name,
        amount,
        num_bills,
        if num_bills == 1 { "" } else { "s" },
        payment_id[0],
        payment_id[1],
    );

    num_bills
}

fn verify_total_supply(participants: &[&Participant], expected: u64) {
    let total: u64 = participants.iter().map(|p| p.billfold.balance()).sum();
    assert_eq!(
        total, expected,
        "supply conservation violated: expected {expected}, got {total}"
    );
}

/// Register all minted bills directly in the registry (skips STARK
/// verification — that is covered in three_node_e2e).
fn register_all_bills(participants: &[&Participant], registry: &Arc<Mutex<OwnershipRegistry>>) {
    let mut reg = registry.lock().unwrap();
    let now = now_unix();
    for p in participants {
        for bill in p.billfold.bills() {
            if reg.is_active(&bill.mint_id) {
                continue;
            }
            let cred = p.credentials.get(&bill.mint_id).unwrap();
            let vk_hash = spend_auth::vk_hash(&cred.spend_vk);
            reg.register(OwnershipRecord {
                mint_id: bill.mint_id,
                chain_tip: bill.chain_tip,
                current_owner_vk_hash: vk_hash,
                current_owner_vk: cred.spend_vk.clone(),
                denomination_value: bill.denomination.value(),
                updated_at: now,
                proof_hash: blake3::hash(&bill.digest).into(),
                digest: bill.digest,
                nonce: [0u8; 32],
                prev_claim_vk_hash: None,
                claim_hash: None,
                chain_depth: 0,
                encrypted_bill: vec![],
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// The test
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn five_node_full_network() {
    println!("\n=== Five-Node Full Network Test + Evil Node ===\n");

    // -- 1. Spin up artery node -------------------------------------------
    let artery_node = VessNode::spawn().await.unwrap();
    artery_node.wait_online().await;
    let artery_addr = artery_node.addr();

    let node_id_bytes: [u8; 32] = *blake3::hash(artery_node.id().as_bytes()).as_bytes();
    let registry = Arc::new(Mutex::new(OwnershipRegistry::new(node_id_bytes)));
    let tag_dht = Arc::new(Mutex::new(TagDht::new(node_id_bytes, 3)));
    let attack_rejections = Arc::new(Mutex::new(0u32));

    let reg = registry.clone();
    let tags = tag_dht.clone();
    let rejections = attack_rejections.clone();
    let artery_handle = tokio::spawn({
        let artery_node = artery_node.clone();
        async move {
            artery_node
                .listen_messages_with_response(move |_peer, msg| match msg {
                    PulseMessage::OwnershipGenesis(og) => {
                        if !handle_ownership_genesis_safe(&reg, &og) {
                            *rejections.lock().unwrap() += 1;
                            println!("    [ARTERY] Rejected bad OwnershipGenesis");
                        }
                        None
                    }
                    PulseMessage::OwnershipClaim(ref oc) => {
                        if !handle_ownership_claim_safe(&reg, oc) {
                            *rejections.lock().unwrap() += 1;
                            println!("    [ARTERY] Rejected bad OwnershipClaim");
                        }
                        None
                    }
                    PulseMessage::ReforgeAttestation(ref ra) => {
                        if !handle_reforge_attestation_safe(&reg, ra) {
                            *rejections.lock().unwrap() += 1;
                            println!("    [ARTERY] Rejected bad ReforgeAttestation");
                        }
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
                    PulseMessage::Payment(_) => None,
                    _ => None,
                })
                .await
                .ok();
        }
    });

    // -- 2. Create 5 participants -----------------------------------------
    let mut alice = Participant::new("alice");
    let mut bob = Participant::new("bob");
    let mut charlie = Participant::new("charlie");
    let mut diana = Participant::new("diana");
    let mut eve = Participant::new("eve");

    // -- 3. Spin up 5 client nodes + 1 evil node -------------------------
    let client_a = VessNode::spawn().await.unwrap();
    let client_b = VessNode::spawn().await.unwrap();
    let client_c = VessNode::spawn().await.unwrap();
    let client_d = VessNode::spawn().await.unwrap();
    let client_e = VessNode::spawn().await.unwrap();
    let evil_node = VessNode::spawn().await.unwrap();

    tokio::join!(
        client_a.wait_online(),
        client_b.wait_online(),
        client_c.wait_online(),
        client_d.wait_online(),
        client_e.wait_online(),
        evil_node.wait_online(),
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    println!("All 5 client nodes + 1 evil node online.");

    // -- 4. Register tags -------------------------------------------------
    for (client, participant) in [
        (&client_a, &alice),
        (&client_b, &bob),
        (&client_c, &charlie),
        (&client_d, &diana),
        (&client_e, &eve),
    ] {
        client
            .send_message(artery_addr.clone(), &participant.tag_register_msg())
            .await
            .expect("register tag");
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    println!("Tags registered: +alice, +bob, +charlie, +diana, +eve\n");

    // =====================================================================
    // Phase 1: Heavy minting (20 D1 bills)
    // =====================================================================
    println!("-- Phase 1: Minting --");
    let start = std::time::Instant::now();

    alice.mint_bills(6).await;
    bob.mint_bills(5).await;
    charlie.mint_bills(4).await;
    diana.mint_bills(3).await;
    eve.mint_bills(2).await;

    let mint_elapsed = start.elapsed();
    println!("All 20 D1 bills minted in {mint_elapsed:.2?}");

    let total_supply = 20u64;
    assert_eq!(alice.billfold.balance(), 6);
    assert_eq!(bob.billfold.balance(), 5);
    assert_eq!(charlie.billfold.balance(), 4);
    assert_eq!(diana.billfold.balance(), 3);
    assert_eq!(eve.billfold.balance(), 2);

    register_all_bills(&[&alice, &bob, &charlie, &diana, &eve], &registry);
    println!("All 20 bills registered in ownership registry.\n");
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);

    // =====================================================================
    // Phase 2: Evil Node Attacks
    // =====================================================================
    println!("-- Phase 2: Evil Node Attacks --");

    let pre_attack_reg_count = registry.lock().unwrap().len();

    // Attack 1: Fake stealth payload (garbage bytes).
    println!("  Attack 1: Fake payment (garbage stealth payload)...");
    {
        let garbage = vec![0xDE; 256];
        let result = try_decrypt_transfer_payload(&bob.secret, &garbage);
        match result {
            Ok(None) => println!("    -> Rejected: view tag mismatch (not for us)"),
            Err(e) => println!("    -> Rejected: decryption failed ({e})"),
            Ok(Some(_)) => panic!("garbage payload should not decrypt successfully"),
        }
    }

    // Attack 2: Counterfeit OwnershipGenesis (empty proof).
    println!("  Attack 2: Counterfeit OwnershipGenesis (empty proof)...");
    {
        let (fake_vk, _) = spend_auth::generate_spend_keypair();
        let fake_vk_hash = spend_auth::vk_hash(&fake_vk);
        let fake_genesis = PulseMessage::OwnershipGenesis(OwnershipGenesis {
            mint_id: [0xBE; 32],
            chain_tip: [0xEF; 32],
            owner_vk_hash: fake_vk_hash,
            owner_vk: fake_vk,
            denomination_value: 10,
            proof: vec![], // Empty proof -> rejected
            digest: [0xAA; 32],
            hops_remaining: 3,
            chain_depth: 0,
            output_index: 0,
        });
        evil_node
            .send_message(artery_addr.clone(), &fake_genesis)
            .await
            .expect("send fake genesis");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let reg = registry.lock().unwrap();
        assert!(
            !reg.is_active(&[0xBE; 32]),
            "counterfeit bill should not be in registry"
        );
        println!("    -> Rejected: not in registry");
    }

    // Attack 3: Bad OwnershipClaim (wrong transfer signature).
    println!("  Attack 3: Bad OwnershipClaim (wrong transfer sig)...");
    {
        let alice_bill = alice.billfold.bills()[0].clone();
        let (evil_vk, _) = spend_auth::generate_spend_keypair();
        let evil_vk_hash = spend_auth::vk_hash(&evil_vk);

        let bad_claim = PulseMessage::OwnershipClaim(OwnershipClaim {
            mint_id: alice_bill.mint_id,
            stealth_id: [0u8; 32],
            prev_owner_vk: evil_vk.clone(), // Wrong: evil is not the owner
            transfer_sig: vec![0u8; 128],   // Garbage signature
            new_owner_vk_hash: evil_vk_hash,
            new_owner_vk: evil_vk,
            new_chain_tip: [0xFF; 32],
            timestamp: now_unix(),
            hops_remaining: 3,
            chain_depth: 1,
            encrypted_bill: vec![],
        });
        evil_node
            .send_message(artery_addr.clone(), &bad_claim)
            .await
            .expect("send bad claim");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Alice still owns her bill.
        let reg = registry.lock().unwrap();
        let record = reg
            .get(&alice_bill.mint_id)
            .expect("alice bill should exist");
        let alice_cred = alice.credentials.get(&alice_bill.mint_id).unwrap();
        let alice_vk_hash = spend_auth::vk_hash(&alice_cred.spend_vk);
        assert_eq!(
            record.current_owner_vk_hash, alice_vk_hash,
            "Alice should still own her bill after evil claim attempt"
        );
        println!("    -> Rejected: Alice still owns her bill");
    }

    // Attack 4: Bad ReforgeAttestation (forged consume signatures).
    println!("  Attack 4: Bad ReforgeAttestation (forged consume sigs)...");
    {
        let bob_bill = bob.billfold.bills()[0].clone();
        let (evil_vk, _) = spend_auth::generate_spend_keypair();

        let mut sorted = vec![bob_bill.mint_id];
        sorted.sort();
        let reforge_id = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-reforge-id-v0");
            for id in &sorted {
                h.update(id);
            }
            *h.finalize().as_bytes()
        };

        let bad_ra = PulseMessage::ReforgeAttestation(ReforgeAttestation {
            consumed_mint_ids: vec![bob_bill.mint_id],
            owner_vk: evil_vk,
            consume_sigs: vec![vec![0u8; 128]],
            reforge_id,
            output_mint_ids: vec![],
            hops_remaining: 3,
        });
        evil_node
            .send_message(artery_addr.clone(), &bad_ra)
            .await
            .expect("send bad reforge attestation");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let reg = registry.lock().unwrap();
        assert!(
            reg.is_active(&bob_bill.mint_id),
            "Bob's bill should still be active after forged reforge"
        );
        println!("    -> Rejected: Bob's bill still active");
    }

    // Attack 5: Inflated denomination genesis (vk_hash mismatch).
    println!("  Attack 5: Inflated denomination genesis (vk_hash mismatch)...");
    {
        let (fake_vk, _) = spend_auth::generate_spend_keypair();
        let inflated = PulseMessage::OwnershipGenesis(OwnershipGenesis {
            mint_id: [0xCC; 32],
            chain_tip: [0xDD; 32],
            owner_vk_hash: [0xFF; 32], // Deliberate mismatch with fake_vk
            owner_vk: fake_vk,
            denomination_value: 10,
            proof: vec![1, 2, 3], // Non-empty but vk_hash won't match
            digest: [0xEE; 32],
            hops_remaining: 3,
            chain_depth: 0,
            output_index: 0,
        });
        evil_node
            .send_message(artery_addr.clone(), &inflated)
            .await
            .expect("send inflated genesis");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let reg = registry.lock().unwrap();
        assert!(
            !reg.is_active(&[0xCC; 32]),
            "inflated denomination should not be registered"
        );
        println!("    -> Rejected: vk_hash mismatch");
    }

    // Attack 6: Replay genesis for an already-registered bill.
    println!("  Attack 6: Replay genesis for existing bill...");
    {
        let alice_bill = alice.billfold.bills()[0].clone();
        let (fake_vk, _) = spend_auth::generate_spend_keypair();
        let fake_vk_hash = spend_auth::vk_hash(&fake_vk);

        let replay = PulseMessage::OwnershipGenesis(OwnershipGenesis {
            mint_id: alice_bill.mint_id,
            chain_tip: [0xFF; 32],
            owner_vk_hash: fake_vk_hash,
            owner_vk: fake_vk,
            denomination_value: 1,
            proof: vec![1, 2, 3],
            digest: alice_bill.digest,
            hops_remaining: 3,
            chain_depth: 0,
            output_index: 0,
        });
        evil_node
            .send_message(artery_addr.clone(), &replay)
            .await
            .expect("send replay genesis");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Alice should STILL be the owner.
        let reg = registry.lock().unwrap();
        let record = reg.get(&alice_bill.mint_id).unwrap();
        let alice_cred = alice.credentials.get(&alice_bill.mint_id).unwrap();
        assert_eq!(
            record.current_owner_vk_hash,
            spend_auth::vk_hash(&alice_cred.spend_vk),
            "Replay genesis should not override existing ownership"
        );
        println!("    -> Ignored: existing ownership preserved");
    }

    // Verify registry didn't grow from attacks.
    let post_attack_reg_count = registry.lock().unwrap().len();
    assert_eq!(
        pre_attack_reg_count, post_attack_reg_count,
        "registry should not have grown from evil node attacks"
    );
    let total_rejections = *attack_rejections.lock().unwrap();
    println!(
        "\n  Evil node summary: 6 attacks, {total_rejections} explicitly rejected, 0 succeeded"
    );
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);
    println!("  Supply intact: {total_supply} Vess\n");

    // =====================================================================
    // Phase 3: Simple D1 payments
    // =====================================================================
    println!("-- Phase 3: Simple D1 payments --");

    // Alice(6) -> Bob(5): 2
    transfer_and_claim(
        &mut alice,
        &mut bob,
        2,
        &client_a,
        &client_b,
        &artery_addr,
        &registry,
    )
    .await;
    // Bob(7) -> Charlie(4): 1
    transfer_and_claim(
        &mut bob,
        &mut charlie,
        1,
        &client_b,
        &client_c,
        &artery_addr,
        &registry,
    )
    .await;
    // Diana(3) -> Eve(2): 2
    transfer_and_claim(
        &mut diana,
        &mut eve,
        2,
        &client_d,
        &client_e,
        &artery_addr,
        &registry,
    )
    .await;
    // Charlie(5) -> Alice(4): 1
    transfer_and_claim(
        &mut charlie,
        &mut alice,
        1,
        &client_c,
        &client_a,
        &artery_addr,
        &registry,
    )
    .await;

    // After: Alice=5, Bob=6, Charlie=4, Diana=1, Eve=4
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);
    println!("Phase 3 complete. Supply conserved.\n");

    // =====================================================================
    // Phase 4: Reforge ladder (D1 -> D2 -> D5 -> D10)
    // =====================================================================
    println!("-- Phase 4: Reforge ladder (D1->D2->D5->D10) --");

    // Alice(5): combine first 2 D1 -> D2.
    do_reforge(
        &mut alice,
        &[0, 1],
        vec![Denomination::D2],
        &registry,
        "2xD1->D2",
    );
    assert_eq!(alice.billfold.balance(), 5);
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);

    // Alice: combine 2 more D1 -> D2.
    let d1_indices: Vec<usize> = alice
        .billfold
        .bills()
        .iter()
        .enumerate()
        .filter(|(_, b)| b.denomination == Denomination::D1)
        .map(|(i, _)| i)
        .collect();
    assert!(d1_indices.len() >= 2, "alice should have >=2 D1 bills");
    do_reforge(
        &mut alice,
        &[d1_indices[0], d1_indices[1]],
        vec![Denomination::D2],
        &registry,
        "2xD1->D2 (second)",
    );
    assert_eq!(alice.billfold.balance(), 5); // 2xD2 + 1xD1
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);

    // Alice: combine all (2xD2 + 1xD1 = 5) -> D5.
    let all_alice: Vec<usize> = (0..alice.billfold.count()).collect();
    do_reforge(
        &mut alice,
        &all_alice,
        vec![Denomination::D5],
        &registry,
        "2xD2+1xD1->D5",
    );
    assert_eq!(alice.billfold.balance(), 5);
    assert_eq!(alice.billfold.count(), 1);
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);

    // Bob(6): combine 5 D1 -> D5, keep 1 D1.
    do_reforge(
        &mut bob,
        &[0, 1, 2, 3, 4],
        vec![Denomination::D5],
        &registry,
        "5xD1->D5",
    );
    assert_eq!(bob.billfold.balance(), 6); // 1xD5 + 1xD1
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);

    // Transfer Bob's D5 to Alice so she can combine 2xD5 -> D10.
    transfer_and_claim(
        &mut bob,
        &mut alice,
        5,
        &client_b,
        &client_a,
        &artery_addr,
        &registry,
    )
    .await;
    assert_eq!(alice.billfold.balance(), 10); // 2xD5
    assert_eq!(bob.billfold.balance(), 1); // 1xD1

    // Combine 2xD5 -> D10.
    do_reforge(
        &mut alice,
        &[0, 1],
        vec![Denomination::D10],
        &registry,
        "2xD5->D10",
    );
    assert_eq!(alice.billfold.balance(), 10);
    assert_eq!(alice.billfold.count(), 1);
    println!("  Alice now holds 1xD10!");
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);
    println!();

    // =====================================================================
    // Phase 5: Split D10 back down
    // =====================================================================
    println!("-- Phase 5: Split D10->D5+D5, then D5->D2+D2+D1, then D2->D1+D1 --");

    // D10 -> D5 + D5.
    do_reforge(
        &mut alice,
        &[0],
        vec![Denomination::D5, Denomination::D5],
        &registry,
        "D10->2xD5",
    );
    assert_eq!(alice.billfold.balance(), 10);
    assert_eq!(alice.billfold.count(), 2);
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);

    // Split first D5 -> D2 + D2 + D1.
    do_reforge(
        &mut alice,
        &[0],
        vec![Denomination::D2, Denomination::D2, Denomination::D1],
        &registry,
        "D5->D2+D2+D1",
    );
    assert_eq!(alice.billfold.balance(), 10); // D5+D2+D2+D1
    assert_eq!(alice.billfold.count(), 4);
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);

    // Split a D2 -> D1 + D1.
    let d2_idx = alice
        .billfold
        .bills()
        .iter()
        .position(|b| b.denomination == Denomination::D2)
        .expect("alice should have a D2");
    do_reforge(
        &mut alice,
        &[d2_idx],
        vec![Denomination::D1, Denomination::D1],
        &registry,
        "D2->2xD1",
    );
    assert_eq!(alice.billfold.balance(), 10);
    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);
    println!();

    // =====================================================================
    // Phase 6: Post-reforge mixed-denomination payments
    // =====================================================================
    println!("-- Phase 6: Post-reforge mixed-denomination payments --");

    // Alice(10) sends 5 to Charlie.
    transfer_and_claim(
        &mut alice,
        &mut charlie,
        5,
        &client_a,
        &client_c,
        &artery_addr,
        &registry,
    )
    .await;

    // Alice sends 2 to Diana.
    transfer_and_claim(
        &mut alice,
        &mut diana,
        2,
        &client_a,
        &client_d,
        &artery_addr,
        &registry,
    )
    .await;

    // Eve sends 1 to Bob.
    transfer_and_claim(
        &mut eve,
        &mut bob,
        1,
        &client_e,
        &client_b,
        &artery_addr,
        &registry,
    )
    .await;

    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);
    println!("Phase 6 complete. Supply conserved.\n");

    // =====================================================================
    // Phase 7: Circular chain payments (A->B->C->D->E->A)
    // =====================================================================
    println!("-- Phase 7: Circular chain payments (A->B->C->D->E->A) --");

    transfer_and_claim(
        &mut alice,
        &mut bob,
        1,
        &client_a,
        &client_b,
        &artery_addr,
        &registry,
    )
    .await;
    transfer_and_claim(
        &mut bob,
        &mut charlie,
        1,
        &client_b,
        &client_c,
        &artery_addr,
        &registry,
    )
    .await;
    transfer_and_claim(
        &mut charlie,
        &mut diana,
        1,
        &client_c,
        &client_d,
        &artery_addr,
        &registry,
    )
    .await;
    transfer_and_claim(
        &mut diana,
        &mut eve,
        1,
        &client_d,
        &client_e,
        &artery_addr,
        &registry,
    )
    .await;
    transfer_and_claim(
        &mut eve,
        &mut alice,
        1,
        &client_e,
        &client_a,
        &artery_addr,
        &registry,
    )
    .await;

    verify_total_supply(&[&alice, &bob, &charlie, &diana, &eve], total_supply);
    println!("Phase 7 complete. Supply conserved.\n");

    // =====================================================================
    // Final report
    // =====================================================================
    println!("=== Final Balances ===");
    for (name, p) in [
        ("Alice", &alice),
        ("Bob", &bob),
        ("Charlie", &charlie),
        ("Diana", &diana),
        ("Eve", &eve),
    ] {
        let breakdown: Vec<String> = p
            .billfold
            .denomination_breakdown()
            .iter()
            .map(|(d, c)| format!("{}xD{}", c, d.value()))
            .collect();
        println!(
            "  {name}: {} Vess ({} bill{}) [{}]",
            p.billfold.balance(),
            p.billfold.count(),
            if p.billfold.count() == 1 { "" } else { "s" },
            breakdown.join(", "),
        );
    }

    let final_total: u64 = [&alice, &bob, &charlie, &diana, &eve]
        .iter()
        .map(|p| p.billfold.balance())
        .sum();
    assert_eq!(final_total, total_supply, "total supply must be conserved");

    // Verify every bill in every billfold is active in the registry.
    {
        let reg = registry.lock().unwrap();
        for participant in [&alice, &bob, &charlie, &diana, &eve] {
            for bill in participant.billfold.bills() {
                assert!(
                    reg.is_active(&bill.mint_id),
                    "{}'s bill {:02x}{:02x}... should be active in registry",
                    participant.name,
                    bill.mint_id[0],
                    bill.mint_id[1],
                );
            }
        }
    }

    println!("\n=== All assertions passed! ===");
    println!(
        "Tags: 5 | Minted: 20 D1 | Reforges: 8 | Transfers: 12 | Evil attacks: 6 | Supply: {} Vess",
        total_supply,
    );

    // -- Cleanup ----------------------------------------------------------
    client_a.shutdown().await;
    client_b.shutdown().await;
    client_c.shutdown().await;
    client_d.shutdown().await;
    client_e.shutdown().await;
    evil_node.shutdown().await;
    artery_node.shutdown().await;
    artery_handle.abort();
}

// ─────────────────────────────────────────────────────────────────────
// Artery handler helpers
// ─────────────────────────────────────────────────────────────────────

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
    assert!(ok, "tag PoW verification failed");

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
    dht.store(record);
}

/// Returns true if genesis was accepted, false if rejected.
fn handle_ownership_genesis_safe(
    registry: &Arc<Mutex<OwnershipRegistry>>,
    og: &OwnershipGenesis,
) -> bool {
    let mut reg = registry.lock().unwrap();

    // Already registered — silently ignore (normal gossip duplication).
    if reg.is_active(&og.mint_id) {
        return true;
    }

    // Verify vk_hash consistency.
    let claimed_vk_hash = spend_auth::vk_hash(&og.owner_vk);
    if claimed_vk_hash != og.owner_vk_hash {
        return false;
    }

    // Require non-empty proof (real node would do full STARK verification).
    if og.proof.is_empty() {
        return false;
    }

    let now = now_unix();
    reg.register(OwnershipRecord {
        mint_id: og.mint_id,
        chain_tip: og.chain_tip,
        current_owner_vk_hash: og.owner_vk_hash,
        current_owner_vk: og.owner_vk.clone(),
        denomination_value: og.denomination_value,
        updated_at: now,
        proof_hash: blake3::hash(&og.proof).into(),
        digest: og.digest,
        nonce: [0u8; 32],
        prev_claim_vk_hash: None,
        claim_hash: None,
        chain_depth: 0,
        encrypted_bill: vec![],
    });
    true
}

/// Returns true if claim was accepted, false if rejected.
fn handle_ownership_claim_safe(
    registry: &Arc<Mutex<OwnershipRegistry>>,
    oc: &OwnershipClaim,
) -> bool {
    // Verify transfer signature.
    let transfer_msg = spend_auth::transfer_message(&oc.mint_id, &oc.stealth_id, oc.timestamp);
    match spend_auth::verify_spend(&oc.prev_owner_vk, &transfer_msg, &oc.transfer_sig) {
        Ok(true) => {}
        _ => return false,
    }

    // Verify new_owner_vk_hash.
    let computed = spend_auth::vk_hash(&oc.new_owner_vk);
    if computed != oc.new_owner_vk_hash {
        return false;
    }

    let mut reg = registry.lock().unwrap();

    // Verify prev_owner matches current record.
    if let Some(rec) = reg.get(&oc.mint_id) {
        let prev_vk_hash = spend_auth::vk_hash(&oc.prev_owner_vk);
        if prev_vk_hash != rec.current_owner_vk_hash {
            return false;
        }
        if oc.chain_depth != rec.chain_depth + 1 {
            return false;
        }
        let expected_tip = vess_foundry::advance_chain_tip(
            &rec.chain_tip,
            &oc.new_owner_vk_hash,
            &oc.transfer_sig,
        );
        if expected_tip != oc.new_chain_tip {
            return false;
        }
    } else {
        return false;
    }

    let now = now_unix();
    if let Some(rec) = reg.get_mut(&oc.mint_id) {
        if oc.chain_depth > rec.chain_depth
            || (oc.chain_depth == rec.chain_depth
                && spend_auth::vk_hash(&oc.prev_owner_vk) == rec.current_owner_vk_hash)
        {
            rec.chain_tip = oc.new_chain_tip;
            rec.current_owner_vk_hash = oc.new_owner_vk_hash;
            rec.current_owner_vk = oc.new_owner_vk.clone();
            rec.chain_depth = oc.chain_depth;
            rec.updated_at = now;
        }
    }
    true
}

/// Returns true if reforge attestation was accepted, false if rejected.
fn handle_reforge_attestation_safe(
    registry: &Arc<Mutex<OwnershipRegistry>>,
    ra: &ReforgeAttestation,
) -> bool {
    if ra.consumed_mint_ids.is_empty() {
        return false;
    }
    if ra.consume_sigs.len() != ra.consumed_mint_ids.len() {
        return false;
    }

    // Verify reforge_id.
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
        return false;
    }

    // Verify owner and consume signatures.
    let owner_vk_hash = spend_auth::vk_hash(&ra.owner_vk);
    let reg = registry.lock().unwrap();
    for (i, mint_id) in ra.consumed_mint_ids.iter().enumerate() {
        if let Some(rec) = reg.get(mint_id) {
            if rec.current_owner_vk_hash != owner_vk_hash {
                return false;
            }
        }
        let consume_msg = {
            let mut h = blake3::Hasher::new();
            h.update(b"vess-reforge-consume-v0");
            h.update(mint_id);
            h.update(&ra.reforge_id);
            *h.finalize().as_bytes()
        };
        match spend_auth::verify_spend(&ra.owner_vk, &consume_msg, &ra.consume_sigs[i]) {
            Ok(true) => {}
            _ => return false,
        }
    }
    drop(reg);

    let mut reg = registry.lock().unwrap();
    for mid in &ra.consumed_mint_ids {
        reg.consume(mid);
    }
    true
}
