use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use vess_artery::ownership_registry::OwnershipRecord;
use vess_artery::OwnershipRegistry;
use vess_compute::{
    compute_program_pow_test, ComputeReceipt, ProgramAddress, ProgramDefinition,
    ProgramOwnershipCondition, ProgramSpendWitness, ProofSystem, StarkProofEnvelope,
    StoredProgram,
};
use vess_foundry::{Denomination, VessBill};
use vess_foundry::spend_auth::{generate_spend_keypair, vk_hash};
use vess_kloak::billfold::BillFold;
use vess_kloak::billfold::SpendCredential;
use vess_kloak::payment::{
    build_program_lock_claims, build_program_unlock_claims, prepare_payment, try_receive_payment,
};
use vess_kloak::recovery::{derive_raw_seed_with_params, RecoveryPhrase};
use vess_mesh::{
    decode_mesh_contact, encode_mesh_contact, generate_mesh_keys_from_seed,
    generate_route_handshake, open_route_handshake,
};
use vess_protocol::{
    ComputeReceiptFetch, ComputeReceiptStore, GenesisProof, LocalTestFaucetProof,
    OwnershipFetch, OwnershipGenesis, PeerExchange, ProgramFetch, ProgramReceiptList,
    ProgramStore, PulseMessage, RegistryQuery, RegistryQueryResponse,
};
use vess_stealth::generate_master_keys_from_seed;
use vess_vascular::MeshPulseNode;

fn localhost_bind_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
}

async fn spawn_local_mesh_node(seed_byte: u8) -> MeshPulseNode {
    let seed = [seed_byte; 64];
    MeshPulseNode::bind_from_seed(localhost_bind_addr(), &seed, 0)
        .await
        .unwrap()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn sample_program_definition() -> ProgramDefinition {
    ProgramDefinition {
        code: b"fn main() { return 1; }".to_vec(),
        proof_system: ProofSystem::VessStarkV1,
        public_input_schema_hash: [0x11; 32],
        public_output_schema_hash: [0x22; 32],
        metadata_hash: [0x33; 32],
        abi_hash: [0x44; 32],
        max_cycles: 50_000,
        max_memory_bytes: 1 << 20,
        supports_program_owned_bills: true,
        entrypoints: vec!["main".to_string()],
    }
}

async fn wait_for_program_fetch(
    client: &MeshPulseNode,
    target: &vess_mesh::MeshCarrierContact,
    prog_id: vess_compute::ProgramId,
) -> StoredProgram {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for program {:?}", prog_id.as_bytes());
        }
        let response = client
            .send_message_with_response(target, &PulseMessage::ProgramFetch(ProgramFetch { prog_id }))
            .await
            .unwrap();
        if let Some(PulseMessage::ProgramFetchResponse(resp)) = response {
            if let Some(program) = resp.program {
                return program;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_ownership_chain_tip(
    client: &MeshPulseNode,
    target: &vess_mesh::MeshCarrierContact,
    mint_id: [u8; 32],
    expected_chain_tip: [u8; 32],
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for ownership chain tip update");
        }
        let response = client
            .send_message_with_response(
                target,
                &PulseMessage::OwnershipFetch(OwnershipFetch {
                    mint_ids: vec![mint_id],
                }),
            )
            .await
            .unwrap();
        if let Some(PulseMessage::OwnershipFetchResponse(resp)) = response {
            if let Some(record) = resp.records.first() {
                if record.found && record.chain_tip == expected_chain_tip {
                    return;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_receipt(
    client: &MeshPulseNode,
    target: &vess_mesh::MeshCarrierContact,
    prog_id: vess_compute::ProgramId,
    receipt_id: [u8; 32],
) -> ComputeReceipt {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for compute receipt");
        }
        let list_response = client
            .send_message_with_response(
                target,
                &PulseMessage::ProgramReceiptList(ProgramReceiptList { prog_id }),
            )
            .await
            .unwrap();
        if let Some(PulseMessage::ProgramReceiptListResponse(list)) = list_response {
            if list.receipt_ids.contains(&receipt_id) {
                let fetch_response = client
                    .send_message_with_response(
                        target,
                        &PulseMessage::ComputeReceiptFetch(ComputeReceiptFetch { receipt_id }),
                    )
                    .await
                    .unwrap();
                if let Some(PulseMessage::ComputeReceiptFetchResponse(fetch)) = fetch_response {
                    if let Some(receipt) = fetch.receipt {
                        return receipt;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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

#[tokio::test]
async fn mesh_pulse_nodes_exchange_typed_messages() {
    let node_a = spawn_local_mesh_node(1).await;
    let node_b = spawn_local_mesh_node(2).await;
    node_a.wait_online().await;
    node_b.wait_online().await;

    let listen_task = {
        let node_b = node_b.clone();
        tokio::spawn(async move {
            let _ = node_b
                .listen_messages_with_response(|_peer, msg| match msg {
                    PulseMessage::RegistryQuery(query) => {
                        Some(PulseMessage::RegistryQueryResponse(RegistryQueryResponse {
                            active: query.mint_ids.iter().map(|_| true).collect(),
                        }))
                    }
                    _ => None,
                })
                .await;
        })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = node_a
        .send_message_with_response(
            &node_b.contact(),
            &PulseMessage::RegistryQuery(RegistryQuery {
                mint_ids: vec![[0x11; 32], [0x22; 32]],
            }),
        )
        .await
        .unwrap();

    match response {
        Some(PulseMessage::RegistryQueryResponse(resp)) => {
            assert_eq!(resp.active, vec![true, true]);
        }
        other => panic!("expected RegistryQueryResponse, got {other:?}"),
    }

    listen_task.abort();
    let _ = listen_task.await;
}

#[tokio::test]
async fn peer_exchange_returns_serialized_mesh_contacts() {
    let node_a = spawn_local_mesh_node(3).await;
    let node_b = spawn_local_mesh_node(4).await;
    let node_c = spawn_local_mesh_node(5).await;
    node_a.wait_online().await;
    node_b.wait_online().await;
    node_c.wait_online().await;

    let node_c_contact = node_c.contact();

    let node_b_task = {
        let node_b = node_b.clone();
        let node_c_contact = node_c_contact.clone();
        tokio::spawn(async move {
            let _ = node_b
                .listen_messages_with_response(move |_peer, msg| match msg {
                    PulseMessage::PeerExchange(_) => Some(PulseMessage::PeerExchangeResponse(
                        vess_protocol::PeerExchangeResponse {
                            peers: vec![encode_mesh_contact(&node_c_contact).unwrap()],
                        },
                    )),
                    _ => None,
                })
                .await;
        })
    };

    let node_c_task = {
        let node_c = node_c.clone();
        tokio::spawn(async move {
            let _ = node_c
                .listen_messages_with_response(|_peer, msg| match msg {
                    PulseMessage::RegistryQuery(query) => {
                        Some(PulseMessage::RegistryQueryResponse(RegistryQueryResponse {
                            active: query.mint_ids.iter().map(|_| true).collect(),
                        }))
                    }
                    _ => None,
                })
                .await;
        })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;

    let discovery = node_a
        .send_message_with_response(
            &node_b.contact(),
            &PulseMessage::PeerExchange(PeerExchange {
                sender_id: node_a.id().as_bytes().to_vec(),
            }),
        )
        .await
        .unwrap();

    let discovered_contact = match discovery {
        Some(PulseMessage::PeerExchangeResponse(resp)) => {
            assert_eq!(resp.peers.len(), 1);
            decode_mesh_contact(&resp.peers[0]).unwrap()
        }
        other => panic!("expected PeerExchangeResponse, got {other:?}"),
    };

    assert_eq!(discovered_contact, node_c_contact);

    let response = node_a
        .send_message_with_response(
            &discovered_contact,
            &PulseMessage::RegistryQuery(RegistryQuery {
                mint_ids: vec![[0x33; 32]],
            }),
        )
        .await
        .unwrap();

    match response {
        Some(PulseMessage::RegistryQueryResponse(resp)) => {
            assert_eq!(resp.active, vec![true]);
        }
        other => panic!("expected RegistryQueryResponse from discovered peer, got {other:?}"),
    }

    node_b_task.abort();
    node_c_task.abort();
    let _ = node_b_task.await;
    let _ = node_c_task.await;
}

#[test]
fn payment_and_mesh_identities_are_separate_but_compatible() {
    let phrase = RecoveryPhrase::from_input(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let raw_seed = derive_raw_seed_with_params(&phrase, 1, 64, 1).unwrap();

    let (recipient_secret, recipient_address) = generate_master_keys_from_seed(&raw_seed);
    let (mesh_secret, mesh_address) = generate_mesh_keys_from_seed(&raw_seed, 0);

    assert_ne!(recipient_address.scan_ek, mesh_address.network_scan_ek);
    assert_ne!(recipient_address.spend_ek, mesh_address.network_route_ek);

    let route = generate_route_handshake(&mesh_address).unwrap();
    let opened = open_route_handshake(&mesh_secret, &route.handshake).unwrap();
    assert_eq!(opened.session_key, route.session_key);

    let mut sender_billfold = BillFold::new();
    sender_billfold.deposit(fresh_bill(Denomination::D10));

    let payment = match prepare_payment(&sender_billfold, 10, &recipient_address)
        .unwrap()
        .0
    {
        PulseMessage::Payment(payment) => payment,
        other => panic!("expected Payment, got {other:?}"),
    };

    let received = try_receive_payment(&recipient_secret, &payment)
        .unwrap()
        .expect("recipient should decrypt payment");
    assert!(!received.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn program_lock_receipt_unlock_propagates_across_live_nodes() {
    let node_a = spawn_local_mesh_node(9).await;
    let node_b = spawn_local_mesh_node(10).await;
    node_a.wait_online().await;
    node_b.wait_online().await;

    #[derive(Default)]
    struct TestNodeState {
        compute_dht: vess_compute::ComputeDht,
        registry: OwnershipRegistry,
    }

    let state = std::sync::Arc::new(std::sync::Mutex::new(TestNodeState {
        compute_dht: vess_compute::ComputeDht::new(),
        registry: OwnershipRegistry::new(*node_b.id().as_bytes()),
    }));

    let listener = {
        let node_b = node_b.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let _ = node_b
                .listen_messages_with_response(move |_peer, msg| {
                    let mut state = state.lock().unwrap();
                    match msg {
                        PulseMessage::ProgramStore(store) => {
                            let _ = state.compute_dht.store_program(store.program);
                            None
                        }
                        PulseMessage::ProgramFetch(ProgramFetch { prog_id }) => {
                            Some(PulseMessage::ProgramFetchResponse(
                                vess_protocol::ProgramFetchResponse {
                                    program: state.compute_dht.fetch_program(prog_id).cloned(),
                                },
                            ))
                        }
                        PulseMessage::OwnershipGenesis(og) => {
                            let proof_hash = match &og.genesis_proof {
                                GenesisProof::LocalTestFaucet(proof) => {
                                    let mut h = blake3::Hasher::new();
                                    h.update(b"vess-local-test-faucet-proof-v0");
                                    h.update(&proof.nonce);
                                    *h.finalize().as_bytes()
                                }
                                _ => [0u8; 32],
                            };
                            let record = OwnershipRecord {
                                mint_id: og.mint_id,
                                chain_tip: og.chain_tip,
                                prev_transfer_chain_tip: None,
                                current_owner_vk_hash: og.owner_vk_hash,
                                current_owner_vk: og.owner_vk,
                                current_owner_program: og.program_owner,
                                denomination_value: og.denomination_value,
                                updated_at: now_unix(),
                                proof_hash,
                                digest: og.digest,
                                nonce: match og.genesis_proof {
                                    GenesisProof::LocalTestFaucet(LocalTestFaucetProof { nonce }) => nonce,
                                    _ => [0u8; 32],
                                },
                                prev_claim_vk_hash: None,
                                claim_hash: None,
                                chain_depth: og.chain_depth,
                                encrypted_bill: Vec::new(),
                                accumulated_work: None,
                            };
                            state.registry.register(record);
                            None
                        }
                        PulseMessage::OwnershipClaim(oc) => {
                            if let Some(prev_program) = &oc.prev_owner_program {
                                let witness = oc.program_spend_witness.as_ref().unwrap();
                                let program = state
                                    .compute_dht
                                    .fetch_program(witness.receipt.prog_id)
                                    .unwrap();
                                witness
                                    .validates_condition(prev_program, &program.definition)
                                    .unwrap();
                            } else {
                                let transfer_msg = vess_foundry::spend_auth::transfer_message(
                                    &oc.mint_id,
                                    &oc.stealth_id,
                                    oc.timestamp,
                                );
                                assert!(vess_foundry::spend_auth::verify_spend(
                                    &oc.prev_owner_vk,
                                    &transfer_msg,
                                    &oc.transfer_sig,
                                )
                                .unwrap());
                            }
                            let record = state.registry.get_mut(&oc.mint_id).unwrap();
                            record.chain_tip = oc.new_chain_tip;
                            record.current_owner_vk_hash = oc.new_owner_vk_hash;
                            record.current_owner_vk = oc.new_owner_vk;
                            record.current_owner_program = oc.new_owner_program;
                            record.updated_at = oc.timestamp;
                            record.chain_depth = oc.chain_depth;
                            record.encrypted_bill = oc.encrypted_bill;
                            None
                        }
                        PulseMessage::OwnershipFetch(fetch) => Some(PulseMessage::OwnershipFetchResponse(
                            vess_protocol::OwnershipFetchResponse {
                                records: fetch
                                    .mint_ids
                                    .into_iter()
                                    .map(|mint_id| match state.registry.get(&mint_id) {
                                        Some(record) => vess_protocol::FetchedRecord {
                                            mint_id,
                                            found: true,
                                            denomination_value: record.denomination_value,
                                            chain_tip: record.chain_tip,
                                            digest: record.digest,
                                        },
                                        None => vess_protocol::FetchedRecord {
                                            mint_id,
                                            found: false,
                                            denomination_value: 0,
                                            chain_tip: [0u8; 32],
                                            digest: [0u8; 32],
                                        },
                                    })
                                    .collect(),
                            },
                        )),
                        PulseMessage::ComputeReceiptStore(store) => {
                            let _ = state.compute_dht.store_receipt(store.receipt);
                            None
                        }
                        PulseMessage::ProgramReceiptList(ProgramReceiptList { prog_id }) => {
                            Some(PulseMessage::ProgramReceiptListResponse(
                                vess_protocol::ProgramReceiptListResponse {
                                    receipt_ids: state.compute_dht.receipts_for_program(prog_id),
                                },
                            ))
                        }
                        PulseMessage::ComputeReceiptFetch(ComputeReceiptFetch { receipt_id }) => {
                            Some(PulseMessage::ComputeReceiptFetchResponse(
                                vess_protocol::ComputeReceiptFetchResponse {
                                    receipt: state.compute_dht.fetch_receipt(&receipt_id).cloned(),
                                },
                            ))
                        }
                        _ => None,
                    }
                })
                .await;
        })
    };

    let definition = sample_program_definition();
    let prog_id = definition.prog_id();
    let (pow_nonce, pow_hash) = compute_program_pow_test(&prog_id, None).unwrap();
    let stored_program = StoredProgram {
        definition: definition.clone(),
        published_at: now_unix(),
        pow_nonce,
        pow_hash,
        publisher_vk: None,
        signature: Vec::new(),
        last_bill_sent_at: None,
    };

    node_a
        .send_message(
            &node_b.contact(),
            &PulseMessage::ProgramStore(ProgramStore {
                program: stored_program.clone(),
                hops_remaining: 8,
            }),
        )
        .await
        .unwrap();

    let fetched_program = wait_for_program_fetch(&node_a, &node_b.contact(), prog_id).await;
    assert_eq!(fetched_program.prog_id(), prog_id);

    let (owner_vk, owner_sk) = generate_spend_keypair();
    let owner_vk_hash = vk_hash(&owner_vk);
    let nonce = [0x31; 32];
    let digest = local_test_faucet_digest(&nonce, 10, &owner_vk_hash);
    let mint_id = vess_foundry::derive_mint_id(&digest, &nonce);
    let chain_tip = vess_foundry::genesis_chain_tip(&mint_id, &owner_vk_hash);
    let bill = VessBill {
        denomination: Denomination::D10,
        digest,
        created_at: now_unix(),
        stealth_id: [0x44; 32],
        dht_index: 0,
        mint_id,
        chain_tip,
        chain_depth: 0,
    };

    node_a
        .send_message(
            &node_b.contact(),
            &PulseMessage::OwnershipGenesis(OwnershipGenesis {
                mint_id,
                chain_tip,
                owner_vk_hash,
                owner_vk: owner_vk.clone(),
                program_owner: None,
                denomination_value: 10,
                genesis_proof: GenesisProof::LocalTestFaucet(LocalTestFaucetProof { nonce }),
                digest,
                hops_remaining: 8,
                chain_depth: 0,
                output_index: 0,
                pow_nonce: None,
                pow_hash: None,
                accumulated_work: None,
            }),
        )
        .await
        .unwrap();

    wait_for_ownership_chain_tip(&node_a, &node_b.contact(), mint_id, chain_tip).await;

    let condition = ProgramOwnershipCondition {
        controller: ProgramAddress {
            prog_id,
            entrypoint: "main".to_string(),
            state_key: None,
        },
        required_proof_system: ProofSystem::VessStarkV1,
        state_commitment: [0x55; 32],
    };
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        mint_id,
        SpendCredential {
            spend_vk: owner_vk.clone(),
            spend_sk: owner_sk,
        },
    );
    let lock_claim = match build_program_lock_claims(&[bill.clone()], &credentials, &condition)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
    {
        PulseMessage::OwnershipClaim(claim) => claim,
        other => panic!("expected ownership claim, got {other:?}"),
    };

    node_a
        .send_message(&node_b.contact(), &PulseMessage::OwnershipClaim(lock_claim.clone()))
        .await
        .unwrap();

    wait_for_ownership_chain_tip(&node_a, &node_b.contact(), mint_id, lock_claim.new_chain_tip).await;

    let proof = StarkProofEnvelope {
        proof_system: ProofSystem::VessStarkV1,
        proof_bytes: vec![0x99, 0x88, 0x77],
        public_inputs_hash: [0x66; 32],
        public_outputs_hash: [0x77; 32],
        transcript_hash: [0x88; 32],
    };
    let receipt = ComputeReceipt::new(
        prog_id,
        [0x21; 32],
        proof.public_inputs_hash,
        proof.public_outputs_hash,
        Some(proof),
        vec![],
        now_unix(),
    );

    node_a
        .send_message(
            &node_b.contact(),
            &PulseMessage::ComputeReceiptStore(ComputeReceiptStore {
                receipt: receipt.clone(),
                hops_remaining: 8,
            }),
        )
        .await
        .unwrap();

    let fetched_receipt = wait_for_receipt(&node_a, &node_b.contact(), prog_id, receipt.receipt_id).await;
    assert_eq!(fetched_receipt.receipt_id, receipt.receipt_id);

    let (recipient_vk, recipient_sk) = generate_spend_keypair();
    let recipient = SpendCredential {
        spend_vk: recipient_vk,
        spend_sk: recipient_sk,
    };
    let witness = ProgramSpendWitness {
        receipt: receipt.clone(),
        authorized_mint_ids: vec![mint_id],
        next_owner_commitment: vk_hash(&recipient.spend_vk),
    };
    let locked_bill = VessBill {
        chain_tip: lock_claim.new_chain_tip,
        chain_depth: 1,
        ..bill.clone()
    };
    let unlock_claim = match build_program_unlock_claims(
        &[locked_bill],
        &condition,
        &witness,
        [0x91; 32],
        &recipient,
        None,
    )
    .unwrap()
    .ownership_claims
    .into_iter()
    .next()
    .unwrap()
    {
        PulseMessage::OwnershipClaim(claim) => claim,
        other => panic!("expected ownership claim, got {other:?}"),
    };

    node_a
        .send_message(&node_b.contact(), &PulseMessage::OwnershipClaim(unlock_claim.clone()))
        .await
        .unwrap();

    wait_for_ownership_chain_tip(&node_a, &node_b.contact(), mint_id, unlock_claim.new_chain_tip).await;

    node_a.shutdown().await;
    node_b.shutdown().await;
    listener.abort();
    let _ = listener.await;
}
