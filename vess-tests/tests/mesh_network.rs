use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use vess_foundry::{Asset, Denomination, VessBill};
use vess_kloak::billfold::BillFold;
use vess_kloak::payment::{prepare_payment, try_receive_payment};
use vess_kloak::recovery::{derive_raw_seed_with_params, RecoveryPhrase};
use vess_mesh::{
    decode_mesh_contact, encode_mesh_contact, generate_mesh_keys_from_seed,
    generate_route_handshake, open_route_handshake,
};
use vess_protocol::{PeerExchange, PulseMessage, RegistryQuery, RegistryQueryResponse};
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
        asset: Asset::Btc,
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
