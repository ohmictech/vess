use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream as StdTcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::consensus::{serialize, Decodable};
use bitcoin::io::ErrorKind as BitcoinIoErrorKind;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::secp256k1::{ecdsa::Signature as EcdsaSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use vess_artery::node_runner::{run_node, NodeConfig};
use vess_bitcoin::{BitcoinConfig, BitcoinNetwork};
use vess_foundry::spend_auth::{generate_spend_keypair, sign_spend};
use vess_stealth::generate_master_keys_from_seed;
use vess_tag::{compute_tag_pow_test, TagRecord, VessTag};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedNode {
    node_id: String,
    contact: String,
    #[serde(default)]
    last_seen_unix: u64,
    #[serde(default)]
    auth_vk: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedChallengeRequest {
    version: u8,
    requester_node_id: Option<String>,
    requester_auth_vk: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedChallenge {
    version: u8,
    server_node_id: String,
    server_auth_vk: Vec<u8>,
    nonce: [u8; 32],
    expires_unix: u64,
    pow_difficulty_bits: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedRequestPayload {
    requester_node: Option<SeedNode>,
    known_nodes: Vec<SeedNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthenticatedSeedRequest {
    version: u8,
    requester_auth_vk: Vec<u8>,
    challenge_nonce: [u8; 32],
    challenge_expires_unix: u64,
    pow_nonce: Option<[u8; 32]>,
    payload: SeedRequestPayload,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeedResponsePayload {
    accepted: bool,
    local_node: Option<SeedNode>,
    known_nodes: Vec<SeedNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedSeedResponse {
    version: u8,
    server_node_id: String,
    server_auth_vk: Vec<u8>,
    timestamp_unix: u64,
    nonce: [u8; 32],
    payload_hash: [u8; 32],
    payload: SeedResponsePayload,
    signature: Vec<u8>,
}

struct NodeHarness {
    _tempdir: TempDir,
    state_dir: std::path::PathBuf,
    rpc_port: u16,
    task: tokio::task::JoinHandle<anyhow::Result<String>>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn bitcoin_magic(network: BitcoinNetwork) -> Magic {
    match network {
        BitcoinNetwork::Mainnet => Magic::BITCOIN,
        BitcoinNetwork::Testnet => Magic::TESTNET3,
        BitcoinNetwork::Signet => Magic::SIGNET,
        BitcoinNetwork::Regtest => Magic::REGTEST,
    }
}

fn send_bitcoin_message(
    stream: &mut StdTcpStream,
    network: BitcoinNetwork,
    payload: NetworkMessage,
) -> anyhow::Result<()> {
    let raw = RawNetworkMessage::new(bitcoin_magic(network), payload);
    let bytes = serialize(&raw);
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn serve_mock_bitcoin_peer(
    mut stream: StdTcpStream,
    network: BitcoinNetwork,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let peer = stream.peer_addr()?;
    let receiver = Address::new(&peer, ServiceFlags::NONE);
    let sender = Address::new(
        &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        ServiceFlags::NONE,
    );
    let version = VersionMessage::new(
        ServiceFlags::NONE,
        now_unix() as i64,
        receiver,
        sender,
        1,
        "/vess-test-bitcoin-peer/".to_string(),
        0,
    );

    let mut sent_handshake = false;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        match RawNetworkMessage::consensus_decode(&mut stream) {
            Ok(message) => match message.into_payload() {
                NetworkMessage::Version(_) => {
                    if !sent_handshake {
                        send_bitcoin_message(&mut stream, network, NetworkMessage::Version(version.clone()))?;
                        send_bitcoin_message(&mut stream, network, NetworkMessage::Verack)?;
                        sent_handshake = true;
                    }
                }
                NetworkMessage::Ping(nonce) => {
                    send_bitcoin_message(&mut stream, network, NetworkMessage::Pong(nonce))?;
                }
                NetworkMessage::GetAddr => {
                    send_bitcoin_message(&mut stream, network, NetworkMessage::Addr(Vec::new()))?;
                }
                NetworkMessage::GetHeaders(_) => {
                    send_bitcoin_message(&mut stream, network, NetworkMessage::Headers(Vec::new()))?;
                }
                _ => {}
            },
            Err(bitcoin::consensus::encode::Error::Io(ref err))
                if matches!(err.kind(), BitcoinIoErrorKind::WouldBlock | BitcoinIoErrorKind::TimedOut) =>
            {
                if shutdown.load(Ordering::Relaxed) {
                    return Ok(());
                }
                continue;
            }
            Err(bitcoin::consensus::encode::Error::Io(ref err))
                if matches!(err.kind(), BitcoinIoErrorKind::UnexpectedEof | BitcoinIoErrorKind::ConnectionReset | BitcoinIoErrorKind::BrokenPipe) =>
            {
                return Ok(());
            }
            Err(error) => return Err(anyhow::anyhow!(error)),
        }
    }
}

async fn spawn_mock_bitcoin_peer(
    network: BitcoinNetwork,
) -> anyhow::Result<(SocketAddr, Arc<AtomicBool>, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let shutdown = listener_shutdown.clone();
            tokio::task::spawn_blocking(move || {
                let Ok(stream) = stream.into_std() else {
                    return;
                };
                let _ = serve_mock_bitcoin_peer(stream, network, shutdown);
            });
        }
    });
    Ok((addr, shutdown, task))
}

async fn read_seed_message<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> anyhow::Result<T> {
    let len = stream.read_u32().await? as usize;
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice::<T>(&bytes)?)
}

async fn write_seed_message<T: Serialize>(stream: &mut TcpStream, value: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn spawn_vess_seed_server() -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let known_nodes = Arc::new(Mutex::new(HashMap::<String, SeedNode>::new()));
    let (server_auth_sk, server_auth_vk) = vess_bitcoin::derive_vess_seed_auth_keypair(&[0xA5; 64]);
    let server_node_id = Arc::new("mock-vess-seed".to_string());

    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let known_nodes = known_nodes.clone();
            let server_auth_vk = server_auth_vk.clone();
            let server_node_id = server_node_id.clone();
            tokio::spawn(async move {
                let Ok(request) = read_seed_message::<SeedChallengeRequest>(&mut stream).await else {
                    return;
                };
                if request.version != 1 {
                    return;
                }

                let nonce = [0x42; 32];
                let expires_unix = now_unix() + 60;
                let challenge = SeedChallenge {
                    version: 1,
                    server_node_id: (*server_node_id).clone(),
                    server_auth_vk: server_auth_vk.clone(),
                    nonce,
                    expires_unix,
                    pow_difficulty_bits: 8,
                };
                if write_seed_message(&mut stream, &challenge).await.is_err() {
                    return;
                }

                let Ok(request) = read_seed_message::<AuthenticatedSeedRequest>(&mut stream).await else {
                    return;
                };
                if request.version != 1
                    || request.challenge_nonce != nonce
                    || request.challenge_expires_unix != expires_unix
                    || !verify_seed_pow(
                        request.challenge_nonce,
                        request.challenge_expires_unix,
                        &request.requester_auth_vk,
                        hash_seed_payload(&request.payload),
                        challenge.pow_difficulty_bits,
                        request.pow_nonce,
                    )
                    || !verify_seed_request_digest(
                        &request.requester_auth_vk,
                        request.challenge_nonce,
                        request.challenge_expires_unix,
                        request.pow_nonce,
                        &request.payload,
                        &request.signature,
                    )
                {
                    return;
                }

                if let Some(node) = request.payload.requester_node {
                    known_nodes.lock().unwrap().insert(node.node_id.clone(), node);
                }
                for node in request.payload.known_nodes {
                    known_nodes.lock().unwrap().insert(node.node_id.clone(), node);
                }

                let payload = SeedResponsePayload {
                    accepted: true,
                    local_node: None,
                    known_nodes: known_nodes.lock().unwrap().values().cloned().collect(),
                };
                let payload_hash = hash_seed_payload(&payload);
                let timestamp_unix = now_unix();
                let response = SignedSeedResponse {
                    version: 1,
                    server_node_id: (*server_node_id).clone(),
                    server_auth_vk: server_auth_vk.clone(),
                    timestamp_unix,
                    nonce,
                    payload_hash,
                    payload,
                    signature: sign_seed_digest(
                        &server_auth_sk,
                        seed_response_digest(&server_node_id, timestamp_unix, nonce, payload_hash),
                    ),
                };
                let _ = write_seed_message(&mut stream, &response).await;
            });
        }
    });

    Ok((addr, task))
}

async fn rpc_call_with_dir(
    state_dir: &std::path::Path,
    port: u16,
    request: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let token_path = state_dir.join("rpc-token");
    let token = std::fs::read_to_string(&token_path)?;
    let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    writer.write_all(token.trim().as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let mut req = serde_json::to_vec(request)?;
    req.push(b'\n');
    writer.write_all(&req).await?;
    writer.flush().await?;

    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str::<serde_json::Value>(&line)?)
}

async fn wait_for_node_info(
    state_dir: &std::path::Path,
    port: u16,
    predicate: impl Fn(&serde_json::Value) -> bool,
    label: &str,
) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {label}");
        if let Ok(response) = rpc_call_with_dir(state_dir, port, &json!({ "method": "node_info" })).await {
            if response["ok"] == true && predicate(&response) {
                return response;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_tag_lookup(
    state_dir: &std::path::Path,
    port: u16,
    tag: &str,
    expected_scan_ek: &str,
    expected_spend_ek: &str,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for tag lookup {tag}");
        if let Ok(response) = rpc_call_with_dir(
            state_dir,
            port,
            &json!({ "method": "tag_lookup", "tag": tag }),
        )
        .await
        {
            if response["ok"] == true
                && response["found"] == true
                && response["scan_ek"].as_str() == Some(expected_scan_ek)
                && response["spend_ek"].as_str() == Some(expected_spend_ek)
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn wait_for_any_remote_tag_lookup(
    nodes: &[NodeHarness],
    registrations: &[(usize, String, String, String)],
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for any remote tag lookup"
        );

        for (owner_index, tag, expected_scan_ek, expected_spend_ek) in registrations {
            for (node_index, node) in nodes.iter().enumerate() {
                if node_index == *owner_index {
                    continue;
                }
                if let Ok(response) = rpc_call_with_dir(
                    &node.state_dir,
                    node.rpc_port,
                    &json!({ "method": "tag_lookup", "tag": tag }),
                )
                .await
                {
                    if response["ok"] == true
                        && response["found"] == true
                        && response["scan_ek"].as_str() == Some(expected_scan_ek)
                        && response["spend_ek"].as_str() == Some(expected_spend_ek)
                    {
                        return;
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn register_tag(state_dir: &std::path::Path, port: u16, tag: &str, seed_byte: u8) -> (String, String) {
    let tag = VessTag::new(tag).unwrap();
    let raw_seed = [seed_byte; 64];
    let (_secret, address) = generate_master_keys_from_seed(&raw_seed);
    let (registrant_vk, registrant_sk) = generate_spend_keypair();
    let tag_hash = *blake3::hash(tag.as_str().as_bytes()).as_bytes();
    let (pow_nonce, pow_hash) = compute_tag_pow_test(&tag_hash, &address.scan_ek, &address.spend_ek)
        .unwrap();

    let unsigned = TagRecord {
        tag_hash,
        master_address: address.clone(),
        pow_nonce,
        pow_hash: pow_hash.clone(),
        registered_at: now_unix(),
        registrant_vk: registrant_vk.clone(),
        signature: Vec::new(),
        hardened_at: None,
    };
    let signature = sign_spend(&registrant_sk, &unsigned.digest()).unwrap();

    let response = rpc_call_with_dir(
        state_dir,
        port,
        &json!({
            "method": "tag_register",
            "tag": tag.display(),
            "scan_ek_hex": to_hex(&address.scan_ek),
            "spend_ek_hex": to_hex(&address.spend_ek),
            "pow_nonce_hex": to_hex(&pow_nonce),
            "pow_hash_hex": to_hex(&pow_hash),
            "timestamp": unsigned.registered_at,
            "registrant_vk_hex": to_hex(&registrant_vk),
            "signature_hex": to_hex(&signature),
        }),
    )
    .await
    .unwrap();
    assert_eq!(response["ok"], true, "tag register failed: {response}");

    (to_hex(&address.scan_ek), to_hex(&address.spend_ek))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn five_nodes_discover_via_bitcoin_seed_and_register_tags() {
    let network = BitcoinNetwork::Regtest;
    let (seed_addr, seed_task) = spawn_vess_seed_server().await.unwrap();
    let (peer_a, peer_a_shutdown, peer_a_task) = spawn_mock_bitcoin_peer(network).await.unwrap();
    let (peer_b, peer_b_shutdown, peer_b_task) = spawn_mock_bitcoin_peer(network).await.unwrap();

    let mut nodes = Vec::new();
    for index in 0..5u8 {
        let tempdir = tempfile::tempdir().unwrap();
        let state_dir = tempdir.path().join(format!("node-{index}"));
        std::fs::create_dir_all(&state_dir).unwrap();

        let ready = tokio::sync::oneshot::channel();
        let rpc_port = 9500 + index as u16;
        let bitcoin_config = BitcoinConfig {
            network,
            peers: vec![peer_a, peer_b],
            seeds: Vec::new(),
            target_peers: 2,
            connect_timeout: Duration::from_secs(2),
            user_agent: format!("/vess-test-node-{index}/"),
            vess_seed_port: seed_addr.port(),
            vess_seed_scan_interval: Duration::from_secs(1),
            allow_private_vess_seed_contacts: true,
        };
        let config = NodeConfig {
            k_neighbors: 6,
            max_hops: 3,
            state_dir: state_dir.clone(),
            bootstrap: Vec::new(),
            ready_tx: Some(ready.0),
            wallet_path: None,
            rpc_port: Some(rpc_port),
            wallet_password: None,
            bitcoin_config: Some(bitcoin_config),
            enable_local_discovery: false,
            allow_private_bitcoin_seed_contact: true,
        };

        let task = tokio::spawn(async move { run_node(config).await });
        let _ = tokio::time::timeout(Duration::from_secs(15), ready.1)
            .await
            .expect("node did not come online in time")
            .expect("ready channel dropped");

        let _ = wait_for_node_info(
            &state_dir,
            rpc_port,
            |resp| resp["bitcoin_connected_peers"].as_u64().unwrap_or(0) >= 1,
            "bitcoin peer connection",
        )
        .await;

        nodes.push(NodeHarness {
            _tempdir: tempdir,
            state_dir,
            rpc_port,
            task,
        });

        tokio::time::sleep(Duration::from_millis(750)).await;
    }

    let mut registrations = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        let tag = format!("node{}tag", index);
        let (scan_ek, spend_ek) = register_tag(&node.state_dir, node.rpc_port, &tag, 11 + index as u8).await;
        wait_for_tag_lookup(&node.state_dir, node.rpc_port, &tag, &scan_ek, &spend_ek).await;
        registrations.push((index, tag, scan_ek, spend_ek));
    }

    wait_for_any_remote_tag_lookup(&nodes, &registrations).await;

    for (node_index, node) in nodes.iter().enumerate() {
        let info = rpc_call_with_dir(&node.state_dir, node.rpc_port, &json!({ "method": "node_info" }))
            .await
            .unwrap();
        assert!(info["bitcoin_connected_peers"].as_u64().unwrap_or(0) >= 1);
        assert!(info["tag_count"].as_u64().unwrap_or(0) >= 1, "node {node_index} never stored any tag");
    }

    for node in nodes {
        node.task.abort();
        let _ = node._tempdir.keep();
    }
    seed_task.abort();
    peer_a_shutdown.store(true, Ordering::Relaxed);
    peer_b_shutdown.store(true, Ordering::Relaxed);
    peer_a_task.abort();
    peer_b_task.abort();
}

fn hash_seed_payload<T: Serialize>(payload: &T) -> [u8; 32] {
    *blake3::hash(&serde_json::to_vec(payload).unwrap()).as_bytes()
}

fn seed_response_digest(
    server_node_id: &str,
    timestamp_unix: u64,
    nonce: [u8; 32],
    payload_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vess-seed-response-v1");
    hasher.update(server_node_id.as_bytes());
    hasher.update(&timestamp_unix.to_le_bytes());
    hasher.update(&nonce);
    hasher.update(&payload_hash);
    *hasher.finalize().as_bytes()
}

fn seed_request_digest(
    challenge_nonce: [u8; 32],
    challenge_expires_unix: u64,
    pow_nonce: Option<[u8; 32]>,
    payload_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vess-seed-request-v1");
    hasher.update(&challenge_nonce);
    hasher.update(&challenge_expires_unix.to_le_bytes());
    match pow_nonce {
        Some(pow_nonce) => {
            hasher.update(&[1]);
            hasher.update(&pow_nonce);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&payload_hash);
    *hasher.finalize().as_bytes()
}

fn seed_pow_digest(
    challenge_nonce: [u8; 32],
    challenge_expires_unix: u64,
    requester_auth_vk: &[u8],
    payload_hash: [u8; 32],
    pow_nonce: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"vess-seed-request-pow-v1");
    hasher.update(&challenge_nonce);
    hasher.update(&challenge_expires_unix.to_le_bytes());
    hasher.update(requester_auth_vk);
    hasher.update(&payload_hash);
    hasher.update(&pow_nonce);
    *hasher.finalize().as_bytes()
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut total = 0u32;
    for byte in hash {
        let zeros = byte.leading_zeros();
        total += zeros;
        if zeros != 8 {
            break;
        }
    }
    total
}

fn verify_seed_pow(
    challenge_nonce: [u8; 32],
    challenge_expires_unix: u64,
    requester_auth_vk: &[u8],
    payload_hash: [u8; 32],
    difficulty_bits: u8,
    pow_nonce: Option<[u8; 32]>,
) -> bool {
    if difficulty_bits == 0 {
        return true;
    }
    let Some(pow_nonce) = pow_nonce else {
        return false;
    };
    leading_zero_bits(&seed_pow_digest(
        challenge_nonce,
        challenge_expires_unix,
        requester_auth_vk,
        payload_hash,
        pow_nonce,
    )) >= difficulty_bits as u32
}

fn verify_seed_request_digest(
    auth_vk: &[u8],
    challenge_nonce: [u8; 32],
    challenge_expires_unix: u64,
    pow_nonce: Option<[u8; 32]>,
    payload: &SeedRequestPayload,
    signature: &[u8],
) -> bool {
    let payload_hash = hash_seed_payload(payload);
    let digest = seed_request_digest(challenge_nonce, challenge_expires_unix, pow_nonce, payload_hash);
    let public_key = PublicKey::from_slice(auth_vk).unwrap();
    let signature = EcdsaSignature::from_compact(signature).unwrap();
    let message = Message::from_digest_slice(&digest).unwrap();
    Secp256k1::verification_only()
        .verify_ecdsa(&message, &signature, &public_key)
        .is_ok()
}

fn sign_seed_digest(auth_sk: &[u8; 32], digest: [u8; 32]) -> Vec<u8> {
    let secret_key = SecretKey::from_slice(auth_sk).unwrap();
    let message = Message::from_digest_slice(&digest).unwrap();
    Secp256k1::new()
        .sign_ecdsa(&message, &secret_key)
        .serialize_compact()
        .to_vec()
}