use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::warn;
use vess_mesh::{
    decode_mesh_contact_string, encode_mesh_contact_string, validate_mesh_contact,
    MeshCarrierContact,
};

#[cfg(windows)]
use ipconfig::{IfType, OperStatus};

pub const LAN_DISCOVERY_PORT: u16 = 18348;
const LOCAL_PEER_STALE_SECS: u64 = 120;
const LAN_DISCOVERY_VERSION: u8 = 1;
const MAX_LOCAL_PEER_RECORD_BYTES: usize = 64 * 1024;
const MAX_LAN_DISCOVERY_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalPeerRecord {
    version: u8,
    node_id: String,
    contact: String,
    pid: u32,
    updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LanDiscoveryEnvelope {
    version: u8,
    kind: LanDiscoveryKind,
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    contact: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LanDiscoveryKind {
    Announce,
    Probe,
    ProbeResponse,
}

#[derive(Debug, Clone)]
pub enum ParsedLanDiscovery {
    Probe,
    Contact(MeshCarrierContact),
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn local_peer_dir() -> PathBuf {
    dirs_next::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Vess")
        .join("local-peers")
}

#[cfg(windows)]
fn local_peer_process_alive(pid: u32) -> bool {
    unsafe {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code = 0u32;
        let ok = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        ok != 0 && exit_code == STILL_ACTIVE as u32
    }
}

#[cfg(not(windows))]
fn local_peer_process_alive(_pid: u32) -> bool {
    true
}

fn contact_node_id_string(contact: &MeshCarrierContact) -> Result<String> {
    contact
        .node_id()
        .map(|node_id| node_id.to_string())
        .ok_or_else(|| anyhow!("mesh contact is missing a node id"))
}

fn contact_matches_node_id(contact: &MeshCarrierContact, expected_node_id: &str) -> bool {
    contact
        .node_id()
        .map(|node_id| node_id.to_string() == expected_node_id)
        .unwrap_or(false)
}

fn peer_record_path(contact: &MeshCarrierContact) -> Result<PathBuf> {
    Ok(local_peer_dir().join(format!(
        "{}-{}.json",
        contact_node_id_string(contact)?,
        std::process::id()
    )))
}

pub fn loopback_contact(contact: &MeshCarrierContact) -> Result<MeshCarrierContact> {
    contact_with_ip(contact, IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn contact_with_ip(contact: &MeshCarrierContact, ip: IpAddr) -> Result<MeshCarrierContact> {
    validate_mesh_contact(contact)?;
    match contact {
        MeshCarrierContact::TcpSocket { addr, mesh_address } => {
            let socket: SocketAddr = addr
                .parse()
                .map_err(|error| anyhow!("invalid tcp mesh contact address: {error}"))?;
            Ok(MeshCarrierContact::TcpSocket {
                addr: SocketAddr::new(ip, socket.port()).to_string(),
                mesh_address: mesh_address.clone(),
            })
        }
        MeshCarrierContact::UdpSocket { addr, mesh_address } => {
            let socket: SocketAddr = addr
                .parse()
                .map_err(|error| anyhow!("invalid udp mesh contact address: {error}"))?;
            Ok(MeshCarrierContact::UdpSocket {
                addr: SocketAddr::new(ip, socket.port()).to_string(),
                mesh_address: mesh_address.clone(),
            })
        }
    }
}

fn contact_from_lan_source(
    contact: &MeshCarrierContact,
    source: SocketAddr,
) -> Result<MeshCarrierContact> {
    contact_with_ip(contact, source.ip())
}

fn ipv4_broadcast_addr(network: Ipv4Addr, prefix_len: u32) -> Option<Ipv4Addr> {
    if !(1..=30).contains(&prefix_len) {
        return None;
    }
    let mask = u32::MAX << (32 - prefix_len);
    Some(Ipv4Addr::from(u32::from(network) | !mask))
}

#[cfg(windows)]
fn lan_broadcast_targets() -> Vec<SocketAddr> {
    let mut targets = HashSet::from([SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::BROADCAST,
        LAN_DISCOVERY_PORT,
    ))]);

    if let Ok(adapters) = ipconfig::get_adapters() {
        for adapter in adapters {
            if adapter.oper_status() != OperStatus::IfOperStatusUp
                || adapter.if_type() == IfType::SoftwareLoopback
            {
                continue;
            }
            for (network, prefix_len) in adapter.prefixes() {
                let std::net::IpAddr::V4(network) = network else {
                    continue;
                };
                if let Some(broadcast) = ipv4_broadcast_addr(*network, *prefix_len) {
                    targets.insert(SocketAddr::V4(SocketAddrV4::new(
                        broadcast,
                        LAN_DISCOVERY_PORT,
                    )));
                }
            }
        }
    }

    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_unstable();
    targets
}

#[cfg(not(windows))]
fn lan_broadcast_targets() -> Vec<SocketAddr> {
    vec![SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::BROADCAST,
        LAN_DISCOVERY_PORT,
    ))]
}

fn lan_probe_targets() -> Vec<SocketAddr> {
    let mut targets = lan_broadcast_targets();
    let loopback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, LAN_DISCOVERY_PORT));
    if !targets.contains(&loopback) {
        targets.push(loopback);
    }
    targets
}

async fn send_lan_payload(
    socket: &UdpSocket,
    payload: &[u8],
    targets: &[SocketAddr],
    context: &str,
) -> Result<()> {
    let mut sent_any = false;
    let mut first_error = None;

    for target in targets {
        match socket.send_to(payload, *target).await {
            Ok(_) => sent_any = true,
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(anyhow!("{context} to {target}: {error}"));
                }
            }
        }
    }

    if sent_any {
        Ok(())
    } else {
        Err(first_error.unwrap_or_else(|| anyhow!("{context}: no LAN discovery targets available")))
    }
}

pub fn publish_local_contact(contact: &MeshCarrierContact) -> Result<()> {
    validate_mesh_contact(contact)?;
    let dir = local_peer_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create local Vess peer directory {}", dir.display()))?;
    let record = LocalPeerRecord {
        version: LAN_DISCOVERY_VERSION,
        node_id: contact_node_id_string(contact)?,
        contact: encode_mesh_contact_string(contact)?,
        pid: std::process::id(),
        updated_at_unix: now_unix(),
    };
    let path = peer_record_path(contact)?;
    let bytes = serde_json::to_vec_pretty(&record).context("encode local Vess peer record")?;
    std::fs::write(&path, bytes)
        .with_context(|| format!("write local Vess peer record {}", path.display()))?;
    Ok(())
}

pub fn discover_local_file_contacts(self_node_id: Option<[u8; 32]>) -> Vec<MeshCarrierContact> {
    let dir = local_peer_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let now = now_unix();
    let mut peers = Vec::new();
    let mut seen = HashSet::new();

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > MAX_LOCAL_PEER_RECORD_BYTES {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(record) = serde_json::from_slice::<LocalPeerRecord>(&bytes) else {
            continue;
        };
        if record.version != LAN_DISCOVERY_VERSION
            || now.saturating_sub(record.updated_at_unix) > LOCAL_PEER_STALE_SECS
            || !local_peer_process_alive(record.pid)
        {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(contact) = decode_mesh_contact_string(&record.contact) else {
            continue;
        };
        if validate_mesh_contact(&contact).is_err()
            || !contact_matches_node_id(&contact, record.node_id.trim())
        {
            continue;
        }
        let Some(node_id) = contact.node_id().map(|node_id| *node_id.as_bytes()) else {
            continue;
        };
        if Some(node_id) == self_node_id || !seen.insert(node_id) {
            continue;
        }
        peers.push(contact);
    }

    peers
}

pub fn bind_lan_discovery_socket(port: u16) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("create LAN discovery UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("enable LAN discovery UDP address reuse")?;
    #[cfg(unix)]
    {
        let _ = socket.set_reuse_port(true);
    }
    socket
        .set_broadcast(true)
        .context("enable LAN discovery UDP broadcast")?;
    socket
        .bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into())
        .context("bind LAN discovery UDP socket")?;
    socket
        .set_nonblocking(true)
        .context("set LAN discovery UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("create Tokio LAN discovery UDP socket")
}

pub fn announcement_payload(contact: &MeshCarrierContact) -> Result<Vec<u8>> {
    contact_payload(contact, LanDiscoveryKind::Announce)
}

pub fn probe_payload() -> Result<Vec<u8>> {
    serde_json::to_vec(&LanDiscoveryEnvelope {
        version: LAN_DISCOVERY_VERSION,
        kind: LanDiscoveryKind::Probe,
        node_id: None,
        contact: None,
    })
    .context("encode LAN discovery probe")
}

pub fn probe_response_payload(contact: &MeshCarrierContact) -> Result<Vec<u8>> {
    contact_payload(contact, LanDiscoveryKind::ProbeResponse)
}

fn contact_payload(contact: &MeshCarrierContact, kind: LanDiscoveryKind) -> Result<Vec<u8>> {
    validate_mesh_contact(contact)?;
    serde_json::to_vec(&LanDiscoveryEnvelope {
        version: LAN_DISCOVERY_VERSION,
        kind,
        node_id: Some(contact_node_id_string(contact)?),
        contact: Some(encode_mesh_contact_string(contact)?),
    })
    .context("encode LAN discovery contact message")
}

pub fn parse_lan_discovery_message(
    payload: &[u8],
    source: SocketAddr,
) -> Result<ParsedLanDiscovery> {
    if payload.len() > MAX_LAN_DISCOVERY_MESSAGE_BYTES {
        return Err(anyhow!("LAN discovery message too large"));
    }
    let envelope: LanDiscoveryEnvelope =
        serde_json::from_slice(payload).context("decode LAN discovery message")?;
    if envelope.version != LAN_DISCOVERY_VERSION {
        return Err(anyhow!("unsupported LAN discovery version"));
    }
    match envelope.kind {
        LanDiscoveryKind::Probe => Ok(ParsedLanDiscovery::Probe),
        LanDiscoveryKind::Announce | LanDiscoveryKind::ProbeResponse => {
            let node_id = envelope
                .node_id
                .as_deref()
                .ok_or_else(|| anyhow!("LAN discovery contact message missing node id"))?;
            let contact = envelope
                .contact
                .ok_or_else(|| anyhow!("LAN discovery contact message missing contact"))?;
            let contact = decode_mesh_contact_string(&contact)
                .context("decode LAN discovery mesh contact")?;
            validate_mesh_contact(&contact)?;
            if !contact_matches_node_id(&contact, node_id.trim()) {
                return Err(anyhow!("LAN discovery node id mismatch"));
            }
            Ok(ParsedLanDiscovery::Contact(contact_from_lan_source(
                &contact, source,
            )?))
        }
    }
}

pub async fn send_lan_announcement(socket: &UdpSocket, contact: &MeshCarrierContact) -> Result<()> {
    let payload = announcement_payload(contact)?;
    let targets = lan_broadcast_targets();
    send_lan_payload(
        socket,
        &payload,
        &targets,
        "send Vess LAN discovery announcement",
    )
    .await?;
    Ok(())
}

pub async fn send_lan_probe(socket: &UdpSocket) -> Result<()> {
    let payload = probe_payload()?;
    let targets = lan_probe_targets();
    send_lan_payload(&socket, &payload, &targets, "send Vess LAN discovery probe").await?;
    Ok(())
}

pub async fn send_probe_response(
    socket: &UdpSocket,
    target: SocketAddr,
    contact: &MeshCarrierContact,
) -> Result<()> {
    let payload = probe_response_payload(contact)?;
    socket
        .send_to(&payload, target)
        .await
        .context("send Vess LAN discovery probe response")?;
    Ok(())
}

pub async fn discover_lan_peer_contacts(
    timeout: Duration,
    self_node_id: Option<[u8; 32]>,
) -> Vec<MeshCarrierContact> {
    let mut peers = discover_local_file_contacts(self_node_id);
    let mut seen: HashSet<[u8; 32]> = peers
        .iter()
        .filter_map(|contact| contact.node_id().map(|node_id| *node_id.as_bytes()))
        .collect();

    let Ok(socket) = bind_lan_discovery_socket(0) else {
        return peers;
    };
    if send_lan_probe(&socket).await.is_err() {
        return peers;
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut buffer = vec![0u8; MAX_LAN_DISCOVERY_MESSAGE_BYTES];
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(now);
        let recv = tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await;
        let Ok(Ok((len, source))) = recv else {
            break;
        };
        let Ok(ParsedLanDiscovery::Contact(contact)) =
            parse_lan_discovery_message(&buffer[..len], source)
        else {
            continue;
        };
        let Some(node_id) = contact.node_id().map(|node_id| *node_id.as_bytes()) else {
            continue;
        };
        if Some(node_id) == self_node_id || !seen.insert(node_id) {
            continue;
        }
        peers.push(contact);
    }

    peers
}

pub fn log_publish_error(error: anyhow::Error) {
    warn!(%error, "failed to publish local Vess peer contact");
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn test_contact(seed_byte: u8, addr: &str) -> MeshCarrierContact {
        let seed = [seed_byte; 64];
        let (_, mesh_address) = vess_mesh::generate_mesh_keys_from_seed(&seed, 0);
        MeshCarrierContact::UdpSocket {
            addr: addr.to_string(),
            mesh_address,
        }
    }

    #[test]
    fn ipv4_broadcast_addr_uses_prefix_length() {
        assert_eq!(
            ipv4_broadcast_addr(Ipv4Addr::new(192, 168, 1, 0), 24),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(
            ipv4_broadcast_addr(Ipv4Addr::new(10, 42, 0, 0), 16),
            Some(Ipv4Addr::new(10, 42, 255, 255))
        );
        assert_eq!(ipv4_broadcast_addr(Ipv4Addr::new(192, 168, 1, 0), 31), None);
        assert_eq!(ipv4_broadcast_addr(Ipv4Addr::new(192, 168, 1, 0), 32), None);
    }

    #[test]
    fn lan_discovery_rejects_mismatched_node_id() {
        let contact = test_contact(7, "10.0.0.7:19001");
        let payload = serde_json::to_vec(&LanDiscoveryEnvelope {
            version: LAN_DISCOVERY_VERSION,
            kind: LanDiscoveryKind::Announce,
            node_id: Some("wrong-node-id".to_string()),
            contact: Some(encode_mesh_contact_string(&contact).unwrap()),
        })
        .unwrap();

        let error = parse_lan_discovery_message(
            &payload,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 8), LAN_DISCOVERY_PORT)),
        )
        .unwrap_err();

        assert!(error.to_string().contains("node id mismatch"));
    }

    #[test]
    fn lan_discovery_preserves_contact_identity_but_uses_source_ip() {
        let contact = test_contact(8, "203.0.113.8:19002");
        let expected_node_id = contact.node_id().unwrap().to_string();
        let payload = announcement_payload(&contact).unwrap();
        let source = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 44), 55555));

        let ParsedLanDiscovery::Contact(parsed) = parse_lan_discovery_message(&payload, source).unwrap() else {
            panic!("expected LAN discovery contact");
        };

        assert_eq!(parsed.node_id().unwrap().to_string(), expected_node_id);
        match parsed {
            MeshCarrierContact::UdpSocket { addr, .. } => {
                assert!(addr.starts_with("192.168.1.44:"));
            }
            other => panic!("expected udp contact, got {other:?}"),
        }
    }

    proptest! {
        #[test]
        fn lan_discovery_parser_handles_arbitrary_payloads(
            payload in proptest::collection::vec(any::<u8>(), 0..(MAX_LAN_DISCOVERY_MESSAGE_BYTES + 512)),
            octet in any::<u8>(),
        ) {
            let source = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, octet), LAN_DISCOVERY_PORT));
            let result = parse_lan_discovery_message(&payload, source);
            if payload.len() > MAX_LAN_DISCOVERY_MESSAGE_BYTES {
                prop_assert!(result.is_err());
            }
        }
    }
}
