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
pub const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;
pub const VESS_MDNS_SERVICE: &str = "_vess._udp.local";
const LOCAL_PEER_STALE_SECS: u64 = 120;
const LAN_DISCOVERY_VERSION: u8 = 1;
const MAX_LOCAL_PEER_RECORD_BYTES: usize = 64 * 1024;
const MAX_LAN_DISCOVERY_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_MDNS_MESSAGE_BYTES: usize = 9000; // RFC 6762 recommends <9000 for legacy compatibility
/// Minimum peers before discovery backs off from aggressive mode.
const HYDRA_TARGET_PEERS: usize = 8;
/// Aggressive probe interval (seconds) when below target.
const HYDRA_AGGRESSIVE_INTERVAL_SECS: u64 = 3;
/// Steady-state probe interval (seconds) when at or above target.
const HYDRA_STEADY_INTERVAL_SECS: u64 = 15;
/// Max parallel handshakes from the hydra drain.
const HYDRA_MAX_PARALLEL_HANDSHAKES: usize = 4;

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

pub fn contact_from_lan_source(
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
    #[cfg(all(unix, not(target_os = "android")))]
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

// ── mDNS (RFC 6762) protocol primitives ────────────────────────────
//
// These are pure wire-format helpers.  The spawner functions that need
// ArteryState live in node_runner.rs.

/// Build an mDNS query for `_vess._udp.local` PTR records (service discovery).
pub fn build_mdns_query() -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    // DNS header: ID=0, FLAGS=0x0000 (standard query), QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00]); // Transaction ID
    buf.extend_from_slice(&[0x00, 0x00]); // Flags
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
    // Question: _vess._udp.local PTR
    buf.push(5); buf.extend_from_slice(b"_vess");
    buf.push(4); buf.extend_from_slice(b"_udp");
    buf.push(5); buf.extend_from_slice(b"local");
    buf.push(0x00); // Root
    buf.extend_from_slice(&[0x00, 0x0C]); // QTYPE = PTR
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    buf
}

/// Build an mDNS response advertising this node with PTR + SRV + TXT records.
pub fn build_mdns_response(
    node_id: &str,
    contact_str: &str,
    service_port: u16,
) -> Result<Vec<u8>> {
    let hostname = format!("{}.local", &node_id[..12]);
    let hostname_bytes = hostname.as_bytes();
    let mut hostname_labels = Vec::new();
    for part in hostname.split('.') {
        hostname_labels.push(part.len() as u8);
        hostname_labels.extend_from_slice(part.as_bytes());
    }
    hostname_labels.push(0x00);

    let txt_value = format!("contact={}", contact_str);
    let txt_bytes = txt_value.as_bytes();
    let mut txt_rdata = Vec::new();
    txt_rdata.push(txt_bytes.len() as u8);
    txt_rdata.extend_from_slice(txt_bytes);

    let total = 12
        + hostname_labels.len() + 4 + hostname_labels.len() + 2 + 2 + 2 + 2
        + hostname_labels.len() + 2 + 2 + 2 + 2 + 6
        + hostname_labels.len() + 2 + 2 + 2 + 2 + txt_rdata.len();
    let mut buf = Vec::with_capacity(total);

    // Header
    buf.extend_from_slice(&[0x00, 0x00]); // ID
    buf.extend_from_slice(&[0x84, 0x00]); // Flags: response + authoritative
    buf.extend_from_slice(&[0x00, 0x00]); // QDCOUNT
    buf.extend_from_slice(&[0x00, 0x03]); // ANCOUNT = 3
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // PTR: _vess._udp.local → hostname
    buf.push(5); buf.extend_from_slice(b"_vess");
    buf.push(4); buf.extend_from_slice(b"_udp");
    buf.push(5); buf.extend_from_slice(b"local"); buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // TYPE=PTR, CLASS=IN
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL=120
    let ptr_len = hostname_labels.len() as u16;
    buf.extend_from_slice(&ptr_len.to_be_bytes());
    buf.extend_from_slice(&hostname_labels);

    // SRV: hostname SRV 0 0 <port> hostname
    buf.extend_from_slice(&hostname_labels);
    buf.extend_from_slice(&[0x00, 0x21, 0x80, 0x01]); // TYPE=SRV, CLASS=IN+flush
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL=120
    let srv_len = (6 + hostname_labels.len()) as u16;
    buf.extend_from_slice(&srv_len.to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Priority=0, Weight=0
    buf.extend_from_slice(&service_port.to_be_bytes());
    buf.extend_from_slice(&hostname_labels);

    // TXT: hostname TXT "contact=..."
    buf.extend_from_slice(&hostname_labels);
    buf.extend_from_slice(&[0x00, 0x10, 0x80, 0x01]); // TYPE=TXT, CLASS=IN+flush
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL=120
    let txt_len = txt_rdata.len() as u16;
    buf.extend_from_slice(&txt_len.to_be_bytes());
    buf.extend_from_slice(&txt_rdata);

    Ok(buf)
}

/// Check if a DNS message is an mDNS query for `_vess._udp.local`.
pub fn is_vess_mdns_query(payload: &[u8]) -> bool {
    if payload.len() < 12 { return false; }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 { return false; } // QR=1 → response
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 { return false; }
    let mut pos = 12;
    let mut labels: Vec<&[u8]> = Vec::new();
    while pos < payload.len() && payload[pos] != 0 {
        let len = payload[pos] as usize;
        if len > 63 || pos + 1 + len > payload.len() { return false; }
        pos += 1;
        labels.push(&payload[pos..pos + len]);
        pos += len;
    }
    labels.first().map(|l| *l == b"_vess").unwrap_or(false)
}

/// Parse contact string from an mDNS TXT record in a DNS response.
pub fn parse_mdns_txt_contact(payload: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < payload.len() {
        let len = payload[pos] as usize;
        pos += 1;
        if pos + len > payload.len() { break; }
        let kv = &payload[pos..pos + len];
        pos += len;
        if kv.starts_with(b"contact=") {
            return String::from_utf8(kv[8..].to_vec()).ok();
        }
    }
    None
}

/// Extract a contact string from a complete mDNS response packet.
/// Walks the answer section looking for TXT records.
pub fn extract_contact_from_mdns_response(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 { return None; }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 { return None; } // not a response
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    if ancount == 0 { return None; }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let mut pos = 12usize;

    // Skip question section
    for _ in 0..qdcount {
        while pos < payload.len() && payload[pos] != 0 {
            let len = payload[pos] as usize;
            if len > 63 || pos + 1 + len > payload.len() { return None; }
            pos += 1 + len;
        }
        if pos < payload.len() { pos += 1; }
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer records
    for _ in 0..ancount {
        if pos + 10 > payload.len() { break; }
        // Skip name (handle compression)
        if payload[pos] & 0xC0 == 0xC0 { pos += 2; }
        else {
            while pos < payload.len() && payload[pos] != 0 {
                let len = payload[pos] as usize;
                if len > 63 || pos + 1 + len > payload.len() { return None; }
                pos += 1 + len;
            }
            if pos < payload.len() { pos += 1; }
        }
        if pos + 10 > payload.len() { break; }
        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let rdlength = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > payload.len() { break; }
        if rtype == 16 {
            if let Some(contact) = parse_mdns_txt_contact(&payload[pos..pos + rdlength]) {
                return Some(contact);
            }
        }
        pos += rdlength;
    }
    None
}

/// Bind a UDP socket for mDNS (multicast 224.0.0.251:5353).
pub fn bind_mdns_socket() -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("create mDNS socket")?;
    socket.set_reuse_address(true).context("mDNS reuse addr")?;
    #[cfg(all(unix, not(target_os = "android")))]
    { let _ = socket.set_reuse_port(true); }
    socket.bind(
        &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into(),
    ).context("bind mDNS socket")?;
    socket.join_multicast_v4(&MDNS_MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)
        .context("join mDNS multicast")?;
    socket.set_multicast_loop_v4(true).context("mDNS loopback")?;
    socket.set_multicast_ttl_v4(255).context("mDNS TTL")?;
    socket.set_nonblocking(true).context("mDNS nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("Tokio mDNS socket")
}

/// Send an mDNS query to the multicast group.
pub async fn send_mdns_query(socket: &UdpSocket) -> Result<()> {
    let query = build_mdns_query();
    let target = SocketAddr::V4(SocketAddrV4::new(MDNS_MULTICAST_ADDR, MDNS_PORT));
    socket.send_to(&query, target).await
        .context("send mDNS query")?;
    Ok(())
}

/// Send an mDNS response to a querier (unicast).
pub async fn send_mdns_unicast_response(
    socket: &UdpSocket,
    target: SocketAddr,
    node_id: &str,
    contact: &MeshCarrierContact,
) -> Result<()> {
    let contact_str = encode_mesh_contact_string(contact)?;
    let response = build_mdns_response(node_id, &contact_str, LAN_DISCOVERY_PORT)?;
    socket.send_to(&response, target).await
        .context("send mDNS unicast response")?;
    Ok(())
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
