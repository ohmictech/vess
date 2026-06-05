//! **vess-mesh** — Vess-owned mesh identity and transport carrier surface.
//!
//! This crate owns the post-quantum mesh identity, route handshakes, and
//! carrier implementations used by the active Vess network.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{info, warn};

type EncapKey = <MlKem768 as KemCore>::EncapsulationKey;
type DecapKey = <MlKem768 as KemCore>::DecapsulationKey;

/// Maximum size of one framed mesh payload.
pub const MAX_MESH_FRAME_SIZE: usize = 16 * 1024 * 1024;
const MAX_MESH_UDP_PACKET_SIZE: usize = 64 * 1024;
pub const DEFAULT_UDP_MTU_SAFE_PAYLOAD: usize = 1200;
const MESH_CONTACT_BINARY_MAGIC: &[u8; 4] = b"VMC1";
const MESH_CONTACT_KIND_TCP: u8 = 1;
const MESH_CONTACT_KIND_UDP: u8 = 2;
const MESH_CONTACT_ADDR_IPV4: u8 = 4;
const MESH_CONTACT_ADDR_IPV6: u8 = 6;

/// Stable Vess-owned mesh node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshNodeId(pub [u8; 32]);

impl MeshNodeId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for MeshNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Published post-quantum network address for a mesh node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshAddress {
    pub node_id: MeshNodeId,
    pub epoch: u64,
    pub network_scan_ek: Vec<u8>,
    pub network_route_ek: Vec<u8>,
}

/// Secret half of a mesh address.
#[derive(Clone)]
pub struct MeshSecretKey {
    pub node_id: MeshNodeId,
    pub epoch: u64,
    pub network_scan_dk: Vec<u8>,
    pub network_route_dk: Vec<u8>,
}

/// One-time handshake capsule for a mesh route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRouteHandshake {
    pub node_id: MeshNodeId,
    pub epoch: u64,
    pub ct_scan: Vec<u8>,
    pub ct_route: Vec<u8>,
    pub view_tag: u8,
    pub route_id: [u8; 32],
}

/// Sender-side route context including the derived session key.
pub struct MeshRouteContext {
    pub handshake: MeshRouteHandshake,
    pub session_key: [u8; 32],
}

/// Receiver-side route result after decapsulation.
pub struct OpenedMeshRoute {
    pub node_id: MeshNodeId,
    pub epoch: u64,
    pub view_tag: u8,
    pub route_id: [u8; 32],
    pub session_key: [u8; 32],
}

/// One fragment of a larger logical UDP payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshFragment {
    pub message_id: [u8; 16],
    pub index: u16,
    pub total: u16,
    pub payload: Vec<u8>,
}

/// Multiplexed frame for a long-lived logical mesh session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshSessionFrame {
    pub session_id: [u8; 16],
    pub stream_id: u32,
    pub sequence: u64,
    pub kind: MeshSessionFrameKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeshSessionFrameKind {
    Open,
    Data,
    Close,
    Reset,
}

/// Opaque peer contact understood by a particular carrier backend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeshCarrierContact {
    TcpSocket {
        addr: String,
        mesh_address: MeshAddress,
    },
    UdpSocket {
        addr: String,
        mesh_address: MeshAddress,
    },
}

/// Peer information surfaced by a carrier implementation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshPeer {
    pub contact: MeshCarrierContact,
}

impl MeshCarrierContact {
    pub fn node_id(&self) -> Option<MeshNodeId> {
        match self {
            MeshCarrierContact::TcpSocket { mesh_address, .. }
            | MeshCarrierContact::UdpSocket { mesh_address, .. } => Some(mesh_address.node_id),
        }
    }
}

/// Recompute the node id that belongs to a published mesh address.
pub fn expected_mesh_node_id(address: &MeshAddress) -> Result<MeshNodeId> {
    // Validate public key encodings before deriving identity from their bytes.
    vec_to_ek(&address.network_scan_ek)?;
    vec_to_ek(&address.network_route_ek)?;
    Ok(derive_node_id(
        address.epoch,
        &address.network_scan_ek,
        &address.network_route_ek,
    ))
}

/// Validate that a published mesh address is internally self-consistent.
pub fn validate_mesh_address(address: &MeshAddress) -> Result<()> {
    let expected = expected_mesh_node_id(address)?;
    anyhow::ensure!(
        expected == address.node_id,
        "mesh address node_id does not match its public route keys"
    );
    Ok(())
}

/// Validate a carrier contact before accepting it into routing or dialing it.
pub fn validate_mesh_contact(contact: &MeshCarrierContact) -> Result<()> {
    match contact {
        MeshCarrierContact::TcpSocket { addr, mesh_address }
        | MeshCarrierContact::UdpSocket { addr, mesh_address } => {
            addr.parse::<SocketAddr>()
                .map_err(|error| anyhow!("invalid mesh contact socket address: {error}"))?;
            validate_mesh_address(mesh_address)
        }
    }
}

/// Policy for contact material that is going to be advertised to other nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvertisedContactPolicy {
    /// Local/test/LAN contexts may use loopback, private, and wildcard sockets.
    Local,
    /// Public discovery contexts must only publish globally routable sockets.
    Public,
}

/// Validate a contact for an explicit advertising context.
pub fn validate_advertised_mesh_contact(
    contact: &MeshCarrierContact,
    policy: AdvertisedContactPolicy,
) -> Result<()> {
    validate_mesh_contact(contact)?;
    if policy == AdvertisedContactPolicy::Public {
        let socket = contact_socket_addr(contact)?;
        anyhow::ensure!(
            is_public_routable_socket_addr(&socket),
            "public mesh contact must advertise a globally routable socket address"
        );
    }
    Ok(())
}

/// Validate a contact before placing it in public DNS or Bitcoin-side seed exchange.
pub fn validate_public_mesh_contact(contact: &MeshCarrierContact) -> Result<()> {
    validate_advertised_mesh_contact(contact, AdvertisedContactPolicy::Public)
}

/// Returns `true` when a socket address is acceptable for public discovery.
pub fn is_public_routable_socket_addr(addr: &SocketAddr) -> bool {
    addr.port() != 0
        && match addr.ip() {
            IpAddr::V4(ip) => is_public_routable_ipv4(ip),
            IpAddr::V6(ip) => is_public_routable_ipv6(ip),
        }
}

/// Compact binary encoding for a carrier contact.
///
/// This format is used for routing tables, peer exchange, and seed records.
/// `decode_mesh_contact` also accepts legacy JSON bytes for compatibility.
pub fn encode_mesh_contact(contact: &MeshCarrierContact) -> Result<Vec<u8>> {
    validate_mesh_contact(contact)?;
    let (kind, addr, mesh_address) = match contact {
        MeshCarrierContact::TcpSocket { addr, mesh_address } => {
            (MESH_CONTACT_KIND_TCP, addr, mesh_address)
        }
        MeshCarrierContact::UdpSocket { addr, mesh_address } => {
            (MESH_CONTACT_KIND_UDP, addr, mesh_address)
        }
    };
    let socket: SocketAddr = addr
        .parse()
        .map_err(|error| anyhow!("invalid mesh contact socket address: {error}"))?;
    let scan_len: u16 = mesh_address
        .network_scan_ek
        .len()
        .try_into()
        .map_err(|_| anyhow!("mesh scan key too large for compact contact"))?;
    let route_len: u16 = mesh_address
        .network_route_ek
        .len()
        .try_into()
        .map_err(|_| anyhow!("mesh route key too large for compact contact"))?;

    let mut out = Vec::with_capacity(
        64 + mesh_address.network_scan_ek.len() + mesh_address.network_route_ek.len(),
    );
    out.extend_from_slice(MESH_CONTACT_BINARY_MAGIC);
    out.push(kind);
    match socket.ip() {
        IpAddr::V4(ip) => {
            out.push(MESH_CONTACT_ADDR_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(MESH_CONTACT_ADDR_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&socket.port().to_be_bytes());
    out.extend_from_slice(mesh_address.node_id.as_bytes());
    out.extend_from_slice(&mesh_address.epoch.to_be_bytes());
    out.extend_from_slice(&scan_len.to_be_bytes());
    out.extend_from_slice(&route_len.to_be_bytes());
    out.extend_from_slice(&mesh_address.network_scan_ek);
    out.extend_from_slice(&mesh_address.network_route_ek);
    Ok(out)
}

/// Decode a compact binary contact, accepting legacy JSON contact bytes as fallback.
pub fn decode_mesh_contact(bytes: &[u8]) -> Result<MeshCarrierContact> {
    let contact = if bytes.starts_with(MESH_CONTACT_BINARY_MAGIC) {
        decode_binary_mesh_contact(bytes)?
    } else {
        serde_json::from_slice(bytes).context("deserialize legacy JSON mesh contact")?
    };
    validate_mesh_contact(&contact)?;
    Ok(contact)
}

/// Encode a contact as hex of the compact binary contact format.
pub fn encode_mesh_contact_string(contact: &MeshCarrierContact) -> Result<String> {
    Ok(hex_encode(&encode_mesh_contact(contact)?))
}

/// Decode a contact string. Compact hex is preferred; legacy JSON is accepted.
pub fn decode_mesh_contact_string(value: &str) -> Result<MeshCarrierContact> {
    let value = value.trim();
    let contact = if value.starts_with('{') {
        serde_json::from_str(value).context("parse legacy JSON mesh contact string")?
    } else {
        let bytes = hex_decode(value).context("decode compact mesh contact hex")?;
        decode_mesh_contact(&bytes)?
    };
    validate_mesh_contact(&contact)?;
    Ok(contact)
}

fn contact_socket_addr(contact: &MeshCarrierContact) -> Result<SocketAddr> {
    match contact {
        MeshCarrierContact::TcpSocket { addr, .. } | MeshCarrierContact::UdpSocket { addr, .. } => {
            addr.parse()
                .map_err(|error| anyhow!("invalid mesh contact socket address: {error}"))
        }
    }
}

fn is_public_routable_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || octets[0] == 0
        || octets[0] >= 224
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)))
}

fn is_public_routable_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn decode_binary_mesh_contact(bytes: &[u8]) -> Result<MeshCarrierContact> {
    let mut cursor = MESH_CONTACT_BINARY_MAGIC.len();
    let kind = read_u8(bytes, &mut cursor)?;
    let addr_kind = read_u8(bytes, &mut cursor)?;
    let ip = match addr_kind {
        MESH_CONTACT_ADDR_IPV4 => {
            let octets = read_array::<4>(bytes, &mut cursor)?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        MESH_CONTACT_ADDR_IPV6 => {
            let octets = read_array::<16>(bytes, &mut cursor)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        other => return Err(anyhow!("unknown compact mesh contact address kind {other}")),
    };
    let port = read_u16(bytes, &mut cursor)?;
    let node_id = MeshNodeId(read_array::<32>(bytes, &mut cursor)?);
    let epoch = read_u64(bytes, &mut cursor)?;
    let scan_len = read_u16(bytes, &mut cursor)? as usize;
    let route_len = read_u16(bytes, &mut cursor)? as usize;
    let network_scan_ek = read_vec(bytes, &mut cursor, scan_len)?;
    let network_route_ek = read_vec(bytes, &mut cursor, route_len)?;
    anyhow::ensure!(
        cursor == bytes.len(),
        "trailing bytes in compact mesh contact"
    );
    let mesh_address = MeshAddress {
        node_id,
        epoch,
        network_scan_ek,
        network_route_ek,
    };
    let addr = SocketAddr::new(ip, port).to_string();
    match kind {
        MESH_CONTACT_KIND_TCP => Ok(MeshCarrierContact::TcpSocket { addr, mesh_address }),
        MESH_CONTACT_KIND_UDP => Ok(MeshCarrierContact::UdpSocket { addr, mesh_address }),
        other => Err(anyhow!("unknown compact mesh contact carrier kind {other}")),
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    anyhow::ensure!(*cursor < bytes.len(), "truncated compact mesh contact");
    let value = bytes[*cursor];
    *cursor += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    Ok(u16::from_be_bytes(read_array::<2>(bytes, cursor)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    Ok(u64::from_be_bytes(read_array::<8>(bytes, cursor)?))
}

fn read_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    anyhow::ensure!(
        bytes.len().saturating_sub(*cursor) >= N,
        "truncated compact mesh contact"
    );
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>> {
    anyhow::ensure!(
        bytes.len().saturating_sub(*cursor) >= len,
        "truncated compact mesh contact"
    );
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        value.len().is_multiple_of(2),
        "compact mesh contact hex has odd length"
    );
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|error| anyhow!("invalid compact mesh contact hex at {index}: {error}"))
        })
        .collect()
}

impl fmt::Display for MeshCarrierContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeshCarrierContact::TcpSocket { addr, mesh_address } => {
                write!(f, "tcp:{}@{}", mesh_address.node_id, addr)
            }
            MeshCarrierContact::UdpSocket { addr, mesh_address } => {
                write!(f, "udp:{}@{}", mesh_address.node_id, addr)
            }
        }
    }
}

impl MeshPeer {
    pub fn node_id(&self) -> Option<MeshNodeId> {
        self.contact.node_id()
    }
}

impl fmt::Display for MeshPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.contact.fmt(f)
    }
}

/// Transport-agnostic carrier interface for Vess mesh traffic.
#[async_trait]
pub trait MeshCarrier: Clone + Send + Sync + 'static {
    fn local_contact(&self) -> MeshCarrierContact;

    async fn wait_online(&self);

    async fn send_with_response(
        &self,
        target: &MeshCarrierContact,
        payload: &[u8],
    ) -> Result<Vec<u8>>;

    async fn send(&self, target: &MeshCarrierContact, payload: &[u8]) -> Result<()> {
        self.send_with_response(target, payload).await?;
        Ok(())
    }
}

/// Fully Vess-owned PQ mesh carrier over plain TCP sockets.
#[derive(Clone)]
pub struct PqTcpMeshCarrier {
    listener: Arc<TcpListener>,
    local_addr: SocketAddr,
    local_secret: Arc<MeshSecretKey>,
    local_address: MeshAddress,
}

/// Fully Vess-owned PQ mesh carrier over UDP datagrams.
#[derive(Clone)]
pub struct PqUdpMeshCarrier {
    socket: Arc<UdpSocket>,
    request_socket: Arc<UdpSocket>,
    request_lock: Arc<Mutex<()>>,
    local_addr: SocketAddr,
    local_secret: Arc<MeshSecretKey>,
    local_address: MeshAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeshClientHello {
    initiator_address: MeshAddress,
    #[serde(default)]
    initiator_contact_addr: Option<String>,
    route_to_responder: MeshRouteHandshake,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeshServerHello {
    responder_address: MeshAddress,
    route_to_initiator: MeshRouteHandshake,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MeshUdpPacket {
    ClientHello(MeshClientHello),
    ServerHello(MeshServerHello),
    EncryptedRequest { ciphertext: Vec<u8> },
    EncryptedResponse { ciphertext: Vec<u8> },
    Keepalive { nonce: u64 },
    KeepaliveAck { nonce: u64 },
    PathProbe { probe_id: [u8; 16] },
    PathProbeAck { probe_id: [u8; 16] },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MeshRendezvousMessage {
    Register {
        mesh_address: MeshAddress,
    },
    RegisterAck {
        observed_addr: String,
    },
    PunchRequest {
        requester_address: MeshAddress,
        target_node_id: MeshNodeId,
    },
    PunchReady {
        target_addr: String,
        target_mesh_address: MeshAddress,
    },
    PunchNotify {
        requester_addr: String,
        requester_mesh_address: MeshAddress,
    },
    Error {
        message: String,
    },
}

#[derive(Clone)]
struct UdpSessionState {
    transport_key: [u8; 32],
    remote_mesh_address: MeshAddress,
    remote_contact_addr: SocketAddr,
}

#[derive(Clone)]
struct RendezvousRegistration {
    addr: SocketAddr,
    mesh_address: MeshAddress,
}

#[derive(Clone)]
struct RelayRegistration {
    addr: SocketAddr,
}

/// UDP rendezvous server for observed-address discovery and peer introduction.
#[derive(Clone)]
pub struct MeshRendezvousServer {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    registrations: Arc<Mutex<HashMap<MeshNodeId, RendezvousRegistration>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MeshRelayMessage {
    Register {
        mesh_address: MeshAddress,
    },
    RegisterAck {
        observed_addr: String,
    },
    Forward {
        destination_node_id: MeshNodeId,
        source_addr: String,
        source_mesh_address: MeshAddress,
        packet: MeshUdpPacket,
    },
    Deliver {
        source_addr: String,
        source_mesh_address: MeshAddress,
        packet: MeshUdpPacket,
    },
    Error {
        message: String,
    },
}

/// UDP relay server for fallback transport when direct paths fail.
#[derive(Clone)]
pub struct MeshRelayServer {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    registrations: Arc<Mutex<HashMap<MeshNodeId, RelayRegistration>>>,
}

impl PqTcpMeshCarrier {
    /// Bind a PQ mesh carrier on a plain TCP socket.
    pub async fn bind(
        bind_addr: SocketAddr,
        local_secret: MeshSecretKey,
        local_address: MeshAddress,
    ) -> Result<Self> {
        anyhow::ensure!(
            local_secret.node_id == local_address.node_id,
            "mesh secret/address node id mismatch"
        );
        anyhow::ensure!(
            local_secret.epoch == local_address.epoch,
            "mesh secret/address epoch mismatch"
        );

        let listener = TcpListener::bind(bind_addr)
            .await
            .context("bind PQ mesh tcp listener")?;
        let local_addr = listener.local_addr().context("read PQ mesh local addr")?;

        info!(addr = %local_addr, node_id = %local_address.node_id, "pq tcp mesh carrier online");

        Ok(Self {
            listener: Arc::new(listener),
            local_addr,
            local_secret: Arc::new(local_secret),
            local_address,
        })
    }

    /// Deterministically derive the mesh address from a seed and bind.
    pub async fn bind_from_seed(
        bind_addr: SocketAddr,
        seed: &[u8; 64],
        epoch: u64,
    ) -> Result<Self> {
        let (local_secret, local_address) = generate_mesh_keys_from_seed(seed, epoch);
        Self::bind(bind_addr, local_secret, local_address).await
    }

    pub fn mesh_address(&self) -> &MeshAddress {
        &self.local_address
    }

    pub async fn listen_with_response(
        &self,
        on_frame: impl Fn(MeshPeer, Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
    ) -> Result<()> {
        let handler = Arc::new(on_frame);

        loop {
            let (stream, peer_addr) = self
                .listener
                .accept()
                .await
                .context("accept PQ mesh tcp connection")?;
            let handler = handler.clone();
            let local_secret = self.local_secret.clone();
            let local_address = self.local_address.clone();

            tokio::spawn(async move {
                if let Err(error) =
                    handle_tcp_incoming(stream, peer_addr, local_secret, local_address, handler)
                        .await
                {
                    warn!(error = %error, "failed to handle incoming PQ mesh tcp session");
                }
            });
        }
    }
}

impl PqUdpMeshCarrier {
    async fn bind_request_socket(bind_addr: SocketAddr) -> Result<UdpSocket> {
        let request_bind_addr = match bind_addr {
            SocketAddr::V4(_) => SocketAddr::V4(std::net::SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                0,
            )),
            SocketAddr::V6(_) => SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                0,
            ),
        };
        UdpSocket::bind(request_bind_addr)
            .await
            .context("bind PQ mesh udp request socket")
    }

    /// Bind a PQ mesh carrier on a UDP socket.
    pub async fn bind(
        bind_addr: SocketAddr,
        local_secret: MeshSecretKey,
        local_address: MeshAddress,
    ) -> Result<Self> {
        anyhow::ensure!(
            local_secret.node_id == local_address.node_id,
            "mesh secret/address node id mismatch"
        );
        anyhow::ensure!(
            local_secret.epoch == local_address.epoch,
            "mesh secret/address epoch mismatch"
        );

        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("bind PQ mesh udp socket")?;
        let local_addr = socket.local_addr().context("read PQ mesh udp local addr")?;
        let request_socket = Self::bind_request_socket(bind_addr).await?;

        info!(addr = %local_addr, node_id = %local_address.node_id, "pq udp mesh carrier online");

        Ok(Self {
            socket: Arc::new(socket),
            request_socket: Arc::new(request_socket),
            request_lock: Arc::new(Mutex::new(())),
            local_addr,
            local_secret: Arc::new(local_secret),
            local_address,
        })
    }

    /// Deterministically derive the mesh address from a seed and bind.
    pub async fn bind_from_seed(
        bind_addr: SocketAddr,
        seed: &[u8; 64],
        epoch: u64,
    ) -> Result<Self> {
        let (local_secret, local_address) = generate_mesh_keys_from_seed(seed, epoch);
        Self::bind(bind_addr, local_secret, local_address).await
    }

    pub fn mesh_address(&self) -> &MeshAddress {
        &self.local_address
    }

    /// Periodically emit keepalives to preserve NAT bindings for a peer path.
    pub fn spawn_keepalive_task(
        &self,
        target: MeshCarrierContact,
        interval: Duration,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let (target_addr, _) = udp_contact_parts(&target)?;
        let socket = self.socket.clone();

        Ok(tokio::spawn(async move {
            let mut counter = 0u64;
            loop {
                let packet = MeshUdpPacket::Keepalive { nonce: counter };
                if send_udp_packet(&socket, target_addr, &packet)
                    .await
                    .is_err()
                {
                    break;
                }
                counter = counter.wrapping_add(1);
                tokio::time::sleep(interval).await;
            }
        }))
    }

    /// Probe a single UDP path and return its measured round-trip time.
    pub async fn probe_path(
        &self,
        target: &MeshCarrierContact,
        timeout: Duration,
    ) -> Result<Duration> {
        let (target_addr, _) = udp_contact_parts(target)?;
        let probe_id = random_id16();
        let started = Instant::now();
        let _request_guard = self.request_lock.lock().await;

        send_udp_packet(
            &self.request_socket,
            target_addr,
            &MeshUdpPacket::PathProbe { probe_id },
        )
        .await?;

        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];
        let recv = tokio::time::timeout(timeout, self.request_socket.recv_from(&mut buffer))
            .await
            .map_err(|_| anyhow!("PQ mesh path probe timed out"))?
            .context("receive PQ mesh path probe ack")?;
        let (len, from) = recv;
        anyhow::ensure!(
            from == target_addr,
            "PQ mesh path probe ack from unexpected peer"
        );

        match parse_udp_packet(&buffer[..len])? {
            MeshUdpPacket::PathProbeAck { probe_id: ack_id } if ack_id == probe_id => {
                Ok(started.elapsed())
            }
            _ => Err(anyhow!("unexpected PQ mesh path probe response")),
        }
    }

    /// Probe several candidate UDP paths and pick the fastest working one.
    pub async fn select_best_path(
        &self,
        candidates: &[MeshCarrierContact],
        timeout: Duration,
    ) -> Result<MeshCarrierContact> {
        let mut best: Option<(Duration, MeshCarrierContact)> = None;

        for candidate in candidates {
            if let Ok(rtt) = self.probe_path(candidate, timeout).await {
                match &best {
                    Some((best_rtt, _)) if *best_rtt <= rtt => {}
                    _ => best = Some((rtt, candidate.clone())),
                }
            }
        }

        best.map(|(_, contact)| contact)
            .ok_or_else(|| anyhow!("no viable PQ mesh path candidates responded"))
    }

    /// Register this carrier with a rendezvous server and learn the observed address.
    pub async fn register_with_rendezvous(
        &self,
        rendezvous_addr: SocketAddr,
    ) -> Result<SocketAddr> {
        let message = MeshRendezvousMessage::Register {
            mesh_address: self.local_address.clone(),
        };
        send_rendezvous_message(&self.socket, rendezvous_addr, &message).await?;

        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];
        let (len, from) = self
            .socket
            .recv_from(&mut buffer)
            .await
            .context("receive rendezvous register ack")?;
        anyhow::ensure!(
            from == rendezvous_addr,
            "rendezvous register ack from unexpected peer"
        );
        match parse_rendezvous_message(&buffer[..len])? {
            MeshRendezvousMessage::RegisterAck { observed_addr } => observed_addr
                .parse()
                .map_err(|error| anyhow!("invalid observed rendezvous address: {error}")),
            MeshRendezvousMessage::Error { message } => {
                Err(anyhow!("rendezvous register failed: {message}"))
            }
            _ => Err(anyhow!("unexpected rendezvous register response")),
        }
    }

    /// Ask the rendezvous server for the current contact information of a target node.
    pub async fn request_peer_via_rendezvous(
        &self,
        rendezvous_addr: SocketAddr,
        target_node_id: MeshNodeId,
    ) -> Result<MeshCarrierContact> {
        let message = MeshRendezvousMessage::PunchRequest {
            requester_address: self.local_address.clone(),
            target_node_id,
        };
        send_rendezvous_message(&self.socket, rendezvous_addr, &message).await?;

        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];
        let (len, from) = self
            .socket
            .recv_from(&mut buffer)
            .await
            .context("receive rendezvous punch response")?;
        anyhow::ensure!(
            from == rendezvous_addr,
            "rendezvous punch response from unexpected peer"
        );
        match parse_rendezvous_message(&buffer[..len])? {
            MeshRendezvousMessage::PunchReady {
                target_addr,
                target_mesh_address,
            } => Ok(MeshCarrierContact::UdpSocket {
                addr: target_addr,
                mesh_address: target_mesh_address,
            }),
            MeshRendezvousMessage::Error { message } => {
                Err(anyhow!("rendezvous punch failed: {message}"))
            }
            _ => Err(anyhow!("unexpected rendezvous punch response")),
        }
    }

    /// Resolve a target through rendezvous, then connect using the normal PQ UDP mesh path.
    pub async fn send_with_response_via_rendezvous(
        &self,
        rendezvous_addr: SocketAddr,
        target_node_id: MeshNodeId,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let contact = self
            .request_peer_via_rendezvous(rendezvous_addr, target_node_id)
            .await?;
        self.send_with_response(&contact, payload).await
    }

    /// Register this carrier with a relay server for fallback delivery.
    pub async fn register_with_relay(&self, relay_addr: SocketAddr) -> Result<SocketAddr> {
        let message = MeshRelayMessage::Register {
            mesh_address: self.local_address.clone(),
        };
        send_relay_message(&self.socket, relay_addr, &message).await?;

        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];
        let (len, from) = self
            .socket
            .recv_from(&mut buffer)
            .await
            .context("receive relay register ack")?;
        anyhow::ensure!(
            from == relay_addr,
            "relay register ack from unexpected peer"
        );
        match parse_relay_message(&buffer[..len])? {
            MeshRelayMessage::RegisterAck { observed_addr } => observed_addr
                .parse()
                .map_err(|error| anyhow!("invalid observed relay address: {error}")),
            MeshRelayMessage::Error { message } => Err(anyhow!("relay register failed: {message}")),
            _ => Err(anyhow!("unexpected relay register response")),
        }
    }

    /// Deliver through a relay server when direct delivery is unavailable.
    pub async fn send_with_response_via_relay(
        &self,
        relay_addr: SocketAddr,
        target: &MeshCarrierContact,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let (_, target_mesh_address) = udp_contact_parts(target)?;

        let initiator_ctx = generate_route_handshake(&target_mesh_address)?;
        send_relay_message(
            &self.socket,
            relay_addr,
            &MeshRelayMessage::Forward {
                destination_node_id: target_mesh_address.node_id,
                source_addr: self.local_addr.to_string(),
                source_mesh_address: self.local_address.clone(),
                packet: MeshUdpPacket::ClientHello(MeshClientHello {
                    initiator_address: self.local_address.clone(),
                    initiator_contact_addr: Some(self.local_addr.to_string()),
                    route_to_responder: initiator_ctx.handshake,
                }),
            },
        )
        .await?;

        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];
        let (hello_len, hello_from) = self
            .socket
            .recv_from(&mut buffer)
            .await
            .context("receive relay delivered server hello")?;
        anyhow::ensure!(
            hello_from == relay_addr,
            "relay delivery from unexpected peer"
        );
        let hello_delivery = parse_relay_message(&buffer[..hello_len])?;
        let MeshRelayMessage::Deliver {
            source_mesh_address,
            packet: MeshUdpPacket::ServerHello(server_hello),
            ..
        } = hello_delivery
        else {
            return Err(anyhow!("expected relay-delivered PQ mesh server hello"));
        };
        anyhow::ensure!(
            server_hello.responder_address == target_mesh_address
                && source_mesh_address == target_mesh_address,
            "relay delivered responder address mismatch"
        );

        let opened_return =
            open_route_handshake(self.local_secret.as_ref(), &server_hello.route_to_initiator)?;
        let transport_key = derive_transport_key(
            &self.local_address.node_id,
            &server_hello.responder_address.node_id,
            &initiator_ctx.session_key,
            &opened_return.session_key,
        );

        send_relay_message(
            &self.socket,
            relay_addr,
            &MeshRelayMessage::Forward {
                destination_node_id: target_mesh_address.node_id,
                source_addr: self.local_addr.to_string(),
                source_mesh_address: self.local_address.clone(),
                packet: MeshUdpPacket::EncryptedRequest {
                    ciphertext: encrypt_transport_payload(&transport_key, b"request", payload)?,
                },
            },
        )
        .await?;

        let (response_len, response_from) = self
            .socket
            .recv_from(&mut buffer)
            .await
            .context("receive relay delivered encrypted response")?;
        anyhow::ensure!(
            response_from == relay_addr,
            "relay response from unexpected peer"
        );
        let response_delivery = parse_relay_message(&buffer[..response_len])?;
        let MeshRelayMessage::Deliver {
            packet: MeshUdpPacket::EncryptedResponse { ciphertext },
            ..
        } = response_delivery
        else {
            return Err(anyhow!("expected relay-delivered PQ mesh response"));
        };
        decrypt_transport_payload(&transport_key, b"response", &ciphertext)
    }

    pub async fn listen_with_response(
        &self,
        on_frame: impl Fn(MeshPeer, Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
    ) -> Result<()> {
        let handler: Arc<dyn Fn(MeshPeer, Vec<u8>) -> Vec<u8> + Send + Sync> = Arc::new(on_frame);
        let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSessionState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];

        loop {
            let (len, peer_addr) = match self.socket.recv_from(&mut buffer).await {
                Ok(received) => received,
                Err(error) => {
                    warn!(%error, "failed to receive PQ mesh udp packet; continuing listener");
                    continue;
                }
            };
            if let Ok(packet) = parse_udp_packet(&buffer[..len]) {
                let processed = process_udp_packet(
                    &self.socket,
                    &handler,
                    &sessions,
                    self.local_secret.as_ref(),
                    &self.local_address,
                    peer_addr,
                    packet,
                    None,
                )
                .await;
                match processed {
                    Ok(Some((destination, relay_message))) => {
                        if let Err(error) =
                            send_relay_message(&self.socket, destination, &relay_message).await
                        {
                            warn!(%error, "failed to send PQ mesh relay response");
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!(%peer_addr, %error, "failed to process PQ mesh udp packet");
                    }
                }
                continue;
            }

            if let Ok(relay_message) = parse_relay_message(&buffer[..len]) {
                if let MeshRelayMessage::Deliver {
                    source_addr,
                    source_mesh_address,
                    packet,
                } = relay_message
                {
                    let Ok(source_addr) = source_addr.parse::<SocketAddr>() else {
                        warn!(source_addr, "invalid PQ mesh relay source addr");
                        continue;
                    };
                    let processed = process_udp_packet(
                        &self.socket,
                        &handler,
                        &sessions,
                        self.local_secret.as_ref(),
                        &self.local_address,
                        source_addr,
                        packet,
                        Some(source_mesh_address),
                    )
                    .await;
                    match processed {
                        Ok(Some((_destination, relay_message))) => {
                            if let Err(error) =
                                send_relay_message(&self.socket, peer_addr, &relay_message).await
                            {
                                warn!(%error, "failed to send PQ mesh relayed response");
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            warn!(%peer_addr, %error, "failed to process relayed PQ mesh packet");
                        }
                    }
                }
                continue;
            }

            if parse_rendezvous_message(&buffer[..len]).is_ok() {
                continue;
            }
        }
    }
}

impl MeshRendezvousServer {
    /// Bind a rendezvous server on UDP.
    pub async fn bind(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("bind mesh rendezvous udp socket")?;
        let local_addr = socket
            .local_addr()
            .context("read mesh rendezvous local addr")?;

        info!(addr = %local_addr, "mesh rendezvous server online");

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            registrations: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run(&self) -> Result<()> {
        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];

        loop {
            let (len, peer_addr) = self
                .socket
                .recv_from(&mut buffer)
                .await
                .context("receive mesh rendezvous packet")?;
            let message = parse_rendezvous_message(&buffer[..len])?;

            match message {
                MeshRendezvousMessage::Register { mesh_address } => {
                    self.registrations.lock().await.insert(
                        mesh_address.node_id,
                        RendezvousRegistration {
                            addr: peer_addr,
                            mesh_address,
                        },
                    );

                    send_rendezvous_message(
                        &self.socket,
                        peer_addr,
                        &MeshRendezvousMessage::RegisterAck {
                            observed_addr: peer_addr.to_string(),
                        },
                    )
                    .await?;
                }
                MeshRendezvousMessage::PunchRequest {
                    requester_address,
                    target_node_id,
                } => {
                    let target = self
                        .registrations
                        .lock()
                        .await
                        .get(&target_node_id)
                        .cloned();
                    let Some(target) = target else {
                        send_rendezvous_message(
                            &self.socket,
                            peer_addr,
                            &MeshRendezvousMessage::Error {
                                message: format!("target node {} not registered", target_node_id),
                            },
                        )
                        .await?;
                        continue;
                    };

                    send_rendezvous_message(
                        &self.socket,
                        peer_addr,
                        &MeshRendezvousMessage::PunchReady {
                            target_addr: target.addr.to_string(),
                            target_mesh_address: target.mesh_address.clone(),
                        },
                    )
                    .await?;

                    send_rendezvous_message(
                        &self.socket,
                        target.addr,
                        &MeshRendezvousMessage::PunchNotify {
                            requester_addr: peer_addr.to_string(),
                            requester_mesh_address: requester_address,
                        },
                    )
                    .await?;
                }
                MeshRendezvousMessage::RegisterAck { .. }
                | MeshRendezvousMessage::PunchReady { .. }
                | MeshRendezvousMessage::PunchNotify { .. }
                | MeshRendezvousMessage::Error { .. } => {}
            }
        }
    }
}

impl MeshRelayServer {
    /// Bind a relay server on UDP.
    pub async fn bind(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context("bind mesh relay udp socket")?;
        let local_addr = socket.local_addr().context("read mesh relay local addr")?;

        info!(addr = %local_addr, "mesh relay server online");

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            registrations: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run(&self) -> Result<()> {
        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];

        loop {
            let (len, peer_addr) = self
                .socket
                .recv_from(&mut buffer)
                .await
                .context("receive mesh relay packet")?;
            let message = parse_relay_message(&buffer[..len])?;

            match message {
                MeshRelayMessage::Register { mesh_address } => {
                    self.registrations
                        .lock()
                        .await
                        .insert(mesh_address.node_id, RelayRegistration { addr: peer_addr });

                    send_relay_message(
                        &self.socket,
                        peer_addr,
                        &MeshRelayMessage::RegisterAck {
                            observed_addr: peer_addr.to_string(),
                        },
                    )
                    .await?;
                }
                MeshRelayMessage::Forward {
                    destination_node_id,
                    source_addr,
                    source_mesh_address,
                    packet,
                } => {
                    let destination = self
                        .registrations
                        .lock()
                        .await
                        .get(&destination_node_id)
                        .cloned();
                    let Some(destination) = destination else {
                        send_relay_message(
                            &self.socket,
                            peer_addr,
                            &MeshRelayMessage::Error {
                                message: format!(
                                    "relay target node {} not registered",
                                    destination_node_id
                                ),
                            },
                        )
                        .await?;
                        continue;
                    };

                    send_relay_message(
                        &self.socket,
                        destination.addr,
                        &MeshRelayMessage::Deliver {
                            source_addr,
                            source_mesh_address,
                            packet,
                        },
                    )
                    .await?;
                }
                MeshRelayMessage::RegisterAck { .. }
                | MeshRelayMessage::Deliver { .. }
                | MeshRelayMessage::Error { .. } => {}
            }
        }
    }
}

#[async_trait]
impl MeshCarrier for PqTcpMeshCarrier {
    fn local_contact(&self) -> MeshCarrierContact {
        MeshCarrierContact::TcpSocket {
            addr: self.local_addr.to_string(),
            mesh_address: self.local_address.clone(),
        }
    }

    async fn wait_online(&self) {}

    async fn send_with_response(
        &self,
        target: &MeshCarrierContact,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let (target_addr, target_mesh_address) = tcp_contact_parts(target)?;
        let mut stream = TcpStream::connect(target_addr)
            .await
            .context("connect to PQ mesh peer")?;

        let initiator_ctx = generate_route_handshake(&target_mesh_address)?;
        let hello = MeshClientHello {
            initiator_address: self.local_address.clone(),
            initiator_contact_addr: Some(self.local_addr.to_string()),
            route_to_responder: initiator_ctx.handshake,
        };
        write_json_blob(&mut stream, &hello)
            .await
            .context("write PQ mesh client hello")?;

        let server_hello: MeshServerHello = read_json_blob(&mut stream)
            .await
            .context("read PQ mesh server hello")?;
        anyhow::ensure!(
            server_hello.responder_address == target_mesh_address,
            "PQ mesh responder address mismatch"
        );

        let opened_return =
            open_route_handshake(self.local_secret.as_ref(), &server_hello.route_to_initiator)?;
        let transport_key = derive_transport_key(
            &self.local_address.node_id,
            &server_hello.responder_address.node_id,
            &initiator_ctx.session_key,
            &opened_return.session_key,
        );

        let encrypted_request = encrypt_transport_payload(&transport_key, b"request", payload)?;
        write_blob(&mut stream, &encrypted_request)
            .await
            .context("write PQ mesh encrypted request")?;

        let encrypted_response = read_blob(&mut stream)
            .await
            .context("read PQ mesh encrypted response")?;
        decrypt_transport_payload(&transport_key, b"response", &encrypted_response)
    }
}

#[async_trait]
impl MeshCarrier for PqUdpMeshCarrier {
    fn local_contact(&self) -> MeshCarrierContact {
        MeshCarrierContact::UdpSocket {
            addr: self.local_addr.to_string(),
            mesh_address: self.local_address.clone(),
        }
    }

    async fn wait_online(&self) {}

    async fn send_with_response(
        &self,
        target: &MeshCarrierContact,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let (target_addr, target_mesh_address) = udp_contact_parts(target)?;
        let _request_guard = self.request_lock.lock().await;

        let initiator_ctx = generate_route_handshake(&target_mesh_address)?;
        let hello = MeshUdpPacket::ClientHello(MeshClientHello {
            initiator_address: self.local_address.clone(),
            initiator_contact_addr: Some(self.local_addr.to_string()),
            route_to_responder: initiator_ctx.handshake,
        });
        send_udp_packet(&self.request_socket, target_addr, &hello).await?;

        // Loop to receive the ServerHello, discarding stray/non-matching
        // packets that may arrive on the shared request socket (e.g. late
        // responses from previous requests or probe packets from other nodes).
        let mut buffer = vec![0u8; MAX_MESH_UDP_PACKET_SIZE];
        let (_hello_len, hello_from, server_hello) = loop {
            let (len, from) = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.request_socket.recv_from(&mut buffer),
            )
            .await
            .context("receive PQ mesh udp server hello (timeout)")?
            .context("receive PQ mesh udp server hello")?;

            let Ok(packet) = parse_udp_packet(&buffer[..len]) else {
                tracing::debug!(from = %from, "discarding unparseable UDP packet on request socket");
                continue;
            };
            let MeshUdpPacket::ServerHello(sh) = packet else {
                tracing::debug!(from = %from, ?packet, "discarding non-ServerHello packet on request socket");
                continue;
            };
            // Accept the server hello from any address — the target may have
            // restarted with a new port.  Identity is verified cryptographically
            // via the responder_address match and route handshake below.
            if sh.responder_address != target_mesh_address {
                tracing::debug!(from = %from, "discarding ServerHello from wrong responder");
                continue;
            }
            break (len, from, sh);
        };

        if hello_from != target_addr {
            tracing::debug!(
                expected = %target_addr,
                got = %hello_from,
                "mesh server hello from different port — accepting (node may have restarted)"
            );
        }

        // Verify identity cryptographically via the route handshake.
        let opened_return =
            open_route_handshake(self.local_secret.as_ref(), &server_hello.route_to_initiator)?;
        let transport_key = derive_transport_key(
            &self.local_address.node_id,
            &server_hello.responder_address.node_id,
            &initiator_ctx.session_key,
            &opened_return.session_key,
        );

        // Use the actual responding address for subsequent communications
        // (the node may have restarted with a different port).
        let actual_addr = hello_from;

        let encrypted_request = encrypt_transport_payload(&transport_key, b"request", payload)?;
        send_udp_packet(
            &self.request_socket,
            actual_addr,
            &MeshUdpPacket::EncryptedRequest {
                ciphertext: encrypted_request,
            },
        )
        .await?;

        let (response_len, response_from) = loop {
            let (len, from) = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.request_socket.recv_from(&mut buffer),
            )
            .await
            .context("receive PQ mesh udp encrypted response (timeout)")?
            .context("receive PQ mesh udp encrypted response")?;

            let Ok(packet) = parse_udp_packet(&buffer[..len]) else {
                tracing::debug!(from = %from, "discarding unparseable UDP packet on request socket (response)");
                continue;
            };
            // Accept EncryptedResponse from any address — the node may have
            // shifted ports further during the session.
            if matches!(packet, MeshUdpPacket::EncryptedResponse { .. }) {
                break (len, from);
            }
            tracing::debug!(from = %from, ?packet, "discarding non-EncryptedResponse packet on request socket");
        };
        if response_from != actual_addr {
            tracing::debug!(
                expected = %actual_addr,
                got = %response_from,
                "mesh encrypted response from different address — accepting via crypto"
            );
        }
        let response_packet = parse_udp_packet(&buffer[..response_len])?;
        let MeshUdpPacket::EncryptedResponse { ciphertext } = response_packet else {
            return Err(anyhow!("expected PQ mesh udp encrypted response"));
        };
        decrypt_transport_payload(&transport_key, b"response", &ciphertext)
    }
}

/// Generate a fresh mesh address using OS randomness.
pub fn generate_mesh_keys(epoch: u64) -> (MeshSecretKey, MeshAddress) {
    let mut rng = rand::thread_rng();
    let (scan_dk, scan_ek) = MlKem768::generate(&mut rng);
    let (route_dk, route_ek) = MlKem768::generate(&mut rng);
    mesh_keys_from_parts(epoch, &scan_dk, &scan_ek, &route_dk, &route_ek)
}

/// Generate a deterministic mesh address from the wallet root seed.
pub fn generate_mesh_keys_from_seed(seed: &[u8; 64], epoch: u64) -> (MeshSecretKey, MeshAddress) {
    let scan_rng_seed = derive_seed(seed, b"vess-mesh-scan-v0", epoch);
    let route_rng_seed = derive_seed(seed, b"vess-mesh-route-v0", epoch);

    let mut scan_rng = ChaCha20Rng::from_seed(scan_rng_seed);
    let mut route_rng = ChaCha20Rng::from_seed(route_rng_seed);

    let (scan_dk, scan_ek) = MlKem768::generate(&mut scan_rng);
    let (route_dk, route_ek) = MlKem768::generate(&mut route_rng);
    mesh_keys_from_parts(epoch, &scan_dk, &scan_ek, &route_dk, &route_ek)
}

/// Build a one-time DKSAP route capsule for the target mesh address.
pub fn generate_route_handshake(address: &MeshAddress) -> Result<MeshRouteContext> {
    let scan_ek = vec_to_ek(&address.network_scan_ek)?;
    let route_ek = vec_to_ek(&address.network_route_ek)?;

    let mut rng = rand::thread_rng();
    let (ct_scan, ss_scan) = scan_ek
        .encapsulate(&mut rng)
        .map_err(|_| anyhow!("mesh scan encapsulation failed"))?;
    let (ct_route, ss_route) = route_ek
        .encapsulate(&mut rng)
        .map_err(|_| anyhow!("mesh route encapsulation failed"))?;

    let ss_scan_bytes: &[u8] = ss_scan.as_ref();
    let ss_route_bytes: &[u8] = ss_route.as_ref();

    let view_tag = {
        let mut hasher = Hasher::new();
        hasher.update(b"vess-mesh-view-v1");
        hasher.update(ss_scan_bytes);
        hasher.finalize().as_bytes()[0]
    };

    let route_id = derive_route_id(address.epoch, ss_scan_bytes, ss_route_bytes);
    let session_key = derive_session_key(address.epoch, ss_scan_bytes, ss_route_bytes);

    Ok(MeshRouteContext {
        handshake: MeshRouteHandshake {
            node_id: address.node_id,
            epoch: address.epoch,
            ct_scan: ct_scan.to_vec(),
            ct_route: ct_route.to_vec(),
            view_tag,
            route_id,
        },
        session_key,
    })
}

/// Open a route handshake with the recipient's mesh secret keys.
pub fn open_route_handshake(
    secret: &MeshSecretKey,
    handshake: &MeshRouteHandshake,
) -> Result<OpenedMeshRoute> {
    if secret.epoch != handshake.epoch {
        return Err(anyhow!(
            "mesh route epoch mismatch: expected {}, got {}",
            secret.epoch,
            handshake.epoch
        ));
    }

    if secret.node_id != handshake.node_id {
        return Err(anyhow!("mesh route node id mismatch"));
    }

    let scan_dk = vec_to_dk(&secret.network_scan_dk)?;
    let route_dk = vec_to_dk(&secret.network_route_dk)?;
    let ss_scan = scan_dk
        .decapsulate(&vec_to_ct(&handshake.ct_scan)?)
        .map_err(|_| anyhow!("mesh scan decapsulation failed"))?;
    let ss_route = route_dk
        .decapsulate(&vec_to_ct(&handshake.ct_route)?)
        .map_err(|_| anyhow!("mesh route decapsulation failed"))?;

    let ss_scan_bytes: &[u8] = ss_scan.as_ref();
    let ss_route_bytes: &[u8] = ss_route.as_ref();

    let expected_view_tag = {
        let mut hasher = Hasher::new();
        hasher.update(b"vess-mesh-view-v1");
        hasher.update(ss_scan_bytes);
        hasher.finalize().as_bytes()[0]
    };
    let expected_route_id = derive_route_id(secret.epoch, ss_scan_bytes, ss_route_bytes);

    if handshake.view_tag != expected_view_tag {
        return Err(anyhow!("mesh route view tag mismatch"));
    }
    if handshake.route_id != expected_route_id {
        return Err(anyhow!("mesh route id mismatch"));
    }

    Ok(OpenedMeshRoute {
        node_id: secret.node_id,
        epoch: secret.epoch,
        view_tag: expected_view_tag,
        route_id: expected_route_id,
        session_key: derive_session_key(secret.epoch, ss_scan_bytes, ss_route_bytes),
    })
}

fn derive_seed(seed: &[u8; 64], domain: &[u8], epoch: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(seed);
    hasher.update(domain);
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn mesh_keys_from_parts(
    epoch: u64,
    scan_dk: &DecapKey,
    scan_ek: &EncapKey,
    route_dk: &DecapKey,
    route_ek: &EncapKey,
) -> (MeshSecretKey, MeshAddress) {
    let scan_ek_bytes = scan_ek.as_bytes().to_vec();
    let route_ek_bytes = route_ek.as_bytes().to_vec();
    let node_id = derive_node_id(epoch, &scan_ek_bytes, &route_ek_bytes);

    (
        MeshSecretKey {
            node_id,
            epoch,
            network_scan_dk: scan_dk.as_bytes().to_vec(),
            network_route_dk: route_dk.as_bytes().to_vec(),
        },
        MeshAddress {
            node_id,
            epoch,
            network_scan_ek: scan_ek_bytes,
            network_route_ek: route_ek_bytes,
        },
    )
}

fn derive_node_id(epoch: u64, scan_ek: &[u8], route_ek: &[u8]) -> MeshNodeId {
    let mut hasher = Hasher::new();
    hasher.update(b"vess-mesh-nodeid-v1");
    hasher.update(&epoch.to_le_bytes());
    hasher.update(scan_ek);
    hasher.update(route_ek);
    MeshNodeId(*hasher.finalize().as_bytes())
}

fn derive_route_id(epoch: u64, ss_scan: &[u8], ss_route: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"vess-mesh-route-v1");
    hasher.update(&epoch.to_le_bytes());
    hasher.update(ss_scan);
    hasher.update(ss_route);
    *hasher.finalize().as_bytes()
}

fn derive_session_key(epoch: u64, ss_scan: &[u8], ss_route: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"vess-mesh-session-v1");
    hasher.update(&epoch.to_le_bytes());
    hasher.update(ss_scan);
    hasher.update(ss_route);
    *hasher.finalize().as_bytes()
}

fn derive_transport_key(
    initiator_node_id: &MeshNodeId,
    responder_node_id: &MeshNodeId,
    initiator_to_responder_key: &[u8; 32],
    responder_to_initiator_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"vess-mesh-transport-v1");
    hasher.update(initiator_node_id.as_bytes());
    hasher.update(responder_node_id.as_bytes());
    hasher.update(initiator_to_responder_key);
    hasher.update(responder_to_initiator_key);
    *hasher.finalize().as_bytes()
}

fn derive_directional_material(transport_key: &[u8; 32], direction: &[u8]) -> ([u8; 32], [u8; 12]) {
    let mut key_hasher = Hasher::new();
    key_hasher.update(b"vess-mesh-aead-key-v1");
    key_hasher.update(transport_key);
    key_hasher.update(direction);
    let key = *key_hasher.finalize().as_bytes();

    let mut nonce_hasher = Hasher::new();
    nonce_hasher.update(b"vess-mesh-aead-nonce-v1");
    nonce_hasher.update(transport_key);
    nonce_hasher.update(direction);
    let nonce_hash = nonce_hasher.finalize();

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_hash.as_bytes()[..12]);
    (key, nonce)
}

fn encrypt_transport_payload(
    transport_key: &[u8; 32],
    direction: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let (key, nonce_bytes) = derive_directional_material(transport_key, direction);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|error| anyhow!("PQ mesh transport encrypt: {error}"))
}

fn decrypt_transport_payload(
    transport_key: &[u8; 32],
    direction: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let (key, nonce_bytes) = derive_directional_material(transport_key, direction);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|error| anyhow!("PQ mesh transport decrypt: {error}"))
}

fn tcp_contact_parts(contact: &MeshCarrierContact) -> Result<(SocketAddr, MeshAddress)> {
    validate_mesh_contact(contact)?;
    match contact {
        MeshCarrierContact::TcpSocket { addr, mesh_address } => Ok((
            addr.parse()
                .map_err(|error| anyhow!("invalid tcp mesh contact addr: {error}"))?,
            mesh_address.clone(),
        )),
        MeshCarrierContact::UdpSocket { .. } => Err(anyhow!("expected tcp mesh carrier contact")),
    }
}

fn udp_contact_parts(contact: &MeshCarrierContact) -> Result<(SocketAddr, MeshAddress)> {
    validate_mesh_contact(contact)?;
    match contact {
        MeshCarrierContact::UdpSocket { addr, mesh_address } => Ok((
            addr.parse()
                .map_err(|error| anyhow!("invalid udp mesh contact addr: {error}"))?,
            mesh_address.clone(),
        )),
        MeshCarrierContact::TcpSocket { .. } => Err(anyhow!("expected udp mesh carrier contact")),
    }
}

fn vec_to_ek(bytes: &[u8]) -> Result<EncapKey> {
    let encoded: Encoded<EncapKey> = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid mesh encapsulation key length"))?;
    Ok(EncapKey::from_bytes(&encoded))
}

fn vec_to_dk(bytes: &[u8]) -> Result<DecapKey> {
    let encoded: Encoded<DecapKey> = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid mesh decapsulation key length"))?;
    Ok(DecapKey::from_bytes(&encoded))
}

fn vec_to_ct(bytes: &[u8]) -> Result<ml_kem::Ciphertext<MlKem768>> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid mesh ciphertext length"))
}

async fn write_blob(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .context("write PQ mesh blob length")?;
    stream
        .write_all(payload)
        .await
        .context("write PQ mesh blob payload")?;
    Ok(())
}

async fn read_blob(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read PQ mesh blob length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(
        len <= MAX_MESH_FRAME_SIZE,
        "PQ mesh blob too large: {len} bytes"
    );

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read PQ mesh blob payload")?;
    Ok(payload)
}

async fn write_json_blob<T: Serialize>(stream: &mut TcpStream, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value).context("serialize PQ mesh json blob")?;
    write_blob(stream, &payload).await
}

async fn read_json_blob<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    let payload = read_blob(stream).await?;
    serde_json::from_slice(&payload).context("deserialize PQ mesh json blob")
}

async fn send_udp_packet(
    socket: &UdpSocket,
    addr: SocketAddr,
    packet: &MeshUdpPacket,
) -> Result<()> {
    let payload = serde_json::to_vec(packet).context("serialize PQ mesh udp packet")?;
    anyhow::ensure!(
        payload.len() <= MAX_MESH_UDP_PACKET_SIZE,
        "PQ mesh udp packet too large: {} bytes",
        payload.len()
    );
    socket
        .send_to(&payload, addr)
        .await
        .context("send PQ mesh udp packet")?;
    Ok(())
}

async fn send_rendezvous_message(
    socket: &UdpSocket,
    addr: SocketAddr,
    message: &MeshRendezvousMessage,
) -> Result<()> {
    let payload = serde_json::to_vec(message).context("serialize mesh rendezvous packet")?;
    anyhow::ensure!(
        payload.len() <= MAX_MESH_UDP_PACKET_SIZE,
        "mesh rendezvous packet too large: {} bytes",
        payload.len()
    );
    socket
        .send_to(&payload, addr)
        .await
        .context("send mesh rendezvous packet")?;
    Ok(())
}

fn parse_udp_packet(payload: &[u8]) -> Result<MeshUdpPacket> {
    serde_json::from_slice(payload).context("deserialize PQ mesh udp packet")
}

fn parse_rendezvous_message(payload: &[u8]) -> Result<MeshRendezvousMessage> {
    serde_json::from_slice(payload).context("deserialize mesh rendezvous packet")
}

async fn send_relay_message(
    socket: &UdpSocket,
    addr: SocketAddr,
    message: &MeshRelayMessage,
) -> Result<()> {
    let payload = serde_json::to_vec(message).context("serialize mesh relay packet")?;
    anyhow::ensure!(
        payload.len() <= MAX_MESH_UDP_PACKET_SIZE,
        "mesh relay packet too large: {} bytes",
        payload.len()
    );
    socket
        .send_to(&payload, addr)
        .await
        .context("send mesh relay packet")?;
    Ok(())
}

fn parse_relay_message(payload: &[u8]) -> Result<MeshRelayMessage> {
    serde_json::from_slice(payload).context("deserialize mesh relay packet")
}

fn usable_udp_contact_addr(advertised: Option<&str>, fallback: SocketAddr) -> SocketAddr {
    advertised
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .filter(|addr| !addr.ip().is_unspecified() && addr.port() != 0)
        .unwrap_or(fallback)
}

async fn process_udp_packet(
    socket: &UdpSocket,
    handler: &Arc<dyn Fn(MeshPeer, Vec<u8>) -> Vec<u8> + Send + Sync>,
    sessions: &Arc<Mutex<HashMap<SocketAddr, UdpSessionState>>>,
    local_secret: &MeshSecretKey,
    local_address: &MeshAddress,
    peer_addr: SocketAddr,
    packet: MeshUdpPacket,
    relayed_mesh_address: Option<MeshAddress>,
) -> Result<Option<(SocketAddr, MeshRelayMessage)>> {
    match packet {
        MeshUdpPacket::ClientHello(hello) => {
            let remote_contact_addr =
                usable_udp_contact_addr(hello.initiator_contact_addr.as_deref(), peer_addr);
            let opened_inbound = open_route_handshake(local_secret, &hello.route_to_responder)?;
            let outbound = generate_route_handshake(&hello.initiator_address)?;
            let transport_key = derive_transport_key(
                &hello.initiator_address.node_id,
                &local_address.node_id,
                &opened_inbound.session_key,
                &outbound.session_key,
            );
            sessions.lock().await.insert(
                peer_addr,
                UdpSessionState {
                    transport_key,
                    remote_mesh_address: hello.initiator_address.clone(),
                    remote_contact_addr,
                },
            );

            let response = MeshUdpPacket::ServerHello(MeshServerHello {
                responder_address: local_address.clone(),
                route_to_initiator: outbound.handshake,
            });

            if let Some(source_mesh_address) = relayed_mesh_address {
                return Ok(Some((
                    peer_addr,
                    MeshRelayMessage::Forward {
                        destination_node_id: source_mesh_address.node_id,
                        source_addr: local_address_placeholder_addr(local_address, socket)?
                            .to_string(),
                        source_mesh_address: local_address.clone(),
                        packet: response,
                    },
                )));
            }

            send_udp_packet(socket, peer_addr, &response).await?;
            Ok(None)
        }
        MeshUdpPacket::Keepalive { nonce } => {
            send_udp_packet(socket, peer_addr, &MeshUdpPacket::KeepaliveAck { nonce }).await?;
            Ok(None)
        }
        MeshUdpPacket::PathProbe { probe_id } => {
            send_udp_packet(socket, peer_addr, &MeshUdpPacket::PathProbeAck { probe_id }).await?;
            Ok(None)
        }
        MeshUdpPacket::EncryptedRequest { ciphertext } => {
            let session = sessions.lock().await.remove(&peer_addr);
            let Some(session) = session else {
                return Ok(None);
            };

            let request_payload =
                decrypt_transport_payload(&session.transport_key, b"request", &ciphertext)?;
            let effective_mesh_address = relayed_mesh_address
                .clone()
                .unwrap_or(session.remote_mesh_address);
            let peer = MeshPeer {
                contact: MeshCarrierContact::UdpSocket {
                    addr: session.remote_contact_addr.to_string(),
                    mesh_address: effective_mesh_address,
                },
            };
            let response_payload = handler(peer, request_payload);
            let response = MeshUdpPacket::EncryptedResponse {
                ciphertext: encrypt_transport_payload(
                    &session.transport_key,
                    b"response",
                    &response_payload,
                )?,
            };

            if let Some(source_mesh_address) = relayed_mesh_address {
                return Ok(Some((
                    peer_addr,
                    MeshRelayMessage::Forward {
                        destination_node_id: source_mesh_address.node_id,
                        source_addr: local_address_placeholder_addr(local_address, socket)?
                            .to_string(),
                        source_mesh_address: local_address.clone(),
                        packet: response,
                    },
                )));
            }

            send_udp_packet(socket, peer_addr, &response).await?;
            Ok(None)
        }
        MeshUdpPacket::ServerHello(_)
        | MeshUdpPacket::EncryptedResponse { .. }
        | MeshUdpPacket::KeepaliveAck { .. }
        | MeshUdpPacket::PathProbeAck { .. } => Ok(None),
    }
}

fn local_address_placeholder_addr(
    _local_address: &MeshAddress,
    socket: &UdpSocket,
) -> Result<SocketAddr> {
    socket.local_addr().context("read PQ mesh local UDP addr")
}

fn random_id16() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

pub fn fragment_payload(payload: &[u8], mtu_safe_payload: usize) -> Result<Vec<MeshFragment>> {
    anyhow::ensure!(
        mtu_safe_payload > 0,
        "mtu_safe_payload must be greater than zero"
    );

    let message_id = random_id16();
    let total = payload.len().div_ceil(mtu_safe_payload) as u16;

    if total == 0 {
        return Ok(vec![MeshFragment {
            message_id,
            index: 0,
            total: 1,
            payload: Vec::new(),
        }]);
    }

    let mut fragments = Vec::with_capacity(total as usize);
    for (index, chunk) in payload.chunks(mtu_safe_payload).enumerate() {
        fragments.push(MeshFragment {
            message_id,
            index: index as u16,
            total,
            payload: chunk.to_vec(),
        });
    }
    Ok(fragments)
}

#[derive(Default)]
pub struct MeshReassemblyBuffer {
    fragments: HashMap<[u8; 16], HashMap<u16, Vec<u8>>>,
    totals: HashMap<[u8; 16], u16>,
}

impl MeshReassemblyBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, fragment: MeshFragment) -> Option<Vec<u8>> {
        let message_id = fragment.message_id;
        let total = fragment.total;
        self.totals.entry(message_id).or_insert(total);

        let entry = self.fragments.entry(message_id).or_default();
        entry.insert(fragment.index, fragment.payload);

        if entry.len() != total as usize {
            return None;
        }

        let mut payload = Vec::new();
        for index in 0..total {
            let chunk = entry.remove(&index)?;
            payload.extend_from_slice(&chunk);
        }

        self.fragments.remove(&message_id);
        self.totals.remove(&message_id);
        Some(payload)
    }
}

async fn handle_tcp_incoming(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    local_secret: Arc<MeshSecretKey>,
    local_address: MeshAddress,
    on_frame: Arc<dyn Fn(MeshPeer, Vec<u8>) -> Vec<u8> + Send + Sync>,
) -> Result<()> {
    let hello: MeshClientHello = read_json_blob(&mut stream)
        .await
        .context("read PQ mesh client hello")?;
    let opened_inbound = open_route_handshake(local_secret.as_ref(), &hello.route_to_responder)?;
    let outbound = generate_route_handshake(&hello.initiator_address)?;
    let server_hello = MeshServerHello {
        responder_address: local_address.clone(),
        route_to_initiator: outbound.handshake,
    };
    write_json_blob(&mut stream, &server_hello)
        .await
        .context("write PQ mesh server hello")?;

    let transport_key = derive_transport_key(
        &hello.initiator_address.node_id,
        &local_address.node_id,
        &opened_inbound.session_key,
        &outbound.session_key,
    );

    let encrypted_request = read_blob(&mut stream)
        .await
        .context("read PQ mesh encrypted request")?;
    let request_payload =
        decrypt_transport_payload(&transport_key, b"request", &encrypted_request)?;

    let peer = MeshPeer {
        contact: MeshCarrierContact::TcpSocket {
            addr: peer_addr.to_string(),
            mesh_address: hello.initiator_address,
        },
    };
    let response_payload = on_frame(peer, request_payload);
    let encrypted_response =
        encrypt_transport_payload(&transport_key, b"response", &response_payload)?;
    write_blob(&mut stream, &encrypted_response)
        .await
        .context("write PQ mesh encrypted response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_mesh_contact, decode_mesh_contact_string, encode_mesh_contact,
        encode_mesh_contact_string, fragment_payload, generate_mesh_keys_from_seed,
        generate_route_handshake, is_public_routable_socket_addr, open_route_handshake,
        validate_public_mesh_contact, MeshCarrier, MeshCarrierContact, MeshReassemblyBuffer,
        MeshRelayServer, MeshRendezvousServer, MeshSessionFrame, MeshSessionFrameKind,
        PqTcpMeshCarrier, PqUdpMeshCarrier, DEFAULT_UDP_MTU_SAFE_PAYLOAD,
    };
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::Duration;

    #[test]
    fn route_handshake_round_trips() {
        let seed = [7u8; 64];
        let (secret, address) = generate_mesh_keys_from_seed(&seed, 42);
        let sender = generate_route_handshake(&address).expect("sender route context");
        let receiver =
            open_route_handshake(&secret, &sender.handshake).expect("receiver route open");

        assert_eq!(receiver.node_id, address.node_id);
        assert_eq!(receiver.epoch, address.epoch);
        assert_eq!(receiver.view_tag, sender.handshake.view_tag);
        assert_eq!(receiver.route_id, sender.handshake.route_id);
        assert_eq!(receiver.session_key, sender.session_key);
    }

    #[test]
    fn compact_contact_round_trips_and_legacy_json_still_decodes() {
        let (_, mesh_address) = generate_mesh_keys_from_seed(&[7u8; 64], 1);
        let contact = MeshCarrierContact::UdpSocket {
            addr: "93.184.216.34:9444".to_string(),
            mesh_address,
        };

        let compact = encode_mesh_contact(&contact).expect("encode compact contact");
        assert!(compact.len() < serde_json::to_vec(&contact).unwrap().len());
        assert_eq!(decode_mesh_contact(&compact).unwrap(), contact);

        let compact_string = encode_mesh_contact_string(&contact).unwrap();
        assert_eq!(
            decode_mesh_contact_string(&compact_string).unwrap(),
            contact
        );

        let legacy_json = serde_json::to_vec(&contact).unwrap();
        assert_eq!(decode_mesh_contact(&legacy_json).unwrap(), contact);
    }

    #[test]
    fn public_contact_policy_rejects_non_routable_addresses() {
        let (_, mesh_address) = generate_mesh_keys_from_seed(&[8u8; 64], 1);
        let localhost = MeshCarrierContact::UdpSocket {
            addr: "127.0.0.1:9444".to_string(),
            mesh_address: mesh_address.clone(),
        };
        let wildcard = MeshCarrierContact::UdpSocket {
            addr: "0.0.0.0:9444".to_string(),
            mesh_address: mesh_address.clone(),
        };
        let public = MeshCarrierContact::UdpSocket {
            addr: "93.184.216.34:9444".to_string(),
            mesh_address,
        };

        assert!(validate_public_mesh_contact(&localhost).is_err());
        assert!(validate_public_mesh_contact(&wildcard).is_err());
        assert!(validate_public_mesh_contact(&public).is_ok());
        assert!(is_public_routable_socket_addr(
            &"1.1.1.1:443".parse().unwrap()
        ));
        assert!(!is_public_routable_socket_addr(
            &"10.0.0.1:443".parse().unwrap()
        ));
    }

    #[test]
    fn usable_udp_contact_addr_falls_back_from_unspecified_address() {
        let fallback = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 44), 55000));

        assert_eq!(
            usable_udp_contact_addr(Some("0.0.0.0:19001"), fallback),
            fallback
        );
        assert_eq!(
            usable_udp_contact_addr(Some("192.168.1.9:19001"), fallback),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 9), 19001))
        );
        assert_eq!(usable_udp_contact_addr(None, fallback), fallback);
    }

    #[tokio::test]
    async fn pq_tcp_carrier_round_trips_over_mesh_handshake() {
        let seed_a = [1u8; 64];
        let seed_b = [2u8; 64];
        let bind_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let client = PqTcpMeshCarrier::bind_from_seed(bind_any, &seed_a, 7)
            .await
            .expect("bind client carrier");
        let server = PqTcpMeshCarrier::bind_from_seed(bind_any, &seed_b, 7)
            .await
            .expect("bind server carrier");

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.listen_with_response(|_peer, payload| payload).await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = client
            .send_with_response(&server.local_contact(), b"hello pq mesh")
            .await
            .expect("send over PQ mesh carrier");

        assert_eq!(response, b"hello pq mesh");

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn pq_udp_carrier_round_trips_over_mesh_handshake() {
        let seed_a = [3u8; 64];
        let seed_b = [4u8; 64];
        let bind_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let client = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_a, 9)
            .await
            .expect("bind udp client carrier");
        let server = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_b, 9)
            .await
            .expect("bind udp server carrier");

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.listen_with_response(|_peer, payload| payload).await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;

        let response = client
            .send_with_response(&server.local_contact(), b"hello pq udp mesh")
            .await
            .expect("send over PQ UDP mesh carrier");

        assert_eq!(response, b"hello pq udp mesh");

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn pq_udp_carrier_round_trips_while_sender_is_listening() {
        let seed_a = [11u8; 64];
        let seed_b = [12u8; 64];
        let bind_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let client = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_a, 17)
            .await
            .expect("bind udp client carrier");
        let server = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_b, 17)
            .await
            .expect("bind udp server carrier");

        let client_task = {
            let client = client.clone();
            tokio::spawn(async move {
                let _ = client.listen_with_response(|_peer, payload| payload).await;
            })
        };

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.listen_with_response(|_peer, payload| payload).await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;

        for _ in 0..8 {
            let response = tokio::time::timeout(
                Duration::from_secs(2),
                client.send_with_response(
                    &server.local_contact(),
                    b"hello pq udp full duplex",
                ),
            )
            .await
            .expect("client send should not be consumed by its listener")
            .expect("send over PQ UDP mesh carrier");

            assert_eq!(response, b"hello pq udp full duplex");
        }

        client_task.abort();
        server_task.abort();
        let _ = client_task.await;
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn pq_udp_carrier_resolves_peer_via_rendezvous() {
        let rendezvous =
            MeshRendezvousServer::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind rendezvous server");
        let rendezvous_addr = rendezvous.local_addr();
        let rendezvous_task = {
            let rendezvous = rendezvous.clone();
            tokio::spawn(async move {
                let _ = rendezvous.run().await;
            })
        };

        let seed_a = [5u8; 64];
        let seed_b = [6u8; 64];
        let bind_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let client = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_a, 11)
            .await
            .expect("bind udp client carrier");
        let server = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_b, 11)
            .await
            .expect("bind udp server carrier");

        let server_node_id = server.mesh_address().node_id;

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.listen_with_response(|_peer, payload| payload).await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = client
            .register_with_rendezvous(rendezvous_addr)
            .await
            .expect("register client with rendezvous");
        let _ = server
            .register_with_rendezvous(rendezvous_addr)
            .await
            .expect("register server with rendezvous");

        let response = client
            .send_with_response_via_rendezvous(
                rendezvous_addr,
                server_node_id,
                b"hello pq udp rendezvous",
            )
            .await
            .expect("send over PQ UDP rendezvous carrier");

        assert_eq!(response, b"hello pq udp rendezvous");

        server_task.abort();
        let _ = server_task.await;
        rendezvous_task.abort();
        let _ = rendezvous_task.await;
    }

    #[tokio::test]
    async fn pq_udp_probe_path_returns_rtt() {
        let seed_a = [7u8; 64];
        let seed_b = [8u8; 64];
        let bind_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let client = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_a, 13)
            .await
            .expect("bind udp client carrier");
        let server = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_b, 13)
            .await
            .expect("bind udp server carrier");

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.listen_with_response(|_peer, payload| payload).await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        let rtt = client
            .probe_path(&server.local_contact(), Duration::from_secs(1))
            .await
            .expect("probe udp path");
        assert!(rtt < Duration::from_secs(1));

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn pq_udp_carrier_resolves_peer_via_relay() {
        let relay =
            MeshRelayServer::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("bind relay server");
        let relay_addr = relay.local_addr();
        let relay_task = {
            let relay = relay.clone();
            tokio::spawn(async move {
                let _ = relay.run().await;
            })
        };

        let seed_a = [9u8; 64];
        let seed_b = [10u8; 64];
        let bind_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

        let client = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_a, 15)
            .await
            .expect("bind udp client carrier");
        let server = PqUdpMeshCarrier::bind_from_seed(bind_any, &seed_b, 15)
            .await
            .expect("bind udp server carrier");

        let server_contact = server.local_contact();

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.listen_with_response(|_peer, payload| payload).await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = client
            .register_with_relay(relay_addr)
            .await
            .expect("register client with relay");
        let _ = server
            .register_with_relay(relay_addr)
            .await
            .expect("register server with relay");

        let response = client
            .send_with_response_via_relay(relay_addr, &server_contact, b"hello pq relay mesh")
            .await
            .expect("send over PQ relay mesh carrier");

        assert_eq!(response, b"hello pq relay mesh");

        server_task.abort();
        let _ = server_task.await;
        relay_task.abort();
        let _ = relay_task.await;
    }

    #[test]
    fn fragmentation_round_trips() {
        let payload = vec![0x5Au8; DEFAULT_UDP_MTU_SAFE_PAYLOAD * 3 + 111];
        let fragments =
            fragment_payload(&payload, DEFAULT_UDP_MTU_SAFE_PAYLOAD).expect("fragment payload");
        assert!(fragments.len() >= 4);

        let mut reassembly = MeshReassemblyBuffer::new();
        let mut restored = None;
        for fragment in fragments {
            restored = reassembly.push(fragment);
        }

        assert_eq!(restored.expect("reassembled payload"), payload);
    }

    #[test]
    fn multiplexed_session_frame_preserves_metadata() {
        let frame = MeshSessionFrame {
            session_id: [0x11; 16],
            stream_id: 7,
            sequence: 42,
            kind: MeshSessionFrameKind::Data,
            payload: b"mesh stream payload".to_vec(),
        };

        assert_eq!(frame.stream_id, 7);
        assert_eq!(frame.sequence, 42);
        assert_eq!(frame.kind, MeshSessionFrameKind::Data);
        assert_eq!(frame.payload, b"mesh stream payload");
    }
}
