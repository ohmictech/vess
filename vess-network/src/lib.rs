use std::net::SocketAddr;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as _;
use vess_crypto::*;

pub const TAG_PAYMENT: u8 = 0x01;
pub const TAG_ROOT: u8 = 0x02;
pub const TAG_PEER_ANNOUNCE: u8 = 0x05;
pub const TAG_PING: u8 = 0x06;
pub const TAG_PONG: u8 = 0x07;
pub const TAG_STATE_SYNC_REQ: u8 = 0x08;
pub const TAG_STATE_SYNC_CHUNK: u8 = 0x09;
pub const TAG_INTRODUCE_REQUEST: u8 = 0x0A;
pub const TAG_BLOCK: u8 = 0x0B;
pub const TAG_INTRODUCE: u8 = 0x0C;
pub const TAG_HOLE_PUNCH: u8 = 0x0D;
pub const TAG_STEM_RELAY: u8 = 0x0E;

pub const RPC_CHECK: u8 = 0x10;
pub const RPC_CHECK_RESP: u8 = 0x11;
pub const RPC_SUBMIT: u8 = 0x14;
pub const RPC_SUBMIT_RESP: u8 = 0x15;
pub const RPC_CONNECT_PEER: u8 = 0x1A;
pub const RPC_CONNECT_PEER_RESP: u8 = 0x1B;
pub const RPC_GET_PEERS: u8 = 0x18;
pub const RPC_GET_PEERS_RESP: u8 = 0x19;

pub const HANDSHAKE_INIT: u8 = 0x80;
pub const HANDSHAKE_RESP: u8 = 0x81;
pub const ENCRYPTED_DATA: u8 = 0x00;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub enum GossipMessage {
    Payment(VessPayment),
    Block(VessBlock),
    Root(u64, MerkleRoot),
    PeerAnnounce(NodeId, SocketAddr),
    Ping(u32),
    Pong(u32),
    StateSyncReq(u64, u32),
    StateSyncChunk(u64, Vec<VessId>),
    /// "Introduce me to this peer" — sent by NAT'd node to its introducer
    IntroduceRequest(NodeId),
    /// "This peer wants to reach you at this address" — sent by introducer
    Introduce(NodeId, SocketAddr),
    /// Dummy packet for NAT hole punching; carries random nonce
    HolePunch(u32),
    /// Fallback relay through introducer: target_node_id, raw_gossip_bytes
    StemRelay(NodeId, Vec<u8>),
}

#[derive(Debug)]
pub enum RpcRequest {
    Check(VessId),
    Submit(VessPayment),
    GetPeers,
    ConnectPeer(std::net::SocketAddr),
}

#[derive(Debug)]
pub enum RpcResponse {
    Check(bool),
    Submit(bool),
    GetPeers(Vec<(NodeId, SocketAddr)>),
    ConnectPeer(bool),
}

pub fn frame(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![tag];
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn unframe(data: &[u8]) -> Option<(u8, &[u8])> {
    if data.len() < 5 { return None; }
    let len = u32::from_le_bytes(data[1..5].try_into().ok()?) as usize;
    if data.len() < 5 + len { return None; }
    Some((data[0], &data[5..5 + len]))
}

pub fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

impl GossipMessage {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            GossipMessage::Payment(p) => frame(TAG_PAYMENT, &p.encode()),
            GossipMessage::Block(b) => frame(TAG_BLOCK, &b.encode()),
            GossipMessage::Root(v, r) => {
                let mut p = Vec::new();
                write_u64(&mut p, *v);
                write_fixed(&mut p, r);
                frame(TAG_ROOT, &p)
            }
            GossipMessage::PeerAnnounce(id, addr) => {
                let mut p = Vec::new();
                write_fixed(&mut p, id);
                write_u16(&mut p, addr.port());
                write_bytes(&mut p, addr.ip().to_string().as_bytes());
                frame(TAG_PEER_ANNOUNCE, &p)
            }
            GossipMessage::Ping(n) => frame(TAG_PING, &n.to_le_bytes()),
            GossipMessage::Pong(n) => frame(TAG_PONG, &n.to_le_bytes()),
            GossipMessage::StateSyncReq(start, count) => {
                let mut p = Vec::new();
                write_u64(&mut p, *start);
                write_u32(&mut p, *count);
                frame(TAG_STATE_SYNC_REQ, &p)
            }
            GossipMessage::StateSyncChunk(start, ids) => {
                let mut p = Vec::new();
                write_u64(&mut p, *start);
                write_u32(&mut p, ids.len() as u32);
                for id in ids { write_fixed(&mut p, id); }
                frame(TAG_STATE_SYNC_CHUNK, &p)
            }
            GossipMessage::IntroduceRequest(target_id) => {
                frame(TAG_INTRODUCE_REQUEST, target_id)
            }
            GossipMessage::Introduce(id, addr) => {
                let mut p = Vec::new();
                write_fixed(&mut p, id);
                write_u16(&mut p, addr.port());
                write_bytes(&mut p, addr.ip().to_string().as_bytes());
                frame(TAG_INTRODUCE, &p)
            }
            GossipMessage::HolePunch(nonce) => {
                frame(TAG_HOLE_PUNCH, &nonce.to_le_bytes())
            }
            GossipMessage::StemRelay(target_id, data) => {
                let mut p = Vec::new();
                write_fixed(&mut p, target_id);
                write_u32(&mut p, data.len() as u32);
                p.extend_from_slice(data);
                frame(TAG_STEM_RELAY, &p)
            }
        }
    }

    pub fn decode(tag: u8, payload: &[u8]) -> Option<Self> {
        let mut pos = 0;
        match tag {
            TAG_PAYMENT => VessPayment::decode(payload, &mut pos).map(GossipMessage::Payment),
            TAG_BLOCK => VessBlock::decode(payload, &mut pos).map(GossipMessage::Block),
            TAG_ROOT => {
                Some(GossipMessage::Root(read_u64(payload, &mut pos)?, read_fixed(payload, &mut pos)?))
            }
            TAG_PEER_ANNOUNCE => {
                let id = read_fixed(payload, &mut pos)?;
                let port = u16::from_le_bytes(payload[pos..pos+2].try_into().ok()?); pos += 2;
                let ip_bytes = read_bytes(payload, &mut pos)?;
                let ip_str = std::str::from_utf8(&ip_bytes).ok()?;
                let addr = format!("{}:{}", ip_str, port).parse().ok()?;
                Some(GossipMessage::PeerAnnounce(id, addr))
            }
            TAG_PING => {
                Some(GossipMessage::Ping(u32::from_le_bytes(payload[..4].try_into().ok()?)))
            }
            TAG_PONG => {
                Some(GossipMessage::Pong(u32::from_le_bytes(payload[..4].try_into().ok()?)))
            }
            TAG_STATE_SYNC_REQ => {
                Some(GossipMessage::StateSyncReq(read_u64(payload, &mut pos)?, read_u32(payload, &mut pos)?))
            }
            TAG_STATE_SYNC_CHUNK => {
                let start = read_u64(payload, &mut pos)?;
                let count = read_u32(payload, &mut pos)? as usize;
                let mut ids = Vec::with_capacity(count);
                for _ in 0..count { ids.push(read_fixed(payload, &mut pos)?); }
                Some(GossipMessage::StateSyncChunk(start, ids))
            }
            TAG_INTRODUCE_REQUEST => {
                Some(GossipMessage::IntroduceRequest(read_fixed(payload, &mut pos)?))
            }
            TAG_INTRODUCE => {
                let id = read_fixed(payload, &mut pos)?;
                let port = u16::from_le_bytes(payload[pos..pos+2].try_into().ok()?); pos += 2;
                let ip_bytes = read_bytes(payload, &mut pos)?;
                let ip_str = std::str::from_utf8(&ip_bytes).ok()?;
                let addr = format!("{}:{}", ip_str, port).parse().ok()?;
                Some(GossipMessage::Introduce(id, addr))
            }
            TAG_HOLE_PUNCH => {
                Some(GossipMessage::HolePunch(u32::from_le_bytes(payload[..4].try_into().ok()?)))
            }
            TAG_STEM_RELAY => {
                let target_id = read_fixed(payload, &mut pos)?;
                let len = read_u32(payload, &mut pos)? as usize;
                if payload.len() < pos + len { return None; }
                let data = payload[pos..pos+len].to_vec();
                Some(GossipMessage::StemRelay(target_id, data))
            }
            _ => None,
        }
    }
}

impl RpcRequest {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RpcRequest::Check(id) => frame(RPC_CHECK, id),
            RpcRequest::Submit(p) => frame(RPC_SUBMIT, &p.encode()),
            RpcRequest::GetPeers => frame(RPC_GET_PEERS, &[]),
            RpcRequest::ConnectPeer(addr) => {
                let mut p = Vec::new();
                write_u16(&mut p, addr.port());
                write_bytes(&mut p, addr.ip().to_string().as_bytes());
                frame(RPC_CONNECT_PEER, &p)
            }
        }
    }

    pub fn decode(tag: u8, payload: &[u8]) -> Option<Self> {
        let mut pos = 0;
        match tag {
            RPC_CHECK => Some(RpcRequest::Check(read_fixed(payload, &mut pos)?)),
            RPC_SUBMIT => VessPayment::decode(payload, &mut pos).map(RpcRequest::Submit),
            RPC_GET_PEERS => Some(RpcRequest::GetPeers),
            RPC_CONNECT_PEER => {
                let port = u16::from_le_bytes(payload.get(..2)?.try_into().ok()?);
                pos = 2;
                let ip_bytes = read_bytes(payload, &mut pos)?;
                let ip_str = std::str::from_utf8(&ip_bytes).ok()?;
                let addr = format!("{}:{}", ip_str, port).parse().ok()?;
                Some(RpcRequest::ConnectPeer(addr))
            }
            _ => None,
        }
    }
}

impl RpcResponse {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RpcResponse::Check(b) => frame(RPC_CHECK_RESP, &[*b as u8]),
            RpcResponse::Submit(b) => frame(RPC_SUBMIT_RESP, &[*b as u8]),
            RpcResponse::ConnectPeer(b) => frame(RPC_CONNECT_PEER_RESP, &[*b as u8]),
            RpcResponse::GetPeers(peers) => {
                let mut p = Vec::new();
                write_u32(&mut p, peers.len() as u32);
                for (id, addr) in peers {
                    write_fixed(&mut p, id); write_u16(&mut p, addr.port());
                    write_bytes(&mut p, addr.ip().to_string().as_bytes());
                }
                frame(RPC_GET_PEERS_RESP, &p)
            }
        }
    }

    pub fn decode(tag: u8, payload: &[u8]) -> Option<Self> {
        let mut pos = 0;
        match tag {
            RPC_CHECK_RESP => Some(RpcResponse::Check(payload.first()? != &0)),
            RPC_SUBMIT_RESP => Some(RpcResponse::Submit(payload.first()? != &0)),
            RPC_GET_PEERS_RESP => {
                let count = read_u32(payload, &mut pos)? as usize;
                let mut peers = Vec::with_capacity(count);
                for _ in 0..count {
                    let id = read_fixed(payload, &mut pos)?;
                    let port = u16::from_le_bytes(payload[pos..pos+2].try_into().ok()?); pos += 2;
                    let ip_bytes = read_bytes(payload, &mut pos)?;
                    let ip_str = std::str::from_utf8(&ip_bytes).ok()?;
                    let addr = format!("{}:{}", ip_str, port).parse().ok()?;
                    peers.push((id, addr));
                }
                Some(RpcResponse::GetPeers(peers))
            }
            RPC_CONNECT_PEER_RESP => {
                Some(RpcResponse::ConnectPeer(payload.first().copied().unwrap_or(0) != 0))
            }
            _ => None,
        }
    }
}

pub struct Session {
    pub addr: SocketAddr,
    pub node_id: Option<NodeId>,
    pub session_key: [u8; 32],
    pub peer_version: u32,
    /// The address this peer claims is theirs (from PeerAnnounce).
    /// If this matches the observed source, the peer is publicly reachable.
    pub reported_addr: Option<SocketAddr>,
    pub nonce_ctr: u64,
}

impl Session {
    /// Encrypt with explicit nonce prepended: nonce(8 bytes) || ciphertext.
    /// Packet loss cannot desync the stream — each message carries its own nonce.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_ctr.to_le_bytes());
        self.nonce_ctr = self.nonce_ctr.wrapping_add(1);
        let ct = chacha_encrypt(&self.session_key, &nonce, plaintext);
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&nonce[..8]);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt: reads nonce from first 8 bytes, decrypts the rest.
    /// No counter state needed on the receiving side.
    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 8 { return None; }
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&data[..8]);
        chacha_decrypt(&self.session_key, &nonce, &data[8..])
    }

    /// A peer is publicly reachable if their self-reported address matches
    /// the address we observe them sending from.
    pub fn is_public_peer(&self) -> bool {
        self.reported_addr == Some(self.addr)
    }
}

pub struct Network {
    pub sessions: Vec<Session>,
    pub dsa_sk: dilithium3::SecretKey,
    pub dsa_pk: dilithium3::PublicKey,
    pub kem_sk: kyber512::SecretKey,
    pub kem_pk: kyber512::PublicKey,
}

impl Network {
    pub fn new() -> Self {
        let (dsa_pk, dsa_sk) = dsa_generate();
        let (kem_pk, kem_sk) = kem_generate();
        Self { sessions: Vec::new(), dsa_sk, dsa_pk, kem_sk, kem_pk }
    }

    pub fn my_node_id(&self) -> NodeId { node_id(&self.dsa_pk) }

    pub fn session_by_addr(&self, addr: &SocketAddr) -> Option<&Session> {
        self.sessions.iter().find(|s| s.addr == *addr)
    }

    pub fn session_by_addr_mut(&mut self, addr: &SocketAddr) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|s| s.addr == *addr)
    }

    pub fn build_handshake_init(&mut self, addr: SocketAddr) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&self.my_node_id());
        p.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        p.extend_from_slice(self.kem_pk.as_bytes());
        self.sessions.push(Session { addr, node_id: None, session_key: [0u8; 32], peer_version: 0, reported_addr: None, nonce_ctr: 0 });
        frame(HANDSHAKE_INIT, &p)
    }

    pub fn handle_handshake(&mut self, addr: SocketAddr, tag: u8, payload: &[u8]) -> Option<Vec<u8>> {
        match tag {
            HANDSHAKE_INIT => {
                if payload.len() <= 36 { return None; }
                let peer_id: NodeId = payload[..32].try_into().ok()?;
                let peer_ver = u32::from_le_bytes(payload[32..36].try_into().ok()?);
                let ekem_raw = &payload[36..];
                let ekem_pk = kyber512::PublicKey::from_bytes(ekem_raw).ok()?;
                let (ct_bytes, ss_bytes) = kem_encapsulate(&ekem_pk);
                let sig = dsa_sign(&self.dsa_sk, &payload[..32]);
                // Canonical ordering: both sides derive the same key
                let (a, b) = if peer_id < self.my_node_id() { (peer_id, self.my_node_id()) } else { (self.my_node_id(), peer_id) };
                let session_key = blake3_hash_multi(&[&ss_bytes, &a, &b]);
                let mut resp = Vec::new();
                resp.extend_from_slice(&self.my_node_id());
                resp.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
                write_bytes(&mut resp, &sig);
                write_bytes(&mut resp, &ct_bytes);
                self.sessions.push(Session { addr, node_id: Some(peer_id), session_key, peer_version: peer_ver, reported_addr: None, nonce_ctr: 0 });
                Some(frame(HANDSHAKE_RESP, &resp))
            }
            HANDSHAKE_RESP => {
                if payload.len() < 36 { return None; }
                let peer_id: NodeId = payload[..32].try_into().ok()?;
                let peer_ver = u32::from_le_bytes(payload[32..36].try_into().ok()?);
                let mut pos = 36;
                let _sig = read_bytes(payload, &mut pos)?;
                let ct_bytes = read_bytes(payload, &mut pos)?;
                let ss_bytes = kem_decapsulate(&ct_bytes, &self.kem_sk)?;
                let (a, b) = if peer_id < self.my_node_id() { (peer_id, self.my_node_id()) } else { (self.my_node_id(), peer_id) };
                let session_key = blake3_hash_multi(&[&ss_bytes, &a, &b]);
                if let Some(s) = self.session_by_addr_mut(&addr) {
                    s.node_id = Some(peer_id);
                    s.session_key = session_key;
                    s.peer_version = peer_ver;
                    s.nonce_ctr = 0;
                }
                None
            }
            _ => None,
        }
    }
}
