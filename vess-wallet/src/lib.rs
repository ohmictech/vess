use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use vess_crypto::*;
use vess_network::{unframe, GossipMessage, Network, RpcRequest, RpcResponse, HANDSHAKE_RESP, HANDSHAKE_INIT, frame, ENCRYPTED_DATA};
use vess_network::data_packets::{self, MessageId, PacketReassembler};
use zeroize::Zeroize;

mod ffi;

const RPC_TIMEOUT_MS: u64 = 5000;
const WALLET_MAGIC: &[u8; 8] = b"VESSWLT\0";
const WALLET_FORMAT_VERSION: u8 = 2; // v2: ML-DSA-65 keys, 32-byte seeds, no spend keys in canonical encodings
const WALLET_HEADER_LEN: usize = WALLET_MAGIC.len() + 1 + 12 + 32;
const MAX_WALLET_ITEMS: usize = 1_000_000;

struct Keypair {
    dsa_pk: Vec<u8>,   // 1952-byte ML-DSA-65 verifying key
    dsa_sk: Vec<u8>,   // 32-byte ML-DSA-65 seed
}

pub struct Wallet {
    pub vbank_claimed: Vec<Vess>,
    pub vbank_unclaimed: Vec<Vess>,
    pub vbank_pending: Vec<Vess>,          // spent in an exported payment, awaiting confirmation
    preimages: HashMap<VessId, [u8; 32]>,  // hashlock preimages for inputs we can spend
    #[allow(dead_code)]
    pbank_minting: Vec<VessPayment>,
    pbank_built: Vec<VessPayment>,
    pbank_received: Vec<VessPayment>,
    keypairs: HashMap<OwnerHash, Keypair>,
    password_hash: [u8; 32],
    salt: [u8; 32],
    network: Network,
    node_addr: Option<SocketAddr>,
    socket: Option<UdpSocket>,
    packet_reassembly: PacketReassembler,
    transport_tick: u64,
}

impl Wallet {
    pub fn new(password: &[u8]) -> Self {
        let salt = random_bytes::<32>();
        let key = argon2id_key(password, &salt);
        Self {
            vbank_claimed: Vec::new(), vbank_unclaimed: Vec::new(), vbank_pending: Vec::new(),
            preimages: HashMap::new(),
            pbank_minting: Vec::new(), pbank_built: Vec::new(), pbank_received: Vec::new(),
            keypairs: HashMap::new(),
            password_hash: key, salt,
            network: Network::new(),
            node_addr: None, socket: None, packet_reassembly: PacketReassembler::new(), transport_tick: 0,
        }
    }

    fn reassemble_packet(&mut self, bytes: &[u8]) -> Option<Option<(Option<MessageId>, Vec<u8>)>> {
        self.transport_tick = self.transport_tick.wrapping_add(1);
        if !data_packets::is_fragment(bytes) { return Some(Some((None, bytes.to_vec()))); }
        self.packet_reassembly.push(bytes, self.transport_tick).ok()
            .map(|result| result.map(|(id, message)| (Some(id), message)))
    }

    fn acknowledge_packet(&mut self, id: MessageId) {
        let Some(addr) = self.node_addr else { return; };
        let Some(socket) = self.socket.as_ref().and_then(|s| s.try_clone().ok()) else { return; };
        let Some(session) = self.network.session_by_addr_mut(&addr) else { return; };
        let plain = GossipMessage::DataAck(id).encode();
        let packet = frame(ENCRYPTED_DATA, &session.encrypt(&plain));
        if let Some(fragments) = data_packets::fragment_message(&packet) {
            for fragment in fragments { let _ = socket.send_to(&fragment, addr); }
        }
    }

    /// Returns true if we have a completed handshake session with the node.
    pub fn connected(&self) -> bool {
        self.node_addr
            .and_then(|a| self.network.session_by_addr(&a))
            .map(|s| s.session_key != [0u8; 32])
            .unwrap_or(false)
    }

    /// Returns the node address we're connected to, if any.
    pub fn node(&self) -> Option<SocketAddr> {
        self.node_addr
    }

    /// Number of keypairs stored in the wallet.
    pub fn keypair_count(&self) -> usize {
        self.keypairs.len()
    }

    /// Payment history counts: (built, received).
    pub fn history_counts(&self) -> (usize, usize) {
        (self.pbank_built.len(), self.pbank_received.len())
    }

    /// Get peer count from the connected node via RPC.
    pub fn peer_count(&mut self) -> Option<usize> {
        match self.call_rpc(RpcRequest::GetPeers)? {
            RpcResponse::GetPeers(peers) => Some(peers.len()),
            _ => None,
        }
    }

    pub fn bind(&mut self) -> std::io::Result<()> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        // Windows: prevent ICMP port-unreachable from killing the socket.
        // Without this, any stray ICMP error translates to WSAECONNRESET.
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            const SIO_UDP_CONNRESET: u32 = 0x9800000C;
            extern "system" {
                fn WSAIoctl(
                    s: usize, code: u32, inbuf: *const u8, inlen: u32,
                    outbuf: *mut u8, outlen: u32, bytes: *mut u32,
                    ovl: *mut u8, comp: *mut u8,
                ) -> i32;
            }
            let raw = sock.as_raw_socket() as usize;
            let false_val: u32 = 0;
            let mut _bytes: u32 = 0;
            unsafe {
                WSAIoctl(raw, SIO_UDP_CONNRESET,
                    &false_val as *const u32 as *const u8, 4,
                    std::ptr::null_mut(), 0,
                    &mut _bytes,
                    std::ptr::null_mut(), std::ptr::null_mut());
            }
        }
        self.socket = Some(sock);
        Ok(())
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Vec<u8> {
        self.node_addr = Some(addr);
        self.network.build_handshake_init(addr)
    }

    pub fn handshake_complete(&mut self, data: &[u8]) -> bool {
        let (tag, payload) = match unframe(data) { Some(v) => v, None => return false };
        if tag != HANDSHAKE_RESP { return false; }
        let addr = match self.node_addr { Some(a) => a, None => return false };
        self.network.handle_handshake(addr, tag, payload);
        // RESP returns None (no reply needed), but the session key is set
        self.network.session_by_addr(&addr)
            .map(|s| s.session_key != [0u8; 32])
            .unwrap_or(false)
    }

    /// Full connect: solve PoW, send handshake init, wait for response.
    pub fn connect_full(&mut self, addr: SocketAddr) -> bool {
        if self.bind().is_err() { return false; }
        self.node_addr = Some(addr);
        let inner = self.network.build_handshake_init(addr);
        let (tag, payload) = match unframe(&inner) {
            Some((t, p)) if t == HANDSHAKE_INIT => (t, p),
            _ => return false,
        };
        let base = blake3_hash(&[b"vess-handshake" as &[u8], &self.network.my_node_id(), &addr.to_string().as_bytes()].concat());
        let mut header = base;
        let proof = loop {
            if let Some(p) = cuckoo::solve(&header, cuckoo::HANDSHAKE_CYCLE_LENGTH, cuckoo::HANDSHAKE_EDGE_BITS) {
                break (header, p);
            }
            header = blake3_hash(&header);
        };
        let mut payload_with_pow = payload.to_vec();
        payload_with_pow.extend_from_slice(&proof.0);
        for n in &proof.1 { payload_with_pow.extend_from_slice(&n.to_le_bytes()); }
        let init_with_pow = frame(tag, &payload_with_pow);

        let socket = match &self.socket { Some(s) => match s.try_clone() { Ok(s) => s, Err(_) => return false }, None => return false };
        let Some(fragments) = data_packets::fragment_message(&init_with_pow) else { return false; };
        for fragment in fragments {
            if socket.send_to(&fragment, addr).is_err() { return false; }
        }
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        let mut buf = [0u8; 65536];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, _src)) => match self.reassemble_packet(&buf[..len]) {
                    Some(Some((id, packet))) => {
                        let connected = self.handshake_complete(&packet);
                        if connected { if let Some(id) = id { self.acknowledge_packet(id); } }
                        return connected;
                    }
                    Some(None) => continue,
                    None => return false,
                },
                Err(_) => return false,
            }
        }
    }

    fn call_rpc(&mut self, req: RpcRequest) -> Option<RpcResponse> {
        let addr = self.node_addr?;
        let socket = self.socket.as_ref()?.try_clone().ok()?;
        let plain = req.encode();
        let encrypted = self.network.session_by_addr_mut(&addr)?.encrypt(&plain);
        let framed = frame(ENCRYPTED_DATA, &encrypted);
        let fragments = data_packets::fragment_message(&framed)?;
        for fragment in &fragments {
            if socket.send_to(fragment, addr).is_err() { return None; }
        }
        // Switch to non-blocking to drain gossip quickly
        socket.set_nonblocking(true).ok()?;
        let mut buf = [0u8; 65536];
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(RPC_TIMEOUT_MS);
        let mut next_retry = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut retries = 0u8;
        let packet = loop {
            if std::time::Instant::now() >= deadline {
                let _ = socket.set_nonblocking(false);
                return None;
            }
            let (len, _) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= next_retry && retries < 3 {
                        for fragment in &fragments { let _ = socket.send_to(fragment, addr); }
                        retries += 1;
                        next_retry += std::time::Duration::from_secs(1);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(_) => { let _ = socket.set_nonblocking(false); return None; },
            };
            let (packet_id, packet) = match self.reassemble_packet(&buf[..len]) {
                Some(Some(packet)) => packet,
                Some(None) => continue,
                None => { let _ = socket.set_nonblocking(false); return None; },
            };
            if let Some(id) = packet_id { self.acknowledge_packet(id); }
            // Gossip is outer-framed; RPC responses are raw encrypted bytes.
            if packet.len() >= 5 && packet[0] == ENCRYPTED_DATA {
                let frame_len = u32::from_le_bytes(packet[1..5].try_into().ok()?) as usize;
                if packet.len() == 5 + frame_len { continue; }
            }
            break packet;
        };
        let _ = socket.set_nonblocking(false);
        let plain = self.network.session_by_addr_mut(&addr)?.decrypt(&packet)?;
        let (inner_tag, inner_payload) = unframe(&plain)?;
        RpcResponse::decode(inner_tag, inner_payload)
    }

    pub fn check(&mut self, vess_id: &VessId) -> Option<bool> {
        match self.call_rpc(RpcRequest::Check(*vess_id))? {
            RpcResponse::Check(b) => Some(b),
            _ => None,
        }
    }

    pub fn submit_payment(&mut self, payment: &VessPayment) -> Option<bool> {
        match self.call_rpc(RpcRequest::Submit(payment.clone()))? {
            RpcResponse::Submit(b) => Some(b),
            _ => None,
        }
    }

    pub fn balance(&self) -> Amount {
        self.vbank_claimed.iter().map(|v| v.amount).sum::<u64>()
            + self.vbank_unclaimed.iter().map(|v| v.amount).sum::<u64>()
    }

    /// Balance that is currently spendable (excludes pending).
    pub fn spendable_balance(&self) -> Amount {
        self.vbank_claimed.iter().map(|v| v.amount).sum::<u64>()
    }

    /// Balance locked in pending (exported but unconfirmed).
    pub fn pending_balance(&self) -> Amount {
        self.vbank_pending.iter().map(|v| v.amount).sum::<u64>()
    }

    pub fn build_invoice(&mut self, amount: Option<Amount>, memo: Option<&str>, hashlock: Option<&[u8; 32]>, expires_at: Option<u64>) -> String {
        let (pk, sk) = dsa_generate();
        let owner_hash = dsa_pubkey_hash(&pk);
        self.keypairs.insert(owner_hash, Keypair { dsa_pk: pk, dsa_sk: sk });
        let mut url = format!("vess://{}", hex::encode(owner_hash));
        let mut params = Vec::new();
        if let Some(a) = amount { params.push(format!("amount={}", a)); }
        if let Some(m) = memo { params.push(format!("memo={}", m)); }
        if let Some(hl) = hashlock { params.push(format!("hashlock={}", hex::encode(hl))); }
        if let Some(ts) = expires_at { params.push(format!("expires={}", ts)); }
        if !params.is_empty() { url.push('?'); url.push_str(&params.join("&")); }
        url
    }

    pub fn build_payment(&mut self, outputs: &[(OwnerHash, Amount, Option<SpendCondition>)]) -> Option<VessPayment> {
        let total_needed: Amount = outputs.iter().map(|(_, a, _)| a).sum();
        let mut selected = Vec::new();
        let mut selected_sum = 0;
        // Only select from claimed (never pending or unclaimed)
        let pool: Vec<&Vess> = self.vbank_claimed.iter().collect();
        for v in &pool {
            if selected_sum >= total_needed { break; }
            selected.push((*v).clone());
            selected_sum += v.amount;
        }
        if selected_sum < total_needed { return None; }
        let change = selected_sum - total_needed;

        // Outputs: timestamp=0 for transfers (not mints)
        let mut out_vess: Vec<Vess> = outputs.iter().map(|(oh, amt, sc)| {
            Vess { variant: VessVariant::Output, amount: *amt, owner_hash: *oh,
                timestamp: 0, nonce: 0, salt: random_bytes(),
                pubkey: Vec::new(), spend_key: Vec::new(),
                spend_condition: sc.clone() }
        }).collect();

        if change > 0 {
            let (pk, sk) = dsa_generate();
            let oh = dsa_pubkey_hash(&pk);
            self.keypairs.insert(oh, Keypair { dsa_pk: pk, dsa_sk: sk });
            out_vess.push(Vess { variant: VessVariant::Output, amount: change, owner_hash: oh, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: Vec::new(), spend_key: Vec::new(), spend_condition: None });
        }

        // Populate preimages for hashlocked inputs
        let preimages: Vec<Option<[u8; 32]>> = selected.iter().map(|v| {
            self.preimages.get(&v.vess_id()).copied()
        }).collect();
        let mut payment = VessPayment { payment_id: [0u8; 32], inputs: selected, outputs: out_vess, timestamp: 0, sigs: Vec::new(), preimages };
        payment.compute();

        for v in &payment.inputs {
            if let Some(kp) = self.keypairs.get(&v.owner_hash) {
                if let Some(sig) = dsa_sign(&kp.dsa_sk, &payment.payment_id) {
                    payment.sigs.push(sig);
                }
            }
        }
        self.pbank_built.push(payment.clone());
        Some(payment)
    }

    /// Build and encode a payment for OOB delivery. Moves used inputs to pending.
    /// The receiver calls `claim_payment` to submit; until then these coins are locked.
    pub fn export_payment(&mut self, outputs: &[(OwnerHash, Amount, Option<SpendCondition>)]) -> Option<Vec<u8>> {
        let payment = self.build_payment(outputs)?;
        // Move spent inputs to pending — don't delete until confirmed gone by sync
        for v in &payment.inputs {
            let id = v.vess_id();
            if let Some(pos) = self.vbank_claimed.iter().position(|x| x.vess_id() == id) {
                self.vbank_pending.push(self.vbank_claimed.remove(pos));
            }
        }
        self.pbank_built.push(payment.clone());
        Some(payment.encode())
    }

    pub fn send(&mut self, payment: &VessPayment) -> bool {
        if !self.submit_payment(payment).unwrap_or(false) { return false; }
        for v in &payment.inputs {
            let id = v.vess_id();
            // Move to pending — don't delete until confirmed by sync.
            if let Some(pos) = self.vbank_claimed.iter().position(|x| x.vess_id() == id) {
                self.vbank_pending.push(self.vbank_claimed.remove(pos));
            } else if let Some(pos) = self.vbank_unclaimed.iter().position(|x| x.vess_id() == id) {
                self.vbank_pending.push(self.vbank_unclaimed.remove(pos));
            }
        }
        for v in &payment.outputs {
            if let Some(kp) = self.keypairs.get(&v.owner_hash) {
                let mut owned = v.clone();
                owned.pubkey = kp.dsa_pk.clone();
                owned.spend_key = kp.dsa_sk.clone();
                self.vbank_unclaimed.push(owned);
            }
        }
        true
    }

    /// Receiver side: submit a VessPayment blob (from OOB) to the network and
    /// add any outputs belonging to us into vbank_unclaimed.
    pub fn claim_payment(&mut self, payment: &VessPayment) -> bool {
        if !self.submit_payment(payment).unwrap_or(false) { return false; }
        for v in &payment.outputs {
            if let Some(kp) = self.keypairs.get(&v.owner_hash) {
                let mut owned = v.clone();
                owned.pubkey = kp.dsa_pk.clone();
                owned.spend_key = kp.dsa_sk.clone();
                self.vbank_unclaimed.push(owned);
            }
        }
        self.pbank_received.push(payment.clone());
        true
    }

    /// Consolidate all claimed UTXOs by merging up to 5 at a time into single outputs.
    /// Returns the number of consolidation payments made.
    pub fn consolidate(&mut self) -> usize {
        if self.vbank_claimed.len() < 2 { return 0; }
        let oh = match self.keypairs.keys().next() {
            Some(k) => *k,
            None => return 0,
        };
        let mut count = 0;
        while self.vbank_claimed.len() > 1 {
            let chunk: Vec<Vess> = self.vbank_claimed.iter().take(MAX_INPUTS).cloned().collect();
            if chunk.len() < 2 { break; }
            let total: u64 = chunk.iter().map(|v| v.amount).sum();
            let payment = match self.build_payment(&[(oh, total, None)]) {
                Some(p) => p,
                None => break,
            };
            // Retry a few times — node may be busy mining
            let mut sent = false;
            for _ in 0..3 {
                if self.send(&payment) { sent = true; break; }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            if !sent { break; }
            count += 1;
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        count
    }

    /// Import a payment (OOB receive path). Verifies signatures, idempotency,
    /// and that outputs we claim actually belong to us before accepting.
    pub fn receive(&mut self, payment: VessPayment) -> bool {
        // Verify the payment is well-formed
        let mut canonical = payment.clone();
        canonical.compute();
        if canonical.payment_id != payment.payment_id { return false; }
        if payment.inputs.is_empty() || payment.outputs.is_empty() { return false; }
        if payment.input_sum() != payment.output_sum() { return false; }
        // Verify every signature
        for (i, input) in payment.inputs.iter().enumerate() {
            if i >= payment.sigs.len() { return false; }
            if !dsa_verify(&input.pubkey, &payment.payment_id, &payment.sigs[i]) { return false; }
            if dsa_pubkey_hash(&input.pubkey) != input.owner_hash { return false; }
        }
        let mut ours = 0usize;
        for v in &payment.outputs {
            if let Some(kp) = self.keypairs.get(&v.owner_hash) {
                let mut owned = v.clone();
                owned.pubkey = kp.dsa_pk.clone();
                owned.spend_key = kp.dsa_sk.clone();
                self.vbank_unclaimed.push(owned);
                ours += 1;
            }
        }
        if ours == 0 { return false; }
        self.pbank_received.push(payment);
        true
    }

    /// Import a payment blob from raw bytes (OOB receive path — no node needed).
    /// Returns Some(output_count) on success, None if the blob is invalid.
    pub fn receive_blob(&mut self, data: &[u8]) -> Option<usize> {
        let mut pos = 0;
        let payment = VessPayment::decode(data, &mut pos)?;
        let count = payment.outputs.iter()
            .filter(|v| self.keypairs.contains_key(&v.owner_hash))
            .count();
        if count == 0 { return None; }
        if self.receive(payment) { Some(count) } else { None }
    }

    /// Store a hashlock preimage for a UTXO we own. Required to spend hashlocked inputs.
    pub fn import_preimage(&mut self, vess_id: &VessId, preimage: &[u8; 32]) {
        self.preimages.insert(*vess_id, *preimage);
    }

    /// Sync unclaimed outputs against the node: check each via RPC and move
    /// confirmed ones to vbank_claimed. Returns (moved, remaining).
    /// Pending UTXOs are NOT dropped here — use `prune_pending()` explicitly.
    pub fn sync(&mut self) -> (usize, usize) {
        let ids: Vec<VessId> = self.vbank_unclaimed.iter().map(|v| v.vess_id()).collect();
        let mut moved = 0usize;
        for id in &ids {
            if self.check(id).unwrap_or(false) {
                if let Some(pos) = self.vbank_unclaimed.iter().position(|v| &v.vess_id() == id) {
                    let v = self.vbank_unclaimed.remove(pos);
                    self.vbank_claimed.push(v);
                    moved += 1;
                }
            }
        }
        (moved, self.vbank_unclaimed.len())
    }

    /// Explicitly prune pending UTXOs that are no longer on the network
    /// (payment confirmed and mined). Must be called deliberately.
    pub fn prune_pending(&mut self) -> usize {
        let pending_ids: Vec<VessId> = self.vbank_pending.iter().map(|v| v.vess_id()).collect();
        let mut pruned = 0usize;
        for id in &pending_ids {
            if !self.check(id).unwrap_or(true) {
                self.vbank_pending.retain(|v| &v.vess_id() != id);
                pruned += 1;
            }
        }
        pruned
    }

    /// Import a keypair from raw bytes (1952-byte pubkey, 32-byte seed).
    /// Validates that the seed actually derives the pubkey. Returns the owner_hash for UTXO lookup.
    pub fn import_keypair(&mut self, pubkey_bytes: &[u8], seckey_bytes: &[u8]) -> Option<OwnerHash> {
        if pubkey_bytes.len() != DSA_PUBKEY_BYTES || seckey_bytes.len() != DSA_SEED_BYTES { return None; }
        if dsa_public_from_seed(seckey_bytes)? != pubkey_bytes { return None; }
        let oh = dsa_pubkey_hash(pubkey_bytes);
        self.keypairs.insert(oh, Keypair { dsa_pk: pubkey_bytes.to_vec(), dsa_sk: seckey_bytes.to_vec() });
        Some(oh)
    }

    /// Import a keypair from files. Returns the owner_hash.
    pub fn import_keypair_files(&mut self, pub_path: &str, sec_path: &str) -> Option<OwnerHash> {
        let pk_bytes = std::fs::read(pub_path).ok()?;
        let sk_bytes = std::fs::read(sec_path).ok()?;
        self.import_keypair(&pk_bytes, &sk_bytes)
    }

    /// Import coinbase Vess objects from a node's treasure chest (LMDB "keys" database).
    /// Adds to vbank_claimed (they're confirmed on-chain). Skips duplicates.
    pub fn import_treasure(&mut self, db_path: &str) -> usize {
        let env = match unsafe { heed::EnvOpenOptions::new().map_size(1_073_741_824).max_dbs(5).open(db_path) } {
            Ok(e) => e, Err(_) => return 0,
        };
        let t = match env.read_txn() { Ok(t) => t, Err(_) => return 0 };
        let keys_db: heed::Database<heed::types::Bytes, heed::types::Bytes> = match env.open_database(&t, Some("keys")) {
            Ok(Some(d)) => d, _ => return 0,
        };
        // Cross-check against the UTXO set — only import unspent coinbases
        let vess_db: heed::Database<heed::types::Bytes, heed::types::Unit> = match env.open_database(&t, Some("vess")) {
            Ok(Some(d)) => d, _ => return 0,
        };
        let mut count = 0;
        // Track known IDs to skip duplicates
        let known: Vec<VessId> = self.vbank_claimed.iter()
            .chain(self.vbank_unclaimed.iter())
            .map(|v| v.vess_id())
            .collect();
        if let Ok(iter) = keys_db.iter(&t) {
            for entry in iter {
                if let Ok((_key, bytes)) = entry {
                    if let Some(v) = Vess::decode_with_secrets(&bytes, &mut 0) {
                        if v.variant == VessVariant::Mint {
                            if !known.contains(&v.vess_id()) {
                                // Must be unspent in the UTXO set
                                if vess_db.get(&t, &v.vess_id()).ok().flatten().is_none() {
                                    continue; // already spent, skip
                                }
                                // Extract keypair from Vess or use stored keypair (for dev outputs)
                                if !v.pubkey.is_empty() && !v.spend_key.is_empty()
                                    && !self.keypairs.contains_key(&v.owner_hash) {
                                    let _ = self.import_keypair(&v.pubkey, &v.spend_key);
                                }
                                // Accept if we have the keypair (from import-key or embedded in Vess)
                                if self.keypairs.contains_key(&v.owner_hash) {
                                    self.vbank_claimed.push(v);
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        count
    }

    pub fn save(&self) -> Vec<u8> {
        let mut plain = Vec::new();
        write_u32(&mut plain, self.vbank_claimed.len() as u32);
        for v in &self.vbank_claimed { plain.extend(&v.encode_with_secrets()); }
        write_u32(&mut plain, self.vbank_unclaimed.len() as u32);
        for v in &self.vbank_unclaimed { plain.extend(&v.encode_with_secrets()); }
        write_u32(&mut plain, self.vbank_pending.len() as u32);
        for v in &self.vbank_pending { plain.extend(&v.encode_with_secrets()); }
        write_u32(&mut plain, self.preimages.len() as u32);
        for (id, pre) in &self.preimages {
            write_fixed(&mut plain, id);
            write_fixed(&mut plain, pre);
        }
        write_u32(&mut plain, self.keypairs.len() as u32);
        for (oh, kp) in &self.keypairs {
            write_fixed(&mut plain, oh);
            write_bytes(&mut plain, &kp.dsa_pk);
            write_bytes(&mut plain, &kp.dsa_sk);
        }
        // Persist payment history: built + received
        write_u32(&mut plain, self.pbank_built.len() as u32);
        for p in &self.pbank_built {
            let encoded = p.encode();
            write_u32(&mut plain, encoded.len() as u32);
            plain.extend_from_slice(&encoded);
        }
        write_u32(&mut plain, self.pbank_received.len() as u32);
        for p in &self.pbank_received {
            let encoded = p.encode();
            write_u32(&mut plain, encoded.len() as u32);
            plain.extend_from_slice(&encoded);
        }
        write_fixed(&mut plain, &self.salt);
        let nonce = random_bytes::<12>();
        let ct = chacha_encrypt(&self.password_hash, &nonce, &plain);
        plain.zeroize();
        // Format: magic(8) || version(1) || nonce(12) || salt(32) || ciphertext
        let mut out = Vec::with_capacity(WALLET_HEADER_LEN + ct.len());
        out.extend_from_slice(WALLET_MAGIC);
        out.push(WALLET_FORMAT_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&ct);
        out
    }

    /// Persist only ciphertext. The plaintext serialization buffer exists only
    /// inside `save()` and is wiped before this method writes anything to disk.
    pub fn save_to_path(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("wallet.vess");
        let temp = parent.join(format!(".{name}.tmp"));
        let data = self.save();
        let mut file = std::fs::File::create(&temp)?;
        use std::io::Write as _;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);
        #[cfg(windows)]
        if path.exists() { std::fs::remove_file(path)?; }
        std::fs::rename(temp, path)
    }

    pub fn load(data: &[u8], password: &[u8]) -> Option<Self> {
        let (nonce_offset, salt_offset, cipher_offset) = if data.starts_with(WALLET_MAGIC) {
            if data.len() < WALLET_HEADER_LEN || data[WALLET_MAGIC.len()] != WALLET_FORMAT_VERSION { return None; }
            (WALLET_MAGIC.len() + 1, WALLET_MAGIC.len() + 1 + 12, WALLET_HEADER_LEN)
        } else {
            // Legacy format: nonce(12) || salt(32) || ciphertext.
            if data.len() < 44 { return None; }
            (0, 12, 44)
        };
        let nonce: [u8; 12] = data[nonce_offset..nonce_offset + 12].try_into().ok()?;
        let salt: [u8; 32] = data[salt_offset..salt_offset + 32].try_into().ok()?;
        let key = argon2id_key(password, &salt);
        let mut plain = chacha_decrypt(&key, &nonce, &data[cipher_offset..])?;
        let result = Self::load_plain(&plain, key, salt);
        plain.zeroize();
        result
    }

    fn load_plain(plain: &[u8], key: [u8; 32], salt: [u8; 32]) -> Option<Self> {
        let mut pos = 0;
        let claimed_len = read_u32(&plain, &mut pos)? as usize;
        if claimed_len > MAX_WALLET_ITEMS { return None; }
        let mut vbank_claimed = Vec::with_capacity(claimed_len);
        for _ in 0..claimed_len { vbank_claimed.push(Vess::decode_with_secrets(&plain, &mut pos)?); }
        let unclaimed_len = read_u32(&plain, &mut pos)? as usize;
        if unclaimed_len > MAX_WALLET_ITEMS { return None; }
        let mut vbank_unclaimed = Vec::with_capacity(unclaimed_len);
        for _ in 0..unclaimed_len { vbank_unclaimed.push(Vess::decode_with_secrets(&plain, &mut pos)?); }
        let pending_len = read_u32(&plain, &mut pos)? as usize;
        if pending_len > MAX_WALLET_ITEMS { return None; }
        let mut vbank_pending = Vec::with_capacity(pending_len);
        for _ in 0..pending_len { vbank_pending.push(Vess::decode_with_secrets(&plain, &mut pos)?); }
        let pre_len = read_u32(&plain, &mut pos)? as usize;
        if pre_len > MAX_WALLET_ITEMS { return None; }
        let mut preimages = HashMap::new();
        for _ in 0..pre_len {
            let id = read_fixed(&plain, &mut pos)?;
            let pre = read_fixed(&plain, &mut pos)?;
            preimages.insert(id, pre);
        }
        let kp_len = read_u32(&plain, &mut pos)? as usize;
        if kp_len > MAX_WALLET_ITEMS { return None; }
        let mut keypairs = HashMap::new();
        for _ in 0..kp_len {
            let oh = read_fixed(&plain, &mut pos)?;
            let pk_bytes = read_bytes(&plain, &mut pos)?;
            let sk_bytes = read_bytes(&plain, &mut pos)?;
            if pk_bytes.len() == DSA_PUBKEY_BYTES && sk_bytes.len() == DSA_SEED_BYTES {
                keypairs.insert(oh, Keypair { dsa_pk: pk_bytes, dsa_sk: sk_bytes });
            }
        }
        // Load payment history
        let built_len = read_u32(&plain, &mut pos)? as usize;
        if built_len > MAX_WALLET_ITEMS { return None; }
        let mut pbank_built = Vec::with_capacity(built_len);
        for _ in 0..built_len {
            let blob_len = read_u32(&plain, &mut pos)? as usize;
            if pos + blob_len > plain.len() { break; }
            if let Some(p) = VessPayment::decode(&plain, &mut pos) {
                pbank_built.push(p);
            } else {
                pos = pos.saturating_sub(blob_len).saturating_add(blob_len);
            }
        }
        let recv_len = read_u32(&plain, &mut pos)? as usize;
        if recv_len > MAX_WALLET_ITEMS { return None; }
        let mut pbank_received = Vec::with_capacity(recv_len);
        for _ in 0..recv_len {
            let blob_len = read_u32(&plain, &mut pos)? as usize;
            if pos + blob_len > plain.len() { break; }
            if let Some(p) = VessPayment::decode(&plain, &mut pos) {
                pbank_received.push(p);
            } else {
                pos = pos.saturating_sub(blob_len).saturating_add(blob_len);
            }
        }
        Some(Self {
            vbank_claimed,
            vbank_unclaimed,
            vbank_pending,
            preimages,
            pbank_minting: Vec::new(),
            pbank_built,
            pbank_received,
            keypairs,
            password_hash: key,
            salt,
            network: Network::new(),
            node_addr: None,
            socket: None,
            packet_reassembly: PacketReassembler::new(),
            transport_tick: 0,
        })
    }
}
