use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use vess_crypto::*;
use vess_network::{unframe, Network, RpcRequest, RpcResponse, HANDSHAKE_RESP, HANDSHAKE_INIT, frame, ENCRYPTED_DATA};

mod ffi;

const RPC_TIMEOUT_MS: u64 = 5000;

struct Keypair {
    dsa_pk: dilithium3::PublicKey,
    dsa_sk: dilithium3::SecretKey,
}

pub struct Wallet {
    pub vbank_claimed: Vec<Vess>,
    pub vbank_unclaimed: Vec<Vess>,
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
}

impl Wallet {
    pub fn new(password: &[u8]) -> Self {
        let salt = random_bytes::<32>();
        let key = argon2id_key(password, &salt);
        Self {
            vbank_claimed: Vec::new(), vbank_unclaimed: Vec::new(),
            pbank_minting: Vec::new(), pbank_built: Vec::new(), pbank_received: Vec::new(),
            keypairs: HashMap::new(),
            password_hash: key, salt,
            network: Network::new(),
            node_addr: None, socket: None,
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

        let socket = match &self.socket { Some(s) => s, None => return false };
        if socket.send_to(&init_with_pow, addr).is_err() { return false; }
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        let mut buf = [0u8; 65536];
        match socket.recv_from(&mut buf) {
            Ok((len, _src)) => self.handshake_complete(&buf[..len]),
            Err(_) => false,
        }
    }

    fn call_rpc(&mut self, req: RpcRequest) -> Option<RpcResponse> {
        let addr = self.node_addr?;
        let socket = self.socket.as_ref()?;
        let session = self.network.session_by_addr_mut(&addr)?;
        let plain = req.encode();
        let encrypted = session.encrypt(&plain);
        let framed = frame(ENCRYPTED_DATA, &encrypted);
        if socket.send_to(&framed, addr).is_err() { return None; }
        // Switch to non-blocking to drain gossip quickly
        socket.set_nonblocking(true).ok()?;
        let mut buf = [0u8; 65536];
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(RPC_TIMEOUT_MS);
        let len = loop {
            if std::time::Instant::now() >= deadline {
                let _ = socket.set_nonblocking(false);
                return None;
            }
            let (len, _) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(_) => { let _ = socket.set_nonblocking(false); return None; },
            };
            // Skip gossip (framed ENCRYPTED_DATA) from the node
            if len >= 5 && buf[0] == ENCRYPTED_DATA {
                let frame_len = u32::from_le_bytes(buf[1..5].try_into().unwrap()) as usize;
                if len == 5 + frame_len { continue; }
            }
            break len;
        };
        let _ = socket.set_nonblocking(false);
        let plain = session.decrypt(&buf[..len])?;
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
                pubkey: Vec::new(), spend_key: Vec::new(), proof: vec![],
                spend_condition: sc.clone() }
        }).collect();

        if change > 0 {
            let (pk, sk) = dsa_generate();
            let oh = dsa_pubkey_hash(&pk);
            self.keypairs.insert(oh, Keypair { dsa_pk: pk, dsa_sk: sk });
            out_vess.push(Vess { variant: VessVariant::Output, amount: change, owner_hash: oh, timestamp: 0, nonce: 0, salt: random_bytes(), pubkey: Vec::new(), spend_key: Vec::new(), proof: vec![], spend_condition: None });
        }

        let preimage_count = selected.len();
        let mut payment = VessPayment { payment_id: [0u8; 32], inputs: selected, outputs: out_vess, timestamp: 0, sigs: Vec::new(), preimages: vec![None; preimage_count] };
        payment.compute();

        for v in &payment.inputs {
            if let Some(kp) = self.keypairs.get(&v.owner_hash) {
                payment.sigs.push(dsa_sign(&kp.dsa_sk, &payment.payment_id));
            }
        }
        self.pbank_built.push(payment.clone());
        Some(payment)
    }

    /// Build and encode a payment for OOB delivery — returns the raw bytes to hand off.
    /// Does NOT submit to the network. The receiver calls `claim_payment` to submit.
    pub fn export_payment(&mut self, outputs: &[(OwnerHash, Amount, Option<SpendCondition>)]) -> Option<Vec<u8>> {
        let payment = self.build_payment(outputs)?;
        Some(payment.encode())
    }

    pub fn send(&mut self, payment: &VessPayment) -> bool {
        if !self.submit_payment(payment).unwrap_or(false) { return false; }
        for v in &payment.inputs {
            let id = v.vess_id();
            self.vbank_claimed.retain(|x| x.vess_id() != id);
            self.vbank_unclaimed.retain(|x| x.vess_id() != id);
        }
        for v in &payment.outputs {
            if let Some(kp) = self.keypairs.get(&v.owner_hash) {
                let mut owned = v.clone();
                owned.pubkey = kp.dsa_pk.as_bytes().to_vec();
                owned.spend_key = kp.dsa_sk.as_bytes().to_vec();
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
                owned.pubkey = kp.dsa_pk.as_bytes().to_vec();
                owned.spend_key = kp.dsa_sk.as_bytes().to_vec();
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

    pub fn receive(&mut self, payment: VessPayment) {
        for v in &payment.outputs {
            if let Some(kp) = self.keypairs.get(&v.owner_hash) {
                let mut owned = v.clone();
                owned.pubkey = kp.dsa_pk.as_bytes().to_vec();
                owned.spend_key = kp.dsa_sk.as_bytes().to_vec();
                self.vbank_unclaimed.push(owned);
            }
        }
        self.pbank_received.push(payment);
    }

    /// Import a payment blob from raw bytes (OOB receive path — no node needed).
    /// Returns Some(output_count) on success, None if the blob is invalid.
    pub fn receive_blob(&mut self, data: &[u8]) -> Option<usize> {
        let mut pos = 0;
        let payment = VessPayment::decode(data, &mut pos)?;
        let count = payment.outputs.iter()
            .filter(|v| self.keypairs.contains_key(&v.owner_hash))
            .count();
        self.receive(payment);
        Some(count)
    }

    /// Sync unclaimed outputs against the node: check each via RPC and move
    /// confirmed ones to vbank_claimed. Returns (moved, remaining).
    pub fn sync(&mut self) -> (usize, usize) {
        let ids: Vec<VessId> = self.vbank_unclaimed.iter().map(|v| v.vess_id()).collect();
        let mut moved = 0usize;
        for id in &ids {
            if self.check(id).unwrap_or(false) {
                // Confirmed on-chain — move from unclaimed to claimed
                if let Some(pos) = self.vbank_unclaimed.iter().position(|v| &v.vess_id() == id) {
                    let v = self.vbank_unclaimed.remove(pos);
                    self.vbank_claimed.push(v);
                    moved += 1;
                }
            }
        }
        (moved, self.vbank_unclaimed.len())
    }

    /// Import a keypair from raw bytes. Returns the owner_hash for UTXO lookup.
    pub fn import_keypair(&mut self, pubkey_bytes: &[u8], seckey_bytes: &[u8]) -> Option<OwnerHash> {
        let pk = dilithium3::PublicKey::from_bytes(pubkey_bytes).ok()?;
        let sk = dilithium3::SecretKey::from_bytes(seckey_bytes).ok()?;
        let oh = dsa_pubkey_hash(&pk);
        self.keypairs.insert(oh, Keypair { dsa_pk: pk, dsa_sk: sk });
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
                    if let Some(v) = Vess::decode(&bytes, &mut 0) {
                        if v.variant == VessVariant::Mint {
                            if !known.contains(&v.vess_id()) {
                                // Must be unspent in the UTXO set
                                if vess_db.get(&t, &v.vess_id()).ok().flatten().is_none() {
                                    continue; // already spent, skip
                                }
                                // Extract keypair from Vess or use stored keypair (for dev outputs)
                                if !v.pubkey.is_empty() {
                                    if let (Ok(pk), Ok(sk)) = (
                                        dilithium3::PublicKey::from_bytes(&v.pubkey),
                                        dilithium3::SecretKey::from_bytes(&v.spend_key)
                                    ) {
                                        self.keypairs.entry(v.owner_hash).or_insert(Keypair { dsa_pk: pk, dsa_sk: sk });
                                    }
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
        for v in &self.vbank_claimed { plain.extend(&v.encode()); }
        write_u32(&mut plain, self.vbank_unclaimed.len() as u32);
        for v in &self.vbank_unclaimed { plain.extend(&v.encode()); }
        write_u32(&mut plain, self.keypairs.len() as u32);
        for (oh, kp) in &self.keypairs {
            write_fixed(&mut plain, oh);
            write_bytes(&mut plain, kp.dsa_pk.as_bytes());
            write_bytes(&mut plain, kp.dsa_sk.as_bytes());
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
        // Format: nonce(12) || salt(32) || ciphertext
        let mut out = nonce.to_vec();
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&ct);
        out
    }

    pub fn load(data: &[u8], password: &[u8]) -> Option<Self> {
        if data.len() < 44 { return None; }
        let nonce: [u8; 12] = data[..12].try_into().ok()?;
        let salt: [u8; 32] = data[12..44].try_into().ok()?;
        let key = argon2id_key(password, &salt);
        let plain = chacha_decrypt(&key, &nonce, &data[44..])?;
        let mut pos = 0;
        let claimed_len = read_u32(&plain, &mut pos)? as usize;
        let mut vbank_claimed = Vec::with_capacity(claimed_len);
        for _ in 0..claimed_len { vbank_claimed.push(Vess::decode(&plain, &mut pos)?); }
        let unclaimed_len = read_u32(&plain, &mut pos)? as usize;
        let mut vbank_unclaimed = Vec::with_capacity(unclaimed_len);
        for _ in 0..unclaimed_len { vbank_unclaimed.push(Vess::decode(&plain, &mut pos)?); }
        let kp_len = read_u32(&plain, &mut pos)? as usize;
        let mut keypairs = HashMap::new();
        for _ in 0..kp_len {
            let oh = read_fixed(&plain, &mut pos)?;
            let pk_bytes = read_bytes(&plain, &mut pos)?;
            let sk_bytes = read_bytes(&plain, &mut pos)?;
            if let (Ok(dsa_pk), Ok(dsa_sk)) = (
                dilithium3::PublicKey::from_bytes(&pk_bytes),
                dilithium3::SecretKey::from_bytes(&sk_bytes),
            ) {
                keypairs.insert(oh, Keypair { dsa_pk, dsa_sk });
            }
        }
        // Load payment history
        let built_len = read_u32(&plain, &mut pos)? as usize;
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
            pbank_minting: Vec::new(),
            pbank_built,
            pbank_received,
            keypairs,
            password_hash: key,
            salt,
            network: Network::new(),
            node_addr: None,
            socket: None,
        })
    }
}
