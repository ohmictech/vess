use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

pub mod cuckoo;

pub const VESS_ID_V1: &[u8] = b"vess-id-v1";
pub const VESS_AMOUNT_V1: &[u8] = b"vess-amount-v1";
pub const VESS_PAYMENT_V1: &[u8] = b"vess-payment-v1";
pub const DIFFICULTY_BASE_BITS: u32 = 0;  // 1 Vess at diff=0, doubling each bit: 1→2→4→8...
pub const DIFFICULTY_WINDOW: usize = 10; // adjust every 10 blocks (~10s at 1s target)
pub const MAX_INPUTS: usize = 5;
pub const MAX_OUTPUTS: usize = 5;
pub const DEV_PUBKEY_HASH: OwnerHash = [0u8; 32]; // TODO: replace with real dev pubkey hash

/// Dev subsidy: 1% of block reward, minimum 1 Vess.
pub fn dev_reward(miner_reward: Amount) -> Amount {
    (miner_reward / 100).max(1)
}
pub const DANDELION_MAX_STEM: u8 = 4;
pub const DANDELION_BUFFER_MS: u64 = 200;
pub const DIFFICULTY_TEST_BITS: u32 = 2;

pub type Amount = u64;
pub type VessId = [u8; 32];
pub type OwnerHash = [u8; 32];
pub type AmountHash = [u8; 32];
pub type PaymentId = [u8; 32];

pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize().into()
}

pub fn blake3_hash_multi(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn argon2id_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use argon2::Argon2;
    let a = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2::Params::new(65536, 3, 1, None).unwrap());
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt, &mut out).unwrap();
    out
}

pub fn chacha_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).unwrap()
}

pub fn chacha_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext).ok()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn check_difficulty(hash: &[u8; 32], target_bits: u32) -> bool {
    let full_bytes = (target_bits / 8) as usize;
    let rem_bits = target_bits % 8;
    for i in 0..full_bytes {
        if hash[i] != 0 {
            return false;
        }
    }
    if rem_bits > 0 {
        hash[full_bytes] >> (8 - rem_bits) == 0
    } else {
        true
    }
}

pub fn required_difficulty(amount: Amount) -> u32 {
    if amount == 0 { return 0; }
    DIFFICULTY_BASE_BITS + amount.ilog2()
}

/// Block reward: 1 Vess at diff=0, doubles each bit: 0→1, 1→2, 2→4, 3→8...
pub fn block_reward(difficulty_bits: u32) -> Amount {
    1u64 << difficulty_bits as u32
}

/// Adjust difficulty to target a given block time. Returns new bits.
/// `recent_times`: last N block durations in millis. `target_ms`: desired block time.
pub fn adjust_difficulty(current_bits: u32, recent_times: &[u64], target_ms: u64) -> u32 {
    if recent_times.is_empty() { return current_bits; }
    let avg: f64 = recent_times.iter().sum::<u64>() as f64 / recent_times.len() as f64;
    if avg < target_ms as f64 * 0.75 { return current_bits + 1; }  // too fast
    if avg > target_ms as f64 * 1.5  { return current_bits.saturating_sub(1); } // too slow
    current_bits
}

/// Deterministic VessId for a dev subsidy mint (no PoW proof needed).
pub fn dev_mint_vess_id(amount: Amount, owner_hash: &OwnerHash, timestamp: u64) -> VessId {
    blake3_hash_multi(&[b"vess-dev-mint", &amount.to_le_bytes(), owner_hash, &timestamp.to_le_bytes()])
}

pub use pqcrypto_dilithium::dilithium3;
pub use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};

pub type Signature = Vec<u8>;
pub type NodeId = [u8; 32];
pub type MerkleRoot = [u8; 32];

pub fn dsa_generate() -> (dilithium3::PublicKey, dilithium3::SecretKey) {
    dilithium3::keypair()
}

pub fn dsa_pubkey_hash(pk: &dilithium3::PublicKey) -> OwnerHash {
    blake3_hash(pk.as_bytes())
}

pub fn dsa_sign(sk: &dilithium3::SecretKey, message: &[u8]) -> Vec<u8> {
    dilithium3::detached_sign(message, sk).as_bytes().to_vec()
}

pub fn dsa_verify(pk: &dilithium3::PublicKey, message: &[u8], sig: &[u8]) -> bool {
    dilithium3::DetachedSignature::from_bytes(sig)
        .map(|s| dilithium3::verify_detached_signature(&s, message, pk).is_ok())
        .unwrap_or(false)
}

pub fn kem_generate() -> (kyber512::PublicKey, kyber512::SecretKey) {
    kyber512::keypair()
}

pub fn kem_encapsulate(pk: &kyber512::PublicKey) -> (Vec<u8>, Vec<u8>) {
    let (ss, ct) = kyber512::encapsulate(pk);
    (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
}

pub fn kem_decapsulate(ct: &[u8], sk: &kyber512::SecretKey) -> Option<Vec<u8>> {
    kyber512::Ciphertext::from_bytes(ct)
        .map(|c| kyber512::decapsulate(&c, sk).as_bytes().to_vec())
        .ok()
}

#[derive(Clone, Debug)]
pub struct Vess {
    pub variant: VessVariant,
    pub amount: Amount,
    pub owner_hash: OwnerHash,
    pub timestamp: u64,         // Unix timestamp for mint TTL; 0 for outputs
    pub nonce: u64,
    pub salt: [u8; 32],
    pub pubkey: Vec<u8>,
    pub spend_key: Vec<u8>,
    pub proof: Vec<u32>,        // cuckatoo proof: 42 sorted nonces for Mint, empty for Output
}

#[derive(Clone, PartialEq, Debug)]
pub enum VessVariant {
    Mint,
    Output,
}

impl Vess {
    pub fn mint_vess_id_from_proof(proof: &[u32]) -> VessId {
        cuckoo::proof_to_id(proof)
    }

    pub fn mint_header_hash(amount: Amount, owner_hash: &OwnerHash, timestamp: u64, nonce: u64) -> [u8; 32] {
        cuckoo::mint_header(amount, owner_hash, timestamp, nonce)
    }

    pub fn output_vess_id(amount_hash: &AmountHash, owner_hash: &OwnerHash) -> VessId {
        blake3_hash_multi(&[VESS_ID_V1, amount_hash, owner_hash])
    }

    pub fn amount_hash(amount: Amount, salt: &[u8; 32]) -> AmountHash {
        blake3_hash_multi(&[VESS_AMOUNT_V1, &amount.to_le_bytes(), salt])
    }

    pub fn vess_id(&self) -> VessId {
        match self.variant {
            VessVariant::Mint => {
                if self.proof.is_empty() {
                    // Dev subsidy — deterministic ID from (amount, owner_hash, timestamp)
                    dev_mint_vess_id(self.amount, &self.owner_hash, self.timestamp)
                } else {
                    Self::mint_vess_id_from_proof(&self.proof)
                }
            }
            VessVariant::Output => {
                let ah = Self::amount_hash(self.amount, &self.salt);
                Self::output_vess_id(&ah, &self.owner_hash)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct VessPayment {
    pub payment_id: PaymentId,
    pub inputs: Vec<Vess>,
    pub outputs: Vec<Vess>,
    pub timestamp: u64,         // Unix timestamp for mint TTL; 0 for transfers
    pub sigs: Vec<Signature>,
}

impl VessPayment {
    pub fn compute_payment_id(timestamp: u64, input_ids: &[VessId], output_ids: &[VessId]) -> PaymentId {
        let ts_bytes = timestamp.to_le_bytes();
        let mut parts: Vec<&[u8]> = vec![VESS_PAYMENT_V1, &ts_bytes];
        let id_refs: Vec<&[u8]> = input_ids.iter().map(|id| id.as_slice()).chain(output_ids.iter().map(|id| id.as_slice())).collect();
        parts.extend(&id_refs);
        blake3_hash_multi(&parts)
    }

    pub fn compute(&mut self) {
        let in_ids: Vec<VessId> = self.inputs.iter().map(|v| v.vess_id()).collect();
        let out_ids: Vec<VessId> = self.outputs.iter().map(|v| v.vess_id()).collect();
        self.payment_id = Self::compute_payment_id(self.timestamp, &in_ids, &out_ids);
    }

    pub fn input_sum(&self) -> Amount {
        self.inputs.iter().map(|v| v.amount).sum()
    }

    pub fn output_sum(&self) -> Amount {
        self.outputs.iter().map(|v| v.amount).sum()
    }

    pub fn is_mint(&self) -> bool {
        self.inputs.is_empty() && self.outputs.len() == 1 && self.outputs[0].variant == VessVariant::Mint
    }
}

// ---- VessBlock: DAG-based data consensus ----

pub type BlockHash = [u8; 32];

#[derive(Clone, Debug)]
pub struct VessBlock {
    pub version: u32,
    pub parents: Vec<BlockHash>,
    pub timestamp: u64,
    pub difficulty_bits: u32,
    pub nonce: u64,
    pub payment_merkle: MerkleRoot,
    pub state_merkle: MerkleRoot,
    pub coinbase: VessPayment,
    pub payments: Vec<VessPayment>,
}

impl VessBlock {
    pub fn header_hash(&self) -> BlockHash {
        let mut pre = Vec::new();
        pre.extend_from_slice(&self.version.to_le_bytes());
        pre.push(self.parents.len() as u8);
        for p in &self.parents {
            pre.extend_from_slice(p);
        }
        pre.extend_from_slice(&self.timestamp.to_le_bytes());
        pre.extend_from_slice(&self.difficulty_bits.to_le_bytes());
        pre.extend_from_slice(&self.nonce.to_le_bytes());
        pre.extend_from_slice(&self.payment_merkle);
        pre.extend_from_slice(&self.state_merkle);
        blake3_hash(&pre)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_u32(&mut buf, self.version);
        write_u8(&mut buf, self.parents.len() as u8);
        for p in &self.parents { write_fixed(&mut buf, p); }
        write_u64(&mut buf, self.timestamp);
        write_u32(&mut buf, self.difficulty_bits);
        write_u64(&mut buf, self.nonce);
        write_fixed(&mut buf, &self.payment_merkle);
        write_fixed(&mut buf, &self.state_merkle);
        buf.extend_from_slice(&self.coinbase.encode());
        write_u32(&mut buf, self.payments.len() as u32);
        for p in &self.payments { buf.extend_from_slice(&p.encode()); }
        buf
    }

    pub fn decode(bytes: &[u8], pos: &mut usize) -> Option<Self> {
        let version = read_u32(bytes, pos)?;
        let parent_count = read_u8(bytes, pos)? as usize;
        let mut parents = Vec::with_capacity(parent_count);
        for _ in 0..parent_count { parents.push(read_fixed(bytes, pos)?); }
        let timestamp = read_u64(bytes, pos)?;
        let difficulty_bits = read_u32(bytes, pos)?;
        let nonce = read_u64(bytes, pos)?;
        let payment_merkle = read_fixed(bytes, pos)?;
        let state_merkle = read_fixed(bytes, pos)?;
        let coinbase = VessPayment::decode(bytes, pos)?;
        let pay_len = read_u32(bytes, pos)? as usize;
        let mut payments = Vec::with_capacity(pay_len);
        for _ in 0..pay_len { payments.push(VessPayment::decode(bytes, pos)?); }
        Some(VessBlock { version, parents, timestamp, difficulty_bits, nonce, payment_merkle, state_merkle, coinbase, payments })
    }
}

pub fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

pub fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    write_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

pub fn write_fixed<const N: usize>(buf: &mut Vec<u8>, data: &[u8; N]) {
    buf.extend_from_slice(data);
}

pub fn read_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > bytes.len() { return None; }
    let v = u64::from_le_bytes(bytes[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Some(v)
}

pub fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > bytes.len() { return None; }
    let v = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Some(v)
}

pub fn read_u8(bytes: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos >= bytes.len() { return None; }
    let v = bytes[*pos];
    *pos += 1;
    Some(v)
}

pub fn read_bytes(bytes: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = read_u32(bytes, pos)? as usize;
    if *pos + len > bytes.len() { return None; }
    let v = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Some(v)
}

pub fn read_fixed<const N: usize>(bytes: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    if *pos + N > bytes.len() { return None; }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;
    Some(arr)
}

impl Vess {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_u8(&mut buf, if self.variant == VessVariant::Mint { 0 } else { 1 });
        write_u64(&mut buf, self.amount);
        write_fixed(&mut buf, &self.owner_hash);
        write_u64(&mut buf, self.timestamp);
        write_u64(&mut buf, self.nonce);
        write_fixed(&mut buf, &self.salt);
        write_bytes(&mut buf, &self.pubkey);
        write_bytes(&mut buf, &self.spend_key);
        write_u32(&mut buf, self.proof.len() as u32);
        for &n in &self.proof { write_u32(&mut buf, n); }
        buf
    }

    pub fn decode(bytes: &[u8], pos: &mut usize) -> Option<Self> {
        let variant = match read_u8(bytes, pos)? { 0 => VessVariant::Mint, _ => VessVariant::Output };
        let amount = read_u64(bytes, pos)?;
        let owner_hash = read_fixed(bytes, pos)?;
        let timestamp = read_u64(bytes, pos)?;
        let nonce = read_u64(bytes, pos)?;
        let salt = read_fixed(bytes, pos)?;
        let pubkey = read_bytes(bytes, pos)?;
        let spend_key = read_bytes(bytes, pos)?;
        let proof_len = read_u32(bytes, pos)? as usize;
        let mut proof = Vec::with_capacity(proof_len);
        for _ in 0..proof_len { proof.push(read_u32(bytes, pos)?); }
        Some(Vess { variant, amount, owner_hash, timestamp, nonce, salt, pubkey, spend_key, proof })
    }
}

impl VessPayment {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_fixed(&mut buf, &self.payment_id);
        write_u64(&mut buf, self.timestamp);
        write_u32(&mut buf, self.inputs.len() as u32);
        for v in &self.inputs { buf.extend_from_slice(&v.encode()); }
        write_u32(&mut buf, self.outputs.len() as u32);
        for v in &self.outputs { buf.extend_from_slice(&v.encode()); }
        write_u32(&mut buf, self.sigs.len() as u32);
        for s in &self.sigs { write_bytes(&mut buf, s); }
        buf
    }

    pub fn decode(bytes: &[u8], pos: &mut usize) -> Option<Self> {
        let payment_id = read_fixed(bytes, pos)?;
        let timestamp = read_u64(bytes, pos)?;
        let in_len = read_u32(bytes, pos)? as usize;
        let mut inputs = Vec::with_capacity(in_len.min(MAX_INPUTS));
        for _ in 0..in_len { inputs.push(Vess::decode(bytes, pos)?); }
        let out_len = read_u32(bytes, pos)? as usize;
        let mut outputs = Vec::with_capacity(out_len.min(MAX_OUTPUTS));
        for _ in 0..out_len { outputs.push(Vess::decode(bytes, pos)?); }
        let sig_len = read_u32(bytes, pos)? as usize;
        let mut sigs = Vec::with_capacity(sig_len);
        for _ in 0..sig_len { sigs.push(read_bytes(bytes, pos)?); }
        Some(VessPayment { payment_id, inputs, outputs, timestamp, sigs })
    }
}

pub fn merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    if items.is_empty() { return [0u8; 32]; }
    let mut layer: Vec<[u8; 32]> = items.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for pair in layer.chunks(2) {
            let h = if pair.len() == 2 {
                blake3_hash_multi(&[&pair[0], &pair[1]])
            } else {
                blake3_hash_multi(&[&pair[0], &pair[0]])
            };
            next.push(h);
        }
        layer = next;
    }
    layer[0]
}

pub fn node_id(pk: &dilithium3::PublicKey) -> NodeId {
    blake3_hash(pk.as_bytes())
}
