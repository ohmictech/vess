use blake3::Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

// FIPS 204 ML-DSA-65 signatures (RustCrypto ml-dsa). Secret keys are handled
// exclusively as 32-byte seeds — the expanded signing key is re-derived.
use ml_dsa::{
    B32 as DsaSeed, EncodedVerifyingKey as DsaVerifyingKeyBytes, Generate as _, Keypair as _,
    MlDsa65, Signature as DsaSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
};
// FIPS 203 ML-KEM-512 key encapsulation (RustCrypto ml-kem).
use ml_kem::{
    Ciphertext as KemCiphertext, Decapsulate as _, DecapsulationKey, Encapsulate as _,
    EncapsulationKey, Kem as _, KeyExport as _, MlKem512, Seed as KemSeed,
};

pub mod cuckoo;

pub const VESS_ID_V1: &[u8] = b"vess-id-v1";
pub const VESS_AMOUNT_V1: &[u8] = b"vess-amount-v1";
pub const VESS_PAYMENT_V1: &[u8] = b"vess-payment-v1";
pub const VESS_MINT_ID_V1: &[u8] = b"vess-mint-id-v1";
pub const VESS_HEADER_V1: &[u8] = b"VESS_HEADER_V1";
pub const DIFFICULTY_BASE_BITS: u32 = 0;  // start at 0; DAA adjusts upward
pub const MINING_DIFFICULTY: u32 = 10;
pub const DIFFICULTY_WINDOW: usize = 40; // adjust every 40 blocks, matches prune window
pub const MAX_INPUTS: usize = 5;
pub const MAX_OUTPUTS: usize = 5;
pub const MAX_BLOCK_PAYMENTS: usize = 10_000; // decode cap; consensus caps far lower
// Testnet dev fund: blake3 of the ML-DSA-65 pubkey in dev-key-testnet.hex (gitignored).
// pubkey_hash = f2861d4dadd5aa196eb8e5b89869b148a61021b3d3282c17beaf740ab18f511e
pub const DEV_PUBKEY_HASH: OwnerHash = [0xf2, 0x86, 0x1d, 0x4d, 0xad, 0xd5, 0xaa, 0x19, 0x6e, 0xb8, 0xe5, 0xb8, 0x98, 0x69, 0xb1, 0x48, 0xa6, 0x10, 0x21, 0xb3, 0xd3, 0x28, 0x2c, 0x17, 0xbe, 0xaf, 0x74, 0x0a, 0xb1, 0x8f, 0x51, 0x1e];

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

/// Total: never indexes out of bounds — any target_bits > 256 is simply unmet.
pub fn check_difficulty(hash: &[u8; 32], target_bits: u32) -> bool {
    if target_bits > 256 { return false; }
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

/// Block reward: 1 Vess below MINING_DIFFICULTY, doubles each bit beyond.
/// Total: saturates at Amount::MAX past 73 bits instead of overflowing the shift
/// (the ≤60 bits consensus cap lives in vess-node).
pub fn block_reward(difficulty_bits: u32) -> Amount {
    if difficulty_bits < MINING_DIFFICULTY { return 1; }
    if difficulty_bits > 73 { return Amount::MAX; } // 1 << (bits - 10) would overflow u64
    1u64 << (difficulty_bits - MINING_DIFFICULTY) as u32
}

/// Adjust difficulty to target a given block time. Returns new bits.
/// `recent_times`: last N block durations in millis. `target_ms`: desired block time.
pub fn adjust_difficulty(current_bits: u32, recent_times: &[u64], target_ms: u64) -> u32 {
    if recent_times.is_empty() { return current_bits; }
    let avg: f64 = recent_times.iter().sum::<u64>() as f64 / recent_times.len() as f64;
    let next = if avg < target_ms as f64 * 0.75 {
        current_bits + 1  // too fast
    } else if avg > target_ms as f64 * 1.5 {
        current_bits.saturating_sub(1) // too slow
    } else {
        current_bits
    };
    next.min(60)  // cap at 60 to prevent shift overflow in cumulative work
}

pub type Signature = Vec<u8>;
pub type NodeId = [u8; 32];
pub type MerkleRoot = [u8; 32];

/// Copy a fixed-size key/signature array into an owned Vec (AsRef<[u8]> is
/// ambiguous on hybrid-array types, hence the explicit helper).
fn arr_bytes(a: &impl AsRef<[u8]>) -> Vec<u8> {
    a.as_ref().to_vec()
}

// ---- ML-DSA-65 (FIPS 204) ----
//
// Public keys are 1952 bytes, signatures 3309 bytes. The secret key handled by
// this API is always the 32-byte seed; the expanded signing key is re-derived
// from it at signing time.

pub const DSA_PUBKEY_BYTES: usize = 1952;
pub const DSA_SEED_BYTES: usize = 32;
pub const DSA_SIGNATURE_BYTES: usize = 3309;

/// Generate a fresh ML-DSA-65 keypair. Returns (verifying_key bytes, seed bytes).
/// Store the SEED — the full signing key is deterministically re-derived from it.
pub fn dsa_generate() -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::<MlDsa65>::generate();
    let vk = sk.verifying_key();
    (arr_bytes(&vk.encode()), arr_bytes(&sk.to_seed()))
}

/// Derive the verifying key bytes for a 32-byte seed. None if seed length is wrong.
pub fn dsa_public_from_seed(seed: &[u8]) -> Option<Vec<u8>> {
    let seed: [u8; DSA_SEED_BYTES] = seed.try_into().ok()?;
    let sk = SigningKey::<MlDsa65>::from_seed(&DsaSeed::from(seed));
    Some(arr_bytes(&sk.verifying_key().encode()))
}

pub fn dsa_pubkey_hash(pk: &[u8]) -> OwnerHash {
    blake3_hash(pk)
}

/// Sign `message` with the key derived from `seed` (32 bytes).
/// Returns the 3309-byte signature, or None if the seed is malformed.
pub fn dsa_sign(seed: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let seed: [u8; DSA_SEED_BYTES] = seed.try_into().ok()?;
    let sk = SigningKey::<MlDsa65>::from_seed(&DsaSeed::from(seed));
    Some(arr_bytes(&sk.try_sign(message).ok()?.encode()))
}

/// Verify an ML-DSA-65 signature. False on any parse or verify failure — never panics.
pub fn dsa_verify(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let vk = DsaVerifyingKeyBytes::<MlDsa65>::try_from(pk)
        .map(|enc| VerifyingKey::<MlDsa65>::decode(&enc));
    let (Ok(vk), Ok(sig)) = (vk, DsaSignature::<MlDsa65>::try_from(sig)) else { return false; };
    vk.verify(message, &sig).is_ok()
}

/// Node identity: blake3 of the ML-DSA verifying key bytes.
pub fn node_id(pk: &[u8]) -> NodeId {
    blake3_hash(pk)
}

// ---- ML-KEM-512 (FIPS 203) ----
//
// Encapsulation keys are 800 bytes, ciphertexts 768 bytes, shared secrets 32
// bytes. Decapsulation keys are handled as their 64-byte seed serialization.

pub const KEM_PUBKEY_BYTES: usize = 800;
pub const KEM_SEED_BYTES: usize = 64;
pub const KEM_CIPHERTEXT_BYTES: usize = 768;
pub const KEM_SHARED_SECRET_BYTES: usize = 32;

/// Generate a fresh ML-KEM-512 keypair. Returns (encapsulation_key bytes, decapsulation seed bytes).
pub fn kem_generate() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem512::generate_keypair();
    (arr_bytes(&ek.to_bytes()), arr_bytes(&dk.to_bytes()))
}

/// Encapsulate against an untrusted peer encapsulation key. Validates the key;
/// returns (ciphertext, shared_secret) or None if the key is malformed.
pub fn kem_encapsulate(ek_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let enc = ml_kem::Key::<EncapsulationKey<MlKem512>>::try_from(ek_bytes).ok()?;
    let ek = EncapsulationKey::<MlKem512>::new(&enc).ok()?;
    let (ct, ss) = ek.encapsulate();
    Some((arr_bytes(&ct), arr_bytes(&ss)))
}

/// Decapsulate a ciphertext with our decapsulation seed. Returns the shared
/// secret, or None if the ciphertext or seed length is wrong.
pub fn kem_decapsulate(ct_bytes: &[u8], dk_bytes: &[u8]) -> Option<Vec<u8>> {
    let seed = KemSeed::try_from(dk_bytes).ok()?;
    let dk = DecapsulationKey::<MlKem512>::from_seed(seed);
    let ct = KemCiphertext::<MlKem512>::try_from(ct_bytes).ok()?;
    Some(arr_bytes(&dk.decapsulate(&ct)))
}

#[derive(Clone, Debug, PartialEq)]
pub struct SpendCondition {
    pub hashlock: [u8; 32],         // blake3(preimage) must match; [0;32] = no hashlock
    pub expires_at: u64,            // UNIX seconds; output expires, can't spend after; 0 = no expiry
}

impl SpendCondition {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.hashlock);
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8], pos: &mut usize) -> Option<Self> {
        if *pos + 40 > bytes.len() { return None; }
        let hashlock: [u8; 32] = bytes[*pos..*pos+32].try_into().ok()?;
        *pos += 32;
        let expires_at = u64::from_le_bytes(bytes[*pos..*pos+8].try_into().ok()?);
        *pos += 8;
        Some(SpendCondition { hashlock, expires_at })
    }

    /// Returns true if the condition imposes any restriction (hashlock or expiry).
    pub fn is_active(&self) -> bool {
        self.hashlock != [0u8; 32] || self.expires_at != 0
    }
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
    pub spend_key: Vec<u8>,     // 32-byte ML-DSA seed; LOCAL STORAGE ONLY — never on the wire
    pub spend_condition: Option<SpendCondition>,  // optional hashlock + expiry
}

#[derive(Clone, PartialEq, Debug)]
pub enum VessVariant {
    Mint,
    Output,
}

impl Vess {
    pub fn output_vess_id(amount_hash: &AmountHash, owner_hash: &OwnerHash) -> VessId {
        blake3_hash_multi(&[VESS_ID_V1, amount_hash, owner_hash])
    }

    pub fn amount_hash(amount: Amount, salt: &[u8; 32]) -> AmountHash {
        blake3_hash_multi(&[VESS_AMOUNT_V1, &amount.to_le_bytes(), salt])
    }

    /// Canonical VessId — pure function of the Vess' public fields. Mint and
    /// Output both commit to (amount_hash, owner_hash); Mint additionally
    /// commits to (timestamp, nonce). Never touches spend_key.
    pub fn vess_id(&self) -> VessId {
        let ah = Self::amount_hash(self.amount, &self.salt);
        match self.variant {
            VessVariant::Mint => {
                blake3_hash_multi(&[VESS_MINT_ID_V1, &ah, &self.owner_hash,
                    &self.timestamp.to_le_bytes(), &self.nonce.to_le_bytes()])
            }
            VessVariant::Output => {
                // Include spend condition in the output ID if present
                if let Some(ref sc) = self.spend_condition {
                    blake3_hash_multi(&[VESS_ID_V1, &ah, &self.owner_hash, &sc.encode()])
                } else {
                    Self::output_vess_id(&ah, &self.owner_hash)
                }
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
    pub preimages: Vec<Option<[u8; 32]>>,  // hashlock preimage per input; None if no hashlock
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
        self.inputs.iter().fold(0u64, |acc, v| acc.saturating_add(v.amount))
    }

    pub fn output_sum(&self) -> Amount {
        self.outputs.iter().fold(0u64, |acc, v| acc.saturating_add(v.amount))
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
    /// Cuckatoo PoW: exactly cuckoo::CYCLE_LENGTH strictly-ascending nonces.
    /// NOT committed to by header_hash — mining finds the proof for a given header.
    pub proof: Vec<u32>,
    pub coinbase: VessPayment,
    pub payments: Vec<VessPayment>,
}

impl VessBlock {
    /// Header commitment: version, parents, timestamp, difficulty, nonce and
    /// both merkle roots — but NOT the proof (mining varies the proof for a
    /// fixed header) and NOT the body (committed via payment_merkle).
    pub fn header_hash(&self) -> BlockHash {
        let mut pre = Vec::new();
        pre.extend_from_slice(VESS_HEADER_V1);
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
        write_u32(&mut buf, self.proof.len() as u32);
        for &n in &self.proof { write_u32(&mut buf, n); }
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
        // A block proof is exactly CYCLE_LENGTH nonces — nothing else is a block.
        let proof_len = read_u32(bytes, pos)? as usize;
        if proof_len != cuckoo::CYCLE_LENGTH { return None; }
        let mut proof = Vec::with_capacity(cuckoo::CYCLE_LENGTH);
        for _ in 0..proof_len { proof.push(read_u32(bytes, pos)?); }
        let coinbase = VessPayment::decode(bytes, pos)?;
        let pay_len = read_u32(bytes, pos)? as usize;
        if pay_len > MAX_BLOCK_PAYMENTS { return None; }
        let mut payments = Vec::with_capacity(pay_len);
        for _ in 0..pay_len { payments.push(VessPayment::decode(bytes, pos)?); }
        Some(VessBlock { version, parents, timestamp, difficulty_bits, nonce, payment_merkle, state_merkle, proof, coinbase, payments })
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
    /// Canonical wire/consensus encoding. Secrets are NEVER serialized here —
    /// spend_key is local-only key material (see encode_with_secrets).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_u8(&mut buf, if self.variant == VessVariant::Mint { 0 } else { 1 });
        write_u64(&mut buf, self.amount);
        write_fixed(&mut buf, &self.owner_hash);
        write_u64(&mut buf, self.timestamp);
        write_u64(&mut buf, self.nonce);
        write_fixed(&mut buf, &self.salt);
        write_bytes(&mut buf, &self.pubkey);
        // Spend condition: 1 byte discriminant + optional 40 bytes
        if let Some(ref sc) = self.spend_condition {
            write_u8(&mut buf, 1);
            buf.extend_from_slice(&sc.encode());
        } else {
            write_u8(&mut buf, 0);
        }
        buf
    }

    /// Local-storage encoding: canonical form + spend key seed.
    /// Used ONLY for local key stores (node mined_keys table, wallet file).
    pub fn encode_with_secrets(&self) -> Vec<u8> {
        let mut buf = self.encode();
        write_bytes(&mut buf, &self.spend_key);
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
        let spend_condition = match read_u8(bytes, pos)? {
            1 => SpendCondition::decode(bytes, pos),
            _ => None,
        };
        Some(Vess { variant, amount, owner_hash, timestamp, nonce, salt, pubkey, spend_key: Vec::new(), spend_condition })
    }

    /// Decode the local-storage form written by encode_with_secrets.
    pub fn decode_with_secrets(bytes: &[u8], pos: &mut usize) -> Option<Self> {
        let mut v = Self::decode(bytes, pos)?;
        v.spend_key = read_bytes(bytes, pos)?;
        Some(v)
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
        // Preimages: exactly one per input (0=none, 1=present) + 32 bytes if present
        for i in 0..self.inputs.len() {
            match self.preimages.get(i).and_then(|pi| pi.as_ref()) {
                Some(preimage) => {
                    write_u8(&mut buf, 1);
                    buf.extend_from_slice(preimage);
                }
                None => write_u8(&mut buf, 0),
            }
        }
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
        if sig_len > MAX_INPUTS { return None; } // never pre-allocate from untrusted lengths
        let mut sigs = Vec::with_capacity(sig_len);
        for _ in 0..sig_len { sigs.push(read_bytes(bytes, pos)?); }
        // Preimages: one per input
        let mut preimages = Vec::with_capacity(inputs.len());
        for _ in 0..inputs.len() {
            preimages.push(match read_u8(bytes, pos)? {
                1 => {
                    if *pos + 32 > bytes.len() { return None; }
                    let pi: [u8; 32] = bytes[*pos..*pos+32].try_into().ok()?;
                    *pos += 32;
                    Some(pi)
                }
                _ => None,
            });
        }
        Some(VessPayment { payment_id, inputs, outputs, timestamp, sigs, preimages })
    }
}

pub fn merkle_root(items: &[[u8; 32]]) -> [u8; 32] {
    if items.is_empty() { return [0u8; 32]; }
    merkle_root_stream(items.iter().copied())
}

/// Streaming Merkle root — O(log N) memory, processes items in order.
pub fn merkle_root_stream<I: IntoIterator<Item = [u8; 32]>>(items: I) -> [u8; 32] {
    let mut stack: Vec<([u8; 32], u32)> = Vec::new(); // (hash, height)
    let mut count = 0u64;
    for item in items {
        let mut current = item;
        let mut height = 0u32;
        while let Some(&(top, h)) = stack.last() {
            if h != height { break; }
            stack.pop();
            current = blake3_hash_multi(&[&top, &current]);
            height += 1;
        }
        stack.push((current, height));
        count += 1;
    }
    if count == 0 { return [0u8; 32]; }
    while stack.len() > 1 {
        let (right, _) = stack.pop().unwrap();
        let (left, _) = stack.pop().unwrap();
        stack.push((blake3_hash_multi(&[&left, &right]), 0));
    }
    stack[0].0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_payment() -> VessPayment {
        let (_, seed) = dsa_generate();
        let input = Vess {
            variant: VessVariant::Output, amount: 5, owner_hash: [1u8; 32],
            timestamp: 0, nonce: 0, salt: [2u8; 32],
            pubkey: Vec::new(), spend_key: seed, spend_condition: None,
        };
        let output = Vess {
            variant: VessVariant::Output, amount: 5, owner_hash: [3u8; 32],
            timestamp: 0, nonce: 0, salt: [4u8; 32],
            pubkey: Vec::new(), spend_key: Vec::new(), spend_condition: None,
        };
        let mut p = VessPayment {
            payment_id: [0u8; 32], inputs: vec![input], outputs: vec![output],
            timestamp: 0, sigs: Vec::new(), preimages: Vec::new(),
        };
        p.compute();
        p
    }

    #[test]
    fn test_dsa_roundtrip() {
        let (pk, seed) = dsa_generate();
        assert_eq!(pk.len(), DSA_PUBKEY_BYTES);
        assert_eq!(seed.len(), DSA_SEED_BYTES);
        assert_eq!(dsa_public_from_seed(&seed).unwrap(), pk, "seed must re-derive the same pubkey");
        let sig = dsa_sign(&seed, b"hello").expect("signing with a valid seed works");
        assert_eq!(sig.len(), DSA_SIGNATURE_BYTES);
        assert!(dsa_verify(&pk, b"hello", &sig));
        assert!(!dsa_verify(&pk, b"HELLO", &sig), "wrong message rejected");
        let (pk2, _) = dsa_generate();
        assert!(!dsa_verify(&pk2, b"hello", &sig), "wrong key rejected");
    }

    #[test]
    fn test_dsa_verify_never_panics_on_garbage() {
        let (pk, seed) = dsa_generate();
        let sig = dsa_sign(&seed, b"m").unwrap();
        assert!(!dsa_verify(&[], b"m", &sig));
        assert!(!dsa_verify(&pk[..17], b"m", &sig));
        assert!(!dsa_verify(&pk, b"m", &[]));
        assert!(!dsa_verify(&pk, b"m", &sig[..100]));
        assert!(!dsa_verify(&[0xAB; DSA_PUBKEY_BYTES], b"m", &sig));
        assert!(dsa_sign(&[0u8; 31], b"m").is_none(), "short seed rejected");
        assert!(dsa_sign(&[], b"m").is_none());
    }

    #[test]
    fn test_kem_roundtrip() {
        let (ek, dk) = kem_generate();
        assert_eq!(ek.len(), KEM_PUBKEY_BYTES);
        assert_eq!(dk.len(), KEM_SEED_BYTES);
        let (ct, ss) = kem_encapsulate(&ek).expect("valid ek encapsulates");
        assert_eq!(ct.len(), KEM_CIPHERTEXT_BYTES);
        assert_eq!(ss.len(), KEM_SHARED_SECRET_BYTES);
        assert_eq!(kem_decapsulate(&ct, &dk).unwrap(), ss, "shared secrets match");
        assert!(kem_encapsulate(&ek[..100]).is_none(), "truncated ek rejected");
        assert!(kem_decapsulate(&ct[..100], &dk).is_none(), "truncated ct rejected");
        assert!(kem_decapsulate(&ct, &dk[..32]).is_none(), "truncated dk rejected");
        // Tampered ciphertext: implicit rejection yields a DIFFERENT secret, never a panic.
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert_ne!(kem_decapsulate(&bad_ct, &dk).unwrap(), ss);
    }

    #[test]
    fn test_vess_wire_excludes_spend_key() {
        let (_, seed) = dsa_generate();
        let v = Vess {
            variant: VessVariant::Output, amount: 7, owner_hash: [9u8; 32],
            timestamp: 0, nonce: 0, salt: [8u8; 32],
            pubkey: vec![1, 2, 3], spend_key: seed.clone(), spend_condition: None,
        };
        let wire = v.encode();
        // The 32-byte seed must not appear in the canonical encoding.
        assert!(wire.windows(DSA_SEED_BYTES).all(|w| w != seed.as_slice()),
            "spend_key must never be in the wire encoding");
        let mut pos = 0;
        let decoded = Vess::decode(&wire, &mut pos).unwrap();
        assert!(decoded.spend_key.is_empty(), "decode leaves spend_key empty");
        assert_eq!(decoded.vess_id(), v.vess_id(), "id is a function of public fields only");
        // Local-storage form round-trips the seed.
        let mut pos = 0;
        let restored = Vess::decode_with_secrets(&v.encode_with_secrets(), &mut pos).unwrap();
        assert_eq!(restored.spend_key, seed);
    }

    #[test]
    fn test_mint_vess_id_stable() {
        // Mint ids come from normal fields — identical twice, distinct on any field change.
        let m = Vess {
            variant: VessVariant::Mint, amount: 10, owner_hash: [1u8; 32],
            timestamp: 42, nonce: 0, salt: [7u8; 32],
            pubkey: Vec::new(), spend_key: Vec::new(), spend_condition: None,
        };
        assert_eq!(m.vess_id(), m.vess_id());
        let mut m2 = m.clone();
        m2.salt[0] ^= 1;
        assert_ne!(m.vess_id(), m2.vess_id());
        let mut m3 = m.clone();
        m3.timestamp += 1;
        assert_ne!(m.vess_id(), m3.vess_id());
        let mut m4 = m.clone();
        m4.spend_key = vec![0xFF; 32];
        assert_eq!(m.vess_id(), m4.vess_id(), "spend_key never enters the id");
    }

    #[test]
    fn test_payment_preimage_encode_symmetric() {
        // Encode writes exactly inputs.len() preimage slots even if preimages is short.
        let mut p = test_payment();
        p.inputs.push(p.inputs[0].clone());
        p.preimages = vec![None]; // shorter than inputs
        let enc = p.encode();
        let mut pos = 0;
        let decoded = VessPayment::decode(&enc, &mut pos).unwrap();
        assert_eq!(decoded.preimages.len(), decoded.inputs.len());
        assert_eq!(pos, enc.len(), "encode/decode fully symmetric");
    }

    #[test]
    fn test_payment_decode_sig_count_capped() {
        // A huge sig count must fail fast, not pre-allocate.
        let p = test_payment();
        let mut enc = p.encode();
        // Layout: payment_id(32) || ts(8) || in_len(4)+inputs || out_len(4)+outputs || sig_len(4)
        let inputs_end = 32 + 8 + 4 + p.inputs[0].encode().len();
        let sig_len_off = inputs_end + 4 + p.outputs[0].encode().len();
        enc.truncate(sig_len_off);
        enc.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut pos = 0;
        assert!(VessPayment::decode(&enc, &mut pos).is_none(), "huge sig_len rejected");
    }

    #[test]
    fn test_block_proof_wire_rules() {
        let (pk, seed) = dsa_generate();
        let cb_out = Vess {
            variant: VessVariant::Mint, amount: 1, owner_hash: dsa_pubkey_hash(&pk),
            timestamp: 1, nonce: 0, salt: [5u8; 32],
            pubkey: pk, spend_key: seed, spend_condition: None,
        };
        let mut coinbase = VessPayment {
            payment_id: [0u8; 32], inputs: vec![], outputs: vec![cb_out],
            timestamp: 0, sigs: vec![], preimages: vec![],
        };
        coinbase.compute();
        let block = VessBlock {
            version: 1, parents: vec![], timestamp: 1, difficulty_bits: 2, nonce: 0,
            payment_merkle: merkle_root(&[coinbase.payment_id]), state_merkle: [0u8; 32],
            proof: (0..cuckoo::CYCLE_LENGTH as u32).collect(), coinbase, payments: vec![],
        };
        let enc = block.encode();
        let mut pos = 0;
        let decoded = VessBlock::decode(&enc, &mut pos).unwrap();
        assert_eq!(decoded.proof, block.proof);
        assert_eq!(decoded.header_hash(), block.header_hash());
        assert_eq!(pos, enc.len());

        // header_hash must NOT commit to the proof
        let mut other = block.clone();
        other.proof = (0..cuckoo::CYCLE_LENGTH as u32).map(|n| n + 100).collect();
        assert_eq!(other.header_hash(), block.header_hash());

        // Any proof length other than CYCLE_LENGTH is rejected at decode
        let mut bad = block.clone();
        bad.proof = vec![0u32; cuckoo::CYCLE_LENGTH - 1];
        let enc = bad.encode();
        let mut pos = 0;
        assert!(VessBlock::decode(&enc, &mut pos).is_none());
        let mut bad2 = block.clone();
        bad2.proof = Vec::new();
        let enc = bad2.encode();
        let mut pos = 0;
        assert!(VessBlock::decode(&enc, &mut pos).is_none());
    }

    #[test]
    fn test_block_payments_count_capped() {
        let p = test_payment();
        let coinbase = p.clone();
        let block = VessBlock {
            version: 1, parents: vec![], timestamp: 1, difficulty_bits: 2, nonce: 0,
            payment_merkle: [0u8; 32], state_merkle: [0u8; 32],
            proof: vec![0u32; cuckoo::CYCLE_LENGTH], coinbase, payments: vec![p],
        };
        let mut enc = block.encode();
        // Truncate everything after the payments count and inflate it.
        let fixed = 4 + 1 + 8 + 4 + 8 + 32 + 32 + 4 + cuckoo::CYCLE_LENGTH * 4;
        let tail = block.coinbase.encode().len();
        enc.truncate(fixed + tail);
        enc.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut pos = 0;
        assert!(VessBlock::decode(&enc, &mut pos).is_none(), "huge payment count rejected");
    }

    #[test]
    fn test_check_difficulty_bounds() {
        let zero = [0u8; 32];
        assert!(check_difficulty(&zero, 0));
        assert!(check_difficulty(&zero, 255));
        assert!(check_difficulty(&zero, 256));
        assert!(!check_difficulty(&zero, 257), "out-of-range target is simply unmet");
        assert!(!check_difficulty(&zero, u32::MAX));
        let mut h = [0u8; 32];
        h[31] = 1;
        assert!(check_difficulty(&h, 255));
        assert!(!check_difficulty(&h, 256));
        h[0] = 0x80;
        assert!(!check_difficulty(&h, 1));
    }

    #[test]
    fn test_block_reward_bounds() {
        assert_eq!(block_reward(0), 1);
        assert_eq!(block_reward(MINING_DIFFICULTY - 1), 1);
        assert_eq!(block_reward(MINING_DIFFICULTY), 1);
        assert_eq!(block_reward(MINING_DIFFICULTY + 1), 2);
        assert_eq!(block_reward(73), 1u64 << 63);
        assert_eq!(block_reward(74), Amount::MAX, "saturates instead of overflowing");
        assert_eq!(block_reward(u32::MAX), Amount::MAX);
    }
}
