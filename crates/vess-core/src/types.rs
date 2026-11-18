//! Consensus objects. Encodings here are byte-for-byte normative.

use core::fmt;

use crate::codec::{Decode, Encode, Reader, Writer};
use crate::constants::{
    AUTHORITY_RULES, AUTHORITY_SIGNATURE, BLOCK_HEADER_BYTES, ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES,
    PREIMAGE_BYTES, PROTOCOL_VERSION, RULES_BYTES, TRANSACTION_VERSION,
    TRANSACTION_VERSION_PAYLOAD, TX_PAYLOAD_BYTES,
};
use crate::error::CodecError;
use crate::hash;
use crate::u256::U256;

pub type Hash = [u8; 32];
pub type AccountId = [u8; 32];
pub type PublicKey = [u8; ML_DSA_PK_BYTES];
pub type Signature = [u8; ML_DSA_SIG_BYTES];

pub const TRANSACTION_KIND_TRANSFER: u8 = 1;
pub const TRANSACTION_KIND_STATE_UPDATE: u8 = 2;

/// Whether a transaction at `version` is valid under this protocol. Transaction version is separate
/// from the block/network protocol version: version 3 transactions predate the payload field and
/// version 5 replaced the mandatory sender key with an authority union, so all of them are accepted.
pub fn transaction_version_supported(version: u16) -> bool {
    version == PROTOCOL_VERSION
        || version == TRANSACTION_VERSION_PAYLOAD
        || version == TRANSACTION_VERSION
}

// ----------------------------------------------------------------- account

/// One account holding the single native asset, `Vess`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Account {
    pub next_nonce: u64,
    pub balance: u64,
    pub state_hash: Hash,
}

impl Account {
    /// The committed leaf value: `balance || nonce || state_hash`, 48 bytes.
    pub fn leaf_value(&self) -> [u8; 48] {
        let mut w = Writer::with_capacity(48);
        w.u64(self.balance);
        w.u64(self.next_nonce);
        w.fixed(&self.state_hash);
        let mut out = [0u8; 48];
        out.copy_from_slice(w.as_slice());
        out
    }
}

impl Encode for Account {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.next_nonce);
        w.u64(self.balance);
        w.fixed(&self.state_hash);
    }
}

impl Decode for Account {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Account {
            next_nonce: r.u64()?,
            balance: r.u64()?,
            state_hash: r.array()?,
        })
    }
}

// ---------------------------------------------------------------- transfer

/// The spend condition of an escrow account.
///
/// An escrow is not a special account type: its account id is `hash::rules_account_id(canonical)`,
/// which no key hashes to, so the only way to spend it is to reveal these rules. The rules are
/// therefore self-verifying — revealing them proves the account, and they name both destinations, so
/// a submitter can never redirect the funds.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rules {
    /// [`RULES_VERSION`]. Consensus rejects any other value.
    pub version: u8,
    /// `BLAKE3(preimage)`; the claim path needs the secret.
    pub hash_lock: Hash,
    /// First height at which the owner path opens. Claims are valid strictly below it.
    pub refund_height: u64,
    /// Destination before [`Self::refund_height`], once the preimage is revealed.
    pub recipient_account_id: AccountId,
    /// Destination at or after [`Self::refund_height`]. Never the submitter's choice.
    pub owner_account_id: AccountId,
    /// Ceiling on the fee a submitter may charge against the balance.
    pub max_fee: u64,
}

impl Rules {
    /// The exact bytes the account id commits to.
    pub fn canonical(&self) -> [u8; RULES_BYTES] {
        let mut w = Writer::with_capacity(RULES_BYTES);
        w.u8(self.version);
        w.fixed(&self.hash_lock);
        w.u64(self.refund_height);
        w.fixed(&self.recipient_account_id);
        w.fixed(&self.owner_account_id);
        w.u64(self.max_fee);
        let bytes = w.into_vec();
        debug_assert_eq!(bytes.len(), RULES_BYTES);
        let mut out = [0u8; RULES_BYTES];
        out.copy_from_slice(&bytes);
        out
    }

    pub fn account_id(&self) -> AccountId {
        hash::rules_account_id(&self.canonical())
    }

    /// True while the claim path is open at `height`.
    pub fn claims_open_at(&self, height: u64) -> bool {
        height < self.refund_height
    }
}

impl Encode for Rules {
    fn encode(&self, w: &mut Writer) {
        w.bytes(&self.canonical());
    }
}

impl Decode for Rules {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Rules {
            version: r.u8()?,
            hash_lock: r.array()?,
            refund_height: r.u64()?,
            recipient_account_id: r.array()?,
            owner_account_id: r.array()?,
            max_fee: r.u64()?,
        })
    }
}

/// Who authorises a transfer.
#[derive(Clone, PartialEq, Eq)]
pub enum TransferAuthority {
    /// The ordinary path: the sender's key signed the unsigned body.
    Signature {
        sender_public_key: PublicKey,
        signature: Signature,
    },
    /// An escrow spend: the debited account is [`Rules::account_id`], and the revealed rules decide
    /// where the balance may go. `preimage` is `Some` only for a claim.
    Rules {
        rules: Rules,
        preimage: Option<[u8; PREIMAGE_BYTES]>,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct Transfer {
    pub version: u16,
    pub chain_id: Hash,
    pub recipient_account_id: AccountId,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    /// Unix seconds; zero disables expiry.
    pub expiry_unix: u64,
    /// Optional 32-byte application payload (a memo, tag, or commitment). It is signed and covered
    /// by the transaction id. Only transactions at [`TRANSACTION_VERSION_PAYLOAD`] or later carry
    /// the field; older versions encode no payload at all and must leave this `None`.
    pub payload: Option<[u8; TX_PAYLOAD_BYTES]>,
    pub authority: TransferAuthority,
}

impl fmt::Debug for Transfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Transfer");
        d.field("sender", &hex(&self.sender_id()))
            .field("recipient", &hex(&self.recipient_account_id))
            .field("amount", &self.amount)
            .field("fee", &self.fee)
            .field("nonce", &self.nonce)
            .field("expiry_unix", &self.expiry_unix)
            .field("payload", &self.payload.as_ref().map(hex));
        if let TransferAuthority::Rules { rules, preimage } = &self.authority {
            d.field("hash_lock", &hex(&rules.hash_lock))
                .field("refund_height", &rules.refund_height)
                .field("owner", &hex(&rules.owner_account_id))
                .field("max_fee", &rules.max_fee)
                .field("preimage", &preimage.is_some());
        }
        d.finish()
    }
}

impl Transfer {
    /// Every field except the signature.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut w =
            Writer::with_capacity(2 + 32 + ML_DSA_PK_BYTES + 32 + 8 * 4 + 1 + TX_PAYLOAD_BYTES);
        w.u16(self.version);
        w.fixed(&self.chain_id);
        if self.version >= TRANSACTION_VERSION {
            self.authority.encode_into(&mut w);
        } else if let TransferAuthority::Signature {
            sender_public_key, ..
        } = &self.authority
        {
            w.fixed(sender_public_key);
        } else {
            debug_assert!(false, "a rules authority requires a version 5 transfer");
        }
        w.fixed(&self.recipient_account_id);
        w.u64(self.amount);
        w.u64(self.fee);
        w.u64(self.nonce);
        w.u64(self.expiry_unix);
        if self.version >= TRANSACTION_VERSION_PAYLOAD {
            match &self.payload {
                Some(payload) => {
                    w.u8(1);
                    w.fixed(payload);
                }
                None => w.u8(0),
            }
        }
        debug_assert!(self.version >= TRANSACTION_VERSION_PAYLOAD || self.payload.is_none());
        w.into_vec()
    }

    /// The account this transfer debits: a key-derived account, or the rules' escrow account.
    pub fn sender_id(&self) -> AccountId {
        match &self.authority {
            TransferAuthority::Signature {
                sender_public_key, ..
            } => hash::account_id(sender_public_key),
            TransferAuthority::Rules { rules, .. } => rules.account_id(),
        }
    }

    pub fn sender_public_key(&self) -> Option<&PublicKey> {
        match &self.authority {
            TransferAuthority::Signature {
                sender_public_key, ..
            } => Some(sender_public_key),
            TransferAuthority::Rules { .. } => None,
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        match &self.authority {
            TransferAuthority::Signature { signature, .. } => Some(signature),
            TransferAuthority::Rules { .. } => None,
        }
    }

    /// The rules of an escrow spend, if this is one.
    pub fn rules(&self) -> Option<&Rules> {
        match &self.authority {
            TransferAuthority::Rules { rules, .. } => Some(rules),
            TransferAuthority::Signature { .. } => None,
        }
    }

    pub fn preimage(&self) -> Option<&[u8; PREIMAGE_BYTES]> {
        match &self.authority {
            TransferAuthority::Rules { preimage, .. } => preimage.as_ref(),
            TransferAuthority::Signature { .. } => None,
        }
    }

    pub fn tx_id(&self) -> Hash {
        hash::transaction_id(TRANSACTION_KIND_TRANSFER, &self.unsigned_bytes())
    }
}

impl TransferAuthority {
    fn encode_into(&self, w: &mut Writer) {
        match self {
            TransferAuthority::Signature {
                sender_public_key, ..
            } => {
                w.u8(AUTHORITY_SIGNATURE);
                w.fixed(sender_public_key);
            }
            TransferAuthority::Rules { rules, preimage } => {
                w.u8(AUTHORITY_RULES);
                rules.encode(w);
                match preimage {
                    Some(preimage) => {
                        w.u8(1);
                        w.fixed(preimage);
                    }
                    None => w.u8(0),
                }
            }
        }
    }
}

impl Encode for Transfer {
    fn encode(&self, w: &mut Writer) {
        w.bytes(&self.unsigned_bytes());
        if let TransferAuthority::Signature { signature, .. } = &self.authority {
            w.fixed(signature);
        }
    }
}

impl Decode for Transfer {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        enum Head {
            Key(PublicKey),
            Rules(Rules),
        }

        let version = r.u16()?;
        let chain_id = r.array()?;
        let head = if version >= TRANSACTION_VERSION {
            match r.u8()? {
                AUTHORITY_SIGNATURE => Head::Key(r.array()?),
                AUTHORITY_RULES => Head::Rules(Rules::decode(r)?),
                _ => return Err(CodecError::InvalidValue),
            }
        } else {
            Head::Key(r.array()?)
        };
        let recipient_account_id = r.array()?;
        let amount = r.u64()?;
        let fee = r.u64()?;
        let nonce = r.u64()?;
        let expiry_unix = r.u64()?;
        let payload = if version >= TRANSACTION_VERSION_PAYLOAD {
            match r.u8()? {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(CodecError::InvalidValue),
            }
        } else {
            None
        };
        let authority = match head {
            Head::Key(sender_public_key) => {
                let signature = r.array()?;
                TransferAuthority::Signature {
                    sender_public_key,
                    signature,
                }
            }
            Head::Rules(rules) => {
                let preimage = match r.u8()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(CodecError::InvalidValue),
                };
                TransferAuthority::Rules { rules, preimage }
            }
        };
        Ok(Transfer {
            version,
            chain_id,
            recipient_account_id,
            amount,
            fee,
            nonce,
            expiry_unix,
            payload,
            authority,
        })
    }
}

// ------------------------------------------------------------ state update

#[derive(Clone, PartialEq, Eq)]
pub struct StateUpdate {
    pub version: u16,
    pub chain_id: Hash,
    pub sender_public_key: PublicKey,
    pub new_state_hash: Hash,
    pub fee: u64,
    pub nonce: u64,
    /// Unix seconds; zero disables expiry.
    pub expiry_unix: u64,
    pub signature: Signature,
}

impl fmt::Debug for StateUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateUpdate")
            .field("sender", &hex(&self.sender_id()))
            .field("new_state_hash", &hex(&self.new_state_hash))
            .field("fee", &self.fee)
            .field("nonce", &self.nonce)
            .field("expiry_unix", &self.expiry_unix)
            .finish()
    }
}

impl StateUpdate {
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(2 + 32 + ML_DSA_PK_BYTES + 32 + 8 * 3);
        w.u16(self.version);
        w.fixed(&self.chain_id);
        w.fixed(&self.sender_public_key);
        w.fixed(&self.new_state_hash);
        w.u64(self.fee);
        w.u64(self.nonce);
        w.u64(self.expiry_unix);
        w.into_vec()
    }

    pub fn sender_id(&self) -> AccountId {
        hash::account_id(&self.sender_public_key)
    }

    pub fn tx_id(&self) -> Hash {
        hash::transaction_id(TRANSACTION_KIND_STATE_UPDATE, &self.unsigned_bytes())
    }
}

impl Encode for StateUpdate {
    fn encode(&self, w: &mut Writer) {
        w.bytes(&self.unsigned_bytes());
        w.fixed(&self.signature);
    }
}

impl Decode for StateUpdate {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(StateUpdate {
            version: r.u16()?,
            chain_id: r.array()?,
            sender_public_key: r.array()?,
            new_state_hash: r.array()?,
            fee: r.u64()?,
            nonce: r.u64()?,
            expiry_unix: r.u64()?,
            signature: r.array()?,
        })
    }
}

// ------------------------------------------------------------- transaction

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
    Transfer(Transfer),
    StateUpdate(StateUpdate),
}

impl Transaction {
    pub fn kind(&self) -> u8 {
        match self {
            Transaction::Transfer(_) => TRANSACTION_KIND_TRANSFER,
            Transaction::StateUpdate(_) => TRANSACTION_KIND_STATE_UPDATE,
        }
    }

    pub fn encode_into(&self, w: &mut Writer) {
        w.u8(self.kind());
        match self {
            Transaction::Transfer(t) => t.encode(w),
            Transaction::StateUpdate(s) => s.encode(w),
        }
    }

    pub fn canonical(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_into(&mut w);
        w.into_vec()
    }

    pub fn decode_from(r: &mut Reader<'_>, max_bytes: usize) -> Result<Self, CodecError> {
        let start = r.position();
        let kind = r.u8()?;
        let tx = match kind {
            TRANSACTION_KIND_TRANSFER => Transaction::Transfer(Transfer::decode(r)?),
            TRANSACTION_KIND_STATE_UPDATE => Transaction::StateUpdate(StateUpdate::decode(r)?),
            _ => return Err(CodecError::UnknownVersion),
        };
        if r.position() - start > max_bytes {
            return Err(CodecError::LengthTooLarge);
        }
        Ok(tx)
    }

    pub fn id(&self) -> Hash {
        match self {
            Transaction::Transfer(t) => t.tx_id(),
            Transaction::StateUpdate(s) => s.tx_id(),
        }
    }
}

// ------------------------------------------------------------------ block

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u16,
    pub chain_id: Hash,
    pub previous_block_id: Hash,
    pub transaction_root: Hash,
    pub state_root: Hash,
    /// Unix time in milliseconds.
    pub timestamp_unix_ms: u64,
    pub target: U256,
    pub payout_account_id: AccountId,
    pub security_nonce: [u8; 32],
}

impl BlockHeader {
    pub fn canonical(&self) -> [u8; BLOCK_HEADER_BYTES] {
        let mut w = Writer::with_capacity(BLOCK_HEADER_BYTES);
        w.u16(self.version);
        w.fixed(&self.chain_id);
        w.fixed(&self.previous_block_id);
        w.fixed(&self.transaction_root);
        w.fixed(&self.state_root);
        w.u64(self.timestamp_unix_ms);
        w.fixed(&self.target.to_be_bytes());
        w.fixed(&self.payout_account_id);
        w.fixed(&self.security_nonce);
        let bytes = w.into_vec();
        debug_assert_eq!(bytes.len(), BLOCK_HEADER_BYTES);
        let mut out = [0u8; BLOCK_HEADER_BYTES];
        out.copy_from_slice(&bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != BLOCK_HEADER_BYTES {
            return Err(CodecError::Truncated);
        }
        let mut r = Reader::new(bytes);
        let header = BlockHeader {
            version: r.u16()?,
            chain_id: r.array()?,
            previous_block_id: r.array()?,
            transaction_root: r.array()?,
            state_root: r.array()?,
            timestamp_unix_ms: r.u64()?,
            target: U256::from_be_bytes(r.array()?),
            payout_account_id: r.array()?,
            security_nonce: r.array()?,
        };
        r.finish()?;
        Ok(header)
    }

    pub fn id(&self) -> Hash {
        hash::block_id(&self.canonical())
    }

    pub fn pow_hash(&self) -> Hash {
        hash::pow_hash(&self.canonical())
    }

    /// `BLAKE3(domain || header) <= target`, compared as unsigned 256-bit integers.
    pub fn meets_target(&self) -> bool {
        U256::from_be_bytes(self.pow_hash()) <= self.target
    }
}

fn hex(bytes: &Hash) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_bytes, to_bytes};
    use crate::constants::{
        MAX_TRANSACTION_BYTES, PROTOCOL_VERSION, TRANSACTION_VERSION, TX_PAYLOAD_BYTES,
    };

    fn sample_transfer(signature_byte: u8) -> Transfer {
        Transfer {
            version: TRANSACTION_VERSION,
            chain_id: [9u8; 32],
            sender_public_key: [3u8; ML_DSA_PK_BYTES],
            recipient_account_id: [4u8; 32],
            amount: 42,
            fee: 7,
            nonce: 5,
            expiry_unix: 0,
            payload: None,
            signature: [signature_byte; ML_DSA_SIG_BYTES],
        }
    }

    #[test]
    fn account_leaf_value_layout() {
        let account = Account {
            next_nonce: 1,
            balance: 3,
            state_hash: [8u8; 32],
        };
        let v = account.leaf_value();
        assert_eq!(v.len(), 48);
        assert_eq!(&v[..8], &3u64.to_be_bytes());
        assert_eq!(&v[8..16], &1u64.to_be_bytes());
        assert_eq!(&v[16..], &[8u8; 32]);
    }

    #[test]
    fn account_codec_roundtrip() {
        let account = Account {
            next_nonce: 9,
            balance: 13,
            state_hash: [2u8; 32],
        };
        let bytes = to_bytes(&account);
        assert_eq!(bytes.len(), 48);
        assert_eq!(from_bytes::<Account>(&bytes).unwrap(), account);
    }

    #[test]
    fn transfer_roundtrip_and_size() {
        let tx = sample_transfer(1);
        let bytes = to_bytes(&tx);
        assert_eq!(bytes.len(), 2 + 32 + 1952 + 32 + 32 + 1 + 3309);
        assert!(bytes.len() < MAX_TRANSACTION_BYTES);
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), tx);

        let with_payload = Transfer {
            payload: Some([0xABu8; TX_PAYLOAD_BYTES]),
            ..sample_transfer(1)
        };
        let bytes = to_bytes(&with_payload);
        assert_eq!(
            bytes.len(),
            2 + 32 + 1952 + 32 + 32 + 1 + TX_PAYLOAD_BYTES + 3309
        );
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), with_payload);
    }

    #[test]
    fn version_three_transfers_keep_their_original_bytes() {
        let legacy = Transfer {
            version: PROTOCOL_VERSION,
            payload: None,
            ..sample_transfer(1)
        };
        let bytes = to_bytes(&legacy);
        assert_eq!(bytes.len(), 2 + 32 + 1952 + 32 + 32 + 3309);
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), legacy);
        assert!(transaction_version_supported(PROTOCOL_VERSION));
        assert!(transaction_version_supported(TRANSACTION_VERSION));
        assert!(!transaction_version_supported(TRANSACTION_VERSION + 1));
    }

    #[test]
    fn payload_is_signed_and_bound_by_the_id() {
        let base = sample_transfer(1);
        let with_payload = Transfer {
            payload: Some([1u8; TX_PAYLOAD_BYTES]),
            ..base.clone()
        };
        assert_ne!(with_payload.tx_id(), base.tx_id());
        assert_ne!(with_payload.unsigned_bytes(), base.unsigned_bytes());

        let other_payload = Transfer {
            payload: Some([2u8; TX_PAYLOAD_BYTES]),
            ..base
        };
        assert_ne!(other_payload.tx_id(), with_payload.tx_id());
    }

    #[test]
    fn an_invalid_payload_presence_byte_is_rejected() {
        let mut bytes = to_bytes(&sample_transfer(1));
        // The presence byte sits right after version, chain id, key, recipient, amount, fee, nonce
        // and expiry.
        bytes[2 + 32 + ML_DSA_PK_BYTES + 32 + 8 * 4] = 2;
        assert_eq!(
            from_bytes::<Transfer>(&bytes),
            Err(CodecError::InvalidValue)
        );
    }

    #[test]
    fn tx_id_ignores_the_signature() {
        let a = sample_transfer(1);
        let b = sample_transfer(2);
        assert_ne!(a.signature, b.signature);
        assert_eq!(a.tx_id(), b.tx_id());
    }

    #[test]
    fn tx_id_binds_every_field() {
        let base = sample_transfer(1);
        let id = base.tx_id();

        let mut other = base.clone();
        other.amount += 1;
        assert_ne!(other.tx_id(), id);

        let mut other = base.clone();
        other.fee += 1;
        assert_ne!(other.tx_id(), id);

        let mut other = base.clone();
        other.nonce += 1;
        assert_ne!(other.tx_id(), id);

        let mut other = base.clone();
        other.expiry_unix = 1;
        assert_ne!(other.tx_id(), id);

        let mut other = base.clone();
        other.recipient_account_id = [5u8; 32];
        assert_ne!(other.tx_id(), id);

        let mut other = base.clone();
        other.chain_id = [10u8; 32];
        assert_ne!(other.tx_id(), id);
    }

    #[test]
    fn unknown_transaction_kind_is_rejected() {
        let mut w = Writer::new();
        w.u8(9);
        let bytes = w.into_vec();
        let mut r = Reader::new(&bytes);
        assert_eq!(
            Transaction::decode_from(&mut r, MAX_TRANSACTION_BYTES),
            Err(CodecError::UnknownVersion)
        );
    }

    #[test]
    fn block_header_is_exactly_234_bytes_and_roundtrips() {
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            chain_id: [1u8; 32],
            previous_block_id: [2u8; 32],
            transaction_root: [3u8; 32],
            state_root: [4u8; 32],
            timestamp_unix_ms: 1_700_000_005,
            target: U256::pow2(226),
            payout_account_id: [5u8; 32],
            security_nonce: [6u8; 32],
        };
        let bytes = header.canonical();
        assert_eq!(bytes.len(), 234);
        assert_eq!(BlockHeader::decode(&bytes).unwrap(), header);
        assert_eq!(header.id(), hash::block_id(&bytes));
        assert_ne!(header.id(), header.pow_hash());
    }

    #[test]
    fn header_decode_rejects_wrong_length() {
        assert_eq!(BlockHeader::decode(&[0u8; 233]), Err(CodecError::Truncated));
        assert_eq!(BlockHeader::decode(&[0u8; 235]), Err(CodecError::Truncated));
    }

    #[test]
    fn pow_comparison_is_against_the_target() {
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            chain_id: [1u8; 32],
            previous_block_id: [2u8; 32],
            transaction_root: [3u8; 32],
            state_root: [4u8; 32],
            timestamp_unix_ms: 1_700_000_005,
            target: U256::MAX,
            payout_account_id: [5u8; 32],
            security_nonce: [6u8; 32],
        };
        assert!(header.meets_target());

        let impossible = BlockHeader {
            target: U256::ZERO,
            ..header
        };
        assert!(!impossible.meets_target());
    }

    fn sample_account() -> Account {
        Account {
            next_nonce: 2,
            balance: 1_003,
            state_hash: [7u8; 32],
        }
    }

    fn sample_state_update() -> StateUpdate {
        StateUpdate {
            version: PROTOCOL_VERSION,
            chain_id: [9u8; 32],
            sender_public_key: [3u8; ML_DSA_PK_BYTES],
            new_state_hash: [5u8; 32],
            fee: 3,
            nonce: 1,
            expiry_unix: 0,
            signature: [2u8; ML_DSA_SIG_BYTES],
        }
    }

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: PROTOCOL_VERSION,
            chain_id: [1u8; 32],
            previous_block_id: [2u8; 32],
            transaction_root: [3u8; 32],
            state_root: [4u8; 32],
            timestamp_unix_ms: 1_700_000_005,
            target: U256::from_u64(1 << 40),
            payout_account_id: [5u8; 32],
            security_nonce: [6u8; 32],
        }
    }

    /// Every decoder must reject corrupt input, never panic on it.
    ///
    /// This stands in for a fuzzing harness: truncation at every length, single-byte corruption at
    /// a stride, and a deterministic multi-byte corruption pass. A decoder that panics is a
    /// remotely triggerable crash, because every one of these types arrives from a peer.
    fn sweep_decoder(name: &str, bytes: &[u8], decode: &dyn Fn(&[u8])) {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        for length in 0..bytes.len() {
            let outcome = catch_unwind(AssertUnwindSafe(|| decode(&bytes[..length])));
            assert!(outcome.is_ok(), "{name} panicked on {length} bytes");
        }

        let stride = (bytes.len() / 512).max(1);
        for index in (0..bytes.len()).step_by(stride) {
            for delta in [0x01u8, 0x80, 0xFF] {
                let mut mutated = bytes.to_vec();
                mutated[index] ^= delta;
                let outcome = catch_unwind(AssertUnwindSafe(|| decode(&mutated)));
                assert!(
                    outcome.is_ok(),
                    "{name} panicked on byte {index} ^ {delta:#04x}"
                );
            }
        }

        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..256 {
            let mut mutated = bytes.to_vec();
            for _ in 0..8 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let index = (seed as usize) % mutated.len();
                mutated[index] = (seed >> 40) as u8;
            }
            let outcome = catch_unwind(AssertUnwindSafe(|| decode(&mutated)));
            assert!(outcome.is_ok(), "{name} panicked on a corrupted copy");
        }
    }

    #[test]
    fn decoders_never_panic_on_corrupt_input() {
        sweep_decoder("Transfer", &to_bytes(&sample_transfer(1)), &|bytes| {
            let _ = from_bytes::<Transfer>(bytes);
        });
        sweep_decoder("StateUpdate", &to_bytes(&sample_state_update()), &|bytes| {
            let _ = from_bytes::<StateUpdate>(bytes);
        });
        sweep_decoder("Account", &to_bytes(&sample_account()), &|bytes| {
            let _ = from_bytes::<Account>(bytes);
        });
        sweep_decoder("BlockHeader", &sample_header().canonical(), &|bytes| {
            let _ = BlockHeader::decode(bytes);
        });
        // The envelope that carries all of the above.
        sweep_decoder(
            "Transaction",
            &Transaction::Transfer(sample_transfer(1)).canonical(),
            &|bytes| {
                let mut reader = Reader::new(bytes);
                let _ = Transaction::decode_from(&mut reader, MAX_TRANSACTION_BYTES);
            },
        );
    }
}
