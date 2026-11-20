//! Consensus objects. Encodings here are byte-for-byte normative.

use core::fmt;

use crate::codec::{Decode, Encode, Reader, Writer};
use crate::constants::{
    AUTHORITY_FUTURES, AUTHORITY_RULES, AUTHORITY_SIGNATURE, BLOCK_HEADER_BYTES, DEPTH,
    FUTURES_RULES_BYTES, MAX_TARGET_DELTA, MAX_TRANSFER_INPUTS, MAX_TRANSFER_OUTPUTS,
    ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES, PREIMAGE_BYTES, PROTOCOL_VERSION, RULES_BYTES,
    TRANSACTION_VERSION, TRANSACTION_VERSION_JOINT, TRANSACTION_VERSION_PAYLOAD, TX_PAYLOAD_BYTES,
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
pub const TRANSACTION_KIND_JOINT_TRANSFER: u8 = 3;

/// Whether a transaction at `version` is valid under this protocol. Transaction version is separate
/// from the block/network protocol version: version 3 transactions predate the payload field, version
/// 5 replaced the mandatory sender key with an authority union, and version 6 carries several inputs
/// and outputs, so all of them are accepted.
pub fn transaction_version_supported(version: u16) -> bool {
    version == PROTOCOL_VERSION
        || version == TRANSACTION_VERSION_PAYLOAD
        || version == TRANSACTION_VERSION
        || version == TRANSACTION_VERSION_JOINT
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

// --------------------------------------------------------------- futures

/// The terms of a fully collateralized future on the total supply delta.
///
/// Like [`Rules`], this is not a special account type: the pot's account id is
/// [`Self::account_id`], which no key hashes to, so the only way to spend it is to reveal these
/// terms. Both parties fund the pot in one jointly signed transaction, and at or after
/// [`Self::earliest_settle_height`] anyone may submit the settlement, which pays `recipient` and
/// `owner` a split that consensus computes from the measured supply delta:
///
/// ```text
/// delta     = supply - start_supply
/// recipient = (pot - fee) * min(delta, 2 * target_delta) / (2 * target_delta)
/// owner     = (pot - fee) - recipient
/// ```
///
/// At `delta == target_delta` the two sides receive exactly half the pot, which is the fair strike
/// when both parties posted equal collateral. The submitter names neither destination nor amount.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FuturesRules {
    /// [`crate::constants::RULES_VERSION_FUTURES`]. Consensus rejects any other value.
    pub version: u8,
    /// The supply the parties agreed to measure from.
    ///
    /// Not chain-verified: the account id commits to these bytes and both parties sign the funding
    /// transaction, so a wrong value is a bad price rather than a theft. A value above the real
    /// supply clamps the measured delta to zero.
    pub start_supply: u64,
    /// The supply delta at which the pot splits evenly. Non-zero, and at most
    /// [`crate::constants::MAX_TARGET_DELTA`].
    pub target_delta: u64,
    /// First height at which the settlement may be applied.
    ///
    /// The measurement reads the state as of the settlement, so a later settlement sees a larger
    /// delta. Supply only grows, so that drift is bounded by emission over the delay and never moves
    /// against the party it would flatter.
    pub earliest_settle_height: u64,
    /// Paid when the measured delta exceeds the strike.
    pub recipient_account_id: AccountId,
    /// Paid when it falls short. Never the submitter's choice.
    pub owner_account_id: AccountId,
    /// Ceiling on the fee a submitter may charge against the pot.
    pub max_fee: u64,
}

impl FuturesRules {
    /// The exact bytes the pot's account id commits to.
    pub fn canonical(&self) -> [u8; FUTURES_RULES_BYTES] {
        let mut w = Writer::with_capacity(FUTURES_RULES_BYTES);
        w.u8(self.version);
        w.u64(self.start_supply);
        w.u64(self.target_delta);
        w.u64(self.earliest_settle_height);
        w.fixed(&self.recipient_account_id);
        w.fixed(&self.owner_account_id);
        w.u64(self.max_fee);
        let bytes = w.into_vec();
        debug_assert_eq!(bytes.len(), FUTURES_RULES_BYTES);
        let mut out = [0u8; FUTURES_RULES_BYTES];
        out.copy_from_slice(&bytes);
        out
    }

    pub fn account_id(&self) -> AccountId {
        hash::futures_account_id(&self.canonical())
    }

    /// True once the settlement path is open at `height`.
    pub fn settle_open_at(&self, height: u64) -> bool {
        height >= self.earliest_settle_height
    }

    /// The pot split at `supply`: `(owner, recipient)`, whose sum is exactly `pot`.
    ///
    /// ```text
    /// delta     = supply - start_supply                  (saturating at zero)
    /// recipient = pot * min(delta, 2 * target_delta) / (2 * target_delta)
    /// owner     = pot - recipient
    /// ```
    ///
    /// Linear in the delta and clamped at both ends, so each share is always within `[0, pot]` and
    /// the contract is fully collateralized by construction: neither side can owe more than it posted.
    /// At `delta == target_delta` the two sides receive exactly half, which is the fair strike when
    /// both parties posted equal collateral.
    ///
    /// `None` when the terms are unusable. Consensus and wallets both call this, so there is one
    /// definition of the payoff rather than two that can drift.
    pub fn split(&self, pot: u64, supply: u128) -> Option<(u64, u64)> {
        if self.target_delta == 0 || self.target_delta > MAX_TARGET_DELTA {
            return None;
        }
        let max_delta = (self.target_delta as u128) * 2;
        let delta = supply.saturating_sub(self.start_supply as u128);
        let numerator = delta.min(max_delta);
        let scaled = (pot as u128).checked_mul(numerator)?;
        let recipient = (scaled / max_delta) as u64;
        Some((pot - recipient, recipient))
    }
}

impl fmt::Debug for FuturesRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FuturesRules")
            .field("version", &self.version)
            .field("start_supply", &self.start_supply)
            .field("target_delta", &self.target_delta)
            .field("earliest_settle_height", &self.earliest_settle_height)
            .field("recipient", &hex(&self.recipient_account_id))
            .field("owner", &hex(&self.owner_account_id))
            .field("max_fee", &self.max_fee)
            .finish()
    }
}

impl Encode for FuturesRules {
    fn encode(&self, w: &mut Writer) {
        w.bytes(&self.canonical());
    }
}

impl Decode for FuturesRules {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(FuturesRules {
            version: r.u8()?,
            start_supply: r.u64()?,
            target_delta: r.u64()?,
            earliest_settle_height: r.u64()?,
            recipient_account_id: r.array()?,
            owner_account_id: r.array()?,
            max_fee: r.u64()?,
        })
    }
}

/// Who authorises a transfer.
// An ML-DSA key and signature dominate a transfer by design; boxing them would add an allocation to
// every decode of the most common object in the chain.
#[allow(clippy::large_enum_variant)]
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
        // Same reason as `TransferAuthority`: the key is what a transfer inevitably carries.
        #[allow(clippy::large_enum_variant)]
        enum Head {
            Key(PublicKey),
            Rules(Rules, Option<[u8; PREIMAGE_BYTES]>),
        }

        let version = r.u16()?;
        let chain_id = r.array()?;
        let head = if version >= TRANSACTION_VERSION {
            match r.u8()? {
                AUTHORITY_SIGNATURE => Head::Key(r.array()?),
                AUTHORITY_RULES => {
                    let rules = Rules::decode(r)?;
                    let preimage = match r.u8()? {
                        0 => None,
                        1 => Some(r.array()?),
                        _ => return Err(CodecError::InvalidValue),
                    };
                    Head::Rules(rules, preimage)
                }
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
            Head::Key(sender_public_key) => TransferAuthority::Signature {
                sender_public_key,
                signature: r.array()?,
            },
            Head::Rules(rules, preimage) => TransferAuthority::Rules { rules, preimage },
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

// -------------------------------------------------------- joint transfer

/// One credit in a joint transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Output {
    pub account_id: AccountId,
    pub amount: u64,
}

impl Encode for Output {
    fn encode(&self, w: &mut Writer) {
        w.fixed(&self.account_id);
        w.u64(self.amount);
    }
}

impl Decode for Output {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Output {
            account_id: r.array()?,
            amount: r.u64()?,
        })
    }
}

/// Who authorises one debit in a joint transaction.
// A key and signature dominate the variant by design; boxing them would add an allocation to the
// decode of every funding input.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub enum InputAuthority {
    /// The holder of a key signed the whole body, so every input and output is covered at once.
    Signature {
        public_key: PublicKey,
        signature: Signature,
    },
    /// A futures settlement. Revealing the terms proves which account is spent; consensus computes
    /// both destinations and both amounts, so the submitter chooses nothing.
    Futures { rules: FuturesRules },
}

impl InputAuthority {
    /// The account this input debits.
    pub fn account_id(&self) -> AccountId {
        match self {
            InputAuthority::Signature { public_key, .. } => hash::account_id(public_key),
            InputAuthority::Futures { rules } => rules.account_id(),
        }
    }

    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            InputAuthority::Signature { public_key, .. } => Some(public_key),
            InputAuthority::Futures { .. } => None,
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        match self {
            InputAuthority::Signature { signature, .. } => Some(signature),
            InputAuthority::Futures { .. } => None,
        }
    }

    pub fn futures(&self) -> Option<&FuturesRules> {
        match self {
            InputAuthority::Futures { rules } => Some(rules),
            InputAuthority::Signature { .. } => None,
        }
    }

    fn encode_into(&self, w: &mut Writer) {
        match self {
            InputAuthority::Signature { public_key, .. } => {
                w.u8(AUTHORITY_SIGNATURE);
                w.fixed(public_key);
            }
            InputAuthority::Futures { rules } => {
                w.u8(AUTHORITY_FUTURES);
                rules.encode(w);
            }
        }
    }
}

/// One debit in a joint transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct TransferInput {
    pub authority: InputAuthority,
    /// Taken from the account the authority names, and only if the balance covers it.
    pub amount: u64,
    /// That account's next nonce. Nonces live on accounts, so every input carries its own.
    pub nonce: u64,
}

impl TransferInput {
    pub fn account_id(&self) -> AccountId {
        self.authority.account_id()
    }
}

impl fmt::Debug for TransferInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("TransferInput");
        d.field("account", &hex(&self.account_id()))
            .field("amount", &self.amount)
            .field("nonce", &self.nonce);
        if let Some(rules) = self.authority.futures() {
            d.field("futures", rules);
        }
        d.finish()
    }
}

/// A transaction that debits several accounts and credits several, all or nothing.
///
/// This is the only shape that can fund a shared pot atomically: both parties sign the same body, so
/// the pot is either absent or exactly what they agreed. It is also the only shape that can pay a
/// settlement, whose two destinations and two amounts consensus derives from the futures terms.
///
/// Canonical form, enforced by consensus rather than by the codec: input and output account ids are
/// strictly ascending, so no account appears twice. Ordering is what lets two parties build the same
/// body independently and sign identical bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct JointTransfer {
    pub version: u16,
    pub chain_id: Hash,
    pub inputs: Vec<TransferInput>,
    pub fee: u64,
    /// Unix seconds; zero disables expiry. Every signer covers it, so they agree on it.
    pub expiry_unix: u64,
    pub outputs: Vec<Output>,
}

impl fmt::Debug for JointTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JointTransfer")
            .field("inputs", &self.inputs)
            .field("fee", &self.fee)
            .field("expiry_unix", &self.expiry_unix)
            .field("outputs", &self.outputs)
            .finish()
    }
}

impl JointTransfer {
    /// Every field except the signatures. Signatures are appended after this, in input order, so
    /// each signer covers every input and every output.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(
            2 + 32
                + 4
                + self.inputs.len().saturating_mul(1 + ML_DSA_PK_BYTES + 16)
                + 16
                + 4
                + self.outputs.len().saturating_mul(40),
        );
        w.u16(self.version);
        w.fixed(&self.chain_id);
        w.u32(self.inputs.len() as u32);
        for input in &self.inputs {
            input.authority.encode_into(&mut w);
            w.u64(input.amount);
            w.u64(input.nonce);
        }
        w.u64(self.fee);
        w.u64(self.expiry_unix);
        w.u32(self.outputs.len() as u32);
        for output in &self.outputs {
            output.encode(&mut w);
        }
        w.into_vec()
    }

    pub fn tx_id(&self) -> Hash {
        hash::transaction_id(TRANSACTION_KIND_JOINT_TRANSFER, &self.unsigned_bytes())
    }

    /// Every debited account, in input order.
    pub fn input_accounts(&self) -> Vec<AccountId> {
        self.inputs.iter().map(TransferInput::account_id).collect()
    }

    /// The futures terms, when this transaction settles a contract.
    pub fn futures_rules(&self) -> Option<&FuturesRules> {
        self.inputs.iter().find_map(|i| i.authority.futures())
    }

    /// Total credited to outputs.
    pub fn output_total(&self) -> Option<u64> {
        self.outputs
            .iter()
            .try_fold(0u64, |sum, o| sum.checked_add(o.amount))
    }

    /// Total debited from inputs.
    pub fn input_total(&self) -> Option<u64> {
        self.inputs
            .iter()
            .try_fold(0u64, |sum, i| sum.checked_add(i.amount))
    }
}

impl Encode for JointTransfer {
    fn encode(&self, w: &mut Writer) {
        w.bytes(&self.unsigned_bytes());
        for input in &self.inputs {
            if let Some(signature) = input.authority.signature() {
                w.fixed(signature);
            }
        }
    }
}

impl Decode for JointTransfer {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let version = r.u16()?;
        if version < TRANSACTION_VERSION_JOINT {
            return Err(CodecError::UnknownVersion);
        }
        let chain_id = r.array()?;
        let input_count = r.u32()? as usize;
        if input_count == 0 || input_count > MAX_TRANSFER_INPUTS {
            return Err(CodecError::LengthTooLarge);
        }
        let mut pending = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let tag = r.u8()?;
            let authority = match tag {
                AUTHORITY_SIGNATURE => InputAuthority::Signature {
                    public_key: r.array()?,
                    signature: [0u8; ML_DSA_SIG_BYTES],
                },
                AUTHORITY_FUTURES => InputAuthority::Futures {
                    rules: FuturesRules::decode(r)?,
                },
                _ => return Err(CodecError::InvalidValue),
            };
            pending.push((authority, r.u64()?, r.u64()?));
        }
        let fee = r.u64()?;
        let expiry_unix = r.u64()?;
        let output_count = r.u32()? as usize;
        if output_count == 0 || output_count > MAX_TRANSFER_OUTPUTS {
            return Err(CodecError::LengthTooLarge);
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(Output::decode(r)?);
        }
        let inputs = pending
            .into_iter()
            .map(|(authority, amount, nonce)| {
                let authority = match authority {
                    InputAuthority::Signature { public_key, .. } => InputAuthority::Signature {
                        public_key,
                        signature: r.array()?,
                    },
                    other => other,
                };
                Ok(TransferInput {
                    authority,
                    amount,
                    nonce,
                })
            })
            .collect::<Result<Vec<_>, CodecError>>()?;
        Ok(JointTransfer {
            version,
            chain_id,
            inputs,
            fee,
            expiry_unix,
            outputs,
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

// ----------------------------------------------------------------- witness

/// Proof that one account held a given value under a committed account root.
///
/// Only the **non-default** siblings are carried, so the size follows the number of accounts
/// (about `log2(n)` entries) instead of the tree depth: an absent sibling is exactly
/// `DEFAULT[depth]` by construction, so it costs nothing to omit and nothing to reconstruct.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountWitness {
    pub id: AccountId,
    /// `None` proves the account did not exist, which is what creating one needs.
    pub account: Option<Account>,
    /// `(depth, sibling)` for each non-default sibling on the path, ascending by depth.
    pub siblings: Vec<(u8, Hash)>,
}

impl AccountWitness {
    /// Bytes this witness occupies in the canonical encoding.
    pub fn encoded_len(&self) -> usize {
        32 + 1 + if self.account.is_some() { 48 } else { 0 } + 4 + self.siblings.len() * 33
    }
}

impl Encode for AccountWitness {
    fn encode(&self, w: &mut Writer) {
        w.fixed(&self.id);
        match &self.account {
            Some(account) => {
                w.u8(1);
                account.encode(w);
            }
            None => w.u8(0),
        }
        w.u32(self.siblings.len() as u32);
        for (depth, hash) in &self.siblings {
            w.u8(*depth);
            w.fixed(hash);
        }
    }
}

impl Decode for AccountWitness {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let id = r.array()?;
        let account = match r.u8()? {
            0 => None,
            1 => Some(Account::decode(r)?),
            _ => return Err(CodecError::InvalidValue),
        };
        let count = r.u32()? as usize;
        // At most one sibling per level, so a larger count cannot be honest.
        if count > DEPTH {
            return Err(CodecError::LengthTooLarge);
        }
        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            siblings.push((r.u8()?, r.array()?));
        }
        Ok(AccountWitness {
            id,
            account,
            siblings,
        })
    }
}

/// A block's stateless witness: the parent account root plus a proof per touched account.
///
/// The header carries `state_root`, which is `BLAKE3(DOM_STATE_ROOT || version || account_root)` and
/// therefore not invertible; so the witness states the account root it opens, and a verifier accepts
/// it only if re-hashing that root reproduces the trusted `state_root`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockWitness {
    pub account_root: Hash,
    /// The network total supply the block's parent state carried.
    ///
    /// Not derivable from the accounts a witness proves, and needed because the futures settlement
    /// rule reads it. It is a claim by whoever built the witness: a wrong value can only make a valid
    /// block fail verification, never make an invalid one pass, because the split it would produce
    /// cannot match outputs already fixed by the block.
    pub total_supply: u128,
    pub accounts: Vec<AccountWitness>,
}

impl Encode for BlockWitness {
    fn encode(&self, w: &mut Writer) {
        w.fixed(&self.account_root);
        w.bytes(&self.total_supply.to_be_bytes());
        w.u32(self.accounts.len() as u32);
        for account in &self.accounts {
            account.encode(w);
        }
    }
}

impl Decode for BlockWitness {
    fn decode(r: &mut Reader<'_>) -> Result<Self, CodecError> {
        let account_root = r.array()?;
        let total_supply = u128::from_be_bytes(r.array()?);
        let count = r.u32()? as usize;
        // Every witness is at least one byte, so a larger count cannot be honest.
        if count > r.remaining() {
            return Err(CodecError::LengthTooLarge);
        }
        let mut accounts = Vec::with_capacity(count.min(1_024));
        for _ in 0..count {
            accounts.push(AccountWitness::decode(r)?);
        }
        Ok(BlockWitness {
            account_root,
            total_supply,
            accounts,
        })
    }
}

// ------------------------------------------------------------- transaction

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction {
    Transfer(Transfer),
    StateUpdate(StateUpdate),
    JointTransfer(JointTransfer),
}

impl Transaction {
    pub fn kind(&self) -> u8 {
        match self {
            Transaction::Transfer(_) => TRANSACTION_KIND_TRANSFER,
            Transaction::StateUpdate(_) => TRANSACTION_KIND_STATE_UPDATE,
            Transaction::JointTransfer(_) => TRANSACTION_KIND_JOINT_TRANSFER,
        }
    }

    pub fn encode_into(&self, w: &mut Writer) {
        w.u8(self.kind());
        match self {
            Transaction::Transfer(t) => t.encode(w),
            Transaction::StateUpdate(s) => s.encode(w),
            Transaction::JointTransfer(j) => j.encode(w),
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
            TRANSACTION_KIND_JOINT_TRANSFER => {
                Transaction::JointTransfer(JointTransfer::decode(r)?)
            }
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
            Transaction::JointTransfer(j) => j.tx_id(),
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

/// Byte offset of `security_nonce` in the canonical header: every field before it is fixed while a
/// nonce is being searched, and the nonce runs to the end of the header.
pub const NONCE_OFFSET: usize = BLOCK_HEADER_BYTES - 32;

impl BlockHeader {
    pub fn canonical(&self) -> [u8; BLOCK_HEADER_BYTES] {
        // Built from the prefix plus the nonce so the mining fast path cannot drift from the
        // canonical encoding: there is one definition of the layout.
        let mut out = [0u8; BLOCK_HEADER_BYTES];
        out[..NONCE_OFFSET].copy_from_slice(&self.prefix_bytes());
        out[NONCE_OFFSET..].copy_from_slice(&self.security_nonce);
        out
    }

    /// The header bytes that stay fixed while a nonce is searched, i.e. everything but
    /// [`Self::security_nonce`].
    pub fn prefix_bytes(&self) -> [u8; NONCE_OFFSET] {
        let mut w = Writer::with_capacity(NONCE_OFFSET);
        w.u16(self.version);
        w.fixed(&self.chain_id);
        w.fixed(&self.previous_block_id);
        w.fixed(&self.transaction_root);
        w.fixed(&self.state_root);
        w.u64(self.timestamp_unix_ms);
        w.fixed(&self.target.to_be_bytes());
        w.fixed(&self.payout_account_id);
        let bytes = w.into_vec();
        debug_assert_eq!(bytes.len(), NONCE_OFFSET);
        let mut out = [0u8; NONCE_OFFSET];
        out.copy_from_slice(&bytes);
        out
    }

    /// Increment `security_nonce` until the proof-of-work hash meets the target.
    ///
    /// The prefix is hashed once and each attempt hashes only the 32-byte nonce, which is the
    /// difference between a mining loop bounded by hashing and one bounded by re-serialising the
    /// header. The result is identical to [`Self::meets_target`] on the finished header.
    pub fn mine_nonce(&mut self, max_attempts: u64) -> bool {
        if self.meets_target() {
            return true;
        }
        let base = hash::pow_state(&self.prefix_bytes());
        for _ in 0..max_attempts {
            for byte in self.security_nonce.iter_mut().rev() {
                let (value, overflow) = byte.overflowing_add(1);
                *byte = value;
                if !overflow {
                    break;
                }
            }
            let mut h = base.clone();
            h.update(&self.security_nonce);
            if U256::from_be_bytes(*h.finalize().as_bytes()) <= self.target {
                return true;
            }
        }
        false
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
        FUTURES_RULES_BYTES, MAX_TARGET_DELTA, MAX_TRANSACTION_BYTES, PREIMAGE_BYTES,
        PROTOCOL_VERSION, RULES_BYTES, RULES_VERSION, RULES_VERSION_FUTURES, TRANSACTION_VERSION,
        TRANSACTION_VERSION_JOINT, TRANSACTION_VERSION_PAYLOAD, TX_PAYLOAD_BYTES,
    };

    fn pow_sample_header(nonce: u8) -> BlockHeader {
        BlockHeader {
            version: PROTOCOL_VERSION,
            chain_id: [7u8; 32],
            previous_block_id: [8u8; 32],
            transaction_root: [9u8; 32],
            state_root: [10u8; 32],
            timestamp_unix_ms: 1_700_000_000_000,
            target: U256::pow2(240),
            payout_account_id: [11u8; 32],
            security_nonce: [nonce; 32],
        }
    }

    /// Mining hashes `domain || prefix` and then only the nonce. That must be byte-identical to
    /// hashing the whole canonical header, or a block mined quickly would fail validation everywhere
    /// else on the network.
    #[test]
    fn the_incremental_pow_hash_matches_the_canonical_hash() {
        for byte in 0..=255u8 {
            let mut header = pow_sample_header(byte);
            let prefix = header.prefix_bytes();
            assert_eq!(prefix.len(), NONCE_OFFSET);
            for step in 0..4u8 {
                header.security_nonce[31] = byte.wrapping_add(step);
                let mut state = hash::pow_state(&prefix);
                state.update(&header.security_nonce);
                assert_eq!(
                    *state.finalize().as_bytes(),
                    hash::pow_hash(&header.canonical()),
                    "nonce byte {byte} step {step}"
                );
            }
        }
    }

    /// The prefix must be exactly the canonical encoding minus the trailing nonce.
    #[test]
    fn the_header_prefix_is_the_header_without_its_nonce() {
        let header = pow_sample_header(0x5a);
        let canonical = header.canonical();
        assert_eq!(&canonical[..NONCE_OFFSET], &header.prefix_bytes()[..]);
        assert_eq!(&canonical[NONCE_OFFSET..], &header.security_nonce[..]);
    }

    /// Mining leaves the header in a state the ordinary validator accepts.
    #[test]
    fn a_mined_header_meets_its_target() {
        let mut header = pow_sample_header(0);
        assert!(header.mine_nonce(2_000_000), "expected to find a nonce");
        assert!(header.meets_target());
        assert_eq!(hash::pow_hash(&header.canonical()), header.pow_hash());
    }

    fn sample_transfer(signature_byte: u8) -> Transfer {
        Transfer {
            version: TRANSACTION_VERSION,
            chain_id: [9u8; 32],
            recipient_account_id: [4u8; 32],
            amount: 42,
            fee: 7,
            nonce: 5,
            expiry_unix: 0,
            payload: None,
            authority: TransferAuthority::Signature {
                sender_public_key: [3u8; ML_DSA_PK_BYTES],
                signature: [signature_byte; ML_DSA_SIG_BYTES],
            },
        }
    }

    fn sample_rules() -> Rules {
        Rules {
            version: RULES_VERSION,
            hash_lock: [0x11u8; 32],
            refund_height: 500,
            recipient_account_id: [0x22u8; 32],
            owner_account_id: [0x33u8; 32],
            max_fee: 9,
        }
    }

    fn sample_rules_spend(preimage: Option<[u8; PREIMAGE_BYTES]>) -> Transfer {
        Transfer {
            version: TRANSACTION_VERSION,
            chain_id: [9u8; 32],
            recipient_account_id: [0x22u8; 32],
            amount: 1_000,
            fee: 9,
            nonce: 0,
            expiry_unix: 0,
            payload: None,
            authority: TransferAuthority::Rules {
                rules: sample_rules(),
                preimage,
            },
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
        assert_eq!(bytes.len(), 2 + 32 + 1 + 1952 + 32 + 32 + 1 + 3309);
        assert!(bytes.len() < MAX_TRANSACTION_BYTES);
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), tx);

        let with_payload = Transfer {
            payload: Some([0xABu8; TX_PAYLOAD_BYTES]),
            ..sample_transfer(1)
        };
        let bytes = to_bytes(&with_payload);
        assert_eq!(
            bytes.len(),
            2 + 32 + 1 + 1952 + 32 + 32 + 1 + TX_PAYLOAD_BYTES + 3309
        );
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), with_payload);
    }

    #[test]
    fn version_four_transfers_keep_their_bytes_without_an_authority_tag() {
        let legacy = Transfer {
            version: TRANSACTION_VERSION_PAYLOAD,
            payload: None,
            ..sample_transfer(1)
        };
        let bytes = to_bytes(&legacy);
        assert_eq!(bytes.len(), 2 + 32 + 1952 + 32 + 32 + 1 + 3309);
        assert_eq!(legacy.unsigned_bytes()[34], 3); // the sender key starts right after chain_id
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), legacy);
    }

    #[test]
    fn rules_commit_to_every_field() {
        let base = sample_rules();
        let id = base.account_id();
        assert_ne!(base.account_id(), hash::account_id(&[3u8; ML_DSA_PK_BYTES]));
        assert_eq!(base.canonical().len(), RULES_BYTES);

        let mutators: Vec<fn(&mut Rules)> = vec![
            |r| r.hash_lock[0] ^= 1,
            |r| r.refund_height += 1,
            |r| r.recipient_account_id[0] ^= 1,
            |r| r.owner_account_id[0] ^= 1,
            |r| r.max_fee += 1,
            |r| r.version = 2,
        ];
        for mutate in mutators {
            let mut other = base.clone();
            mutate(&mut other);
            assert_ne!(other.account_id(), id);
        }
        assert!(base.claims_open_at(base.refund_height - 1));
        assert!(!base.claims_open_at(base.refund_height));
    }

    #[test]
    fn rules_spend_roundtrips_and_stays_small() {
        let claim = sample_rules_spend(Some([7u8; PREIMAGE_BYTES]));
        let bytes = to_bytes(&claim);
        // version, chain, tag, rules, preimage presence, preimage, recipient, amount, fee, nonce,
        // expiry, payload presence.
        assert_eq!(
            bytes.len(),
            2 + 32 + 1 + RULES_BYTES + 1 + PREIMAGE_BYTES + 32 + 8 * 4 + 1
        );
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), claim);
        assert_eq!(claim.sender_id(), sample_rules().account_id());
        assert!(claim.sender_public_key().is_none());
        assert!(claim.signature().is_none());

        let refund = sample_rules_spend(None);
        let bytes = to_bytes(&refund);
        assert_eq!(bytes.len(), 214);
        assert_eq!(from_bytes::<Transfer>(&bytes).unwrap(), refund);
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
        assert!(transaction_version_supported(TRANSACTION_VERSION_PAYLOAD));
        assert!(transaction_version_supported(TRANSACTION_VERSION));
        assert!(transaction_version_supported(TRANSACTION_VERSION_JOINT));
        assert!(!transaction_version_supported(
            TRANSACTION_VERSION_JOINT + 1
        ));
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
        // The presence byte sits right after version, chain id, authority, recipient, amount, fee,
        // nonce and expiry.
        bytes[2 + 32 + 1 + ML_DSA_PK_BYTES + 32 + 8 * 4] = 2;
        assert_eq!(
            from_bytes::<Transfer>(&bytes),
            Err(CodecError::InvalidValue)
        );
    }

    #[test]
    fn tx_id_ignores_the_signature() {
        let a = sample_transfer(1);
        let b = sample_transfer(2);
        assert_ne!(a.signature(), b.signature());
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

    fn sample_futures() -> FuturesRules {
        FuturesRules {
            version: RULES_VERSION_FUTURES,
            start_supply: 10_000,
            target_delta: 500,
            earliest_settle_height: 900,
            recipient_account_id: [0x22u8; 32],
            owner_account_id: [0x33u8; 32],
            max_fee: 9,
        }
    }

    #[test]
    fn futures_rules_commit_to_a_sized_canonical_form() {
        let rules = sample_futures();
        assert_eq!(rules.canonical().len(), FUTURES_RULES_BYTES);
        let bytes = to_bytes(&rules);
        assert_eq!(bytes.len(), FUTURES_RULES_BYTES);
        assert_eq!(from_bytes::<FuturesRules>(&bytes).unwrap(), rules);
        // A futures account never collides with an escrow account, whatever the bytes say.
        assert_ne!(
            rules.account_id(),
            hash::rules_account_id(&rules.canonical())
        );
        assert_eq!(
            rules.account_id(),
            hash::futures_account_id(&rules.canonical())
        );
        assert!(rules.settle_open_at(900));
        assert!(!rules.settle_open_at(899));
    }

    #[test]
    fn every_futures_term_changes_the_account() {
        let base = sample_futures();
        let variants = [
            FuturesRules {
                start_supply: base.start_supply + 1,
                ..base
            },
            FuturesRules {
                target_delta: base.target_delta + 1,
                ..base
            },
            FuturesRules {
                earliest_settle_height: base.earliest_settle_height + 1,
                ..base
            },
            FuturesRules {
                recipient_account_id: [0x44u8; 32],
                ..base
            },
            FuturesRules {
                owner_account_id: [0x55u8; 32],
                ..base
            },
            FuturesRules {
                max_fee: base.max_fee + 1,
                ..base
            },
        ];
        for variant in variants {
            assert_ne!(variant.account_id(), base.account_id());
        }
    }

    /// Linear in the delta, clamped at both ends, and always conserving the pot. At the strike the
    /// split is even, which is the fair point for equal collateral.
    #[test]
    fn the_futures_split_is_linear_and_fully_collateralized() {
        let rules = sample_futures();
        let pot = 1_000u64;
        assert_eq!(rules.split(pot, 10_000), Some((pot, 0)));
        // A supply below the agreed start clamps to zero rather than underflowing.
        assert_eq!(rules.split(pot, 9_000), Some((pot, 0)));
        assert_eq!(rules.split(pot, 10_250), Some((750, 250)));
        assert_eq!(rules.split(pot, 10_500), Some((500, 500)));
        assert_eq!(rules.split(pot, 11_000), Some((0, pot)));
        assert_eq!(rules.split(pot, 50_000), Some((0, pot)));
        // Rounding always lands on the owner, so the two shares still sum to the pot exactly.
        for supply in 10_500..10_600 {
            let (owner, recipient) = rules.split(999, supply).unwrap();
            assert_eq!(owner + recipient, 999);
        }
        // Unusable terms are refused rather than producing a nonsense split.
        assert_eq!(
            FuturesRules {
                target_delta: 0,
                ..rules
            }
            .split(pot, 10_500),
            None
        );
        assert_eq!(
            FuturesRules {
                target_delta: MAX_TARGET_DELTA + 1,
                ..rules
            }
            .split(pot, 10_500),
            None
        );
    }

    fn sample_joint() -> JointTransfer {
        JointTransfer {
            version: TRANSACTION_VERSION_JOINT,
            chain_id: [9u8; 32],
            inputs: vec![
                TransferInput {
                    authority: InputAuthority::Signature {
                        public_key: [1u8; ML_DSA_PK_BYTES],
                        signature: [2u8; ML_DSA_SIG_BYTES],
                    },
                    amount: 60,
                    nonce: 3,
                },
                TransferInput {
                    authority: InputAuthority::Futures {
                        rules: sample_futures(),
                    },
                    amount: 40,
                    nonce: 0,
                },
            ],
            fee: 7,
            expiry_unix: 0,
            outputs: vec![
                Output {
                    account_id: [0x22u8; 32],
                    amount: 50,
                },
                Output {
                    account_id: [0x33u8; 32],
                    amount: 43,
                },
            ],
        }
    }

    #[test]
    fn a_joint_transfer_round_trips_and_binds_every_output() {
        let mut tx = sample_joint();
        let bytes = to_bytes(&tx);
        assert_eq!(from_bytes::<JointTransfer>(&bytes).unwrap(), tx);
        let tx_id = tx.tx_id();
        tx.outputs[1].amount += 1;
        assert_ne!(tx.tx_id(), tx_id);

        // The transaction envelope carries it too, so it travels the ordinary path.
        let envelope = Transaction::JointTransfer(sample_joint()).canonical();
        let mut reader = Reader::new(&envelope);
        let decoded = Transaction::decode_from(&mut reader, MAX_TRANSACTION_BYTES).unwrap();
        assert_eq!(decoded, Transaction::JointTransfer(sample_joint()));
        assert_eq!(decoded.kind(), TRANSACTION_KIND_JOINT_TRANSFER);
    }

    #[test]
    fn a_joint_transfer_needs_inputs_and_outputs() {
        let empty_inputs = JointTransfer {
            inputs: Vec::new(),
            ..sample_joint()
        };
        assert!(from_bytes::<JointTransfer>(&to_bytes(&empty_inputs)).is_err());
        let empty_outputs = JointTransfer {
            outputs: Vec::new(),
            ..sample_joint()
        };
        assert!(from_bytes::<JointTransfer>(&to_bytes(&empty_outputs)).is_err());
    }

    #[test]
    fn the_futures_authority_encodes_without_a_signature() {
        let tx = sample_joint();
        // The signature of the first input is appended; the futures input contributes none.
        assert_eq!(
            tx.unsigned_bytes().len() + ML_DSA_SIG_BYTES,
            to_bytes(&tx).len()
        );
        assert!(tx.futures_rules().is_some());
        assert_eq!(tx.input_accounts().len(), 2);
    }
}
