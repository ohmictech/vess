//! Block construction and full block validation.

use std::collections::HashSet;

use vess_core::U256;
use vess_core::codec::{Reader, Writer};
use vess_core::constants::{
    BLOCK_HEADER_BYTES, DEV_FEE_ACCOUNT, MAX_BLOCK_BYTES, MAX_TRANSACTION_BYTES, NetworkProfile,
    PREIMAGE_BYTES, PROTOCOL_VERSION, RULES_VERSION, RULES_VERSION_FUTURES, TRANSACTION_VERSION,
    TRANSACTION_VERSION_JOINT,
};
use vess_core::hash::{self, DOM_JOINT_TRANSFER, DOM_STATE_UPDATE, DOM_TRANSFER};
use vess_core::types::transaction_version_supported;
use vess_core::{
    AccountId, BlockHeader, BlockWitness, FuturesRules, Hash, InputAuthority, JointTransfer,
    Output, Transaction,
};
use vess_state::{State, UndoLog};

use crate::chain::{HeaderSource, check_header, median_time_past, required_target};
use crate::error::{ConsensusError, TxReject};

#[derive(Debug)]
pub struct ValidatedBlock {
    pub header: BlockHeader,
    pub height: u64,
    pub chain_work: u128,
    pub transactions: Vec<Transaction>,
    /// Post-block state.
    pub state: State,
    pub undo: UndoLog,
}

#[derive(Debug, Clone)]
pub struct BlockTemplate {
    pub header: BlockHeader,
    pub body: Vec<u8>,
}

impl BlockTemplate {
    pub fn encode(&self) -> Vec<u8> {
        let header = self.header.canonical();
        let mut out = Vec::with_capacity(header.len() + self.body.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.body);
        out
    }

    /// Search for a security nonce meeting the template's target.
    pub fn mine(&mut self, max_attempts: u64) -> bool {
        mine_header(&mut self.header, max_attempts)
    }
}

/// Increment `security_nonce` until the PoW hash meets the target.
pub fn mine_header(header: &mut BlockHeader, max_attempts: u64) -> bool {
    // The search itself lives on the header so it can hash the fixed prefix once and vary only the
    // trailing nonce; this stays the stable entry point for callers.
    header.mine_nonce(max_attempts)
}

/// Canonical block body: `u32` count followed by every transaction.
pub fn encode_body(transactions: &[Transaction]) -> Result<Vec<u8>, ConsensusError> {
    let count = u32::try_from(transactions.len()).map_err(|_| ConsensusError::BlockTooLarge)?;
    let mut w = Writer::new();
    w.u32(count);
    for tx in transactions {
        tx.encode_into(&mut w);
    }
    Ok(w.into_vec())
}

pub fn decode_body(bytes: &[u8]) -> Result<Vec<Transaction>, ConsensusError> {
    let mut r = Reader::new(bytes);
    let count = r.u32().map_err(|_| ConsensusError::BadTxEncoding)? as usize;
    if count > r.remaining() {
        // Every transaction is at least one byte, so a larger count cannot be honest.
        return Err(ConsensusError::BadTxEncoding);
    }
    let mut transactions = Vec::with_capacity(count.min(1_024));
    for _ in 0..count {
        transactions.push(
            Transaction::decode_from(&mut r, MAX_TRANSACTION_BYTES)
                .map_err(|_| ConsensusError::BadTxEncoding)?,
        );
    }
    r.finish().map_err(|_| ConsensusError::BadTxEncoding)?;
    Ok(transactions)
}

pub fn split_block(bytes: &[u8]) -> Result<(BlockHeader, Vec<Transaction>), ConsensusError> {
    if bytes.len() > MAX_BLOCK_BYTES {
        return Err(ConsensusError::BlockTooLarge);
    }
    if bytes.len() < BLOCK_HEADER_BYTES {
        return Err(ConsensusError::BadHeader);
    }
    let header =
        BlockHeader::decode(&bytes[..BLOCK_HEADER_BYTES]).map_err(|_| ConsensusError::BadHeader)?;
    let transactions = decode_body(&bytes[BLOCK_HEADER_BYTES..])?;
    Ok((header, transactions))
}

fn reject(index: usize, reason: TxReject) -> ConsensusError {
    ConsensusError::BadTransaction {
        index: index as u32,
        reason,
    }
}

/// The escrow spend rule. No signature is involved: revealing the rules proves which account is
/// being spent, and the rules name both destinations, so a submitter chooses only *when* to spend,
/// never *where* the balance goes.
///
/// Below `rules.refund_height` the claim path is open and needs the preimage. At or above it the
/// claim window is closed for good and only the owner may be paid, whether or not a preimage is
/// offered.
///
/// Public because a node decides mempool membership and block templates with the same predicate that
/// consensus applies; two implementations would eventually disagree.
pub fn check_rules_spend(
    tx: &vess_core::Transfer,
    rules: &vess_core::types::Rules,
    preimage: Option<&[u8; PREIMAGE_BYTES]>,
    height: u64,
    balance: u64,
) -> Result<(), TxReject> {
    if tx.version < TRANSACTION_VERSION {
        return Err(TxReject::BadVersion);
    }
    if rules.version != RULES_VERSION {
        return Err(TxReject::BadRules);
    }
    if tx.fee > rules.max_fee {
        return Err(TxReject::FeeTooHigh);
    }
    if tx.expiry_unix != 0 {
        return Err(TxReject::BadRules);
    }
    // An escrow leaves nothing behind: no change output, no dust, no partial sweep.
    if tx.amount.checked_add(tx.fee) != Some(balance) {
        return Err(TxReject::PartialSpend);
    }
    if rules.claims_open_at(height) {
        match preimage {
            Some(preimage) if hash::hash_lock(preimage) == rules.hash_lock => {
                if tx.recipient_account_id != rules.recipient_account_id {
                    return Err(TxReject::WrongDestination);
                }
            }
            _ => return Err(TxReject::PreimageMismatch),
        }
    } else {
        if preimage.is_some() {
            return Err(TxReject::ClaimWindowClosed);
        }
        if tx.recipient_account_id != rules.owner_account_id {
            return Err(TxReject::WrongDestination);
        }
    }
    Ok(())
}

/// The futures settlement rule.
///
/// The submitter chooses nothing. Consensus derives both destinations and both amounts from the
/// revealed terms and the measured supply delta, then requires the transaction to declare exactly
/// that split — a mismatch is a rejection, never a rewrite, so a transaction id always describes the
/// effect it actually has.
///
/// ```text
/// delta     = supply - rules.start_supply        (saturating at zero)
/// recipient = (pot - fee) * min(delta, 2 * target_delta) / (2 * target_delta)
/// owner     = (pot - fee) - recipient
/// ```
///
/// The split is linear in the delta and clamped to the pot, so the contract is fully collateralized
/// by construction: neither side can be asked for more than what was posted. At
/// `delta == target_delta` the two sides receive exactly half, which is the fair strike for equal
/// collateral.
///
/// `supply` is the state entering the settling block. Because transfers conserve supply and the block
/// reward is credited after the body, that value is the same wherever the settlement sits in the
/// block: nobody can move it by stuffing the block.
pub fn check_futures_settle(
    tx: &JointTransfer,
    rules: &FuturesRules,
    height: u64,
    balance: u64,
    supply: u128,
) -> Result<(), TxReject> {
    if rules.version != RULES_VERSION_FUTURES {
        return Err(TxReject::BadRules);
    }
    if rules.owner_account_id == rules.recipient_account_id {
        return Err(TxReject::BadFuturesRules);
    }
    if tx.version < TRANSACTION_VERSION_JOINT {
        return Err(TxReject::BadVersion);
    }
    if !rules.settle_open_at(height) {
        return Err(TxReject::SettleTooEarly);
    }
    if tx.fee > rules.max_fee {
        return Err(TxReject::FeeTooHigh);
    }
    if tx.expiry_unix != 0 {
        return Err(TxReject::BadFuturesRules);
    }
    // The pot is spent whole, and only the pot: no second input, no change output, no dust.
    if tx.inputs.len() != 1 || tx.inputs[0].amount != balance {
        return Err(TxReject::PartialSpend);
    }
    let pot = balance.checked_sub(tx.fee).ok_or(TxReject::FeeTooHigh)?;
    if pot == 0 {
        return Err(TxReject::FeeTooHigh);
    }

    let (owner, recipient) = rules.split(pot, supply).ok_or(TxReject::BadFuturesRules)?;
    let mut expected: Vec<Output> = [
        (rules.owner_account_id, owner),
        (rules.recipient_account_id, recipient),
    ]
    .into_iter()
    .filter(|(_, amount)| *amount > 0)
    .map(|(account_id, amount)| Output { account_id, amount })
    .collect();
    expected.sort_unstable_by(|a, b| a.account_id.cmp(&b.account_id));
    if tx.outputs.len() != expected.len() || tx.outputs.iter().zip(&expected).any(|(a, b)| a != b) {
        return Err(TxReject::BadSettlement);
    }
    Ok(())
}

/// Every account a block reads or writes: each transaction's sender and recipient, plus the two
/// accounts the reward is credited to.
///
/// This is derived from the block alone, so a witness can be checked for completeness: it must name
/// exactly these accounts, no more and no fewer.
pub fn touched_accounts(transactions: &[Transaction], payout: &AccountId) -> Vec<AccountId> {
    let mut set = std::collections::BTreeSet::new();
    for tx in transactions {
        match tx {
            Transaction::Transfer(t) => {
                set.insert(t.sender_id());
                set.insert(t.recipient_account_id);
            }
            Transaction::StateUpdate(t) => {
                set.insert(t.sender_id());
            }
            Transaction::JointTransfer(t) => {
                for input in &t.inputs {
                    set.insert(input.account_id());
                }
                for output in &t.outputs {
                    set.insert(output.account_id);
                }
            }
        }
    }
    set.insert(*payout);
    set.insert(DEV_FEE_ACCOUNT);
    set.into_iter().collect()
}

/// Validate a block from its header and a witness, without holding the parent state.
///
/// The witness is the parent state's proof for [`touched_accounts`]. Every proof is opened against
/// `parent_state_root`, the block is executed against the partial state it reconstructs, and the
/// resulting root must equal `header.state_root`. Nothing here reads the database or a full tree, so
/// a verifier needs only headers (for `parent_state_root`) and the block with its witness.
///
/// The result is the post-block state root, which the caller compares with `header.state_root`; it is
/// returned so a caller can chain blocks without re-reading it from the header.
#[allow(clippy::too_many_arguments)]
pub fn verify_witness(
    network: &NetworkProfile,
    parent_state_root: &Hash,
    header: &BlockHeader,
    transactions: &[Transaction],
    height: u64,
    witness: &BlockWitness,
) -> Result<Hash, ConsensusError> {
    if header.version != PROTOCOL_VERSION {
        return Err(ConsensusError::BadVersion);
    }
    if header.chain_id != hash::chain_id(network.network) {
        return Err(ConsensusError::BadChainId);
    }
    let ids: Vec<Hash> = transactions.iter().map(|tx| tx.id()).collect();
    if hash::tx_root(&ids) != header.transaction_root {
        return Err(ConsensusError::BadTxRoot);
    }

    // The witness names the account root it opens; it is only useful if that root is the one the
    // trusted header commits to.
    if hash::state_root(&witness.account_root) != *parent_state_root {
        return Err(ConsensusError::BadWitness);
    }

    // A witness that names the wrong accounts could otherwise omit one and still fold to a root,
    // because the missing account would simply be absent from the partial tree.
    let expected = touched_accounts(transactions, &header.payout_account_id);
    if witness.accounts.len() != expected.len()
        || witness.accounts.iter().map(|w| w.id).ne(expected)
    {
        return Err(ConsensusError::BadWitness);
    }

    let mut state = State::from_witnesses(
        &witness.accounts,
        &witness.account_root,
        witness.total_supply,
    )
    .ok_or(ConsensusError::BadWitness)?;
    apply_body(
        &mut state,
        &header.chain_id,
        network,
        header.target,
        transactions,
        height,
        header.timestamp_unix_ms,
        &header.payout_account_id,
    )?;
    Ok(state.root())
}

/// Execute a body against `state`, then credit the block reward derived from `target`.
/// `height` is the height of the block being applied: escrow rules gate on it, so it is part of the
/// validation context and never inferred from the clock.
#[allow(clippy::too_many_arguments)]
pub fn apply_body(
    state: &mut State,
    chain_id: &Hash,
    network: &NetworkProfile,
    target: U256,
    transactions: &[Transaction],
    height: u64,
    timestamp_unix_ms: u64,
    payout: &AccountId,
) -> Result<(), ConsensusError> {
    state.begin_block();
    for (index, tx) in transactions.iter().enumerate() {
        match tx {
            Transaction::Transfer(t) => {
                if !transaction_version_supported(t.version) {
                    return Err(reject(index, TxReject::BadVersion));
                }
                if &t.chain_id != chain_id {
                    return Err(reject(index, TxReject::BadChainId));
                }
                let sender = t.sender_id();
                match &t.authority {
                    vess_core::types::TransferAuthority::Signature {
                        sender_public_key,
                        signature,
                    } => {
                        if !vess_crypto::verify(
                            sender_public_key,
                            DOM_TRANSFER,
                            &t.unsigned_bytes(),
                            signature,
                        ) {
                            return Err(reject(index, TxReject::BadSignature));
                        }
                    }
                    vess_core::types::TransferAuthority::Rules { rules, preimage } => {
                        let account = state.account(&sender).ok_or_else(|| {
                            reject(
                                index,
                                TxReject::InvalidState(vess_state::StateError::UnknownAccount),
                            )
                        })?;
                        check_rules_spend(t, rules, preimage.as_ref(), height, account.balance)
                            .map_err(|reason| reject(index, reason))?;
                    }
                }
                state
                    .execute_transfer(t, &sender, timestamp_unix_ms / 1_000, payout)
                    .map_err(|e| reject(index, TxReject::InvalidState(e)))?;
            }
            Transaction::StateUpdate(t) => {
                if t.version != PROTOCOL_VERSION {
                    return Err(reject(index, TxReject::BadVersion));
                }
                if &t.chain_id != chain_id {
                    return Err(reject(index, TxReject::BadChainId));
                }
                let sender = t.sender_id();
                if !vess_crypto::verify(
                    &t.sender_public_key,
                    DOM_STATE_UPDATE,
                    &t.unsigned_bytes(),
                    &t.signature,
                ) {
                    return Err(reject(index, TxReject::BadSignature));
                }
                state
                    .execute_state_update(t, &sender, timestamp_unix_ms / 1_000, payout)
                    .map_err(|e| reject(index, TxReject::InvalidState(e)))?;
            }
            Transaction::JointTransfer(t) => {
                if !transaction_version_supported(t.version) {
                    return Err(reject(index, TxReject::BadVersion));
                }
                if &t.chain_id != chain_id {
                    return Err(reject(index, TxReject::BadChainId));
                }
                // A settlement is authorised by the terms it reveals, so it is checked against the
                // measured supply before anything moves. The supply read here is the state entering
                // the block whenever the settlement sits inside it, because transfers conserve
                // supply and the reward is credited afterwards.
                if let Some(rules) = t.futures_rules() {
                    let account = state.account(&rules.account_id()).ok_or_else(|| {
                        reject(
                            index,
                            TxReject::InvalidState(vess_state::StateError::UnknownAccount),
                        )
                    })?;
                    check_futures_settle(t, rules, height, account.balance, state.total_supply())
                        .map_err(|reason| reject(index, reason))?;
                }
                // Every signature covers the same body, so each signer agreed to every input and
                // every output, not just its own.
                let body = t.unsigned_bytes();
                for input in &t.inputs {
                    if let InputAuthority::Signature {
                        public_key,
                        signature,
                    } = &input.authority
                        && !vess_crypto::verify(public_key, DOM_JOINT_TRANSFER, &body, signature)
                    {
                        return Err(reject(index, TxReject::BadSignature));
                    }
                }
                state
                    .execute_joint_transfer(t, timestamp_unix_ms / 1_000, payout)
                    .map_err(|e| reject(index, TxReject::InvalidState(e)))?;
            }
        }
    }

    // The reward is split by consensus: 1% (floored) to the development account, the rest to the
    // miner. The fee comes out of the reward, never on top of it, so total issuance is unchanged.
    let (miner_reward, dev_fee) = vess_emission::split(*network, target);
    state
        .credit_block_reward(payout, miner_reward)
        .map_err(|e| reject(transactions.len(), TxReject::InvalidState(e)))?;
    state
        .credit(DEV_FEE_ACCOUNT, dev_fee)
        .map_err(|e| reject(transactions.len(), TxReject::InvalidState(e)))?;
    Ok(())
}

/// Build a block on top of `parent_id` with an empty security nonce.
#[allow(clippy::too_many_arguments)]
pub fn build_template<C: HeaderSource>(
    chain: &C,
    network: &NetworkProfile,
    parent_id: &Hash,
    parent_state: &State,
    payout: &AccountId,
    timestamp_unix_ms: u64,
    transactions: &[Transaction],
) -> Result<BlockTemplate, ConsensusError> {
    let parent_meta = chain.meta(parent_id).ok_or(ConsensusError::UnknownParent)?;
    let height = parent_meta
        .height
        .checked_add(1)
        .ok_or(ConsensusError::BadHeader)?;
    let target = required_target(chain, network, parent_id, height)?;
    let mtp = median_time_past(chain, parent_id)?;
    if timestamp_unix_ms <= mtp {
        return Err(ConsensusError::BadTimestamp);
    }

    let mut unique = HashSet::with_capacity(transactions.len());
    for tx in transactions {
        if !unique.insert(tx.id()) {
            return Err(ConsensusError::DuplicateInBlock);
        }
    }

    let ids: Vec<Hash> = transactions.iter().map(|tx| tx.id()).collect();
    let transaction_root = hash::tx_root(&ids);

    let mut state = parent_state.clone();
    apply_body(
        &mut state,
        &hash::chain_id(network.network),
        network,
        target,
        transactions,
        height,
        timestamp_unix_ms,
        payout,
    )?;

    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        chain_id: hash::chain_id(network.network),
        previous_block_id: *parent_id,
        transaction_root,
        state_root: state.root(),
        timestamp_unix_ms,
        target,
        payout_account_id: *payout,
        security_nonce: [0u8; 32],
    };

    Ok(BlockTemplate {
        body: encode_body(transactions)?,
        header,
    })
}

/// Validate a complete block against the post-state of its parent.
pub fn validate_block<C: HeaderSource>(
    chain: &C,
    network: &NetworkProfile,
    parent_state: &State,
    bytes: &[u8],
) -> Result<ValidatedBlock, ConsensusError> {
    let (header, transactions) = split_block(bytes)?;

    let meta = check_header(chain, network, &header, true)?;
    if chain.header(&header.previous_block_id).is_none() {
        return Err(ConsensusError::UnknownParent);
    }

    let mut unique = HashSet::with_capacity(transactions.len());
    for tx in &transactions {
        if !unique.insert(tx.id()) {
            return Err(ConsensusError::DuplicateInBlock);
        }
    }

    let ids: Vec<Hash> = transactions.iter().map(|tx| tx.id()).collect();
    if hash::tx_root(&ids) != header.transaction_root {
        return Err(ConsensusError::BadTxRoot);
    }

    let mut state = parent_state.clone();
    apply_body(
        &mut state,
        &header.chain_id,
        network,
        header.target,
        &transactions,
        meta.height,
        header.timestamp_unix_ms,
        &header.payout_account_id,
    )?;

    if state.root() != header.state_root {
        return Err(ConsensusError::BadStateRoot);
    }
    let undo = state.take_undo();

    Ok(ValidatedBlock {
        header,
        height: meta.height,
        chain_work: meta.chain_work,
        transactions,
        state,
        undo,
    })
}
