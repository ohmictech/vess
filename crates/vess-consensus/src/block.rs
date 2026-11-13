//! Block construction and full block validation.

use std::collections::HashSet;

use vess_core::U256;
use vess_core::codec::{Reader, Writer};
use vess_core::constants::{
    BLOCK_HEADER_BYTES, DEV_FEE_ACCOUNT, MAX_BLOCK_BYTES, MAX_FUTURE_DRIFT_SECONDS,
    MAX_TRANSACTION_BYTES, NetworkProfile, PROTOCOL_VERSION,
};
use vess_core::hash::{self, DOM_STATE_UPDATE, DOM_TRANSFER};
use vess_core::{AccountId, BlockHeader, Hash, Transaction};
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

fn increment_nonce(nonce: &mut [u8; 32]) {
    for byte in nonce.iter_mut().rev() {
        let (v, overflow) = byte.overflowing_add(1);
        *byte = v;
        if !overflow {
            return;
        }
    }
}

/// Increment `security_nonce` until the PoW hash meets the target.
pub fn mine_header(header: &mut BlockHeader, max_attempts: u64) -> bool {
    if header.meets_target() {
        return true;
    }
    for _ in 0..max_attempts {
        increment_nonce(&mut header.security_nonce);
        if header.meets_target() {
            return true;
        }
    }
    false
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

/// Execute a body against `state`, then credit the block reward derived from `target`.
pub fn apply_body(
    state: &mut State,
    chain_id: &Hash,
    network: &NetworkProfile,
    target: U256,
    transactions: &[Transaction],
    timestamp_unix: u64,
    payout: &AccountId,
) -> Result<(), ConsensusError> {
    state.begin_block();
    for (index, tx) in transactions.iter().enumerate() {
        match tx {
            Transaction::Transfer(t) => {
                if t.version != PROTOCOL_VERSION {
                    return Err(reject(index, TxReject::BadVersion));
                }
                if &t.chain_id != chain_id {
                    return Err(reject(index, TxReject::BadChainId));
                }
                let sender = t.sender_id();
                if !vess_crypto::verify(
                    &t.sender_public_key,
                    DOM_TRANSFER,
                    &t.unsigned_bytes(),
                    &t.signature,
                ) {
                    return Err(reject(index, TxReject::BadSignature));
                }
                state
                    .execute_transfer(t, &sender, timestamp_unix, payout)
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
                    .execute_state_update(t, &sender, timestamp_unix, payout)
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
    timestamp_unix: u64,
    transactions: &[Transaction],
) -> Result<BlockTemplate, ConsensusError> {
    let parent_meta = chain.meta(parent_id).ok_or(ConsensusError::UnknownParent)?;
    let height = parent_meta
        .height
        .checked_add(1)
        .ok_or(ConsensusError::BadHeader)?;
    let target = required_target(chain, network, parent_id, height)?;
    let mtp = median_time_past(chain, parent_id)?;
    if timestamp_unix <= mtp || timestamp_unix > mtp.saturating_add(MAX_FUTURE_DRIFT_SECONDS) {
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
        timestamp_unix,
        payout,
    )?;

    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        chain_id: hash::chain_id(network.network),
        previous_block_id: *parent_id,
        transaction_root,
        state_root: state.root(),
        timestamp_unix,
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
        header.timestamp_unix,
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
