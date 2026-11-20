//! Bounded local admission policy. Never affects consensus validity.
//!
//! One pending signed transaction per account, fee-based replacement for the same nonce,
//! deterministic eviction, and a size-bounded template selector.

use vess_core::constants::{
    MAX_BLOCK_BYTES, MAX_TRANSACTION_BYTES, MEMPOOL_MAX_TRANSACTION_BYTES,
    MEMPOOL_MAX_TRANSACTIONS, MEMPOOL_PER_ACCOUNT_TRANSACTIONS,
};
use vess_core::{AccountId, Hash, Transaction};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolError {
    TooLarge,
    AccountBusy,
    WouldNotReplace,
    Full,
    Duplicate,
}

impl core::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            MempoolError::TooLarge => "object exceeds the mempool size limit",
            MempoolError::AccountBusy => "account already has a pending transaction",
            MempoolError::WouldNotReplace => "replacement fee is not strictly higher",
            MempoolError::Full => "mempool is full",
            MempoolError::Duplicate => "object already present",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    Replaced,
}

#[derive(Debug)]
pub enum AdmissionError<E> {
    Policy(MempoolError),
    Persistence(E),
}

#[derive(Debug, Clone)]
struct Entry {
    tx: Transaction,
    /// Every account the transaction debits. One for a transfer or a state update, one or more for a
    /// joint transaction.
    accounts: Vec<AccountId>,
    nonce: u64,
    fee: u64,
    size: usize,
    seq: u64,
}

/// The accounts a transaction debits, in canonical order.
fn tx_accounts(tx: &Transaction) -> Vec<AccountId> {
    match tx {
        Transaction::Transfer(t) => vec![t.sender_id()],
        Transaction::StateUpdate(t) => vec![t.sender_id()],
        Transaction::JointTransfer(t) => t.input_accounts(),
    }
}

/// The nonce a replacement has to beat. A joint transaction has one per input; the highest is the
/// only one that orders it against a later attempt by any participant.
fn tx_nonce(tx: &Transaction) -> u64 {
    match tx {
        Transaction::Transfer(t) => t.nonce,
        Transaction::StateUpdate(t) => t.nonce,
        Transaction::JointTransfer(t) => t.inputs.iter().map(|i| i.nonce).max().unwrap_or(0),
    }
}

fn tx_fee(tx: &Transaction) -> u64 {
    match tx {
        Transaction::Transfer(t) => t.fee,
        Transaction::StateUpdate(t) => t.fee,
        Transaction::JointTransfer(t) => t.fee,
    }
}

fn tx_expiry(tx: &Transaction) -> Option<u64> {
    let expiry = match tx {
        Transaction::Transfer(t) => t.expiry_unix,
        Transaction::StateUpdate(t) => t.expiry_unix,
        Transaction::JointTransfer(t) => t.expiry_unix,
    };
    (expiry != 0).then_some(expiry)
}

#[derive(Debug, Clone, Default)]
pub struct Mempool {
    entries: Vec<Entry>,
    pending_bytes: usize,
    seq: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn transaction_count(&self) -> usize {
        self.entries.len()
    }

    /// Everything currently admitted, for relaying to a peer.
    pub fn pending_transactions(&self) -> Vec<Transaction> {
        self.entries.iter().map(|entry| entry.tx.clone()).collect()
    }

    pub fn bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Admit a transfer or state update. Cryptographic validity is the caller's job.
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<AddOutcome, MempoolError> {
        match self.add_transaction_with(tx, |_| Ok::<_, std::convert::Infallible>(())) {
            Ok(outcome) => Ok(outcome),
            Err(AdmissionError::Policy(error)) => Err(error),
            Err(AdmissionError::Persistence(never)) => match never {},
        }
    }

    /// Persist the admission and removals before changing the in-memory pool.
    pub fn add_transaction_with<E>(
        &mut self,
        tx: Transaction,
        persist: impl FnOnce(&[Hash]) -> Result<(), E>,
    ) -> Result<AddOutcome, AdmissionError<E>> {
        let (accounts, nonce, fee, size) = (
            tx_accounts(&tx),
            tx_nonce(&tx),
            tx_fee(&tx),
            tx.canonical().len(),
        );
        if size > MAX_TRANSACTION_BYTES {
            return Err(AdmissionError::Policy(MempoolError::TooLarge));
        }

        if let Some(position) = self
            .entries
            .iter()
            .position(|e| e.accounts.iter().any(|a| accounts.contains(a)))
        {
            let existing = &self.entries[position];
            if existing.tx.id() == tx.id() {
                return Err(AdmissionError::Policy(MempoolError::Duplicate));
            }
            // Replacement is only well defined when both sides touch exactly one account: a joint
            // transaction occupies several, so any overlap is treated as a plain conflict.
            let replaceable = accounts.len() == 1
                && existing.accounts.len() == 1
                && existing.accounts[0] == accounts[0]
                && existing.nonce == nonce
                && fee > existing.fee;
            if !replaceable {
                return Err(AdmissionError::Policy(MempoolError::WouldNotReplace));
            }
            persist(&[self.entries[position].tx.id()]).map_err(AdmissionError::Persistence)?;
            let old_size = self.entries[position].size;
            self.pending_bytes = self.pending_bytes + size - old_size;
            let seq = self.next_seq();
            let existing = &mut self.entries[position];
            existing.tx = tx;
            existing.fee = fee;
            existing.size = size;
            existing.seq = seq;
            return Ok(AddOutcome::Replaced);
        }

        for account in &accounts {
            let per_account = self
                .entries
                .iter()
                .filter(|e| e.accounts.contains(account))
                .count();
            if per_account >= MEMPOOL_PER_ACCOUNT_TRANSACTIONS {
                return Err(AdmissionError::Policy(MempoolError::AccountBusy));
            }
        }

        let mut victims = Vec::new();
        let mut remaining_bytes = self.pending_bytes;
        if self.entries.len() >= MEMPOOL_MAX_TRANSACTIONS
            || remaining_bytes + size > MEMPOOL_MAX_TRANSACTION_BYTES
        {
            let mut candidates: Vec<usize> = (0..self.entries.len()).collect();
            candidates.sort_by_key(|&index| (self.entries[index].fee, self.entries[index].seq));
            for index in candidates {
                if self.entries.len() - victims.len() < MEMPOOL_MAX_TRANSACTIONS
                    && remaining_bytes + size <= MEMPOOL_MAX_TRANSACTION_BYTES
                {
                    break;
                }
                remaining_bytes -= self.entries[index].size;
                victims.push(index);
            }
        }
        if self.entries.len() - victims.len() >= MEMPOOL_MAX_TRANSACTIONS
            || remaining_bytes + size > MEMPOOL_MAX_TRANSACTION_BYTES
        {
            return Err(AdmissionError::Policy(MempoolError::Full));
        }
        let removed: Vec<Hash> = victims
            .iter()
            .map(|&index| self.entries[index].tx.id())
            .collect();
        persist(&removed).map_err(AdmissionError::Persistence)?;
        victims.sort_unstable_by(|a, b| b.cmp(a));
        for index in victims {
            self.entries.remove(index);
        }
        self.pending_bytes = remaining_bytes;

        let seq = self.next_seq();
        self.entries.push(Entry {
            tx,
            accounts,
            nonce,
            fee,
            size,
            seq,
        });
        self.pending_bytes += size;
        Ok(AddOutcome::Added)
    }

    pub fn transaction_id_for_account(&self, account: &AccountId) -> Option<Hash> {
        self.entries
            .iter()
            .find(|entry| entry.accounts.contains(account))
            .map(|entry| entry.tx.id())
    }

    pub fn transaction_ids_where(
        &self,
        mut predicate: impl FnMut(&Transaction) -> bool,
    ) -> Vec<Hash> {
        self.entries
            .iter()
            .filter(|entry| predicate(&entry.tx))
            .map(|entry| entry.tx.id())
            .collect()
    }

    /// Drop a transaction once it is included in a block (by id).
    pub fn remove_transaction(&mut self, id: &Hash) {
        if let Some(pos) = self.entries.iter().position(|e| &e.tx.id() == id) {
            let entry = self.entries.remove(pos);
            self.pending_bytes -= entry.size;
        }
    }

    /// Drop a transaction for an account whose state moved on (nonce consumed).
    pub fn remove_account(&mut self, account: &AccountId) {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.accounts.contains(account))
        {
            let entry = self.entries.remove(pos);
            self.pending_bytes -= entry.size;
        }
    }

    /// Remove expired objects. Returns the objects that were dropped.
    pub fn expire(&mut self, now: u64) -> Vec<Transaction> {
        let mut dropped = Vec::new();
        let mut index = 0;
        while index < self.entries.len() {
            let expired = tx_expiry(&self.entries[index].tx).is_some_and(|expiry| expiry < now);
            if expired {
                let entry = self.entries.remove(index);
                self.pending_bytes -= entry.size;
                dropped.push(entry.tx);
            } else {
                index += 1;
            }
        }

        dropped
    }

    /// Highest-fee-first selection that fits the block budget.
    pub fn select_for_template(&self, max_bytes: usize) -> Vec<Transaction> {
        let budget = max_bytes.min(MAX_BLOCK_BYTES);
        let mut chosen = Vec::new();
        let mut used = 4usize; // body count prefix

        let mut ordered: Vec<&Entry> = self.entries.iter().collect();
        ordered.sort_by(|a, b| b.fee.cmp(&a.fee).then(a.seq.cmp(&b.seq)));
        for entry in ordered {
            if used + entry.size > budget {
                continue;
            }
            used += entry.size;
            chosen.push(entry.tx.clone());
        }
        chosen
    }

    /// Re-admit everything still valid after a reorg. Invalid objects are dropped.
    pub fn retain_valid(&mut self, mut still_valid: impl FnMut(&Transaction) -> bool) {
        let mut dropped_bytes = 0usize;
        self.entries.retain(|entry| {
            if still_valid(&entry.tx) {
                true
            } else {
                dropped_bytes += entry.size;
                false
            }
        });
        self.pending_bytes -= dropped_bytes;
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_core::constants::{ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES, PROTOCOL_VERSION};
    use vess_core::{StateUpdate, Transfer, TransferAuthority};

    fn transfer(sender_byte: u8, nonce: u64, fee: u64) -> Transaction {
        Transaction::Transfer(Transfer {
            version: PROTOCOL_VERSION,
            chain_id: [1u8; 32],
            recipient_account_id: [0xEEu8; 32],
            amount: 1,
            fee,
            nonce,
            expiry_unix: 0,
            payload: None,
            authority: TransferAuthority::Signature {
                sender_public_key: [sender_byte; ML_DSA_PK_BYTES],
                signature: [0u8; ML_DSA_SIG_BYTES],
            },
        })
    }

    fn update(sender_byte: u8, nonce: u64, fee: u64) -> Transaction {
        Transaction::StateUpdate(StateUpdate {
            version: PROTOCOL_VERSION,
            chain_id: [1u8; 32],
            sender_public_key: [sender_byte; ML_DSA_PK_BYTES],
            new_state_hash: [7u8; 32],
            fee,
            nonce,
            expiry_unix: 0,
            signature: [0u8; ML_DSA_SIG_BYTES],
        })
    }

    #[test]
    fn one_pending_transaction_per_account() {
        let mut pool = Mempool::new();
        assert_eq!(
            pool.add_transaction(transfer(1, 0, 5)),
            Ok(AddOutcome::Added)
        );
        assert_eq!(
            pool.add_transaction(transfer(1, 0, 9)),
            Ok(AddOutcome::Replaced)
        );
        assert_eq!(pool.transaction_count(), 1);
        // A different nonce can never be added while one is pending.
        assert_eq!(
            pool.add_transaction(transfer(1, 1, 99)),
            Err(MempoolError::WouldNotReplace)
        );
    }

    #[test]
    fn replacement_requires_a_strictly_higher_fee() {
        let mut pool = Mempool::new();
        pool.add_transaction(transfer(1, 4, 10)).unwrap();
        // An identical object is a duplicate, not a replacement.
        assert_eq!(
            pool.add_transaction(transfer(1, 4, 10)),
            Err(MempoolError::Duplicate)
        );
        assert_eq!(
            pool.add_transaction(transfer(1, 4, 9)),
            Err(MempoolError::WouldNotReplace)
        );
        assert_eq!(
            pool.add_transaction(transfer(1, 4, 11)),
            Ok(AddOutcome::Replaced)
        );
        // The replaced transaction is gone.
        assert_eq!(pool.transaction_count(), 1);
    }

    #[test]
    fn failed_persistence_does_not_change_the_pool() {
        let mut pool = Mempool::new();
        let original = transfer(1, 0, 5);
        let original_id = original.id();
        pool.add_transaction(original).unwrap();
        let error = pool.add_transaction_with(transfer(1, 0, 9), |removed| {
            assert_eq!(removed, &[original_id]);
            Err("disk failure")
        });
        assert!(matches!(
            error,
            Err(AdmissionError::Persistence("disk failure"))
        ));
        assert_eq!(pool.pending_transactions()[0].id(), original_id);
        assert_eq!(pool.transaction_count(), 1);
    }

    #[test]
    fn different_accounts_coexist() {
        let mut pool = Mempool::new();
        pool.add_transaction(transfer(1, 0, 5)).unwrap();
        pool.add_transaction(update(2, 0, 5)).unwrap();
        assert_eq!(pool.transaction_count(), 2);
    }

    #[test]
    fn expiring_transactions_are_dropped() {
        let mut pool = Mempool::new();
        let mut tx = transfer(1, 0, 5);
        if let Transaction::Transfer(t) = &mut tx {
            t.expiry_unix = 100;
        }
        pool.add_transaction(tx).unwrap();
        assert!(pool.expire(100).is_empty());
        assert_eq!(pool.expire(101).len(), 1);
        assert_eq!(pool.transaction_count(), 0);
    }

    #[test]
    fn template_selection_prefers_fees_and_respects_the_budget() {
        let mut pool = Mempool::new();
        for (account, fee) in [(1u8, 1u64), (2, 50), (3, 10)] {
            pool.add_transaction(transfer(account, 0, fee)).unwrap();
        }
        let selected = pool.select_for_template(MAX_BLOCK_BYTES);
        assert_eq!(selected.len(), 3);
        let fees: Vec<u64> = selected
            .iter()
            .map(|tx| match tx {
                Transaction::Transfer(t) => t.fee,
                _ => 0,
            })
            .collect();
        assert_eq!(fees, vec![50, 10, 1]);

        // A tiny budget admits nothing (each transfer is ~5.3 KB).
        assert!(pool.select_for_template(1_000).is_empty());
    }

    fn indexed_transfer(index: usize, fee: u64) -> Transaction {
        let mut tx = transfer(0, 0, fee);
        if let Transaction::Transfer(Transfer {
            authority:
                TransferAuthority::Signature {
                    sender_public_key, ..
                },
            ..
        }) = &mut tx
        {
            sender_public_key[0] = (index & 0xff) as u8;
            sender_public_key[1] = ((index >> 8) & 0xff) as u8;
        }
        tx
    }

    #[test]
    fn eviction_prefers_the_lowest_fee() {
        let mut pool = Mempool::new();
        // Seed one cheap entry, then fill the pool with expensive ones.
        pool.add_transaction(indexed_transfer(0, 1)).unwrap();
        for index in 1..=MEMPOOL_MAX_TRANSACTIONS {
            let _ = pool.add_transaction(indexed_transfer(index, 50));
        }

        assert!(pool.transaction_count() <= MEMPOOL_MAX_TRANSACTIONS);
        assert!(
            !pool.entries.iter().any(|e| e.fee == 1),
            "the cheapest entry must be evicted first"
        );
        assert!(pool.entries.iter().all(|e| e.fee == 50));
    }

    #[test]
    fn eviction_reports_removed_ids_before_persistence() {
        let mut pool = Mempool::new();
        let victim = indexed_transfer(0, 1);
        let victim_id = victim.id();
        pool.add_transaction(victim).unwrap();
        let mut index = 1;
        loop {
            let next = indexed_transfer(index, 50);
            if pool.transaction_count() >= MEMPOOL_MAX_TRANSACTIONS
                || pool.bytes() + next.canonical().len() > MEMPOOL_MAX_TRANSACTION_BYTES
            {
                pool.add_transaction_with(next, |removed| {
                    assert_eq!(removed, &[victim_id]);
                    Ok::<_, ()>(())
                })
                .unwrap();
                break;
            }
            pool.add_transaction(next).unwrap();
            index += 1;
        }
        assert!(
            !pool
                .pending_transactions()
                .iter()
                .any(|tx| tx.id() == victim_id)
        );
    }
    #[test]
    fn removal_paths_are_consistent() {
        let mut pool = Mempool::new();
        let tx = transfer(1, 0, 5);
        let id = tx.id();
        pool.add_transaction(tx).unwrap();
        pool.remove_transaction(&id);
        assert_eq!(pool.transaction_count(), 0);
        assert_eq!(pool.bytes(), 0);
    }

    #[test]
    fn retain_valid_drops_rejected_objects() {
        let mut pool = Mempool::new();
        pool.add_transaction(transfer(1, 0, 5)).unwrap();
        pool.add_transaction(transfer(2, 0, 5)).unwrap();
        pool.retain_valid(
            |tx| matches!(tx, Transaction::Transfer(t) if t.sender_public_key().is_some_and(|k| k[0] == 1)),
        );
        assert_eq!(pool.transaction_count(), 1);
    }
}
