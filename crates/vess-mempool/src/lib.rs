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

#[derive(Debug, Clone)]
struct Entry {
    tx: Transaction,
    account: AccountId,
    nonce: u64,
    fee: u64,
    size: usize,
    seq: u64,
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
        let (account, nonce, fee, size) = match &tx {
            Transaction::Transfer(t) => (t.sender_id(), t.nonce, t.fee, tx.canonical().len()),
            Transaction::StateUpdate(t) => (t.sender_id(), t.nonce, t.fee, tx.canonical().len()),
        };
        if size > MAX_TRANSACTION_BYTES {
            return Err(MempoolError::TooLarge);
        }

        if let Some(position) = self.entries.iter().position(|e| e.account == account) {
            if self.entries[position].tx.id() == tx.id() {
                return Err(MempoolError::Duplicate);
            }
            if self.entries[position].nonce != nonce || fee <= self.entries[position].fee {
                return Err(MempoolError::WouldNotReplace);
            }
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

        let per_account = self.entries.iter().filter(|e| e.account == account).count();
        if per_account >= MEMPOOL_PER_ACCOUNT_TRANSACTIONS {
            return Err(MempoolError::AccountBusy);
        }

        while !self.entries.is_empty()
            && (self.entries.len() >= MEMPOOL_MAX_TRANSACTIONS
                || self.pending_bytes + size > MEMPOOL_MAX_TRANSACTION_BYTES)
        {
            if !self.evict_one() {
                break;
            }
        }
        if self.entries.len() >= MEMPOOL_MAX_TRANSACTIONS
            || self.pending_bytes + size > MEMPOOL_MAX_TRANSACTION_BYTES
        {
            return Err(MempoolError::Full);
        }

        let seq = self.next_seq();
        self.entries.push(Entry {
            tx,
            account,
            nonce,
            fee,
            size,
            seq,
        });
        self.pending_bytes += size;
        Ok(AddOutcome::Added)
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
        if let Some(pos) = self.entries.iter().position(|e| &e.account == account) {
            let entry = self.entries.remove(pos);
            self.pending_bytes -= entry.size;
        }
    }

    /// Remove expired objects. Returns the objects that were dropped.
    pub fn expire(&mut self, now: u64) -> Vec<Transaction> {
        let mut dropped = Vec::new();
        let mut index = 0;
        while index < self.entries.len() {
            let expired = match &self.entries[index].tx {
                Transaction::Transfer(t) => t.expiry_unix != 0 && t.expiry_unix < now,
                Transaction::StateUpdate(t) => t.expiry_unix != 0 && t.expiry_unix < now,
            };
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

    fn evict_one(&mut self) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let mut victim = 0;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.fee < self.entries[victim].fee
                || (entry.fee == self.entries[victim].fee && entry.seq < self.entries[victim].seq)
            {
                victim = index;
            }
        }
        let entry = self.entries.remove(victim);
        self.pending_bytes -= entry.size;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_core::constants::{ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES, PROTOCOL_VERSION};
    use vess_core::{StateUpdate, Transfer};

    fn transfer(sender_byte: u8, nonce: u64, fee: u64) -> Transaction {
        Transaction::Transfer(Transfer {
            version: PROTOCOL_VERSION,
            chain_id: [1u8; 32],
            sender_public_key: [sender_byte; ML_DSA_PK_BYTES],
            recipient_account_id: [0xEEu8; 32],
            amount: 1,
            fee,
            nonce,
            expiry_unix: 0,
            signature: [0u8; ML_DSA_SIG_BYTES],
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
        if let Transaction::Transfer(t) = &mut tx {
            t.sender_public_key[0] = (index & 0xff) as u8;
            t.sender_public_key[1] = ((index >> 8) & 0xff) as u8;
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
            |tx| matches!(tx, Transaction::Transfer(t) if t.sender_public_key[0] == 1),
        );
        assert_eq!(pool.transaction_count(), 1);
    }
}
