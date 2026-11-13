//! Account state: balances, nonces, commitments, and a reversible change log.
//!
//! One asset, `Vess`. There is no mint transaction: new balance enters only as a block reward or as a
//! transaction fee, both of which consensus credits through [`State::credit`].

use std::collections::BTreeMap;

use vess_core::hash;
use vess_core::types::{Account, AccountId, Hash, StateUpdate, Transfer};

use crate::error::StateError;
use crate::merkle::SparseMerkle;
use crate::undo::{StateChange, UndoLog};

#[derive(Debug, Clone, Default)]
pub struct State {
    accounts: BTreeMap<AccountId, Account>,
    account_tree: SparseMerkle,
    log: UndoLog,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild a state from persisted rows. Used at startup; the caller is responsible for having
    /// validated every block that produced these rows.
    pub fn restore(accounts: impl IntoIterator<Item = (AccountId, Account)>) -> State {
        let mut state = State::default();
        for (id, account) in accounts {
            state.accounts.insert(id, account);
            state.account_tree.insert(id, account.leaf_value().to_vec());
        }
        state
    }

    // ------------------------------------------------------------- inspection

    pub fn account(&self, id: &AccountId) -> Option<Account> {
        self.accounts.get(id).copied()
    }

    pub fn accounts_iter(&self) -> impl Iterator<Item = (&AccountId, &Account)> {
        self.accounts.iter()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn balance(&self, id: &AccountId) -> u64 {
        self.accounts.get(id).map(|a| a.balance).unwrap_or(0)
    }

    pub fn next_nonce(&self, id: &AccountId) -> Option<u64> {
        self.accounts.get(id).map(|a| a.next_nonce)
    }

    /// Total balance across every account. Supply is the sum of balances, because the only way
    /// balance enters is the block reward.
    pub fn total_supply(&self) -> u128 {
        self.accounts.values().map(|a| a.balance as u128).sum()
    }

    pub fn account_root(&self) -> Hash {
        self.account_tree.root()
    }

    /// The committed leaf value for an account, if it exists.
    pub fn account_leaf_value(&self, id: &AccountId) -> Option<Vec<u8>> {
        self.accounts.get(id).map(|a| a.leaf_value().to_vec())
    }

    /// 256-level inclusion (or non-inclusion) proof against `account_root`.
    pub fn account_proof(&self, id: &AccountId) -> Vec<Hash> {
        self.account_tree.proof(id)
    }

    pub fn root(&self) -> Hash {
        hash::state_root(&self.account_root())
    }

    // -------------------------------------------------------------- mutation

    /// Write an account back and refresh its committed leaf.
    fn put_account(&mut self, id: AccountId, account: Account) {
        let previous = self.accounts.get(&id).copied();
        self.log.record_account(id, previous);
        self.accounts.insert(id, account);
        self.account_tree.insert(id, account.leaf_value().to_vec());
    }

    /// Start recording an undo log for the block about to be applied.
    pub fn begin_block(&mut self) {
        self.log.clear();
    }

    /// Take the undo log for the block just applied.
    pub fn take_undo(&mut self) -> UndoLog {
        let log = std::mem::take(&mut self.log);
        self.log.clear();
        log
    }

    /// Reverse a block's changes, restoring the exact prior accounts.
    pub fn apply_undo(&mut self, log: UndoLog) {
        for change in log.into_changes().into_iter().rev() {
            match change {
                StateChange::Account(id, previous) => match previous {
                    Some(account) => {
                        self.accounts.insert(id, account);
                        self.account_tree.insert(id, account.leaf_value().to_vec());
                    }
                    None => {
                        self.accounts.remove(&id);
                        self.account_tree.remove(&id);
                    }
                },
            }
        }
    }

    /// Credit an account, creating it at zero if absent. Consensus calls this only for the block
    /// reward and for transaction fees; no other path may create balance.
    pub fn credit(&mut self, id: AccountId, amount: u64) -> Result<(), StateError> {
        if amount == 0 {
            return Ok(());
        }
        let mut account = self.accounts.get(&id).copied().unwrap_or_default();
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or(StateError::Overflow)?;
        self.put_account(id, account);
        Ok(())
    }

    /// Apply a transfer whose signature and sender binding the caller has already verified.
    pub fn execute_transfer(
        &mut self,
        tx: &Transfer,
        sender: &AccountId,
        block_timestamp: u64,
        payout: &AccountId,
    ) -> Result<(), StateError> {
        if tx.amount == 0 {
            return Err(StateError::ZeroAmount);
        }
        if tx.expiry_unix != 0 && block_timestamp > tx.expiry_unix {
            return Err(StateError::Expired);
        }

        let mut account = *self
            .accounts
            .get(sender)
            .ok_or(StateError::UnknownAccount)?;
        if account.next_nonce != tx.nonce {
            return Err(StateError::BadNonce);
        }
        let total = tx.amount.checked_add(tx.fee).ok_or(StateError::Overflow)?;
        if account.balance < total {
            return Err(StateError::InsufficientBalance);
        }
        account.balance -= total;
        account.next_nonce = account
            .next_nonce
            .checked_add(1)
            .ok_or(StateError::Overflow)?;
        self.put_account(*sender, account);

        self.credit(tx.recipient_account_id, tx.amount)?;
        self.credit(*payout, tx.fee)?;
        Ok(())
    }

    /// Apply a state update whose signature and sender binding the caller has already verified.
    pub fn execute_state_update(
        &mut self,
        tx: &StateUpdate,
        sender: &AccountId,
        block_timestamp: u64,
        payout: &AccountId,
    ) -> Result<(), StateError> {
        if tx.expiry_unix != 0 && block_timestamp > tx.expiry_unix {
            return Err(StateError::Expired);
        }

        let mut account = *self
            .accounts
            .get(sender)
            .ok_or(StateError::UnknownAccount)?;
        if account.next_nonce != tx.nonce {
            return Err(StateError::BadNonce);
        }
        if account.balance < tx.fee {
            return Err(StateError::InsufficientBalance);
        }

        account.balance -= tx.fee;
        account.next_nonce = account
            .next_nonce
            .checked_add(1)
            .ok_or(StateError::Overflow)?;
        account.state_hash = tx.new_state_hash;
        self.put_account(*sender, account);

        self.credit(*payout, tx.fee)?;
        Ok(())
    }

    /// Credit the block reward to the payout account.
    pub fn credit_block_reward(
        &mut self,
        payout: &AccountId,
        amount: u64,
    ) -> Result<(), StateError> {
        self.credit(*payout, amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vess_core::constants::{
        MAX_TRANSACTION_BYTES, ML_DSA_PK_BYTES, ML_DSA_SIG_BYTES, PROTOCOL_VERSION,
    };
    use vess_core::hash::chain_id;

    fn sender() -> AccountId {
        [1u8; 32]
    }

    fn recipient() -> AccountId {
        [2u8; 32]
    }

    fn payout() -> AccountId {
        [3u8; 32]
    }

    fn funded(balance: u64) -> State {
        let mut state = State::new();
        state.credit(sender(), balance).unwrap();
        state
    }

    fn transfer(amount: u64, fee: u64, nonce: u64) -> Transfer {
        Transfer {
            version: PROTOCOL_VERSION,
            chain_id: chain_id(0),
            sender_public_key: [9u8; ML_DSA_PK_BYTES],
            recipient_account_id: recipient(),
            amount,
            fee,
            nonce,
            expiry_unix: 0,
            signature: [0u8; ML_DSA_SIG_BYTES],
        }
    }

    #[test]
    fn credit_creates_and_adds() {
        let state = funded(100);
        assert_eq!(state.balance(&sender()), 100);
        assert_eq!(state.account_count(), 1);
    }

    #[test]
    fn transfer_moves_amount_and_pays_the_fee() {
        let mut state = funded(1_000);
        state
            .execute_transfer(&transfer(400, 25, 0), &sender(), 0, &payout())
            .unwrap();
        assert_eq!(state.balance(&sender()), 575);
        assert_eq!(state.balance(&recipient()), 400);
        assert_eq!(state.balance(&payout()), 25);
    }

    #[test]
    fn transfer_advances_the_nonce() {
        let mut state = funded(1_000);
        state
            .execute_transfer(&transfer(1, 0, 0), &sender(), 0, &payout())
            .unwrap();
        assert_eq!(state.next_nonce(&sender()), Some(1));
        assert_eq!(
            state.execute_transfer(&transfer(1, 0, 0), &sender(), 0, &payout()),
            Err(StateError::BadNonce)
        );
    }

    #[test]
    fn transfer_rejects_overspend_and_zero() {
        let mut state = funded(100);
        assert_eq!(
            state.execute_transfer(&transfer(101, 0, 0), &sender(), 0, &payout()),
            Err(StateError::InsufficientBalance)
        );
        assert_eq!(
            state.execute_transfer(&transfer(0, 0, 0), &sender(), 0, &payout()),
            Err(StateError::ZeroAmount)
        );
    }

    #[test]
    fn transfer_honours_expiry() {
        let mut state = funded(100);
        let mut tx = transfer(10, 0, 0);
        tx.expiry_unix = 50;
        assert_eq!(
            state.execute_transfer(&tx, &sender(), 51, &payout()),
            Err(StateError::Expired)
        );
        tx.expiry_unix = 0;
        assert!(
            state
                .execute_transfer(&tx, &sender(), 10_000, &payout())
                .is_ok()
        );
    }

    #[test]
    fn state_update_charges_the_fee_and_sets_the_hash() {
        let mut state = funded(100);
        let tx = StateUpdate {
            version: PROTOCOL_VERSION,
            chain_id: chain_id(0),
            sender_public_key: [9u8; ML_DSA_PK_BYTES],
            new_state_hash: [7u8; 32],
            fee: 20,
            nonce: 0,
            expiry_unix: 0,
            signature: [0u8; ML_DSA_SIG_BYTES],
        };
        state
            .execute_state_update(&tx, &sender(), 0, &payout())
            .unwrap();
        assert_eq!(state.balance(&sender()), 80);
        assert_eq!(state.balance(&payout()), 20);
        assert_eq!(state.account(&sender()).unwrap().state_hash, [7u8; 32]);
    }

    #[test]
    fn block_reward_is_the_only_issuance_path() {
        let mut state = State::new();
        state.credit_block_reward(&payout(), 50).unwrap();
        assert_eq!(state.total_supply(), 50);
        // Fees move balance; they do not create it.
        state.credit(recipient(), 100).unwrap();
        state
            .execute_transfer(&transfer(10, 5, 0), &recipient(), 0, &payout())
            .unwrap();
        assert_eq!(state.total_supply(), 150);
    }

    #[test]
    fn undo_restores_accounts_exactly() {
        let mut state = funded(1_000);
        let before_root = state.root();
        state.begin_block();
        state
            .execute_transfer(&transfer(400, 25, 0), &sender(), 0, &payout())
            .unwrap();
        state.credit_block_reward(&payout(), 50).unwrap();
        let log = state.take_undo();
        assert_ne!(state.root(), before_root);
        state.apply_undo(log);
        assert_eq!(state.root(), before_root);
        assert_eq!(state.balance(&sender()), 1_000);
        assert_eq!(state.balance(&recipient()), 0);
        assert_eq!(state.account_count(), 1);
    }

    #[test]
    fn root_commits_to_balances_and_nonces() {
        let a = funded(10);
        let mut b = funded(11);
        assert_ne!(a.root(), b.root());
        b.credit(recipient(), 1).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn restore_rebuilds_the_same_root() {
        let mut state = funded(500);
        state.credit_block_reward(&payout(), 50).unwrap();
        let root = state.root();
        let restored = State::restore(
            state
                .accounts_iter()
                .map(|(id, account)| (*id, *account))
                .collect::<Vec<_>>(),
        );
        assert_eq!(restored.root(), root);
    }

    #[test]
    fn proofs_verify_against_the_account_root() {
        let state = funded(7);
        let proof = state.account_proof(&sender());
        let value = state.account_leaf_value(&sender()).unwrap();
        assert!(crate::merkle::SparseMerkle::verify_proof(
            &state.account_root(),
            &sender(),
            Some(&value),
            &proof
        ));
        // Non-inclusion for an untouched account.
        let proof = state.account_proof(&recipient());
        assert!(crate::merkle::SparseMerkle::verify_proof(
            &state.account_root(),
            &recipient(),
            None,
            &proof
        ));
    }

    #[test]
    fn transaction_size_bound_is_respected() {
        // A transfer with the largest signature still fits a transaction.
        let bytes = vess_core::codec::to_bytes(&transfer(u64::MAX, u64::MAX, u64::MAX));
        assert!(bytes.len() < MAX_TRANSACTION_BYTES);
    }
}
