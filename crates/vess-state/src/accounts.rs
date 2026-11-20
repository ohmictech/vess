//! Account state: balances, nonces, commitments, and a reversible change log.
//!
//! One asset, `Vess`. There is no mint transaction: new balance enters only as a block reward or as a
//! transaction fee, both of which consensus credits through [`State::credit`].

use std::collections::BTreeMap;

use vess_core::constants::{MAX_TRANSFER_INPUTS, MAX_TRANSFER_OUTPUTS};
use vess_core::hash;
use vess_core::types::{
    Account, AccountId, AccountWitness, Hash, JointTransfer, StateUpdate, Transfer,
};

use crate::error::StateError;
use crate::merkle::SparseMerkle;
use crate::undo::{StateChange, UndoLog};

#[derive(Debug, Clone, Default)]
pub struct State {
    accounts: BTreeMap<AccountId, Account>,
    account_tree: SparseMerkle,
    log: UndoLog,
    /// Running sum of every balance.
    ///
    /// Supply changes only by mint-like credits (the block reward), so maintaining it as accounts are
    /// written keeps [`State::total_supply`] O(1) for the consensus and mempool paths that evaluate a
    /// supply delta per candidate transaction.
    supply: u128,
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
        state.supply = state.accounts.values().map(|a| a.balance as u128).sum();
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
        self.supply
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

    /// Everything needed to prove this account's value under the current root, in about
    /// `log2(accounts)` hashes rather than 256.
    pub fn witness(&self, id: &AccountId) -> AccountWitness {
        AccountWitness {
            id: *id,
            account: self.accounts.get(id).copied(),
            siblings: self.account_tree.compact_proof(id),
        }
    }

    /// Rebuild a state from witnesses alone, or `None` if they do not open `account_root`.
    ///
    /// Each proof is checked against `account_root` on its own, and the reconstructed partial tree
    /// must then agree with it — a witness that is missing an account fails that second check rather
    /// than quietly describing a different state.
    ///
    /// `total_supply` is the network total the witness claims, because supply is not derivable from a
    /// subset of accounts. A wrong value cannot make an invalid block verify: the only rule that reads
    /// it is the futures settlement, which compares the split it derives against outputs fixed by the
    /// block, so a lie makes a valid block fail rather than an invalid one pass.
    pub fn from_witnesses(
        witnesses: &[AccountWitness],
        account_root: &Hash,
        total_supply: u128,
    ) -> Option<State> {
        let mut proofs = Vec::with_capacity(witnesses.len());
        let mut accounts = BTreeMap::new();
        for witness in witnesses {
            let value = witness.account.map(|account| account.leaf_value().to_vec());
            if !SparseMerkle::verify_compact_proof(
                account_root,
                &witness.id,
                value.as_deref(),
                &witness.siblings,
            ) {
                return None;
            }
            if let Some(account) = witness.account {
                accounts.insert(witness.id, account);
            }
            proofs.push((witness.id, value, witness.siblings.clone()));
        }
        let state = State {
            accounts,
            account_tree: SparseMerkle::from_proofs(&proofs),
            log: UndoLog::new(),
            supply: total_supply,
        };
        (state.account_root() == *account_root).then_some(state)
    }

    pub fn root(&self) -> Hash {
        hash::state_root(&self.account_root())
    }

    // -------------------------------------------------------------- mutation

    /// Write an account back and refresh its committed leaf.
    fn put_account(&mut self, id: AccountId, account: Account) {
        let previous = self.accounts.get(&id).copied();
        self.log.record_account(id, previous);
        self.adjust_supply(previous, Some(account));
        self.accounts.insert(id, account);
        self.account_tree.insert(id, account.leaf_value().to_vec());
    }

    /// Keep [`Self::supply`] exact across an account write, removal, or undo.
    fn adjust_supply(&mut self, before: Option<Account>, after: Option<Account>) {
        let before = before.map_or(0u128, |a| a.balance as u128);
        let after = after.map_or(0u128, |a| a.balance as u128);
        self.supply = self.supply - before + after;
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
                StateChange::Account(id, previous) => {
                    let current = self.accounts.get(&id).copied();
                    self.adjust_supply(current, previous);
                    match previous {
                        Some(account) => {
                            self.accounts.insert(id, account);
                            self.account_tree.insert(id, account.leaf_value().to_vec());
                        }
                        None => {
                            self.accounts.remove(&id);
                            self.account_tree.remove(&id);
                        }
                    }
                }
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

    /// Apply a joint transaction: several debits, several credits, all or nothing.
    ///
    /// Every input is validated before anything is written, so a transaction that fails halfway
    /// leaves the state untouched. The canonical-form checks here — ascending unique accounts,
    /// non-zero amounts, inputs equal to outputs plus fee — are the same rules every node applies, so
    /// two parties building the body independently cannot disagree about what it means.
    pub fn execute_joint_transfer(
        &mut self,
        tx: &JointTransfer,
        block_timestamp: u64,
        payout: &AccountId,
    ) -> Result<(), StateError> {
        if tx.expiry_unix != 0 && block_timestamp > tx.expiry_unix {
            return Err(StateError::Expired);
        }
        if tx.inputs.is_empty() || tx.outputs.is_empty() {
            return Err(StateError::EmptyTransaction);
        }
        if tx.inputs.len() > MAX_TRANSFER_INPUTS || tx.outputs.len() > MAX_TRANSFER_OUTPUTS {
            return Err(StateError::Oversized);
        }

        let mut debits = Vec::with_capacity(tx.inputs.len());
        let mut total_in = 0u64;
        for input in &tx.inputs {
            let id = input.account_id();
            if let Some(previous) = debits.last().map(|(id, _): &(AccountId, u64)| *id)
                && id <= previous
            {
                return Err(StateError::DuplicateInput);
            }
            if input.amount == 0 {
                return Err(StateError::ZeroAmount);
            }
            let account = self.accounts.get(&id).ok_or(StateError::UnknownAccount)?;
            if account.next_nonce != input.nonce {
                return Err(StateError::BadNonce);
            }
            if account.balance < input.amount {
                return Err(StateError::InsufficientBalance);
            }
            total_in = total_in
                .checked_add(input.amount)
                .ok_or(StateError::Overflow)?;
            debits.push((id, input.amount));
        }

        let mut total_out = 0u64;
        let mut previous: Option<AccountId> = None;
        for output in &tx.outputs {
            if let Some(previous) = previous
                && output.account_id <= previous
            {
                return Err(StateError::DuplicateOutput);
            }
            previous = Some(output.account_id);
            if output.amount == 0 {
                return Err(StateError::ZeroAmount);
            }
            total_out = total_out
                .checked_add(output.amount)
                .ok_or(StateError::Overflow)?;
        }
        if total_in != total_out.checked_add(tx.fee).ok_or(StateError::Overflow)? {
            return Err(StateError::Unbalanced);
        }

        for (id, amount) in debits {
            let mut account = *self.accounts.get(&id).ok_or(StateError::UnknownAccount)?;
            account.balance -= amount;
            account.next_nonce = account
                .next_nonce
                .checked_add(1)
                .ok_or(StateError::Overflow)?;
            self.put_account(id, account);
        }
        for output in &tx.outputs {
            self.credit(output.account_id, output.amount)?;
        }
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
            recipient_account_id: recipient(),
            amount,
            fee,
            nonce,
            expiry_unix: 0,
            payload: None,
            authority: vess_core::TransferAuthority::Signature {
                sender_public_key: [9u8; ML_DSA_PK_BYTES],
                signature: [0u8; ML_DSA_SIG_BYTES],
            },
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

    /// A public key whose derived account id is stable, so a test can credit exactly that account.
    fn joint_key(id: u8) -> vess_core::PublicKey {
        [id; ML_DSA_PK_BYTES]
    }

    fn joint_account(id: u8) -> AccountId {
        vess_core::hash::account_id(&joint_key(id))
    }

    fn joint_input(id: u8, amount: u64, nonce: u64) -> vess_core::TransferInput {
        vess_core::TransferInput {
            authority: vess_core::InputAuthority::Signature {
                public_key: joint_key(id),
                signature: [0u8; ML_DSA_SIG_BYTES],
            },
            amount,
            nonce,
        }
    }

    /// A joint transfer over keys 1 and 4, in canonical (ascending account) order.
    fn joint(amounts: (u64, u64), fee: u64) -> vess_core::JointTransfer {
        let mut inputs = vec![joint_input(1, amounts.0, 0), joint_input(4, amounts.1, 0)];
        inputs.sort_by_key(vess_core::TransferInput::account_id);
        let credited = amounts.0 + amounts.1 - fee;
        let mut outputs = vec![vess_core::Output {
            account_id: recipient(),
            amount: credited,
        }];
        outputs.sort_by_key(|output| output.account_id);
        vess_core::JointTransfer {
            version: vess_core::constants::TRANSACTION_VERSION_JOINT,
            chain_id: vess_core::hash::chain_id(0),
            inputs,
            fee,
            expiry_unix: 0,
            outputs,
        }
    }

    #[test]
    fn a_joint_transfer_debits_every_input_and_credits_every_output() {
        let mut state = State::new();
        state.credit(joint_account(1), 100).unwrap();
        state.credit(joint_account(4), 100).unwrap();
        state
            .execute_joint_transfer(&joint((40, 40), 5), 0, &payout())
            .unwrap();
        assert_eq!(state.balance(&joint_account(1)), 60);
        assert_eq!(state.balance(&joint_account(4)), 60);
        assert_eq!(state.balance(&recipient()), 75);
        assert_eq!(state.balance(&payout()), 5);
        assert_eq!(state.next_nonce(&joint_account(1)), Some(1));
        assert_eq!(state.next_nonce(&joint_account(4)), Some(1));
        // Moving balance is not issuing it.
        assert_eq!(state.total_supply(), 200);
    }

    #[test]
    fn a_joint_transfer_is_all_or_nothing() {
        let mut state = State::new();
        state.credit(joint_account(1), 100).unwrap();
        state.credit(joint_account(4), 10).unwrap();
        let before = state.root();
        assert_eq!(
            state.execute_joint_transfer(&joint((40, 40), 0), 0, &payout()),
            Err(StateError::InsufficientBalance)
        );
        // The first input would have been debited had the transaction been applied piecemeal.
        assert_eq!(state.root(), before);
        assert_eq!(state.balance(&joint_account(1)), 100);
        assert_eq!(state.next_nonce(&joint_account(1)), Some(0));
    }

    #[test]
    fn a_joint_transfer_rejects_non_canonical_shapes() {
        let mut state = State::new();
        state.credit(joint_account(1), 1_000).unwrap();
        state.credit(joint_account(4), 1_000).unwrap();

        let duplicate = vess_core::JointTransfer {
            inputs: vec![joint_input(1, 10, 0), joint_input(1, 10, 1)],
            outputs: vec![vess_core::Output {
                account_id: recipient(),
                amount: 20,
            }],
            ..joint((40, 40), 0)
        };
        assert_eq!(
            state.execute_joint_transfer(&duplicate, 0, &payout()),
            Err(StateError::DuplicateInput)
        );

        let unbalanced = vess_core::JointTransfer {
            fee: 0,
            outputs: vec![vess_core::Output {
                account_id: recipient(),
                amount: 79,
            }],
            ..joint((40, 40), 0)
        };
        assert_eq!(
            state.execute_joint_transfer(&unbalanced, 0, &payout()),
            Err(StateError::Unbalanced)
        );

        let zero = vess_core::JointTransfer {
            inputs: vec![joint_input(1, 0, 0)],
            outputs: vec![vess_core::Output {
                account_id: recipient(),
                amount: 1,
            }],
            ..joint((40, 40), 0)
        };
        assert_eq!(
            state.execute_joint_transfer(&zero, 0, &payout()),
            Err(StateError::ZeroAmount)
        );

        let duplicate_outputs = vess_core::JointTransfer {
            outputs: vec![
                vess_core::Output {
                    account_id: recipient(),
                    amount: 40,
                },
                vess_core::Output {
                    account_id: recipient(),
                    amount: 40,
                },
            ],
            ..joint((40, 40), 0)
        };
        assert_eq!(
            state.execute_joint_transfer(&duplicate_outputs, 0, &payout()),
            Err(StateError::DuplicateOutput)
        );
    }

    /// Supply is a running total, so it has to survive credits, debits, and an undo exactly.
    #[test]
    fn supply_is_exact_across_credits_and_undo() {
        let mut state = funded(1_000);
        assert_eq!(state.total_supply(), 1_000);
        state.credit(payout(), 50).unwrap();
        assert_eq!(state.total_supply(), 1_050);

        state.begin_block();
        state
            .execute_transfer(&transfer(100, 5, 0), &sender(), 0, &payout())
            .unwrap();
        assert_eq!(state.total_supply(), 1_050);
        let log = state.take_undo();
        state.apply_undo(log);
        assert_eq!(state.total_supply(), 1_050);
        assert_eq!(state.balance(&recipient()), 0);

        let restored = State::restore(
            state
                .accounts_iter()
                .map(|(id, account)| (*id, *account))
                .collect::<Vec<_>>(),
        );
        assert_eq!(restored.total_supply(), state.total_supply());
    }
}
