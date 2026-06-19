use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::ecdsa;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};

use crate::BitcoinNetwork;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Keychain {
    External,
    Internal,
}

#[derive(Debug, Clone)]
pub struct DerivedAddress {
    pub address: Address,
    pub script_pubkey: ScriptBuf,
    pub keychain: Keychain,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct OwnedUtxo {
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub script_pubkey: ScriptBuf,
    pub address: Address,
    pub keychain: Keychain,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct TimeLockTransactionPlan {
    pub transaction: Transaction,
    pub consumed_utxos: Vec<OwnedUtxo>,
    pub commitment_payload: [u8; 32],
    pub canonical_output_values: Vec<u64>,
    pub first_owner_vk_hash: [u8; 32],
    pub locked_sats: u64,
    pub fee_sats: u64,
}

#[derive(Debug, Clone)]
pub struct PendingTimeLock {
    pub txid: Txid,
    pub transaction: Transaction,
    pub consumed_utxos: Vec<OwnedUtxo>,
    pub first_owner_vk: Vec<u8>,
    pub first_owner_sk: Vec<u8>,
    pub first_owner_vk_hash: [u8; 32],
    pub locked_sats: u64,
    pub lock_blocks: u64,
    pub cltv_block_height: u64,
    pub vess_amount: u64,
    pub vichor_burned: u64,
    pub fee_sats: u64,
    pub created_at: u64,
    pub last_broadcast_at: Option<u64>,
    pub broadcast_attempts: u32,
    pub last_error: Option<String>,
}

/// A standard Bitcoin send (non-time-lock).
#[derive(Debug, Clone)]
pub struct SentTransaction {
    pub txid: Txid,
    pub transaction: Transaction,
    pub recipient: Address,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub sent_at: u64,
    pub confirmed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct WalletTransactionUpdate {
    pub discovered_utxos: Vec<OwnedUtxo>,
    pub seen_pending_timelocks: Vec<Txid>,
    pub conflicted_pending_timelocks: Vec<Txid>,
}

impl WalletTransactionUpdate {
    pub fn has_state_change(&self) -> bool {
        !self.discovered_utxos.is_empty()
            || !self.seen_pending_timelocks.is_empty()
            || !self.conflicted_pending_timelocks.is_empty()
    }
}

#[derive(Debug, Clone)]
struct DerivedKey {
    address: Address,
    keychain: Keychain,
    index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedOwnedUtxo {
    txid: [u8; 32],
    vout: u32,
    value_sats: u64,
    keychain: Keychain,
    index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedPendingTimeLock {
    transaction: Vec<u8>,
    consumed_utxos: Vec<PersistedOwnedUtxo>,
    first_owner_vk: Vec<u8>,
    first_owner_sk: Vec<u8>,
    first_owner_vk_hash: [u8; 32],
    locked_sats: u64,
    lock_blocks: u64,
    cltv_block_height: u64,
    vess_amount: u64,
    vichor_burned: u64,
    fee_sats: u64,
    created_at: u64,
    last_broadcast_at: Option<u64>,
    broadcast_attempts: u32,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedBitcoinWallet {
    network: BitcoinNetwork,
    next_external_index: u32,
    next_internal_index: u32,
    utxos: Vec<PersistedOwnedUtxo>,
    pending_timelocks: Vec<PersistedPendingTimeLock>,
}

#[derive(Debug, Clone)]
pub struct BitcoinWallet {
    network: BitcoinNetwork,
    master_xpriv: Xpriv,
    next_external_index: u32,
    next_internal_index: u32,
    known_scripts: HashMap<ScriptBuf, DerivedKey>,
    utxos: HashMap<OutPoint, OwnedUtxo>,
    pending_timelocks: HashMap<Txid, PendingTimeLock>,
}

impl BitcoinNetwork {
    pub fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Testnet => bitcoin::Network::Testnet,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }

    fn bip84_coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet | Self::Signet | Self::Regtest => 1,
        }
    }
}

impl BitcoinWallet {
    pub fn from_vess_seed(network: BitcoinNetwork, raw_seed: &[u8]) -> Result<Self> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vess-bitcoin-hd-seed-v0");
        hasher.update(raw_seed);
        let hd_seed = *hasher.finalize().as_bytes();
        let master_xpriv = Xpriv::new_master(network.bitcoin_network(), &hd_seed)
            .context("failed to derive bitcoin HD root from Vess seed")?;

        Ok(Self {
            network,
            master_xpriv,
            next_external_index: 0,
            next_internal_index: 0,
            known_scripts: HashMap::new(),
            utxos: HashMap::new(),
            pending_timelocks: HashMap::new(),
        })
    }

    pub fn from_vess_seed_with_state(
        network: BitcoinNetwork,
        raw_seed: &[u8],
        state_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        let mut wallet = Self::from_vess_seed(network, raw_seed)?;
        if let Some(bytes) = state_bytes {
            wallet.import_state_bytes(bytes)?;
        }
        Ok(wallet)
    }

    pub fn export_state_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&PersistedBitcoinWallet {
            network: self.network,
            next_external_index: self.next_external_index,
            next_internal_index: self.next_internal_index,
            utxos: self
                .utxos
                .values()
                .cloned()
                .map(Self::persist_owned_utxo)
                .collect(),
            pending_timelocks: self
                .pending_timelocks
                .values()
                .cloned()
                .map(Self::persist_pending_burn)
                .collect::<Result<Vec<_>>>()?,
        })
        .context("serialize bitcoin wallet state")
    }

    pub fn import_state_bytes(&mut self, state_bytes: &[u8]) -> Result<()> {
        let state: PersistedBitcoinWallet =
            serde_json::from_slice(state_bytes).context("deserialize bitcoin wallet state")?;
        if state.network != self.network {
            return Err(anyhow!(
                "bitcoin wallet state network mismatch: expected {:?}, found {:?}",
                self.network,
                state.network
            ));
        }

        self.next_external_index = state.next_external_index;
        self.next_internal_index = state.next_internal_index;
        self.known_scripts.clear();
        self.utxos.clear();
        self.pending_timelocks.clear();

        for index in 0..self.next_external_index {
            let derived = self.derive_address(Keychain::External, index)?;
            self.remember_address(&derived);
        }
        for index in 0..self.next_internal_index {
            let derived = self.derive_address(Keychain::Internal, index)?;
            self.remember_address(&derived);
        }

        for persisted in state.utxos {
            let utxo = self.restore_owned_utxo(&persisted)?;
            self.utxos.insert(utxo.outpoint, utxo);
        }
        for persisted in state.pending_timelocks {
            let pending = self.restore_pending_burn(&persisted)?;
            self.pending_timelocks.insert(pending.txid, pending);
        }

        Ok(())
    }

    pub fn preview_next_receive_address(&self) -> Result<DerivedAddress> {
        self.derive_address(Keychain::External, self.next_external_index)
    }

    pub fn current_receive_address(&self) -> Result<Option<DerivedAddress>> {
        if self.next_external_index == 0 {
            Ok(None)
        } else {
            self.derive_address(Keychain::External, self.next_external_index - 1)
                .map(Some)
        }
    }

    pub fn ensure_receive_address(&mut self) -> Result<DerivedAddress> {
        if let Some(existing) = self.current_receive_address()? {
            self.remember_address(&existing);
            Ok(existing)
        } else {
            self.issue_receive_address()
        }
    }

    pub fn issue_receive_address(&mut self) -> Result<DerivedAddress> {
        let derived = self.derive_address(Keychain::External, self.next_external_index)?;
        self.next_external_index = self
            .next_external_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("bitcoin receive address index overflow"))?;
        self.remember_address(&derived);
        Ok(derived)
    }

    pub fn total_tracked_balance(&self) -> u64 {
        self.utxos.values().map(|utxo| utxo.value_sats).sum()
    }

    pub fn spendable_tracked_balance(&self) -> u64 {
        self.available_tracked_utxos()
            .iter()
            .map(|utxo| utxo.value_sats)
            .sum()
    }

    pub fn pending_timelock_count(&self) -> usize {
        self.pending_timelocks.len()
    }

    pub fn pending_timelocks(&self) -> Vec<PendingTimeLock> {
        let mut pending: Vec<_> = self.pending_timelocks.values().cloned().collect();
        pending.sort_by_key(|burn| burn.created_at);
        pending
    }

    pub fn tracked_utxos(&self) -> Vec<OwnedUtxo> {
        let mut utxos: Vec<_> = self.utxos.values().cloned().collect();
        utxos.sort_by_key(|utxo| (utxo.outpoint.txid, utxo.outpoint.vout));
        utxos
    }

    pub fn pending_timelocks_ready_for_broadcast(
        &self,
        now: u64,
        retry_interval_secs: u64,
    ) -> Vec<PendingTimeLock> {
        let mut pending: Vec<_> = self
            .pending_timelocks
            .values()
            .filter(|burn| {
                burn.last_broadcast_at
                    .map(|last| now.saturating_sub(last) >= retry_interval_secs)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        pending.sort_by_key(|burn| burn.created_at);
        pending
    }

    pub fn record_transaction(&mut self, tx: &Transaction) -> WalletTransactionUpdate {
        let txid = tx.compute_txid();
        let spent_outpoints: HashSet<_> =
            tx.input.iter().map(|input| input.previous_output).collect();
        let mut update = WalletTransactionUpdate::default();

        if self.pending_timelocks.contains_key(&txid) {
            update.seen_pending_timelocks.push(txid);
        }

        let conflicted: Vec<Txid> = self
            .pending_timelocks
            .iter()
            .filter_map(|(pending_txid, pending)| {
                if *pending_txid == txid {
                    return None;
                }
                pending
                    .consumed_utxos
                    .iter()
                    .any(|utxo| spent_outpoints.contains(&utxo.outpoint))
                    .then_some(*pending_txid)
            })
            .collect();
        for pending_txid in &conflicted {
            self.pending_timelocks.remove(pending_txid);
        }
        update.conflicted_pending_timelocks = conflicted;

        for input in &tx.input {
            self.utxos.remove(&input.previous_output);
        }

        for (vout, output) in tx.output.iter().enumerate() {
            if let Some(known) = self.known_scripts.get(&output.script_pubkey) {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                if self.utxos.contains_key(&outpoint) {
                    continue;
                }
                let utxo = OwnedUtxo {
                    outpoint,
                    value_sats: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.clone(),
                    address: known.address.clone(),
                    keychain: known.keychain,
                    index: known.index,
                };
                self.utxos.insert(outpoint, utxo.clone());
                update.discovered_utxos.push(utxo);
            }
        }

        update
    }

    /// Mint Vess by time-locking a percentage of available BTC.
    ///
    /// # Arguments
    /// - `percentage` — fraction of spendable balance to lock (1.0–100.0).
    /// - `duration_years` — how many years to lock, in 0.1 increments
    ///   (0.1–10.0). 1.0 = 1 year (default), 1.5 = 1.5 years, etc.
    /// - `fee_sats` — miner fee in satoshis.
    /// - `current_height` — latest known Bitcoin block height.
    /// - `now` — Unix timestamp for the pending record.
    ///
    /// # Vichor gate
    ///
    /// Locks ≤1 year are free. Duration is in 0.1-year increments.
    /// Beyond 1 year: 10 Vichor per full year, 1 per 0.1 step.
    ///
    /// ```text
    /// vichor_required = max(0, (years - 1.0) × 10)
    /// ```
    ///
    /// 1.0 = 0, 1.1 = 1, 2.0 = 10, 5.0 = 40, 10.0 = 90.
    /// Long-term speculators subsidize the network before accessing leverage.
    ///
    /// Returns the pending time-lock ready for broadcast.
    pub fn mint_timelock(
        &mut self,
        percentage: f64,
        duration_years: f64,
        fee_sats: u64,
        current_height: u64,
        now: u64,
        vichor_burned: u64,
        vichor_burn_digest: Option<[u8; 32]>,
    ) -> Result<PendingTimeLock> {
        // Validate percentage
        if percentage <= 0.0 || percentage > 100.0 {
            return Err(anyhow!(
                "percentage must be between 0 and 100, got {percentage}"
            ));
        }

        // Validate and clamp duration — must be in 0.1 year increments.
        let duration_years = duration_years.clamp(0.1, 10.0);
        // Round to nearest 0.1 to enforce discrete increments.
        let duration_years = (duration_years * 10.0).round() / 10.0;
        let lock_blocks = (duration_years * vess_foundry::BLOCKS_PER_YEAR as f64) as u64;
        if lock_blocks < vess_foundry::MIN_LOCK_BLOCKS {
            return Err(anyhow!(
                "duration too short: {duration_years} years = {lock_blocks} blocks (min {})",
                vess_foundry::MIN_LOCK_BLOCKS
            ));
        }

        // Vichor gate: free ≤1 year, then quadratic (y-1)²×10 in 0.1 increments.
        let vichor_required = vess_foundry::vichor_required_for_years(duration_years);
        if vichor_burned < vichor_required {
            return Err(anyhow!(
                "duration {duration_years} years requires {vichor_required} Vichor burned, got {vichor_burned}"
            ));
        }
        // If Vichor is required, the burn proof MUST be cryptographically
        // committed in the Bitcoin transaction's OP_RETURN.
        if vichor_required > 0 && vichor_burn_digest.is_none() {
            return Err(anyhow!(
                "duration >1 year requires a VichorBurnProof committed in the time-lock transaction"
            ));
        }

        let spendable = self.spendable_tracked_balance();
        if spendable <= fee_sats {
            return Err(anyhow!(
                "spendable balance {spendable} sats insufficient to cover fee {fee_sats}"
            ));
        }

        let target_sats = ((spendable as f64) * (percentage / 100.0)) as u64;
        let locked_sats = target_sats.saturating_sub(fee_sats);
        if locked_sats == 0 {
            return Err(anyhow!(
                "fee {fee_sats} consumes entire target amount {target_sats} sats"
            ));
        }

        let cltv_block_height = current_height + lock_blocks;
        let vess_amount = vess_foundry::compute_vess_amount(locked_sats, lock_blocks);
        if vess_amount == 0 {
            return Err(anyhow!(
                "lock produces 0 Vess — increase amount or duration"
            ));
        }

        let (first_owner_vk, first_owner_sk) = vess_foundry::spend_auth::generate_spend_keypair();
        let first_owner_vk_hash = vess_foundry::spend_auth::vk_hash(&first_owner_vk);

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let owner_privkey = self.derive_private_key(Keychain::External, 0)?;
        let owner_pubkey = owner_privkey.inner.public_key(&secp);
        let bitcoin_pubkey = bitcoin::PublicKey::new(owner_pubkey);

        let plan = self.build_timelock_transaction(
            locked_sats,
            fee_sats,
            cltv_block_height,
            current_height,
            &bitcoin_pubkey,
            first_owner_vk_hash,
            vichor_burn_digest,
        )?;

        let pending = PendingTimeLock {
            txid: plan.transaction.compute_txid(),
            transaction: plan.transaction,
            consumed_utxos: plan.consumed_utxos,
            first_owner_vk,
            first_owner_sk,
            first_owner_vk_hash,
            locked_sats,
            lock_blocks,
            cltv_block_height,
            vess_amount,
            vichor_burned,
            fee_sats,
            created_at: now,
            last_broadcast_at: None,
            broadcast_attempts: 0,
            last_error: None,
        };
        self.pending_timelocks.insert(pending.txid, pending.clone());
        Ok(pending)
    }

    pub fn mark_pending_timelock_broadcast_success(&mut self, txid: &Txid, now: u64) {
        if let Some(pending) = self.pending_timelocks.get_mut(txid) {
            pending.last_broadcast_at = Some(now);
            pending.broadcast_attempts = pending.broadcast_attempts.saturating_add(1);
            pending.last_error = None;
        }
    }

    pub fn mark_pending_timelock_broadcast_failure(&mut self, txid: &Txid, now: u64, error: String) {
        if let Some(pending) = self.pending_timelocks.get_mut(txid) {
            pending.last_broadcast_at = Some(now);
            pending.broadcast_attempts = pending.broadcast_attempts.saturating_add(1);
            pending.last_error = Some(error);
        }
    }

    pub fn remove_pending_timelock(&mut self, txid: &Txid) -> Option<PendingTimeLock> {
        self.pending_timelocks.remove(txid)
    }

    /// Build a standard Bitcoin transaction sending `amount_sats` to `recipient`.
    ///
    /// Selects UTXOs, creates outputs [recipient, change], signs all inputs.
    /// Returns the signed transaction ready for broadcast.
    pub fn send_to_address(
        &mut self,
        recipient: &Address,
        amount_sats: u64,
        fee_sats: u64,
    ) -> Result<Transaction> {
        if amount_sats == 0 {
            return Err(anyhow!("send amount must be greater than zero"));
        }

        let target_total = amount_sats
            .checked_add(fee_sats)
            .ok_or_else(|| anyhow!("send amount + fee overflow"))?;

        let selected_utxos = self.select_utxos(target_total)?;
        let total_input_sats: u64 = selected_utxos.iter().map(|utxo| utxo.value_sats).sum();
        let change_sats = total_input_sats - target_total;

        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: recipient.script_pubkey(),
        }];

        if change_sats > 0 {
            let change = self.issue_change_address()?;
            outputs.push(TxOut {
                value: Amount::from_sat(change_sats),
                script_pubkey: change.script_pubkey,
            });
        }

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: selected_utxos
                .iter()
                .map(|utxo| TxIn {
                    previous_output: utxo.outpoint,
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                })
                .collect(),
            output: outputs,
        };

        self.sign_p2wpkh_inputs(&mut tx, &selected_utxos)?;
        Ok(tx)
    }

    /// Sweep all available UTXOs to `recipient`, minus `fee_sats`.
    ///
    /// Sends the entire spendable balance. Returns the signed transaction
    /// and the total amount sent.
    pub fn sweep_to_address(
        &mut self,
        recipient: &Address,
        fee_sats: u64,
    ) -> Result<(Transaction, u64)> {
        let utxos = self.available_tracked_utxos();
        if utxos.is_empty() {
            return Err(anyhow!("no spendable UTXOs available"));
        }

        let total_input_sats: u64 = utxos.iter().map(|utxo| utxo.value_sats).sum();
        if total_input_sats <= fee_sats {
            return Err(anyhow!(
                "balance {total_input_sats} sats insufficient to cover fee {fee_sats}"
            ));
        }

        let amount_sats = total_input_sats - fee_sats;

        let outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: recipient.script_pubkey(),
        }];

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: utxos
                .iter()
                .map(|utxo| TxIn {
                    previous_output: utxo.outpoint,
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                })
                .collect(),
            output: outputs,
        };

        self.sign_p2wpkh_inputs(&mut tx, &utxos)?;
        Ok((tx, amount_sats))
    }

    /// Build a CLTV time-lock script that locks funds until `cltv_height`.
    ///
    /// Script: `<cltv_height> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG`
    ///
    /// The funds can only be spent by `pubkey` after block `cltv_height`.
    pub fn build_timelock_script(
        pubkey: &bitcoin::PublicKey,
        cltv_height: u64,
    ) -> ScriptBuf {
        let height_blocks = bitcoin::blockdata::locktime::absolute::Height::from_consensus(
            cltv_height as u32,
        )
        .expect("CLTV height must fit in u32");
        bitcoin::blockdata::script::Builder::new()
            .push_lock_time(height_blocks.into())
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CLTV)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_DROP)
            .push_key(pubkey)
            .push_opcode(bitcoin::blockdata::opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    pub fn build_timelock_transaction(
        &mut self,
        locked_sats: u64,
        fee_sats: u64,
        cltv_block_height: u64,
        current_height: u64,
        owner_pubkey: &bitcoin::PublicKey,
        first_owner_vk_hash: [u8; 32],
        vichor_burn_digest: Option<[u8; 32]>,
    ) -> Result<TimeLockTransactionPlan> {
        if locked_sats == 0 {
            return Err(anyhow!("timelock amount must be greater than zero"));
        }
        if cltv_block_height <= current_height {
            return Err(anyhow!(
                "CLTV height {cltv_block_height} must be above current height {current_height}"
            ));
        }

        let lock_blocks = cltv_block_height - current_height;
        let vess_amount = vess_foundry::compute_vess_amount(locked_sats, lock_blocks);
        let timelock_script = Self::build_timelock_script(owner_pubkey, cltv_block_height);

        let target_total = locked_sats
            .checked_add(fee_sats)
            .ok_or_else(|| anyhow!("timelock amount + fee overflow"))?;

        let selected_utxos = self.select_utxos(target_total)?;

        self.build_timelock_transaction_with_change(
            selected_utxos,
            locked_sats,
            fee_sats,
            timelock_script,
            first_owner_vk_hash,
            None,
            lock_blocks,
            vess_amount,
            vichor_burn_digest,
        )
    }

    fn issue_change_address(&mut self) -> Result<DerivedAddress> {
        let derived = self.derive_address(Keychain::Internal, self.next_internal_index)?;
        self.next_internal_index = self
            .next_internal_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("bitcoin change address index overflow"))?;
        self.remember_address(&derived);
        Ok(derived)
    }

    fn remember_address(&mut self, derived: &DerivedAddress) {
        self.known_scripts.insert(
            derived.script_pubkey.clone(),
            DerivedKey {
                address: derived.address.clone(),
                keychain: derived.keychain,
                index: derived.index,
            },
        );
    }

    fn available_tracked_utxos(&self) -> Vec<OwnedUtxo> {
        let reserved: HashSet<OutPoint> = self
            .pending_timelocks
            .values()
            .flat_map(|pending| pending.consumed_utxos.iter().map(|utxo| utxo.outpoint))
            .collect();
        self.tracked_utxos()
            .into_iter()
            .filter(|utxo| !reserved.contains(&utxo.outpoint))
            .collect()
    }

    fn derive_address(&self, keychain: Keychain, index: u32) -> Result<DerivedAddress> {
        let secp = Secp256k1::new();
        let path = self.derivation_path(keychain, index)?;
        let child_xpriv = self
            .master_xpriv
            .derive_priv(&secp, &path)
            .with_context(|| format!("failed to derive bitcoin path {path}"))?;
        let private_key = child_xpriv.to_priv();
        let public_key = bitcoin::CompressedPublicKey::from_private_key(&secp, &private_key)
            .context("failed to derive compressed bitcoin pubkey")?;
        let address = Address::p2wpkh(&public_key, self.network.bitcoin_network());
        Ok(DerivedAddress {
            script_pubkey: address.script_pubkey(),
            address,
            keychain,
            index,
        })
    }

    fn derivation_path(&self, keychain: Keychain, index: u32) -> Result<DerivationPath> {
        let chain = match keychain {
            Keychain::External => 0,
            Keychain::Internal => 1,
        };
        Ok(vec![
            ChildNumber::from_hardened_idx(84).context("invalid purpose index")?,
            ChildNumber::from_hardened_idx(self.network.bip84_coin_type())
                .context("invalid coin type index")?,
            ChildNumber::from_hardened_idx(0).context("invalid account index")?,
            ChildNumber::from_normal_idx(chain).context("invalid keychain index")?,
            ChildNumber::from_normal_idx(index).context("invalid address index")?,
        ]
        .into())
    }

    fn derive_private_key(&self, keychain: Keychain, index: u32) -> Result<bitcoin::PrivateKey> {
        let secp = Secp256k1::new();
        let path = self.derivation_path(keychain, index)?;
        let child = self
            .master_xpriv
            .derive_priv(&secp, &path)
            .with_context(|| format!("failed to derive bitcoin signer path {path}"))?;
        Ok(child.to_priv())
    }

    fn select_utxos(&self, target_total: u64) -> Result<Vec<OwnedUtxo>> {
        let mut utxos = self.available_tracked_utxos();
        utxos.sort_by_key(|utxo| utxo.value_sats);

        let mut selected = Vec::new();
        let mut running = 0u64;
        for utxo in utxos {
            running = running
                .checked_add(utxo.value_sats)
                .ok_or_else(|| anyhow!("bitcoin UTXO sum overflow"))?;
            selected.push(utxo);
            if running >= target_total {
                return Ok(selected);
            }
        }

        Err(anyhow!(
            "insufficient tracked bitcoin funds: need {target_total} sats, have {running} sats"
        ))
    }

    fn build_timelock_transaction_internal(
        &self,
        selected_utxos: Vec<OwnedUtxo>,
        locked_sats: u64,
        fee_sats: u64,
        timelock_script_pubkey: ScriptBuf,
        first_owner_vk_hash: [u8; 32],
        lock_blocks: u64,
        vess_amount: u64,
        vichor_burn_digest: Option<[u8; 32]>,
    ) -> Result<TimeLockTransactionPlan> {
        self.build_timelock_transaction_with_change(
            selected_utxos,
            locked_sats,
            fee_sats,
            timelock_script_pubkey,
            first_owner_vk_hash,
            None,
            lock_blocks,
            vess_amount,
            vichor_burn_digest,
        )
    }

    fn build_timelock_transaction_with_change(
        &self,
        selected_utxos: Vec<OwnedUtxo>,
        locked_sats: u64,
        fee_sats: u64,
        timelock_script_pubkey: ScriptBuf,
        first_owner_vk_hash: [u8; 32],
        change_script_pubkey: Option<ScriptBuf>,
        lock_blocks: u64,
        vess_amount: u64,
        vichor_burn_digest: Option<[u8; 32]>,
    ) -> Result<TimeLockTransactionPlan> {
        if locked_sats == 0 {
            return Err(anyhow!("timelock amount must be greater than zero"));
        }

        // Locks >1 year require a VichorBurnProof committed in OP_RETURN.
        if lock_blocks > vess_foundry::BLOCKS_PER_YEAR && vichor_burn_digest.is_none() {
            return Err(anyhow!(
                "time-lock >1 year ({lock_blocks} blocks) requires a VichorBurnProof"
            ));
        }

        let total_input_sats: u64 = selected_utxos.iter().map(|utxo| utxo.value_sats).sum();
        let target_total = locked_sats
            .checked_add(fee_sats)
            .ok_or_else(|| anyhow!("burn amount + fee overflow"))?;
        if total_input_sats < target_total {
            return Err(anyhow!(
                "selected inputs do not cover burn amount + fee: have {total_input_sats}, need {target_total}"
            ));
        }
        let change_sats = total_input_sats - target_total;

        let canonical_output_values = vess_foundry::bitcoin_timelock_output_values(vess_amount);
        let commitment_payload = vess_foundry::bitcoin_timelock_payload_commitment(
            &first_owner_vk_hash,
            locked_sats,
            lock_blocks,
            &canonical_output_values,
            vichor_burn_digest.as_ref(),
        );

        let mut outputs = vec![
            TxOut {
                value: Amount::from_sat(locked_sats),
                script_pubkey: timelock_script_pubkey,
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new_op_return(commitment_payload),
            },
        ];
        if let Some(change_script) = change_script_pubkey {
            if change_sats > 0 {
                outputs.push(TxOut {
                    value: Amount::from_sat(change_sats),
                    script_pubkey: change_script,
                });
            }
        } else if change_sats > 0 {
            return Err(anyhow!(
                "change of {change_sats} sats requires an explicit change script"
            ));
        }

        let mut unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: selected_utxos
                .iter()
                .map(|utxo| TxIn {
                    previous_output: utxo.outpoint,
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                })
                .collect(),
            output: outputs,
        };

        self.sign_p2wpkh_inputs(&mut unsigned_tx, &selected_utxos)?;

        Ok(TimeLockTransactionPlan {
            transaction: unsigned_tx,
            consumed_utxos: selected_utxos,
            commitment_payload,
            canonical_output_values,
            first_owner_vk_hash,
            locked_sats,
            fee_sats,
        })
    }

    fn sign_p2wpkh_inputs(&self, tx: &mut Transaction, utxos: &[OwnedUtxo]) -> Result<()> {
        let secp = Secp256k1::new();
        let sighash_type = EcdsaSighashType::All;
        let mut sighasher = SighashCache::new(tx);

        for (input_index, utxo) in utxos.iter().enumerate() {
            let private_key = self.derive_private_key(utxo.keychain, utxo.index)?;
            let sighash = sighasher
                .p2wpkh_signature_hash(
                    input_index,
                    &utxo.script_pubkey,
                    Amount::from_sat(utxo.value_sats),
                    sighash_type,
                )
                .with_context(|| {
                    format!(
                        "failed to compute sighash for bitcoin input {} ({})",
                        input_index, utxo.outpoint
                    )
                })?;

            let msg = Message::from(sighash);
            let signature = secp.sign_ecdsa(&msg, &private_key.inner);
            let signature = ecdsa::Signature {
                signature,
                sighash_type,
            };
            let public_key = private_key.inner.public_key(&secp);
            *sighasher
                .witness_mut(input_index)
                .ok_or_else(|| anyhow!("missing witness slot for bitcoin input {input_index}"))? =
                Witness::p2wpkh(&signature, &public_key);
        }

        Ok(())
    }

    fn persist_owned_utxo(utxo: OwnedUtxo) -> PersistedOwnedUtxo {
        PersistedOwnedUtxo {
            txid: utxo.outpoint.txid.to_byte_array(),
            vout: utxo.outpoint.vout,
            value_sats: utxo.value_sats,
            keychain: utxo.keychain,
            index: utxo.index,
        }
    }

    fn restore_owned_utxo(&self, persisted: &PersistedOwnedUtxo) -> Result<OwnedUtxo> {
        let derived = self.derive_address(persisted.keychain, persisted.index)?;
        Ok(OwnedUtxo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array(persisted.txid),
                vout: persisted.vout,
            },
            value_sats: persisted.value_sats,
            script_pubkey: derived.script_pubkey,
            address: derived.address,
            keychain: persisted.keychain,
            index: persisted.index,
        })
    }

    fn persist_pending_burn(pending: PendingTimeLock) -> Result<PersistedPendingTimeLock> {
        Ok(PersistedPendingTimeLock {
            transaction: serialize(&pending.transaction),
            consumed_utxos: pending
                .consumed_utxos
                .into_iter()
                .map(Self::persist_owned_utxo)
                .collect(),
            first_owner_vk: pending.first_owner_vk,
            first_owner_sk: pending.first_owner_sk,
            first_owner_vk_hash: pending.first_owner_vk_hash,
            locked_sats: pending.locked_sats,
            lock_blocks: pending.lock_blocks,
            cltv_block_height: pending.cltv_block_height,
            vess_amount: pending.vess_amount,
            vichor_burned: pending.vichor_burned,
            fee_sats: pending.fee_sats,
            created_at: pending.created_at,
            last_broadcast_at: pending.last_broadcast_at,
            broadcast_attempts: pending.broadcast_attempts,
            last_error: pending.last_error,
        })
    }

    fn restore_pending_burn(&self, persisted: &PersistedPendingTimeLock) -> Result<PendingTimeLock> {
        let transaction: Transaction =
            deserialize(&persisted.transaction).context("deserialize persisted pending burn tx")?;
        let txid = transaction.compute_txid();
        Ok(PendingTimeLock {
            txid,
            transaction,
            consumed_utxos: persisted
                .consumed_utxos
                .iter()
                .map(|utxo| self.restore_owned_utxo(utxo))
                .collect::<Result<Vec<_>>>()?,
            first_owner_vk: persisted.first_owner_vk.clone(),
            first_owner_sk: persisted.first_owner_sk.clone(),
            first_owner_vk_hash: persisted.first_owner_vk_hash,
            locked_sats: persisted.locked_sats,
            lock_blocks: persisted.lock_blocks,
            cltv_block_height: persisted.cltv_block_height,
            vess_amount: persisted.vess_amount,
            vichor_burned: persisted.vichor_burned,
            fee_sats: persisted.fee_sats,
            created_at: persisted.created_at,
            last_broadcast_at: persisted.last_broadcast_at,
            broadcast_attempts: persisted.broadcast_attempts,
            last_error: persisted.last_error.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn seed() -> [u8; 64] {
        [7u8; 64]
    }

    #[test]
    fn derived_receive_address_is_deterministic() {
        let wallet_a = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();
        let wallet_b = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();

        let addr_a = wallet_a.preview_next_receive_address().unwrap();
        let addr_b = wallet_b.preview_next_receive_address().unwrap();

        assert_eq!(addr_a.address, addr_b.address);
        assert_eq!(addr_a.script_pubkey, addr_b.script_pubkey);
    }

    #[test]
    fn record_transaction_discovers_owned_output() {
        let mut wallet = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();
        let receive = wallet.issue_receive_address().unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(12_345),
                script_pubkey: receive.script_pubkey.clone(),
            }],
        };

        let update = wallet.record_transaction(&tx);

        assert_eq!(update.discovered_utxos.len(), 1);
        assert_eq!(update.discovered_utxos[0].value_sats, 12_345);
        assert_eq!(wallet.total_tracked_balance(), 12_345);
    }

    #[test]
    fn build_timelock_transaction_signs_inputs_and_commits_payload() {
        let mut wallet = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();
        let receive = wallet.issue_receive_address().unwrap();
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: receive.script_pubkey.clone(),
            }],
        };
        wallet.record_transaction(&funding_tx);

        let owner_hash = [9u8; 32];
        let plan = wallet
            .build_timelock_transaction(40_000, 500, BitcoinWallet::fixed_timelock_script(), owner_hash)
            .unwrap();

        assert_eq!(plan.locked_sats, 40_000);
        assert_eq!(plan.fee_sats, 500);
        assert_eq!(plan.transaction.input.len(), 1);
        assert!(!plan.transaction.input[0].witness.is_empty());
        assert_eq!(plan.transaction.output[0].value.to_sat(), 40_000);
        assert_eq!(
            plan.commitment_payload,
            vess_foundry::bitcoin_timelock_payload_commitment(
                &owner_hash,
                40_000,
                &vess_foundry::bitcoin_timelock_output_values(40_000)
            )
        );
    }

    #[test]
    fn auto_burn_uses_all_spendable_balance_without_change() {
        let mut wallet = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();
        let receive = wallet.issue_receive_address().unwrap();
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: receive.script_pubkey.clone(),
            }],
        };
        wallet.record_transaction(&funding_tx);

        let pending = wallet.queue_auto_burn_if_needed(500, 123).unwrap().unwrap();
        assert_eq!(pending.locked_sats, 49_500);
        assert_eq!(pending.transaction.output.len(), 2);
        assert_eq!(wallet.spendable_tracked_balance(), 0);
        assert_eq!(wallet.pending_burn_count(), 1);
    }

    #[test]
    fn state_round_trip_restores_indexes_utxos_and_pending_timelocks() {
        let mut wallet = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();
        let receive = wallet.issue_receive_address().unwrap();
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(60_000),
                script_pubkey: receive.script_pubkey.clone(),
            }],
        };
        wallet.record_transaction(&funding_tx);
        wallet.queue_auto_burn_if_needed(500, 321).unwrap();

        let state = wallet.export_state_bytes().unwrap();
        let restored = BitcoinWallet::from_vess_seed_with_state(
            BitcoinNetwork::Testnet,
            &seed(),
            Some(&state),
        )
        .unwrap();

        assert_eq!(restored.pending_burn_count(), 1);
        assert_eq!(restored.total_tracked_balance(), 60_000);
        assert_eq!(restored.spendable_tracked_balance(), 0);
        assert_eq!(
            restored.current_receive_address().unwrap().unwrap().address,
            wallet.current_receive_address().unwrap().unwrap().address
        );
    }

    #[test]
    fn record_transaction_removes_spent_owned_utxo() {
        let mut wallet = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();
        let receive = wallet.issue_receive_address().unwrap();
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(20_000),
                script_pubkey: receive.script_pubkey.clone(),
            }],
        };
        let discovered = wallet.record_transaction(&funding_tx);
        assert_eq!(discovered.discovered_utxos.len(), 1);

        let spending_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(19_000),
                script_pubkey: ScriptBuf::new_op_return([1u8; 32]),
            }],
        };
        let update = wallet.record_transaction(&spending_tx);
        assert!(update.discovered_utxos.is_empty());
        assert_eq!(wallet.total_tracked_balance(), 0);
    }

    #[test]
    fn record_transaction_evicts_conflicting_pending_burn() {
        let mut wallet = BitcoinWallet::from_vess_seed(BitcoinNetwork::Testnet, &seed()).unwrap();
        let receive = wallet.issue_receive_address().unwrap();
        let funding_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: receive.script_pubkey.clone(),
            }],
        };
        wallet.record_transaction(&funding_tx);

        let pending = wallet.queue_auto_burn_if_needed(500, 123).unwrap().unwrap();
        assert_eq!(wallet.pending_burn_count(), 1);

        let conflicting_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: pending
                .consumed_utxos
                .iter()
                .map(|utxo| TxIn {
                    previous_output: utxo.outpoint,
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new_op_return([0xAB; 32]),
            }],
        };

        let update = wallet.record_transaction(&conflicting_tx);
        assert_eq!(update.conflicted_pending_timelocks, vec![pending.txid]);
        assert_eq!(wallet.pending_burn_count(), 0);
    }

    #[test]
    fn txid_type_stays_constructible_in_tests() {
        let _ = Txid::all_zeros();
    }
}






