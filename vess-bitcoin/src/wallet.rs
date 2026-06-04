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
pub struct BurnTransactionPlan {
    pub transaction: Transaction,
    pub consumed_utxos: Vec<OwnedUtxo>,
    pub burn_commitment_payload: [u8; 32],
    pub canonical_output_values: Vec<u64>,
    pub first_owner_vk_hash: [u8; 32],
    pub burn_amount_sats: u64,
    pub fee_sats: u64,
}

#[derive(Debug, Clone)]
pub struct PendingBurn {
    pub txid: Txid,
    pub transaction: Transaction,
    pub consumed_utxos: Vec<OwnedUtxo>,
    pub first_owner_vk: Vec<u8>,
    pub first_owner_sk: Vec<u8>,
    pub first_owner_vk_hash: [u8; 32],
    pub burn_amount_sats: u64,
    pub fee_sats: u64,
    pub created_at: u64,
    pub last_broadcast_at: Option<u64>,
    pub broadcast_attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WalletTransactionUpdate {
    pub discovered_utxos: Vec<OwnedUtxo>,
    pub seen_pending_burns: Vec<Txid>,
    pub conflicted_pending_burns: Vec<Txid>,
}

impl WalletTransactionUpdate {
    pub fn has_state_change(&self) -> bool {
        !self.discovered_utxos.is_empty()
            || !self.seen_pending_burns.is_empty()
            || !self.conflicted_pending_burns.is_empty()
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
struct PersistedPendingBurn {
    transaction: Vec<u8>,
    consumed_utxos: Vec<PersistedOwnedUtxo>,
    first_owner_vk: Vec<u8>,
    first_owner_sk: Vec<u8>,
    first_owner_vk_hash: [u8; 32],
    burn_amount_sats: u64,
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
    pending_burns: Vec<PersistedPendingBurn>,
}

#[derive(Debug, Clone)]
pub struct BitcoinWallet {
    network: BitcoinNetwork,
    master_xpriv: Xpriv,
    next_external_index: u32,
    next_internal_index: u32,
    known_scripts: HashMap<ScriptBuf, DerivedKey>,
    utxos: HashMap<OutPoint, OwnedUtxo>,
    pending_burns: HashMap<Txid, PendingBurn>,
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
            pending_burns: HashMap::new(),
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
            pending_burns: self
                .pending_burns
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
        self.pending_burns.clear();

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
        for persisted in state.pending_burns {
            let pending = self.restore_pending_burn(&persisted)?;
            self.pending_burns.insert(pending.txid, pending);
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

    pub fn pending_burn_count(&self) -> usize {
        self.pending_burns.len()
    }

    pub fn pending_burns(&self) -> Vec<PendingBurn> {
        let mut pending: Vec<_> = self.pending_burns.values().cloned().collect();
        pending.sort_by_key(|burn| burn.created_at);
        pending
    }

    pub fn tracked_utxos(&self) -> Vec<OwnedUtxo> {
        let mut utxos: Vec<_> = self.utxos.values().cloned().collect();
        utxos.sort_by_key(|utxo| (utxo.outpoint.txid, utxo.outpoint.vout));
        utxos
    }

    pub fn pending_burns_ready_for_broadcast(
        &self,
        now: u64,
        retry_interval_secs: u64,
    ) -> Vec<PendingBurn> {
        let mut pending: Vec<_> = self
            .pending_burns
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

        if self.pending_burns.contains_key(&txid) {
            update.seen_pending_burns.push(txid);
        }

        let conflicted: Vec<Txid> = self
            .pending_burns
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
            self.pending_burns.remove(pending_txid);
        }
        update.conflicted_pending_burns = conflicted;

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

    pub fn queue_auto_burn_if_needed(
        &mut self,
        fee_sats: u64,
        now: u64,
    ) -> Result<Option<PendingBurn>> {
        let available = self.available_tracked_utxos();
        if available.is_empty() {
            return Ok(None);
        }

        let total_input_sats: u64 = available.iter().map(|utxo| utxo.value_sats).sum();
        if total_input_sats <= fee_sats {
            return Ok(None);
        }

        let burn_amount_sats = total_input_sats - fee_sats;
        let (first_owner_vk, first_owner_sk) = vess_foundry::spend_auth::generate_spend_keypair();
        let first_owner_vk_hash = vess_foundry::spend_auth::vk_hash(&first_owner_vk);
        let plan = self.build_burn_transaction_from_utxos(
            available.clone(),
            burn_amount_sats,
            fee_sats,
            Self::fixed_burn_script(),
            first_owner_vk_hash,
        )?;

        let pending = PendingBurn {
            txid: plan.transaction.compute_txid(),
            transaction: plan.transaction,
            consumed_utxos: plan.consumed_utxos,
            first_owner_vk,
            first_owner_sk,
            first_owner_vk_hash,
            burn_amount_sats,
            fee_sats,
            created_at: now,
            last_broadcast_at: None,
            broadcast_attempts: 0,
            last_error: None,
        };
        self.pending_burns.insert(pending.txid, pending.clone());
        Ok(Some(pending))
    }

    pub fn mark_pending_burn_broadcast_success(&mut self, txid: &Txid, now: u64) {
        if let Some(pending) = self.pending_burns.get_mut(txid) {
            pending.last_broadcast_at = Some(now);
            pending.broadcast_attempts = pending.broadcast_attempts.saturating_add(1);
            pending.last_error = None;
        }
    }

    pub fn mark_pending_burn_broadcast_failure(&mut self, txid: &Txid, now: u64, error: String) {
        if let Some(pending) = self.pending_burns.get_mut(txid) {
            pending.last_broadcast_at = Some(now);
            pending.broadcast_attempts = pending.broadcast_attempts.saturating_add(1);
            pending.last_error = Some(error);
        }
    }

    pub fn remove_pending_burn(&mut self, txid: &Txid) -> Option<PendingBurn> {
        self.pending_burns.remove(txid)
    }

    pub fn fixed_burn_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0]).to_p2wsh()
    }

    pub fn build_burn_transaction(
        &mut self,
        burn_amount_sats: u64,
        fee_sats: u64,
        burn_script_pubkey: ScriptBuf,
        first_owner_vk_hash: [u8; 32],
    ) -> Result<BurnTransactionPlan> {
        if burn_amount_sats == 0 {
            return Err(anyhow!("burn amount must be greater than zero"));
        }

        let target_total = burn_amount_sats
            .checked_add(fee_sats)
            .ok_or_else(|| anyhow!("burn amount + fee overflow"))?;

        let selected_utxos = self.select_utxos(target_total)?;
        let total_input_sats: u64 = selected_utxos.iter().map(|utxo| utxo.value_sats).sum();
        let change_sats = total_input_sats.saturating_sub(target_total);

        let mut change_script = None;
        if change_sats > 0 {
            let change = self.issue_change_address()?;
            change_script = Some(change.script_pubkey);
        }

        self.build_burn_transaction_from_utxos_with_change(
            selected_utxos,
            burn_amount_sats,
            fee_sats,
            burn_script_pubkey,
            first_owner_vk_hash,
            change_script,
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
            .pending_burns
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

    fn build_burn_transaction_from_utxos(
        &self,
        selected_utxos: Vec<OwnedUtxo>,
        burn_amount_sats: u64,
        fee_sats: u64,
        burn_script_pubkey: ScriptBuf,
        first_owner_vk_hash: [u8; 32],
    ) -> Result<BurnTransactionPlan> {
        self.build_burn_transaction_from_utxos_with_change(
            selected_utxos,
            burn_amount_sats,
            fee_sats,
            burn_script_pubkey,
            first_owner_vk_hash,
            None,
        )
    }

    fn build_burn_transaction_from_utxos_with_change(
        &self,
        selected_utxos: Vec<OwnedUtxo>,
        burn_amount_sats: u64,
        fee_sats: u64,
        burn_script_pubkey: ScriptBuf,
        first_owner_vk_hash: [u8; 32],
        change_script_pubkey: Option<ScriptBuf>,
    ) -> Result<BurnTransactionPlan> {
        if burn_amount_sats == 0 {
            return Err(anyhow!("burn amount must be greater than zero"));
        }

        let total_input_sats: u64 = selected_utxos.iter().map(|utxo| utxo.value_sats).sum();
        let target_total = burn_amount_sats
            .checked_add(fee_sats)
            .ok_or_else(|| anyhow!("burn amount + fee overflow"))?;
        if total_input_sats < target_total {
            return Err(anyhow!(
                "selected inputs do not cover burn amount + fee: have {total_input_sats}, need {target_total}"
            ));
        }
        let change_sats = total_input_sats - target_total;

        let canonical_output_values = vess_foundry::bitcoin_burn_output_values(burn_amount_sats);
        let burn_commitment_payload = vess_foundry::bitcoin_burn_payload_commitment(
            &first_owner_vk_hash,
            burn_amount_sats,
            &canonical_output_values,
        );

        let mut outputs = vec![
            TxOut {
                value: Amount::from_sat(burn_amount_sats),
                script_pubkey: burn_script_pubkey,
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new_op_return(burn_commitment_payload),
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

        Ok(BurnTransactionPlan {
            transaction: unsigned_tx,
            consumed_utxos: selected_utxos,
            burn_commitment_payload,
            canonical_output_values,
            first_owner_vk_hash,
            burn_amount_sats,
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

    fn persist_pending_burn(pending: PendingBurn) -> Result<PersistedPendingBurn> {
        Ok(PersistedPendingBurn {
            transaction: serialize(&pending.transaction),
            consumed_utxos: pending
                .consumed_utxos
                .into_iter()
                .map(Self::persist_owned_utxo)
                .collect(),
            first_owner_vk: pending.first_owner_vk,
            first_owner_sk: pending.first_owner_sk,
            first_owner_vk_hash: pending.first_owner_vk_hash,
            burn_amount_sats: pending.burn_amount_sats,
            fee_sats: pending.fee_sats,
            created_at: pending.created_at,
            last_broadcast_at: pending.last_broadcast_at,
            broadcast_attempts: pending.broadcast_attempts,
            last_error: pending.last_error,
        })
    }

    fn restore_pending_burn(&self, persisted: &PersistedPendingBurn) -> Result<PendingBurn> {
        let transaction: Transaction =
            deserialize(&persisted.transaction).context("deserialize persisted pending burn tx")?;
        let txid = transaction.compute_txid();
        Ok(PendingBurn {
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
            burn_amount_sats: persisted.burn_amount_sats,
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
    fn build_burn_transaction_signs_inputs_and_commits_payload() {
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
            .build_burn_transaction(40_000, 500, BitcoinWallet::fixed_burn_script(), owner_hash)
            .unwrap();

        assert_eq!(plan.burn_amount_sats, 40_000);
        assert_eq!(plan.fee_sats, 500);
        assert_eq!(plan.transaction.input.len(), 1);
        assert!(!plan.transaction.input[0].witness.is_empty());
        assert_eq!(plan.transaction.output[0].value.to_sat(), 40_000);
        assert_eq!(
            plan.burn_commitment_payload,
            vess_foundry::bitcoin_burn_payload_commitment(
                &owner_hash,
                40_000,
                &vess_foundry::bitcoin_burn_output_values(40_000)
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
        assert_eq!(pending.burn_amount_sats, 49_500);
        assert_eq!(pending.transaction.output.len(), 2);
        assert_eq!(wallet.spendable_tracked_balance(), 0);
        assert_eq!(wallet.pending_burn_count(), 1);
    }

    #[test]
    fn state_round_trip_restores_indexes_utxos_and_pending_burns() {
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
        assert_eq!(update.conflicted_pending_burns, vec![pending.txid]);
        assert_eq!(wallet.pending_burn_count(), 0);
    }

    #[test]
    fn txid_type_stays_constructible_in_tests() {
        let _ = Txid::all_zeros();
    }
}
