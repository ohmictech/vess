//! Independent replay of the history behind a trusted snapshot.

use std::path::Path;

use vess_consensus::chain::Chain;
use vess_consensus::{ConsensusError, split_block, validate_block};
use vess_core::constants::NetworkProfile;
use vess_core::hash;
use vess_core::{BlockHeader, Hash};
use vess_state::State;
use vess_storage::Store;

use crate::NodeError;

pub struct HistoryVerifier {
    store: Store,
    chain: Chain,
    state: State,
}

pub enum ReplayError {
    /// The peer did not supply the body committed by the requested header.
    WrongBody,
    /// The committed body itself fails consensus validation.
    Invalid(String),
    Storage(NodeError),
}

impl HistoryVerifier {
    pub fn open(datadir: &Path, network: NetworkProfile) -> Result<Self, NodeError> {
        std::fs::create_dir_all(datadir)?;
        let store = Store::open(&datadir.join("ledger.redb"), network)?;
        let chain = store.load_chain()?;
        let state = store.load_state()?;
        Ok(Self {
            store,
            chain,
            state,
        })
    }

    pub fn height(&self) -> u64 {
        self.chain.best_height()
    }

    pub fn tip(&self) -> Hash {
        self.chain.best_id()
    }

    pub fn root(&self) -> Hash {
        self.state.root()
    }

    pub fn reset(&mut self, network: NetworkProfile) -> Result<(), NodeError> {
        self.store.reset_replay()?;
        self.chain = Chain::new(network);
        self.state = State::new();
        Ok(())
    }

    pub fn replay(
        &mut self,
        expected: &BlockHeader,
        bytes: &[u8],
        network: &NetworkProfile,
    ) -> Result<(), ReplayError> {
        let (header, transactions) = split_block(bytes).map_err(|_| ReplayError::WrongBody)?;
        let ids: Vec<Hash> = transactions.iter().map(|tx| tx.id()).collect();
        if header.id() != expected.id() || hash::tx_root(&ids) != header.transaction_root {
            return Err(ReplayError::WrongBody);
        }
        let block = validate_block(&self.chain, network, &self.state, bytes).map_err(|error| {
            // Transaction IDs commit to unsigned fields, not signatures. A peer can therefore
            // corrupt a signature without changing the header's transaction root.
            if matches!(
                error,
                ConsensusError::BadTransaction {
                    reason: vess_consensus::error::TxReject::BadSignature,
                    ..
                }
            ) {
                ReplayError::WrongBody
            } else {
                ReplayError::Invalid(error.to_string())
            }
        })?;
        self.store
            .commit_block(&block, bytes)
            .map_err(|error| ReplayError::Storage(error.into()))?;
        self.chain
            .insert(header)
            .map_err(|error| ReplayError::Storage(error.into()))?;
        self.state = block.state;
        Ok(())
    }
}
