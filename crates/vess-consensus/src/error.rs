//! Consensus rejection reasons.

use core::fmt;

use vess_state::StateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxReject {
    BadVersion,
    BadChainId,
    BadSignature,
    BadAccountBinding,
    /// The revealed rules are not the version this protocol understands.
    BadRules,
    /// A claim presented a preimage that does not open the lock.
    PreimageMismatch,
    /// The claim window has closed; only the owner path is open.
    ClaimWindowClosed,
    /// The escrow spend names a destination the rules do not allow.
    WrongDestination,
    /// The submitter asked for more than the rules permit.
    FeeTooHigh,
    /// A rules account must be spent in full.
    PartialSpend,
    /// The revealed futures terms are malformed or unusable.
    BadFuturesRules,
    /// A settlement arrived before the terms allow one.
    SettleTooEarly,
    /// The settlement does not declare the split consensus derives from the measured supply.
    BadSettlement,
    InvalidState(StateError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusError {
    BlockTooLarge,
    BadHeader,
    BadVersion,
    BadChainId,
    UnknownParent,
    BadTarget,
    BadTimestamp,
    BadPow,
    BadTxEncoding,
    DuplicateInBlock,
    BadTxRoot,
    BadStateRoot,
    /// A stateless witness did not open the parent state root, or named the wrong accounts.
    BadWitness,
    UnknownTip,
    BadTransaction {
        index: u32,
        reason: TxReject,
    },
}

impl fmt::Display for TxReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxReject::BadVersion => f.write_str("unsupported transaction version"),
            TxReject::BadChainId => f.write_str("transaction belongs to another chain"),
            TxReject::BadSignature => f.write_str("invalid signature"),
            TxReject::BadAccountBinding => f.write_str("public key does not match the account"),
            TxReject::BadRules => f.write_str("unsupported escrow rules version"),
            TxReject::PreimageMismatch => f.write_str("preimage does not open the hash lock"),
            TxReject::ClaimWindowClosed => f.write_str("claim window is closed"),
            TxReject::WrongDestination => f.write_str("escrow spend names the wrong destination"),
            TxReject::FeeTooHigh => f.write_str("fee exceeds the escrow rules"),
            TxReject::PartialSpend => f.write_str("escrow balance must be spent in full"),
            TxReject::BadFuturesRules => f.write_str("malformed or unusable futures terms"),
            TxReject::SettleTooEarly => f.write_str("settlement is not open yet"),
            TxReject::BadSettlement => {
                f.write_str("settlement does not match the measured supply delta")
            }
            TxReject::InvalidState(e) => write!(f, "state rejection: {e}"),
        }
    }
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusError::BlockTooLarge => f.write_str("block exceeds the size limit"),
            ConsensusError::BadHeader => f.write_str("malformed block header"),
            ConsensusError::BadVersion => f.write_str("unsupported block version"),
            ConsensusError::BadChainId => f.write_str("block belongs to another chain"),
            ConsensusError::UnknownParent => f.write_str("unknown previous block"),
            ConsensusError::BadTarget => f.write_str("target is not the required target"),
            ConsensusError::BadTimestamp => f.write_str("timestamp outside the permitted window"),
            ConsensusError::BadPow => f.write_str("insufficient proof of work"),
            ConsensusError::BadTxEncoding => f.write_str("malformed transaction list"),
            ConsensusError::DuplicateInBlock => f.write_str("duplicate transaction or mint id"),
            ConsensusError::BadTxRoot => f.write_str("transaction root mismatch"),
            ConsensusError::BadStateRoot => f.write_str("state root mismatch"),
            ConsensusError::BadWitness => {
                f.write_str("witness does not open the parent state root")
            }
            ConsensusError::UnknownTip => f.write_str("no current tip"),
            ConsensusError::BadTransaction { index, reason } => {
                write!(f, "transaction {index}: {reason}")
            }
        }
    }
}

impl std::error::Error for ConsensusError {}
