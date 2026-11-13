//! Consensus rejection reasons.

use core::fmt;

use vess_state::StateError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxReject {
    BadVersion,
    BadChainId,
    BadSignature,
    BadAccountBinding,
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
    UnknownTip,
    /// A checkpointed height held a different block id, so this is not our chain.
    CheckpointMismatch,
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
            ConsensusError::UnknownTip => f.write_str("no current tip"),
            ConsensusError::CheckpointMismatch => {
                f.write_str("block conflicts with a trusted checkpoint")
            }
            ConsensusError::BadTransaction { index, reason } => {
                write!(f, "transaction {index}: {reason}")
            }
        }
    }
}

impl std::error::Error for ConsensusError {}
