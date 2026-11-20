//! State transition failures. Every variant maps to a consensus rejection reason.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    ZeroAmount,
    Expired,
    UnknownAccount,
    BadNonce,
    InsufficientBalance,
    Overflow,
    /// A transaction with no inputs or no outputs.
    EmptyTransaction,
    /// More inputs or outputs than the protocol allows.
    Oversized,
    /// Two inputs debit the same account, or two outputs credit it.
    DuplicateInput,
    DuplicateOutput,
    /// Inputs do not equal outputs plus fee.
    Unbalanced,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            StateError::ZeroAmount => "zero amount",
            StateError::Expired => "transaction expired",
            StateError::UnknownAccount => "sender account does not exist",
            StateError::BadNonce => "nonce mismatch",
            StateError::InsufficientBalance => "insufficient balance",
            StateError::Overflow => "arithmetic overflow",
            StateError::EmptyTransaction => "transaction has no inputs or no outputs",
            StateError::Oversized => "too many inputs or outputs",
            StateError::DuplicateInput => "duplicate input account",
            StateError::DuplicateOutput => "duplicate output account",
            StateError::Unbalanced => "inputs do not equal outputs plus fee",
        };
        f.write_str(s)
    }
}

impl std::error::Error for StateError {}
