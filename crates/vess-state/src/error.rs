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
        };
        f.write_str(s)
    }
}

impl std::error::Error for StateError {}
