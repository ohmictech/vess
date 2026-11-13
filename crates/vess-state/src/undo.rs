//! Reversible change log.
//!
//! Every mutation performed while a block is applied is recorded once, keeping the value as it was
//! *before* the block. Reversing the log therefore restores the exact prior state, which is what a
//! reorganization needs.

use std::collections::HashSet;

use vess_core::codec::{Decode, Encode, Reader, Writer};
use vess_core::{Account, AccountId, CodecError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateChange {
    /// Previous account value; `None` means the account did not exist.
    Account(AccountId, Option<Account>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoLog {
    changes: Vec<StateChange>,
    touched: HashSet<AccountId>,
}

impl UndoLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.changes.len()
    }

    pub fn changes(&self) -> &[StateChange] {
        &self.changes
    }

    pub(crate) fn clear(&mut self) {
        self.changes.clear();
        self.touched.clear();
    }

    /// Record the pre-block value of an account, at most once per account.
    pub(crate) fn record_account(&mut self, id: AccountId, previous: Option<Account>) {
        if self.touched.insert(id) {
            self.changes.push(StateChange::Account(id, previous));
        }
    }

    pub(crate) fn into_changes(self) -> Vec<StateChange> {
        self.changes
    }

    /// Rebuild a log from storage. The touch set is only used while recording.
    pub fn from_changes(changes: Vec<StateChange>) -> UndoLog {
        UndoLog {
            changes,
            touched: HashSet::new(),
        }
    }

    pub fn write_to(&self, w: &mut Writer) {
        w.u32(self.changes.len() as u32);
        for change in &self.changes {
            match change {
                StateChange::Account(id, None) => {
                    w.u8(0);
                    w.fixed(id);
                }
                StateChange::Account(id, Some(account)) => {
                    w.u8(1);
                    w.fixed(id);
                    account.encode(w);
                }
            }
        }
    }

    pub fn read_from(r: &mut Reader<'_>) -> Result<UndoLog, CodecError> {
        let count = r.u32()? as usize;
        // Every change occupies at least one tag byte, so a larger count cannot be honest.
        if count > r.remaining() {
            return Err(CodecError::LengthTooLarge);
        }
        let mut changes = Vec::with_capacity(count.min(4_096));
        for _ in 0..count {
            let tag = r.u8()?;
            let change = match tag {
                0 => StateChange::Account(r.array()?, None),
                1 => {
                    let id = r.array()?;
                    StateChange::Account(id, Some(Account::decode(r)?))
                }
                _ => return Err(CodecError::InvalidValue),
            };
            changes.push(change);
        }
        Ok(UndoLog::from_changes(changes))
    }
}
