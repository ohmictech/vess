//! Block validation, difficulty, timestamps, and fork choice.

pub mod block;
pub mod chain;
pub mod error;

pub use block::{
    BlockTemplate, ValidatedBlock, apply_body, build_template, decode_body, encode_body,
    mine_header, split_block, validate_block,
};
pub use chain::{
    BlockMeta, Chain, Checkpoint, HeaderSource, InsertOutcome, ancestor, check_checkpoint,
    check_header, clamp_target, empty_state_root, genesis_header, median_time_past,
    required_target,
};
pub use error::{ConsensusError, TxReject};

#[cfg(test)]
mod tests;
