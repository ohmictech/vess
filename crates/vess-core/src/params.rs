//! Network parameters as seen by an operator: the printable table behind `vess node params`.

use crate::constants::*;
use crate::u256::U256;

/// One row of the operator-facing parameter table.
pub struct Param {
    pub name: &'static str,
    pub value: String,
}

fn row(name: &'static str, value: impl ToString) -> Param {
    Param {
        name,
        value: value.to_string(),
    }
}

/// The exponent, when `target` is exactly `2^n`.
///
/// Every target in the parameter table is a power of two, so this is how the document spells them.
fn pow2_exponent(target: U256) -> u32 {
    let limbs = target.limbs();
    for (index, limb) in limbs.iter().enumerate() {
        if *limb != 0 {
            return ((3 - index) as u32) * 64 + (63 - limb.leading_zeros());
        }
    }
    0
}

/// The parameters of one network, in a fixed order so output diffs are readable.
pub fn network_rows(network: NetworkProfile) -> Vec<Param> {
    let checkpoints = crate::constants::checkpoints(network.network);
    vec![
        row("network", network.network),
        row("genesis_timestamp_ms", network.genesis_timestamp_ms),
        row(
            "genesis_target",
            format!("2^{}", pow2_exponent(network.genesis_target)),
        ),
        // A checkpoint is a consensus rule, so it belongs here rather than in a config file: an
        // operator who cannot see which heights the binary settles cannot tell what it will refuse.
        row("checkpoints", checkpoints.len()),
        row(
            "checkpoint",
            if checkpoints.is_empty() {
                "none".to_string()
            } else {
                checkpoints
                    .iter()
                    .map(|c| format!("{}:{}", c.height, hex(&c.id)))
                    .collect::<Vec<_>>()
                    .join(",")
            },
        ),
    ]
}

/// Constants shared by every network.
pub fn network_agnostic_rows() -> Vec<Param> {
    vec![
        row("PROTOCOL_VERSION", PROTOCOL_VERSION),
        row("TARGET_BLOCK_MS", TARGET_BLOCK_MS),
        row("DIFFICULTY_WINDOW_BLOCKS", DIFFICULTY_WINDOW_BLOCKS),
        row("MAX_DIFFICULTY_ADJUSTMENT", MAX_DIFFICULTY_ADJUSTMENT),
        row(
            "DIFFICULTY_FIRST_RETARGET_HEIGHT",
            DIFFICULTY_FIRST_RETARGET_HEIGHT,
        ),
        row("MAX_FUTURE_DRIFT_MS", MAX_FUTURE_DRIFT_MS),
        row(
            "MINIMUM_TARGET",
            format!("2^{}", pow2_exponent(MINIMUM_TARGET)),
        ),
        row(
            "MAXIMUM_TARGET",
            format!("2^{}", pow2_exponent(MAXIMUM_TARGET)),
        ),
        row("MAX_BLOCK_BYTES", MAX_BLOCK_BYTES),
        row("MAX_TRANSACTION_BYTES", MAX_TRANSACTION_BYTES),
        row("GENESIS_REWARD", GENESIS_REWARD),
        row("MINIMUM_BLOCK_REWARD", MINIMUM_BLOCK_REWARD),
        row("MAX_BLOCK_REWARD", MAX_BLOCK_REWARD),
        row("DEV_FEE_DIVISOR", DEV_FEE_DIVISOR),
        row("DEV_FEE_ACCOUNT", hex(&DEV_FEE_ACCOUNT)),
        row("MAX_SUPPLY", MAX_SUPPLY),
        row("REORG_UNDO_RETENTION_SECONDS", REORG_UNDO_RETENTION_SECONDS),
        row("BLOCK_BODY_RETENTION_SECONDS", BLOCK_BODY_RETENTION_SECONDS),
        row("DEFAULT_PRUNE_BLOCKS", DEFAULT_PRUNE_BLOCKS),
        row("DEFAULT_PRUNE_HEADERS", DEFAULT_PRUNE_HEADERS),
        row("PRUNE_FLOOR_BLOCKS", PRUNE_FLOOR_BLOCKS),
    ]
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A printable block for `vess node params`.
pub fn describe(network: NetworkProfile) -> String {
    let mut out = String::new();
    out.push_str(&format!("network_name={}\n", network_name(network)));
    for param in network_rows(network) {
        out.push_str(&format!("{}={}\n", param.name, param.value));
    }
    for param in network_agnostic_rows() {
        out.push_str(&format!("{}={}\n", param.name, param.value));
    }
    out
}

fn network_name(network: NetworkProfile) -> &'static str {
    match network.network {
        NETWORK_DEVNET => "devnet",
        NETWORK_TESTNET => "testnet",
        _ => "mainnet",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_lists_every_parameter() {
        let text = describe(NetworkProfile::MAINNET);
        assert!(text.contains("network_name=mainnet"), "{text}");
        assert!(text.contains("MINIMUM_BLOCK_REWARD=1"), "{text}");
        assert!(text.contains("genesis_target=2^226"), "{text}");
    }
}
