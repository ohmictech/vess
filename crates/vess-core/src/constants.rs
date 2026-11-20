//! Consensus constants. One versioned module; nothing here is user-configurable at runtime.

use crate::u256::U256;

pub const PROTOCOL_VERSION: u16 = 3;

/// Transaction version that carries the optional [`TX_PAYLOAD_BYTES`] payload. Transactions at
/// [`PROTOCOL_VERSION`] (the pre-payload layout) are still accepted, so history written before the
/// payload existed keeps verifying byte for byte.
pub const TRANSACTION_VERSION_PAYLOAD: u16 = 4;

/// Transaction version that replaces the mandatory sender key and signature with a tagged
/// authority: either a signature, or the rules prefixed to an escrow account id.
pub const TRANSACTION_VERSION: u16 = 5;

/// Transaction version that carries several inputs and several outputs in one atomic spend. Every
/// input is debited and every output credited, or the whole transaction is rejected.
pub const TRANSACTION_VERSION_JOINT: u16 = 6;

/// Most inputs a joint transaction may carry. Bounds both decode allocation and the amount of state
/// work a single transaction can impose.
pub const MAX_TRANSFER_INPUTS: usize = 16;

/// Most outputs a joint transaction may carry.
pub const MAX_TRANSFER_OUTPUTS: usize = 16;

/// The optional application payload a transfer can carry.
pub const TX_PAYLOAD_BYTES: usize = 32;

/// The revealing secret of a rules account. Same size as the hash it commits to.
pub const PREIMAGE_BYTES: usize = 32;

/// Version of the [`crate::types::Rules`] struct. A rules account commits to exactly these bytes.
pub const RULES_VERSION: u8 = 1;

/// Canonical size of a version 1 rules struct: `1 + 32 + 8 + 32 + 32 + 8`.
pub const RULES_BYTES: usize = 113;

/// Version of the [`crate::types::FuturesRules`] struct. A futures account commits to exactly these
/// bytes, and the version byte keeps its id space disjoint from an escrow's.
pub const RULES_VERSION_FUTURES: u8 = 2;

/// Canonical size of a futures rules struct: `1 + 8 + 8 + 8 + 32 + 32 + 8`.
pub const FUTURES_RULES_BYTES: usize = 97;

/// Ceiling on `FuturesRules::target_delta`.
///
/// The settlement split multiplies the pot by `min(delta, 2 * target_delta)` in `u128`. Bounding the
/// delta at `2^62` keeps `2 * target_delta` inside `u64` and the product inside `u128` for every
/// reachable balance, so the arithmetic cannot overflow and no contract can be written whose payout
/// is unrepresentable.
pub const MAX_TARGET_DELTA: u64 = 1 << 62;

/// Depth of the account tree: one path bit per level, one level per bit of the account id.
pub const DEPTH: usize = 256;

/// Authority tags inside a version 5 transfer, and input authorities inside a version 6 one.
pub const AUTHORITY_SIGNATURE: u8 = 0;
pub const AUTHORITY_RULES: u8 = 1;
pub const AUTHORITY_FUTURES: u8 = 2;

// ---------------------------------------------------------------- networks

pub const NETWORK_DEVNET: u8 = 0;
pub const NETWORK_TESTNET: u8 = 1;
pub const NETWORK_MAINNET: u8 = 2;

/// Protocol parameters that differ between networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkProfile {
    pub network: u8,
    pub genesis_target: U256,
    pub genesis_timestamp_ms: u64,
}

impl NetworkProfile {
    pub const DEVNET: NetworkProfile = NetworkProfile {
        network: NETWORK_DEVNET,
        genesis_target: U256::pow2(240),
        // 2026-10-01T00:00:00Z
        genesis_timestamp_ms: 1_790_812_800_000,
    };

    pub const TESTNET: NetworkProfile = NetworkProfile {
        network: NETWORK_TESTNET,
        genesis_target: U256::pow2(235),
        // 2026-11-01T00:00:00Z
        genesis_timestamp_ms: 1_793_491_200_000,
    };

    pub const MAINNET: NetworkProfile = NetworkProfile {
        network: NETWORK_MAINNET,
        genesis_target: U256::pow2(226),
        // 2026-12-01T00:00:00Z
        genesis_timestamp_ms: 1_796_083_200_000,
    };
}

/// Addresses compiled into the binary that a node with an empty address book dials on start-up.
///
/// These are bootstrap hints, not authorities: once a seed answers, its gossiped addresses fill the
/// book and the seed is just one peer among many. Each network gets its own list so a devnet node
/// never dials a mainnet host. Empty means the network has no public entry point yet, and a node
/// then only connects to whatever `--peer`, `--seed`, `VESS_SEEDS`, or `<datadir>/peers.txt` names.
pub const DEFAULT_SEEDS_DEVNET: &[&str] = &[];
pub const DEFAULT_SEEDS_TESTNET: &[&str] = &[];
pub const DEFAULT_SEEDS_MAINNET: &[&str] = &[];

/// Bootstrap peers for `network`, in `host:port` form.
pub fn default_seeds(network: u8) -> &'static [&'static str] {
    match network {
        NETWORK_DEVNET => DEFAULT_SEEDS_DEVNET,
        NETWORK_TESTNET => DEFAULT_SEEDS_TESTNET,
        _ => DEFAULT_SEEDS_MAINNET,
    }
}

/// A block this network treats as settled: the header chain must contain exactly this id at this
/// height, or it is not this network's chain at all.
///
/// This is the only defence against a long-range attack, where an attacker holding keys that were
/// valid long ago — or nothing but the genesis block — presents a cheaper history from before the
/// point where the honest chain became expensive. No amount of local validation can tell the two
/// apart once the fork is below the last block *you* validated, so the answer has to be a constant
/// compiled into the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub id: [u8; 32],
}

/// Checkpoints per network. Empty means "no settled history yet", which is the honest state of a
/// network that has not been running long enough for a checkpoint to mean anything.
///
/// To add one, put a real height and block id here and rebuild: a checkpoint is a claim that a
/// specific block is in the history of that network forever, and a wrong entry permanently forks the
/// node that ships it off the network, so this is deliberately not configurable at runtime.
pub const CHECKPOINTS_DEVNET: &[Checkpoint] = &[];
pub const CHECKPOINTS_TESTNET: &[Checkpoint] = &[];
pub const CHECKPOINTS_MAINNET: &[Checkpoint] = &[];

pub fn checkpoints(network: u8) -> &'static [Checkpoint] {
    match network {
        NETWORK_DEVNET => CHECKPOINTS_DEVNET,
        NETWORK_TESTNET => CHECKPOINTS_TESTNET,
        _ => CHECKPOINTS_MAINNET,
    }
}

// ------------------------------------------------------------------- sizes

pub const ML_DSA_PK_BYTES: usize = 1_952;
pub const ML_DSA_SIG_BYTES: usize = 3_309;

pub const MAX_BLOCK_BYTES: usize = 1_048_576;
pub const MAX_TRANSACTION_BYTES: usize = 65_536;
pub const MAX_NETWORK_FRAME_BYTES: usize = 2_097_152;

/// 2 + 32 + 32 + 32 + 32 + 8 + 32 + 32 + 32
pub const BLOCK_HEADER_BYTES: usize = 234;

// -------------------------------------------------------------------- time

pub const TARGET_BLOCK_MS: u64 = 1_000;
pub const MTP_SPAN_BLOCKS: usize = 11;
pub const MAX_FUTURE_DRIFT_MS: u64 = 120_000;
pub const MAX_PER_BLOCK_ELAPSED_MS: u64 = 4_000;

// -------------------------------------------------------------- difficulty

pub const DIFFICULTY_WINDOW_BLOCKS: u64 = 64;
pub const DIFFICULTY_FIRST_RETARGET_HEIGHT: u64 = 128;
pub const MAX_DIFFICULTY_ADJUSTMENT: u64 = 4;
pub const MIN_RETARGET_ELAPSED_MS: u64 =
    DIFFICULTY_WINDOW_BLOCKS * TARGET_BLOCK_MS / MAX_DIFFICULTY_ADJUSTMENT;
pub const MAX_RETARGET_ELAPSED_MS: u64 =
    DIFFICULTY_WINDOW_BLOCKS * TARGET_BLOCK_MS * MAX_DIFFICULTY_ADJUSTMENT;

pub const MAXIMUM_TARGET: U256 = U256::pow2(240);
pub const MINIMUM_TARGET: U256 = U256::pow2(216);

// ----------------------------------------------------------------- emission

/// Emission is the difficulty of a block measured against the genesis difficulty, scaled so that a
/// block at genesis difficulty pays exactly this much:
///
/// ```text
/// reward = GENESIS_REWARD * genesis_target / target
/// ```
///
/// Difficulty `D` is the expected number of hashes per block, `D = 2^256 / target`, so
/// `genesis_target / target = D / D_genesis` and the reward is still strictly proportional to
/// difficulty — one hundredth of a fixed quantum of work per unit. Doubling the hashrate doubles both
/// `D` and the per-block reward, leaving per-hash revenue constant. There is no curve, no halving and
/// no cap; supply is the integral of work performed.
///
/// The value is 100 so that the 1% development fee (`DEV_FEE_DIVISOR = 100`) is exactly one unit at
/// genesis difficulty, and the miner keeps 99.
pub const GENESIS_REWARD: u64 = 100;

/// Emission floor. A target easier than `genesis_target` divides the reward below `GENESIS_REWARD`,
/// and far enough below that it would truncate to zero, which would stop emission entirely.
pub const MINIMUM_BLOCK_REWARD: u64 = 1;

/// Reward clamp, for arithmetic safety only. The largest reachable reward is
/// `GENESIS_REWARD * MAXIMUM_TARGET / MINIMUM_TARGET = 100 * 2^24 = 1.68e9`, so this is unreachable
/// with the shipped targets.
pub const MAX_BLOCK_REWARD: u64 = 10_000_000_000;

/// Where the development fee goes. Consensus, not configuration: every node must agree.
///
/// Rotating it is a hard fork: the account id is part of the state transition, so changing it changes
/// the state root of every block after the change.
pub const DEV_FEE_ACCOUNT: [u8; 32] = [
    0x5c, 0x5b, 0x1f, 0x65, 0x5f, 0x17, 0xd9, 0x17, 0x58, 0xa7, 0x78, 0xe3, 0xe4, 0x8a, 0xc3, 0x6f,
    0xda, 0xaf, 0x90, 0xb6, 0xe7, 0x92, 0x30, 0x9e, 0x03, 0x0a, 0xb5, 0x2c, 0x6c, 0xb2, 0xf0, 0xa7,
];

/// The development fee is `reward / DEV_FEE_DIVISOR`, floored to a whole unit, taken out of the block
/// reward (never added to it). At 100 that is 1%.
pub const DEV_FEE_DIVISOR: u64 = 100;

/// A display and arithmetic bound: 10^18 units, i.e. 18 decimal places of one "coin". Supply is
/// work-driven and unbounded (see `MINIMUM_BLOCK_REWARD`), so this is not an issuance cap — it is the
/// largest total the shipped tooling will format.
pub const MAX_SUPPLY: u64 = 1_000_000_000_000_000_000;

// --------------------------------------------------------------- retention

pub const REORG_UNDO_RETENTION_SECONDS: u64 = 43_200;
pub const BLOCK_BODY_RETENTION_SECONDS: u64 = 43_200;

// ------------------------------------------------------------------ pruning

/// Default for `--prune-blocks`: bodies and undo records older than this many blocks below the tip
/// are deleted. `0` keeps everything, which makes the node archival for bodies.
pub const DEFAULT_PRUNE_BLOCKS: u64 = 16_384;

/// Default for `--prune-headers`: a deliberately large number, so header pruning is off unless an
/// operator asks for it. `0` means never.
pub const DEFAULT_PRUNE_HEADERS: u64 = 100_000_000;

/// Default for `--prune-undo`: undo records older than this many blocks below the tip are deleted.
/// Deliberately separate from `--prune-blocks`, so an archival node can keep every body without
/// carrying a reorg log that no reorg can ever reach. `0` keeps them forever.
pub const DEFAULT_PRUNE_UNDO: u64 = 16_384;

/// Blocks below the tip whose history this node treats as final: no branch that replaces our main
/// chain at or below that height is adopted.
///
/// The anchor is derived from the chain the node validated itself, so it needs no published hashes,
/// no attestations and no operator maintenance. `0` disables the rule.
pub const DEFAULT_FINALITY_DEPTH_BLOCKS: u64 = 10_000;

/// Never prune inside this window, whatever the configuration says. It covers median-time-past (11
/// blocks), the difficulty window (64), the peer sync lookback (32) and a reorg allowance, so a
/// pruned node can still validate new blocks and follow an ordinary fork.
pub const PRUNE_FLOOR_BLOCKS: u64 = 256;

// ----------------------------------------------------------------- mempool

pub const MEMPOOL_MAX_TRANSACTIONS: usize = 4_096;
pub const MEMPOOL_MAX_TRANSACTION_BYTES: usize = 16_777_216;
pub const MEMPOOL_PER_ACCOUNT_TRANSACTIONS: usize = 1;

// ----------------------------------------------------------------- network

/// Wire identity, spelled in ASCII so a captured frame is recognisable: "VESS" and "VESR".
pub const P2P_MAGIC: u32 = 0x5645_5353;
pub const RPC_MAGIC: u32 = 0x5645_5352;
pub const P2P_DEFAULT_PORT: u16 = 9_732;
pub const RPC_DEFAULT_PORT: u16 = 9_733;

/// Headers one message may carry. Bounded by the frame limit rather than by round-trip comfort:
/// 4,096 headers is ~958 KiB, and every extra kilobyte here is one less round trip during catch-up.
pub const MAX_HEADERS_PER_MESSAGE: usize = 4_096;

pub const CONNECT_TIMEOUT_MS: u64 = 5_000;
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
pub const READ_TIMEOUT_MS: u64 = 30_000;
pub const WRITE_TIMEOUT_MS: u64 = 30_000;

// Compile-time invariants:
const _: () = assert!(
    MIN_RETARGET_ELAPSED_MS
        == DIFFICULTY_WINDOW_BLOCKS * TARGET_BLOCK_MS / MAX_DIFFICULTY_ADJUSTMENT
);
const _: () = assert!(BLOCK_HEADER_BYTES == 234);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_matches_field_layout() {
        assert_eq!(BLOCK_HEADER_BYTES, 2 + 32 + 32 + 32 + 32 + 8 + 32 + 32 + 32);
    }

    /// A full header batch must fit one frame: the encoder refuses oversized payloads rather than
    /// splitting them, so a batch that did not fit would stall catch-up instead of slowing it.
    #[test]
    fn a_full_header_batch_fits_in_one_frame() {
        let batch = 4 + MAX_HEADERS_PER_MESSAGE * BLOCK_HEADER_BYTES;
        assert!(
            batch <= MAX_NETWORK_FRAME_BYTES,
            "a {MAX_HEADERS_PER_MESSAGE}-header batch is {batch} bytes"
        );
    }

    #[test]
    fn retarget_window_spans_four_x() {
        // Elapsed in [16_000, 256_000] ms means /4 .. *4.
        assert_eq!(
            MIN_RETARGET_ELAPSED_MS * MAX_DIFFICULTY_ADJUSTMENT,
            DIFFICULTY_WINDOW_BLOCKS * TARGET_BLOCK_MS
        );
        assert_eq!(
            DIFFICULTY_WINDOW_BLOCKS * TARGET_BLOCK_MS * MAX_DIFFICULTY_ADJUSTMENT,
            MAX_RETARGET_ELAPSED_MS
        );
    }

    #[test]
    fn target_bounds_are_ordered() {
        assert!(MINIMUM_TARGET < MAXIMUM_TARGET);
        assert!(NetworkProfile::MAINNET.genesis_target >= MINIMUM_TARGET);
        assert!(NetworkProfile::DEVNET.genesis_target <= MAXIMUM_TARGET);
        assert!(NetworkProfile::TESTNET.genesis_target <= MAXIMUM_TARGET);
    }
}
