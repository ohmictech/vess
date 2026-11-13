//! Work-linked emission: a block pays Vess in proportion to the difficulty it was mined at.
//!
//! ```text
//! reward = GENESIS_REWARD * genesis_target / target      (clamped to the floor and the cap)
//! ```
//!
//! Difficulty `D` is the expected number of hashes per block, `D = 2^256 / target`, so
//! `genesis_target / target = D / D_genesis`: the reward is the difficulty measured relative to the
//! genesis block, scaled by `GENESIS_REWARD`. A block at genesis difficulty pays exactly
//! `GENESIS_REWARD` (100); a block at twice that difficulty pays 200. There is no curve, no halving
//! and no cap — supply is the integral of work performed.
//!
//! Two properties follow, and they are the reason for the rule:
//!
//! - revenue per hash is the same at every difficulty, so nobody gains by manipulating `D`;
//! - emission tracks hashrate exactly, so at zero profit price equals the cost of production.
//!
//! Every reward is split in two by [`split`]: a 1% development fee taken *out of* the reward, and the
//! remainder to the miner. Total issuance is unaffected by the split.
//!
//! `MINIMUM_BLOCK_REWARD` keeps emission from stopping when difficulty eases below genesis (a target
//! between `genesis_target` and `MAXIMUM_TARGET` divides the reward toward zero). That case is
//! reachable on any network whose genesis target is harder than the easiest allowed target, so the
//! floor is consensus, not a convenience.

use vess_core::constants::{
    DEV_FEE_DIVISOR, GENESIS_REWARD, MAX_BLOCK_REWARD, MINIMUM_BLOCK_REWARD, NetworkProfile,
};
use vess_core::u256::U256;

/// The total reward a block pays for being mined at `target` on `network`, dev fee included.
pub fn reward(network: NetworkProfile, target: U256) -> u64 {
    if target.is_zero() {
        return MAX_BLOCK_REWARD;
    }
    let scaled = match network.genesis_target.checked_mul_u64(GENESIS_REWARD) {
        Some(v) => v,
        // Unreachable with the shipped constants (100 * 2^240 < 2^256); saturate rather than panic.
        None => return MAX_BLOCK_REWARD,
    };
    let (quotient, _) = match scaled.div_rem(target) {
        Some(qr) => qr,
        None => return MAX_BLOCK_REWARD,
    };
    let limbs = quotient.limbs();
    // `limbs[3]` is the least-significant word; anything in 0..=2 means the value exceeds u64.
    if limbs[0] != 0 || limbs[1] != 0 || limbs[2] != 0 {
        return MAX_BLOCK_REWARD;
    }
    limbs[3].clamp(MINIMUM_BLOCK_REWARD, MAX_BLOCK_REWARD)
}

/// The development fee for a block paying `reward`: `reward / DEV_FEE_DIVISOR`, floored.
///
/// The fee is *taken out of* the reward, never added to it, so total issuance stays exactly
/// `reward(network, target)` and the "emission is difficulty" invariant survives. Floored division
/// means a reward below `DEV_FEE_DIVISOR` pays no fee: at genesis difficulty the reward is exactly
/// `GENESIS_REWARD`, so the fee is exactly one unit, and it only disappears if difficulty eases more
/// than 100x below genesis.
pub fn dev_fee(reward: u64) -> u64 {
    reward / DEV_FEE_DIVISOR
}

/// What the miner of a block paying `reward` actually receives: `reward - dev_fee(reward)`.
pub fn miner_reward(reward: u64) -> u64 {
    reward - dev_fee(reward)
}

/// Both sides of a block reward: `(miner, dev_fee)`, whose sum is `reward(network, target)`.
pub fn split(network: NetworkProfile, target: U256) -> (u64, u64) {
    let reward = reward(network, target);
    let fee = dev_fee(reward);
    (reward - fee, fee)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(target_exp: u32) -> NetworkProfile {
        NetworkProfile {
            network: 9,
            genesis_target: U256::pow2(target_exp),
            genesis_timestamp: 0,
        }
    }

    #[test]
    fn genesis_pays_the_genesis_reward_on_every_network() {
        for n in [
            NetworkProfile::DEVNET,
            NetworkProfile::TESTNET,
            NetworkProfile::MAINNET,
        ] {
            assert_eq!(reward(n, n.genesis_target), GENESIS_REWARD);
            // And the split at genesis difficulty is exactly 1 unit of fee.
            assert_eq!(split(n, n.genesis_target), (GENESIS_REWARD - 1, 1));
        }
    }

    #[test]
    fn reward_is_proportional_to_relative_difficulty() {
        let n = profile(240);
        assert_eq!(reward(n, U256::pow2(240)), 100);
        assert_eq!(reward(n, U256::pow2(239)), 200);
        assert_eq!(reward(n, U256::pow2(238)), 400);
        assert_eq!(reward(n, U256::pow2(224)), 100 * 65_536);
    }

    #[test]
    fn reward_never_falls_below_the_floor() {
        let n = profile(240);
        // An easier target divides below GENESIS_REWARD; far enough, it would truncate to zero.
        assert_eq!(reward(n, U256::pow2(241)), 50);
        assert_eq!(reward(n, U256::pow2(247)), MINIMUM_BLOCK_REWARD);
        assert_eq!(reward(n, U256::pow2(255)), MINIMUM_BLOCK_REWARD);
    }

    #[test]
    fn reward_is_monotone_in_difficulty() {
        let n = profile(240);
        let mut previous = 0u64;
        for exp in (216..=255).rev() {
            let r = reward(n, U256::pow2(exp));
            assert!(r >= previous, "reward fell going to 2^{exp}");
            previous = r;
        }
    }

    #[test]
    fn the_largest_reachable_reward_is_below_the_clamp() {
        // devnet: the easiest genesis target and the hardest allowed target.
        let n = NetworkProfile::DEVNET;
        let largest = reward(n, vess_core::constants::MINIMUM_TARGET);
        assert_eq!(largest, 100 << 24);
        assert!(
            largest < MAX_BLOCK_REWARD,
            "the clamp must stay unreachable"
        );
    }

    #[test]
    fn reward_is_clamped_instead_of_overflowing() {
        let n = profile(240);
        // A target far below the consensus floor would exceed u64 / the clamp.
        assert_eq!(reward(n, U256::from_u64(1)), MAX_BLOCK_REWARD);
    }

    #[test]
    fn zero_target_is_not_reachable_but_saturates() {
        assert_eq!(reward(profile(240), U256::from_u64(0)), MAX_BLOCK_REWARD);
    }

    #[test]
    fn the_dev_fee_is_one_percent_floored() {
        assert_eq!(dev_fee(1), 0);
        assert_eq!(dev_fee(99), 0);
        assert_eq!(dev_fee(100), 1);
        assert_eq!(dev_fee(199), 1);
        assert_eq!(dev_fee(1024), 10);
        assert_eq!(dev_fee(100 << 24), (100 << 24) / 100);
    }

    #[test]
    fn the_split_preserves_total_issuance() {
        for reward in [1u64, 2, 99, 100, 101, 819_200, 100 << 24, MAX_BLOCK_REWARD] {
            assert_eq!(dev_fee(reward) + miner_reward(reward), reward);
        }
        let n = profile(240);
        for exp in [216u32, 224, 230, 240, 245, 255] {
            let target = U256::pow2(exp);
            let (miner, fee) = split(n, target);
            assert_eq!(miner + fee, reward(n, target));
        }
    }

    #[test]
    fn revenue_per_hash_is_constant() {
        // reward / difficulty is the same at every difficulty, which is the point of the rule.
        let n = profile(240);
        let reference = 100.0f64 / 65_536.0;
        for exp in [240u32, 236, 230, 224] {
            let hashes = 2f64.powi(256 - exp as i32);
            let per_hash = reward(n, U256::pow2(exp)) as f64 / hashes;
            assert!(
                (per_hash - reference).abs() / reference < 1e-9,
                "2^{exp}: {per_hash}"
            );
        }
    }
}
