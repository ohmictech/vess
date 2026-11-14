//! Minimal unsigned 256-bit integer, sufficient for targets, PoW comparison, and chain work.
//!
//! Limbs are stored most-significant first so the derived `Ord` is the numeric order.

use core::cmp::Ordering;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct U256([u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([0, 0, 0, 1]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    /// `2^n` for `n < 256`.
    pub const fn pow2(n: u32) -> U256 {
        assert!(n < 256, "pow2 exponent out of range");
        let mut limbs = [0u64; 4];
        limbs[3 - (n / 64) as usize] = 1u64 << (n % 64);
        U256(limbs)
    }

    pub const fn from_u64(v: u64) -> U256 {
        U256([0, 0, 0, v])
    }

    pub const fn limbs(self) -> [u64; 4] {
        self.0
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> U256 {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            *limb = u64::from_be_bytes(b);
        }
        U256(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    pub fn bit(self, i: u32) -> bool {
        (self.0[3 - (i / 64) as usize] >> (i % 64)) & 1 == 1
    }

    fn set_bit(&mut self, i: u32) {
        self.0[3 - (i / 64) as usize] |= 1u64 << (i % 64);
    }

    /// Shift left by one, dropping the bit shifted out of the top.
    fn shl1(self) -> U256 {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in (0..4).rev() {
            out[i] = (self.0[i] << 1) | carry;
            carry = self.0[i] >> 63;
        }
        U256(out)
    }

    pub fn checked_add(self, other: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for i in (0..4).rev() {
            let (s1, c1) = self.0[i].overflowing_add(other.0[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            out[i] = s2;
            carry = u64::from(c1 || c2);
        }
        if carry != 0 { None } else { Some(U256(out)) }
    }

    pub fn checked_sub(self, other: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut borrow = 0u64;
        for i in (0..4).rev() {
            let (d1, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            out[i] = d2;
            borrow = u64::from(b1 || b2);
        }
        if borrow != 0 { None } else { Some(U256(out)) }
    }

    pub fn checked_mul_u64(self, m: u64) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for i in (0..4).rev() {
            let acc = (self.0[i] as u128) * (m as u128) + carry;
            out[i] = acc as u64;
            carry = acc >> 64;
        }
        if carry != 0 { None } else { Some(U256(out)) }
    }

    /// Binary long division. Returns `None` for a zero divisor.
    pub fn div_rem(self, divisor: U256) -> Option<(U256, U256)> {
        if divisor.is_zero() {
            return None;
        }
        let mut quotient = U256::ZERO;
        let mut remainder = U256::ZERO;
        for i in (0..256).rev() {
            remainder = remainder.shl1();
            if self.bit(i) {
                remainder.set_bit(0);
            }
            if remainder >= divisor {
                remainder = remainder.checked_sub(divisor)?;
                quotient.set_bit(i);
            }
        }
        Some((quotient, remainder))
    }

    /// `floor(2^256 / (target + 1))`, the standard PoW work of one block.
    ///
    /// Saturated to `u128::MAX`; consensus bounds `target >= MINIMUM_TARGET`, which keeps the
    /// true value at most `2^40`.
    pub fn work_from_target(target: U256) -> u128 {
        let divisor = match target.checked_add(U256::ONE) {
            Some(d) => d,
            None => return u128::MAX,
        };
        let (q, r) = match U256::MAX.div_rem(divisor) {
            Some(v) => v,
            None => return u128::MAX,
        };
        let q = if r.checked_add(U256::ONE) == Some(divisor) {
            match q.checked_add(U256::ONE) {
                Some(v) => v,
                None => return u128::MAX,
            }
        } else {
            q
        };
        let bytes = q.to_be_bytes();
        if bytes[..16].iter().any(|&b| b != 0) {
            return u128::MAX;
        }
        let mut low = [0u8; 16];
        low.copy_from_slice(&bytes[16..]);
        u128::from_be_bytes(low)
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MAXIMUM_TARGET, MINIMUM_TARGET, NetworkProfile};

    #[test]
    fn pow2_bit_positions() {
        assert_eq!(U256::pow2(0), U256::ONE);
        assert!(U256::pow2(216).bit(216));
        assert!(!U256::pow2(216).bit(215));
        assert_eq!(U256::pow2(255).limbs(), [0x8000_0000_0000_0000, 0, 0, 0]);
    }

    #[test]
    fn byte_roundtrip() {
        let v = U256::pow2(216)
            .checked_add(U256::from_u64(0x1234_5678_9abc_def0))
            .unwrap();
        assert_eq!(U256::from_be_bytes(v.to_be_bytes()), v);
    }

    #[test]
    fn add_sub_roundtrip_and_overflow() {
        let a = U256::pow2(200);
        let b = U256::pow2(201);
        assert_eq!(a.checked_add(b).unwrap().checked_sub(a).unwrap(), b);
        assert_eq!(U256::MAX.checked_add(U256::ONE), None);
        assert_eq!(U256::ZERO.checked_sub(U256::ONE), None);
    }

    #[test]
    fn work_matches_reference_values() {
        assert_eq!(U256::work_from_target(MAXIMUM_TARGET), 65_535);
        assert_eq!(
            U256::work_from_target(NetworkProfile::DEVNET.genesis_target),
            65_535
        );
        assert_eq!(
            U256::work_from_target(NetworkProfile::TESTNET.genesis_target),
            2_097_151
        );
        assert_eq!(
            U256::work_from_target(NetworkProfile::MAINNET.genesis_target),
            1_073_741_823
        );
        assert_eq!(U256::work_from_target(MINIMUM_TARGET), 1_099_511_627_775);
    }

    #[test]
    fn work_is_monotone_in_target() {
        let easy = U256::pow2(230);
        let hard = U256::pow2(220);
        assert!(U256::work_from_target(easy) < U256::work_from_target(hard));
    }

    #[test]
    fn div_rem_base_cases() {
        assert_eq!(U256::ONE.div_rem(U256::ONE), Some((U256::ONE, U256::ZERO)));
        assert_eq!(U256::ONE.div_rem(U256::ZERO), None);
        assert_eq!(
            U256::from_u64(100).div_rem(U256::from_u64(7)),
            Some((U256::from_u64(14), U256::from_u64(2)))
        );
    }

    #[test]
    fn mul_overflow_is_reported() {
        assert_eq!(
            U256::from_u64(3).checked_mul_u64(5),
            Some(U256::from_u64(15))
        );
        assert_eq!(U256::MAX.checked_mul_u64(2), None);
    }
}
