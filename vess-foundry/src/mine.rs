//! Vess miner — epoch-aware Argon2d proof-of-work.
use argon2::Argon2;

pub const VESS_M_COST: u32 = 1024 * 1024;
pub const VESS_T_COST: u32 = 1;
pub const VESS_P_COST: u32 = 1;
pub const VESS_HASH_LEN: usize = 32;

const DOMAIN: &[u8] = b"vess-mine-v3";
const SALT: &[u8] = b"vess-salt-v3";

pub fn required_zeros(amount: u64) -> u32 {
    if amount >= 100_000 { 8 }
    else if amount >= 10_000 { 7 }
    else if amount >= 1_000 { 6 }
    else if amount >= 100 { 5 }
    else if amount >= 10 { 4 }
    else { 3 }
}

pub fn hash_attempt(initial_pk: &[u8; 32], epoch: u64, nonce: u64, amount: u64) -> [u8; 32] {
    let mut password = Vec::new();
    password.extend_from_slice(initial_pk);
    password.extend_from_slice(&epoch.to_be_bytes());
    password.extend_from_slice(&nonce.to_be_bytes());
    password.extend_from_slice(&amount.to_be_bytes());
    password.extend_from_slice(DOMAIN);
    let mut output = [0u8; VESS_HASH_LEN];
    let argon2 = Argon2::new(argon2::Algorithm::Argon2d, argon2::Version::V0x13,
        argon2::Params::new(VESS_M_COST, VESS_T_COST, VESS_P_COST, Some(VESS_HASH_LEN)).unwrap());
    argon2.hash_password_into(&password, SALT, &mut output).unwrap();
    output
}

pub fn leading_zero_bytes(bytes: &[u8; 32]) -> u32 {
    let mut c = 0u32;
    for &b in bytes.iter() { if b == 0 { c += 1; } else { break; } }
    c
}

pub fn verify_mined(initial_pk: &[u8; 32], epoch: u64, nonce: u64, amount: u64, current_epoch: u64) -> Result<(), String> {
    if epoch + 1 < current_epoch { return Err("epoch expired".into()); }
    let output = hash_attempt(initial_pk, epoch, nonce, amount);
    let zeros = leading_zero_bytes(&output);
    let required = required_zeros(amount);
    if zeros < required { return Err(format!("need {required} zeros, got {zeros}")); }
    Ok(())
}

pub struct VessMiner { pk: [u8; 32], amount: u64, epoch: u64, nonce: u64 }
impl VessMiner {
    pub fn new(pk: [u8; 32], amount: u64, epoch: u64, start_nonce: u64) -> Self { Self { pk, amount, epoch, nonce: start_nonce } }
    pub fn next_nonce(&self) -> u64 { self.nonce }
    pub fn mine_until(&mut self, mut stop: impl FnMut() -> bool) -> Option<([u8; 32], u64)> {
        let req = required_zeros(self.amount);
        loop {
            if stop() { return None; }
            let out = hash_attempt(&self.pk, self.epoch, self.nonce, self.amount);
            if leading_zero_bytes(&out) >= req { let n = self.nonce; self.nonce += 1; return Some((out, n)); }
            self.nonce += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pk() -> [u8; 32] { let mut p = [0u8; 32]; p[0..8].copy_from_slice(b"test-pk-"); p }
    #[test] fn test_curve() { assert_eq!(required_zeros(1), 3); assert_eq!(required_zeros(1000), 6); }
    #[test] fn test_determinism() { assert_eq!(hash_attempt(&pk(), 1, 42, 100), hash_attempt(&pk(), 1, 42, 100)); }
    #[test] fn test_expiry() { assert!(verify_mined(&pk(), 5, 0, 100, 8).is_err()); }
    #[test] fn test_stop() { let mut m = VessMiner::new(pk(), 1, 1, 0); assert!(m.mine_until(|| true).is_none()); }
}