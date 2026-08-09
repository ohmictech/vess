#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use stylus_sdk::{
    alloy_primitives::{Address, FixedBytes, U256},
    prelude::*,
    storage::{StorageFixedBytes, StorageMap, StorageU256},
};

use alloy_sol_types::sol;

use vess_crypto::{blake3_hash, block_reward, check_difficulty, cuckoo};

sol! {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

const MAX_FUTURE_SECS: u64 = 48 * 3600;

#[storage]
#[entrypoint]
pub struct Vess {
    /// blake3 of the chain name — set at init, never changes.
    pub chain_hash: StorageFixedBytes<32>,
    /// ERC-20: total supply.
    pub total_supply: StorageU256,
    /// ERC-20: address → balance.
    pub balances: StorageMap<Address, StorageU256>,
    /// ERC-20: owner → (spender → allowance).
    pub allowances: StorageMap<Address, StorageMap<Address, StorageU256>>,
    /// Owner address (can transfer ownership).
    pub owner: StorageFixedBytes<20>,
    /// Mint nullifier: preimage_hash → expiry timestamp.
    pub nullifiers: StorageMap<U256, StorageU256>,
}

#[public]
impl Vess {
    // ── ERC-20 metadata ─────────────────────────────────────────────────

    pub fn name() -> Result<String, Vec<u8>> {
        Ok(String::from("Vess"))
    }

    pub fn symbol() -> Result<String, Vec<u8>> {
        Ok(String::from("VESS"))
    }

    pub fn decimals() -> Result<u8, Vec<u8>> {
        Ok(0)
    }

    // ── ERC-20: total supply ────────────────────────────────────────────

    pub fn total_supply(&self) -> Result<U256, Vec<u8>> {
        Ok(self.total_supply.get())
    }

    // ── ERC-20: balance / allowance ─────────────────────────────────────

    pub fn balance_of(&self, account: Address) -> Result<U256, Vec<u8>> {
        Ok(self.balances.getter(account).get())
    }

    pub fn allowance(&self, owner: Address, spender: Address) -> Result<U256, Vec<u8>> {
        Ok(self.allowances.getter(owner).getter(spender).get())
    }

    // ── ERC-20: approve ─────────────────────────────────────────────────

    pub fn approve(&mut self, spender: Address, value: U256) -> Result<bool, Vec<u8>> {
        let sender = self.vm().msg_sender();
        self.allowances.setter(sender).setter(spender).set(value);
        self.vm().log(Approval {
            owner: sender,
            spender,
            value,
        });
        Ok(true)
    }

    // ── ERC-20: transfer ────────────────────────────────────────────────

    pub fn transfer(&mut self, to: Address, value: U256) -> Result<bool, Vec<u8>> {
        let from = self.vm().msg_sender();
        self._transfer(from, to, value)
    }

    // ── ERC-20: transferFrom ────────────────────────────────────────────

    pub fn transfer_from(
        &mut self,
        from: Address,
        to: Address,
        value: U256,
    ) -> Result<bool, Vec<u8>> {
        let spender = self.vm().msg_sender();
        let allowed = self.allowances.getter(from).getter(spender).get();
        if allowed < value {
            return Err("insufficient allowance".into());
        }
        // Unchecked sub is safe due to check above
        self.allowances
            .setter(from)
            .setter(spender)
            .set(allowed - value);
        self._transfer(from, to, value)
    }

    // ── Mint: Cuckatoo proof-of-work ────────────────────────────────────

    /// Submit a Cuckatoo proof.  Caller is credited `1 << diff_bits` Vess.
    ///
    /// All fields must match the preimage the miner solved against:
    /// `mint_header(chain_hash, diff_bits, address, timestamp, nonce)`.
    pub fn mint(
        &mut self,
        chain_hash: FixedBytes<32>,
        diff_bits: u32,
        address: FixedBytes<32>,
        timestamp: u64,
        nonce: u64,
        proof: Vec<u8>,
    ) -> Result<bool, Vec<u8>> {
        // ── chain binding ────────────────────────────────────────────────
        let expected = self.chain_hash.get();
        if chain_hash.0 != expected.0 {
            return Err("wrong chain".into());
        }

        // ── decode reward address ────────────────────────────────────────
        // Chain-agnostic 32-byte address. On Arbitrum the first 20 bytes
        // are the reward recipient. No sender check — anyone can submit a
        // valid proof to credit `address`.
        let mut reward = [0u8; 20];
        reward.copy_from_slice(&address.0[..20]);
        let recipient = Address::from(reward);
        if recipient == Address::ZERO {
            return Err("zero address".into());
        }

        // ── preimage + nullifier key ────────────────────────────────────
        let header = cuckoo::mint_header(&chain_hash.0, diff_bits, &address.0, timestamp, nonce);
        let nullifier_key = U256::from_be_bytes(blake3_hash(&header));

        // ── nullifier check ──────────────────────────────────────────────
        let now = self.vm().block_timestamp();
        let existing = self.nullifiers.getter(nullifier_key).get();
        if !existing.is_zero() && U256::from(now) < existing {
            return Err("already minted".into());
        }
        // An expired nullifier (now >= existing) can never mint again anyway:
        // the preimage timestamp is the stored expiry, so the staleness check
        // below rejects it. No need to clear it.

        // ── timestamp validity ───────────────────────────────────────────
        if timestamp <= now || timestamp > now + MAX_FUTURE_SECS {
            return Err("timestamp out of range".into());
        }

        // ── PoW verification ─────────────────────────────────────────────
        if proof.len() != cuckoo::CYCLE_LENGTH * 4 {
            return Err("bad proof length".into());
        }
        let nonces: Vec<u32> = proof
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        if !cuckoo::verify(&header, &nonces, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
            return Err("invalid cuckatoo proof".into());
        }
        let pow_hash = cuckoo::proof_to_id(&nonces);
        if !check_difficulty(&pow_hash, diff_bits) {
            return Err("difficulty not met".into());
        }

        // ── nullifier insert ─────────────────────────────────────────────
        self.nullifiers
            .setter(nullifier_key)
            .set(U256::from(timestamp));

        // ── reward ──────────────────────────────────────────────────────
        let reward = block_reward(diff_bits);
        self._mint(recipient, U256::from(reward));

        Ok(true)
    }

    // ── Ownership ───────────────────────────────────────────────────────

    pub fn transfer_ownership(&mut self, new_owner: Address) -> Result<bool, Vec<u8>> {
        self._ensure_owner()?;
        if new_owner == Address::ZERO {
            return Err("zero address".into());
        }
        self.owner.set(FixedBytes::from(new_owner.into_array()));
        Ok(true)
    }

    // ── Init ────────────────────────────────────────────────────────────

    /// One-time initialisation: set the owner and chain binding.
    /// `chain_name` is the raw string, e.g. "arbitrum" — its blake3 is stored.
    pub fn init(&mut self, initial_owner: Address, chain_name: String) -> Result<(), Vec<u8>> {
        let current: FixedBytes<20> = self.owner.get();
        if current != FixedBytes::<20>::ZERO {
            return Err("already initialized".into());
        }
        self.owner.set(FixedBytes::from(initial_owner.into_array()));
        let ch = blake3_hash(chain_name.as_bytes());
        self.chain_hash.set(FixedBytes::from(ch));
        self.total_supply.set(U256::ZERO);
        Ok(())
    }

    // ── Diagnostics (bisection probes) ─────────────────────────────────
    // These are TEMPORARY helpers to isolate why `mint` traps on-chain.
    // Call each via eth_call; whichever reverts empty pinpoints the fault.

    /// Does basic dispatch work for a no-arg function?
    pub fn probe(&self) -> Result<bool, Vec<u8>> {
        Ok(true)
    }

    /// Does reading the `chain_hash` storage field work?
    pub fn probe_chain(&self) -> Result<FixedBytes<32>, Vec<u8>> {
        Ok(self.chain_hash.get())
    }

    /// Do mint's static arg types decode and does blake3 (mint_header) work?
    pub fn probe_header(
        &self,
        chain_hash: FixedBytes<32>,
        diff_bits: u32,
        address: FixedBytes<32>,
        timestamp: u64,
        nonce: u64,
    ) -> Result<FixedBytes<32>, Vec<u8>> {
        Ok(FixedBytes::from(cuckoo::mint_header(
            &chain_hash.0,
            diff_bits,
            &address.0,
            timestamp,
            nonce,
        )))
    }

    /// Do mint's full args (incl. dynamic bytes) decode, and does verify run?
    pub fn probe_verify(
        &self,
        chain_hash: FixedBytes<32>,
        diff_bits: u32,
        address: FixedBytes<32>,
        timestamp: u64,
        nonce: u64,
        proof: Vec<u8>,
    ) -> Result<bool, Vec<u8>> {
        let nonces: Vec<u32> = proof
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let header =
            cuckoo::mint_header(&chain_hash.0, diff_bits, &address.0, timestamp, nonce);
        Ok(cuckoo::verify(
            &header,
            &nonces,
            cuckoo::CYCLE_LENGTH,
            cuckoo::EDGE_BITS,
        ))
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────

impl Vess {
    fn _mint(&mut self, to: Address, value: U256) {
        let supply = self.total_supply.get();
        self.total_supply.set(supply + value);
        let bal = self.balances.getter(to).get();
        self.balances.setter(to).set(bal + value);
        self.vm().log(Transfer {
            from: Address::ZERO,
            to,
            value,
        });
    }

    fn _transfer(&mut self, from: Address, to: Address, value: U256) -> Result<bool, Vec<u8>> {
        if to == Address::ZERO {
            return Err("transfer to zero address".into());
        }
        let from_bal = self.balances.getter(from).get();
        if from_bal < value {
            return Err("insufficient balance".into());
        }
        self.balances.setter(from).set(from_bal - value);
        let to_bal = self.balances.getter(to).get();
        self.balances.setter(to).set(to_bal + value);
        self.vm().log(Transfer { from, to, value });
        Ok(true)
    }

    fn _ensure_owner(&self) -> Result<(), Vec<u8>> {
        let sender = self.vm().msg_sender();
        let owner: FixedBytes<20> = self.owner.get();
        if sender.into_array() != owner.0 {
            return Err("only owner".into());
        }
        Ok(())
    }
}

// ── Native tests (stylus-test TestVM) ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stylus_sdk::{
        alloy_primitives::{Address, U256},
        testing::TestVM,
    };

    /// Proves the current source's error path returns READABLE revert data
    /// ("insufficient balance") — unlike the stale on-chain build that
    /// reverted empty. A fresh deploy from this source must carry error data.
    #[test]
    fn test_transfer_revert_is_readable() {
        let vm = TestVM::default();
        let mut contract = Vess::from(&vm);
        let err = contract
            .transfer(Address::from([0x22u8; 20]), U256::from(1))
            .unwrap_err();
        assert_eq!(err, b"insufficient balance".to_vec());
    }

    #[test]
    fn test_init_guard() {
        let vm = TestVM::default();
        let mut contract = Vess::from(&vm);
        let owner = Address::from([0x11u8; 20]);
        contract.init(owner, "arbitrum".into()).unwrap();
        // Second init must fail with a readable "already initialized".
        let err = contract.init(owner, "arbitrum".into()).unwrap_err();
        assert_eq!(err, b"already initialized".to_vec());
    }
}
