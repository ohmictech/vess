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

/// Max expired nullifiers reaped per mint, so drain gas stays flat even after
/// a long downtime (leftovers are cleaned on subsequent mints).
const MAX_PRUNE_PER_MINT: u32 = 64;

/// ABI-encode a revert reason as standard Solidity `Error(string)` (selector
/// 0x08c379a0) so explorers, wallets, and tooling decode it natively.
fn abi_err(msg: &str) -> Vec<u8> {
    let msg = msg.as_bytes();
    let padded = msg.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(4 + 32 + 32 + padded);
    out.extend_from_slice(&[0x08, 0xc3, 0x79, 0xa0]);
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&32u64.to_be_bytes()); // head: offset to string data
    out.extend_from_slice(&word);
    word[24..].copy_from_slice(&(msg.len() as u64).to_be_bytes()); // string length
    out.extend_from_slice(&word);
    out.extend_from_slice(msg);
    out.resize(4 + 32 + 32 + padded, 0); // zero-pad to a 32-byte multiple
    out
}

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
    /// Expiry FIFO for nullifier pruning: seq → nullifier key (oldest first).
    /// Lets mint reap nullifiers once their header timestamp passes, capping
    /// the map at ~the 48h live window instead of growing forever.
    pub null_order: StorageMap<U256, StorageU256>,
    /// Front of the expiry FIFO.
    pub null_head: StorageU256,
    /// Back of the expiry FIFO (next free seq).
    pub null_tail: StorageU256,
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
            return Err(abi_err("insufficient allowance"));
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
    ///
    /// `proof` is a fixed `uint32[42]` (the 42 nonces). NOTE: fixed array on
    /// purpose — a `Vec<u8>` param maps to Solidity `uint8[]`, not `bytes`,
    /// which previously caused a selector mismatch with the miner's
    /// `bytes`-encoded calls (every mint reverted at dispatch).
    pub fn mint(
        &mut self,
        chain_hash: FixedBytes<32>,
        diff_bits: u32,
        address: FixedBytes<32>,
        timestamp: u64,
        nonce: u64,
        proof: [u32; cuckoo::CYCLE_LENGTH],
    ) -> Result<bool, Vec<u8>> {
        // ── chain binding ────────────────────────────────────────────────
        let expected = self.chain_hash.get();
        if chain_hash.0 != expected.0 {
            return Err(abi_err("wrong chain"));
        }

        // ── decode reward address ────────────────────────────────────────
        // Chain-agnostic 32-byte address. On Arbitrum the first 20 bytes
        // are the reward recipient. No sender check — anyone can submit a
        // valid proof to credit `address`.
        let mut reward = [0u8; 20];
        reward.copy_from_slice(&address.0[..20]);
        let recipient = Address::from(reward);
        if recipient == Address::ZERO {
            return Err(abi_err("zero address"));
        }

        // ── preimage + nullifier key ────────────────────────────────────
        let header = cuckoo::mint_header(&chain_hash.0, diff_bits, &address.0, timestamp, nonce);
        let nullifier_key = U256::from_be_bytes(blake3_hash(&header));

        // ── nullifier check ──────────────────────────────────────────────
        let now = self.vm().block_timestamp();
        let existing = self.nullifiers.getter(nullifier_key).get();
        if !existing.is_zero() && U256::from(now) < existing {
            return Err(abi_err("already minted"));
        }
        // An expired nullifier (now >= existing) can never mint again anyway:
        // the preimage timestamp is the stored expiry, so the staleness check
        // below rejects it. No need to clear it.

        // ── timestamp validity ───────────────────────────────────────────
        if timestamp <= now || timestamp > now + MAX_FUTURE_SECS {
            return Err(abi_err("timestamp out of range"));
        }

        // ── PoW verification ─────────────────────────────────────────────
        if !cuckoo::verify(&header, &proof, cuckoo::CYCLE_LENGTH, cuckoo::EDGE_BITS) {
            return Err(abi_err("invalid cuckatoo proof"));
        }
        let pow_hash = cuckoo::proof_to_id(&proof);
        if !check_difficulty(&pow_hash, diff_bits) {
            return Err(abi_err("difficulty not met"));
        }

        // ── nullifier insert + expiry FIFO ──────────────────────────────
        // Enqueue the key so it can be pruned once its header timestamp
        // passes. An expired nullifier is provably inert (the header's own
        // timestamp check rejects reuse), so deleting it bounds the map.
        self.nullifiers
            .setter(nullifier_key)
            .set(U256::from(timestamp));
        let tail = self.null_tail.get();
        self.null_order.setter(tail).set(nullifier_key);
        self.null_tail.set(tail + U256::from(1));
        self._prune_nullifiers(now);

        // ── reward ──────────────────────────────────────────────────────
        let reward = block_reward(diff_bits);
        self._mint(recipient, U256::from(reward));

        Ok(true)
    }

    // ── Ownership ───────────────────────────────────────────────────────

    pub fn transfer_ownership(&mut self, new_owner: Address) -> Result<bool, Vec<u8>> {
        self._ensure_owner()?;
        if new_owner == Address::ZERO {
            return Err(abi_err("zero address"));
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
            return Err(abi_err("already initialized"));
        }
        self.owner.set(FixedBytes::from(initial_owner.into_array()));
        let ch = blake3_hash(chain_name.as_bytes());
        self.chain_hash.set(FixedBytes::from(ch));
        self.total_supply.set(U256::ZERO);
        Ok(())
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

    /// Reap nullifiers whose header timestamp has passed, oldest-first.
    ///
    /// The FIFO front is the oldest insertion. If the front is still live we
    /// stop: any expired entries behind it (a later mint may have picked a
    /// smaller future timestamp) are reaped once the front expires — worst case
    /// they linger ~one extra 48h window, still a hard bound. Work is capped
    /// per call so mint gas stays flat after long gaps.
    fn _prune_nullifiers(&mut self, now: u64) {
        // head/tail are read once; this loop is the only writer, so head is
        // written back once at the end instead of every round.
        let tail = self.null_tail.get();
        let mut head = self.null_head.get();
        let mut drained = 0u32;
        while drained < MAX_PRUNE_PER_MINT && head < tail {
            let key = self.null_order.getter(head).get();
            let expiry = self.nullifiers.getter(key).get();
            if U256::from(now) < expiry {
                break; // front still live → stop
            }
            self.nullifiers.delete(key);
            self.null_order.delete(head);
            head += U256::from(1);
            drained += 1;
        }
        if drained > 0 {
            self.null_head.set(head);
        }
    }

    fn _transfer(&mut self, from: Address, to: Address, value: U256) -> Result<bool, Vec<u8>> {
        if to == Address::ZERO {
            return Err(abi_err("transfer to zero address"));
        }
        let from_bal = self.balances.getter(from).get();
        if from_bal < value {
            return Err(abi_err("insufficient balance"));
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
            return Err(abi_err("only owner"));
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

    /// Revert reasons are ABI-wrapped as standard `Error(string)` so
    /// explorers/wallets decode them natively.
    #[test]
    fn test_transfer_revert_is_readable() {
        let vm = TestVM::default();
        let mut contract = Vess::from(&vm);
        let err = contract
            .transfer(Address::from([0x22u8; 20]), U256::from(1))
            .unwrap_err();
        assert_eq!(err, abi_err("insufficient balance"));
    }

    #[test]
    fn test_init_guard() {
        let vm = TestVM::default();
        let mut contract = Vess::from(&vm);
        let owner = Address::from([0x11u8; 20]);
        contract.init(owner, "arbitrum".into()).unwrap();
        // Second init must fail with a readable "already initialized".
        let err = contract.init(owner, "arbitrum".into()).unwrap_err();
        assert_eq!(err, abi_err("already initialized"));
    }

    /// The `Error(string)` wrapper must match the Solidity ABI layout:
    /// selector 0x08c379a0, offset word = 32, length word, zero-padded data.
    #[test]
    fn test_abi_err_layout() {
        let enc = abi_err("wrong chain"); // 11 bytes -> one padded word
        assert_eq!(&enc[..4], [0x08, 0xc3, 0x79, 0xa0]);
        assert_eq!(u64::from_be_bytes(enc[28..36].try_into().unwrap()), 32); // offset
        assert_eq!(u64::from_be_bytes(enc[60..68].try_into().unwrap()), 11); // length
        assert_eq!(&enc[68..79], b"wrong chain");
        assert_eq!(enc.len(), 4 + 32 + 32 + 32);
        assert!(enc[79..].iter().all(|&b| b == 0)); // padding
    }

    /// The expiry FIFO must reap expired nullifiers (and free the queue slots)
    /// while leaving still-live entries untouched, and advance head past the
    /// reaped entries.
    #[test]
    fn test_nullifier_pruning() {
        let vm = TestVM::default();
        let mut contract = Vess::from(&vm);
        let now: u64 = 2_000_000_000;

        let k_old = U256::from(111u64);
        let k_live = U256::from(222u64);
        contract.null_head.set(U256::ZERO);
        contract.null_tail.set(U256::from(2u8));
        contract.nullifiers.setter(k_old).set(U256::from(now - 100));
        contract.nullifiers.setter(k_live).set(U256::from(now + 1000));
        contract.null_order.setter(U256::ZERO).set(k_old);
        contract.null_order.setter(U256::from(1u8)).set(k_live);

        contract._prune_nullifiers(now);

        // Expired key removed, head advanced past it, queue slot freed.
        assert!(contract.nullifiers.getter(k_old).get().is_zero());
        assert_eq!(contract.null_head.get(), U256::from(1u8));
        assert!(contract.null_order.getter(U256::ZERO).get().is_zero());
        // Live key untouched.
        assert!(!contract.nullifiers.getter(k_live).get().is_zero());
    }
}
