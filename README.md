# Vess

**Vess is a decentralized compute oracle, platform-agnostic (currently living on Arbitrum). Emission is tied directly to inputted work, no speculation, no gambling, pure commodity.**

---

## Philosophy

Every Vess ever created represents the same marginal unit of computation. Not staking, not locking, not "owning to earn" — just raw CPU cycles converted into money at a fixed ratio.

Vess inverts the usual token model. Most coins create artificial scarcity: fixed supply, halvings, deflation schedules designed to pump the chart. Vess is elastic — issuance responds directly to hashrate. If more miners join, more Vess is minted. If miners leave, less enters circulation. The *per-unit* cost of creation stays flat. Like any commodity — oil, copper, electricity — price is set by the market that uses it, not by a pre-programmed supply curve.

**0 bits = 1 Vess (every valid proof earns). 1 bit = 2 Vess. 2 bits = 4 Vess.** That's it. No DAA, no epoch adjustments, no governance. The miner picks their target difficulty, solves a Cuckatoo proof at that difficulty, and submits it. The contract verifies the proof and credits the reward address. Compute → emission, 1:1.

---

## Why Arbitrum Stylus

Vess originally ran on its own L1 (source retained in this repo). The pivot to an Arbitrum Stylus contract is pragmatic:

- **Gas is externalized.** Miners pay ETH for gas, Vess holders pay nothing to transfer. The token itself is feeless.
- **No bootstrapping a validator set.** Arbitrum already has security, finality, and a live network of RPC providers and indexers.
- **Stylus runs Rust natively.** The Cuckatoo verifier compiles to WASM and executes at near-native speed. A 42-cycle proof verifies in microseconds on-chain.
- **ERC-20 compatibility.** Vess works with every Arbitrum wallet, DEX, and bridge out of the box.

The contract is minimal: `init()`, `mint()`, plus standard ERC-20 `transfer`/`approve`/`transferFrom`/`balanceOf`. No governance token, no DAO, no upgrade proxy.

---

## How minting works

1. Miner builds a preimage: `blake3("vess-id-v1" || chain_hash || diff_bits || address || timestamp || nonce)`
2. Finds a 42-cycle Cuckatoo27 proof matching that preimage (1.3 GB RAM, single-threaded)
3. Submits `mint(chain_hash, diff_bits, address, timestamp, nonce, proof)` to the contract
4. Contract verifies the Cuckatoo proof, checks difficulty, checks nullifier, credits the reward address

**Nullifiers prevent double-submission.** Each mint inserts a nullifier keyed by `blake3(preimage)` with expiry = `timestamp`. The nullifier blocks resubmission until the timestamp passes. After expiry, the timestamp itself is stale (must be in the future), so the mint is permanently dead.

**Chain binding.** The preimage commits to `blake3(chain_name)`, set at contract init. A proof solved for "arbitrum" won't verify on a contract deployed for "ethereum" or any other chain.

**No sender check.** Anyone can submit a valid proof to credit any address — the proof is bound to the reward address in the preimage, so paying gas to give someone else free tokens is the only possible "attack."

---

## Miner (ultra-light)

```
vess-miner                           # reads miner.toml, starts mining
vess-miner --generate-config         # write default miner.toml and exit
vess-miner --config /path/config.toml
```

The miner is a multi-threaded Cuckatoo27 solver that submits proofs directly to Arbitrum RPC.

**Security model:** The miner uses a separate gas-payer key (auto-generated, stored in `miner.key`). Your reward address — set in `miner.toml` — is a public wallet that never touches the miner machine. Fund the gas address with a small amount of ETH; if the machine is compromised, the attacker gets an empty gas key and no access to your Vess.

On first run the miner generates `miner.key` and `miner.address`. Fund the address in `miner.address` with ETH, set your `reward_address` in `miner.toml`, and start mining.

The miner saves progress to `miner.json` every 30 seconds. On restart it resumes from where it left off. Ctrl+C triggers a clean save-and-exit.

---

## Workspace

| Crate | Purpose |
|-------|---------|
| `vess-crypto` | Blake3, Cuckatoo27 solver/verifier, difficulty, shared types (no_std compatible) |
| `vess-contract` | Arbitrum Stylus ERC-20 token with Cuckatoo minting |
| `vess-miner` | Multi-threaded miner with alloy RPC, state persistence, auto key generation |

---

## License

Apache 2.0
