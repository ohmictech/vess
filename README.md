# Vess

Vess is a compute-based token on Arbitrum. Emission tracks the work actually done. One Vess is created per unit of computation. No speculation, no gambling, no pre-mine.

Current contract:
0x00609432cb4ad6a72d7b07e279c27ddcb4682ba4

---

## Philosophy

Every Vess represents the same marginal unit of computation. Not staking, not locking, not "owning to earn". Just raw CPU cycles turned into money at a fixed ratio.

Vess inverts the usual token model. Most coins create artificial scarcity: fixed supply, halvings, deflation schedules designed to pump the chart. Vess is elastic. Issuance responds directly to hashrate. More miners means more Vess minted, fewer miners means less enters circulation. Like any commodity (oil, copper, electricity), the price is set by the market that uses it, not by a pre-programmed supply curve.

Difficulty is set by the miner, not the network: 0 bits = 1 Vess, 1 bit = 2 Vess, 2 bits = 4 Vess. No DAA, no epoch adjustments, no governance. A miner picks a target difficulty, solves a Cuckatoo proof at that difficulty, and submits it. The contract verifies the proof and credits the reward address. Compute to emission, 1:1.

---

## Miner

```
vess-miner                           # reads miner.toml, starts mining
vess-miner --generate-config         # write default miner.toml and exit
vess-miner --config /path/config.toml
```

The miner is a multi-threaded Cuckatoo27 solver that submits proofs directly to an Arbitrum RPC endpoint.

It mines on 1 core by default. Set `cores = N` in `miner.toml` to scale up. Each solver thread allocates about 1.5 GB RAM, so keep `N x 1.5 GB` within your free memory. Proofs that pass the difficulty check are handed to a single submitter thread, which serializes transactions (no nonce races), waits for receipts, and retries transient RPC failures.

**Security model.** The miner uses a separate gas-payer key (auto-generated, stored in `miner.key`). Your reward address, set in `miner.toml`, is a public wallet that never touches the miner machine. Fund the gas address with a small amount of ETH. If the machine is compromised, the attacker gets an empty gas key and no access to your Vess.

On first run the miner generates `miner.key` and `miner.address`. Fund the address in `miner.address` with ETH for fees, set your `reward_address` in `miner.toml`, and start mining. Progress is saved to `miner.json` every 30 seconds. On restart it resumes where it left off. Ctrl+C triggers a clean save-and-exit.

Optional monitoring: set `webhook_url` in `miner.toml` (an ntfy, Discord, or Slack webhook) to get a JSON notification on each confirmed mint, a low-gas-balance alert, and an optional periodic heartbeat.

---

## Why Arbitrum Stylus

- **Gas is externalized.** Miners pay ETH for gas. Vess holders pay nothing to transfer. The token itself is feeless.
- **No validator set to bootstrap.** Arbitrum already has security, finality, and a live network of RPC providers and indexers.
- **Stylus runs Rust natively.** The Cuckatoo verifier compiles to WASM and runs at near-native speed. A 42-cycle proof verifies in microseconds on-chain.
- **ERC-20 compatible.** Vess works with every Arbitrum wallet, DEX, and bridge out of the box.

The contract is minimal: `init()`, `mint()`, plus standard ERC-20 `transfer`/`approve`/`transferFrom`/`balanceOf`. No governance token, no DAO, no upgrade proxy.

---

## How minting works

1. A miner builds a preimage: `blake3("vess-id-v1" || chain_hash || diff_bits || address || timestamp || nonce)`
2. Finds a 42-cycle Cuckatoo27 proof matching that preimage (about 1.5 GB RAM per solver thread)
3. Submits `mint(chain_hash, diff_bits, address, timestamp, nonce, proof)` to the contract
4. The contract verifies the Cuckatoo proof, checks difficulty and nullifier, and credits the reward address

**Nullifiers prevent double-submission.** Each mint inserts a nullifier keyed by `blake3(preimage)` with expiry = `timestamp`. The nullifier blocks resubmission until the timestamp passes. After expiry the timestamp is stale (it must be in the future), so the mint is permanently dead.

**Storage stays bounded.** Each mint enqueues its nullifier in an expiry FIFO and reaps expired entries from the front (capped at 64 per mint, so gas stays flat even after long downtime). Expired nullifiers are provably inert (the timestamp check rejects reuse), so deleting them is always safe, and the map hovers around the 48h live window instead of growing forever.

**Chain binding.** The preimage commits to `blake3(chain_name)`, set at contract init. A proof solved for "arbitrum" will not verify on a contract deployed for another chain.

**No sender check.** Anyone can submit a valid proof to credit any address. The proof is bound to the reward address in the preimage, so the only possible "attack" is paying gas to give someone else free tokens.

---

## License

Apache 2.0
