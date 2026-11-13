# Vess

An account-based proof-of-work ledger with **one asset**, where the block reward *is* the difficulty
the block was mined at.

```text
reward = 100 * genesis_target / target     # genesis difficulty pays 100; twice as hard pays 200
```

Revenue per hash is constant. Supply is the integral of work performed. No curve, no halving, no cap,
no scarcity.

---

## Why it is built this way

Bitcoin pays a fixed subsidy that halves on a timer, so reward per hash falls forever and mining only
works if the price rises. Vess inverts that: **emission is the difficulty**, so one Vess is a claim on a
fixed quantity of energy. If hashrate doubles, emissions double with it and per-hash income does not move.

That is a deliberate refusal of the store-of-value story. Vess is a commodity ledger with a predictable
marginal cost, not a vault. Everything else follows from it:

- **BLAKE3 over the 234-byte header.** No memory-hard puzzle; ASICs are accepted, because resisting them
  was tried five times and lost (architecture.md §8.3). The reward rule decides who mines, not the puzzle.
- **One second blocks**, retargeted every 64 blocks, clamped to ±4× per window.
- **1% of every block goes to a hard-coded development account**, out of the reward — total issuance is
  unchanged, and the split cannot be skipped.
- **Accounts, not UTXOs.** An account id *is* the hash of an ML-DSA-65 public key (post-quantum), and
  carries `balance`, `next_nonce`, and an opaque 32-byte `state_hash` that consensus never interprets.
- **Nothing else.** No script, no second asset, no nullifiers, no smart contracts.

## Quick start

```sh
cargo build --release
BIN=./target/release/vess

$BIN node init --datadir ./chain
printf 'correct horse battery staple' > ./chain/pw
$BIN wallet new --datadir ./chain --name alice --password-file ./chain/pw
# hd=1  account=<hex>  index=0        (one master seed, accounts derived by index)

# two blocks at genesis difficulty, each paying 100: 99 to the miner, 1 to the dev account
$BIN miner --datadir ./chain --payout <account> --blocks 2
$BIN wallet balance --datadir ./chain --name alice --password-file ./chain/pw
# balance=198  next_nonce=0
```

Send, then watch it confirm — no polling loop, no guessed interval:

```sh
$BIN wallet send  --datadir ./chain --name alice --to <account> --amount 5 --password-file ./chain/pw
$BIN wallet watch --datadir ./chain --name alice --rpc 127.0.0.1:9733 --password-file ./chain/pw
# start balance=198 … / balance=193 next_nonce=1 …
```

## Running a node

```sh
vess node run --datadir ./chain --rpc 9733 --port 9732 --peer 127.0.0.1:9800
vess node run --datadir ./chain --port 9732 --seed 1.2.3.4:9732    # bootstrap, then discover
```

Peers are found, not configured. A completed session records the address and the static key its
handshake proved; `GET_ADDR`/`ADDR` carry only those verified records, and a crawler dials them. The book
persists to `<datadir>/peers.txt`, so a node restarted with no flags still rejoins. Seed sources merge in
order: `--peer`, `--seed`, `VESS_SEEDS`, then the per-network defaults compiled in.

Sessions are `Noise_XX`-encrypted before a single frame is sent, and an address verified once is
**key-pinned**: a later session presenting a different key is refused. Bans persist in
`<datadir>/bans.txt`, so a restart no longer hands a flooding peer a clean slate.

Ask a running node anything over loopback RPC:

```sh
vess node status   --rpc 127.0.0.1:9733      # height, supply, next reward, peers, bans
vess node block    --rpc 127.0.0.1:9733 --height 12
vess node tx       --rpc 127.0.0.1:9733 --id <txid>     # status + who paid whom, how much
vess node account  --rpc 127.0.0.1:9733 --account <id>  # exists, balance, nonce, state hash
vess node proof    --rpc 127.0.0.1:9733 --account <id>  # 256-sibling inclusion or non-inclusion
vess node watch    --rpc 127.0.0.1:9733 --count 3       # long-poll: the next 3 tips
```

**History is prunable.** `--prune-blocks N --prune-headers N` keeps a window and deletes the rest. A peer
that falls behind such a node can only join by state snapshot, which needs `--trust-snapshot` because the
built-in checkpoint lists are still empty. Old transactions still report their depth from the index.

## The numbers

| | |
|---|---|
| Block time | 1 s; retarget every 64 blocks, ±4× clamp, median-time-past over 11 blocks |
| Reward | `100 × genesis_target / target`, floor 1, 1% to the dev account |
| Genesis target | devnet `2^240`, testnet `2^232`, mainnet `2^226` |
| Block size | 1 MiB; a transfer is ~5.4 KB because the signature is post-quantum |
| Accounts | ML-DSA-65; id = hash of public key; 256-level sparse Merkle state root |
| Transport | Noise_XX + ChaCha20-Poly1305; key pinning after first contact |
| Keyfiles | Argon2id (64 MiB, t=3) + ChaCha20-Poly1305; HD master seed, hardened derivation |
| Tests | 186, with clippy `-D warnings` and `fmt --check` clean |

The design document is [architecture.md](./architecture.md). Consensus constants are not a separate file:
`vess node params --network mainnet` prints them from the binary, so the two cannot disagree.

## What it does not do

No privacy. No smart contracts. No light clients. No ASIC resistance. Nothing is final — only
heavier-work branches win — and while checkpoints are enforced, every network ships an empty list, so a
node syncing from scratch still trusts the first valid history it is shown. The ML-DSA implementation is
not independently audited. architecture.md §23 has the full, unflattering list.

## Build

```sh
cargo build --release
cargo test --workspace      # 186 tests
./target/release/vess node params --network devnet
```
