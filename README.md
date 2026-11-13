# Vess

Vess is a proof-of-work blockchain with one asset, also called Vess. Accounts are post-quantum public
keys, and a transaction moves a balance from one account to another. There are no smart contracts, no
tokens, and no second asset.

## What it is

| | |
|---|---|
| Consensus | Proof of work; the chain with the most accumulated work wins, no finality |
| Block time | 1 second (target) |
| Mining | BLAKE3-256 over the 234-byte block header |
| Signatures | ML-DSA-65 (post-quantum) |
| Accounts | Public key hash, with balance, nonce, and a 32-byte state commitment |
| State | 256-level sparse Merkle tree, root committed in every header |
| Block reward | `100 × genesis_target / target`; 99% to the miner, 1% development fee |
| Supply | Unbounded, proportional to cumulative work; no halving, no cap |
| Pre-mine | None |
| Block size | 1 MiB maximum |
| Networks | `devnet`, `testnet`, `mainnet`; ports 9732 (P2P) and 9733 (RPC) |

## What it does differently

Most proof-of-work chains fix the block reward and halve it on a schedule, so growing hashrate dilutes
every miner and the chain depends on the price rising to stay alive. Vess ties the reward to
difficulty instead: twice the difficulty, twice the reward. Revenue per unit of hashpower stays
constant, and supply grows with the work done rather than with the calendar.

That rule shapes the rest. The puzzle does not need to resist ASICs, so mining is plain BLAKE3. State
holds only accounts, so headers stay small and proofs and snapshots stay simple. Accounts are
post-quantum, so a transfer is about 5.4 KB and the network is built for that.

## Running a node

Build:

```sh
cargo build --release
BIN=./target/release/vess
```

Create a chain, make a wallet, and mine two blocks:

```sh
$BIN node init --datadir ./chain
printf 'correct horse battery staple' > ./chain/pw
$BIN wallet new --datadir ./chain --name alice --password-file ./chain/pw
# hd=1  account=<hex>  index=0

$BIN miner --datadir ./chain --payout <account> --blocks 2
$BIN wallet balance --datadir ./chain --name alice --password-file ./chain/pw
# balance=198  next_nonce=0
```

Run a node, either mining or joining a network:

```sh
$BIN node run --datadir ./chain --rpc 9733 --port 9732 --mine --payout <account>
$BIN node run --datadir ./chain2 --rpc 9743 --port 9742 --seed 127.0.0.1:9732
```

Peers are discovered automatically and remembered in `<datadir>/peers.txt`, so a restart with no
flags rejoins the network.

Send a payment and follow it:

```sh
$BIN wallet send  --datadir ./chain --name alice --to <account> --amount 5 --password-file ./chain/pw
$BIN wallet watch --datadir ./chain --name alice --rpc 127.0.0.1:9733 --password-file ./chain/pw
```

Inspect a running node:

```sh
$BIN node status  --rpc 127.0.0.1:9733                 # height, tip, supply, next reward, peers, bans
$BIN node block   --rpc 127.0.0.1:9733 --height 12
$BIN node tx      --rpc 127.0.0.1:9733 --id <txid>
$BIN node account --rpc 127.0.0.1:9733 --account <id>  # balance, nonce, state commitment
$BIN node proof   --rpc 127.0.0.1:9733 --account <id>  # inclusion or non-inclusion proof
$BIN node params  --network mainnet                    # every consensus constant
```

`node run` also accepts `--prune-blocks N` and `--prune-headers N` to keep only recent history, and
`--trust-snapshot` to join a pruned peer by state snapshot.