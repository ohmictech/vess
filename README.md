# Vess

Vess is a proof-of-work blockchain with one asset, also called Vess. Accounts are post-quantum public
keys, and a transaction moves a balance from one account to another. There are no smart contracts, no
tokens, and no second asset.

**Experimental software:** Vess has not been independently audited. Do not rely on it to protect
valuable funds.

## What it is

| | |
|---|---|
| Consensus | Proof of work; the chain with the most accumulated work wins, no finality |
| Block time | 1 second (target) |
| Mining | BLAKE3-256 over the 234-byte block header |
| Signatures | ML-DSA-65 (post-quantum) |
| Accounts | Public key hash, with balance, nonce, and a 32-byte state commitment |
| State | 256-level sparse Merkle tree, root committed in every header |
| Block reward | `100 × genesis_target / target`, rounded down with a minimum of 1; 1% development fee, rounded down, comes out of the reward |
| Supply | Work-linked issuance; no halving or scheduled cap |
| Pre-mine | None |
| Block size | 1 MiB maximum |
| Networks | `devnet`, `testnet`, `mainnet`; ports 9732 (P2P) and 9733 (RPC) |

## What it does differently

Vess ties the block reward to difficulty instead of using a halving schedule. A block at twice the
genesis difficulty pays twice the reward. This aims to keep issuance per unit of mining work roughly
constant, subject to integer rounding and the minimum reward. It does not guarantee a market price or
mining profitability.

That rule shapes the rest. The puzzle does not need to resist ASICs, so mining is plain BLAKE3. State
holds only accounts, so headers stay small and proofs and snapshots stay simple. Accounts are
post-quantum, so a transfer is about 5.4 KB and the network is built for that.

## Running a node

Build:

```sh
cargo build --release
BIN=./target/release/vess
```

The examples use the default `devnet`. Choose a strong, unique password, store it securely, and
provide it through an environment variable or password file. Back up the encrypted keyfile at
`<datadir>/wallets/<name>.key` and the password separately; losing either can mean losing access to
funds. Set `VESS_WALLET_PASSWORD` in your environment before running these commands.

Create a chain, make a wallet, and mine two blocks:

```sh
$BIN node init --datadir ./chain
$BIN wallet new --datadir ./chain --name alice --password-env VESS_WALLET_PASSWORD
# hd=1  account=<hex>  index=0

$BIN miner --datadir ./chain --payout <account> --blocks 2
$BIN wallet balance --datadir ./chain --name alice --password-env VESS_WALLET_PASSWORD
# balance=198  next_nonce=0
```

Run a node, either mining or joining a network:

```sh
$BIN node run --datadir ./chain --rpc 9733 --port 9732 --mine --payout <account>
$BIN node run --datadir ./chain2 --rpc 9743 --port 9742 --seed 127.0.0.1:9732
```

There are no built-in bootstrap peers. Supply a known peer with `--seed`, `--peer`, or `VESS_SEEDS`
when joining a network. Peers discovered after connecting are remembered in `<datadir>/peers.txt`.
For testnet or mainnet, pass `--network testnet` or `--network mainnet` consistently to commands
that open the data directory.

The current protocol uses millisecond block timestamps and a testnet genesis target of `2^235`.
All networks are incompatible with earlier builds: use a new data directory and connect only to
peers using the same protocol and genesis.

Mining timestamps use the local clock in milliseconds and must exceed median chain time. Nodes
temporarily reject blocks more than two minutes ahead of their local clock, so keep system clocks
synchronized. The fixed genesis is shared by all nodes; the first mined block records its own time,
and a stalled chain can resume at the current time. A long pause still affects the retarget window
until that pause moves out of it. Built-in miners refresh their templates approximately every second
while searching, rather than continuing to mine indefinitely with an old timestamp.

Send a payment and follow it:

```sh
$BIN wallet send  --datadir ./chain --name alice --to <a
ccount> --amount 5 --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
$BIN wallet watch --datadir ./chain --name alice --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
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
`--trust-snapshot` to join a pruned peer by state snapshot. Trusting a snapshot across a history gap
means trusting that peer's state. RPC is unauthenticated and listens only on loopback.