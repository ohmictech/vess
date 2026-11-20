# Vess

Vess is a decentralized, proof-of-work, post-quantum blockchain ledger. It exists to fill the gap that crypto should have existed to fill but never did: a truly neutral, trustless, digital unit of account. It functions as a simple, reliable, and fast settlement network (1 block per second) with a monetary basis rooted in thermodynamics rather than policy or policymakers.

This network has no pre-mine, ICO, allocations, hidden fees, or staking. It is not intended to increase in price indefinitely, or be held and sold later for profit. There is no benefit for being early and no penalty for being late. The only thing that matters is how many hashes you produce.

# What is different

Vess ties the block reward to difficulty instead of using a halving schedule. A block at twice the
genesis difficulty pays twice the reward. This aims to keep issuance per unit of mining work roughly
constant. This is not the same as debasement, as every hash represents a tangible input cost.

Bitcoin, and every other PoW cryptocurrency with engineered scarcity, requires a continuous increase in asset price for security to remain stable long-term. This monetary policy has a problematic consequence: it cannot be used as a reliable unit of account. So the crypto narrative has shifted, and every project has settled into either the "store of value" camp, or the "fiat facilitation" camp.

On the latter, crypto technology has become nothing more than a convenient transportation layer for national currencies and securities. The same problems with fiat live in stablecoins. Freeze functions, the cantillion effect, regulation, debasement.

Vess reduces the impact of speculation on price, relying on the sunk costs of electricity and hardware to be the basis of commodity-style value, allowing Vess to be used as a truly decentralized, trustless, fair, digital unit of account where Bitcoin cannot be.

It seeks to become the borderless, sovereign "stablecoin" of the digital age.

## Running a node

Download an archive for your platform from [GitHub Releases](https://github.com/ohmictech/vess/releases)
and extract it to a writable directory. Release notes explain how to verify the download.
Alternatively, build with Rust:

```sh
cargo build --release
```

Set the executable path for the examples below. For a downloaded archive, use the path to its
extracted executable instead:

```sh
# Linux or macOS
BIN=./target/release/vess
```

```powershell
# Windows PowerShell
$BIN = ".\target\release\vess.exe"
```

The remaining commands use shell syntax. In PowerShell, use `& $BIN` wherever they show `$BIN`.

### Configuration

Vess is configured by `vess.toml`, kept **beside the executable** — `target/release/vess.toml` for a
source build. The first command you run creates it with the defaults below and creates the data
directory next to it; later runs read it and never overwrite it. `--config FILE` selects another file.
Running `$BIN` with no arguments starts the node on that config.

To create the config before any chain exists, run `$BIN node params`: it writes the file, then prints
consensus constants without opening a database.

```toml
network = "devnet"
datadir = "./chain"
rpc_port = 9733
p2p_port = 9732
peers = []
seeds = []
mine = false
mine_threads = 1
trust_snapshot = true

# Optional; unset means "use the default shown".
# payout = "YOUR_64_CHARACTER_ACCOUNT_ADDRESS"
# finality_depth = 10000
# prune_blocks = 16384
# prune_headers = 100000000
# prune_undo = 16384
```

| key | meaning |
|---|---|
| `network` | `devnet`, `testnet`, or `mainnet`. This selects the chain, so give each network its own `datadir`. |
| `datadir` | Data directory, relative to the config file. Holds `ledger.redb`, `identity.key`, `wallets/`, and `peers.txt`. |
| `rpc_port` | Local RPC port. Bound to `127.0.0.1` only, with no authentication. |
| `p2p_port` | Listening port for peers. |
| `peers` | Addresses to keep a permanent session with. |
| `seeds` | Bootstrap hints, merged with `--seed` and the `VESS_SEEDS` environment variable. A seed becomes an ordinary peer once it answers. |
| `mine` | Mine continuously. Requires `payout`. |
| `mine_threads` | CPU workers for the node miner, 1–256. |
| `payout` | Account that receives block rewards and fees. |
| `trust_snapshot` | Accept a state snapshot this node cannot prove itself. See [State snapshots](#state-snapshots). |
| `finality_depth` | Blocks below the tip that no competing branch may replace. `0` disables the rule. |
| `prune_blocks` | Blocks below the tip whose bodies are deleted. `0` keeps every body. |
| `prune_headers` | Blocks below the tip whose headers are deleted. `0` keeps every header. |
| `prune_undo` | Blocks below the tip whose undo records are deleted. Only a reorg reads them. `0` keeps them all. |

Unknown keys are rejected, so a typo fails at startup instead of being silently ignored. Relative
paths in the config resolve against the config file's directory, and command-line options override
config values for one run.

The node is a single long-running process: it follows the heaviest chain, applies blocks, keeps the
mempool, and serves RPC for wallets and miners. Stop it with Ctrl+C; nothing is lost, because each
block commits atomically.

### Networks

The default is devnet, which needs no peers and mines trivially. For testnet, set `network =
"testnet"`, point `datadir` somewhere separate such as `"./testnet-chain"`, and add a real address to
`seeds`, for example `seeds = ["PEER_ADDRESS:9732"]`. Vess has no built-in bootstrap node yet, so a
testnet node with no reachable seeds will not sync.

### Mining

Create a wallet first (see [Wallet](#wallet)), then set `mine = true` and `payout` to that account in
the config, and optionally `mine_threads`. The separate `vess miner` command instead mines a fixed
number of blocks (`--blocks`, default 1), single-threaded, through a running node's RPC, and never
changes the config. Never put a wallet password or recovery phrase in the config.

### Storage

By default a node keeps 16,384 blocks of bodies and undo records and effectively all headers, so it
can follow forks and serve recent history but not answer for old blocks. To run an archival node set
`prune_blocks = 0` and `prune_headers = 0`; to keep every body but still drop the reorg log, leave
`prune_blocks = 0` and set `prune_undo` to a number. Retention can only remove data: raising a window
does not restore blocks that were already pruned, and the policy is stored in the database, so a run
without flags keeps whatever it finds.

`--prune-blocks`, `--prune-headers`, `--prune-undo`, and `--finality-depth` override these for one run
and persist the new policy. `vess export` writes the bodies a node still holds as verifiable chunk
files; `vess archive verify|encode|decode` checks and erasure-codes them for mirroring. See
`architecture.md` §16.3.

### State snapshots

A node that has saved nothing and cannot replay from its peers may install a state snapshot, which
must match the state root of a block it already holds. Snapshot trust is enabled by default and a
single connected peer can authorize one, so with `trust_snapshot = true` a malicious peer can present
false state; history is then replayed in the background when possible, and invalid history stops
normal operation. Set `trust_snapshot = false` (or pass `--no-trust-snapshot`) to refuse any snapshot
this node cannot verify itself.

### Wallet

Wallet commands read `network` and `datadir` from the config. Keep the password in an environment
variable rather than an argument:

```sh
export VESS_WALLET_PASSWORD='...'
$BIN wallet new --name alice --password-env VESS_WALLET_PASSWORD
$BIN wallet restore --name alice-recovered --password-env VESS_WALLET_PASSWORD
```

`restore` reads the recovery phrase without echoing it; add `--mnemonic-stdin` to pipe the phrase in
instead of typing it.

A new wallet prints a 24-word recovery phrase **once**; it and the encrypted keyfile are the backup,
and anyone holding either can spend the funds. Older keyfiles have no phrase, so keep those files and
passwords. Restore on the same network.

With a node running on the same machine:

```sh
$BIN wallet balance --name alice --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
$BIN wallet send --name alice --to ACCOUNT --amount 5 --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
```

`--to` takes a 32-byte account address in hex. `wallet set-state --state-hash HASH` commits an opaque
32-byte value to the account; Vess does not store the message it commits to.

### Signing messages

Signing and verification work offline, with no node:

```sh
$BIN wallet sign --name alice --message "Hello" --password-env VESS_WALLET_PASSWORD > proof.txt
$BIN wallet sign verify --message "Hello" --proof proof.txt --account EXPECTED_ACCOUNT
```

`verify` prints `valid=1` only for the exact message, and only tells you the signature is by whoever
owns `EXPECTED_ACCOUNT`; obtain that address independently. Include the application, purpose, and a
fresh challenge in the message, and keep secrets out of command arguments.

### Node commands

```sh
$BIN node status  --rpc 127.0.0.1:9733
$BIN node history --rpc 127.0.0.1:9733
$BIN --help
```

`node status` reports height, tip, chain work, supply, mempool, peers, and the active prune policy.
`node history` reports snapshot verification progress, where `pending` and `not_tracked` do **not**
mean verified. RPC is loopback-only and unauthenticated, so treat the machine as trusted, keep the
clock synchronized, and run compatible versions.

Vess is experimental and unaudited. Do not use it for valuable funds.
