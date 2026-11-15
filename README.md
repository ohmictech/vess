# Vess

Vess is a decentralized, proof-of-work, post-quantum blockchain ledger. It exists to fill the gap that crypto should have existed to fill but never did: a truly neutral, trustless, digital unit of account. It functions as a simple, reliable, and fast settlement network (1 block per second) with a monetary basis rooted in thermodynamics rather than policy or policymakers.

This network has no pre-mine, ICO, allocations, hidden fees, or staking. It is not intended to increase in price indefinitely, or be held and sold later for profit. There is no benefit for being early and no penalty for being late. The only thing that matters is how many hashes you produce.

# What is different

Vess ties the block reward to difficulty instead of using a halving schedule. A block at twice the
genesis difficulty pays twice the reward. This aims to keep issuance per unit of mining work roughly
constant. This is not the same as debasement, as every hash represents a tangible input cost.

Bitcoin, and every other cryptocurrency with engineered scarcity, requires a continuous increase in asset price for security to remain stable long-term, and to stay useful. This monetary policy has a problematic consequence: it cannot be used as a reliable unit of account. So the crypto narrative has shifted, and every project has settled into either the "store of value" camp, or the "fiat facilitation" camp.

Vess reduces the impact of speculation on price, relying on the sunk costs of electricity and hardware to be the basis of commodity-style value, allowing Vess to be used as a truly decentralized, trustless, fair, digital unit of account where Bitcoin cannot be.

It seeks to become the borderless, sovereign "stablecoin" of the digital age.

## Running a node

Build with Rust:

```sh
cargo build --release
```

Set the executable path for the examples below:

```sh
# Linux or macOS
BIN=./target/release/vess
```

```powershell
# Windows PowerShell
$BIN = ".\target\release\vess.exe"
```

The remaining commands use shell syntax. In PowerShell, use `& $BIN` wherever they show `$BIN`.

### First run

Start the node with:

```sh
$BIN
```

On first run, Vess creates `vess.toml` **beside the executable**: for this build, that is
`target/release/vess.toml`. It also creates the `chain` data directory beside the config. The
generated settings are:

```toml
network = "devnet"
datadir = "./chain"
rpc_port = 9733
p2p_port = 9732
peers = []
seeds = []
mine = false
trust_snapshot = true

# Optional settings
# payout = "YOUR_64_CHARACTER_ACCOUNT_ADDRESS"
# prune_blocks = 16384
# prune_headers = 100000000
```

The default node runs on devnet and does not mine. With no remembered peers or `VESS_SEEDS`
environment variable, it does not connect to peers. Stop it with Ctrl+C, edit `vess.toml`, and start
it again to apply changes. Existing configs are never overwritten.

To join a testnet, set `network = "testnet"`, choose a separate `datadir` such as
`"./testnet-chain"`, and add a real testnet address to `seeds`, for example
`seeds = ["PEER_ADDRESS:9732"]`. Replace that example with an actual reachable peer: Vess does not
currently have a built-in bootstrap node. Use separate data directories for different networks.

To generate the config **before** starting a node or creating a chain, run `$BIN node params`
instead. Edit the resulting file, then run `$BIN`.

To mine continuously, first create a wallet as described below, then set `mine = true` and
`payout = "YOUR_ACCOUNT_ADDRESS"` in the config. Leave `mine = false` to run without mining.
Never put a wallet password or recovery phrase in the config.

The optional pruning settings retain the database's saved policy when commented out. A new database
defaults to retaining 16,384 block bodies; set both `prune_blocks = 0` and `prune_headers = 0`
before pruning to keep all history. Mining resumes immediately after a block; the obsolete
`mine_interval` setting is ignored with a warning.

Command-line options override config settings for that invocation only and are not saved.
`--config FILE` selects another config; `--no-mine` and `--no-trust-snapshot` temporarily disable
those settings. A relative `datadir` in the config is relative to the config file, while relative
`--config` and `--datadir` paths are relative to the working directory.

Earlier builds placed the config and relative data directory in the working directory. To keep using
them, pass `--config` with the old config path, and if needed `--datadir` with the old data path, or
set an absolute `datadir` in the config. You can instead move them together beside the executable.
Back up wallets and data before moving them.

Trusted snapshots require a majority of connected peer identities; a single connected peer can
authorize one. These identities are not proof of independent ownership: an eclipse or Sybil attack
can still supply a false state. Snapshot history is verified in the background when historical blocks
are available; until then, the state remains trusted rather than fully verified.

### Wallet

Wallet commands use the network and data directory in `vess.toml`. Set a strong
`VESS_WALLET_PASSWORD` environment variable, then create or restore a wallet:

```sh
$BIN wallet new --name alice --password-env VESS_WALLET_PASSWORD
$BIN wallet restore --name alice-recovered --password-env VESS_WALLET_PASSWORD
```

New wallets show a 24-word recovery phrase **once**. Keep it private and backed up; anyone with it
can access the wallet. Also back up the encrypted keyfile and password separately. Restore using the
same network and account index. Older and legacy wallets do not have recovery phrases, so keep their
keyfiles and passwords.

```sh
# With the node running:
$BIN wallet balance --name alice --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
$BIN wallet send --name alice --to ACCOUNT --amount 5 --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
$BIN wallet set-state --name alice --state-hash HASH --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
```

Replace `ACCOUNT` with the recipient's address and `HASH` with a 32-byte value in hex. `set-state`
updates the account's state commitment; it does not store the underlying message or file.

Sign and verify a message locally, without a running node:

```sh
$BIN wallet sign --name alice --message "Hello" --password-env VESS_WALLET_PASSWORD > proof.txt
$BIN wallet sign verify --message "Hello" --proof proof.txt --account EXPECTED_ACCOUNT
```

Verification requires the exact message and prints `valid=1` when successful. Obtain
`EXPECTED_ACCOUNT` independently; otherwise a valid signature does not establish who signed it.
For authentication, include the application, purpose, and a fresh challenge in the message.
Do not put secret messages in command arguments.

### Node status

```sh
$BIN node status --rpc 127.0.0.1:9733
$BIN node history --rpc 127.0.0.1:9733
$BIN --help
```

`node history` shows snapshot verification progress: `pending` and `not_tracked` do not mean
verified, and invalid history stops normal node operation. Previously pruned blocks cannot be
restored by increasing retention. RPC listens only on loopback and has no authentication; keep
your system clock synchronized and use compatible node versions.

Vess is experimental and unaudited. Do not use it for valuable funds.