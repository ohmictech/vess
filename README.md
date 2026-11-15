# Vess

Vess is a proof-of-work blockchain. Accounts are post-quantum public
keys, and a transaction moves a balance from one account to another.

## What it is

| | |
|---|---|
| Consensus | Proof of work; the chain with the most accumulated work wins |
| Block time | 1 second |
| Mining | BLAKE3-256 |
| Signatures | ML-DSA-65 (post-quantum) |
| Accounts | Public key hash with balance, nonce, and a 32-byte state commitment |
| State | 256-level sparse Merkle tree, root committed in every header |
| Block reward | `100 × genesis_target / target`, rounded down with a minimum of 1; 1% development fee, rounded down, comes out of the reward |
| Supply | Work-linked issuance; no halving or scheduled cap |
| Pre-mine | None |

## What it does differently

Vess ties the block reward to difficulty instead of using a halving schedule. A block at twice the
genesis difficulty pays twice the reward. This aims to keep issuance per unit of mining work roughly
constant, subject to integer rounding and the minimum reward. 

Bitcoin, with its halvings, requires a constant increase in price for security to remain stable long-term. This monetary policy has a second consequence: it cannot be used as a medium of exchange.

Vess reduces the impact of speculation on price, relying on the sunk costs of electricity and mining equipment to be the basis of commodity-style value, allowing Vess to be used as a truly decentralized, trustless, fair, digital unit of account where Bitcoin cannot be.

It seeks to replace the need for stablecoins in the crypto economy.

That rule shapes the rest. The puzzle does not need to resist ASICs, so mining is plain BLAKE3. State
holds only accounts, so headers stay small and proofs and snapshots stay simple. Accounts are
post-quantum, so a transfer is about 5.4 KB and the network is built for that.

## Running a node

Build:

```sh
cargo build --release
BIN=./target/release/vess
```

The first operational command creates `vess.toml` beside the executable with preset defaults:
`devnet`, a `chain` folder beside the config, no mining, no configured peers, and snapshot trust
enabled. Edit the file to change persistent settings.
It includes an inactive placeholder for a future default seed; replace it with a real seed for the
chosen network in the `seeds` list when one is available. Existing config files are not modified.
Command-line options are optional and override the file for that invocation only; they are never
saved to it. `--config FILE` selects a different config file. A relative `datadir` in the config is
relative to that file; a relative `--config` or `--datadir` argument is relative to the working
directory.

Earlier builds placed the config and relative data directory in the working directory. Vess refuses
to silently ignore such a config and warns if a working-directory data folder already exists. To
keep using them, pass `--config` with the old config path, and if needed `--datadir` with the old
data path, or set an absolute `datadir` in the config. You can instead move them together beside the
executable. Back up wallets and data before moving them.

Run the configured node with just:

```sh
$BIN
```

With a fresh data directory, it does not mine or connect to a peer by default. To configure either,
stop the node, edit `vess.toml`, and restart it. For example:

```toml
network = "testnet"
datadir = "./chain"
rpc_port = 9733
p2p_port = 9732
peers = []
seeds = ["127.0.0.1:9732"]
mine = true
payout = "YOUR_64_CHARACTER_ACCOUNT_ADDRESS"
trust_snapshot = true
```

Replace the example seed and payout with real values, and use a data directory for the chosen
network. Do **not** put a recovery phrase or wallet password in this file. Set `mine = false` if you
only want to run a node. `--no-mine` and `--no-trust-snapshot` temporarily disable those config
settings. The generated config lists optional `payout`, `prune_blocks`, and `prune_headers`
settings as commented examples. Uncomment an example to apply it; leaving pruning unset preserves
the database's saved policy. Mining resumes immediately after a block; the obsolete `mine_interval`
setting is ignored with a warning.

Trusted snapshots require a majority of connected peer identities; a single connected peer can
authorize one. These identities are not proof of independent ownership: an eclipse or Sybil attack
can still supply a false state. Snapshot history is verified in the background when historical blocks
are available; until then, the state remains trusted rather than fully verified.

The examples use the default `devnet`. Choose a strong, unique password, store it securely, and
provide it through an environment variable or password file. Set `VESS_WALLET_PASSWORD` in your
environment before running these commands.

New HD wallets display a 24-word recovery phrase **once**. Write it down privately and keep it safe:
anyone with the phrase can access the wallet. It cannot be displayed again from the keyfile. Back up
the encrypted keyfile at `<datadir>/wallets/<name>.key` and its password separately as well. If you
lose the password, the phrase can restore the wallet with a new one. The keyfile password is not part
of the recovery phrase.

With the node stopped, create a chain, make a wallet, and mine two blocks:

```sh
$BIN node init
$BIN wallet new --name alice --password-env VESS_WALLET_PASSWORD
# hd=1  account=<hex>  index=0

$BIN miner --payout <account> --blocks 2
$BIN wallet balance --name alice --password-env VESS_WALLET_PASSWORD
# balance=198  next_nonce=0
```

To recover a new HD wallet, set a password for the new keyfile and run:

```sh
$BIN wallet restore --name alice-recovered --password-env VESS_WALLET_PASSWORD
```

Enter the 24 words when prompted; input is hidden. Use the same `--network` as the original wallet
and the same account indices. Creation requires a terminal so the phrase is not accidentally captured
in redirected output. Automation can explicitly opt in to `--unsafe-phrase-stdout` for creation or
pipe a phrase to recovery with `--mnemonic-stdin`; protect those streams from logs and other readers.
Do not put a phrase in command arguments or shell history.

Older wallets and `wallet new --legacy` do not gain recovery phrases. Keep their keyfiles and any
passwords backed up; they cannot be recovered with a newly generated phrase.

Sign a message locally without running a node or submitting a transaction:

```sh
$BIN wallet sign --name alice --message "Hello from Alice" --password-env VESS_WALLET_PASSWORD
```

The output contains the account, public key and signature in hex, plus the algorithm and signing
context. Use `--index N` for another HD account. The exact UTF-8 bytes of the message are signed;
share the message separately with anyone verifying the signature. Command arguments may appear in
shell history or process listings, so do not pass secret messages this way.

Verification requires ML-DSA-65 with context `VESS-SIGNED-MESSAGE-V1` and the exact message bytes.
Save the signing output to a file, then verify it locally:

```sh
$BIN wallet sign --name alice --message "Hello from Alice" --password-env VESS_WALLET_PASSWORD > alice-proof.txt
$BIN wallet sign verify --message "Hello from Alice" --proof alice-proof.txt --account <expected-account>
```

`--proof -` reads the signing output from standard input. Alternatively, supply `--public-key HEX`
and `--signature HEX` instead of `--proof`. A valid signature prints `valid=1` and the derived account;
an invalid signature or account mismatch prints `valid=0` and exits with an error. Malformed input
also exits with an error. Obtain the expected account independently: without `--account`, a valid
signature proves only that the supplied key signed the message, not who owns it.

These signatures are separate from transaction signatures but are not bound to a specific network or
application; include an application, purpose, and fresh challenge in the message when using one for
authentication. With the Rust libraries, use `vess_crypto::verify` with
`vess_wallet::MESSAGE_SIGNING_CONTEXT.as_bytes()`.

Run a node, either mining or joining a network:

```sh
$BIN node run --rpc 9733 --port 9732 --mine --payout <account>
$BIN node run --datadir ./chain2 --rpc 9743 --port 9742 --seed 127.0.0.1:9732
```

There are no built-in bootstrap peers. Supply a known peer with `--seed`, `--peer`, or `VESS_SEEDS`
when joining a network. Peers discovered after connecting are remembered in `<datadir>/peers.txt`.
Set the network in the config, or pass `--network testnet` or `--network mainnet` consistently to
commands that open the data directory. When the node is running, use `--rpc 127.0.0.1:9733` (or
its configured port) for commands that query it rather than opening the database directly.

The current protocol uses millisecond block timestamps and a testnet genesis target of `2^235`.
All networks are incompatible with earlier builds: use a new data directory and connect only to
peers using the same protocol and genesis.

Mining timestamps use the local clock in milliseconds and must exceed median chain time. Nodes
temporarily reject blocks more than two minutes ahead of their local clock, so keep system clocks
synchronized. The fixed genesis is shared by all nodes; the first mined block records its own time,
and a stalled chain can resume at the current time. A long pause still affects the retarget window
until that pause moves out of it. Built-in miners refresh their templates approximately every second
while searching, rather than continuing to mine indefinitely with an old timestamp.
Both built-in and RPC miners also abandon work on an outdated tip; RPC miners check for tip changes
approximately every 50 ms, and a final node-side check prevents stale submissions.

Send a payment and follow it:

```sh
$BIN wallet send  --datadir ./chain --name alice --to <a
ccount> --amount 5 --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
$BIN wallet watch --datadir ./chain --name alice --rpc 127.0.0.1:9733 --password-env VESS_WALLET_PASSWORD
```

Inspect a running node:

```sh
$BIN node status  --rpc 127.0.0.1:9733                 # height, tip, supply, next reward, peers, bans
$BIN node history --rpc 127.0.0.1:9733                 # snapshot verification progress
$BIN node block   --rpc 127.0.0.1:9733 --height 12
$BIN node tx      --rpc 127.0.0.1:9733 --id <txid>
$BIN node account --rpc 127.0.0.1:9733 --account <id>  # balance, nonce, state commitment
$BIN node proof   --rpc 127.0.0.1:9733 --account <id>  # inclusion or non-inclusion proof
$BIN node params  --network mainnet                    # every consensus constant
```

`node run` also accepts `--prune-blocks N` and `--prune-headers N` to keep only recent history.
The default keeps 16,384 block bodies and undo records below the tip, about 4 hours and 33 minutes
at one block per second. Saved pruning policies take precedence; raising retention cannot restore
blocks already pruned.
Snapshot trust is enabled by default to join pruned peers; set `trust_snapshot = false` or pass
`--no-trust-snapshot` to disable it. An existing config that explicitly sets it to `false` remains
disabled. Before installing a newly received snapshot, the node asks its
connected peers for their block ID at the snapshot height and requires a strict majority to agree.
One connected peer can authorize a snapshot; duplicate connections with the same peer key count once,
and peers that cannot answer do not count as agreement. If the set of connected sessions changes
during a vote, the node retries. Peer keys are not proof of independent ownership, so an attacker
controlling enough connections can still mislead the node. A vote does not prove that the peer executed
the block; this is not a trusted checkpoint or a signed attestation.

This check applies to newly installed snapshots, not snapshots already in a database. The node
independently replays snapshot history in the background using available connected peers, and checks
the result against the snapshot's block. `node history` reports `pending`, `verified`, `invalid`, or
`not_tracked` (not proof that an older database was independently verified). Replay resumes after a
restart and remains pending if peers cannot supply the necessary history. It uses additional disk,
bandwidth and CPU; the separate replay database retains the history it downloads, and header pruning
is paused while replay is pending. If replay proves the snapshot history invalid, the node stops
serving normal operations and refuses to reopen that database.

An archival node can make history available to others by starting with `--prune-blocks 0` and
`--prune-headers 0` before pruning has removed it. Changing these flags cannot restore blocks already
deleted. RPC is unauthenticated and listens only on loopback.