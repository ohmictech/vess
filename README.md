# Vess

**Vess is a post-quantum, feeless, energy-backed, decentralized crypto payment protocol.**

What this network achieves:

- Quantum resistant from the ground up
- ~1 second block time
- Good surveillance resistance
- Bandwidth limited throughput
- Zero transaction fees
- Low state bloat and hardware requirements
- Payment transport agnosticism (OOB)
- Node discovery agnosticism (OOB)
- Memory hard, highly ASIC resistant mining
- No pre-mine or VC
- No artificial scarcity
- Mnimalist codebase

---

The reason for its existence overlaps precisely zero with almost the entirety of DeFi. If you're interested in making a quick buck, move along.

Vess is backed 1:1 by energy. It is intended as a thermodynamic currency, rather than a speculative asset to hold and sell for more later on. There are no arbitrary tokenomics or programmatic deflation schedules. Mine it, spend it, move it around. Create velocity rather than stagnation, using it as an actual payment method.

---

It allows feelessness because unlike traditional consensus, it does not passively and politely reorder malicious data. Millions of lines of code have been written in the past two decades to solidify distributed ledgers that agree on which version of a spend is the correct one. Blocks, PoW, PoS, DAGs. Their entire architectural purpose outside of agreement on a set of data is to respectfully resolve conflicts.

Unfortunately, historical cryptocurrency offloads the cost of malice onto honest node operators. You pay for adversarial resistance with fees, state bloat, thoughput blockages, all in the name of protection. Vess understands a double spend for what it actually is: a willful, malicious attempt to extract value and sabotage a network.

So, a conflict in Vess is resolved with appropriate force: a total vaporization of all associated UTXOs. If a node sees a conflicting set of payments, it simply deletes all associated inputs. The penalty for dishonesty in Vess rests completely on the attackers.

---

## Everything is out-of-band

Vess payments never travel from payer to payee through the node network. A `vess://` invoice and the signed `VessPayment` blob are exchanged through whatever channel the two parties choose: a messaging app, a QR code, an email, a USB drive, a printed piece of paper, a forum post, an NFC tap, a Bluetooth transfer. The network only sees the blob when the receiver decides to submit it: payments are fundamentally receiver-claimed. Unless a payment blob is claimed and submitted to the network to transfer ownership, nothing changes.

This is a structural defense.

**Massively increased attack surface for surveillance.** To trace who paid whom, an adversary can no longer just monitor the P2P network. They must also compromise every possible channel in use. Signal, WhatsApp, Gmail, iMessage, physical mail, in-person meetings, whatever. The payment graph scatters across carriers the network has no visibility into. A blockchain analyst who reconstructs the full on-chain history still doesn't know whether the blob traveled through a ProtonMail attachment or a sticker on a coffee shop counter. Every channel added to the ecosystem multiplies the adversary's required coverage.

**Network-level attacks become irrelevant.** You can't eclipse-attack a payment that doesn't touch the mesh. You can't DDoS a transaction out of the mempool when the mempool isn't involved until the receiver is ready. Payer and receiver can complete the entire exchange while both are fully offline from the Vess network. The payment blob is inert bytes until submitted — it has no expiration, no nonce dependency on network state, no sequence number that expires.

**Third-party flexibility with no protocol lock-in.** Any app can generate a `vess://` invoice. Any wallet implementation can sign a `VessPayment`. Any node can accept the submission. The format is just bytes, and there is no handshake between wallet and node, no API key, no registration. Every medium can operate at the level of "produce this blob, accept that blob." Nobody needs permission to participate.

---

## Why should you care?

| | Bitcoin | Ethereum | Nano | **Vess** |
|---|---|---|---|---|
| Post-quantum | No | No | No | **Yes** |
| Fees | Yes | Yes | No | **No** |
| Speed | 7 tps | 20
| Security | PoW | PoS | Validators | **PoW** |
| ASIC resistant | No | No | N/A | **Yes** |
| Privacy | Medium | Low | Low | **Good** |
| Value anchor | Speculation | Speculation | Speculation | **Energy (PoW)** |
| Codebase size | 500K+ LoC | 2M+ LoC | 200K+ LoC | **~3K LoC** |

## How it works (60 seconds)

1. **Mining:** Find a 42-cycle in a Cuckatoo32 graph (~1.3GB RAM, single-threaded). Submit the block. Nodes verify the proof in microseconds and reward the miner with freshly minted coins. Difficulty auto-adjusts toward a ~1-second block time.
2. **Consensus:** Every node maintains a UTXO set in LMDB — just opaque `VessId` hashes with no amounts or owner data. When a payment arrives, nodes verify signatures, check that inputs are unspent, and apply the state change. If two payments spend the same coin (a double-spend), Vess doesn't reorder — it **vaporizes** all inputs from both payments. The penalty for malice falls entirely on the attacker.
3. **Spending (always OOB):** There are no on-chain addresses. Every payment begins with a `vess://` invoice shared however you want (QR code, messaging app, email, NFC, wallet). The payer's wallet builds and signs a `VessPayment` blob, then hands it back to the receiver out-of-band. The receiver submits it to any node. Each output uses a one-time ML-DSA-65 keypair, so there's nothing to reuse, link, or track.
4. **Dev subsidy:** 1% of each block reward (minimum 1 Vess) goes to a hardcoded dev key. No premine, no ICO, no special minting privilege.

### No seed phrases — you own the files

Vess has no 12-word recovery phrase. There is no BIP39, no HD derivation, no master seed. Each UTXO contains its own independent ML-DSA-65 keypair, stored directly in your encrypted wallet file (`wallet.vess`). Owning Vess literally means possessing the files that contain those private keys.

This means:

- **No phrase to leak.** There's no 12- or 24-word string that, if screenshot or spoken, drains everything. Your coins are individual keys in an encrypted blob.
- **No BIP39 footgun.** Nobody loses funds because they stored a seed phrase in a password manager, cloud note, or under their keyboard. If you don't have the wallet file, you don't have the coins — period.
- **Natural partitioning.** Cold storage is as simple as copying `wallet.vess` to a USB drive and deleting it from the online machine. Spend a few coins by moving just those keypairs into a hot wallet file. No derivation paths, no gap limits, no change-chain scanning.
- **Backup is copy.** Wallet file on two drives? That's your backup. Lose all copies? Those coins are gone — there's no registrar to appeal to. This is a feature, not a bug.
- **Nothing to subpoena.** If a custodian or exchange claims to hold Vess, they must produce the actual signed blobs. There is no "wallet import format" that lets them sweep from a 12-word phrase extracted from a database. Either they have the keys, or they don't.

In short: your wallet file *is* your money. Treat it accordingly.

## Running a node

```bash
# Build everything
cargo build --release

# Start a node (listens on 0.0.0.0:9876 by default)
cargo run --release -p vess-node

# Start with mining enabled
cargo run --release -p vess-node -- --mine

# Listen on a specific port
cargo run --release -p vess-node -- --listen 0.0.0.0:9877

# Bootstrap from an existing peer
cargo run --release -p vess-node -- --bootstrap 127.0.0.1:9876

# All flags combined
cargo run --release -p vess-node -- --listen 0.0.0.0:9877 --mine --bootstrap 127.0.0.1:9876
```

| Flag | Description |
|---|---|
| `--listen <addr>` | Bind address (default: `0.0.0.0:9876`) |
| `--mine` | Enable mining |
| `--bootstrap <addr>` | Connect to an existing peer on startup (repeatable) |

## Running the wallet

```bash
# Build
cargo build --release

# Import coinbase outputs from a node's LMDB (run while node is live)
cargo run --release -p vess-wallet -- --import vess-db

# Check balance
cargo run --release -p vess-wallet -- --balance

# Consolidate all UTXOs into fewer outputs (reduces future tx sizes)
cargo run --release -p vess-wallet -- --consolidate

# Generate an invoice (receiver)
cargo run --release -p vess-wallet -- --invoice 100

# Pay an invoice — export signed blob for OOB delivery (payer)
cargo run --release -p vess-wallet -- --pay "vess://abc123...?amount=100" --out payment.vess

# Claim a payment blob received OOB (receiver)
cargo run --release -p vess-wallet -- --submit payment.vess

# Connect to a specific node (default: 127.0.0.1:9876)
cargo run --release -p vess-wallet -- --connect 127.0.0.1:9877 --balance

# Use a custom wallet file and password
cargo run --release -p vess-wallet -- --wallet my-wallet.vess --password hunter2 --balance
```

| Flag | Description |
|---|---|
| `--import <db-path>` | Import unspent coinbase outputs from a node's LMDB |
| `--balance` | Print balance and exit |
| `--consolidate` | Merge up to 5 UTXOs at a time into single outputs |
| `--invoice <amount>` | Print a `vess://` invoice URL for the given amount |
| `--pay <url>` | Build and sign a payment for a `vess://` invoice (requires `--out`) |
| `--out <file>` | File path for exported payment blob |
| `--submit <file>` | Submit a `VessPayment` blob received OOB to the network |
| `--connect <addr>` | Node address for RPC (default: `127.0.0.1:9876`) |
| `--wallet <path>` | Wallet file path (default: `wallet.vess`) |
| `--password <pw>` | Wallet encryption password (default: empty) |

### Interactive mode

Run without flags for a REPL:

```bash
cargo run --release -p vess-wallet
> connect 127.0.0.1:9876
> balance
> invoice 50
> pay vess://...
> submit payment.vess
> consolidate
> help
```

## License

Apache 2.0
