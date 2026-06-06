[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange)](https://rust-lang.org)

# Vess

**Bitcoin-backed post-quantum digital cash.**

Vess upgrades Bitcoin sats into private, feeless bearer bills. 1 sat = 1 Vess. The conversion is one-way: a burn transaction commits to the first owner, and from that point the value moves inside Vess as encrypted bills on a distributed hash table, with no public transfer history.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Why Vess](#why-vess)
- [Ownership & Payments](#ownership--payments)
- [Privacy](#privacy)
- [Smart Contracts](#smart-contracts)
- [Cryptography](#cryptography)
- [Status](#status)
- [Security Assumptions](#security-assumptions)
- [Specification](#specification)
- [License](#license)

---

## How It Works

1. **Deposit BTC** — Your node tracks incoming Bitcoin via its embedded light client.
2. **Burn** — It builds a burn transaction committing to the Vess bill decomposition.
3. **Genesis** — After confirmation, `OwnershipGenesis` records are gossiped to the DHT.
4. **Spend** — Bills become private bearer instruments sent via stealth addresses.
5. **Claim** — The recipient broadcasts an `OwnershipClaim` to finalize receipt.

Users are identified by human-readable **+vesstags** (e.g. `+alice`), which resolve
to post-quantum stealth addresses on the DHT. Tags require a small PoW to claim,
preventing Sybil squatting.

All of this is managed through the interactive shell — create a wallet, tag yourself,
start the node, and send value, all from the same session:

---

## Quick Start

### Build from source

```bash
git clone https://github.com/ohmictech/vess.git
cd vess
cargo build --release --package vess-cli
```

The binary lands at `target/release/vess.exe` (Windows) or `target/release/vess` (Linux/macOS).

### Interactive mode (recommended)

The interactive shell is the primary way to run a node and manage your wallet.
Just run `vess` with no arguments:

```bash
vess
```

This starts the node **and** drops you into the interactive prompt. Everything
happens inside this session — no need to juggle terminal windows or keep track
of RPC ports:

---

## Architecture

Nodes form a peer-to-peer mesh with post-quantum handshakes (ML-KEM-768 + Falcon).
Handshakes are retried with exponential backoff on failure and only permanently
banished after 3 consecutive failures.

Ownership state is replicated deterministically across the DHT rather than through
global consensus. On peer verification, the node automatically pages through the
peer's DHT shard for seed catch-up, with quorum-based installation requiring
≥2 peers to agree on each record.

Payments try direct delivery first when the recipient is a known verified peer,
falling back to gossip relay through the mesh. The interactive shell surfaces
real-time events and notifications as the node operates.

---

## Why Vess

Bitcoin is excellent at scarce issuance and terrible at private spending. Every
payment lands on a public graph. Every UTXO cluster becomes a surveillance
surface. Every reuse mistake is permanent.

Vess is the sovereign spending layer for sats — a one-way upgrade from
transparent UTXOs into private bearer cash:

| Bitcoin | Vess |
|---|---|
| Public transaction graph | No transfer history |
| Fee market | Feeless |
| ~10 min confirmation | Instant |
| ECDSA / Schnorr | ML-DSA-65 (post-quantum) |
| Full node ~700 GB | Full node runs on a phone |
| Account/UTXO model | Bearer bills |

Vess is **not** a sidechain, rollup, federated mint, or multisig bridge.
It is a one-way conversion into private post-quantum cash.

---

## Ownership & Payments

### Ownership

Each bill has a permanent `mint_id`, a `chain_tip`, a `chain_depth`, and an
owner verification key hash. Genesis binds the first owner. Transfers advance
the chain with post-quantum signatures. Double spending is prevented by
deterministic registry rules rather than probabilistic consensus.

### Payments

Payments are encrypted proposals sent to a recipient stealth address. The sender
retains control until the recipient broadcasts an `OwnershipClaim`. This gives
Vess deterministic conflict resolution, offline-tolerant delivery, and no
mempool or fee auction.

---

## Privacy

Vess transfers are never published to a public ledger.

- **Stealth addressing** — Every payment uses one-time addresses.
- **Hashed tags** — `+tags` are Blake3-hashed before entering the DHT.
- **Ownership registries** — Store current state, not transfer history.
- **Bearer bills** — No accounts, no address reuse.
- **Dual-layer stealth** — Both the mesh handshake and the value transfer use ephemeral keys.
- **Denomination discipline** — Bills are minted in standard denominations (1, 2, 5, 20, 500...), with no change — only splitting and combining.

---

## Smart Contracts

Vess supports deterministic covenants via [**VessLogic**](docs/vess-logic.md),
a line-by-line predicate language. Programs are deployed to the DHT under
human-readable names (e.g. `+vl_market1`) and bills can be locked to them.
Unlocking requires an `OwnershipClaim` with a valid witness and compute receipt.

See the full language reference in **[docs/vess-logic.md](docs/vess-logic.md)**.

```bash
vess deploy ./covenant.vess --name +vl_market1
```

---

## Cryptography

All Vess-native operations are post-quantum.

| Purpose | Primitive |
|---|---|
| Mesh handshake | ML-KEM-768 + Falcon |
| Ownership signatures | ML-DSA-65 |
| Stealth addressing | ML-KEM-768 (DKSAP) |
| Hashing | Blake3 |
| Wallet KDF | Argon2id |
| Symmetric encryption | ChaCha20-Poly1305 |
| Bitcoin integration | Native P2P + SegWit |

---

## Status

| Feature | Status |
|---|---|
| PQ mesh networking (UDP) | ✅ Stable |
| Peer handshake + PoW | ✅ Stable |
| Kademlia DHT (256 buckets) | ✅ Stable |
| Wallet create / unlock / backup | ✅ Stable |
| Send / receive / reforge | ✅ Stable |
| +Tag registration / lookup | ✅ Stable |
| CLI + interactive mode | ✅ Stable |
| Test faucet (dev profile) | ✅ Stable |
| Bitcoin light client | 🧪 Experimental |
| BTC burn → Vess genesis | 🧪 Experimental |
| VessLogic covenant engine | 🧪 Experimental |
| Vess STARKs | 🔬 Planned |

---

## Security Assumptions

Vess nodes trust:

- **Bitcoin** for final settlement of burns (same security model as Bitcoin).
- **Post-quantum cryptography** (ML-KEM-768, ML-DSA-65, Falcon) for all Vess-native operations.
- **The DHT quorum** — ownership state requires agreement from a majority of replicating peers before acceptance.
- **Argon2id PoW** — handshake proof-of-work raises the cost of Sybil identities.

Vess nodes do **not** trust any single peer, coordinator, sequencer, or validator.

---

## Specification

The frozen V1 protocol specification is in **[docs/v1-spec.md](docs/v1-spec.md)**.

---

> Keep your lives free from the love of money and be content with what you have,
> because God has said, 'Never will I leave you; never will I forsake you.'
> — Hebrews 13:5

## License

Apache 2.0 — see [LICENSE](LICENSE).