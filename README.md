[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange)](https://rust-lang.org)

# Vess

**Bitcoin time-credit protocol — post-quantum, feeless, fair-launch.**

Vess turns locked Bitcoin into spendable time-credits. Lock BTC via
`OP_CHECKLOCKTIMEVERIFY` and receive Vess — 1 sat locked for 1 year = 1 Vess.
The BTC returns after the lock expires. No burn, no bridge, no custodian.

## How It Works

1. **Lock BTC** — Your wallet builds a CLTV time-lock transaction. BTC sits at your own address, locked for 0.1–10 years.
2. **Mint Vess** — When the lock confirms, ownership records are gossiped to the DHT. `Vess = locked_sats × lock_blocks / 52,560`.
3. **Spend** — Vess bills are bearer instruments sent via tags (e.g. `+ALICE`), QR, NFC, BLE, or any transport.
4. **Claim** — The recipient broadcasts an `OwnershipClaim` to the DHT to finalize receipt.

## Vess & Vichor

Vess and Vichor are two independent assets with distinct purposes.

| | Vess | Vichor |
|---|---|---|
| **What** | Time-credit (sat-block) | Network stock |
| **Supply** | Unlimited (backed by BTC locks) | Fixed 1,000,000,000 |
| **Launch** | Fair — same formula for everyone | Dev holds initial supply |
| **Purpose** | Spending, payments | Gating long locks, funding dev |

### Vichor Gate

Locks ≤1 year are free. Beyond that, Vichor must be burned:

```
Duration    Vichor Required
────────    ───────────────
≤1.0 year   0 (free)
 1.1 years  1
 2.0 years  10
 3.0 years  40
 5.0 years  160
 7.0 years  360
10.0 years  810
```

Vichor is burned by transferring it to a provably unspendable address
(`VICHOR_BURN_VK_HASH`). The burn proof is committed in the Bitcoin
time-lock transaction's `OP_RETURN`, binding it to a specific mint.

Speculators who want high-leverage long-term locks must buy Vichor from
the market, funding protocol development while making the remaining
Vichor supply scarcer.

### Self-Contained Liquidity

Vichor never needs a CEX or DEX. The Swap DHT (`vess-swap-v0|btc|vichor`)
is the only exchange it needs — same keys, same wallet, same network.

## Tags

Human-readable identities (e.g. `+ALICE`). Uppercase display eliminates
`I`/`l`/`1` confusion. Immutable — once registered, the tag→address mapping
is permanent.

- Lowercase alphanumeric only, 3–20 chars
- Argon2id PoW (2 GiB) to claim
- No expiry, no pruning, no lockout

## Quick Start

```bash
git clone https://github.com/ohmictech/vess.git
cd vess
cargo build --release --package vess-cli
```

## Architecture

Nodes form a peer-to-peer mesh with post-quantum handshakes (ML-KEM-768 + Falcon).
Ownership state is replicated deterministically across the DHT. Payments try
direct delivery first, falling back to gossip relay.

- **No consensus** — deterministic registry rules
- **No fees** — no gas, no mempool, no fee auction
- **No burn** — BTC returns after CLTV expiry
- **No bridge** — native Bitcoin script
- **No CEX** — swap DHT is the exchange

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
| Bitcoin integration | Native P2P + SegWit + CLTV |

## Why Vess

| Bitcoin | Vess |
|---|---|
| Public transaction graph | No transfer history |
| Fee market | Feeless |
| ~10 min confirmation | Instant |
| ECDSA / Schnorr | ML-DSA-65 (post-quantum) |
| BTC is spent | BTC is locked, then returned |
| Single asset | Vess (time-credit) + Vichor (stock) |

Vess is **not** a sidechain, rollup, federated mint, or multisig bridge.
It is Bitcoin-native time-credit with self-contained liquidity.

## License

Apache 2.0 — see [LICENSE](LICENSE).