[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange)](https://rust-lang.org)

# Vess

**Bitcoin time-value credit protocol. Post-quantum. Feeless. Stateless.**

Vess turns locked Bitcoin into spendable time-credits. Lock BTC via
`OP_CHECKLOCKTIMEVERIFY` and receive Vess. 1 satoshi locked for 1 year = 1 Vess.
The BTC returns after the lock expires. No burn, no bridge, no custodian. The economic value behind a unit of Vess represents the opportunity-time cost of locking your Bitcoin.

The protocol's intention and novelty is to fundamentally change what "access to credit" means. Rather than having to be in debt to someone else to acquire liquidity against your assets, Vess allows you to directly issue tokenized claims on future work against your own Bitcoin, trustlessly.

Once BTC is locked, the corresponding minted Vess is moved around as cryptographically self-contained bearer bonds that can be split and combined. As such, there is no global consensus mechanism, "blocks", or state, just a deterministic ownership registry hash table.

Vess is built on maximum decentralization, piggybacking the BTC network with a builtin light client + self-audited transaction and block commitments. No node RPC required.

Every Vess wallet is its own node.

## How It Works

1. **Lock BTC** — Your wallet builds a CLTV time-lock transaction. BTC sits at your own address, locked for 0.1–10 years.
2. **Mint Vess** — When the lock confirms, ownership records are gossiped to the DHT.
3. **Spend** — Vess bills are bearer instruments sent via tags (e.g. `+ALICE`)
4. **Claim** — The recipient wallet automatically broadcasts an `OwnershipClaim` to the DHT to finalize receipt.

## Vess & Vichor

Vess and Vichor are two independent assets with distinct purposes.

| | Vess | Vichor |
|---|---|---|
| **What** | Time-credit (sat-block) | Network stock |
| **Supply** | Unlimited (backed by BTC locks) | Fixed 1,000,000,000 |
| **Launch** | Fair — same formula for everyone | Dev holds initial supply |
| **Purpose** | Spending, payments | Gating long locks, funding dev |

### Vichor Gate

Locks ≤1 year are freely accessible. Beyond that, Vichor must be burned proportionally, ensuring speculators are contributing to the network longevity and strength:

Vichor is burned by transferring it to a provably unspendable address
(`VICHOR_BURN_VK_HASH`). The burn proof is committed in the Bitcoin
time-lock transaction's `OP_RETURN`, binding it to a specific mint.

Speculators who want high leverage, long-term locks must buy Vichor from
the market, funding protocol development while making the remaining
Vichor supply scarcer.

### Self-Contained Liquidity

Vichor never needs a CEX or DEX. The Swap DHT (`vess-swap-v0|btc|vichor`)
is the only exchange it needs, retaining the same keys, same wallet, same network. Bitcoin, Vichor, and Vess can all be exchanged feelessly and P2P. No price oracles required.

## Tags

Human-readable identities for payments (e.g. `+ALICE`). Once registered and paid to, the tag→address mapping is permanent.

- Lowercase alphanumeric only, 3–20 chars
- Argon2id PoW (2 GiB) to claim

## Architecture

Nodes form a peer-to-peer mesh with post-quantum handshakes (ML-KEM-768 + Falcon).
Ownership state is replicated deterministically. 

- **No consensus** — deterministic registry rules
- **No fees** — no gas, no mempool, no fee auction
- **No burn** — BTC returns after CLTV expiry
- **No bridge** — native Bitcoin script
- **No UTXOs or accounts** - payment amounts and recipients are obfuscated

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

## License

Apache 2.0 — see [LICENSE](LICENSE).