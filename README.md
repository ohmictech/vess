[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange)](https://rust-lang.org)

# Vess

**Post-quantum digital cash. CPU-mined commodity. Stateless P2P network.**

Vess is a tri-asset stateless monetary system where value flows from physics through
time into spendable currency. No blockchain, no fees, no validators.

| Asset | Role | Supply | Backing |
|-------|------|--------|---------|
| **Vhalix** | Commodity | Unlimited, linear | CPU work (Argon2id) |
| **Vess** | Currency | ≤ locked Vhalix | Work + time commitment |
| **Vichor** | Equity | Fixed 1B | Network access premium |

## Vhalix — CPU-Mined Commodity

Vhalix is created by computing Argon2id proofs-of-work. Each proof is an
independent 1 GiB memory-hard hash computation taking ~30 minutes on a
mid-range CPU. Proofs are bound to a specific `(owner, nonce)` pair —
they cannot be reused, reordered, or stolen.

### Mining Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Algorithm | Argon2id | Memory-hard, ASIC-resistant |
| Memory | 1 GiB | Beyond commodity ASIC HBM capacity |
| Time passes | 12 | ~30 min per proof |
| Parallelism | 1 | Strictly single-core |

### Denomination

Proofs are batched into a Merkle tree and submitted as a single bill.
The denomination follows the 1-2-5 series: the largest valid value
≤ the number of proofs mined.

```
2295 proofs → denomination 2000 (excess: 295 → bounty pool)
2005 proofs → denomination 2000 (excess: 5 → bare minimum)
```

Every bill requires at least 5 excess proofs. These become a **bounty pool**
that pays verifiers 1 Vhalix per Argon2id recomputation they perform,
creating a self-sustaining verification economy.

### Fairness

Argon2id at 1 GiB cannot be meaningfully accelerated by specialized
hardware. A laptop and a server produce the same output per core per hour.
The only way to scale is to buy more CPU cores — and every core produces
at the same rate. No ASIC arms race, no mining cartels.

## Vess — Time-Locked Currency

Vhalix can be the basis for issuing Vess when locked for a duration (0.1–10 years).
The lock is a commitment: "I mined this work, and I'm staking it for N years."
This gives Vess its economic value. It's a currency backed by both past work
and future time commitment.

All Vess is fungible. Lock duration is the minter's commitment, not a
property of the bills themselves.

| Lock Duration | Vichor Required | Purpose |
|---------------|-----------------|---------|
| ≤ 1 year | None | Standard (free) |
| 1–10 years | Proportional burn | Premium credit |
| > 10 years | Not allowed | Cap at 10 years |

## Vichor — Network Equity

Vichor is a fixed-supply (1B) access token created in a one-time genesis
event. It is not for governance, as the protocol is founder-led. Vichor grants
access to premium time-lock durations beyond 1 year.

Vichor is burned to unlock extended credit. The burn is permanent,
reducing circulating supply. Demand for Vichor scales with demand for
longer-term Vess issuance, creating natural market pricing.

Vichor is a capitalization model that is non-extractive and essentially forces speculators to contribute to the network development, and user equity.

```
Vichor required = ceil(locked_vhalix × years / 100,000)
```

Traded on the built-in Swap DHT alongside Vhalix and Vess — no external
exchange required.

## Verification Economy

Every Vhalix bill includes a bounty pool from its excess proofs. Any node
can verify a bill by recomputing one Argon2id proof and submitting a
`BountyGenesis` claim. The verifier receives 1 Vhalix per proof verified.

| Role | Hardware | Time | Reward |
|------|----------|------|--------|
| Miner | Any CPU | Days/weeks per bill | Denomination value |
| Verifier | Any CPU | 30 min per proof | 1 Vhalix per bounty |

## How It Works

1. **Mine Vhalix** — Run Argon2id CPU proofs. Each takes ~30 min at 1 GiB.
2. **Submit batch** — When enough proofs accumulate, end your minting session.
3. **Lock → Vess** — Lock Vhalix for 0.1–10 years to mint Vess.
4. **Spend** — Vess, Vhalix, and Vichor units move via tags (e.g. `+ALICE`)

## Tags

Human-readable identities for payments (e.g. `+ALICE`). Once registered and
paid to, the tag→address mapping is permanent. Unconfirmed tags last 30 days.

- Lowercase alphanumeric only, 3–20 chars
- Argon2id PoW to claim

## Architecture

Nodes form a peer-to-peer mesh with post-quantum handshakes (ML-KEM-768 +
Falcon). Ownership state is replicated deterministically across Kademlia
DHT shards.

- **No blockchain** — deterministic registry rules, gossip-based
- **No fees** — no gas, no mempool, no fee auction
- **No validators** — every node independently verifies proofs
- **No burn** — Vhalix is locked, not destroyed
- **No accounts** — payment amounts and recipients are obfuscated

## Sovereignty & Routing

The Vess network is built on multiple layers of security, and node-to-node payments pass through multiple nodes to reach a destination, with an onion inspired payload.

Payments travel as fixed byte size, denominational, encapsulated bills to single use stealth addresses. Payment recipients, senders, minters, verifiers, and amounts are all invisible.

## Consensus

Vess has no blockchain or ledger. Rather, each bill contains its own state history and commitment. A bill cryptographically traces back to its mint or timelock origin, and ownership of a bill is claimed by the receiver, rather than announced by the sender. Deeper ownership chains of a bill win, which are located deterministically on the network's distributed hash table. In the case of conflicting depths, lower hash wins. This renders doublespends deterministically, rather than probabilistically, impossible.

## Cryptography

All operations are post-quantum.

| Purpose | Primitive |
|---------|-----------|
| Mesh handshake | ML-KEM-768 + Falcon |
| Ownership signatures | ML-DSA-65 |
| Stealth addressing | ML-KEM-768 (DKSAP) |
| Mining | Argon2id (1 GiB, data-dependent memory) |
| Hashing | Blake3 |
| Symmetric encryption | ChaCha20-Poly1305 |

## License

Apache 2.0 — see [LICENSE](LICENSE).