# Vess Protocol

Post-quantum digital cash. No blockchain. Deterministic finality in under one second. Unlimited throughput.

Bills are minted via proof-of-work, owned via hash chains, and transferred through a peer-to-peer mesh. Payments settle the moment the recipient claims the bill — no block confirmations, no epochs, no probabilistic waiting. Throughput has no protocol ceiling because there is no shared ledger to bottleneck: every payment is an independent message between two peers. All cryptography is post-quantum. There is no consensus mechanism because there is nothing to reach consensus about.

---

## Why Vess Exists

Crypto was supposed to be freedom money. It isn't.

Bitcoin promised decentralization. Today 4 mining pools control over 50% of hash rate, every transaction is permanently etched in a public ledger, and chain analysis firms sell your financial history to anyone who asks. Ethereum added smart contracts and got a surveillance-friendly account model where your entire token portfolio is one subpoena away. "Privacy coins" like Monero and Zcash exist — and are being systematically delisted from every exchange under regulatory pressure, pushing users back toward the transparent chains.

Meanwhile, governments are building CBDCs — Central Bank Digital Currencies — which are cashless surveillance systems with a currency symbol, using precious blockchain. Programmable money that can be frozen, expired, or restricted to approved merchants. The trajectory is clear: the financial system is converging on total visibility, whether it's run by a central bank or a public blockchain.

The original cypherpunk promise — **send money like handing someone a bill, with nobody watching** — has been abandoned by every major protocol.

Vess picks it up.

### What's different

**No ledger. No history. No trace.** There is no blockchain. No growing chain of blocks that every node must download and store forever. Bills are self-contained bearer instruments — like physical cash, they carry their own proof of value. A new node joins the network, participates fully, and never needs to download a single byte of transaction history.

**Your computer mints real money.** The 1 GiB memory-hard VM means regular laptops and desktops can mint competitively. No ASIC farms. No GPU warehouses. No staking cartels. You convert your own electricity into money on your own hardware. This is the "Bitcoin in 2009" story, except the architecture is designed to keep it that way.

**Privacy isn't a feature — it's the architecture.** Every payment targets a unique one-time stealth address. Human-readable names are hashed before they ever touch the network. There are no accounts to freeze, no addresses to blacklist, no transaction graph to analyze. Chain analysis doesn't work when there's no chain.

**Post-quantum from day one.** Not bolted on later, not "quantum-resistant roadmap." Every signature is ML-DSA-65. Every key exchange is ML-KEM-768. When quantum computers break ECDSA (and they will), Vess doesn't need a hard fork.

**Scales without the baggage.** DHT replication with k=20 means the early network (5–25 nodes) behaves like full consensus — every node sees everything. As the network grows, it naturally transitions to efficient sharded replication. No "bootstrap mode," no fragile early phase, no 500 GB initial sync.

**Anyone with a phone can participate.** The 1 GiB scratchpad fits comfortably on any smartphone made in the last five years. You won't get rich mining on a phone — maybe a few cents a day. But that's the point. In economies where a dollar is a meal, the ability to create money from a device you already own, with no bank account, no KYC, no intermediary taking a cut, is the difference between participating in the financial system and being locked out of it entirely. Bitcoin mining requires a warehouse. Ethereum staking requires capital. Vess requires a phone and electricity.

---

## How It Works

**Minting creates value.** A memory-hard VM grinds through a 1 GiB scratchpad until it finds a nonce that satisfies a STARK-provable difficulty target. The resulting `VessBill` carries an unforgeable proof of computation tied to a denomination and owner. Difficulty is hardcoded — no adjustment, no inflation schedule, no halvings.

**Ownership is a hash chain.** Each bill has a `chain_tip` and `chain_depth`. At genesis the minter's verification key is hashed into the tip. On transfer the new owner's key and an ML-DSA-65 signature advance the chain. Deeper chains are authoritative. Same-depth conflicts resolve deterministically (lowest hash wins). Re-spending supersedes any pending delivery, so no retraction mechanism is needed.

**Payments are proposals.** Sending a bill encrypts it to the recipient's stealth address and routes it through the mesh. The recipient claims ownership by broadcasting an `OwnershipClaim` at depth + 1. Until that happens the sender can still spend the bill. Offline delivery, cancellation, and double-spend resolution all fall out of this single mechanism.

**Identity is invisible.** Dual-Key Stealth Addressing (DKSAP) with ML-KEM-768 means every payment targets a unique one-time address. View tags let the recipient scan traffic in constant time. Human-readable `+tags` (e.g. `+alice`) map to stealth addresses through a DHT so the user never handles a raw public key. Tags are stored and gossiped as Blake3 hashes — no relay node ever sees the plaintext name.

---

## Architecture

```
┌──────────────┐  ┌───────────────┐  ┌──────────────┐
│  vess-cli    │  │  vess-kloak   │  │  vess-tag    │
│  (commands)  │──│  (wallet)     │──│  (naming)    │
└──────┬───────┘  └───────┬───────┘  └──────────────┘
       │                  │
┌──────┴───────┐  ┌───────┴───────┐  ┌──────────────┐
│ vess-foundry │  │ vess-stealth  │  │ vess-protocol│
│ (mint/proof) │  │ (DKSAP/KEM)  │  │ (wire format)│
└──────────────┘  └───────────────┘  └──────┬───────┘
                                            │
       ┌────────────────────────────────────┘
       │
┌──────┴───────┐  ┌──────────────┐
│ vess-artery  │  │vess-vascular │
│ (node logic) │  │ (iroh QUIC)  │
└──────────────┘  └──────────────┘
```

| Crate | Role |
|---|---|
| **vess-foundry** | `VessBill`, memory-hard minting VM, STARK proofs, ML-DSA-65 spend auth, bill sealing, reforge (split/combine) |
| **vess-protocol** | `PulseMessage` wire format — every message the network speaks |
| **vess-artery** | Node logic — ownership registry, limbo buffer, tag DHT, gossip, handshake, banishment, reputation, local RPC server |
| **vess-kloak** | Wallet — BillFold, bill selection (branch-and-bound), auto-reforge, stealth payments, recovery |
| **vess-stealth** | ML-KEM-768 stealth addresses with view tags, dual-key derivation |
| **vess-tag** | `+tag` validation and Argon2id proof-of-work registration |
| **vess-vascular** | Iroh QUIC transport (`vess/pulse/0` ALPN) |
| **vess-cli** | Unified CLI — wallet init, send, mint, balance, tag management, node operation |
| **vess-tests** | Integration and network tests |

---

## Cryptographic Primitives

| Purpose | Primitive | Standard |
|---|---|---|
| Key exchange | ML-KEM-768 | FIPS 203, NIST Level 3 |
| Signatures | ML-DSA-65 | FIPS 204 (Dilithium3) |
| Proof of work | STARK (IOP + Fiat-Shamir) | — |
| Hashing | Blake3 | — |
| Key derivation | Argon2id (2 GiB) | RFC 9106 |
| Symmetric encryption | ChaCha20-Poly1305 | RFC 8439 |

No pre-quantum cryptography. No RSA, no ECDSA, no Curve25519.

---

## Quick Start

```bash
# Build
cargo build --release

# Create a wallet (discovers peers via DNS seeds automatically)
vess init --tag yourname

# Run a node with embedded wallet and RPC enabled
vess node --wallet ~/.vess/wallet.json --rpc-port 9400

# Check balance (talks to local node via RPC)
vess balance

# Send payment
vess send 50 +alice

# Mint new bills (writes session to disk, Ctrl+C to stop)
vess mint
vess mint --finalize   # aggregate solves into bills and register ownership

# Register a tag (auto-hardens if wallet has bills)
vess register-tag alice

# Set a password for fast daily unlock
vess set-password --password "hunter2"
```

All commands except `init`, `recover`, and `node` route through the local node's RPC server (default port 9400).

---

## Design Decisions

**No global state.** Bills are self-contained. Artery nodes maintain local ownership registries with K-nearest replication, not a shared ledger.

**STARKs at genesis only.** The STARK proves minting. After that, ownership transfers are hash-chain advancements with ML-DSA-65 signatures. Proofs don't travel with every payment.

**Sampled aggregate proofs.** Large denomination mints produce a constant ~14 MiB proof regardless of how many D1 solves were aggregated. Merkle commitment over all digests + Fiat-Shamir 80-sample spot-check.

**Soft limbo, not hard locks.** Offline payments are buffered by artery nodes (up to 10K entries, 1-hour TTL). Bills in limbo are not locked — the sender keeps spending power until the recipient claims.

**Denomination-weighted eviction.** When limbo fills, low-denomination entries are evicted first, protecting high-value payments.

**Tag hardening.** Tags start unhardened (30-day TTL) after Argon2id registration. `register-tag` auto-hardens with a bill from the wallet if available; otherwise the tag hardens on the next mutation.

**Tag privacy.** All protocol messages carry `tag_hash: [u8; 32]` (Blake3 of the plaintext name). The plaintext never leaves the client. Relay nodes can store and replicate tag records without learning what name they correspond to.

**Wallet persistence.** The wallet is saved to disk immediately after every send and receive, plus a 60-second periodic flush as a safety net. No manual backup command needed.

**Per-peer rate limiting.** Tag lookups (30/60 s), mailbox collects (10/60 s), and general gossip (200/10 s) are rate-limited per peer with strike-based banishment on abuse.

**5-word recovery.** 5 BIP39 words + 5-digit PIN → Argon2id (2 GiB) → deterministic master keys. ~$2^{71.6}$ entropy. No seed file to lose.

---

## Tests

```bash
cargo test --workspace  # 186 tests
```

---

## License

BSL 1.1
