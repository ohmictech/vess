# Vess Protocol

Post-quantum digital cash. No blockchain. Deterministic finality in under one second. Unlimited throughput. Zero fees. Full nodes on smartphones.

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

**Your computer mints real money.** The minting VM uses 1 GiB of RAM, saturates the memory bus with 4 reads per step, and reads an 8 GiB per-identity dataset from NVMe/SSD — three layers that make regular laptops and desktops competitive miners. No ASIC farms. No GPU warehouses. No staking cartels. You convert your own electricity into money on your own hardware. This is the "Bitcoin in 2009" story, except the architecture is designed to keep it that way.

**Privacy isn't a feature — it's the architecture.** Every payment targets a unique one-time stealth address. Human-readable names are hashed before they ever touch the network. There are no accounts to freeze, no addresses to blacklist, no transaction graph to analyze. Chain analysis doesn't work when there's no chain.

**Post-quantum from day one.** Not bolted on later, not "quantum-resistant roadmap." Every signature is ML-DSA-65. Every key exchange is ML-KEM-768. When quantum computers break ECDSA (and they will), Vess doesn't need a hard fork.

**Scales without the baggage.** DHT replication with k=20 means the early network (5–25 nodes) behaves like full consensus — every node sees everything. As the network grows, it naturally transitions to efficient sharded replication. No "bootstrap mode," no fragile early phase, no 500 GB initial sync.

**Anyone with a phone can participate — as a full node.** Every other cryptocurrency requires you to trust someone else's server on a mobile device. Bitcoin's full node needs 600 GB. Ethereum's needs 1 TB+. "Light" clients skip verification entirely and rely on trusted third parties. Vess is the first cryptocurrency protocol where a phone running the native app is a genuine full node: it routes payments, verifies transfers it relays, holds DHT shards, participates in ownership resolution, and can mine — all in a ~60 MB background process with no chain to sync and no history to download. The foreground service survives Android battery optimization; the 1 GiB scratchpad fits on any phone made after 2019; the 8 GiB disk dataset fits on internal storage or a microSD card. In economies where a dollar is a meal, the ability to create money from a device you already own, with no bank account, no KYC, no intermediary taking a cut, is the difference between participating in the financial system and being locked out of it entirely. Bitcoin mining requires a warehouse. Ethereum staking requires 32 ETH. Vess requires a phone and electricity.

---

## Protocol Firsts

These are properties that, to the best of our knowledge, no other cryptocurrency protocol achieves simultaneously.

**First full-node protocol that runs natively on a smartphone.** Other mobile crypto apps are either light clients (trusting a third-party server), custodial wallets (trusting a company), or thin wrappers around a remote RPC. A Vess phone node has no chain to sync, bounded fixed memory, and participates in payment routing, ownership verification, and DHT replication at full protocol depth — not observer mode.

**First post-quantum digital cash protocol.** Every cryptographic primitive is post-quantum from genesis: ML-KEM-768 (key exchange / stealth addressing), ML-DSA-65 (ownership signatures), Blake3 (hashing), Argon2id (key derivation). No elliptic curve cryptography appears anywhere in the codebase. Most "post-quantum roadmap" projects still rely on ECDSA today.

**First digital cash system with deterministic sub-second finality and no global state.** Bitcoin finalizes probabilistically in ~60 minutes. Ethereum in ~12 seconds (with checkpoints). Monero in ~2 minutes. All of them require global ledger agreement. Vess payments finalize the instant the recipient broadcasts an ownership claim — typically under one second on a live network — and no global state is required because there is no shared ledger to agree on.

**First memory-hard + bandwidth-hard + storage-hard proof-of-work.** Most memory-hard PoW (Ethash, RandomX) uses one or two resistance layers. Vess uses three simultaneously: a 1 GiB RAM scratchpad, 4× memory bus saturation per VM step, and an 8 GiB per-identity NVMe dataset. The combination means no single hardware optimization (faster DRAM, wider memory bus, denser storage) breaks the balance — all three must be provisioned at commodity scale.

**No fees, ever.** There is no fee market. There is no miner extractable value. There are no gas costs. Payments are free to route because relay nodes are compensated by the ability to participate in the network, not by skimming from transactions. This is only possible because there is no shared ledger creating economic scarcity of block space.

---

## How It Works

**Minting creates value.** Running `vess mint` starts a continuous minting loop. The VM executes until it finds a nonce satisfying the difficulty target; on a hit, a `VessBill` with an unforgeable STARK proof is emitted. Difficulty is hardcoded — no adjustment, no inflation schedule, no halvings. Higher-denomination bills cost proportionally more work.

**Three-layer ASIC resistance.** The minting VM is designed so that a purpose-built ASIC cannot gain a meaningful advantage over a commodity laptop, desktop, or smartphone:

1. **Memory-hard scratchpad (1 GiB RAM).** At the start of each attempt the VM builds a 1 GiB random-access scratchpad seeded from the minter's identity. The entire scratchpad participates in every execution — keeping it at D-DRAM speed on-chip would require 1 GiB of SRAM, which is economically infeasible compared to cheap DRAM on a consumer motherboard.

2. **Bandwidth amplification (4× memory reads/step).** Each VM step performs 4 non-sequential scratchpad reads instead of 1, saturating the memory bus at full bandwidth. An ASIC with fast memory still pays the same bus bandwidth cost as consumer hardware — the bottleneck shifts from compute to memory I/O where ASICs have no structural advantage.

3. **Disk dataset (8 GiB NVMe/SSD).** A per-identity 8 GiB dataset is generated on first run and stored on local NVMe or SSD. The VM reads one dataset cache line every 8 steps, mixing it into register state. Storing 8 GiB per miner identity on-die is cost-prohibitive for ASICs; consumer SSDs handle it for a few dollars. Under the `test-mint` feature both the scratchpad and dataset shrink to 1 MiB (in-memory) so CI and tests complete in seconds.

Together these constraints mean your laptop or phone can mint competitively. All three resources — RAM, memory bandwidth, and fast storage — are cheap and abundant on commodity hardware but expensive to provision in the geometric quantities required for an ASIC advantage.

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
| **vess-android** | Android JNI bridge (`cdylib`) + Kotlin app — foreground service node, terminal CLI activity with full command parity |
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

# Send directly to a specific node (instant IRL payments, no mesh relay)
vess send 50 +alice --node-direct <hex_node_id>

# Recover a wallet from its 5-word recovery phrase + PIN
vess recover --words "apple brave clock delta echo" --pin 83921

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
