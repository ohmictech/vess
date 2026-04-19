# Vess Protocol

Post-quantum digital cash. No blockchain.

Bills are minted via proof-of-work, owned via hash chains, and transferred through a peer-to-peer mesh. All cryptography is post-quantum. There is no consensus mechanism because there is nothing to reach consensus about.

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
