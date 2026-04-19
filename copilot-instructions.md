Role: Lead Systems Architect & Cryptographer (Rust/Iroh Specialist)

Goal: Build the Vess Protocol — a stateless, post-quantum digital cash network. No global ledger. Value lives in local STARK-proven VessBill objects routed through a vascular P2P mesh.

---

## Core Principles

1. **Stateless Sovereignty**: No blockchain, no global state. Value is encapsulated in VessBill structs — STARK-proven objects with an immutable `mint_id`.
2. **Vascular Flow**: Iroh QUIC-based P2P "pulses" — targeted, not broadcast. ALPN: `vess/pulse/0`, max 16 MiB per message.
3. **Conserved Quantity**: Sending is a proposal. Ownership changes ONLY when the recipient broadcasts an OwnershipClaim with deeper `chain_depth`. Sender can re-spend at any time before that.
4. **Post-Quantum Only**: ML-KEM-768 (key exchange), ML-DSA-65 (signatures), STARK (proof of work), Blake3 (hashing), Argon2id (KDF). Zero pre-quantum primitives.

---

## Workspace Layout (9 crates)

| Crate | Purpose |
|---|---|
| `vess-foundry` | VessBill, minting VM, STARK proofs, spend auth (ML-DSA-65), seal/unseal, reforge |
| `vess-protocol` | Wire format — `PulseMessage` enum, all network struct definitions |
| `vess-artery` | Node logic — ownership registry, limbo buffer, tag DHT, gossip, handshake, banishment, reputation, persistence, local RPC server |
| `vess-cli` | Unified CLI binary — init, send, mint, balance, tag ops, backup, recover, node, set-password |
| `vess-kloak` | Wallet — BillFold, bill selection, auto-reforge, stealth payments, tag cache, recovery, persistence |
| `vess-stealth` | DKSAP + ML-KEM-768 stealth addresses, view tags |
| `vess-tag` | VessTag validation, Argon2id PoW registration |
| `vess-vascular` | Iroh QUIC transport layer (`VessNode`) |
| `vess-tests` | Integration and network tests |

---

## VessBill — The Unit of Value

```
VessBill {
    denomination: Denomination,   // 1-2-5 series: D1..D50000
    digest: [u8; 32],             // Blake3 of final VM register state
    created_at: u64,              // Unix timestamp
    stealth_id: [u8; 32],        // Current owner's stealth address
    dht_index: u64,              // Deterministic DHT storage position
    mint_id: [u8; 32],           // Immutable identity (never changes)
    chain_tip: [u8; 32],         // Head of ownership hash chain
    chain_depth: u64,            // Transfer counter (deeper = authoritative)
}
```

Denominations: 1, 2, 5 multiplied through `D1, D2, D5, D10, D20, D50, D100, D200, D500, D1000, D2000, D5000, D10000, D20000, D50000`.

---

## Minting (vess-foundry)

Two-phase proof-of-work with a memory-hard VM:

1. **Phase 1 — Fast digest**: Execute VM (`execute_digest_only`) with random nonce. Check if `Blake3(digest)` has required leading zero bits. 99.99% miss — discard.
2. **Phase 2 — Full trace**: On a hit, re-execute with full `VmTrace` recording. Build STARK proof (IOP + Merkle commitments + Fiat-Shamir spot checks).

- **Scratchpad**: 4,194,304 cache lines × 64 bytes = 256 MiB, seeded via Blake3.
- **VM**: 7 opcodes (XOR-rotate, Add-mix, Mul-xor, Swap-add, Shift-mix, Rotate-add, Xor-chain). Memory-hard random walks over the scratchpad.
- **Scaling**: `BASE_ITERATIONS = 1 << 20` (~1M steps for D1). Iterations and difficulty bits scale with denomination.
- **Difficulty is hardcoded** — nodes reject bills with insufficient proof. No difficulty adjustment.

Session-based minting: `try_mint_d1()` returns `CompletedSolve`, accumulated in `MintSessionState`, finalized via `finalize_session()`.

**SampledAggregateProof**: For large denomination batches, a constant ~14 MiB sampled proof replaces per-bill proofs. Proof size is independent of denomination count.

---

## Ownership Model

Bills use a hash-chain ownership model. STARKs prove minting; ownership transfers use chain advancement.

**Genesis** (minting):
```
chain_tip[0] = Blake3("vess-chain-v0" || mint_id || owner_vk_hash)
chain_depth = 0
```
Submitted as `OwnershipGenesis` with full STARK proof. Nodes verify proof, register in `OwnershipRegistry`.

**Transfer** (spending):
```
chain_tip[n] = Blake3(prev_chain_tip || new_owner_vk_hash || transfer_sig_hash)
chain_depth += 1
```
Submitted as `OwnershipClaim`. No STARK needed — just the chain advancement + ML-DSA-65 transfer signature. The `encrypted_bill` field carries the bill encrypted to the recipient's stealth address for DHT recovery.

**Conflict Resolution** (double-spend defense):
1. **Deeper `chain_depth` wins** — the longer ownership chain is authoritative.
2. **Same depth → lowest `claim_hash` wins** — deterministic tiebreaker, no race conditions.

No retraction mechanism exists. To cancel a pending payment, the sender re-spends the bill (producing a deeper chain). The old claim is naturally superseded.

---

## Payment Flow

**Sending** (`prepare_payment` / `prepare_payment_with_transfer`):
1. Kloak selects bills via branch-and-bound (1000 iterations) → greedy fallback. `waste = change + BILL_COST × bill_count`.
2. Builds `TransferPayload` = bills + ML-DSA-65 transfer signatures + sender verification keys.
3. Encrypts payload into `StealthPayload` via DKSAP + ML-KEM-768 (dual encapsulation to scan + spend keys).
4. Wraps as `PulseMessage::Payment` with `view_tag`, `stealth_id`, `mint_ids`, `denomination_values`.
5. Bills marked as "reserved" in BillFold — excluded from future selection but re-spendable.

**Receiving** (`try_receive_payment` / `claim_transfer_bills`):
1. Fast filter: check `view_tag` against `scan_dk`. Single-byte comparison eliminates ~255/256 non-matching payments.
2. Decrypt `StealthPayload` → `TransferPayload`.
3. For each bill: generate new spend keypair, advance `chain_tip` (depth + 1), build `OwnershipClaim` with `encrypted_bill`.
4. Broadcast `OwnershipClaim` to network. Recipient now has deeper chain — authoritative owner.

**PaymentState**: `InFlight { sent_at, bill_mint_ids }` → `Final { finalized_at }`. No retracted state.

---

## Stealth Addressing (vess-stealth)

DKSAP with ML-KEM-768 (FIPS 203, NIST Level 3). Dual-key: `scan_ek` (1184 bytes) + `spend_ek` (1184 bytes).

```
MasterStealthAddress { scan_ek, spend_ek }   // Public — shared via VessTag
StealthSecretKey { scan_dk, spend_dk }        // Private — 2400 bytes each
```

**Payload construction** (`prepare_stealth_payload`):
- Encapsulate to both keys → `ss_scan`, `ss_spend` (shared secrets)
- `view_tag = Blake3(ss_scan)[0]` — 1-byte fast filter
- `stealth_id = Blake3(ss_scan || ss_spend)` — unique payment binding
- Encrypt plaintext with ChaCha20Poly1305 keyed from shared secrets

**Key derivation**: Deterministic from 64-byte seed via `generate_master_keys_from_seed()`. Seeds derived from recovery phrase.

---

## Spend Authorization (ML-DSA-65)

All ownership transfers are authorized via ML-DSA-65 (FIPS 204 / Dilithium3).

- `generate_spend_keypair() → (vk, sk)` — per-bill keypair
- `spend_message(mint_id, denomination, stealth_id, timestamp) → [u8; 32]` — genesis binding
- `transfer_message(mint_id, stealth_id, timestamp) → [u8; 32]` — transfer binding
- `sign_spend(sk, msg) → signature`, `verify_spend(vk, msg, sig) → bool`
- `vk_hash(vk) → [u8; 32]` — owner identity in ownership chain

---

## Reforge (Split & Combine)

Value conservation: $\sum \text{inputs} = \sum \text{outputs}$.

- **Split**: One D20 → one D10 + one D5 + one D5. Change bills returned to sender.
- **Combine**: Five D1 → one D5. All input bills must be owned by the same party.
- 1:1 transfers pass the original STARK proof through unchanged.
- Multi-input reforges produce compound proofs referencing all input STARKs.
- `ReforgeRequest { inputs, output_denominations, output_stealth_ids }` → `ReforgeResult { outputs, consumed_mint_ids }`

---

## Seal / Unseal (DHT Bill Storage)

Bills are stored encrypted in the DHT for recovery:

```
SealedBill { vk_hash, ciphertext, nonce: [u8; 12], denomination }
```

- `seal(bill, spend_seed, vk, sk) → SealedBill` — encrypt with key derived from `spend_seed + dht_index`
- `unseal(spend_seed, dht_index) → UnsealedContents { bill, spend_vk, spend_sk }`
- DHT key: `Blake3(spend_seed || domain || index)` — deterministic, recoverable from seed alone

**Manifest**: Index of all owned bill locations. Encrypted with `Blake3(seed || "vess-wallet-enc-v0")`, stored in DHT via `ManifestStore`.

---

## Artery Nodes (vess-artery)

Infrastructure nodes that maintain the ownership registry, limbo buffer, tag DHT, peer mesh, and a local-only JSON-RPC server.

### Ownership Registry
```
OwnershipRecord {
    mint_id, chain_tip, current_owner_vk_hash, current_owner_vk,
    denomination_value, updated_at, proof, digest, nonce,
    prev_claim_vk_hash: Option, claim_hash: Option, chain_depth
}
```
- `register(record) → bool` — conflict resolution on insert
- `consume(mint_id)` — mark spent (reforge input)
- `merkle_root()` — Blake3 Merkle tree over all records
- Replication: K-nearest by XOR distance, `K = max(20, network_size / 1000)`

### Limbo Buffer (Offline Delivery)
Holds encrypted payments for offline recipients:
- `MAX_TOTAL_ENTRIES = 10,000`, `MAX_ENTRY_AGE_SECS = 3600`, `MAX_ENTRIES_PER_PEER = 200`
- Denomination-weighted eviction at `EVICTION_THRESHOLD = 8,000`
- Bills in limbo are NOT spent — sender can re-spend to cancel
- `LimboEntry { payment, bill_ids, entered_at, relay_peer }`

### Tag DHT
- `store(record)` — first-broadcast-wins, one-tag-per-address invariant
- `harden(tag, bill_id, now)` — proof-of-payment makes tag permanent
- `purge_unhardened(now)` — 30-day TTL eviction (`TAG_PRUNE_SECS = 2,592,000`)
- XOR-distance storage with K replication

### Gossip
- K-nearest neighbors by XOR distance + random fan-out (2 additional)
- `PeerRateLimiter`: 200 msgs per 10s window, 3 strikes → banishment
- `DuplicateTracker`: 50 same-payload messages in 60s → flood detection

### Handshake
- `PROTOCOL_VERSION_HASH` — Blake3 Merkle of all source files (compile-time)
- HMAC challenge-response + Argon2id PoW (256 MiB, t=2)
- `PeerState`: Unknown → Challenged → Verified | Banished
- Sliding version window for rolling upgrades

### Banishment
- Thread-safe `BanishmentManager` with read-lock hot path
- Banished peers silently dropped — messages ignored

### Reputation
- `PeerReputation`: latency EMA (α=0.3), success/failure ratio, interaction window of 100
- `score = reliability × (1.0 / (1.0 + latency_ms / 1000.0))`
- `ReputationTable`: score-based peer selection, max 50,000 tracked peers

### Persistence
- `ArterySnapshot` → atomic file save/load via `NodeStorage`
- Contains: tags, limbo entries, peer reputations, ownership records, manifests, known peers, banned peers, hardening proofs
- Default directory: `~/.vess-artery/`

---

## VessTags (vess-tag)

Human-readable identifiers: 3-20 lowercase alphanumeric chars, prefixed with `+` (e.g., `+alice`).

- `dht_key = Blake3(tag_string)` — DHT routing key
- **Registration PoW**: Argon2id with 2 GiB memory, t=1, p=1 (~10 seconds on consumer hardware)
- **Lifecycle**: Unhardened (30-day TTL) → Hardened (permanent, via proof-of-payment with `confirm-tag`)
- **One-tag-per-address**: DHT enforces uniqueness in both directions
- **Lookup validation**: CLI verifies ML-DSA-65 signatures on tag records, requires quorum of 5 matching responses via `TagResolver`

---

## Wallet Recovery (vess-kloak/recovery)

5 BIP39 words + 5-digit PIN → full wallet reconstruction.

1. `passphrase = join(words, " ")`
2. `salt = "vess-recovery-v0:" || pin`
3. `seed = argon2id(passphrase, salt, t=4, m=2GiB, p=1) → 64 bytes`
4. `scan_seed = Blake3(seed || "vess-scan-v0")` → deterministic ML-KEM-768 keygen
5. `spend_seed = Blake3(seed || "vess-spend-v0")` → deterministic ML-KEM-768 keygen
6. `encryption_key = Blake3(seed || "vess-wallet-enc-v0")` — for sealed bill / manifest decryption

Security budget: $2048^5 \times 10^5 \approx 2^{71.6}$ combinations. With 2 GiB argon2id per evaluation, brute-force is economically infeasible. Post-quantum safe (Grover → ~$2^{35.8}$ quantum evaluations of memory-hard function).

---

## Wire Protocol (vess-protocol)

`PulseMessage` variants (serde + postcard):

| Message | Direction | Purpose |
|---|---|---|
| `Payment` | sender → network | Stealth-encrypted bill transfer |
| `DirectPayment` / `Response` | sender ↔ recipient | P2P payment bypassing relay |
| `OwnershipGenesis` | minter → artery | Register new bill with STARK proof |
| `OwnershipClaim` | recipient → artery | Claim ownership (chain_depth + 1) |
| `OwnershipFetch` / `Response` | any → artery | Query ownership status by mint_id |
| `TagRegister` | user → artery | Register VessTag with PoW |
| `TagLookup` / `Response` | user → artery | Resolve tag to stealth address |
| `TagStore` / `TagConfirm` | artery ↔ artery | Tag replication & hardening |
| `LimboHold` / `LimboNotify` / `LimboDeliver` | artery ↔ artery | Offline payment lifecycle |
| `MailboxCollect` / `Response` | user → artery | Collect buffered payments |
| `MailboxSweep` / `Response` | user → artery | Full limbo sweep on reconnect |
| `HandshakeChallenge` / `Response` | artery ↔ artery | Version + PoW peer verification |
| `PeerExchange` / `Response` | artery ↔ artery | Peer discovery (up to 10) |
| `FindNode` / `Response` | artery ↔ artery | Kademlia-style node lookup |
| `RegistryQuery` / `Response` | any → artery | Ownership registry lookup |
| `ManifestStore` / `ManifestRecover` / `Response` | user → artery | Wallet recovery manifests |
| `ReforgeAttestation` | artery → network | Broadcast completed reforge |
| `NetworkStats` / `Response` | any → artery | Network health metrics |

---

## CLI Commands (vess-cli)

All commands except `init`, `recover`, and `node` route through the local node's JSON-RPC server (default port 9400). `init` and `recover` auto-discover artery peers via DNS seeds.

```
vess init --tag <TAG>
vess recover --words "w1 w2 w3 w4 w5" --pin XXXXX
vess balance
vess send <AMOUNT> <+tag | stealth_id>
vess mint [--finalize] [--status]
vess register-tag <TAG>
vess lookup-tag <TAG>
vess confirm-tag <TAG> --mint-id <HEX>
vess backup <PATH>
vess pulse <NODE_ID> <MESSAGE>
vess listen
vess node [--k-neighbors 6] [--max-hops 3] [--state-dir PATH] [--bootstrap p1,p2]
         [--wallet PATH] [--wallet-password PWD] [--rpc-port PORT]
         [--seed DOMAIN] [--no-seed]
vess set-password --password <PWD>
```

Global flags: `--wallet <PATH>`, `--json`, `--rpc <PORT>`

---

## Test Suite

184 tests, 0 warnings. Key test files:
- `vess-tests/tests/integration.rs` — Payment lifecycle, double-spend prevention, reforge consumption, tag DHT
- `vess-tests/tests/network.rs` — QUIC connectivity, wire roundtrip, direct P2P payment
- Per-crate unit tests in each module

---

## Conventions

- Rust 2021 edition, workspace with shared dependencies
- All crypto: post-quantum only (ML-KEM-768, ML-DSA-65, STARK, Blake3, Argon2id, ChaCha20Poly1305)
- Networking: Iroh (iroh) with QUIC transport
- Wire serialization: serde + postcard (compact, no-std friendly)
- Persistence: serde_json for wallet and artery state files
- Error handling: `anyhow::Result` throughout
- No global mutable state — all node state behind `Mutex<ArteryState>`
- No retraction mechanism — chain_depth conflict resolution makes it unnecessary
- CLI routing: `init`/`recover` use DNS seed discovery; everything else goes through the local node's RPC server
