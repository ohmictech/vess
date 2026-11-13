# Architecture: Vess

Status: **revision 3 — one asset, work-linked emission, implemented.** Revision 3 is a reduction, not
an addition: the two-asset design of revision 2 and every alternative proof-of-work it explored are
gone. What remains is the smallest chain that still does the job.

Normative unless marked *policy*.

## 0. What changed in revision 3

| Rev 2 | Rev 3 | Section |
|---|---|---|
| Two assets, `Deep Vess` (security) and `Vess` (minted commodity) | One asset, `Vess`. No mint transaction, no nullifiers, no second balance | §1, §6 |
| Vess minted by memory-hard puzzles (Cuckatoo27, then four unshipped replacements) | No separate puzzle. Block PoW is BLAKE3 and ASICs are accepted | §8 |
| Deep Vess reward from a harmonic supply curve over cumulative Vess | **Emission is proportional to difficulty**: `reward = GENESIS_REWARD × genesis_target / target` with `GENESIS_REWARD = 100`. No curve, no halving, no cap | §13 |
| State root committed to an issuance counter and a nullifier set | State root commits to the account set only | §14.2 |
| Snapshots carried accounts + nullifiers + issuance | Snapshots carry accounts only | §16.2 |
| `vess-cuckatoo`, `vess-mint` crates | Deleted. Ten crates remain | §21 |
| No dev fee | **1% of every block reward** (floored) to a hard-coded `DEV_FEE_ACCOUNT`, taken out of the reward | §13.5 |

The Vess design documents from revision 2 (`SUPERTREE.md`, `COINCIDE.md`, `HAYSTACK.md`,
`VESSMINT.md`) are deleted with the code they described. Their conclusion is recorded in §8.3 so the
same dead end is not walked twice.

### 0.1 Implementation status

| Crate | Contents | Tests |
|---|---|---|
| `vess-core` | constants, canonical codec, `U256`, domain hashes, consensus types, operator parameter table, decoder corruption sweep | 34 |
| `vess-emission` | `reward(network, target)`, `split`/`dev_fee`/`miner_reward`, per-hash-invariance and clamp tests | 10 |
| `vess-crypto` | ML-DSA-65 adapter: context-string signing, canonical encoding checks, hardened seed derivation | 9 |
| `vess-state` | 256-level sparse Merkle tree, accounts, transfer/state-update execution, undo logs | 20 |
| `vess-consensus` | header/target/MTP rules, checkpoints, fork choice, block template, mining, full block validation, reward-proportionality and dev-fee split, boundary suites | 24 |
| `vess-storage` | redb schema, atomic per-block commit, transaction index carrying height, header re-validation on load, body/header pruning windows, crash recovery | 7 |
| `vess-mempool` | admission, per-account limit, fee replacement, eviction, expiry, fee-ordered selection | 8 |
| `vess-net` | frame envelope with checksum, Noise session, read-timeout discrimination, RPC request/reply including content-bearing transaction replies and `WAIT_FOR_TIP`, handshake, snapshot frames | 8 |
| `vess-wallet` | key files (plaintext, Argon2id-encrypted, single and hierarchical), HD account derivation, signed transfers and state updates, RPC client with auto-nonce send | 13 |
| `vess-node` | node service (CLI `vess`): init/run/status, wallet, miner, loopback RPC, account/state/proof lookup, transaction content and status, tip and account long-polls, `INV` sessions with compact block relay, address gossip and crawler, limits, scoring, catch-up, reorg, orphan re-admission, leveled logger, snapshot install/refuse, pruning knobs | 53 |

**186 tests pass**; `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`
are both clean.

## 1. Project summary

The chain issues exactly one asset, `Vess`, and pays it to whoever mines a block. There is nothing
else to own:

1. Block PoW is `BLAKE3` over the header. No memory-hard puzzle, no separate mining commodity. Custom
   hardware is not resisted; §8.3 explains why resisting it was abandoned.
2. A block's reward is proportional to the work it proves, so emission *is* difficulty (§13).
3. Accounts are post-quantum `ML-DSA-65` identities, addressed by the hash of their public key.
4. Signed transfers are transportable out of band and submittable by anyone.
5. Per-account 32-byte opaque state commitments are updated by signed messages.
6. One-second target block interval, retargeted every 64 blocks within ±4×.
7. Prunable block bodies, a compact current-state database, and trustless state snapshots.
8. A minimal wallet crate that builds, signs, and submits transfers over local RPC, and a miner that
   mines block templates.

What this design deliberately gives up: scarcity. Supply is the integral of work performed, so it
grows without bound while the network hashes, and price settles near the cost of production rather
than above it. That is the point — it makes one Vess a claim on a fixed amount of energy, not a
speculative store of value (§13.2).

## 2. Implementation constraints

- Latest stable Rust; pinned in `rust-toolchain.toml` (edition 2024).
- Minimal dependencies; §21 lists all of them with their justification.
- **No JSON anywhere** — not in networking, storage, config, logging, CLI output, or tests.
- Raw TCP with a canonical binary protocol. `std::net`, explicit worker threads, bounded queues.
- No async runtime. No `serde`.
- One implementation per operation. No duplicated logic, no dead code, no placeholder modules, no
  `unimplemented!()`, no fake crypto.
- Checked integer arithmetic throughout. Floating point never affects consensus.
- ML-DSA must be a real implementation. Never substitute a weaker scheme.

## 3. Networks

Each network is a distinct genesis and a distinct `chain_id`. Transactions and blocks from one
network are invalid on another.

```text
chain_id = BLAKE3("VESS-CHAIN-ID-V1" || network: u8)
```

| Network | `network` | Genesis target | Genesis timestamp | Purpose |
|---|---|---|---|---|
| DEVNET  | 0 | 2^240 | 1 700 000 000 | integration tests, trivial PoW |
| TESTNET | 1 | 2^232 | 1 700 000 000 | long-running test chain |
| MAINNET | 2 | 2^226 | 1 700 000 000 | production |

The genesis target sets the reward scale as well as the starting difficulty, because the two are the
same number (§13). A block at genesis difficulty pays `GENESIS_REWARD = 100` on every network,
of which 99 goes to the miner and 1 to the development account; what differs is how hard that first
block is.

## 4. Consensus constants

One versioned module (`vess-core::constants`). Not user-configurable at runtime. The operator-facing
copy is whatever `vess node params --network <name>` prints, generated from these constants.

```text
PROTOCOL_VERSION                     = 1

# sizes
MAX_BLOCK_BYTES                      = 1_048_576      # header + body, inclusive
MAX_TRANSACTION_BYTES                = 65_536
MAX_NETWORK_FRAME_BYTES              = 2_097_152
ML_DSA_PK_BYTES                      = 1_952
ML_DSA_SIG_BYTES                     = 3_309
BLOCK_HEADER_BYTES                   = 234

# hashing / crypto
SECURITY_HASH                        = BLAKE3-256
ACCOUNT_HASH                         = BLAKE3-256
SIGNATURE_SCHEME                     = ML-DSA-65

# time
TARGET_BLOCK_SECONDS                 = 1
MTP_SPAN_BLOCKS                      = 11
MAX_FUTURE_DRIFT_SECONDS             = 120
MAX_PER_BLOCK_ELAPSED_SECONDS        = 4

# difficulty
DIFFICULTY_WINDOW_BLOCKS             = 64
DIFFICULTY_FIRST_RETARGET_HEIGHT     = 128
MAX_DIFFICULTY_ADJUSTMENT            = 4
MIN_RETARGET_ELAPSED_SECONDS         = 16            # window clamp: 64 / 4
MAX_RETARGET_ELAPSED_SECONDS         = 256           # window clamp: 64 * 4
MAXIMUM_TARGET                       = 2^240
MINIMUM_TARGET                       = 2^216

# emission
AMOUNT_TYPE                          = u64
INTERMEDIATE_ARITHMETIC              = checked u128 (u256 for target/work)
GENESIS_REWARD                       = 100           # total reward of a block at genesis_target
MINIMUM_BLOCK_REWARD                 = 1             # emission floor for easier-than-genesis targets
DEV_FEE_DIVISOR                      = 100           # dev fee is reward / 100, floored
DEV_FEE_ACCOUNT                      = 5c5b1f655f17d91758a778e3e48ac36fdaaf90b6e792309e030ab52c6cb2f0a7
MAX_BLOCK_REWARD                     = 10_000_000_000 # clamp, unreachable with the shipped targets
MAX_SUPPLY                           = 10^18         # representational bound, not a cap

# retention
REORG_UNDO_RETENTION_SECONDS         = 43_200
BLOCK_BODY_RETENTION_SECONDS         = 43_200

# pruning
DEFAULT_PRUNE_BLOCKS                 = 1_024
DEFAULT_PRUNE_HEADERS                = 100_000_000
PRUNE_FLOOR_BLOCKS                   = 256

# mempool (policy)
MEMPOOL_MAX_TRANSACTIONS             = 4_096
MEMPOOL_MAX_TRANSACTION_BYTES        = 16_777_216
MEMPOOL_PER_ACCOUNT_TRANSACTIONS     = 1

# network (policy)
P2P_MAGIC                            = 0x56455353    # "VESS"
RPC_MAGIC                            = 0x56455352    # "VESR"
P2P_DEFAULT_PORT                     = 9_732
RPC_DEFAULT_PORT                     = 9_733
MAX_HEADERS_PER_MESSAGE              = 512
CONNECT_TIMEOUT_MS                   = 5_000
HANDSHAKE_TIMEOUT_MS                 = 10_000
READ_TIMEOUT_MS                      = 30_000
WRITE_TIMEOUT_MS                     = 30_000
```

Peer session limits (frame budget, scoring, ban window, connection caps) are *node policy*, not
consensus, so they are constants in `crates/vess-node/src/p2p.rs` rather than in `vess-core`: a
128-frame-per-second budget, a **192-signature-verification-per-second budget**, a session score
ceiling of 24, 60-second bans, 32 inbound connections total and 4 per address, a 200 ms session tick
with at most 32 announced transactions (so honest relay peaks near 160 verifications/s, under the
budget), a 2 s resync interval, a 32-block sync lookback and 64 pull rounds per announcement. None of
them can make a block valid or invalid.

`2^N` as a 32-byte big-endian target is `0x01` at byte index `(255 - N) / 8`, zeros elsewhere. A
`u128` cumulative-work accumulator holds 2^88 blocks at `MINIMUM_TARGET`; saturation is specified but
unreachable.

## 5. Canonical binary encoding

One codec (`vess-core::codec`), used by consensus, storage, networking, signing, and tests.

- Integers are unsigned, fixed-width, big-endian. `usize`, pointers, native layout, and native-endian
  integers are never serialized.
- No floating-point fields anywhere.
- Fixed-size byte arrays have no length prefix.
- Variable-length collections use a checked `u32` element count.
- Variable-length byte strings use a checked `u32` length plus an explicit maximum for the context.
- Every structure that may need extension carries a `u16` version as its first field.
- The decoder rejects trailing bytes, non-canonical encodings, unknown versions, overflowing lengths,
  lengths exceeding the context maximum, and any allocation before the length has been validated
  against the remaining input.

Domain separation. Every hash preimage starts with exactly one of these ASCII strings (no NUL
terminator, no length prefix):

```text
VESS-CHAIN-ID-V1
VESS-ACCOUNT-V1
VESS-TRANSFER-V1
VESS-STATE-UPDATE-V1
VESS-TRANSACTION-ID-V1
VESS-BLOCK-HEADER-POW-V1
VESS-BLOCK-ID-V1
VESS-TX-LEAF-V1
VESS-TX-NODE-V1
VESS-TX-ROOT-V1
VESS-STATE-ROOT-V1
VESS-STATE-LEAF-V1
VESS-STATE-NODE-V1
VESS-NETWORK-FRAME-V1
VESS-RPC-FRAME-V1
```

Signature domains use the same strings as ML-DSA's `ctx` parameter (§7.3), not as a hash prefix.

## 6. Accounts

```text
account_id = BLAKE3("VESS-ACCOUNT-V1" || ml_dsa_65_public_key)
```

An account ID *is* the hash of its owner's public key: no separate address encoding, no checksum.
Paying someone means paying that hash, and anyone holding the recipient's public key can derive the
address it pays without asking (`vess wallet address --public-key HEX`); the recipient proves ownership
by signing, which every transfer already requires (§7.3). An account's identity is therefore bound to
one key and cannot be re-pointed at another.

Stored value (the ID is the database key and is not duplicated):

```text
Account {
    next_nonce: u64,
    balance:    u64,
    state_hash: [u8; 32],
}
```

Rules:

- A newly referenced account starts at balance 0, nonce 0, zero state hash.
- A spending account must already exist and have sufficient balance.
- A signed transaction is valid only when `nonce == next_nonce`; success increments nonce by exactly
  one (checked).
- The ML-DSA public key travels in every signed transaction and must hash to the sender account ID.
- Keys cannot rotate in protocol version 1. Loss of the private key means loss of the account.
- `state_hash` is opaque to consensus; the chain stores no associated data.
- **Balance enters the ledger in exactly one place: `State::credit`.** Consensus calls it for the
  block reward and for transaction fees. There is no other issuance path, and no transaction type
  that creates balance.

## 7. Transactions

Protocol version 1 has exactly two objects that can appear in a block body:

```text
BlockBody {
    count: u32,                 // <= floor(MAX_BLOCK_BYTES / minimum tx size)
    items: [Transaction; count]
}

Transaction {
    kind: u8,                   // 1 = Transfer, 2 = StateUpdate
    body: <kind-specific>
}
```

Unknown `kind` values are invalid. Trailing bytes after the last item are invalid.

### 7.1 Transfer

```text
Transfer {
    version:              u16,
    chain_id:             [u8; 32],
    sender_public_key:    [u8; 1952],
    recipient_account_id: [u8; 32],
    amount:               u64,
    fee:                  u64,
    nonce:                u64,
    expiry_unix:          u64,     // 0 = no expiry
    signature:            [u8; 3309],
}
```

Canonical size is `2 + 32 + 1952 + 32 + 8 + 8 + 8 + 8 + 3309 = 5 359` bytes, plus the kind byte and
the body count prefix, so a 1 MiB block holds at most 195 transfers. This is the cost of post-quantum
signatures travelling with every payment; it is not hidden or amortised.

The *unsigned body* is every field above except `signature`, in the order shown, canonically encoded.

Execution is atomic and happens only after all checks pass:

1. `version == 1`, `chain_id` matches.
2. `BLAKE3("VESS-ACCOUNT-V1" || sender_public_key)` equals the account ID being debited.
3. Signature verifies over the unsigned body with `ctx = "VESS-TRANSFER-V1"`.
4. Sender account exists.
5. `nonce == sender.next_nonce`.
6. `amount > 0`.
7. `expiry_unix == 0 || block.timestamp <= expiry_unix`.
8. `balance >= amount + fee` (checked).
9. Debit `amount + fee` from the sender.
10. Credit `amount` to the recipient (creating the account if absent).
11. Credit `fee` to `header.payout_account_id`.
12. Increment the sender nonce.

Steps 9–12 cannot fail after step 8; they still use checked arithmetic.

### 7.2 Account state update

```text
StateUpdate {
    version:           u16,
    chain_id:          [u8; 32],
    sender_public_key: [u8; 1952],
    new_state_hash:    [u8; 32],
    fee:               u64,
    nonce:             u64,
    expiry_unix:       u64,
    signature:         [u8; 3309],
}
```

Same validation order as a transfer (steps 1–7, with `amount` replaced by `fee`: `balance >= fee`),
signature `ctx = "VESS-STATE-UPDATE-V1"`, then: debit the fee, set `state_hash = new_state_hash`,
credit the fee to the payout account, increment the nonce. Setting the hash to its current value is
allowed and costs the fee.

### 7.3 Signatures

- Scheme: ML-DSA-65 (FIPS 204), pure (message, not pre-hash), with a non-empty context string.
- `ctx` is the ASCII domain string of §5: `b"VESS-TRANSFER-V1"` / `b"VESS-STATE-UPDATE-V1"`.
- Message is the canonical unsigned body bytes. No additional hashing.
- The decoder rejects non-canonical signature encodings, so a transaction has exactly one valid
  serialization per (message, signature) pair. If the library cannot guarantee that, re-encode the
  parsed signature and compare bytes.
- ML-DSA is randomized: this is why identity never hashes signature bytes (§7.4).

### 7.4 Identifiers

```text
transaction_id = BLAKE3("VESS-TRANSACTION-ID-V1" || kind: u8 || canonical_unsigned_body)
block_id       = BLAKE3("VESS-BLOCK-ID-V1" || canonical(BlockHeader))
```

`transaction_id` hashes the **unsigned** body, so re-signing the same intent yields the same ID: a
transaction cannot be made to look new by randomizing its signature. Two transactions with the same
`transaction_id` are the same transaction.

### 7.5 Rejection reasons

Consensus-critical, reported by tests and the RPC reply, never used as a consensus comparison:
`BadVersion, BadChainId, BadAccountId, BadSignature, UnknownAccount, BadNonce, ZeroAmount, Expired,
InsufficientBalance, DuplicateInBlock, BadPoW, BadTarget, BadTimestamp, BadTxRoot, BadStateRoot,
BlockTooLarge, BadTxEncoding, MissingParent`.

## 8. Proof of work

### 8.1 Rule

```text
BLAKE3("VESS-BLOCK-HEADER-POW-V1" || canonical_header) <= target
```

Compared as unsigned 256-bit big-endian integers, equality allowed. The nonce is
`header.security_nonce`, 32 bytes; a miner increments it as a 256-bit big-endian integer and re-hashes
the 234-byte header. Any 256-bit value that satisfies the target is a valid solution: there is no
structure to solve, only hashes to compute.

```text
work(target) = floor(2^256 / (target + 1))
```

So `MINIMUM_TARGET = 2^216` means at most 2^40 work per block, and difficulty is exactly the expected
number of hashes a block costs: `D = 2^256 / target`.

### 8.2 Mining

`vess_consensus::mine_header` grinds the nonce until the header satisfies its own target. A miner
therefore needs a template from a node (header plus selected transactions), a payout account, and CPU
time. Nothing else — no solver, no memory budget, no proof file. `vess miner` does this.

### 8.3 Why memory hardness was abandoned

Revision 2 tried to make mining ASIC-resistant in order to issue a second "commodity" asset that only
GPUs could produce. Five designs were specified, measured, and then discarded:

| Design | Why it failed |
|---|---|
| Cuckatoo27 (1.5 GiB, 42-cycle) | Fine as a puzzle, but a second asset with its own issuance policy needed a whole second consensus path, and ASICs for a 1.5 GiB graph are buildable anyway. |
| Supertree / structured data ordering | The proof is a step list that costs as much to check as to produce, or requires full recomputation, so verification is never cheaper than mining. |
| Coincide (Equihash `k=1`) | Collapses to a birthday search once `k=1`; the memory/time tradeoff moves to the verifier. |
| Haystack (cycle search in a lattice) | Hit rate too low to be a mint, and it needed a shared per-epoch table, which lets many mining chains share one copy of the memory and destroys per-chain hardness. |
| VessMint (sequential memory chain, per-branch 64 MiB tables) | Measured 309 ns/step: a 2^19-step chain is 0.14 s to derive and 0.23 s to verify. Verification was *more* expensive than mining, so a validator paid more than a miner to check a block's worth of mints. |

The lesson that ended the line of work: **a proof of work that is cheap to verify is a proof that
admits ASICs, and a proof that resists ASICs is expensive to verify.** There is no third option. So
this chain takes the honest branch — plain BLAKE3, ASICs welcome — and lets the reward rule, not the
puzzle, decide who mines (§13).

## 9. Blocks

### 9.1 Header

```text
BlockHeader {
    version:           u16,
    chain_id:          [u8; 32],
    previous_block_id: [u8; 32],
    transaction_root:  [u8; 32],
    state_root:        [u8; 32],
    timestamp_unix:    u64,
    target:            [u8; 32],     // u256 big-endian
    payout_account_id: [u8; 32],
    security_nonce:    [u8; 32],
}
```

Canonical encoding is exactly this field order: 234 bytes, no length prefix.

### 9.2 Full block

```text
block = canonical_header (234 bytes) || BlockBody
block.len() <= MAX_BLOCK_BYTES
```

### 9.3 Transaction root

Binary Merkle tree over the transaction IDs in list order:

```text
leaf      = BLAKE3("VESS-TX-LEAF-V1" || tx_id)
internal  = BLAKE3("VESS-TX-NODE-V1" || left || right)
odd node  = promoted unchanged (never duplicated)
empty set = 32 zero bytes
transaction_root = BLAKE3("VESS-TX-ROOT-V1" || u32 be(count) || merkle_root)
```

### 9.4 Block validation

A block is valid iff all of the following hold, in this order:

1. `block.len() <= MAX_BLOCK_BYTES`; header decodes canonically; `version == 1`; `chain_id` matches.
2. `previous_block_id` is known (main chain or a side branch with retained undo data).
3. `target` equals the consensus-required target for this height (§11) and lies in
   `[MINIMUM_TARGET, MAXIMUM_TARGET]`.
4. Timestamp rules (§12).
5. PoW satisfies the target (§8.1).
6. Body decodes canonically; every item ≤ `MAX_TRANSACTION_BYTES`; no duplicate `transaction_id`
   within the block.
7. `transaction_root` matches the recomputed root (§9.3).
8. Execute the body in list order against the parent state. Any invalid item invalidates the whole
   block; nothing is partially applied.
9. Split `reward(network, header.target)` (§13): credit `reward - dev_fee` to
   `header.payout_account_id` and `dev_fee` to `DEV_FEE_ACCOUNT`, creating either account if absent
   and crediting nothing when a share is zero.
10. Recompute `state_root` (§14.2); it must equal `header.state_root`.

Because the reward is a function of `header.target` alone, a miner cannot influence its own reward by
choosing transactions, ordering, or timing — only by mining at a different difficulty, which the
retarget controls.

### 9.5 Fees

Fees are credited to `header.payout_account_id` during execution (step 8), so a transaction later in
the same block may spend fees credited earlier in that block. Deterministic and allowed.

### 9.6 Genesis

Genesis is a fixed header per network, exempt from PoW, target, timestamp, and body checks:

```text
version           = 1
chain_id          = chain_id(network)
previous_block_id = 0x00 * 32
transaction_root  = BLAKE3("VESS-TX-ROOT-V1" || u32 be(0) || 0x00*32)
state_root        = state root of the empty account set
timestamp_unix    = profile timestamp (§3)
target            = profile genesis target (§3)
payout_account_id = 0x00 * 32
security_nonce    = 0x00 * 32
```

Genesis chain work is `work(genesis_target)`. No reward is paid at genesis; genesis has no body.

## 10. Chain selection

```text
work(target)  = floor(2^256 / (target + 1))
chain_work(b) = chain_work(parent) + work(b.target)      // u128, saturating add
```

- Follow the branch with the greatest `chain_work`, not the greatest height.
- Ties are broken by the **lower** `block_id` (byte-wise lexicographic) so all nodes agree.
- `HELLO`/`INV` carry `chain_work` as a 16-byte big-endian hint. It is never trusted: it is recomputed
  locally, and only used to decide whether a pull is worth starting.

## 11. Difficulty adjustment

```text
fn required_target(height h, chain) -> Target:
    if h < DIFFICULTY_FIRST_RETARGET_HEIGHT (128):
        return profile.genesis_target
    if h % DIFFICULTY_WINDOW_BLOCKS != 0:
        return target(h - 1)
    # window: the 64 parent-child deltas ending at block h-1
    elapsed = 0
    for i in (h - 64) ..= (h - 1):
        dt = ts(i) - ts(i - 1)                        # signed i64
        elapsed += clamp(dt, 0, MAX_PER_BLOCK_ELAPSED_SECONDS)   # u64
    elapsed = clamp(elapsed, MIN_RETARGET_ELAPSED_SECONDS, MAX_RETARGET_ELAPSED_SECONDS)
    t = (target(h - 1) as u256) * elapsed / 64        # u256; elapsed <= 256, target <= 2^240
    return clamp(t, MINIMUM_TARGET, MAXIMUM_TARGET)
```

Properties asserted by tests:

- One manipulated timestamp can move the window by at most ±4 s out of 64 s (≈6.25 %), because each
  delta is clamped.
- A run of equal timestamps gives `elapsed = 0`, clamped to 16, so difficulty can rise at most 4×;
  equal timestamps can never produce cheaper work.
- The target is clamped to `[MINIMUM_TARGET, MAXIMUM_TARGET]` at every retarget, so no target can
  drift outside the range where `work()` is well defined and `u128` cumulative work is safe.
- No floating point; the divisor is the constant 64, never zero.

Adversarial cases covered: hashrate ÷100 step, hashrate ×100 step, constant timestamps throughout the
window, timestamps pinned to the future bound, `elapsed` clamped at both ends, targets at both clamps.

## 11.9 Trusted checkpoints

A checkpoint is a `(height, block id)` pair compiled into the binary. At a checkpointed height exactly
one block id is acceptable; any other is refused with `CheckpointMismatch`, whatever work is behind it.

```text
CHECKPOINTS_DEVNET / _TESTNET / _MAINNET : &[(u64, [u8; 32])]   # vess_core::constants
```

**What it is for.** A long-range attack presents a *different history* — a cheap fork from long ago,
signed with keys or carrying work that were valid then — rather than trying to outrun today's chain.
No local rule can tell the two apart: a node that just joined has nothing to compare against, both
histories are internally valid, and the attacker's is simply lighter. Any chain that has been running
for a while therefore needs a few points that are *not* derivable from the headers, and the only such
point is a constant the operator's binary already contains.

- Enforced in `check_header`, so it covers headers received from a peer, headers ingested during a
  snapshot sync, and bodies pulled directly. No path skips it.
- Re-checked in `Node::open`: a database whose main chain contradicts a checkpoint refuses to start
  rather than serving a history this binary does not believe in. Headers below the node's own pruning
  window cannot be re-checked; they were validated before they were pruned.
- **Empty is the honest default.** All three networks ship none, because a checkpoint claims that a
  specific block is in that network's history forever, and no network here has run long enough for
  that to be true. Adding one is a source change and a rebuild, deliberately: a checkpoint list that a
  remote file or environment variable could rewrite would be an attack, not a defence.
- A wrong entry permanently forks the nodes that ship it off the network, which is why
  `vess node params` prints the list — an operator can see exactly which heights this binary settles.

## 12. Timestamps

`mtp(h)` is the median of the timestamps of blocks `h, h-1, … h-10` (11 blocks; fewer near genesis,
median of what exists). Consensus rules for a non-genesis block at height `h` over parent `p`:

```text
ts >  mtp(p)                                    # strictly greater
ts <= mtp(p) + MAX_FUTURE_DRIFT_SECONDS (120)
```

`mtp` uses the lower median when the history is shorter than 11 blocks, so a two-block history
resolves deterministically. The 11-block window is what stops the clock ratcheting: each block is
bounded relative to the *median* of its recent past, not to its parent, so no run of blocks can walk
the timestamp forward by 120 s each. The drift bound is deliberately loose — at a 1 s target an honest
node must be able to represent 2 s, 10 s, or 60 s spacing when hashrate drops, and a tight bound would
make difficulty unable to ease. Manipulation is contained by the per-delta clamp of §11 instead:
whatever a miner claims, one block adds at most 4 s to the retarget window.

Timestamps are **not** required to be monotone across the chain; the retarget clamps handle
regressions. A node may additionally refuse to relay a block whose timestamp exceeds its own wall
clock by a few seconds before relaying it — that is *policy*, never a consensus failure, and the block
must still be accepted later if it becomes valid.

## 13. Emission

### 13.1 Rule

```text
reward = GENESIS_REWARD * genesis_target / target      // integer division, GENESIS_REWARD = 100
reward = clamp(reward, MINIMUM_BLOCK_REWARD, MAX_BLOCK_REWARD)
```

Since `D = 2^256 / target`, this is `reward = GENESIS_REWARD * D / D_genesis`: a block pays in
proportion to the work it proves, and a block at genesis difficulty pays 100. Emission *is*
difficulty, which has three consequences that are the whole reason for the rule.

The floor is not cosmetic. `MAXIMUM_TARGET` is the easiest target a block may have, so on any
network whose genesis target is harder than that, difficulty can ease to a target where the division
truncates to zero. `MINIMUM_BLOCK_REWARD = 1` keeps such blocks worth producing; without it a chain
that loses hashrate could reach a state where blocks pay nothing and nobody mines.

`MAX_BLOCK_REWARD = 10^10` is the opposite guard, above `GENESIS_REWARD * MAXIMUM_TARGET /
MINIMUM_TARGET` (`100 * 2^24 = 1.68e9`), so the clamp never sets emission on the shipped networks but
still bounds the arithmetic if a future network makes the targets more extreme.

### 13.2 Consequences

- **Revenue per hash is constant.** A miner's expected `vess` per unit of work is identical at every
  difficulty, so nobody gains by manipulating difficulty, and there is no halving schedule to argue
  about. Compare a fixed-reward chain, where a rising hashrate silently cuts everyone's revenue.
- **Supply is the integral of work.** No curve, no cap (`MAX_SUPPLY` is a representational bound for
  tooling, not a monetary target), no terminal tail. Total supply grows with cumulative energy spent
  on the chain, and at zero profit marginal price equals marginal cost of production.
- **Price tracks hardware efficiency, not a scarcity story.** As ASICs improve, the cost of producing
  one Vess falls, and so does its market price. This asset is a claim on a fixed quantity of energy,
  not a store of value. A decaying-`k` variant would have kept a mild scarcity bias; it was rejected
  because it reintroduces exactly the difficulty-gaming surface this rule removes.

### 13.3 Numbers

Every shipped network pays `100` at genesis difficulty and grows from there:

| Network | `genesis_target` | total reward at genesis | total reward at `MINIMUM_TARGET` |
|---|---|---|---|
| devnet | 2^240 | 100 | 1 677 721 600 |
| testnet | 2^232 | 100 | 6 553 600 |
| mainnet | 2^226 | 100 | 102 400 |

At genesis difficulty the split is 99 miner / 1 dev on every network.

If hashrate doubles, difficulty doubles and so does the reward per block, so per-hash revenue is
unchanged. Emission in `vess/s` is `reward × hashrate / D = GENESIS_REWARD — hashrate /
D_genesis` — linear in hashrate and independent of everything else.

### 13.4 What is not in the reward

Nothing. There is no fee-sharing formula beyond "the fee goes to the payout account", no issuance
counter in the state root, and no second asset whose supply the reward depends on. Removing the
issuance counter from consensus is what makes the state root (§14.2) a pure function of the account
set, and that in turn is what makes snapshots (§16.2) simple.

### 13.5 Development fee

Every block reward is split, by consensus:

```text
dev_fee = reward / DEV_FEE_DIVISOR      // DEV_FEE_DIVISOR = 100, integer division
miner   = reward - dev_fee
```

Details that matter:

- **It comes out of the reward.** Total issuance per block is unchanged, so §13.2's invariants (constant
  revenue per hash, supply as the integral of work) still hold exactly. The fee is not new money.
- **It is consensus, not configuration.** `DEV_FEE_ACCOUNT` is a constant; a node that pays someone
  else produces a different state root and is simply wrong.
- **At genesis difficulty the split is exactly 99 / 1**, because `GENESIS_REWARD = DEV_FEE_DIVISOR =
  100` was chosen for that. The split floors, so it only disappears if difficulty eases more than 100x
  below genesis (reward < 100), at which point emission is already near its floor.
- **The account id is a real key's.** `DEV_FEE_ACCOUNT` is the account id of the project's ML-DSA key;
  the secret key is not in this repository and lives in a git-ignored keyfile
  (`.vess-keys/wallets/dev.key` by convention), so `*.key` and `/.vess-keys/` are in `.gitignore`.
  Whoever holds that seed can spend every fee the chain has paid. `vess-core` asserts the constant is
  not the all-zero id and not `BLAKE3("VESS-DEV-FEE-ACCOUNT-V1")` — the burn placeholder defined by
  `hash::dev_fee_placeholder_account` — so a careless edit cannot route fees into a hole. Rotating it
  is a hard fork: it changes the state root of every block after the change.

## 14. Ledger state and commitments

### 14.1 Sparse Merkle tree

The committed set is a **256-level sparse Merkle tree** over 32-byte account IDs. Path bit for level
`d` (0 = top) is bit `255 - d` of the key, most-significant first: a `0` bit descends left, `1` right.

```text
leaf(key, value) = BLAKE3("VESS-STATE-LEAF-V1" || key || value)
internal(l, r)   = BLAKE3("VESS-STATE-NODE-V1" || l   || r)
DEFAULT[0]       = 0x00 * 32
DEFAULT[d + 1]   = internal(DEFAULT[d], DEFAULT[d])      for d in 0..256
```

`DEFAULT[1..=256]` is generated once and cached; a build-time test pins it.

Account leaf value (48 bytes):

```text
balance u64 be || next_nonce u64 be || state_hash
```

Including the key inside the leaf hash prevents cross-position collisions.

### 14.2 State root

```text
state_root = BLAKE3("VESS-STATE-ROOT-V1" || PROTOCOL_VERSION (u16 be) || account_root)
```

The empty state (genesis) is `account_root = DEFAULT[256]`. There is no issuance counter and no second
tree: the account set *is* the state, so two nodes that agree on accounts agree on the root, and a
snapshot is just the accounts.

### 14.3 Proofs

An inclusion or non-inclusion proof is the 256 sibling hashes from the root down to the leaf (8 192
bytes, top level first). Verification folds the leaf (or `DEFAULT[0]` for non-inclusion) up the path
and compares with the committed root. Proofs are served by RPC (§19) and are not part of consensus.

### 14.4 Atomic application

Applying a block is one storage transaction containing:

1. all account mutations,
2. the block's undo record,
3. the header record and the main-chain pointer (written last).

Either the whole transaction commits or nothing does. The in-memory sparse tree is updated in the same
step as the account map, so a failed commit leaves both unchanged.

### 14.5 Undo record

```text
Undo {
    changes: [(account_id, Option<Account>)]     // previous value, None = did not exist
}
```

One entry per touched account, recorded at most once, holding the value *before* the block. Reversing
the log restores the exact prior accounts and therefore the exact prior root. Retention:
`REORG_UNDO_RETENTION_SECONDS = 43 200` (12 h), with a floor of `PRUNE_FLOOR_BLOCKS` blocks.

## 15. Reorganizations

1. Find the common ancestor of the new branch and the current main chain.
2. Refuse if any block to be detached lacks an undo record or body: stop with an explicit
   `reorg_exceeds_undo_horizon` error and require archive synchronisation. Never guess.
3. Apply undo records in reverse order, restoring accounts and the tip.
4. Replay the new branch with full validation, atomically per block.
5. Rebuild the mempool: re-admit transactions that are still valid; drop the rest.
6. Recompute state roots; a mismatch is a fatal internal error, not a peer-attributable fault.

Headers are retained according to the node's header window and bodies/undo records according to its
body window, both counted in blocks below the tip and both `0` = keep forever (§16.1). Undo records
must outlive `REORG_UNDO_RETENTION_SECONDS`, so the body window has a floor of
`PRUNE_FLOOR_BLOCKS = 256`. Pruning is a background pass, never part of block application, and it never
changes consensus: a pruned node and an archival node produce identical state roots at every height.

## 16. Storage

One embedded transactional store: **`redb`** (pure Rust, ACID, crash recovery, no `serde`). One
database file per node; every value is a canonical-codec blob.

| Table | Key | Value |
|---|---|---|
| `meta` | `&'static str` | schema version, network, `tip_id`, prune policy, oldest retained heights |
| `accounts` | `[u8; 32]` | `Account` |
| `headers` | `[u8; 32]` (block_id) | header + `height` + `chain_work` |
| `height_index` | `u64` (height) ‖ `[u8; 32]` (block_id) | empty — range scans for pruning |
| `bodies` | `[u8; 32]` (block_id) | body bytes |
| `undo` | `[u8; 32]` (block_id) | `Undo` |
| `tx_index` | `[u8; 32]` (transaction_id) | block id ‖ height (8, be), append-only |
| `pending` | `[u8; 32]` (transaction_id) | canonical transaction, survives restart |

### 16.1 Pruning policy

Two node-local knobs, both "keep this many blocks below the tip", both `0` = never prune:

| knob | CLI | default |
|---|---|---|
| bodies + undo records | `--prune-blocks` | `DEFAULT_PRUNE_BLOCKS = 1 024` |
| headers | `--prune-headers` | `DEFAULT_PRUNE_HEADERS = 100 000 000` |

Two integers rather than an "archival / pruned" mode: a mode couples both windows to one binary,
while independent windows let an operator pick any mixture (full archive, pruned bodies with full
headers, full bodies with truncated headers, minimal) with the same code. Both are recorded in `meta`,
so a restart with no flags keeps the previous policy instead of silently changing the node's storage
behaviour.

Constraints:

- A window below `PRUNE_FLOOR_BLOCKS = 256` is raised to the floor: a reorg needs undo data for the
  blocks it detaches, and the floor comfortably exceeds any plausible fork depth.
- Pruning runs at most every `PRUNE_INTERVAL_BLOCKS = 64` accepted blocks, below the tip only.
- `accounts`, `tx_index` and `meta` are never pruned. State is the live set; the transaction index is
  an unbounded convenience and is the one table that only ever grows. It is also what keeps
  `TRANSACTION` answering after the headers and bodies around a transaction are gone (§19).
- The in-memory chain is trimmed to the retained header window, so the node cannot advertise a header
  it can no longer serve.
- Loading a pruned database cannot re-validate headers whose parents are gone, so headers below the
  boundary are trusted from the store (they were validated when written) and the last
  `PRUNE_FLOOR_BLOCKS` headers are re-validated on open.
- **Fresh-sync consequence:** a node cannot replay history it no longer has. State is rebuilt by
  replaying bodies, so a peer whose body window starts above a new node's tip cannot catch it up with
  blocks; that node joins by state snapshot (§16.2) only if it was started with `--trust-snapshot`.
  A peer that is behind and cannot be helped logs the reason with both heights rather than stalling
  silently.

### 16.2 State snapshots

State is transferred instead of replayed:

```text
SnapshotFrame::Start { height, accounts }        // counts, for validation
SnapshotFrame::Accounts([(account_id, Account)]) // batches
SnapshotFrame::End { accounts }
```

A snapshot is accepted only when the height is the tip of our own validated header chain, the
snapshot is newer than our current state, and `state.root()` equals that header's `state_root` — and
then only if we can **prove** that root. A header alone proves nothing: a peer may mine one block with
any `state_root` it likes and send the accounts that hash to it, so an install requires the anchor's
body, which is validated against the parent state we hold (a snapshot that agrees with that is simply
a shortcut for replaying one block). A snapshot for a block we cannot validate is refused with
`SnapshotUnproven` unless the node was started with `--trust-snapshot`, which turns the peer's account
set at that height into a trust decision and is logged as a warning.

That is the honest state of the design: without trusted checkpoints baked into the binary, adopting a
snapshot across a gap is trusting the peer for the whole state, so it is opt-in rather than automatic.
The receiver then drops undo records, bodies, and the transaction index (they describe history it does
not have) and keeps headers and the height index. One consequence is deliberate and worth stating: a
transaction mined before the snapshot is `unknown` afterwards, because the node has no record of it —
so a caller that needs history must not rely on a snapshot-synced node for it.

Because the state root no longer commits to a nullifier set or an issuance counter, "accounts" is the
whole payload, and there is nothing else that can silently be inconsistent.

## 17. Mempool (policy, never consensus)

- One pending transaction per account (`MEMPOOL_PER_ACCOUNT_TRANSACTIONS = 1`). A second transaction
  for the same account replaces the first only with a strictly higher fee and the same nonce;
  otherwise it is refused. This keeps the mempool linear in accounts rather than in transactions.
- Bounded by count (`4 096`) and bytes (16 MiB), with deterministic eviction of the lowest-fee,
  earliest-arrived entry.
- Expired transactions are dropped on the node's own clock; this never affects consensus.
- Selection for a template is fee-descending, then arrival order, capped by `MAX_BLOCK_BYTES`. A
  transaction that fails to apply is skipped, never fatal.
- The mempool is persisted (`pending` table) so a restart does not lose admitted transactions, and it
  is re-admitted through the same `submit_transfer`/`submit_state_update` path, so nothing enters it
  that was not signature-checked.
- After a reorg, anything the abandoned blocks contained goes back in and everything is re-checked
  against the new state (`prune_stale`).

## 18. Peer network

Every peer connection is a Noise session over TCP; canonical-codec frames travel inside it, magic
`0x56455353` ("VESS"), `u32` length plus a checksum of the payload.

### 18.0 Transport encryption

```text
Noise_XX_25519_ChaChaPoly_BLAKE2s
prologue = "VESS-NOISE" || TRANSPORT_VERSION (u16 be) || chain_id (32)
```

- The handshake runs immediately after `connect`/`accept`, **before** the `HELLO` frame, so nothing —
  not even the protocol version — is visible on the wire. A peer that speaks plaintext fails the Noise
  handshake and is dropped without reading a frame.
- `XX` authenticates both sides with static X25519 keys and gives forward secrecy. The static key is
  learned during the handshake and bound to the session; the node logs it at debug level
  (`encrypted session with key ...`).
- The prologue binds the session to this chain and to `TRANSPORT_VERSION`, so a peer on another
  network, or one speaking a future framing, is rejected at the handshake rather than mis-parsed.
- Above this layer nothing changes: the session implements `Read`/`Write` as a byte stream by
  encrypting in records of at most 65 519 bytes, each prefixed with a 2-byte length. The frame codec
  is unaware of it.
- Identity: `<datadir>/identity.key` holds the 32-byte X25519 secret, created on first open and kept
  out of the database so it survives a wiped chain. It is not a wallet key and holds no funds.

**Remaining gap, stated plainly:** the peer's static key is trusted on first use. There is no pinning
list yet, so a first connection to a peer you have never met can be machine-in-the-middled by whoever
answers on that address — encryption alone does not stop that. What it does stop is passive observation
and off-path injection, and the crypto binding means an active attacker must also relay the chain
honestly or the peer diverges visibly. Address gossip (§18.3) widens this gap: whoever wins a first
contact can also feed invented addresses, which is why gossip only ever propagates addresses whose
handshake *we* completed.

Frame kinds: `HELLO`, `HELLO_ACK`, `INV`, `GET_ADDR`, `ADDR`, `GET_HEADERS`, `HEADERS`, `GET_BLOCK`,
`BLOCK`, `TX`, `GET_PENDING`, `PENDING`, `CMPCTBLOCK`, `GET_STATE`, `STATE`, `PING`, `DISCONNECT`.

Handshake payload: protocol version, chain ID, genesis block ID, best block ID, best `chain_work`
(16-byte BE hint only), listening port, random connection nonce (for self-connection detection), and
the sender's oldest retained body and header heights, so a peer can tell "behind" from "behind beyond
what this peer has".

Requirements: partial reads/writes handled exactly; read/write/handshake/idle timeouts; bounded
outbound queue with backpressure; connection caps per node and per address; deterministic peer
scoring with a session ban; nothing a peer says about height, work, state, or time is trusted
without local recomputation. No TLS and no peer identity in v1: object
validity comes from PoW, signatures, and hashes.

### 18.1 Sessions

The network is a set of long-lived TCP sessions running the *same* code on both ends, so a node that
is only ever dialled still serves and still pushes its news:

1. `HELLO`/`HELLO_ACK` with the handshake above. Mismatched chain id, genesis, or protocol version
   ends the session before anything else is accepted.
2. Each wake-up (`SESSION_TICK_MS = 200`) a session announces its own state: `INV {height, tip_id}`
   whenever the tip changed, then `TX` for each pending transaction this peer has not been sent yet.
   Every `RESYNC_INTERVAL_MS = 2000` a session compares its height with the peer's and pulls if it is
   behind, so a missed pull cannot strand a node behind an idle chain.
3. Receiving `INV` for an unknown tip starts a pull over the same socket: `GET_HEADERS` from
   `height − 32` (so a fork point is always included), then `GET_BLOCK` for every unknown header, at
   most `MAX_PULL_ROUNDS = 64` rounds per announcement. Blocks are validated normally, so a peer
   cannot push anything past consensus.
4. `GET_HEADERS`, `GET_BLOCK`, `GET_STATE`, `GET_PENDING`, `PING` and unsolicited `TX`/`BLOCK` are
   served inline, including while a pull is in flight — a node never stops answering because it is
   busy syncing.
5. A blocked or slow peer costs one thread and at most `WRITE_TIMEOUT_MS` per write; no node lock is
   held across a socket operation.

Per session: `FRAME_BUDGET_PER_SECOND = 128` inbound frames, then the session is closed and the
address banned for `BAN_SECONDS = 60`. Signature verification gets its own budget
(`MAX_VERIFICATIONS_PER_SECOND = 192`) because a well-formed transaction with a junk signature costs
us an ML-DSA-65 verification (~370 us release, ~25 ms debug) while costing the sender nothing;
frames past that budget are dropped and charged to the peer's score. Inbound sessions are capped at `MAX_INBOUND_CONNECTIONS = 32`
total and `MAX_INBOUND_PER_IP = 4` per address, and loopback peers are never banned or capped per
address, so a local development cluster cannot lock itself out. Malformed payloads cost 1 point,
unsolicited replies 1, unknown kinds 2, a rejected block 1, out of `MAX_SCORE = 24`.

### 18.2 Compact block relay

A new tip is announced as `CMPCTBLOCK { height, header, short_ids }` rather than a bare `INV`. Each
short id is six bytes of `BLAKE3("VESS-COMPACT-BLOCK-V1" || block_id || transaction_id)`, so ids are
salted per block and cannot be precomputed. The receiver:

1. Ignores the message if it already has the block.
2. Falls back to a normal pull if the parent is unknown — then it is missing history, not this block.
3. Otherwise looks every short id up in its own mempool, rebuilds the body in the announced order, and
   runs the ordinary `validate_block`. Nothing is trusted: a wrong or colliding id produces a block
   whose `transaction_root` or `state_root` does not match, so it is simply invalid.
4. On any miss or rejection, sends `GET_BLOCK` and accepts the full body.

A block whose transactions every peer already has costs 234 B plus 6 B per transaction instead of
5 359 B per transaction: about 1.4 KB instead of 1.05 MB. This matters much more here than in a
small-signature chain, because one transfer is 5.4 KB.

### 18.3 Peer discovery

Discovery is one frame pair and one deliberately conservative rule.

```text
GET_ADDR                             -> ask for up to MAX_ADDR_ENTRIES = 16 addresses
ADDR { count, [addr, static_key]* }  -> count <= 16, addr <= 64 bytes, canonical codec
```

**Only verified addresses travel.** A record is created when a session completes, and it stores the
static X25519 key that the Noise handshake actually proved — never a key a peer merely asserted. `ADDR`
gossip carries verified records only, so an invented address cannot be laundered through an honest
node: it can reach us, but it cannot be re-broadcast by us until we have dialled it and seen its
handshake succeed.

- **Learning** (`ADDR` from a peer): every entry must be an IP literal with a non-zero port. Ports are
  1–65 535, unspecified/multicast/broadcast addresses are dropped, and loopback/private/link-local/
  RFC 5737 ranges are accepted *only* from a peer whose own connection is local, so a remote peer cannot
  point a node at its own loopback. A learned record starts unverified (`successes = 0`) and cannot be
  gossiped on until a real session with it succeeds. The book holds `MAX_RECORDS = 512`, evicting
  unverified records first, so it cannot be grown without bound.
- **Gossip** (our `ADDR` reply): verified records only, excluding the asker, at most
  `GOSSIP_FANOUT = 16` per request, taken from a rotating cursor so every live peer is offered over time
  instead of the same head of the list.
- **Asking**: a session sends one fire-and-forget `GET_ADDR` after the handshake when it knows fewer than
  `GOSSIP_THRESHOLD = 8` verified peers. It never waits for the reply and never blocks the session.
- **Nothing a peer says can downgrade a proven address.** If a gossiped record names an address we have
  already verified but with a different key, it is ignored: only our own handshake may re-key a verified
  record, or one frame per honest peer would erase the whole book. Address classification also folds
  IPv4-mapped IPv6 onto IPv4 first (`::ffff:127.0.0.1` is loopback), and rejects CGNAT, `0.0.0.0/8`,
  `198.18/15` and `240/4`, so an internal address cannot be smuggled in to aim the crawler at it.
- **Crawling**: `crawl()` runs beside the session loops, wakes on the same interval as they do, and dials
  one address it is not already connected to, preferring verified records. A failed dial charges the record
  (`MAX_FAILURES = 8`, after which an *unverified* record is deleted), so a poisoned address dies out on
  its own instead of being retried forever.
- **Persistence**: the book is written to `<datadir>/peers.txt` on change and on shutdown (temp file
  plus rename), so a restart keeps the peers it found instead of starting from `--peer` alone.

Self-connection needs no new defence: `HELLO` already carries a random connection nonce and a node drops
any session that echoes its own, so gossip cannot make a node flood itself.

### 18.4 Bootstrapping at start-up

A node with an empty address book still has to find someone, so the start-up address list is the merge
of four sources, in this order:

```text
--peer A,B          long-lived sessions, kept whether or not they answer
--seed A,B          bootstrap hints, same treatment once they answer
VESS_SEEDS=A,B      the same thing from the environment, for a container or service unit
DEFAULT_SEEDS_*     compiled into the binary, one list per network (vess_core::constants)
```

`peers::bootstrap` merges them, dropping blanks and collapsing duplicates onto their first occurrence,
so passing the same host twice dials it once and the order stays predictable. `DEFAULT_SEEDS_DEVNET`,
`DEFAULT_SEEDS_TESTNET` and `DEFAULT_SEEDS_MAINNET` are currently **empty** — there is no public entry
point to hard-code yet — and `default_seeds(network)` keys off the network so a devnet node can never
dial a mainnet seed. Filling one in is a source change, not a config change, because a seed list that a
remote file could rewrite would be an eclipse vector.

Start-up order is then: open the database, load the book, bind RPC to `127.0.0.1` and p2p to
`0.0.0.0`, start `serve` (inbound), and start `poll` — *if there is anyone to dial*, meaning a
non-empty merged list **or** a non-empty address book. `poll` starts one keep-alive loop per configured
address plus the `crawl` thread that works through the book, so a node restarted without `--peer` or
`--seed` still rejoins the network it found last time. `known_peers=` in the start-up output reports how
many addresses the book had at that moment.

### 18.5 Bans and key pinning

**Bans are persistent.** `BAN_SECONDS = 60` is still the penalty, but the list lives in
`<datadir>/bans.txt` (`ip until_unix`, one per line, written temp-file-plus-rename) and is loaded at
start-up. A ban a restart forgets is barely a ban: a flooding peer would simply reconnect after the
next service restart.

- Loopback is never banned and never written, so a local cluster cannot lock itself out — and an old
  file cannot do it either, because loopback entries are dropped when the file is read.
- Expired entries are dropped on the next check and the file rewritten; a garbage line is ignored
  rather than fatal.
- `STATUS` reports `bans`, so an operator can see the list is growing without reading the file.

**Keys are pinned after first contact.** A record created by a completed handshake stores the static
X25519 key that handshake proved, and from then on that address must present the same key:

- Every session checks its peer's proven key against the book's record before anything else happens;
  a mismatch ends the session, charges the record a failure, and logs the address. This covers
  outbound dials (where the address is known up front) and inbound sessions (where it is derived from
  the peer's `HELLO` listen port).
- `AddressBook::record_success` refuses to overwrite a verified record's key as a second line of
  defence, so no code path can re-key an address that has already been proved.
- The cost is deliberate: a peer that wipes `identity.key` becomes unreachable until the operator
  removes its line from `peers.txt`. That is the correct failure mode for a pin — accepting the new
  key would hand an attacker a way to take over an address by winning one later handshake.
- First contact is still trust on first use, because there is nothing to pin yet. Pinning changes that
  from a permanent window into a one-time one.

Not implemented: capability negotiation, and checkpoint distribution over the network (checkpoints are
compiled in, §11.9, because a peer-supplied one would defeat the purpose).

## 19. Local RPC and the wallet crate

Both use canonical-codec frames over TCP (default `127.0.0.1:9733`), magic `0x56455352` ("VESR").
Every request has a `u32 request_id` echoed in the reply; every reply ends with `ok: u8` and, when
`ok == 0`, a `reason: u16` from §7.5.

| Type | Request | Reply |
|---|---|---|
| `STATUS` | — | network, height, tip_id, chain_work, peers in/out, mempool count, total supply, `reward_next` (miner's share) and `dev_fee_next` |
| `BALANCE` | account_id | `exists`, balance, next_nonce, state_hash |
| `TEMPLATE` | payout_account_id | header (nonce zeroed), height, reward, transactions (the node assembles `transaction_root`/`state_root` from its own mempool) |
| `SUBMIT_BLOCK` | full block bytes | accepted flag, block_id or reason |
| `SUBMIT_TRANSFER` | canonical `Transfer` | accepted flag, transaction_id or reason |
| `SUBMIT_STATE_UPDATE` | canonical `StateUpdate` | accepted flag, transaction_id or reason |
| `PROOF` | account_id | root, `value: Option<48 bytes>` (None = non-inclusion), 256 siblings |
| `BLOCK` | height or block id | id, height, timestamp, state_root, chain_work, transaction ids |
| `TRANSACTION` | transaction_id | position (status, in_mempool, block id, height, confirmations) **and content**: kind, sender, recipient, amount, fee, new_state_hash |
| `WAIT_FOR_TIP` | `after: block id`, timeout_ms | the tip as soon as it differs from `after`, or on timeout |
| `WAIT_FOR_ACCOUNT` | account_id, the last state the caller saw, timeout_ms | that account's current state, as soon as it differs, or on timeout |
| `STOP` | — | exits cleanly (used by tests) |

`TRANSACTION` reports content as well as position because a block lists only transaction ids: a
scanner watching for deposits could otherwise see that a balance moved but not who paid it, how much,
or which of several payments in one block did it. The content comes from the mempool entry or from the
body of the block that carries it, so a mined transaction is still fully described. `kind == 0` means
the node has never seen it — the zeros in the other fields are then not a real sender or amount.

`status` is reported rather than left to the caller to infer, because "unknown", "pending", "mined",
"orphaned" and "outside our pruned window" are five different answers that used to look alike:

| status | Meaning |
|---|---|
| `unknown` | the id has never been seen by this node |
| `pending` | in the mempool, including a transaction a reorg returned to it |
| `mined` | in a block on the main chain, membership verified against our own headers |
| `orphaned` | indexed in a block that is not on the main chain, and no longer pending |
| `pruned` | mined at a known height now below our header window; confirmations come from the height recorded in the index |

`pruned` exists because the transaction index is the only durable record of where an old transaction
was mined: `TX_INDEX` stores `block_id ‖ height` (`decode_tx_location` still reads the older 32-byte
entries as "block known, height unknown"), so pruning the header does not turn a fully buried deposit
into a transaction the node appears never to have seen. Content is genuinely gone with the body at that
point, so `kind` is `0` and the fields are zeroes — the honest answer, since the bytes are not here to
read.

`WAIT_FOR_TIP` is a long-poll, not a subscription: it holds no server state, opens no stream, and
needs no new framing. The waiting thread holds **no node lock**, so a client parked on it cannot
delay mining, peers, or other RPC calls; the tip is read under a short lock, the thread waits on a
`TipSignal` condvar, and the height is re-read afterwards. The wait is clamped to
`MAX_WAIT_MS = 25 000`, below `READ_TIMEOUT_MS`, so a waiting client always gets a reply. Asking with
an already-stale `after` returns immediately. `vess node watch` is the client for it.

`WAIT_FOR_ACCOUNT` is the version a wallet actually wants, and the one that makes the primitive worth
having: it takes the account plus the last state the caller saw, re-checks after every tip change, and
returns only when the balance, nonce, or commitment actually differs. Blocks that do not concern the
account produce no output, and the reply is the account state itself, so a wallet spends one call per
change instead of one poll per interval. It returns the same shape as `BALANCE`, including `exists`.
`vess wallet watch` is the client.

Both are scoped honestly: they are notification *hints* on an unauthenticated loopback port. They tell
a client when to look, never what is true — the state still comes from `BALANCE`/`PROOF`, and a
reorg is visible because a later reply reports fewer confirmations or a different tip.

A real push subscription was considered and rejected: it would need a broadcast bus, per-subscriber
bounded queues, a second frame kind for unsolicited replies, and a cap on subscribers — a new
resource and a new DoS surface on the RPC port, to save polling a loopback socket.

`exists` distinguishes an absent account from one whose fields are all zero: without it, `BALANCE`
would answer "0, 0, zeros" for both. `PROOF` settles the same question cryptographically, since
non-inclusion is provable, and is the only way for a caller that does not trust the node to learn an
account's state; both are reachable from the CLI as `vess node account` and `vess node proof`.

`reward_next` is the miner's share of `reward(network, required_target(tip + 1))` and `dev_fee_next`
is the development fee that goes with it, so a miner can price a block before mining it.

### 19.1 Keyfiles

Three versions, all readable. A single-account key still writes v2; a hierarchical one writes v3,
which carries the byte that says what the 32 plaintext bytes mean.

```text
v1 legacy (35 bytes)       v2 encrypted (92 bytes)       v3 encrypted (93 bytes)
u16 version = 1            u16 version = 2              u16 version = 3
u8  network                u8  network                  u8  network
[u8; 32] seed              u8  kdf = 1 (Argon2id)       u8  kind (0 single, 1 hd)
                           u32 m_cost_kib               u8  kdf = 1 (Argon2id)
                           u32 t_cost                   u32 m_cost_kib
                           u32 p_cost                   u32 t_cost
                           [u8; 16] salt                u32 p_cost
                           [u8; 12] nonce               [u8; 16] salt
                           [u8; 32] ct || [u8; 16] tag  [u8; 12] nonce
                                                        [u8; 32] ct || [u8; 16] tag
```

- Key: Argon2id(passphrase, salt, 64 MiB, 3 passes, 1 lane) -> 32 bytes, default parameters chosen so
  a stolen file costs ~0.2 s per guess; the parameters are stored in the file so they can be raised
  later without stranding old keys.
- AEAD: ChaCha20-Poly1305 with associated data = the whole header (version, network, KDF id, KDF
  parameters, salt). Editing the cost parameters therefore fails the tag instead of silently
  weakening the file, and a file from another network is refused after decryption.
- Wrong passphrase, truncated file, and tampered header or body are all distinct errors
  (`WrongPassphrase`, `MalformedKeyfile`), and none of them is a panic.
- A passphrase is supplied to the CLI with `--password-file FILE` or `--password-env VAR`, never as an
  argument, because arguments are visible in the process list and land in shell history. `wallet new`
  without either writes the legacy format and says so on stderr.

#### Hierarchical accounts

A v3 key with `kind = hd` holds a **master seed**, and every account is derived from it:

```text
child_seed(i) = BLAKE3("VESS-HD-V1" || master_seed || u32_be(i))
account(i)    = ML-DSA-65(child_seed(i))
```

- **Hardened only.** ML-DSA has no public-key derivation, so nothing walks from an account to its
  siblings or its parent: a leaked child key exposes that account and no other. The cost is that
  addresses cannot be generated from a public key, so the master seed is needed — the right trade for
  a wallet that keeps its master offline.
- **One backup, many addresses.** The keyfile is the whole wallet; indices are unlimited and the same
  master always reproduces the same addresses (`vess wallet addresses --count N`).
- **Old keyfiles are untouched.** A v1 or v2 file has `kind = single`: its 32 bytes *are* an ML-DSA
  seed, index 0 is that account, and any other index is refused (`NotHierarchical`) rather than
  silently deriving something else. New wallets are HD; `wallet new --legacy` writes the old shape.
- An HD keyring has **no unencrypted representation** — the plaintext format has no room for the kind
  byte — so `save` refuses rather than writing a file that would be misread as single-account.

`vess-wallet` contains no consensus logic beyond encoding and signing:

```text
keygen(network) -> key file              # canonical binary: version, network, ML-DSA seed
account_id(secret) -> [u8; 32]
build_transfer(secret, recipient, amount, fee, nonce, expiry) -> Transfer            # signed
build_state_update(secret, new_state_hash, fee, nonce, expiry) -> StateUpdate        # signed
submit_transfer(rpc, tx) / submit_state_update(rpc, tx) / submit_block(rpc, block)
transfer(rpc, secret, recipient, amount, fee)          # reads the nonce, then submits
update_state(rpc, secret, new_state_hash, fee)         # reads the nonce, then submits
balance(rpc, account_id) / status(rpc) / block(rpc, height|id) / transaction(rpc, txid)
```

The RPC is unauthenticated by design in v1: it binds to loopback only, and the operator must keep it
that way. Binding it to a public interface is out of scope and unsafe.

## 20. CLI

The binary is `vess` (crate `vess-node`). Every command either opens the data directory for its own
duration or talks to a running node with `--rpc HOST:PORT`.

```text
vess node init    --datadir DIR [--network devnet|testnet|mainnet]
vess node run     --datadir DIR [--network ...] [--rpc PORT] [--port P2P] [--peer A,B] [--seed A,B]
                  [--mine --payout HEX] [--prune-blocks N] [--prune-headers N] [--trust-snapshot]
vess node params  [--network devnet|testnet|mainnet]
vess node status  --datadir DIR | --rpc HOST:PORT
vess node block   --rpc HOST:PORT (--height N | --id HEX)
vess node tx      --rpc HOST:PORT --id HEX
vess node account --rpc HOST:PORT --account HEX
vess node proof   --rpc HOST:PORT --account HEX
vess node watch   --rpc HOST:PORT [--count N] [--timeout MS]

vess wallet new        --datadir DIR --name NAME [--legacy]
vess wallet addresses  --datadir DIR --name NAME [--count N]
vess wallet address    --datadir DIR --name NAME [--index N] | --public-key HEX
vess wallet balance    --datadir DIR --name NAME [--index N] [--rpc ADDR]
vess wallet send       --datadir DIR --name NAME --to HEX --amount N [--fee N] [--index N] [--rpc ADDR]
vess wallet set-state  --datadir DIR --name NAME --state-hash HEX [--fee N] [--index N] [--rpc ADDR]
vess wallet watch      --datadir DIR --name NAME --rpc ADDR [--count N] [--timeout MS]

vess miner --datadir DIR --payout HEX [--blocks N] [--rpc ADDR]
```

All output is `key=value` text. Nothing is JSON.

## 21. Crates and dependencies

```text
vess-core        constants, codec, U256, domain hashes, consensus types, operator params
vess-emission    reward(network, target)
vess-crypto      ML-DSA-65 adapter
vess-state       sparse Merkle tree, accounts, transition rules, undo logs
vess-consensus   header rules, target, MTP, fork choice, template, mining, block validation
vess-storage     redb schema, atomic commit, indices, pruning, snapshots
vess-mempool     admission policy and template selection
vess-net         frames, handshake, RPC codec
vess-wallet      keys, signing, RPC client
vess-node        node service, P2P sessions, RPC server, CLI
```

Seven direct dependencies, and nothing else:

| Crate | Why it is here |
|---|---|
| `blake3` | The consensus hash, and the PoW. SIMD-dispatched, hand-writing it would be a correctness risk. |
| `ml-dsa` | ML-DSA-65 signing. The project may not invent a signature scheme. **Not independently audited.** |
| `getrandom` | OS entropy for keys. Platform-specific, and a hand-rolled path would be a security bug. |
| `redb` | ACID embedded storage; one write transaction per block. |
| `snow` | Noise_XX for the encrypted transport. A hand-written handshake fails silently and insecurely. Pulls `ring` transitively — the one C dependency, accepted rather than hand-rolling an AKE. |
| `argon2` | Argon2id for wallet keyfiles. |
| `chacha20poly1305` | AEAD for wallet keyfiles. |

Deliberately absent: `serde`/JSON anywhere, an async runtime, `clap`, `hex`, a BigInt crate, any
solver crate, and any TLS stack.

## 22. Testing

- `vess-core`: codec round trips and every decoder corruption path; `U256` arithmetic and limb order;
  header layout; target bounds; the printable parameter table.
- `vess-emission`: reward at, above, and below genesis difficulty; per-hash invariance across a wide
  difficulty range; the clamp; a zero target; the dev-fee split floors and never changes total
  issuance.
- `vess-state`: transfers, nonces, expiry boundaries, overdraft, fee routing, state updates, undo
  round trips through storage, proof inclusion and non-inclusion, total-supply accounting.
- `vess-consensus`: genesis identity, empty-block reward, reward proportional to target, the 1% dev
  split at a 128-unit reward, no dev account below 100 units, fork choice, retarget properties and
  adversarial timestamps, MTP bounds, duplicate transactions, tx-root and state-root mismatches.
- `vess-storage`: commit and reopen, crash recovery, pruning windows, undo round trip, snapshot
  install.
- `vess-mempool`: per-account policy, fee replacement, eviction order, expiry, selection.
- `vess-net`: frame checksums, truncation, handshake rejection, snapshot frame round trip.
- `vess-node`: end-to-end mine/persist/reopen, transfer over RPC, reorgs across three nodes, compact
  block relay, snapshot sync, garbage on the wire, lookup by height/id/transaction.

### 22.1 What is deliberately not tested

- Nothing benchmarks hashrate. BLAKE3 throughput on the build machine is not a chain property.
- No test asserts a specific mining time; devnet's target is chosen so a block is found in
  milliseconds, and `mine(20_000_000)` nonce attempts is the bound tests rely on.

## 23. Scope boundaries (documented, not hidden)

- **No scarcity.** Supply is unbounded and grows with work (§13.2). Anyone wanting a store of value
  should not use this chain.
- **No ASIC resistance.** Accepted deliberately (§8.3).
- **No privacy.** Amounts, senders, and recipients are public; there is no shielded pool.
- **No smart contracts.** `state_hash` is an opaque 32-byte commitment; consensus never interprets it.
- **No key rotation.** An account is bound to one ML-DSA public key for the life of the chain.
- **No light clients.** Headers commit to a state root, and proofs exist, but no client implements
  header-only verification yet.
- **No automatic checkpointing.** The mechanism exists and is enforced (§11.9), and the per-network
  seed lists and ban file are in place, but every network ships an empty checkpoint list, so a node
  that syncs from scratch still accepts whichever valid history it is shown first. Filling those
  lists is an operator decision that needs a chain to exist first.
- **No RPC authentication.** Loopback only, by design. There is also no push subscription: a client
  that wants to follow an account uses `WAIT_FOR_TIP` (§19) and re-reads the account, which costs one
  round trip per block and no server-side state.
- **State snapshots across a gap trust the peer.** A snapshot is only accepted when its anchor is a
  block we validated ourselves; adopting one across a gap needs `--trust-snapshot`, because the
  built-in checkpoint lists are still empty (§16.2, §11.9).
- **First contact is still trust on first use.** Once an address has been verified its key is pinned
  (§18.5) and a different key at that address is refused, but the *first* connection to an address
  can still be machine-in-the-middled. Pinning shrinks that from a permanent window to a one-time
  one. RPC remains plaintext, but the binary binds it to `127.0.0.1` and takes only a port, so it
  cannot be exposed by accident.
- **The ML-DSA implementation is not independently audited.** It is the one dependency whose
  correctness this design cannot verify, and it sits under every signature on the chain.

## 24. Launch checklist

1. Freeze `genesis_timestamp` and `genesis_target` per network; changing either changes the genesis
   block id and every balance that depends on it.
2. Check `MAX_BLOCK_REWARD` is above `GENESIS_REWARD * MAXIMUM_TARGET / MINIMUM_TARGET`, or the clamp,
   not the target, sets emission at the top end.
3. Confirm the key behind `DEV_FEE_ACCOUNT` is backed up and untracked (`.gitignore` covers
   `/.vess-keys/` and `*.key`). Losing it strands every fee; leaking it hands them over.
4. Decide the long-range-attack stance (§23): checkpoints in the binary, or accept a from-scratch sync
   that trusts the heaviest chain it hears.
5. Have the ML-DSA dependency audited, or write down the acceptance.
