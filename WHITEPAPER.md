# Vess — a currency that fights back

**Version 0.1 (pre-mainnet, living document).** This paper describes the design
as implemented. Where the design has sharp edges, they are described here, not
hidden. If a claim in this document cannot be traced to the code, that is a
bug in this document.

---

## 1. The mechanism

Vess is a UTXO payment network with one rule that most of the last two decades
of cryptocurrency engineering exists to avoid:

> **If two payments spend the same coin, both payments die. All inputs are
> destroyed. No outputs are created. The coins cease to exist.**

Every other system resolves a double-spend by *ordering*: miners, validators,
or voters politely decide which of the two conflicting spends is the "real"
one, and the loser is discarded at no cost to the attacker. The entire
apparatus of fees, mempools, block templates, and reorg handling is, at root,
machinery for being polite to adversaries — and it is paid for by honest
users in fees, throughput, and state bloat.

Vess declines to be polite. A conflict is not a race to be judged but an
attack to be punished, and the punishment is automatic, deterministic, and
lands entirely on the attacker: the value they tried to spend twice is the
value that burns. Consensus no longer needs to resolve conflicts at all —
only to agree on a growing set of unspent coins, which is a much smaller
problem.

Three consequences fall out of this single rule:

- **No fees.** There is no ordering contention to price. Payments are
  included because including them costs nothing. (What replaces the fee
  market as an anti-spam measure is covered in §4 and §6 — honestly,
  including where it is weaker.)
- **Finality at block inclusion.** A payment is either in a block or it is
  nothing. There is no mempool purgatory, no replace-by-fee, no
  zero-conf sociology.
- **The penalty budget points the right way.** In every fee-based system,
  attacking the network costs the attacker *fees* and costs everyone else
  *the attack's externalities*. In Vess, a failed double-spend destroys the
  attacker's own coins and nothing of anyone else's.

The protocol built on this rule has a name: **DAGARC — a directed acyclic
graph, armored by retributive consensus.** The DAG carries the blocks;
retribution keeps them honest; no ordering apparatus is required anywhere.
The rest of this paper is the engineering required to make that one rule
sound, and a plain statement of the risks it creates.

---

## 2. Threat model and incentive analysis

A consensus mechanism is its answers to "who profits from what." Here are
Vess's answers, including the ones that are merely good, not perfect.

### 2.1 The double-spend for profit — dead

Alice pays Bob 100 Vess for goods, then broadcasts a conflicting spend of the
same coins back to herself. Both payments are individually valid: correct
signatures, correct owner binding, correct sums. A miner includes both in a
block as burn evidence. The block is valid; the 100 Vess are destroyed; Bob
receives nothing; Alice does not receive the coins back — they no longer
exist.

Alice's best-case outcome is identical to having simply paid. Her worst case
is losing the coins and getting nothing. The strategy is strictly dominated
by honesty.

### 2.2 The claim-latency clawback — the real rule

There is one window where the double-spend is not free for the attacker: the
time between handing over a signed payment blob and the receiver's claim
being included in a block. During that window, Alice can conflict the payment
after Bob has already shipped. Burning costs Alice nothing *extra* — the
coins were already spent from her perspective. She ends with the goods; Bob
ends with nothing.

This leads to the only usability rule Vess actually imposes:

> **A signed blob is a promise, not a settlement. Never deliver value before
> inclusion.**

At a ~1 second block target, "wait for inclusion" is a pause, not a delay.
But be precise about what this means: a receiver can *verify* a blob fully
offline (signatures, owner binding, sums) but cannot rule out a double-spend
offline. No bearer design escapes this; Vess simply refuses to lie about it.

### 2.3 Sabotage is cheap but bounded

Vaporization makes *theft* self-defeating. It does not make *sabotage*
expensive. An attacker can burn their own dust to:

- keep their own payment to a merchant permanently contested (clawing back
  a purchase, §2.2 — closed by waiting for inclusion);
- wedge miners' mempools with contested payments (closed by contested
  payments being *minable as burn evidence* — the attacker's coins burn and
  the attack self-terminates);
- spam volume (bounded by per-peer rate limits, bounded mempools with TTL
  eviction, PoW-gated handshakes, and hard caps of 5 inputs / 5 outputs per
  payment — but there is no fee to outbid, so this defense is engineering,
  not economics, and it is honestly weaker than a fee market here).

What the attacker *cannot* do is burn anyone else's coins. Spending requires
a signature from the key whose hash is committed in the output (`owner_hash`
is checked against the signing key at validation). The attack surface of
vaporization is confined to what the attacker owns.

### 2.4 The backup question

Vess has no seed phrases. Each UTXO has its own independent ML-DSA-65
keypair; the wallet file stores the 32-byte seeds, encrypted (Argon2id
64 MiB/3/1 + ChaCha20-Poly1305). The wallet file is the money. This is
deliberate: no phrase to photograph, no derivation to scan, cold storage is
a file copy.

The residual hazard is the unconfirmed window (~1 second at target, up to
the ~60 s mempool TTL in pathological cases): if you export a payment blob
the receiver has not claimed yet, or run the same wallet file live on two
machines at once, two valid spends of the same inputs can coexist in limbo,
meet in a block, and burn your own coins. The defenses are wallet-level and
already implemented: exported inputs are locked as pending until the
network confirms them gone, and re-signing them is refused. The operational
rule is one sentence: **one wallet file, one live instance — and after any
restore, sync before you spend.** (Sync asks the network which of your
outputs still exist, which collapses the window to nothing.)

### 2.5 Nothing at stake

Fork choice is heaviest-chain by cumulative work (Σ 2^difficulty_bits per
block), ties broken deterministically by lowest block hash. Building a
private competing chain requires real Cuckatoo work per block; a private
low-difficulty chain cannot overtake an honest higher-difficulty one, and
the difficulty schedule is consensus-enforced (a block's declared difficulty
must match the deterministic DAA value), so difficulty cannot be declared
away. Vaporization does not interact with forks: burns are block contents
and follow the canonical chain like any other state transition.

### 2.6 Empty blocks — the goodwill equilibrium, stated plainly

Miner reward pays for *work*, not for *inclusion*. A strictly rational miner
could mine empty blocks: identical reward, marginally faster propagation,
slightly lower orphan risk. There is no fee revenue to counterweight this,
and at 1-second blocks the propagation margin is real.

The counterweights are: (a) default software includes everything, and
defecting requires caring enough to run modified software for a marginal
edge; (b) validation and inclusion are cheap relative to the ~1.3 GB
memory-hard solve that dominates mining cost; (c) vaporization means an
empty-block policy cannot censor a payment *profitably* — only delay it.
Bitcoin itself ran on unpaid inclusion for its first years.

---

## 3. Consensus

**Blocks** carry: parent hashes (1–8), timestamp, declared
difficulty, payment merkle, **state merkle**, coinbase, payments, and a
Cuckatoo27 proof.

**DAGARC is a DAG that merges, not a chain that orphans.** A block references every
live tip it knows: the heaviest first (that edge is the DAA spine), then
the rest, up to eight. A block's work is the sum over its entire ancestor
set, each ancestor counted once — so when two miners race in the same
second, the next block references both, **both coinbases pay, and no work
is ever orphaned**. The tree of tips collapses back to one tip at the
merge. This is deliberately the lightest DAG that can exist: no ordering
auction, no scoring, no cluster analysis. Kaspa needs GHOSTDAG's machinery
because its conflict rule is "pick a winner," and picking winners across
branches requires judging. Vess's conflict rule is "both burn," computable
from the payments alone — so a merge is just: gather the ancestor set,
order it deterministically (topological, ties by hash), dedup payments,
compute conflicts over the union, apply. When the judge is fired, the
courthouse is a closet.

**Merge semantics — three kinds of payments.** Over a merged ancestor set a
payment is *clean* (applies normally), *conflicted* (shares an input with
another payment anywhere in the union — both burn, no outputs), or *voided*
(spends an output of a conflicted or voided payment — contributes nothing,
and its other inputs are **not** burned: bystanders are unwound, never
punished). The same payment riding two branches applies exactly once. Every
ancestor coinbase pays. And branch-hopping a double-spend — one spend on
each of two racing branches, hoping one "wins" — simply does not work: the
branches merge, and the union burns both. Finality guidance sharpens
accordingly: small amounts, one block is enough; serious amounts, wait for
merge depth — your block referenced by a few later merges, so no unseen
branch carrying a conflict can still be united with yours.

**The state merkle is the consensus backbone.** Every block commits to the
root of the entire post-transition UTXO set. Every node recomputes the
deterministic transition — apply coinbase, apply clean payments, burn
conflicted inputs — and rejects the block if the roots differ. State
application is specified identically in the miner, the validator, the reorg
replay, and restart recovery, so the commitment cannot diverge across
implementations of the same code.

**Payments** are fully validated individually whether or not they are
conflicted: canonical payment id, input sum == output sum (feeless means
exact), per-input ML-DSA-65 signature, owner binding, and
spend conditions (§5). Then: clean payments apply; conflicted payments'
inputs burn.

**Chained spends do not exist.** Every input must reference pre-block
state — a confirmed UTXO. You cannot spend the output of a payment that is
in the same block or still in the mempool. This deletes an entire class of
problems at one stroke: no in-block ordering dependence (payments in a block
are order-independent), no cascade invalidation, no chain-stuffing spam, no
topological sorting in block construction. The cost is waiting ~1 second
for a parent to confirm before spending its output. That is a good trade
and this paper recommends other small chains copy it.

**DAA.** Difficulty retargets every 40 blocks via an average of recent block
deltas toward a 1000 ms target. Over a DAG there is no unique "recent
chain," so deltas are taken along the spine — the chain of first (heaviest)
parents — which every block commits to by construction. The width of the
DAG is not the DAA's business; widening it would let merge behavior feed
back into the difficulty schedule, which is an oscillator nobody needs.

**The UTXO set is opaque.** On-disk and in sync, the set is bare 32-byte
ids — hashes committing to amount, owner, and salt, revealing none of them.
Amounts and owner hashes are public *in block contents* (they must be, for
validation), but the standing set itself carries no amounts, no keys, no
scripts. It is small, syncs fast, and tells a disk-level observer nothing.

---

## 4. Economics

What Vess actually has is an issuance rule
*elastic to measured work*:

```
reward(bits) = 2^(bits - 8) Vess        # 1 Vess at base difficulty 8
```

Difficulty floats with hashpower toward 1 block/second. So issuance tracks
work: the marginal Vess costs the marginal joule *at the current difficulty*,
always, with no schedule, no halving, no premine, and no foundation wallet.
Two properties follow, and they are the actual economics of the system:

- **Supply is elastic, on purpose.** More hashpower → higher difficulty →
  more issuance per block. A popular network expands; an abandoned one
  deflates to a trickle. This is the opposite of scarcity theater, and it
  is the point: Vess is engineered to be *spent*, at a stable marginal cost
  of production, like a commodity — not hoarded, like a collectible. If you
  want number-go-up tokenomics, every other chain already sells them.
- **Hoarding has no protocol subsidy.** There is no fixed supply to
  speculate against. Velocity is the design goal. A currency that circulates is a payment network; a currency that doesn't is a glorified Ponzi.

**Supply growth is not dilution when it is bought.** Dilution is new units
appearing at near-zero cost — seigniorage, premines, foundation unlocks —
where the issuer pockets the gap between price and a production cost of
nil, and holders pay it. Vess issuance is production, not printing: the
reward doubles exactly when the difficulty doubles, so the marginal Vess
always costs the same amount of expected work, at any hashrate. Every new
coin entering circulation was *paid for* at full energy rates by the miner
who minted it, at the same marginal rate as every coin before it. Supply
expands only as fast as the world is willing to burn real energy to expand
it — the discipline that keeps copper and gold supply growth honest,
enforced by arithmetic instead of geology. One caveat, because this paper
doesn't hide them: a cost-of-production floor disciplines *issuance*, not
price. If demand vanishes, production throttles down with hashpower — the
floor props nothing up, and it isn't meant to. What it guarantees is
narrower and sufficient: no one, anywhere, gets new Vess for free.

**No fee market.** Fees in other systems do two jobs: anti-spam and
ordering contention. Vess has no ordering contention (§1). Anti-spam is
handled by engineering: rate limits, bounded mempools, PoW-gated
handshakes, small payment caps. This is honestly weaker than fees against a
well-funded volumetric attacker, and the testnet exists to find out how much
weaker (§8). What Vess gets in return is the property that a payment of
any size costs exactly zero to send — which is the entire point of a payment
network and something no fee market has ever delivered.

**Dev subsidy.** 1% of each block reward, **minimum 1 Vess**, to a hardcoded
dev key. Read that again: at base difficulty the block reward is 1 Vess, so
the floor binds and the dev share of early issuance is 50%, decaying toward
1% as difficulty rises past ~15 bits (reward ≥ 100). The floor exists so
development is funded from block one rather than never; the tradeoff is
that early issuance is dev-heavy. It is stated here plainly because it is
consensus and you should evaluate it with open eyes. No premine, no ICO, no
VC — this subsidy is the entire insider allocation the network will ever
have, and it is paid continuously for ongoing work rather than upfront for
showing up early.

---

## 5. Spend conditions

Every output can carry two optional, composable constraints, set by the
payer and enforced by consensus:

- **Hashlock.** The output is spendable only by revealing a preimage whose
  Blake3 hash matches the lock. This is the atomic-swap primitive: two
  parties fund outputs locked to the same hash on two chains; whoever
  claims first reveals the secret and lets the other claim.
- **Expiry.** The output is spendable only before a UNIX timestamp; after
  that it is permanently dead, even with the right key and preimage.
  Payment channels with deadlines, offer windows, time-bounded escrow.

No script language. Two constraints, each one line of validation, covering
the use cases that account for nearly all actual script usage in the wild.
The last decade of on-chain scripting produced mostly hacks reimplementing
these two ideas at ten thousand times the complexity budget.

---

## 6. Architecture

**Post-quantum by default, not by roadmap.** Signatures are ML-DSA-65
(FIPS 204); session key establishment is ML-KEM-512 (FIPS 203); hashing is
Blake3 with domain-separated tags. There is no classical-crypto fallback to
downgrade to. Harvest-now-decrypt-later is not a future problem; it is the
current one, and chains that plan to "add PQ later" are planning to fail
later.

**One-time keys per UTXO.** Every output has its own fresh keypair. Nothing
is reused, so there is nothing to link: no address clustering, no change
analysis beyond what public amounts permit (§7). Keys are 32-byte seeds in
an encrypted wallet file; there is no BIP39, no derivation paths, no gap
limits, no chain scanning. The seed-phrase era's greatest hits — photographed
phrases, reused addresses, "watch-only" xpub leaks — are all simply absent.

**Out-of-band transport.** A payment is a signed blob. It travels from payer
to payee over any carrier — QR, NFC, Signal, paper, carrier pigeon with
good handwriting — and touches the network exactly once, when the receiver
claims it. The network cannot observe payment-graph formation, only claims;
claims propagate under Dandelion stem/fluff relay. This is not a privacy
overlay; it is the default and only path. You cannot eclipse a payment that
never enters the mesh, and you cannot DDoS a mempool the payer doesn't use.

**Network layer.** UDP with application-level fragmentation (1 MB cap) and
ACK-based reliability for large messages; mutually authenticated handshakes
(ML-KEM + ML-DSA signatures over the full transcript, bound to both
identities and a fresh handshake PoW); per-message AEAD with explicit
nonces; per-peer rate limits with persistent strike/ban scoring. NAT
traversal via introducer-assisted hole punching with relay fallback. Sync
is two mechanisms: block sync (orphan cache, fetch-missing-parents) for
recent history, and state sync for fast bootstrap — chunks are buffered,
the reconstructed root is checked against a peer quorum, and only then
committed atomically. Trusting one peer's word for the state was tried in
development; it worked exactly as poorly as you'd expect.

**Mining.** Cuckatoo27: find a 42-cycle in a 2^27-edge graph. ~1.3–1.4 GB of
RAM, single-threaded, microseconds to verify. Memory-hard by design —
the cost lives in RAM, not in ALUs, which is the least-worst ASIC
resistance anyone has honestly demonstrated. Proofs are canonical
(strictly ascending nonces), so one cycle yields exactly one valid proof
and the difficulty target cannot be ground by permutation. Difficulty is
consensus-enforced against the DAA schedule, not miner-declared; coinbase
amounts are consensus-enforced against the reward schedule, not
miner-declared. 

**Tiny codebase.** The full node, wallet, crypto, and network stack is on
the order of six thousand lines of Rust. Every line is load-bearing.
Auditability is a security feature; systems too large to read are
systems too large to trust, which describes essentially everything else in
production today.

---

## 7. Honest limitations

Collected in one place, so nobody has to take our word for any of it:

1. **Claim-latency (§2.2).** Receivers must wait for inclusion. Offline
   verification is real; offline finality is not.
2. **The unconfirmed window (§2.4).** Confirmed coins can't be burned by
   anyone, including you — a stale-backup spend of a confirmed coin is just
   rejected. But two live spends of the same unconfirmed input — an
   unclaimed exported blob, or the same wallet file run on two machines —
   will burn them. One wallet file, one live instance; sync before spending
   after a restore.
3. **Empty-block equilibrium (§2.6).** Inclusion is a social equilibrium.
   Measured on testnet; no cryptographic guarantee.
4. **Volumetric spam defense is engineering, not economics.** No fees means
   no economic friction against pure volume. Rate limits and bounded
   mempools are what exist; the testnet will show whether they suffice.
5. **Amounts are public.** One-time keys and OOB transport give unlinkable
   outputs and an invisible payment graph, but amounts in blocks are
   visible and amount correlation is possible during a temporary window. Vess offers surveillance
   *resistance*, not anonymity. If you need Zcash-grade hiding, use Zcash.
6. **1-second blocks are not free.** Fork races are constant at this
   interval; merges mean they cost bandwidth, not work, but large payments
   need merge depth before they're final (§3), and every merge widens the
   ancestor set validators must recompute. The tie-break, the seen-dedup
   relay, and the 8-parent cap exist because of it. The testnet measures
   the actual cost (§8).

---

## 8. The testnet is an experiment, not a marketing event

Novel mechanisms should not get to declare victory by launch. The testnet
pre-registers the following measurements, and the results — good or bad —
belong in the next version of this paper:

- **Vaporization events**: contested payments per day, burns executed,
  and whether any burn hits an honest user (target: zero).
- **DAG health**: tips in flight over time, average parents per block (the
  merge rate), and cross-branch burns vs. same-branch burns.
- **Void events**: payments unwound as daisy-chain dependents of a burn —
  and whether any void hits a payment with no other defect (target: only
  the double-spender burns; bystanders always recover their inputs).
- **Empty-block ratio** per identifiable miner, over time (the goodwill
  equilibrium, §2.6, measured rather than asserted).
- **Fork/merge rate** at the 1-second target, and DAA behavior under
  hashpower shocks.
- **Sync convergence**: time for a fresh node and for a node returning
  after N blocks of absence, including across induced partitions.
- **Spam resistance**: sustained volumetric load against rate limits and
  mempool bounds; what breaks first.
- **State growth**: LMDB size, sync chunk counts, and ancestor-set
  recompute cost as the DAG widens.

If the measurements contradict a claim in this paper, the claim gets
revised or retracted in the next version. That is the entire point of
running a testnet, and it is astonishing how rarely anyone actually does it.

---

## 9. Non-goals

Vess does not want your DeFi. It does not want to be your store of value,
your smart-contract platform, your governance token, your yield farm, or
your JPEG registry. It wants to be spent: mined, moved, accepted, and spent
again, at zero cost per payment, by machines and by people, on hardware you
already own, without asking anyone's permission.

A currency that circulates. Everything else is a different project.
