# Vess V1 Protocol Scope

This document freezes the intended V1 shape of Vess around the code that exists today. It is a scope and invariants document, not a marketing wishlist.

## Core Model

- Bitcoin is the reserve asset and issuance root.
- Vess is a one-way upgrade path from Bitcoin UTXOs into private bearer bills.
- Vess does not use a global blockchain for transfer ordering.
- Ownership changes are represented by `OwnershipGenesis` and `OwnershipClaim` records.
- Deterministic replicated registries, not chain consensus, decide accepted ownership state.
- Programs are passive stateless covenants that validate bill transitions.
- Program interaction is self-submitted by the claimant or wallet handling that bill transition.
- V1 does not include delegated compute markets, remote worker execution, or mutable on-program storage.

## V1 In Scope

### 1. Bitcoin-anchored issuance

V1 supports onboarding from Bitcoin into Vess by detecting wallet-controlled Bitcoin funds, burning those UTXOs, and deriving canonical Vess bills from the burn commitment.

Required protocol objects:

- `BitcoinBurnBundleProof`
- `OwnershipGenesis`
- canonical bill decomposition tied to the burn payload

V1 expectation:

- 1 sat burned maps to 1 Vess issued.
- The burn is one-way.
- Nodes accept issuance only when the burn proof, committed payload, and generated genesis set agree exactly.

### 2. Ownership and transfer

Every Vess bill has a stable `mint_id` and an ownership chain tracked by deterministic registry state.

Ownership transitions are carried by:

- `OwnershipGenesis` for first ownership
- `OwnershipClaim` for every later rotation

V1 expectation:

- Only one current owner exists for a given `mint_id` at any accepted chain tip.
- `chain_depth` advances monotonically along the accepted claim chain.
- Claims are content-addressed, replicated, and validated consistently across nodes.

### 3. Wallet-mediated payments

Payments are proposed privately and finalized when the recipient submits the appropriate `OwnershipClaim`.

V1 expectation:

- A sender does not irrevocably lose control until the recipient-side ownership claim is accepted.
- Wallet persistence must preserve enough encrypted state to resume ownership, claim construction, and receive detection after restart.

### 4. Tags and discovery

V1 includes human-facing VessTags and program names published through the DHT.

V1 expectation:

- Tags resolve to recipient identity material.
- Program names are canonicalized and keyed by the Blake3 hash of the canonical name.
- Claiming a tag requires anti-abuse work.

### 5. Stateless covenants

Programs in V1 are deployed manifests plus program bytes that define passive validation rules.

V1 expectation:

- Bills may rotate into program ownership through an `OwnershipClaim` aimed at `new_owner_program`.
- Bills may rotate out of program ownership through an `OwnershipClaim` carrying `prev_owner_program` plus witness material such as `program_spend_witness`.
- Validation happens on the claim path.
- Mutable state belongs to the bill's `state_commitment`, not to the deployed program.
- Any proof generation is performed by the party constructing the claim for itself, not by remote execution infrastructure.

## V1 Explicitly Out Of Scope

- delegated compute or worker markets
- arbitrary remote execution of programs on mesh peers
- mutable contract storage hosted by the network
- a Vess blockchain or miner/validator ordering layer
- two-way Bitcoin peg redemption
- aspirational features not represented by current protocol objects and tests

## Registry And Validation Invariants

These are the production invariants that matter more than feature count.

### Bitcoin issuance invariants

- A `BitcoinBurnBundleProof` must bind the exact bill decomposition and first-owner commitment accepted by the resulting `OwnershipGenesis` set.
- Burn acceptance must be stable under reorg handling rules and explicit confirmation thresholds.
- Duplicate acceptance of the same burn payload must be impossible.
- Invalid or ambiguous proof bundles must fail closed.

### Ownership invariants

- For each `mint_id`, accepted ownership history forms a single monotonic chain.
- Conflicting claims must resolve deterministically under concurrency.
- Partition healing must converge to the same accepted owner when nodes exchange the same validated claim set.
- Program-owned transitions must validate the same ownership rules as key-owned transitions, plus program witness checks.

### Wallet persistence invariants

- Restarting a node must not silently drop spend authority, receive detection state, or ownership history needed for recovery.
- Sensitive wallet material at rest must remain encrypted behind the wallet unlock path.
- State migrations must be versioned and fail safely.

### Network abuse invariants

- Tag claims, program deploys, and other public DHT writes must remain rate-limited or work-gated.
- Nodes should reject malformed, oversized, or replayed ownership and manifest traffic before expensive work.
- Verification cost asymmetry should favor defenders.

## Protocol Notes On Program Execution

The current wire schema still contains `ComputeJobRequest` and `ComputeJobResult` message types. For V1 they are reserved compatibility surfaces, not supported remote execution behavior.

V1 rule:

- artery nodes do not execute delegated jobs for peers
- program interaction is performed locally by the wallet or node constructing its own ownership transition
- the network verifies resulting witnesses and receipts when those are attached to ownership claims or receipt distribution flows

## Implementation Alignment Work

The codebase should continue narrowing toward these truths:

1. README and user-facing docs must describe self-submitted covenant validation, not worker-based compute.
2. Bitcoin burn validation must gain explicit invariants and focused tests around `BitcoinBurnBundleProof`.
3. Ownership registries must be tested under concurrency and partition healing, especially around competing claims.
4. Wallet persistence must gain migration/versioning guarantees and restart recovery coverage.
5. Node observability must surface issuance, claim acceptance, registry conflicts, burn verification failures, and storage migration events.

## Acceptance Standard For V1 Claims

If a feature is described as part of V1, at least one of the following should already exist in the repository:

- a protocol type used by runtime code
- runtime validation logic
- integration coverage
- explicit documentation in this file and the README

If it is not implemented or validated, it should be described as future work rather than present capability.