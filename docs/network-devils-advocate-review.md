# Vess Network Devil's-Advocate Review

Date: 2026-05-24

## Executive position

The current mesh migration is pointed in the right direction: Vess no longer treats an iroh endpoint as the root network identity, and the active transport is now a Vess-owned post-quantum mesh surface. The devil's-advocate position is that this is not yet enough for an adversarial public network.

The highest-risk areas are not the ML-KEM route handshake itself. They are the trust boundaries around it:

- who is allowed to publish contacts,
- how contacts are verified before they enter routing state,
- how one UDP socket correlates requests and responses,
- how seed and peer-exchange channels are prevented from becoming Sybil/DoS amplifiers,
- how Bitcoin burn confirmations are elevated from "observed by a peer" to sufficiently secure issuance evidence,
- how direct payment delivery proves it reached the intended recipient rather than merely a reachable node.

This document maps the current architecture, identifies critical flaws, lists implemented hardening from this review pass, and proposes next architecture changes.

## Current network map

```text
Wallet / CLI / RPC
  └─ vess-artery node runtime
       ├─ routing table and peer registry
       ├─ tag DHT and tag lookup
       ├─ limbo buffer and mailbox forwarding
       ├─ ownership registry and gossip
       ├─ Bitcoin light client + Vess seed side-channel
       └─ vess-vascular MeshPulseNode facade
            └─ vess-mesh PqUdpMeshCarrier
                 ├─ MeshCarrierContact
                 ├─ MeshAddress / MeshNodeId
                 ├─ ML-KEM route handshakes
                 ├─ direct UDP send/response
                 ├─ rendezvous helper
                 └─ relay helper
```

Payment identity and network identity are separate domains. Payment keys are stealth/DKSAP keys. Network keys are mesh scan/route keys. The dangerous places are where one domain is implicitly used to trust the other or where unauthenticated discovery data is promoted into routing state.

## Implemented hardening in this pass

1. **Mesh contacts are now self-validated before acceptance or dialing.**
   - A contact's `MeshNodeId` must match the node id derived from its published ML-KEM route keys.
   - Invalid socket addresses or malformed route keys are rejected.
   - Applied at the carrier layer and artery contact parse/decode helpers.

2. **Bitcoin-side Vess seed nodes are now validated before storage.**
   - A `VessSeedNode.node_id` must match the node id inside its serialized mesh contact.
   - Invalid or mismatched seed contacts are skipped.

3. **Mesh facade requests now have bounded timeouts.**
   - Direct mesh requests, raw pulse sends, rendezvous sends, relay sends, and registration attempts now fail instead of hanging indefinitely.

4. **Peer exchange responses are bounded.**
   - Serialized mesh contacts over discovery are capped by size.
   - Peer-exchange ingestion and responses are capped to keep UDP response size and memory amplification bounded.

5. **Public seed channels reject non-routable advertised contacts.**
   - Public DNS seed records and Bitcoin-side Vess seed exchange require globally routable socket addresses.
   - Local/LAN/test contacts remain allowed in explicit local contexts and direct user input.
   - Nodes skip Bitcoin seed advertisement when their local contact is wildcard, loopback, or private.

6. **Mesh contacts now have a compact binary codec.**
   - Routing-table bytes, peer exchange, DNS seed records, and CLI/node-info contact strings use compact binary contact encoding.
   - Legacy JSON contact decoding remains accepted for compatibility.

7. **Bitcoin burn confirmation now enforces stronger SPV checks before local issuance.**
   - Header ingestion validates expected retarget bits and cumulative chainwork growth.
   - Burn confirmation requires network-specific confirmation depth.
   - Burn proofs carry block height, confirmations, required confirmations, and chainwork metadata.
   - Artery-side burn genesis validation verifies the burn merkle branch and rejects insufficient confirmation/chainwork metadata.

8. **Direct payment acceptance now requires a recipient/tag-bound signed receipt.**
   - Direct senders bind the payment to the resolved tag hash.
   - Recipients sign a receipt over `payment_id`, tag hash, stealth id, accepted mint ids, and amount using the fresh owner key for the claimed bill.
   - Senders verify the receipt before withdrawing reserved bills permanently.

These are hardening steps, not a complete solution to all findings below.

## Critical and high-risk findings

### 1. Discovery channels can still become trust-amplification paths

**Devil's advocate attack:** DNS seeds, Bitcoin-side Vess seed discovery, and peer exchange all carry contacts that can influence future routing. Even with contact self-validation, an attacker can publish many valid attacker-owned contacts and become the easiest bootstrap path. Contact validation prevents key/ID spoofing, but not Sybil dominance.

**Impact:** New or recovering nodes can land mostly on attacker infrastructure. The attacker may not decrypt payment payloads, but can censor, delay, eclipse, surveil timing, and feed biased routing/tag answers.

**Implemented partial solution:** Public seed channels now reject non-routable contacts and nodes skip public Bitcoin seed advertisement when only a local/wildcard contact is available.

**Remaining solutions:**

- Introduce a signed `PeerRecord`:

```text
PeerRecord {
  node_id,
  mesh_address,
  contacts,
  epoch,
  expires_at,
  capabilities,
  signature_or_node_proof,
}
```

- Require every discovery source to carry `PeerRecord`, not raw contacts.
- Score discovery by source class:
  - hardcoded/bootstrap seed,
  - DNSSEC or pinned DNS seed key,
  - Bitcoin side-channel,
  - peer exchange,
  - locally observed successful sessions.
- Reject sudden contact churn for an existing `node_id` unless signed by the same node identity or backed by a fresh handshake.
- Keep separate quotas per discovery source so one channel cannot dominate the routing table.

### 2. Nodes may advertise non-routable wildcard contacts

**Devil's advocate attack:** A node can bind to `0.0.0.0:0` and publish the resulting socket address as its contact. That address is useful for listening locally but is not a routable remote contact. If this gets into DNS, peer exchange, or Bitcoin-side seed discovery, other peers waste bootstrap attempts and the mesh appears dead.

**Impact:** Network bootstrapping works in local tests but fails or degrades on real public networks without rendezvous/relay observed-address publishing.

**Implemented partial solution:** public discovery paths now reject wildcard, loopback, private, link-local, multicast, documentation, and other non-routable contacts. Nodes skip Bitcoin-side seed publication when their local contact is not publicly routable.

**Remaining solutions:**

- Split bind address from advertised address in the transport API.
- Promote rendezvous-observed addresses into contacts only after a successful return-path proof.
- Represent contacts as a list of scoped endpoints:

```text
ContactEndpoint {
  addr,
  scope: Local | Lan | Public | Relay | RendezvousObserved,
  observed_by,
  observed_at,
}
```

### 3. UDP request/response needs a demultiplexing session layer

**Devil's advocate attack:** A shared UDP socket that performs request/response directly can consume unrelated packets when multiple operations run concurrently. A malicious peer can also send unexpected packets that cause a request path to fail or waste work.

**Impact:** Race conditions, dropped responses, hangs without timeout, and brittle behavior under concurrent bootstrap/gossip/direct-payment load.

**Implemented partial solution:** facade-level request timeouts now prevent indefinite hangs.

**Full solution:**

- Add explicit `request_id` / `session_id` to every packet.
- Run one socket event loop that owns `recv_from`.
- Route packets to pending requests by `(peer_addr, node_id, request_id)`.
- Maintain a replay cache for recent handshakes and encrypted frames.
- Use nonce/counter-based AEAD frames for future multi-message sessions.

### 4. Peer exchange remains expensive because contacts are JSON-encoded

**Devil's advocate attack:** Even valid contacts are large because KEM public keys are serialized as JSON byte arrays. Returning many contacts can exceed UDP frame limits or become a CPU/memory amplifier.

**Implemented solution:** contacts now have a compact binary encoding, peer exchange uses compact bytes, and oversized responses remain capped.

**Remaining solution:**

- Add a protocol-level `MAX_PULSE_SIZE` and message-specific validation in `PulseMessage::from_bytes_checked`.
- Return only contact hashes in peer exchange, then fetch full contact records separately with rate limiting.
- Chunk large discovery responses over a session layer rather than one UDP response packet.

### 5. Bitcoin burn confirmation is not yet strong enough issuance security

**Devil's advocate attack:** A malicious Bitcoin peer can feed a node a weak or isolated header/block view. The current light-client path checks header PoW and block merkle roots, but the issuance path needs chainwork, confirmation depth, retarget validation, and multi-peer agreement before minting Vess from a burn.

**Impact:** If a node accepts insufficient SPV evidence, an attacker can attempt false or short-lived burn confirmations that produce Vess genesis records before the burn is economically final.

**Implemented partial solution:** the Bitcoin light client validates retarget transitions for the active header chain, tracks cumulative chainwork, waits for network-specific confirmation depth, and includes confirmation metadata in burn proofs. Artery verifies the burn merkle branch and rejects burn proofs without sufficient confirmation/chainwork metadata.

**Remaining solutions:**

- Require block/header agreement from multiple peers before accepting a burn proof.
- Pin network configuration explicitly: mainnet/testnet/signet/regtest must be a node config value, not hidden default behavior.
- Treat Bitcoin burn proof verification as its own hardened subsystem with persistent header state.

### 6. Direct payment acceptance is not bound tightly enough to recipient identity

**Devil's advocate attack:** A direct send currently targets a mesh contact or cached node id while the payment is encrypted to a tag-derived stealth address. A malicious or stale contact can return an acceptance response even if it is not the intended recipient. The payment encryption still protects bill contents, but UX may treat reachability/acceptance as final delivery.

**Impact:** Confusing or false delivery confirmation, possible sender-side reservation/withdrawal mistakes if later logic regresses, and poor recipient authentication semantics.

**Implemented partial solution:** direct payments now request a signed recipient receipt bound to the resolved tag hash, recipient stealth id, accepted mint ids, and amount; senders verify it before final withdrawal.

**Remaining solutions:**

- Bind recipient tag records to authorized mesh delivery contacts.
- Extend `DirectPaymentResponse` receipts to include the target mesh node id once tag-to-delivery-contact binding exists:

```text
payment_id || recipient_stealth_id || target_mesh_node_id || accepted_mint_ids || timestamp
```

- Verify that the receipt key is linked to the recipient's tag or stealth address before withdrawing/reserving state permanently.
- Keep current timeout release behavior and add an explicit pending-delivery state for uncertain direct sends.

### 7. Registry query and tag lookup are metadata oracles

**Devil's advocate attack:** Registry queries reveal bill activity for caller-chosen mint IDs. Tag lookups reveal whether a human tag exists. Rate limits help but are peer-ID based, and peer IDs are cheap enough for a Sybil attacker.

**Impact:** Enumeration, timing surveillance, and targeted probing of ownership state or human names.

**Solutions:**

- Apply verified-peer gating to all metadata-sensitive queries.
- Add IP/subnet/source-channel rate limits in addition to node-id limits.
- Prefer DHT-nearest queries over arbitrary global queries.
- Consider batched/noisy responses or private set membership approaches for registry checks.
- Require tag lookup responses to carry and verify the original tag record signature.

### 8. Per-peer quotas do not equal per-attacker quotas

**Devil's advocate attack:** Limbo, mailbox, registry, and tag request limits are largely keyed by mesh peer identity. A Sybil attacker can create many mesh identities and distribute load.

**Impact:** Buffer exhaustion, CPU exhaustion, and denial of service while each individual identity appears under quota.

**Solutions:**

- Add source-IP/subnet quotas for direct paths.
- Add proof-of-work tickets for expensive messages.
- Add per-message-type global budgets.
- Track sender/payment cryptographic identifiers where available, not only relay node identity.
- Penalize discovery sources that repeatedly introduce abusive peers.

## Architecture changes recommended next

### A. Introduce a signed `PeerRecord` and make raw contacts non-authoritative

Raw `MeshCarrierContact` should be treated as a transport hint. A signed `PeerRecord` should be the authoritative network identity object. DNS, Bitcoin-side seeds, peer exchange, and persistence should all move to this one object.

### B. Replace direct socket reads with a mesh event loop

`PqUdpMeshCarrier` should own a single receive loop and demultiplex packets to pending requests, listeners, rendezvous handlers, and relay handlers. This removes request races and makes timeout/retry policy centralized.

### C. Separate public bootstrap, local discovery, and operational routing

Use explicit trust tiers:

```text
Tier 0: hardcoded/pinned bootstrap records
Tier 1: signed DNS seed records
Tier 2: locally successful peers
Tier 3: peer exchange candidates
Tier 4: unverified hints
```

Only promote peers upward after successful handshakes and useful behavior.

### D. Continue compact-contact discovery hardening

The compact binary `MeshCarrierContact` codec is now in place and used for routing bytes, peer exchange, DNS seed records, and CLI/node-info contact strings, with legacy JSON decode compatibility retained. The next step is to stop returning full contacts by default: exchange contact hashes, then fetch full signed records under rate limits.

### E. Finish Bitcoin-backed issuance as a separate verification service

The Bitcoin path now tracks chainwork, validates retarget transitions, requires confirmation depth, and carries finality metadata into burn-backed genesis proofs. The remaining architecture move is to split this into a dedicated burn-verifier module with persistent headers, explicit network configuration, and multi-peer disagreement handling. Artery should consume verified burn events, not raw light-client observations.

### F. Finish binding direct payment receipts to recipient identity

Direct payments now require a recipient-signed receipt bound to the resolved tag hash, stealth id, accepted mint ids, and amount before the sender withdraws reserved bills. The remaining work is to link tag records to authorized mesh delivery contacts and include the target mesh identity in the receipt once that tag/contact binding exists.

## Priority action list

1. Move discovery from raw contacts to signed `PeerRecord`.
2. Add mesh UDP request IDs and a central receive/demux task.
3. Add rendezvous-observed public contact publishing and signed public contact records.
4. Add multi-peer agreement and persistent headers to burn verification.
5. Make peer exchange fetch-by-hash on top of compact contacts.
6. Add per-IP/subnet and proof-of-work abuse budgets for expensive message classes.
7. Bind tag records to authorized delivery contacts and include target mesh identity in direct-payment receipts.

## Bottom line

The mesh now has a post-quantum identity layer, public-contact validation, compact contacts, stronger Bitcoin burn proof metadata, and recipient/tag-bound direct payment receipts. The public network is still only as strong as its discovery, address-publication, request-demux, and multi-peer burn-verification rules. The next major work should be signed peer records, proper UDP session demux, rendezvous-observed public contacts, and a dedicated persistent Bitcoin burn-verifier service.