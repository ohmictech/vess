# PQ-DKSAP Networking for Vess

Historical note: the migration described here is complete. Current Vess networking uses Vess-owned PQ mesh carriers in `vess-mesh`, surfaced through `MeshPulseNode`, rather than iroh or QUIC identities.

This note sketches the replacement path that moved Vess away from relying on an elliptic-curve transport identity underneath post-quantum payment cryptography.

## Problem

Vess payments already use post-quantum DKSAP-style stealth addressing: recipients publish ML-KEM encapsulation keys, senders create one-time shared secrets, and payment ownership is recovered by scanning and decapsulation.

If the transport layer still treats an elliptic-curve node handshake as the trusted network identity, the system has a mismatch:

- payment confidentiality is post-quantum,
- payment ownership is post-quantum,
- but peer authentication, routing identity, and channel establishment remain pre-quantum.

The target is not to make payment keys equal network keys. The target is to make payment delivery and network routing use compatible post-quantum, stealth-style primitives.

## Core idea

Use two layers:

1. **PQ service-node backbone**
   - Stable-ish post-quantum node identities for relays, DHT routing, storage, reputation, and peer accountability.
   - These identities are infrastructure identities, not wallet identities.

2. **DKSAP stealth delivery plane**
   - Wallets receive through one-time route coordinates derived from ML-KEM shared secrets.
   - Relays forward opaque capsules toward coordinates, not toward a public recipient node ID.
   - The actual receiver behaves like a relay after receiving, so observers cannot easily tell where the route terminated.

This keeps routing practical while avoiding permanent public wallet/network identity fusion.

## Carrier versus protocol

The proper long-term design was to make Vess networking a custom protocol layer, not an iroh identity layer.

Iroh was useful as a temporary carrier because it already provided UDP/QUIC plumbing, NAT traversal, relay behavior, streams, and address discovery. Vess no longer treats iroh's elliptic-curve endpoint ID or handshake as a root of trust.

Instead, Vess should define its own transport-independent network protocol:

```text
Vess network protocol
 ├─ PQ service-node authentication
 ├─ DKSAP stealth delivery capsules
 ├─ gradient routing rules
 ├─ atomic payment/network bindings
 ├─ anti-spam/postage rules
 └─ replay, expiry, padding, and cover-forwarding rules

Carrier layer
 ├─ iroh during transition
 ├─ quinn/QUIC later
 └─ custom UDP or relay transport later
```

Under this model, the carrier only moves bytes. The Vess protocol supplies identity, authentication, routing semantics, payment binding, and privacy behavior.

This gives a clean migration path:

1. First, run Vess PQ-DKSAP capsules over iroh as opaque payloads.
2. Then, remove all Vess trust decisions from `iroh::EndpointId`.
3. Finally, replace iroh with a PQ-native carrier without redesigning payments, routing, or wallet delivery.

This also keeps Vess from being trapped by any transport library's default assumptions. If iroh cannot expose enough handshake customization for full PQ identity and key exchange, Vess can keep the same network protocol and swap the carrier underneath it.

## Reusing iroh's lower-level building blocks

A practical middle path is to reuse the kinds of libraries iroh is built from, while not reusing iroh's node identity model as Vess trust.

In the current dependency graph, iroh pulls in pieces such as UDP/QUIC-style transport plumbing, relay support, DNS/address discovery, port mapping, rustls, pkarr, and its own base identity types. Vess can keep the useful operational pieces and replace the identity, handshake, and routing semantics.

Recommended split:

```text
Reuse or mirror from iroh ecosystem:
 ├─ UDP socket management
 ├─ QUIC-like stream multiplexing
 ├─ relay protocol patterns
 ├─ NAT traversal / port mapping
 ├─ address discovery
 ├─ DNS seed and pkarr-like publishing ideas
 └─ metrics and connection management patterns

Own inside Vess:
 ├─ PQ service-node identity
 ├─ PQ/hybrid channel establishment
 ├─ DKSAP route capsules
 ├─ gradient-routing decisions
 ├─ payment/network binding
 ├─ mailbox privacy model
 ├─ anti-spam/postage policy
 └─ peer trust and reputation
```

This avoids a full networking rewrite while still removing the bad dependency: trusting an elliptic-curve endpoint identity beneath PQ payments.

The migration shape should be:

1. **Use iroh directly as a carrier first.**
  - Fastest path.
  - Vess capsules are opaque payloads.
  - Iroh identity is treated as a contact hint only.

2. **Extract a Vess transport trait.**
  - `connect(contact) -> stream`
  - `accept() -> stream`
  - `publish_contact()`
  - `relay_send()` / `relay_fetch()`
  - no exposed `iroh::EndpointId` in protocol logic.

3. **Build a custom carrier using the same primitive categories.**
  - Keep QUIC/UDP, relay, discovery, and NAT traversal patterns.
  - Replace the handshake with Vess PQ authentication and ML-KEM/hybrid key exchange.
  - Keep packetization and stream behavior transport-friendly.

4. **Remove iroh when the custom carrier reaches feature parity.**
  - The DKSAP delivery plane and gradient-routing layer should not need changes.

This is better than forking iroh too early. Forking gives maximum control but also creates a permanent maintenance burden. A Vess transport abstraction lets the project first prove the PQ-DKSAP protocol over an existing carrier, then selectively replace pieces below it.

## Key separation

Derive separate key families from the wallet seed:

```text
wallet seed
 ├─ payment_scan_dk
 ├─ payment_spend_dk
 ├─ network_scan_dk
 ├─ network_route_dk
 ├─ mailbox_capability_keys
 └─ optional node_auth_signing_key
```

Rules:

- payment spend keys never authenticate the network daemon,
- network route keys never authorize spending,
- public service-node IDs are not wallet receive addresses,
- one-time route IDs are not stable node IDs.

## Network stealth address

A DKSAP network receive address can mirror the payment address shape while remaining independent:

```text
NetworkStealthAddress {
  network_scan_ek,
  network_route_ek,
  policy,
  epoch,
  optional_auth_key,
}
```

A sender encapsulates to both network keys:

```text
ct_scan,  ss_scan  = ML-KEM.encap(network_scan_ek)
ct_route, ss_route = ML-KEM.encap(network_route_ek)

view_tag    = first_byte(BLAKE3("vess-net-view-v1" || ss_scan))
route_id    = BLAKE3("vess-net-route-v1" || ss_scan || ss_route || epoch)
session_key = BLAKE3("vess-net-session-v1" || ss_scan || ss_route || transcript)
```

The relay network sees `route_id`, `view_tag`, expiry, size, and ciphertext. It does not see the wallet identity.

## Atomic payment/network binding

A payment should be accepted only when both the payment DKSAP context and network DKSAP context validate.

Example binding:

```text
binding = BLAKE3(
  "vess-dksap-atomic-v1" ||
  network_route_id ||
  payment_stealth_id ||
  hash(network_ciphertext) ||
  hash(payment_ciphertext) ||
  epoch
)
```

The receiver checks:

```text
valid network DKSAP open
valid payment DKSAP open
valid payment proof
valid binding
not replayed
not expired
```

This integrates networking and payment cryptography without making the network identity equal the spend identity.

## Gradient routing

Gradient routing means a node does not know the desired receiver. It only knows how to move a capsule closer to a routing coordinate.

There are three practical levels.

### Level 1: one-time coordinate routing

The capsule carries a full one-time `route_id`.

Each relay chooses a peer whose service-node ID is closer to `route_id` under a DHT metric such as XOR distance.

Relays know the coordinate but not the recipient, because `route_id` is a one-time DKSAP output rather than a public node ID.

This is the simplest and most deployable form.

### Level 2: prefix-gradient routing

The capsule carries only a partial prefix or distance-class hint, not the full route coordinate.

Each hop forwards toward a bucket that better matches the hint. Later hops may receive a more specific prefix, or the capsule may be replicated into a small target neighborhood.

This leaks less routing information but is less efficient and needs careful loop control.

### Level 3: source-assisted gradient layers

The sender wraps several encrypted routing hints. Each hop can open only the next hint and learns only a local direction.

This approaches onion routing, but the hints are directions or buckets rather than exact next-hop identities.

This gives stronger path privacy but requires more routing state and larger headers.

## Receiver relays after receive

To avoid making the receiver obvious, the recipient should not stop the capsule route when it successfully opens the payload.

Instead, after processing, it performs the same outward behavior expected of a non-recipient relay:

```text
receive capsule
try scan/open privately
schedule normal forward action
if opened successfully, still forward cover/dead-route capsule
```

The forward target can be a dead-drop coordinate inside the Vess DHT rather than a real DNS query. Public DNS should not be used for per-payment dead outputs because DNS resolvers would become metadata observers.

A dead output should be:

- internal to Vess,
- indistinguishable from ordinary forwarding,
- TTL-limited,
- expiry-limited,
- padded to normal sizes,
- optionally delayed and batched.

This makes receipt less distinguishable from transit.

## Capsule shape

A first version of the network capsule could be:

```text
GradientCapsule {
  version,
  epoch,
  ttl,
  route_hint,
  view_tag,
  ct_scan,
  ct_route,
  capsule_id,
  postage_or_rate_token,
  encrypted_payload,
  padding,
}
```

`encrypted_payload` can hold a payment envelope, mailbox-forward registration, receipt path, tag update, or other Vess message.

## Anti-spam and DoS controls

DKSAP scanning and relay storage create a spam surface. Mitigations are required:

- short expiries,
- bounded TTL,
- per-bucket quotas,
- proof-of-work or proof-of-postage stamps,
- optional Vess/BTC-backed delivery fees,
- relay reputation for service nodes,
- padded but bounded message sizes,
- randomized delays within limits,
- duplicate suppression by capsule ID.

## Packet size

Two ML-KEM-768 ciphertexts are roughly 2176 bytes before metadata and payload. A full DKSAP network intro will not fit in one conservative 1200-byte UDP datagram.

This is acceptable if Vess treats a capsule as a logical message that can be chunked over QUIC streams or a custom UDP fragmentation layer. The protocol should avoid IP fragmentation and keep physical datagrams around 1200 bytes.

## Migration path

1. Add Vess-owned PQ service-node identity types.
2. Add DKSAP network addresses separate from payment addresses.
3. Add `GradientCapsule` and atomic network/payment binding.
4. Run capsules over current iroh only as an untrusted carrier.
5. Stop treating `iroh::EndpointId` as a Vess trust identity.
6. Add one-time coordinate routing and receiver-cover forwarding.
7. Add prefix-gradient routing once the simple coordinate form is stable.
8. Replace or fork the underlying transport later so the carrier handshake is also PQ-native.

## Bottom line

The best design is not `payment key == node key`.

The best design is:

```text
PQ service-node backbone
+
DKSAP stealth delivery plane
+
gradient routing to one-time coordinates
+
receiver cover forwarding to dead-drop coordinates
+
atomic payment/network binding
+
strict spend-key separation
```

This removes the conceptual weakness of placing PQ payments on top of a trusted elliptic-curve node handshake while preserving Vess's stealth-payment privacy model.
