# Vess: Stateless Post-Quantum Digital Cash

## A Whitepaper

---

Digital cash systems have, for sixteen years, pursued the same architectural pattern: a shared global ledger, replicated across thousands of machines, advanced by a consensus mechanism that converts energy expenditure into append rights. This pattern solved the double-spend problem for a permissionless setting, and in doing so it created an entirely new asset class. But it also inherited the fundamental scaling tension inherent to all replicated state machines — every participant must eventually learn about every transaction, and the system cannot process more throughput than the slowest honest validator can verify.

Vess takes a different approach. It abandons the global ledger entirely.

There is no blockchain in Vess. There is no consensus mechanism, no committee of validators, no mempool, no gas auction, and no block space market. Value does not live in account entries on a replicated state trie. It lives in self-contained cryptographic objects called VessBills — each one a bearer instrument that carries its own ownership chain. A VessBill is not just a ledger entry.

This design shifts the system's security model from social consensus to cryptographic verification of real-world economic commitment. The integrity of a VessBill does not depend on any validator set, any stake distribution, or any honest-majority assumption. It depends on a verifiable Bitcoin time-lock: a CLTV-encumbered UTXO whose transaction ID, Merkle proof, and block header are validated by an embedded SPV light client. You cannot forge a VessBill because you cannot fabricate a Bitcoin block header with sufficient accumulated proof-of-work, nor can you produce a valid Merkle proof for a transaction that does not exist in that block. You cannot double-spend a VessBill because the ownership chain is a hash chain, and the deeper chain always wins. There is no authority to appeal to and no quorum to corrupt — only mathematics and Bitcoin's own proof-of-work security.

### Bill Creation: Bitcoin Time-Locks as Trust Anchors

VessBills enter existence through a mechanism that harnesses Bitcoin's security rather than competing with it. To create VessBills, a user constructs a Bitcoin transaction with a CLTV (CheckLockTimeVerify) output — a time-locked UTXO that cannot be spent until a specified future block height. The locked satoshis are not destroyed. They sit in the Bitcoin UTXO set, verifiably immobilized, and return to the owner's control when the timelock expires. What the owner purchases with this temporary immobilization of capital is the right to issue VessBills proportional to the product of the locked amount and the lock duration.

The issuance formula is straightforward: `vess_amount = locked_sats × lock_blocks / BLOCKS_PER_YEAR`, where `BLOCKS_PER_YEAR` is 52,560 (365.25 days at 144 blocks per day). Locking 100 satoshis for one year produces 100 Vess. Locking the same 100 satoshis for ten years produces 1,000 Vess. The minimum lock is 5,256 blocks — approximately one-tenth of a year — and the maximum standard lock is 525,600 blocks, or roughly ten years. This creates a direct economic relationship: longer capital commitment yields proportionally more issuance rights, exactly as one would expect from the time value of money.

A `BitcoinTimeLockProof` cryptographically binds the Vess bills to the Bitcoin transaction. It contains the transaction ID, the Merkle proof linking that transaction to a confirmed block header, the cumulative chainwork proving the block is part of Bitcoin's most-work chain, the CLTV block height encoding the lock duration, the locked satoshi amount, and the first owner's ML-DSA-65 verification key. Every node in the Vess network verifies this proof independently using an embedded Bitcoin SPV light client before accepting any bill into the ownership registry. The mint ID for each bill is derived deterministically from the Bitcoin transaction: `Blake3("vess-timelock-mint-id-v1" || txid || output_index)`, permanently anchoring every VessBill to a specific Bitcoin UTXO.

There is a second, more powerful creation mechanism: the century lock. A century lock is a Bitcoin time-lock of 5,256,000 blocks — approximately one hundred years. At this timescale, the locked satoshis are effectively permanently immobilized relative to any human planning horizon. A century lock does not produce a one-time issuance of VessBills. Instead, it creates a perpetual faucet that drips one VessBill for every Bitcoin block confirmed over the next century, each denominated at `ceil(locked_sats / BLOCKS_PER_YEAR)` Vess. The faucet is tracked on-DHT: the Vess network records which blocks have been claimed, and anyone who can produce a valid Merkle proof for a new block header can claim that block's bill. This transforms a single irreversible capital commitment into a continuous, century-long stream of value — a primitive that has no analog in any other digital cash system.

For development and testing, a local faucet mode exists that creates bills without any Bitcoin proof. Nodes only accept these proofs when explicitly configured to do so, and they carry no value outside of test environments.

The Vichor asset, a fixed-supply network stock of one billion units, is created through a single one-time genesis event anchored to a canonical protocol nonce. Only one Vichor genesis proof is ever valid, enforced by a hardcoded nonce and a hardcoded developer verification key. The supply is fixed — even the developer cannot print more.

Bills follow the 1-2-5 denomination series: D1, D2, D5, D10, D20, D50, and so forth. Reforge operations allow splitting and combining bills while validating arithmetic conservation of value. A D10 can become a D5, two D2s, and a D1; ten D1s can become a D10. The original genesis proof travels with the reforged output, preserving the cryptographic link back to the Bitcoin time-lock that authorized the issuance.

In code, the VessBill is a compact, self-contained bearer record:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VessBill {
    pub denomination: Denomination,
    pub digest: [u8; 32],
    pub created_at: u64,
    pub stealth_id: [u8; 32],
    pub dht_index: u64,
    pub mint_id: [u8; 32],
    pub chain_tip: [u8; 32],
    pub chain_depth: u64,
    pub asset: Asset,
}
```

The `BitcoinTimeLockProof` that anchors each bill to the Bitcoin chain carries the full SPV verification context:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinTimeLockProof {
    pub network: BitcoinNetwork,
    pub txid: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_height: u64,
    pub confirmations: u32,
    pub required_confirmations: u32,
    pub corroborating_peer_count: u32,
    pub chain_work: [u8; 32],
    pub merkle_root: [u8; 32],
    pub merkle_proof: Vec<[u8; 32]>,
    pub merkle_index: u32,
    pub locked_sats: u64,
    pub lock_blocks: u64,
    pub cltv_block_height: u64,
    pub vess_amount: u64,
    pub first_owner_vk: Vec<u8>,
    pub first_owner_vk_hash: [u8; 32],
    pub output_values: Vec<u64>,
    pub commitment_payload: Vec<u8>,
}
```

And the `GenesisProof` enum that unifies all bill creation paths:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenesisProof {
    Vess(Vec<u8>),
    BitcoinTimeLock(BitcoinTimeLockProof),
    CenturyLock(BitcoinTimeLockProof),
    VichorGenesis(VichorGenesisProof),
    LocalTestFaucet(LocalTestFaucetProof),
}
```

### Ownership as a Hash Chain

Once minted, a VessBill carries a `chain_tip` — a 32-byte Blake3 hash that serves as the root of an ownership chain. At genesis, this tip is computed as `Blake3("vess-chain-v0" || mint_id || owner_vk_hash)`, binding the bill irrevocably to its first owner's ML-DSA-65 verification key. When the bill is transferred, the new owner advances the chain by hashing the previous tip together with their own verification key hash and a Blake3 hash of the transfer signature: `Blake3(prev_chain_tip || new_owner_vk_hash || transfer_sig_hash)`. The `chain_depth` counter increments by one on each transfer.

This construction has an elegant economic property: conflict resolution reduces to comparing integers. If two competing ownership claims appear for the same mint ID, the one with the higher `chain_depth` prevails. At equal depth, the tiebreaker is lexicographic comparison of the claim hashes. There is no need for a court, a slashing condition, or a social fork. The deeper chain is simply the valid one, and every node in the network can verify this independently by recomputing the hash chain from genesis.

The sender signs each transfer with ML-DSA-65, a NIST-standardized post-quantum signature scheme at security level 2. The transfer message binds the mint ID to the recipient's stealth identifier and a timestamp, preventing replay across different payments. Because the ownership chain is purely hash-based, transfers require no additional proofs — the Bitcoin time-lock verification was performed once at genesis, and the resulting mint ID carries that cryptographic authority forward through the entire lifetime of the bill.

The two core ownership messages, as they appear on the wire:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipGenesis {
    pub mint_id: [u8; 32],
    pub chain_tip: [u8; 32],
    pub owner_vk_hash: [u8; 32],
    pub owner_vk: Vec<u8>,
    pub denomination_value: u64,
    pub genesis_proof: GenesisProof,
    pub digest: [u8; 32],
    pub hops_remaining: u8,
    pub chain_depth: u64,
    pub output_index: u32,
    pub pow_nonce: Option<[u8; 32]>,
    pub pow_hash: Option<[u8; 32]>,
    pub accumulated_work: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipClaim {
    pub mint_id: [u8; 32],
    pub stealth_id: [u8; 32],
    pub prev_owner_vk: Vec<u8>,
    pub transfer_sig: Vec<u8>,
    pub new_owner_vk_hash: [u8; 32],
    pub new_owner_vk: Vec<u8>,
    pub new_chain_tip: [u8; 32],
    pub timestamp: u64,
    pub hops_remaining: u8,
    pub chain_depth: u64,
    pub encrypted_bill: Vec<u8>,
    pub pow_nonce: Option<[u8; 32]>,
    pub pow_hash: Option<[u8; 32]>,
    pub accumulated_work: Option<u64>,
    pub hash_preimage: Option<[u8; 32]>,
}
```

The `hash_preimage` field on `OwnershipClaim` is the mechanism that enables atomic swaps: when a payment is hash-locked, the claimant must reveal the Blake3 preimage, proving they know the secret that the sender committed to.

### Privacy Through Stealth Addressing

Every payment in Vess uses a unique, ephemeral destination address derived through the Dual-Key Stealth Address Protocol. Each user generates two independent ML-KEM-768 keypairs: a scan keypair for viewing rights and a spend keypair for claim authority. When Alice wants to pay Bob, she encapsulates fresh ML-KEM shared secrets to both of Bob's public encapsulation keys. From these shared secrets she derives a 1-byte view tag — the first byte of the Blake3 hash of the scan shared secret — and a 32-byte stealth identifier from the Blake3 hash of both shared secrets concatenated. She encrypts the bill payload under a ChaCha20-Poly1305 key derived from the scan shared secret.

Bob scans the network by checking view tags against his derived scan secrets. A single byte comparison eliminates over 99.6% of messages that are not his, without requiring him to perform AEAD decryption on every candidate. When a view tag matches, Bob decapsulates both ML-KEM ciphertexts, verifies the stealth identifier, decrypts the payload, and broadcasts his ownership claim. The sender's identity never appears in any routing metadata. No two payments to the same recipient share a stealth identifier. Network observers see only encrypted blobs of uniform 48 KiB size moving between ephemeral addresses.

This architecture makes transaction graph analysis fundamentally harder than in transparent ledger systems. There is no permanent address to cluster, no UTXO set to enumerate, and no change address heuristic to exploit. Every payment looks like every other payment, and every destination looks like noise.

The stealth payload that carries encrypted bills across the network:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthPayload {
    pub ct_scan: CiphertextBytes,
    pub ct_spend: CiphertextBytes,
    pub view_tag: u8,
    pub stealth_id: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}
```

And the payment envelope that wraps it for routing:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub payment_id: [u8; 32],
    pub stealth_payload: Vec<u8>,
    pub view_tag: u8,
    pub stealth_id: [u8; 32],
    pub created_at: u64,
    pub bill_count: u8,
    pub mailbox_key: Option<[u8; 32]>,
    pub direct_receipt_tag_hash: Option<[u8; 32]>,
    pub hash_lock: Option<[u8; 32]>,
}
```

The `mailbox_key` — derived by both sender and recipient as `Blake3("vess-mailbox-v1" || spend_ek)` — enables DHT-sharded retrieval without trial-decrypting unrelated payments. The `hash_lock` enables atomic swaps by requiring the recipient to present a Blake3 preimage when claiming.

### Human-Readable Identity

Raw cryptographic keys are not user-friendly. VessTags solve this with a simple namespace: 3 to 20 lowercase alphanumeric characters prefixed with a plus sign — `+alice`, `+satoshinakamoto`. Tags resolve through the DHT to stealth addresses, so users can send payments to names rather than pasting 2,400-byte ML-KEM encapsulation keys.

Registering a tag requires a 2 GiB Argon2id proof-of-work — a single pass over a 2 GiB memory region taking approximately ten seconds on consumer hardware. The proof binds the tag string to the registrant's scan and spend keys, preventing precomputation attacks. A tag begins unhardened and can be claimed by anyone who sends a payment to its current holder. Once the tag owner receives their first payment, the tag hardens permanently. This creates a simple economic dynamic: tags have value proportional to their recognizability, and that value is protected by the same payment mechanism that gives the tag utility in the first place. An unhardened tag is a standing invitation to outbid the current registrant; a hardened tag is a permanent digital identity anchored by the receipt of value.

### The Mesh Network

Vess nodes communicate over a custom post-quantum UDP mesh. Every connection begins with an ML-KEM-768 handshake producing ephemeral ChaCha20 session keys. Messages are encrypted and authenticated at the transport layer. The mesh is organized around a Kademlia distributed hash table with 256 XOR-distance buckets, each holding up to 20 peers. The routing table stores only Blake3-hashed node identities — no wallet addresses, no stealth keys, no payment metadata, and no tag names. A node's presence in the DHT reveals only that it runs the Vess protocol, not who it belongs to or what value it holds.

Peer discovery combines three mechanisms: LAN UDP broadcast on port 18348 for local network discovery, filesystem-based contact exchange through `%LOCALAPPDATA%/Vess/local-peers/` for persistence across restarts, and bootstrap from configured or Bitcoin-blockchain-discovered seed nodes. New peers undergo a handshake that verifies protocol version compatibility through a Blake3 Merkle root of all workspace source code, followed by an adaptive Argon2id proof-of-work starting at 256 MiB and scaling with estimated network size.

Gossip propagation uses K-nearest fanout with a random factor of two, ensuring both reliable delivery to the relevant DHT neighborhood and some stochastic diffusion. Rate limiting enforces 200 messages per 10-second window per peer, with three strikes triggering banishment. Duplicate detection uses Blake3 payload hashing — 50 identical payloads in 60 seconds is treated as a flood attack and results in immediate banishment.

### On-Chain DHT Asset Swaps

Vess supports trustless cross-asset exchange directly on the DHT, without any centralized exchange, order book server, or matching engine. Swap offers are themselves DHT records, keyed by the asset pair they represent, and replicated across the K-nearest peers to the swap key. Anyone can query the network for open offers on any asset pair and settle against them atomically.

A swap offer is a simple structure: it declares what asset and amount the offerer is selling, what asset and amount they want in return, the recipient address for the counter-payment, a Blake3 hash lock for atomic settlement, and an expiration timestamp.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOffer {
    pub offer_asset: String,
    pub offer_amount: u64,
    pub want_asset: String,
    pub want_amount: u64,
    pub recipient: String,
    pub hash_lock: [u8; 32],
    pub expires_at: u64,
    pub offerer_node_id: Vec<u8>,
}
```

The DHT key for a swap offer is computed as `Blake3("vess-swap-v0" || min(asset_a, asset_b) || max(asset_a, asset_b))`, with the asset identifiers sorted to ensure canonical ordering — a swap between BTC-backed bills and Vichor resolves to the same DHT shard regardless of which side initiated the query. When a node receives a swap offer, it stores it locally in a BTreeMap indexed by the DHT key and gossips it forward to the K-nearest peers for that key.

The settlement mechanism uses hash-locked atomic payments. When Alice posts a swap offer, she generates a random preimage, hashes it with Blake3, and embeds the hash in the offer as the `hash_lock`. Bob discovers Alice's offer through a DHT query, verifies the terms are acceptable, and sends his payment to Alice's specified recipient address — crucially, Bob's payment includes the same `hash_lock` value in the payment's hash-lock field. This means Alice cannot claim Bob's payment without revealing the preimage, which she knows because she generated it. But by revealing the preimage to claim Bob's payment, Alice simultaneously reveals it to Bob, who can then use it to claim Alice's counter-payment. Both legs settle or neither does. The `OwnershipClaim` message carries an optional `hash_preimage` field — when present, nodes verify that its Blake3 hash matches the payment's hash lock before accepting the claim, enforcing the atomicity constraint at the protocol level.

This design has no central point of failure, no custody risk, no fee extraction by an intermediary, and no order book to front-run. Offers are filtered for expiration at query time, so stale offers naturally evaporate from the network without requiring cleanup messages or garbage collection rounds. The Vichor genesis supply — one billion units held by the developer and sold on the swap DHT at market rates — provides a permanent liquidity backstop for the swap ecosystem, ensuring there is always a counter-asset available for BTC-backed bill holders who wish to exit their positions.

### Sybil Resistance: Handshake, Versioning, and Banishment

A peer-to-peer network without economic stake requirements must defend against Sybil attacks through computational cost and behavioral reputation. Vess layers several complementary defenses, each making Sybil fabrication progressively more expensive while giving honest nodes tools to identify and permanently expel malicious peers.

The first line of defense is the handshake protocol. Every new connection triggers a challenge-response sequence. The challenger sends a random 32-byte nonce. The responder must return an HMAC computed as `Blake3::keyed_hash(version_hash, nonce)`, where `version_hash` is a Blake3 Merkle root of all workspace source files baked into the binary at compile time.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeChallenge {
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub hmac: [u8; 32],
    pub pow_hash: Vec<u8>,
}
```

The challenger verifies this HMAC against a sliding window of allowed version hashes — the current build plus a small set of previous versions defined in a `versions.txt` file bundled with the release. This ensures that every peer on the network is running authentic Vess software, not a modified fork, and supports rolling upgrades by allowing nodes one version behind to continue participating during the transition window. A constant-time comparison prevents timing side-channel attacks on the HMAC verification.

The second defense is an Argon2id proof-of-work attached to every handshake response. The difficulty is a fixed 1 GiB of memory at two iterations and one parallelism lane — a computation that takes several seconds on consumer hardware and consumes substantial RAM, making mass parallelization of handshake attempts expensive. The cost does not scale with network size. It is the same fixed barrier whether the network has ten nodes or ten thousand. A Sybil attacker attempting to deploy a thousand fake nodes must provision a terabyte of RAM dedicated solely to handshake proofs, regardless of how large or small the honest network is. Honest users running a single node feel this as a brief one-time cost; attackers attempting to fabricate an identity fleet feel it as a linear multiplier on their infrastructure budget.

The third defense is continuous reverification. A peer that passes handshake is not trusted indefinitely. Every twenty minutes, the handshake must be repeated. A Sybil node that somehow acquired valid software and passed initial verification cannot simply park itself in the routing table and accumulate reputation — it must continue proving its legitimacy, consuming memory and CPU on an ongoing basis. Five consecutive handshake failures result in permanent banishment.

Banishment is the network's ultimate sanction, and it is irreversible. A `BanishmentManager` maintains a set of permanently banned node IDs behind a `RwLock` — the hot read path (checking whether a peer is banned before processing its messages) acquires only a read lock, while the cold write path (adding a new banishment) acquires a write lock. Banished nodes have all traffic dropped at the transport layer.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanishmentProof {
    pub peer_id: [u8; 32],
    pub offense: BanishmentOffense,
    pub evidence: Vec<u8>,
    pub reporter_vk: Vec<u8>,
    pub reporter_signature: Vec<u8>,
    pub observed_at: u64,
}
```

Banishments are enforced via these cryptographically signed proofs that identify the offending peer, the specific offense, the evidence supporting the accusation, and the reporter's ML-DSA-65 signature. Valid offenses include double-spending (two conflicting `OwnershipClaim` messages for the same mint ID), invalid transfer signatures, invalid reforge proofs, protocol version mismatches, and rate limit abuse. Each offense type is validated independently: a double-spend proof must contain both conflicting claims, an invalid signature proof must demonstrate that the transfer message fails ML-DSA-65 verification against the purported signer's key, and so on. Nodes accept banishment proofs from any peer whose reporter signature verifies, and once accepted, the ban is permanent — there is no appeal, no unbonding period, and no rehabilitation.

Complementing these hard defenses is a softer reputation system that influences peer selection without requiring cryptographic proof. Each peer accumulates a latency score — an exponential moving average with a smoothing factor of 0.3 — and a reliability ratio computed as successes divided by total interactions. The composite reputation score is `reliability / (1 + latency / 1000)`, yielding a value between zero and one. When selecting peers for routing or gossip, nodes prefer higher-scoring peers. Newly connected peers begin with a probation penalty: their identity is less than ten minutes old, so their influence factor is reduced to 10% of a fully established peer. This makes Sybil rotation — continuously discarding old identities and creating new ones — self-defeating, because rotating identities never accumulate meaningful influence before they are rotated out again.

At the network periphery, a global token-bucket rate limiter — 10,000 tokens per second with a 50,000-token burst capacity — prevents any single peer or coordinated group from saturating the network with messages even before the per-peer rate limiter and banishment mechanisms engage. Together, these defenses create a mesh where participation is cheap enough for honest users with a single node, expensive enough in aggregate to deter Sybil attacks, and self-policing through cryptographic evidence that any honest peer can verify independently.

### The Absence of Consensus

The most important thing to understand about Vess is what it does not have. There is no block production. No validator election. No fork choice rule. No gas metering. No state rent. No slashing. No staking. No governance token. No foundation treasury. No upgrade mechanism that depends on social coordination.

The system's security derives from Bitcoin's accumulated proof-of-work. Every VessBill traces back to a specific Bitcoin transaction whose inclusion in the most-work chain is cryptographically verified. The SPV proof in the bill's genesis record is a mathematical certificate that real satoshis were genuinely immobilized for a specific duration. The hash chain is a tamper-evident record of every transfer. The stealth addressing ensures that surveillance requires breaking ML-KEM-768, which is believed to be hard even for quantum adversaries.

This is digital cash built on the strongest computational foundation available: Bitcoin's hash rate, which represents the largest sustained expenditure of energy toward a single cryptographic purpose in human history. Vess does not compete with that expenditure. It harnesses it.

### The Trilemma and the Fourth Vector

Every decentralized system confronts the same structural tension. The blockchain trilemma — articulated most famously in the context of proof-of-stake networks — states that a system can optimize for at most two of three properties: security, scalability, and decentralization. Strengthen any two and the third degrades. This framing has shaped a decade of protocol design, and it has produced an entire taxonomy of tradeoffs: high-security, low-throughput chains; high-throughput, committee-based chains; and everything in between. But the trilemma, as traditionally stated, assumes that all three properties must be secured by the same mechanism — that the consensus layer must simultaneously provide safety, liveness, and censorship resistance using only the resources internal to the system.

Vess escapes this constraint by introducing a fourth vector: bandwidth. More precisely, Vess achieves security, privacy, speed, and decentralization not by solving the trilemma within its own borders, but by outsourcing security to the largest proof-of-work chain in existence and accepting that the resulting payments will be large. A typical Vess payment is not a few hundred bytes referencing UTXOs by index. It is a stealth payload padded to 48 KiB, containing dual ML-KEM-768 ciphertexts, ChaCha20-Poly1305 ciphertext, and the full serialized bill data. An ownership claim carries the previous owner's verification key, the transfer signature, the new chain tip, and an encrypted bill blob for DHT recovery. A genesis proof carries a complete Bitcoin SPV verification context: the transaction ID, the Merkle branch, the block header, the cumulative chainwork. None of this is small.

The tradeoff is deliberate. Privacy requires that payments be indistinguishable from one another, which means fixed-size payloads and no selective disclosure of metadata. Decentralization without consensus requires that every node can independently verify every claim, which means carrying the full proof with the message rather than referencing a shared ledger that already verified it. And security without a native stake asset requires anchoring to Bitcoin's proof-of-work, which means SPV proofs that are large by the standards of a simple signature but minuscule by the standards of the security they inherit. The cost of all three — privacy, decentralization, security — is paid in bytes.

We believe this is the correct tradeoff. Bandwidth is the most optimizable scarce resource in the real world. Global internet capacity has grown by a factor of roughly a thousand over the past two decades and shows no sign of slowing. Last-mile connections that once struggled with 56-kilobit modems now routinely carry hundreds of megabits. Data center interconnects run at terabits per second. Storage density doubles every few years. Compression algorithms improve. Content delivery networks push data to the edge. Of all the physical constraints a protocol designer might choose as a bottleneck — energy, computation, memory, latency, coordination overhead — raw data volume is the one that improves most reliably, most predictably, and with the least human intervention.

A protocol that is bottlenecked by energy costs will always be expensive to use because energy is a commodity with a relatively flat supply curve. A protocol bottlenecked by coordination latency will always be slow because the speed of light is fixed. A protocol bottlenecked by cryptographic novelty will always carry upgrade risk because mathematical assumptions can break. But a protocol bottlenecked by bandwidth will get faster and cheaper every year, automatically, as the physical infrastructure of the internet improves beneath it. The same 48 KiB payload that strains a rural connection today will be trivial on the median connection a decade from now. The same SPV proof that takes a second to transmit over a home uplink will take milliseconds over the fiber that eventually replaces it.

This is the fourth vector. Vess does not solve the trilemma. It sidesteps it by paying for privacy, decentralization, and security in the one currency that inflates in the protocol's favor: bytes. The system is heavy by design, and that weight is a bet on the continued exponential improvement of the physical internet — a bet that has paid out reliably for the entire history of networked computing.

### Implementation

The Vess protocol is implemented in Rust as a workspace of 11 crates. The node binary compiles to a single executable that embeds a Bitcoin SPV light client for time-lock verification, the post-quantum mesh transport, the Kademlia DHT, the ownership registry, the tag system, and the JSON-line TCP RPC server. The wallet frontend is built with Tauri v2 and Svelte, communicating with the local node over an authenticated TCP connection. All of Vess's own cryptographic primitives are post-quantum: no secp256k1, no Ed25519, no ECDH, no RSA appears anywhere in the protocol's native cryptography. The system depends on Bitcoin's proof-of-work for its economic security, not on the longevity of any particular signature scheme within Vess itself, and is designed to survive the eventual arrival of cryptographically relevant quantum computers without requiring any protocol upgrade or migration of user funds.

---