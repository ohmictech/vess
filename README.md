# Vess

**Vess is a post-quantum, feeless, work-tethered, decentralized crypto payment protocol.**

What this network achieves:

- Quantum resistant from the ground up
- ~1 second block time
- Good surveillance resistance
- No orphaned blocks
- Bandwidth limited throughput
- Zero transaction fees
- Low state bloat and hardware requirements
- Payment transport agnosticism (OOB)
- Memory hard, ASIC resistant mining
- No pre-mine or VC
- Commodity rather than artificial scarcity
- Tiny codebase

---

The reason for its existence overlaps precisely zero with almost the entirety of DeFi. If you're interested in making a quick buck, move along.

Vess is intended as a thermodynamic currency, rather than a speculative asset to hold and sell for more later on. There are no arbitrary tokenomics or programmatic deflation schedules. Mine it, spend it, move it around. Create velocity rather than stagnation, using it as an actual payment method. Issuance tracks expected work directly: every Vess ever minted represents the same marginal unit of computation, whatever the hashrate. Elastic, not scarce.

---

It allows feelessness because unlike traditional consensus, it does not passively and politely reorder malicious data. Millions of lines of code have been written in the past two decades to solidify distributed ledgers that agree on which version of a spend is the correct one. Blocks, PoW, PoS, DAGs. Their entire architectural purpose outside of agreement on a set of data is to respectfully resolve conflicts.

Unfortunately, historical cryptocurrency offloads the cost of malice onto honest node operators. You pay for adversarial resistance with fees, state bloat, throughput blockages, all in the name of protection. Vess understands a double spend for what it actually is: a willful, malicious attempt to extract value and sabotage a network.

So, a conflict in Vess is resolved with appropriate force: a total vaporization of all associated UTXOs. If a node sees a conflicting set of payments, it simply deletes all associated inputs. The penalty for dishonesty in Vess rests completely on the attackers.

**This is retributive consensus: agreement by punishment, not by reordering.**

---

## Everything is out-of-band

Vess payments never touch the node network until the receiver decides to submit them. A `vess://` invoice and its signed `VessPayment` blob travel between payer and payee through whatever channel they already use: a messaging app, a QR code, an email, a USB drive, a printed piece of paper. The network only sees the blob when the receiver claims it. Until then, the bytes are inert.

This scatters the payment graph across carriers the network has no visibility into. An analyst who reconstructs every on-chain event still doesn't know whether the blob traveled through Signal or a sticker on a coffee shop counter. You can't eclipse-attack a payment that doesn't touch the mesh. You can't DDoS a transaction out of a mempool that isn't involved until the receiver is ready.

**Claim-latency rule: never deliver before inclusion.** A `VessPayment` blob is a signed promise which has no guaranteed value until the receiver submits it to the network *and* a miner includes it in a block with confirmation. Treat it like receiving a signed cheque.

The format is just bytes. Any app can generate an invoice, any wallet can sign a payment, any node can accept the submission. No API key, no registration, no handshake.

---

## How it works

Mining is Cuckatoo27: find a 42-cycle in a graph with 2^27 edges, which takes about 1.3 GB of RAM and runs single-threaded. The 42 sorted nonces are embedded in the block header, and a block's difficulty is the number of leading zero bits on the Blake3 hash of that proof — bound to the header by the cycle itself. Sorting is consensus-enforced, so one cycle yields exactly one valid proof and the difficulty target can't be ground by permutation. Nodes verify the proof in microseconds. Difficulty adjusts every 40 blocks via a rolling average of recent block intervals toward a 1-second target.

The base difficulty pays 1 Vess per block. For every bit beyond 8, the reward doubles:

| Difficulty | Reward |
|---|---|
| 8 | 1 VESS |
| 9 | 2 VESS |
| 10 | 4 VESS |
| 11 | 8 VESS |
| n | 2^(n−8) VESS |

1% of each block reward (minimum 1 Vess) goes to a hardcoded dev key. No premine, no ICO.

**The core security is DAGARC — a directed acyclic graph armored by retributive consensus.** Blocks merge; they don't orphan. Each block references every live tip it knows (up to 8). When two miners race, the next block references both branches: both coinbases pay out, no work is wasted, and the tips collapse back to one. A block's work accumulates over its full ancestry. The merge also closes the last double-spend hole: conflicting spends placed on different branches vaporize all the same when the branches unite. There is no branch on which a conflict survives.

Every node maintains a UTXO set in LMDB. Entries are opaque hashes with no amounts or owner data. When a payment arrives, nodes verify the ML-DSA-65 signatures, check that inputs are unspent, and apply the state change. If two payments spend the same coin, Vess doesn't reorder them: it vaporizes all inputs from both. The attacker loses everything; honest users lose nothing.

Both payments and wallet consolidations have a nearly identical fingerprint, making linkability extremely difficult.

Spending always starts with a `vess://` invoice. The payer's wallet builds a signed `VessPayment` blob and hands it back to the receiver out-of-band. The receiver submits it to any node. Each output uses a fresh one-time ML-DSA-65 keypair — nothing to reuse, link, or track.

### No seed phrases

Vess has no BIP39, no HD derivation, no master seed. Each UTXO contains its own independent ML-DSA-65 keypair, stored directly in your encrypted `wallet.vess` file. Your wallet file is your money.

No phrase to leak. No derivation paths, no gap limits, no chain scanning. Cold storage is copying `wallet.vess` to a USB drive or cloud storage. Backup is copy. Lose all copies and those coins are gone.

### Spend conditions: hashlock and expiry

Every Vess output can carry an optional `SpendCondition` with two independent constraints:

**Hashlock.** The output can only be spent by revealing a preimage whose Blake3 hash matches the lock. This enables atomic swaps: Alice funds an output locked to `blake3(secret)`, Bob does the same on his chain, and when either claims using the preimage, the other learns it. A `[0u8; 32]` hash means no hashlock.

**Expiry.** The output can only be spent before a given UNIX timestamp. After that time, the output is permanently dead — even with the correct preimage. Useful for payment channels with deadlines, offer windows, or time-bounded escrow. A value of `0` means no expiry.

Both constraints can be combined on a single output. The payer sets the condition when building the payment; the receiver must satisfy it (provide the preimage, submit before the deadline) when submitting. A payment that fails its conditions is rejected by all nodes.

### Running a node

```
vess-node                           # default: 0.0.0.0:9876
vess-node --listen 0.0.0.0:9877     # custom port
vess-node --bootstrap peer:9876     # join existing network
vess-node --bootstrap peers.txt     # file with one peer per line
vess-node --bootstrap https://example.com/peers.txt  # fetch from URL
```

```
mine         # start mining (1 core)
mine 4       # start mining with 4 cores
mine stop    # stop mining
peer 1.2.3.4:9876  # connect to a peer
status       # show peers, UTXOs, difficulty, mining state
```

### NAT and hole-punching

Vess nodes communicate over UDP. You don't need port forwarding, NAT traversal automatically using public introducer peers.

Every node automatically detects whether it's behind NAT by comparing its self-reported address to the address peers see in `PeerAnnounce` messages. The only requirement is that at least one public introducer node exists in the mesh, and any node with an open port on a public IP can serve this role. Bootstrapping to a public seed node is all you need.

### Running the wallet

```
vess-wallet --connect 127.0.0.1:9876 # connect to a node (required before sync, send, etc.)
vess-wallet --import vess-db         # import coinbase UTXOs
vess-wallet --import-key pub sec     # import a raw keypair
vess-wallet --balance                # check balance
vess-wallet --sync                   # confirm unclaimed UTXOs against node
vess-wallet --invoice 100            # generate vess:// invoice
vess-wallet --pay "vess://..." --out payment.vess
vess-wallet --receive payment.vess   # claim received blob
vess-wallet --consolidate            # merge small UTXOs
```

Hashlock and expiry on invoices:
```
vess-wallet --invoice 100 --hashlock <preimage>
vess-wallet --invoice 100 --expires 1720000000
```

## License

Apache 2.0
