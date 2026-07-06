# VESS #

Stateless, stealth energy-value protocol. Vess flows around the most resilient, decentralized crypto mesh network ever conceived. Zero fees. Unlimited network throughput. Rapid settlement. Highly trustless. 100% post-quantum cryptography.

Actual thermodynamic money.

### MINTING ###

Every Vess is born in a memory-hard Argon2d 1GB hashing session. Hit enough leading 0 bits derived from your *nonce | stealth address | epoch | amount* and you've successfully created new value, backed completely by energy and hardware. Unlike traditional PoW, the purpose of minting in this protocol is not to secure the network directly. There are no blocks nor block times, no global ledger agreement. Each individual Vess mined acts like its own UTXO whose ID is a hash of the very lottery preimage that created it, essentially baking in its energy proof as the root of the ownership chain that it contains.

Argon2d was selected to level the playing field. All that matters in terms of minting power is effectively your core count and memory bandwidth, which are much harder to scale industrially than pure hashing silicon. Consumer hardware is sufficient to be worth minting.

### ECONOMICS ###

There is no supply limit or difficulty adjustment, because Vess was not created to be a speculative asset, it was created to represent tokenized energy. This is not problematic because unlike fiat currency, which is birthed into existence arbitrarily, every single Vess requires energy expenditure. Devaluation is not the result of a growing supply of Vess, because each unit has a baseline cost of production. The supply simply expands to match the electricity injected rather than dilution.

As there is no initial coin supply, tokenomics, fees, or allocations, development is funded by a hardcoded dev faucet subsidy. Limited to once per 24 hour epoch, a single payout of 30,000 vess is elligible to be claimed by the protocol. Other than this modest emission, all Vess is created by equal effort.

### HASH TABLE ###

Vess is stored on the network's distributed hash table, keyed by its ID. Conflicting Vess is resolved deterministically, with the longest chain depth winning out, and ties broken by lowest hash. This renders double spends impossible as long as there is at least a single honest node responding to a DHT request.

All data except the global epoch clock is distributed, rather than universally agreed upon, allowing any modest device to run a full node.

### PAYMENTS ###

Payments are made to human readable *+VESSTAGS* rather than crypto addresses. The hashes of these tags are mapped out to public stealth addresses, stored on the hash table. Tag queries are weighted by Vess ownership, which makes spoofing economically unviable.

Tags are alphanumeric, case insensitive strings claimed during wallet creation and reserved for 30 days to give users time to harden them by receiving or minting Vess.

A payment in this network is not a public broadcast of state change. To send Vess to someone, you choose the Vess you'd like to change ownership of privately, sign the hand-off and change locally, and send the data encapsulated to the receiver's stealth address through the DHT. The receiver then has enough data to update the Vess states on the network, claiming the new Vess for themselves and consuming the old.

If it is never claimed, it never changes ownership.

### SOVEREIGNTY ###

Every payment is wrapped in four unlinkable cryptographic layers:

0. Onion routing — 3-hop relay, no single node knows sender + recipient
1. ML-KEM-768 mesh — ephemeral session keys per connection
2. ML-KEM-768 stealth — unique stealth_id per payment, 48 KiB padded payloads
3. ML-DSA-65 ephemeral — fresh owner key per bill, no address reuse

No observer at any layer can correlate sender, amount, or recipient.

### USAGE ###

Build from source (Rust 1.80+):

```bash
git clone https://github.com/vess/vess
cd vess
cargo build --release
```

Binaries produced: `vess` (CLI wallet + node), `vess-relay`, `vess-rendezvous`.

### ARCHITECTURE ###

```
vess-cli/          CLI wallet (init, send, mint, claim, node, etc.)
vess-artery/       Full node — mesh networking, DHT, mining, RPC server
vess-mesh/         P2P transport — UDP/TCP carriers, handshake, relay, rendezvous
vess-foundry/      Core types — Vess bill, minting, spend auth, clock
vess-protocol/     Wire format — PulseMessage enum, DHT query/response, payment
vess-stealth/      ML-KEM-768 stealth addressing — per-payment unlinkability
vess-tag/          VessTag — human-readable recipient identifiers
vess-sovereign/    Wallet file — BIP39 recovery, encrypted persistence
vess-relay/        Standalone relay server binary (NAT fallback)
vess-rendezvous/   Standalone rendezvous server binary (hole punching)
```

Third-party integration path:
```
Your wallet (any language) ← TCP JSON-line :9821 → vess node ← mesh → DHT
```

#### Wallet

```bash
# Create a new wallet (BIP39 recovery phrase + password)
vess init --name mywallet

# Recover a wallet from phrase
vess recover --name mywallet

# Check balance
vess balance

# Show your receiving vesstag (for others to send to you)
vess receive
```

#### Sending

```bash
# Send via onion routing (default, 3-hop private)
vess send --amount 100 --recipient +alice

# Send direct (faster, less private)
vess send --amount 100 --recipient +alice --direct
```

#### Tags

```bash
# Register a human-readable tag (alphanumeric, case-insensitive)
vess tag register alice
```

#### Minting

```bash
# Start mining (continuous, epoch-aware, 1 GB Argon2d)
vess mint start --amount 1

# Check mining status
vess mint status

# Stop mining
vess mint stop
```

#### Claims & Recovery

```bash
# Claim all buffered payments since last sweep (auto-derives mailbox keys)
vess claim

# Push encrypted wallet manifest to DHT for disaster recovery
vess manifest

# Show wallet notifications
vess notifications
```

#### Node

```bash
# Start the artery node (mesh networking + DHT + RPC)
vess node --wallet mywallet

# With NAT traversal (deploy relay/rendezvous servers on public IPs first)
vess node --wallet mywallet --rendezvous 1.2.3.4:9445 --relay 1.2.3.4:9446

# With bootstrap peers and custom bind
vess node --wallet mywallet --bind 0.0.0.0:18348 --bootstrap peer1:port,peer2:port

# Non-interactive password
vess node --wallet mywallet --password "mypass"

# Show node status
vess status
```

#### Peers

```bash
# Add a peer while the node is running
vess peer add "192.168.1.5:18348"

# List known peers
vess peer list

# Remove a peer by node ID prefix
vess peer remove abc12345
```

#### Infrastructure

Vess chooses to stay neutral and censorship resistant at the base layer, not providing any central relay servers or bootstrap nodes. Third party implementations must provide their own bootstrap node paths and relay servers. Out of band node discovery is recommended for maximum decentralization.

```bash
# Run a relay server (transparent forwarding for symmetric NATs)
vess-relay --bind 0.0.0.0:9446

# Run a rendezvous server (UDP hole-punch coordinator)
vess-rendezvous --bind 0.0.0.0:9445
```

#### RPC

Third-party wallets integrate via TCP JSON-line on port 9821:

```bash
# Example: check balance via curl
echo '{"method":"balance","params":{}}' | nc localhost 9821
```

Full RPC API: `balance`, `send`, `send_direct`, `receive`, `tag_register`, `tag_lookup`,
`mint_start`, `mint_stop`, `mint_status`, `faucet_submit`, `manifest_push`,
`recover_manifest`, `claim`, `notifications`, `status`, `wallet_info`,
`add_peer`, `list_peers`, `remove_peer`, `ban_peer`.



## LICENSE ## 

Apache 2.0 License
