# VESS #

Stateless, stealth energy-value protocol. Vess flows around the most resilient, decentralized crypto mesh network ever conceived. Zero fees. Unlimited network throughput. Rapid settlement. Highly trustless.

NOT a speculative investment. NOT premined.

Actual thermodynamic money.

### MINTING ###

Every Vess is born in a memory-hard Argon2d 1GB hashing session. Hit enough leading 0 bits derived from your *nonce | stealth address | epoch | amount* and you've successfully created new value, backed completely by energy and hardware. Unlike traditional PoW, the purpose of minting in this protocol is not to secure the network directly. There are no blocks nor block times, no global ledger agreement. Each individual Vess mined acts like its own UTXO whose ID is a hash of the very lottery preimage that created it, essentially baking in its energy proof as the root of the ownership chain that it contains.

Argon2d was selected to level the playing field. All that matters in terms of minting power is effectively your core count and memory bandwith, which are much harder to scale industrially than pure hashing silicon. Consumer hardware is sufficient to be worth minting.

### HASH TABLE ###

Vess is stored on the network's distributed hash table, keyed by its ID. Conflicting Vess is resolved deterministically, with the longest chain depth winning out, and ties broken by lowest hash. This renders double spends impossible as long as there is at least a single honest node responding to a DHT request.

All data except the global epoch clock is distributed, rather than universally agreed upon, allowing any modest device to run a full node.

### PAYMENTS ###

Payments are made to human readable *+VESSTAGS* rather than crypto addresses. The hash of these tags are mapped out to public stealth addresses, stored on the hash table. Tag queries are weighted by Vess ownership, which makes spoofing economically unviable.

Tags are alphanumeric, case insensitive strings claimed during wallet creation and reserved for 30 days to give users time to harden them by receiving or minting Vess.

A payment in this network is not a public broadcast of state change. To send Vess to someone, you choose the Vess you'd like to change ownership of privately, sign the hand-off and change locally, and send the data encapsulated to the receiver's stealth address through the DHT. The receiver then has enough data to update the Vess states on the network, claiming the new Vess for themselves and consuming the old.

If it is never claimed, it never changes ownership.


