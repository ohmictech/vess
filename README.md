# Vess

Bitcoin-backed post-quantum digital cash.

- Bitcoin is the reserve asset.
- Burning BTC upgrades those sats into Vess.
- 1 sat permanently becomes 1 Vess.
- The upgrade is one-way. The unspendable Bitcoin UTXO becomes the trustless merkle commitment for that bill.
- After the upgrade, the value moves inside Vess as private bearer bills instead of transparent UTXOs.

Vess keeps Bitcoin for hard issuance and uses its own network for ownership and transfer.

Vess uses a simple user-facing payment identity, in the form of a human readable +vesstag, which is stored on the DHT and maps to a DKSAP master public key address. Tags can be claimed but ownership isn't guaranteed until a transaction is received to a given tag, and a small POW is required to claim one, preventing sybil.

---

When a wallet is unlocked inside a running Vess node:

1. The node derives native Bitcoin HD keys from the Vess master seed.
2. It exposes a SegWit receive address owned by that wallet.
3. Incoming BTC to tracked addresses is detected by the integrated Bitcoin light client.
4. The wallet automatically builds a Bitcoin burn transaction that spends the tracked UTXOs.
5. That burn commits to the first Vess owner key and the exact canonical Vess bill decomposition.
6. After Bitcoin confirmation, the node assembles a `BitcoinBurnBundleProof`.
7. The node auto-generates and gossips the corresponding `OwnershipGenesis` records.
8. The resulting Vess bills are deposited into the local wallet and can be sent over the Vess network.

There is no manual bridge operator, no custodian, and no wrapped token. The supply comes from provable Bitcoin destruction.

---

## Why Upgrade Sats To Vess

Bitcoin is excellent at scarce issuance and terrible at private day-to-day cash flow. Every payment lands on a public graph. Every UTXO cluster becomes a surveillance surface. Every reuse mistake is permanent.

Vess is the private spending layer for sats you are willing to re-issue as bearer cash for convenience without sacrificing principle.

Upgrading sats to Vess gives you:

- Bitcoin-anchored issuance instead of validator discretion.
- No Vess blockchain to sync.
- No public history of Vess transfers.
- Post-quantum ownership keys and transfer authentication.
- Feeless and instant payments.
- Full node functionality on any phone or computer.
- Deterministic ownership state via replicated registries instead of chain consensus.

This is not a Bitcoin sidechain, rollup, federated mint, or multisig bridge. It is a one-way conversion from transparent Bitcoin into private post-quantum bearer cash.

---

### Ownership model

Each bill has:

- a permanent `mint_id`,
- a `chain_tip`,
- a `chain_depth`,
- an owner verification key hash.

Genesis binds the first owner to the bill. Transfers advance the ownership chain with post-quantum signatures. Nodes replicate ownership records through the deterministic DHT location instead of global block production. Double spending is prohibitively difficult due to deterministic consensus rules rather than probabilistic chains.

### Payment model

Payments are encrypted proposals sent to a recipient stealth address. The recipient finalizes receipt by broadcasting an `OwnershipClaim`. Until that claim lands, the sender still controls the bill. This gives Vess:

- deterministic conflict resolution,
- offline-tolerant delivery,
- no mempool fee auction,
- no chain-wide ordering requirement.

### Privacy model

Vess transfers are not published to a public ledger.

- Recipients use stealth addressing.
- `+tags` are hashed before entering the network.
- Ownership registries store current ownership state, not a public transfer history.
- Bills are bearer instruments, not accounts.
- Vess relies on a dual-layer stealth process, where both networking handshakes and value exchange are to one time addresses.
- Vess is formatted in common denominator bills in any 1,2,5 format (20, 500, 1000, and so on), but any send amount is allowed. There is no change, only bill splitting and combining.

---

## Cryptography

Vess ownership and privacy remain post-quantum even though issuance is Bitcoin-backed.

| Purpose | Primitive |
|---|---|
| Network node handshake | Falcon & ML-KEM-768 |
| Bitcoin onboarding | Native Bitcoin P2P and SegWit transactions |
| Vess ownership signatures | ML-DSA-65 |
| Stealth addressing / KEM | ML-KEM-768 |
| Hashing | Blake3 |
| Wallet KDF | Argon2id |
| Symmetric encryption | ChaCha20-Poly1305 |

---

## Notifications You Should Expect

As BTC moves through the upgrade pipeline, the wallet can emit notifications such as:

- `bitcoin_received`
- `bitcoin_burn_queued`
- `bitcoin_burn_broadcast`
- `bitcoin_burn_broadcast_failed`
- `bitcoin_burn_seen`
- `bitcoin_burn_conflicted`
- `bitcoin_burn_confirmed`

Use `vess notifications --follow` to watch that lifecycle live.

---

## Tests

```bash
cargo test --workspace
```

---

## License

Apache 2.0