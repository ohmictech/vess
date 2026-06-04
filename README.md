
```
Keep your lives free from the love of money and be content with what you have, 
because God has said, 'Never will I leave you; never will I forsake you.'
Heb 13:5
```

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

---

## Why Upgrade Sats To Vess

Bitcoin is excellent at scarce issuance and terrible at private day-to-day cash flow. Every payment lands on a public graph. Every UTXO cluster becomes a surveillance surface. Every reuse mistake is permanent.

Vess is the sovereign spending layer for sats you are willing to re-issue as bearer cash for convenience without sacrificing principle.

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

### Programmability

Vess has a unique take on smart contracts. Programs can be deployed via a small POW and published through the DHT.
Bills can be locked to a program and later unlocked only when the claimant submits an `OwnershipClaim` carrying whatever witness or zero-knowledge proof that covenant requires. Other nodes verify that claim-path witness material before accepting the ownership rotation.

Programs can be written using VessLogic, a simple, primitive scripting schema.
Each deployed program is also published under a human-facing name such as `+vl_market1`. The client canonicalizes that to `vl_market1` and keys it on the DHT by `Blake3("vl_market1")`, matching the same name-hash style used for VessTags.

VessLogic is line-by-line and zero-format. A source file such as `progname.vess` is split into sections:

- `[constants]` for immutable configuration.
- `[deposit]` for bill-in logic.
- `[withdraw]` for bill-out logic.

Programs are stateless covenants. Mutable state lives on bills via their ownership `state_commitment`, not inside the deployed program blob.
The covenant is passive: a wallet or node proposes its own deposit or withdraw transition, and the covenant only validates whether that proposed bill transition is allowed.
In practice, the main verification path is the normal bill `OwnershipClaim`. Deposits are regular ownership claims that rotate a bill into `new_owner_program`, and withdrawals are regular ownership claims that rotate a program-owned bill back out to a user key or another program. Nodes verify the attached compute witness while distributing that ownership claim.

Each executable section is one instruction per line and must end in `approve`.

Supported instruction forms are:

- `require <expr>`
- `bind <name> = <expr>`
- `approve`

Optional linked covenant names can be listed in a `[links]` section and then referenced from deposit/withdraw predicates.

Supported operators are:

- arithmetic: `+ - * / %`
- comparison: `== != < <= > >=`
- boolean: `! && ||`
- grouping: `(` `)`
- built-in functions: `min(a, b)`, `max(a, b)`, `abs(x)`, `clamp(x, lo, hi)`, `after(ts)`, `before(ts)`, `between(start, value, end)`, `satisfies(link)`, `all_of(link_a, link_b, ...)`, `any_of(link_a, link_b, ...)`

Built-in deposit values are `amount`, `sender`, `timestamp`, `claim_timestamp`, `program_balance`, `current_state`, `next_state`, `claim_mint_id`, `claim_prev_owner`, `claim_new_owner`, `claim_chain_depth`, `claim_has_prev_program`, and `claim_has_new_program`.
Built-in withdraw values are `requested`, `sender`, `timestamp`, `claim_timestamp`, `program_balance`, `current_state`, `next_state`, `claim_mint_id`, `claim_prev_owner`, `claim_new_owner`, `claim_chain_depth`, `claim_has_prev_program`, and `claim_has_new_program`.

The recommended baseline pattern is:

- keep policy like `paused`, caps, and limits in `[constants]`
- describe permitted transitions rather than active bill operations
- gate both sections with `require !paused`
- reject zero-value requests early
- enforce min/max limits and caps with `require`
- treat `current_state` and `next_state` as bill-scoped commitments
- use `[links]` when a covenant must depend on one or more other covenant predicates
- use claim-context built-ins when the covenant must constrain the surrounding ownership claim
- use `after(...)`, `before(...)`, or `between(...)` when a withdraw path needs a timelock window
- bind receipt-friendly public outputs before the final `approve`

Deploys require a program name, for example `vess deploy ./my-program --name +vl_market1`.

The frozen V1 scope and invariants are documented in [`docs/v1-spec.md`](docs/v1-spec.md).

---

### Ownership model

Each bill has:

- a permanent `mint_id`,
- a `chain_tip`,
- a `chain_depth`,
- an owner verification key hash.

Genesis binds the first owner to the bill. Transfers advance the ownership chain with post-quantum signatures. Nodes replicate ownership records through the deterministic DHT location instead of global block production. Double spending is prohibitively difficult due to deterministic consensus rules rather than probabilistic chains.
When a bill is program-owned, the claim path still stays the same: the broadcaster submits an `OwnershipClaim`, but it carries `prev_owner_program` and a `program_spend_witness` so nodes can verify the receipt and ZK/STARK proof before accepting and forwarding the ownership rotation.

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

## License

Apache 2.0