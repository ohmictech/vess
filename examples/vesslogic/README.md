# VessLogic — Sending To and Withdrawing From Programs

This directory contains example VessLogic covenants and walkthroughs for
using them in the Vess payment network.

## Quick Reference

| Action | CLI Command |
|---|---|
| Deploy a program | `vess deploy ./my-program --name +vl_market1` |
| Send bills to a program | `vess send <amount> +vl_market1` |
| Withdraw bills from a program | Handled automatically when you claim with a valid witness |

---

## How Program-Owned Bills Work

When you send Vess to a program tag (e.g. `+vl_market1`), the payment is
structured so that the **program becomes the owner** of those bills.
The recipient's `OwnershipClaim` must include a `ProgramSpendWitness`
that satisfies the program's deposit predicate.

### Sending to a Program

Sending to a program is identical to sending to a person:

```bash
vess send 100 +vl_market1
```

Under the hood, the CLI:

1. Resolves `+vl_market1` to the program's DHT manifest (containing the
   program ID and ownership condition).
2. Builds an `OwnershipClaim` with `new_owner_program = Some(condition)`.
3. Signs the claim and broadcasts it via gossip.

The program's `[deposit]` section is evaluated against the claim. If
it reaches `approve`, the bill is accepted with the program as owner.

### Withdrawing from a Program

To unlock bills held by a program, you need a valid **compute receipt**
(witness) proving you satisfy the program's `[withdraw]` predicate.

The flow:

1. **Claim the bill**: Your wallet trial-decrypts the payment and
   produces an `OwnershipClaim` with `prev_owner_program = Some(condition)`.
2. **Generate a witness**: The `vess-compute` crate evaluates the
   program's `[withdraw]` section against your proposed transition.
   If it reaches `approve`, the compute node produces a signed receipt.
3. **Submit the claim**: Your node broadcasts the `OwnershipClaim`
   with the `ProgramSpendWitness` attached.

This happens automatically when you auto-receive a payment addressed
to a program tag — your node handles the witness generation and claim
submission.

### Manual Program Unlock (CLI)

For manual control, you can build a program unlock claim:

```bash
# Build a program spend witness for bills locked to +vl_market1
vess program-unlock --program +vl_market1 --recipient +alice
```

This generates the witness, builds the claim, and broadcasts it.

---

## Program Receipts — Bearer Credentials for Program Interaction

When you deposit bills into a program, your node generates a **`ProgramReceipt`** —
a cryptographic proof that the program accepted your deposit. This receipt is:

- **Signed** by your spend key (proving you authorized the deposit)
- **Gossiped** back to your node via the mesh
- **Transferable** — you can forward it inside a `Payment` to another party

### Why Transferable Receipts Matter

Program receipts are **bearer credentials**. Whoever holds a valid receipt
can present it alongside a `ProgramSpendWitness` to attempt a program unlock.
This enables trustless program interaction:

1. **Alice** deposits 100 Vess into `+vl_escrow1` → gets a `ProgramReceipt`
2. **Alice** sends the receipt to **Bob** inside a `Payment`
3. **Bob** presents the receipt + his witness to unlock the escrow
4. The program verifies the receipt is valid and the witness satisfies `[withdraw]`

Without transferable receipts, the depositor would need to be online to
authorize the withdrawal — the receipt decouples deposit from withdrawal.

### Sending a Program Receipt

To forward a receipt you received (e.g., as escrow depositor) to the
intended recipient:

```bash
vess send-receipt <payment-id> +bob
```

This wraps the `ProgramReceipt` in a `Payment` envelope addressed to Bob.
Bob's node stores the receipt and can use it when building the unlock claim.

### Receiving and Using a Receipt

When you receive a payment containing a `program_receipt`, your node:

1. Stores the receipt keyed by `program_id`
2. When you attempt to unlock bills from that program, your node
   automatically includes the receipt in the `OwnershipClaim`
3. Verifying nodes check the receipt signature against the depositor's
   owner_vk before accepting the unlock

### Receipt Verification

Any node can verify a `ProgramReceipt`:
```rust
let digest = blake3_hash(
    b"vess-program-receipt-v0"
    || program_id || payment_id || claimed_mint_ids
    || total_amount || resulting_state || depositor_owner_vk || timestamp
);
verify_spend(&receipt.depositor_owner_vk, &digest, &receipt.signature)
```

---

## Example: Escrow Covenant

`escrow.vess` — A two-party escrow that releases funds after a timelock
or with both parties' approval:

```vess
[constants]
u64 release_at = 1750000000
u64 max_deposit = 500
bool paused = false

[links]
buyer_guard
seller_guard

[deposit]
require !paused
require amount <= max_deposit
require all_of(buyer_guard, seller_guard)
bind locked_until = release_at
approve

[withdraw]
require !paused
require after(release_at)
require satisfies(seller_guard)
bind released = requested
approve
```

### Using the Escrow

1. **Deploy**: `vess deploy ./escrow.vess --name +vl_escrow1`
2. **Deposit**: `vess send 100 +vl_escrow1` — the bill is now locked
3. **Withdraw (after timelock)**: The seller's node auto-unlocks after
   `release_at` by generating a witness that satisfies `seller_guard`
   and `after(release_at)`.

---

## Example: Time-Locked Vault

`vault.vess` — A personal vault that can only be withdrawn after a date:

```vess
[constants]
u64 unlock_at = 1750000000
u64 min_deposit = 10
bool paused = false

[deposit]
require !paused
require amount >= min_deposit
bind locked_until = unlock_at
approve

[withdraw]
require !paused
require after(unlock_at)
require requested <= program_balance
bind withdrawn = requested
approve
```

### Using the Vault

1. **Deploy**: `vess deploy ./vault.vess --name +vl_vault1`
2. **Deposit**: `vess send 50 +vl_vault1`
3. **Wait**: The bill is locked until `unlock_at`
4. **Withdraw**: After `unlock_at`, claim the bill — your node generates
   the witness and broadcasts the claim automatically.

---

## Program Link Resolution

When a program references other programs via `[links]`, the `satisfies()`
and `all_of()` functions resolve those links by looking up the linked
program on the DHT and evaluating its predicate.

```
[links]
compliance_guard
risk_guard

[deposit]
require all_of(compliance_guard, risk_guard)
```

This means: "This deposit is valid only if BOTH `compliance_guard` AND
`risk_guard` evaluate to true for this transaction."

---

## See Also

- [VessLogic Language Reference](../../docs/vess-logic.md) — Full syntax and built-in values
- [Deployment Guide](../../docs/deployment.md) — Running a node and deploying programs
- [progname.vess](./progname.vess) — Annotated example covenant
