# VessLogic — Covenant Language Reference

VessLogic is a deterministic covenant language for Vess smart contracts.
Programs are deployed via a small PoW and published through the DHT.
Bills locked to a program can only be unlocked when the claimant submits
an `OwnershipClaim` carrying the witness the covenant requires.

## Program Structure

A source file (e.g. `progname.vess`) is split into sections:

- `[constants]` — immutable configuration values.
- `[deposit]` — bill-in validation logic.
- `[withdraw]` — bill-out validation logic.
- `[links]` — optional linked covenant names.

Programs are **stateless** covenants. Mutable state lives on bills via
their ownership `state_commitment`, not inside the deployed program blob.
The covenant is passive: a wallet proposes its own deposit or withdraw
transition, and the covenant validates whether the proposed bill transition
is allowed.

Each executable section is one instruction per line and **must end in `approve`**.

## Instruction Forms

| Form | Description |
|---|---|
| `require <expr>` | Assertion; fails the transition if false. |
| `bind <name> = <expr>` | Bind a named value for later use. |
| `approve` | Commit the transition. Must be the final instruction. |

## Operators

| Category | Operators |
|---|---|
| Arithmetic | `+ - * / %` |
| Comparison | `== != < <= > >=` |
| Boolean | `! && \|\|` |
| Grouping | `( )` |

## Built-in Functions

`min(a, b)`, `max(a, b)`, `abs(x)`, `clamp(x, lo, hi)`,
`after(ts)`, `before(ts)`, `between(start, value, end)`,
`satisfies(link)`, `all_of(link_a, link_b, ...)`, `any_of(link_a, link_b, ...)`

## Built-in Values

**Deposit context:** `amount`, `sender`, `timestamp`, `claim_timestamp`,
`program_balance`, `current_state`, `next_state`, `claim_mint_id`,
`claim_prev_owner`, `claim_new_owner`, `claim_chain_depth`,
`claim_has_prev_program`, `claim_has_new_program`.

**Withdraw context:** `requested`, `sender`, `timestamp`, `claim_timestamp`,
`program_balance`, `current_state`, `next_state`, `claim_mint_id`,
`claim_prev_owner`, `claim_new_owner`, `claim_chain_depth`,
`claim_has_prev_program`, `claim_has_new_program`.

## Recommended Patterns

- Keep policy (`paused`, caps, limits) in `[constants]`.
- Describe permitted transitions rather than active bill operations.
- Gate both sections with `require !paused`.
- Reject zero-value requests early.
- Enforce min/max limits and caps with `require`.
- Treat `current_state` and `next_state` as bill-scoped commitments.
- Use `[links]` when a covenant depends on other covenant predicates.
- Use claim-context built-ins when the covenant constrains the ownership claim.
- Use `after(...)`, `before(...)`, or `between(...)` for timelock windows.
- Bind receipt-friendly public outputs before the final `approve`.

## Deployment

```
vess deploy ./my-program --name +vl_market1
```

The client canonicalizes the name (strips `+`), keys it on the DHT via
`Blake3("vl_market1")`, matching the same name-hash style used for VessTags.
