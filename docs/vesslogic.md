# VessLogic

VessLogic is the human-facing source language for deployed Vess programs.

It is intentionally small:

- one source file, usually `progname.vess`
- one instruction per line
- no braces, JSON, or indentation rules
- explicit `[deposit]` and `[withdraw]` sections
- stateless covenant logic only

## File layout

Sections appear in this order:

```text
[constants]
[links]
[deposit]
[withdraw]
```

`[constants]` is optional.
`[links]` is optional.
`[deposit]` and `[withdraw]` are required.

`[links]` lets a covenant name other linked covenant predicates that must also be satisfied by the surrounding proof or ownership-claim flow. Each line is one identifier:

```text
[links]
compliance_guard
risk_guard
```

There is no `[state]` section. Deployed programs are stateless covenants. Mutable state belongs to bills and is carried through ownership `state_commitment` values.

The covenant does not move bills by itself. Another node or wallet actor must construct a deposit or withdraw attempt, and the covenant only decides whether that attempted transition satisfies the rules.

The main verification point is the bill ownership path, not a separate contract runtime. A deposit into a covenant is an `OwnershipClaim` that makes `new_owner_program` the owner. A withdrawal is another `OwnershipClaim` that spends from `prev_owner_program` back to a user key or onward to another program. Nodes verify those ownership claims while gossiping them.

## Types

VessLogic currently supports:

- `u64`
- `bool`
- `address`
- `bytes32`

Declarations use this shape:

```text
u64 min_deposit = 5
bool paused = false
```

## Instructions

Inside `[deposit]` and `[withdraw]`, each line must be exactly one instruction:

```text
require <expr>
bind <name> = <expr>
approve
```

`approve` must be the final line of the section.

`bind` does not mutate program state. It names a public output that the surrounding receipt or proof is expected to expose and commit to.

## Built-ins

`[deposit]` can reference:

- `amount`
- `sender`
- `timestamp`
- `claim_timestamp`
- `program_balance`
- `current_state`
- `next_state`
- `claim_mint_id`
- `claim_prev_owner`
- `claim_new_owner`
- `claim_chain_depth`
- `claim_has_prev_program`
- `claim_has_new_program`

`[withdraw]` can reference:

- `requested`
- `sender`
- `timestamp`
- `claim_timestamp`
- `program_balance`
- `current_state`
- `next_state`
- `claim_mint_id`
- `claim_prev_owner`
- `claim_new_owner`
- `claim_chain_depth`
- `claim_has_prev_program`
- `claim_has_new_program`

Both sections can also reference anything declared in `[constants]` or `[links]`.

`current_state` and `next_state` model bill-scoped commitments. They are how a covenant reasons about bill evolution without owning mutable program storage.

That means VessLogic constrains proposed transitions; it does not execute them. If a flow needs bill splitting, combining, routing, or payout construction, an external actor assembles that bill operation and the covenant checks whether it is allowed.

For program-owned withdrawals, that check is carried by the ordinary ownership-claim message: the withdrawer broadcasts an `OwnershipClaim` with a `program_spend_witness`, and receiving nodes verify the receipt, proof-system match, and proof hashes before they accept the new ownership state.

## Operators and functions

Allowed operators:

- arithmetic: `+ - * / %`
- comparison: `== != < <= > >=`
- boolean: `! && ||`
- grouping: `(` `)`

Allowed built-in functions:

- `min(a, b)`
- `max(a, b)`
- `abs(x)`
- `clamp(x, lo, hi)`
- `after(ts)`
- `before(ts)`
- `between(start, value, end)`
- `satisfies(link)`
- `all_of(link_a, link_b, ...)`
- `any_of(link_a, link_b, ...)`

These link-oriented helpers are declarative. They let a VessLogic source file express that the current covenant depends on other linked covenant predicates, even though the actual proof/execution wiring still happens on the ownership-claim / witness path.

The timelock helpers are also declarative. In practice they are shorthand around the ownership-claim timestamp context, so a withdraw rule can say things like `require after(withdraw_unlock_at)` or `require between(window_start, claim_timestamp, window_end)`.

## Recommended patterns

For basic safety and usability, programs should usually:

- keep pause flags, caps, and other policy in `[constants]`
- describe admission and exit rules, not active bill movement logic
- start both `[deposit]` and `[withdraw]` with `require !paused`
- reject zero-value actions with `require amount > 0` or `require requested > 0`
- enforce minimums, caps, and availability with `require`
- use `current_state` and `next_state` when the covenant needs to constrain bill transitions
- use `[links]` when one covenant must be chained behind one or more other covenant predicates
- use claim-context built-ins when the rule depends on the surrounding ownership claim shape
- expose important output facts with `bind`
- end only after all checks, with `approve`

## Example

```text
[constants]
u64 min_deposit = 5
u64 max_withdraw = 250
u64 cap = 1000
u64 withdraw_unlock_at = 86400
bool paused = false

[links]
compliance_guard
risk_guard

[deposit]
require !paused
require amount >= min_deposit
require program_balance + amount <= cap
require all_of(compliance_guard, risk_guard)
require claim_has_new_program || claim_chain_depth >= 1
bind credited = amount
bind locked_state = next_state
approve

[withdraw]
require !paused
require requested > 0
require requested <= max_withdraw
require requested <= program_balance
require satisfies(compliance_guard)
require claim_has_prev_program
require after(withdraw_unlock_at)
bind debited = requested
bind prior_state = current_state
bind next_locked_state = next_state
approve
```

## Deploying

`vess deploy` accepts either:

- a `.vess` source file directly
- a directory containing exactly one `.vess` file

Every deploy must also provide a human-facing program name in the `+vl_<name>` namespace, where `<name>` is 3-25 lowercase ASCII alphanumeric characters.

Examples:

```text
vess deploy ./examples/vesslogic --name +vl_market1
vess deploy ./examples/vesslogic/progname.vess --name +vl_escrow7
```

The `+` is display-only. Vess canonicalizes `+vl_market1` to `vl_market1`, then keys it on the DHT by `Blake3("vl_market1")`, the same way tags are keyed by the hash of their canonical name.

The source is parsed, normalized into canonical VessLogic bytes, and that compiled representation is what commits to the final `prog_id`.