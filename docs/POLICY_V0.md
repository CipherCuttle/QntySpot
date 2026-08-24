# PolicyV0

`qntyspot/policy.py` implements the strict reader. This document describes the
schema it accepts (`schema: "qntyspot.policy.v0"`) and the contract around it.
`tests/fixtures/krakmask_ink_buy.policy.json` is a complete worked example.

## Admission contract

- **Missing policy fails startup** (`PolicyMissingError`): `None`, empty, or
  whitespace-only input.
- **Malformed JSON fails closed** (`CanonicalFormError`).
- **A duplicate JSON key fails closed**, at any depth, enforced by the strict
  reader in `qntyspot/canon.py` before the schema is even consulted.
- **An unknown key fails closed**, at every depth — the top level, every
  section, every ladder level, every instrument reference. V0A declares no
  extension point. There is exactly one optional block (`recycling`; see
  below).
- **A JSON float fails closed.** Economic values are canonical decimal
  strings; counts, timestamps, and basis points are JSON integers.
- **Non-canonical decimal strings fail closed.** `"1.0"`, `"01"`, `"+1"`,
  `"1e3"` are all refused — see `qntyspot/canon.py::CANONICAL_DECIMAL_RE` for
  the exact grammar. This repository picked **reject**, not *canonicalize*,
  as its contract for the value layer; document layer canonicalization (key
  order, whitespace) is separate and is what the digest is taken over.

## Shape

```jsonc
{
  "schema": "qntyspot.policy.v0",
  "policy_name": "string, 1..128 chars",
  "side": "BUY" | "SELL",
  "base":  { "ref": <InstrumentRef>, "decimals": 0..36, "asset_class"?: "FUNGIBLE", "display_symbol"?: "string" },
  "quote": { "ref": <InstrumentRef>, "decimals": 0..36, "asset_class"?: "FUNGIBLE", "display_symbol"?: "string" },
  "entry_ladder": { "levels": [ <LadderLevel>, ... ] },   // side of `side`
  "exit_ladder":  { "levels": [ <LadderLevel>, ... ] },   // opposite side
  "capital": {
    "allocation_quote": "decimal", "per_order_cap_quote": "decimal",
    "per_instrument_cap_quote": "decimal", "per_network_cap_quote": "decimal",
    "global_portfolio_cap_quote": "decimal", "reserved_cash_quote": "decimal"
  },
  "limits": {
    "max_executable_price": "decimal", "min_executable_price": "decimal",
    "max_price_impact_bps": 0..10000, "max_slippage_bps": 0..10000
  },
  "timing": {
    "valid_from_epoch_s": int, "expiry_epoch_s": int, "quote_ttl_s": 1..86400
  },
  "reentry": {
    "max_cycles": 1..10000, "rearm_hysteresis_bps": 0..10000,
    "rearm_cooldown_s": int
  },
  "recycling"?: {                 // OPTIONAL. Absent = { "0", "0" }, the
    "profit_recycle_ratio": "decimal",  // inert choice, not a recommendation.
    "banked_profit_ratio": "decimal"
  }
}
```

`<InstrumentRef>` is one of:

```jsonc
{ "namespace": "evm", "chain_id": <int, 1..2**63-36>, "contract_address": "0x" + 40 lowercase hex }
{ "namespace": "solana", "cluster": "mainnet-beta"|"devnet"|"testnet",
  "mint_address": "<base58, decodes to 32 bytes>", "token_program": "SPL_TOKEN"|"TOKEN_2022" }
```

`<LadderLevel>` (entry): `{ "level_id": str, "trigger_price": "decimal", "input_amount": "decimal" }`
`<LadderLevel>` (exit): `{ "level_id": str, "trigger_price": "decimal", "input_ratio": "decimal in (0,1]" }`

## Cross-field rules

- `base` and `quote` must differ, share a namespace, and share a network — V0
  performs no bridging.
- `entry_ladder` trigger prices strictly monotone in the direction of `side`
  (descending for BUY, ascending for SELL); same for `exit_ladder` in the
  opposite side. Level ids are unique across both ladders.
- `exit_ladder` `input_ratio` values sum to at most 1.
- Caps nest: `per_order_cap <= allocation <= per_instrument_cap <=
  per_network_cap <= global_cap`, and `reserved_cash < global_cap` (otherwise
  no order could ever be admitted).
- A rung whose `trigger_price`, even before slippage, is already outside
  `[min_executable_price, max_executable_price]` is refused at parse time — it
  could never execute. A rung's *total notional* is **not** required to fit
  inside `allocation_quote`: a ladder may be deliberately provisioned deeper
  than the capital behind it. That cap is enforced per-reservation in the
  ledger instead, where it can account for what other actions already hold.
- `recycling`, when present, requires both keys; their sum must not exceed 1.

## Digest identity

`PolicyV0.policy_id` is the SHA-256 hex digest of the policy's canonical JSON
form (`qntyspot.canon.digest_object`): sorted keys, minimal separators, ASCII
escaping. Key order and whitespace in the input document do not affect it, and
`display_symbol` is excluded from every instrument's identity object, so
relabelling an instrument does not change the policy's digest.

The canonical form is itself an admissible policy document:
`parse_policy(policy.canonical)` reproduces the same `policy_id`. That is what
lets `qntyspot.ledger.replay` rebuild policies from the canonical JSON stored
in the `policies` table.
