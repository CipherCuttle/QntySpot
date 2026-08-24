# QntySpot — agent entrypoint

Read this before modifying anything in this repository.

## Phase

```
ACTIVE_PHASE = QNTY_SPOT_V0B_INK_SHADOW
AUTHORITY    = INK_SHADOW_READ_ONLY
```

See [docs/AUTHORITY.md](docs/AUTHORITY.md) for the full, binding statement.
The short version: this repository has one bounded public-read Ink client, no
signer, no key handling, and no live-capital authority — from itself or from
any other repo in this workspace.

## Authority boundary with sibling repositories

QntySpot does **not** inherit live-capital authority from `Qnty`, `QntyLab`,
or `QntyAgentRuntime`.

- `Qnty`'s `quantbot/exec` package is a paper-only routing stub
  (`"Paper mode only - no real trading."`); it is not a live execution
  implementation and must never be treated as one.
- `QntyLab` is exploratory-only and must not claim scientific validation or
  trading authority.
- `QntyAgentRuntime` is a separate, contract-only agent-runtime project
  (`CURRENT_IMPLEMENTATION_AUTHORITY = CONTRACT_ONLY`, `CAPITAL_AUTHORITY =
  NONE`). It is not the home for QntySpot's execution logic, and QntySpot does
  not become a second control plane for it.

If a change would make QntySpot depend on any of those repositories for
capital, signing, or trading authority, stop and treat it as a
`SOURCE_CONFLICT`.

## Rules for this phase

- No third-party RPC library, HTTP client, or database server dependency. The
  bounded Ink adapter uses the standard library plus `pytest`; SQLite remains
  the V0A persistence substrate.
- No private-key or wallet-file access, anywhere, including in tests.
- No binary floating point for any economic quantity. Amounts are integer
  atomic units; prices and ratios are exact `Fraction`s; JSON floats are
  refused by the strict reader (`qntyspot/canon.py`).
- Every economic action has deterministic identity
  `(policy_id, instrument_id, cycle_id, level_id, side)` and the SQLite schema
  — not application code — enforces that it can exist at most once
  (`qntyspot/ledger/schema.py`, table `intents`).
- Malformed, unknown-field, duplicate-key, or non-canonical policy input fails
  closed. A missing policy fails startup. See `qntyspot/policy.py` and
  `docs/POLICY_V0.md`.
- State transitions are enumerated in `qntyspot/states.py`. Anything not
  enumerated is illegal. An unresolved external outcome maps to `SAFE_HALT`,
  never to a retry or a speculative reconstruction — see
  `qntyspot/ledger/recovery.py`.
- `tests/test_no_network.py` statically scans every module in `qntyspot/` for
  forbidden signing/key/venue-client imports, non-determinism, and
  ambient-secret access. Public standard-library transport is allowed only for
  the bounded Ink read path. `tests/conftest.py` additionally disables the
  `socket` module for the whole offline unit-test session. Keep both green; do
  not weaken either to make a change land.

## Before extending the domain model or the ladder

Read `docs/STATE_MACHINE.md` and `docs/POLICY_V0.md` first. The lifecycle
states already anticipate `SIGNED`/`SUBMITTED`/`INCLUDED`/`CONFIRMED` as
future venue steps — they are domain labels only in this phase, with no signer
and no network behind them. Do not add adapter code, venue discovery, or
automatic asset selection to reach those states; that begins in V0B and later
(`docs/ROADMAP.md`).

## Completion discipline

This repository follows: implement → test → one independent hostile review →
fix Critical/High → one targeted re-review only if Critical/High fixes were
required → commit. Do not skip the review step for changes that touch
`qntyspot/ledger/`, `qntyspot/policy.py`, or `qntyspot/states.py` — that is
where a duplicate-execution or budget-race regression would live.
