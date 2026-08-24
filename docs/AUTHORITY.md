# Authority — V0B Ink shadow

This document is the binding statement of what the current phase of QntySpot
authorizes and forbids. If any other document in this repository (or any
sibling repository) appears to contradict it, this document wins for the
scope of `qntyspot/`.

```
PROJECT                 = QntySpot
ACTIVE_PHASE            = QNTY_SPOT_V0B_INK_SHADOW
AUTHORITY               = INK_SHADOW_READ_ONLY
NETWORK_AUTHORIZED      = YES (Ink public JSON-RPC reads only)
SIGNING_AUTHORIZED      = NO
LIVE_CAPITAL_AUTHORIZED = NO
CAPITAL_AUTHORITY       = NONE
```

These flags are also exported at runtime as `qntyspot.AUTHORITY`,
`qntyspot.NETWORK_AUTHORIZED`, `qntyspot.SIGNING_AUTHORIZED`, and
`qntyspot.LIVE_CAPITAL_AUTHORIZED`.

## V0B authorizes

- Deterministic, immutable domain models (`qntyspot/domain.py`,
  `qntyspot/identity.py`)
- Strict, fail-closed policy parsing (`qntyspot/policy.py`)
- SQLite state transitions with database-enforced invariants
  (`qntyspot/ledger/`)
- Deterministic replay from an empty database plus canonical policies and the
  event log (`qntyspot/ledger/replay.py`)
- Accounting primitives: atomic budget reservation, commit, release, and
  quarantine (`qntyspot/ledger/store.py`)
- Tests, including tests that simulate crash/restart and concurrent workers
- Bounded public reads from exactly two caller-supplied Ink JSON-RPC endpoints
- Exact KRAKMASK/WETH9 InkySwap V2 pool observation at a common historical block
- Deterministic constant-product market quotation and policy shadow decisions
- Write-once canonical observation and decision evidence, plus offline replay

## V0B forbids

- private-key access
- wallet signing
- transaction construction
- transaction broadcast
- live trading
- venue discovery
- automatic token selection
- bridging
- OpenSea execution
- Solana and Robinhood adapters

The public-read implementation is limited to `qntyspot/ink.py`. It does not
construct calldata, create a transaction object, read a key, or expose a
submission method. Offline unit tests disable sockets for the entire session;
the live qualification is a separate, explicitly bounded read-only command.

Enforcement is not aspirational. `tests/test_no_network.py` statically scans
every module under `qntyspot/` for forbidden signing/key/venue-client imports,
subprocess and non-determinism sources, and ambient-secret or signing-related
tokens in source code. `tests/conftest.py` disables the `socket` module for the
entire offline unit-test session. Both checks are part of the required suite.

## Asset selection

Asset selection belongs to the user. Runtime asset admission
(`qntyspot/identity.py`) is concerned with **exact canonical identity and
execution constraints** — chain id and contract address for EVM, cluster,
mint address, and token program for Solana — never with a ticker/symbol
lookup, and never with judging whether a project is good, bad, legitimate, or
likely to rug. `display_symbol` is an optional human label that explicitly
does not participate in identity or in any digest.

KRAKMASK is present as the user-selected V0B Ink fixture. Its presence is not
an endorsement, a safety claim, or an assertion of legitimacy.

## Authority does not flow in from sibling repositories

QntySpot does not inherit live-capital authority from `Qnty`, `QntyLab`, or
`QntyAgentRuntime`. See [AGENTS.md](../AGENTS.md#authority-boundary-with-sibling-repositories)
for the reconciliation record.

## Chain truth boundary (documented, not implemented)

A future rule, not yet implemented:

- chain/venue truth is authoritative for actual fills
- the local database is authoritative for intended actions
- reconciliation converts external truth into a canonical `FillReceiptV0`
- ambiguity causes `SAFE_HALT`, never speculative reconstruction

`qntyspot/boundary.py` defines the typing `Protocol`s for the chain/venue
boundary. V0B implements only `QuoteSource` through the read-only Ink shadow
adapter. `ExecutionVenueAdapter`, `ChainTruthSource`, and `Reconciler` remain
unimplemented.

## Changing this document

Any change that would set `NETWORK_AUTHORIZED`, `SIGNING_AUTHORIZED`, or
`LIVE_CAPITAL_AUTHORIZED` to `YES` is a phase transition (see
[docs/ROADMAP.md](ROADMAP.md)), not a routine edit, and requires its own
review.
