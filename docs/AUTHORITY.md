# Authority — V0A

This document is the binding statement of what the current phase of QntySpot
authorizes and forbids. If any other document in this repository (or any
sibling repository) appears to contradict it, this document wins for the
scope of `qntyspot/`.

```
PROJECT               = QntySpot
ACTIVE_PHASE           = QNTY_SPOT_V0A_OFFLINE_CORE_BOOTSTRAP
AUTHORITY              = OFFLINE_CORE_ONLY
NETWORK_AUTHORIZED     = NO
SIGNING_AUTHORIZED     = NO
LIVE_CAPITAL_AUTHORIZED = NO
CAPITAL_AUTHORITY      = NONE
```

These flags are also exported at runtime as `qntyspot.AUTHORITY`,
`qntyspot.NETWORK_AUTHORIZED`, `qntyspot.SIGNING_AUTHORIZED`, and
`qntyspot.LIVE_CAPITAL_AUTHORIZED`.

## V0A authorizes

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

## V0A forbids

- RPC access
- API access
- private-key access
- wallet signing
- transaction construction
- transaction broadcast
- live trading
- shadow network calls
- venue discovery
- automatic token selection
- bridging
- OpenSea execution

Enforcement is not aspirational. `tests/test_no_network.py` statically scans
every module under `qntyspot/` for forbidden imports (socket/HTTP libraries,
`web3`, `solana`/`solders`, subprocess, non-determinism sources) and for
ambient-secret or signing-related tokens in source code, and
`tests/conftest.py` disables the `socket` module for the entire test session.
Both checks are part of the required test suite.

## Asset selection

Asset selection belongs to the user. Runtime asset admission
(`qntyspot/identity.py`) is concerned with **exact canonical identity and
execution constraints** — chain id and contract address for EVM, cluster,
mint address, and token program for Solana — never with a ticker/symbol
lookup, and never with judging whether a project is good, bad, legitimate, or
likely to rug. `display_symbol` is an optional human label that explicitly
does not participate in identity or in any digest.

KRAKMASK is named in this repository only as a future user-selected Ink
fixture, once a V0B Ink shadow adapter exists. Its presence is not an
endorsement, a safety claim, or an assertion of legitimacy.

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

`qntyspot/boundary.py` defines the typing `Protocol`s a future adapter would
implement (`QuoteSource`, `ExecutionVenueAdapter`, `ChainTruthSource`,
`Reconciler`). None of them has an implementation in this phase, and importing
the module cannot cause a request, a signature, or a key read —
`tests/test_no_network.py::test_the_boundary_protocols_have_no_implementations`
asserts this.

## Changing this document

Any change that would set `NETWORK_AUTHORIZED`, `SIGNING_AUTHORIZED`, or
`LIVE_CAPITAL_AUTHORIZED` to `YES` is a phase transition (see
[docs/ROADMAP.md](ROADMAP.md)), not a routine edit, and requires its own
review.
