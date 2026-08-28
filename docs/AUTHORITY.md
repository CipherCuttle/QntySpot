# Authority — external authority-root contract phase

This document is the binding statement of what the current phase of QntySpot
authorizes and forbids. If any other document in this repository (or any
sibling repository) appears to contradict it, this document wins for the
scope of `qntyspot/`.

```
PROJECT                 = QntySpot
ACTIVE_PHASE            = QNTY_SPOT_EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0
AUTHORITY               = ROBINHOOD_SHADOW_READ_ONLY
NETWORK_AUTHORIZED      = YES (bounded public Robinhood REST/RPC, Chainlink, and 0x reads only)
SIGNING_AUTHORIZED      = NO
LIVE_CAPITAL_AUTHORIZED = NO
CAPITAL_AUTHORITY       = NONE
```

These flags are also exported at runtime as `qntyspot.AUTHORITY`,
`qntyspot.NETWORK_AUTHORIZED`, `qntyspot.SIGNING_AUTHORIZED`, and
`qntyspot.LIVE_CAPITAL_AUTHORIZED`.

The external authority-root contract is the active *offline contract* phase.
Naming it here changes no flag: `AUTHORITY` is still
`ROBINHOOD_SHADOW_READ_ONLY`, signing and live capital are still `NO`, and
capital authority is still `NONE`. The `NETWORK_AUTHORIZED = YES` flag remains
the historical bounded-public-read ceiling; this phase performs zero execution
or venue network activity. Program B architecture, B1 implementation, and
this external-root contract do not create live execution authority — see
[docs/PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md](PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md).

The frozen external-root consumer contract is documented in
[docs/EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0.md](EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0.md).
QntySpot consumes a serialized receipt plus an explicit external trust
configuration. It does not contain or select root private material, does not
self-issue, and does not treat a verified receipt as sufficient to escape the
source phase ceiling. The external root is not implemented or deployed in this
phase.

## The read-only shadow authority authorizes

- Deterministic, immutable domain models (`qntyspot/domain.py`,
  `qntyspot/identity.py`)
- Strict, fail-closed policy parsing (`qntyspot/policy.py`)
- SQLite state transitions with database-enforced invariants
  (`qntyspot/ledger/`)
- The offline Program B1 execution runtime over the existing SQLite core and
  execution schema (`qntyspot/ledger/execution.py`), including durable
  session, reservation, envelope, signed-metadata, submission, observation,
  reconciliation, kill-switch, and deterministic replay facts
- Deterministic replay from an empty database plus canonical policies and the
  event log (`qntyspot/ledger/replay.py`)
- Accounting primitives: atomic budget reservation, commit, release, and
  quarantine (`qntyspot/ledger/store.py`)
- Tests, including tests that simulate crash/restart and concurrent workers
- The already-merged bounded Ink shadow implementation remains available as
  historical V0B code; this phase does not change it
- The already-merged bounded Solana shadow implementation remains available as
  historical V0C code; this phase does not change it
- One bounded Robinhood REST/RPC, Chainlink, and 0x Swap API quote read for an
  explicit Stock Token / USDG pair
- Bounded finalized Solana RPC reads for exactly two policy-supplied mint
  accounts on one frozen cluster
- Current official Jupiter Swap V2 `GET /swap/v2/build` read-only quotes for
  an exact input size and exact mint pair
- Exact mint identity including the Token vs Token-2022 owner program,
  decimals, atomic amounts, route split, program identities, and explicit
  version-0/address-lookup-table semantics
- Deterministic policy-bound shadow decisions with canonical SHA-256 evidence
  and offline replay from frozen live evidence

## The read-only shadow authority forbids

- private-key access
- wallet signing
- transaction construction
- transaction broadcast
- live trading
- venue discovery
- automatic token selection
- bridging
- OpenSea execution
- wallet-secret access
- approvals
- transaction submission
- live capital

The public-read implementations are limited to `qntyspot/ink.py`,
`qntyspot/solana.py`, and `qntyspot/robinhood.py`. The Solana path validates Jupiter's raw instruction
evidence but does not assemble or serialize a transaction, trust any
third-party serialized payload, read a secret, or expose a submission method.
Offline unit tests disable sockets for the entire session; the one live
qualification is a separate, explicitly bounded read-only command. The
Robinhood path never constructs or submits the returned 0x transaction.

Enforcement is not aspirational. `tests/test_no_network.py` statically scans
every module under `qntyspot/` for forbidden signing/key/venue-client imports,
subprocess and non-determinism sources, and ambient-secret or signing-related
tokens in source code. `tests/conftest.py` disables the `socket` module for the
entire offline unit-test session. Both checks are part of the required suite.

## Robinhood V0D boundary

Robinhood `/assets` establishes the Stock Token UID, chain deployment,
decimals, multiplier, pending multiplier state, status, and trading
capabilities. `/prices` is raw underlying pricing and is multiplied exactly
once for the token reference price. Chainlink Stock Token answers already
include the multiplier. A missing authoritative Chainlink Sequencer Uptime
Feed is recorded as `UNAVAILABLE_NOT_PUBLISHED`, not as `SEQUENCER_DOWN`.
The only venue read is one 0x Swap API v2 AllowanceHolder quote on chain 4663.
Returned calldata is evidence only and is never submitted.

For V0D shadow qualification, an observation records its explicit local
observation timestamp, the RPC block timestamp, their signed difference, and
`MAX_RPC_FUTURE_SKEW_S = 30`. A negative difference is accepted; a difference
greater than 30 seconds fails closed. This is a technical shadow bound only,
not a V0H live-capital clock or sequencer-safety guarantee.

## Program B — pre-live execution contract (frozen design)

`QNTY_SPOT_PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0` freezes the execution
system later phases must satisfy. It authorizes nothing beyond what is already
listed above. In particular it does not authorize live capital, funding, token
approval, private-key access, transaction signing, transaction broadcast,
transaction submission, autonomous execution, daemon activation, or another 0x
qualification request.

The contract defines a monotone authority ladder:

```
LEVEL 0  SHADOW                      reads and deterministic decisions only
LEVEL 1  RECONCILE_ONLY              observe and reconcile; no signing, no submission
LEVEL 2  SUBMIT_EXACT_SIGNED_BYTES   submit one frozen signed identity only
LEVEL 3  HUMAN_SIGNED_EXECUTION      construct a validated envelope; a human signs
LEVEL 4  AUTONOMOUS_BOUNDED_SIGNER   a future, separately authorized signer
```

```
PHASE_GRANTED_AUTHORITY_LEVEL = LEVEL 0 (SHADOW)
```

`qntyspot/execution_contract.py` refuses every capability above `SHADOW` at
runtime, whatever level a caller passes and whatever any authority document
claims, because the ceiling is a constant in this source tree rather than an
input. Levels 1 through 4 are semantics only; each requires its own explicit
later phase.

`qntyspot/ledger/execution_schema.py` defines the execution authority tables.
The B1 runtime writes only explicit offline records supplied by its caller; it
does not create venue requests, sign, submit, or broadcast anything.

Program B adds no network call, no secret read, no signature, no approval, no
broadcast, and no capital. B1 adds the local transactional record/replay
surface and bounded calldata/hash validation, while preserving that same
authority boundary. The independently rooted external-authority verifier is
an explicit fail-closed seam in B1 and remains deferred.

## Asset selection

Asset selection belongs to the user. Runtime asset admission
(`qntyspot/identity.py`) is concerned with **exact canonical identity and
execution constraints** — chain id and contract address for EVM, cluster,
mint address, and token program for Solana — never with a ticker/symbol
lookup, and never with judging whether a project is good, bad, legitimate, or
likely to rug. `display_symbol` is an optional human label that explicitly
does not participate in identity or in any digest.

KRAKMASK remains the historical user-selected V0B Ink fixture. The V0C
qualification fixture is the exact WSOL/USDC mint pair in
`qualifications/solana_v0c/`; neither fixture is an endorsement, a safety
claim, a recommendation, or an assertion of legitimacy.

## Authority does not flow in from sibling repositories

QntySpot does not inherit live-capital authority from `Qnty`, `QntyLab`, or
`QntyAgentRuntime`. See [AGENTS.md](../AGENTS.md#authority-boundary-with-sibling-repositories)
for the reconciliation record.

## Chain truth boundary (implemented offline, still no chain client)

- chain/venue truth is authoritative for actual fills
- the local database is authoritative for intended actions
- reconciliation converts external truth into a canonical `FillReceiptV0`
- ambiguity causes `SAFE_HALT`, never speculative reconstruction

`qntyspot/boundary.py` defines the typing `Protocol`s for the chain/venue
boundary. V0B implements the Ink `QuoteSource`; V0C adds the Solana/Jupiter
`QuoteSource`; V0D adds the Robinhood shadow `QuoteSource`. The B1 runtime
  implements the chain-truth and reconciliation rules over caller-supplied
  persisted records; it does not implement a `ChainTruthSource` or reach a
  chain. It records an accepted-but-absent or contradictory outcome as
  `SAFE_HALT`, and releases a post-submission reservation only after an exact
  database-bound `REVERTED` reconciliation.

Program B gives that rule an evidence contract:
`qntyspot.execution_contract.evaluate_chain_truth` decides what a set of
provider observations may conclude, and `reconcile_to_receipt` is the only path
from external truth to a `FillReceiptV0`. Both are pure functions over records
the caller supplies; neither reads a chain. No venue adapter implements
`ChainTruthSource` or `Reconciler` yet; the B1 runtime only consumes persisted
records.

## Changing this document

Any change that would set `NETWORK_AUTHORIZED`, `SIGNING_AUTHORIZED`, or
`LIVE_CAPITAL_AUTHORIZED` to `YES` is a phase transition (see
[docs/ROADMAP.md](ROADMAP.md)), not a routine edit, and requires its own
review.
