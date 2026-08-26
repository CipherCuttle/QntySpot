# Architecture

## Module map

```
qntyspot/
  canon.py       exact decimal <-> Fraction, strict JSON admission, canonical
                 digests. The one place numbers cross the text/machine boundary.
  identity.py    InstrumentV0 and its EVM / Solana identity references. Exact
                 canonical identifiers only; symbols never establish identity.
  states.py      IntentState and the enumerated legal-transition table.
  errors.py      the error taxonomy. Every error here means fail closed.
  domain.py      the immutable dataclasses: PolicyV0, LadderV0/LadderLevelV0,
                 CycleV0, IntentV0, QuoteV0, ExecutionPlanV0, FillReceiptV0,
                 PortfolioBudgetV0, RuntimeStateV0, EconomicBounds.
  policy.py      the strict PolicyV0 reader. Unknown fields fail closed at
                 every depth; there is no extension point in V0A.
  economics.py   turns a policy rung into an EconomicBounds / IntentV0: the
                 absolute limit contract. No clock reads, no I/O.
  boundary.py    typing Protocols for the chain/venue truth boundary.
  execution_contract.py
                 the frozen Program B pre-live execution contract: the
                 authority ladder, ExecutionSessionV0, ExecutionEnvelopeV0,
                 ApprovalActionV0, SignedTransactionRecordV0,
                 SubmissionAttemptV0, ChainObservationV0, and the deterministic
                 validators over them. Authorizes nothing.
  ink.py         bounded dual-RPC Ink observation, exact V2 quote arithmetic,
                 canonical shadow decisions, immutable evidence, and replay.
  solana.py      bounded finalized Solana mint reads and current Jupiter Swap
                 V2 exact-input observations, route/program evidence,
                 version-0/ALT semantics, canonical decisions, and replay.
  ledger/
    schema.py    the SQL schema and its integrity rules (append-only triggers,
                 uniqueness constraints, foreign keys).
    atomics.py   big-integer atomic amounts stored as SQLite TEXT, with SQL
                 user functions for exact arithmetic inside the budget guard.
    store.py     SpotLedger: admission, cycles, intents, transitions, budget
                 reservation, fill receipts, snapshots, integrity checks.
    replay.py    deterministic reconstruction from policies + event log.
    recovery.py  restart recovery: sorts every non-terminal intent into
                 ABANDON / RECONCILIATION_REQUIRED / COMPLETE_FROM_RECEIPT.
    execution_schema.py
                 the Program B execution authority surface: STRICT tables for
                 sessions, envelopes, approvals, external actions, signed
                 transactions, submissions, observations, reconciliations and
                 operator control. Created on demand; written by nothing.
```

## Data flow

```
PolicyV0 (text)
   │  qntyspot.policy.parse_policy   (fail closed)
   ▼
PolicyV0 (object) ──digest──▶ policy_id
   │
   │  SpotLedger.admit_policy
   ▼
policies / instruments / ladder_levels tables
   │
   │  SpotLedger.open_cycle
   ▼
cycles table (OPEN)
   │
   │  qntyspot.economics.build_intent(policy, cycle_id, level, now_epoch_s)
   ▼
IntentV0 (ARMED) ──economic_action_id = f(policy_id, instrument_id,
   │                                       cycle_id, level_id, side)
   │  SpotLedger.create_intent        (DB enforces uniqueness)
   ▼
intents table (ARMED)
   │
   │  SpotLedger.transition(..., RESERVED, ...)   (atomic cap guard)
   ▼
budget_reservations table (ACTIVE) ── caps checked in one SQL statement
   │
   │  SpotLedger.transition(..., SIGNED/SUBMITTED/... , ...)
   │  (domain labels only — no signer, no network, in V0A)
   ▼
   ...
   │
   │  SpotLedger.append_fill_receipt(FillReceiptV0, ...)
   ▼
fill_receipts table, bounds checked ──▶ CONFIRMED/RECONCILED or SAFE_HALT
   │
   │  SpotLedger.transition(..., FILLED, ...)
   ▼
intents table (FILLED), budget_reservations (COMMITTED)
```

Every step above that changes state does so inside one SQLite write
transaction that also appends the `state_events` row explaining it. That is
what makes the append-only log — `state_events` plus the admitted
`policies` — a sufficient input for `qntyspot.ledger.replay.reconstruct`.

## Ink shadow data flow

```
RPC A/B heads
   │  chain-id check + bounded head-lag check
   ▼
common historical block
   │  code, factory, getPair, token0, token1, getReserves at that block
   ▼
agreeing INK_MARKET_OBSERVATION_V0 ──SHA-256──▶ immutable evidence
   │
   │  integer V2 quote (997/1000) + exact Fraction metrics
   ▼
SHADOW_DECISION_V0 ──references observation digest──▶ offline replay
```

The V0B market identity is fixed to KRAKMASK/WETH9 and the verified InkySwap
V2 factory/pool. A provider disagreement, identity mismatch, absent bytecode,
zero reserves, or stale observation fails closed. The quote is a market-state
simulation only; it is not a transaction simulation.

## Solana V0C shadow data flow

```
PolicyV0 exact mint pair + exact atomic input
   │
   ├─ finalized getLatestBlockhash / getBlockHeight
   ├─ finalized getMultipleAccounts (mint owner + decimals)
   └─ Jupiter Swap V2 GET /build
         │ exact input/output + bps + instructions + ALT map + blockhash
         ▼
SOLANA_MARKET_OBSERVATION_V0 ──SHA-256──▶ immutable evidence
   │
   │ exact human-unit Fraction price, strict stale slot/height checks
   ▼
SHADOW_DECISION_V0 ──policy/economic-action identity──▶ offline replay
```

The Jupiter response is evidence, not authority. The adapter never accepts a
serialized third-party payload, never interprets raw instruction bytes as a
trusted execution plan, and never silently labels an empty lookup map as a
legacy message. A non-empty lookup map is explicitly recorded as version 0;
an omitted map fails closed.

## Why SQLite carries big integers as TEXT

SQLite's native `INTEGER` is signed 64-bit. An 18-decimal token exceeds that
range at roughly 9.22 whole units, so storing atomic amounts as `INTEGER`
would silently cap or overflow on an ordinary-sized ladder. `qntyspot/ledger/
atomics.py` stores every atomic amount as canonical decimal-digit `TEXT` and
registers SQLite user functions (`atomic_add`, `atomic_sub`, `atomic_le`,
`atomic_sum`, `atomic_min`) backed by Python's arbitrary-precision `int`, so
the budget guard stays a single SQL statement — preserving its atomicity —
while remaining exact at any magnitude. `tests/test_budget.py::
test_caps_are_exact_far_beyond_64_bit_range` exercises this directly.

## Why replay does not re-run the budget guard

Replay reconstructs projections from the log; it does not re-decide whether an
action should have been admitted. Re-running the cap guard during replay would
let a change in cap arithmetic silently rewrite recorded history. What replay
does check is that the log is internally self-consistent: sequence numbers
strictly increase, every transition it replays is legal under the current
state machine, and no event references an action not yet created. See the
module docstring in `qntyspot/ledger/replay.py`.

## The Program B pre-live execution contract

`qntyspot/execution_contract.py` and `qntyspot/ledger/execution_schema.py`
describe the execution runtime a later phase must build. They are records,
digests, deterministic validators and a SQLite schema — no I/O, no clock, no
signer, no submission surface, and no capability above `SHADOW`.

The shape worth knowing here is the four-way partition on
`ExecutionEnvelopeV0`. Its *identity* digest covers only what determines what
the chain would do plus who authorized it; *evidence* (plan, quote, block,
construction time) is digested separately; *mutable observation* lives on the
approval and chain-observation records instead; and the authority-policy digest
is identity rather than evidence. Because evidence is excluded from identity,
reconstructing the same intent after a crash produces the same `envelope_id`,
and the database primary key turns reconstruction into a no-op rather than a
duplicate.

The database, not application code, carries the exactly-once guarantee into
execution: `signed_transactions.external_action_id` is UNIQUE, so one
`EconomicActionID` can never hold two economically distinct signed
transactions, and an exact-byte retransmission reuses the same row because
`signed_transaction_id` digests the envelope identity and the payload digest.

See [docs/PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md](PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md).

## FUTURE_DEFERRED: NFT execution

The core does not assume every `Instrument` is fungible: `AssetClass` is a
stated fact (`qntyspot/identity.py`), and V0A admits exactly one member,
`FUNGIBLE`. A future OpenSea/Seaport adapter would introduce its own
Instrument and Intent semantics behind the `ExecutionVenueAdapter` seam in
`qntyspot/boundary.py`, without changing the fungible V0 execution contracts.
No collection, trait, floor-price, or bidding model exists in this phase, and
none is added speculatively.
