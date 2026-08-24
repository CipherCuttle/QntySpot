# State machine

`qntyspot/states.py` defines `IntentState` and the complete legal-transition
table `TRANSITIONS`. Every ordered pair of states is either legal (enumerated)
or illegal (refused by `assert_legal_transition`); there is no third case, and
`tests/test_states.py` exercises all 121 ordered pairs (11 states squared)
exhaustively, both the 38 legal ones and the 187 illegal ones (self-pairs plus
the rest are also illegal).

## States

| State          | Meaning in V0A |
|----------------|----------------|
| `ARMED`        | An `IntentV0` exists. Nothing has been evaluated against the market yet. |
| `TRIGGERED`    | The rung's price condition is judged to have been met. |
| `QUOTE_PINNED` | A `QuoteV0` has been attached (in V0A, always from a local fixture). |
| `SIMULATED`    | The intent has been checked against everything computable offline. |
| `RESERVED`     | Budget has been reserved. This is the last state before anything venue-visible could happen, and the last state from which `CANCELLED`/`EXPIRED` are reachable. |
| `SIGNED`       | **Domain label only.** No signer exists in V0A. |
| `SUBMITTED`    | **Domain label only.** No network exists in V0A. |
| `INCLUDED`     | **Domain label only.** |
| `CONFIRMED`    | **Domain label only.** |
| `RECONCILED`   | External truth (a `FillReceiptV0`) has been matched to this intent. |
| `FILLED`       | Terminal happy path. Reachable only from `RECONCILED`. |
| `CANCELLED`    | Terminal. Reachable only from the pre-commitment states (`ARMED` .. `RESERVED`). |
| `EXPIRED`      | Terminal. Same reachability as `CANCELLED`. |
| `REJECTED`     | Terminal. Reachable from `ARMED` through `INCLUDED`. |
| `SAFE_HALT`    | Terminal. Reachable from every non-terminal state. |

## Why `SIGNED`/`SUBMITTED`/`INCLUDED`/`CONFIRMED` exist with no signer or network

A future live runtime needs these states to represent "a transaction may
already exist outside this process." Modelling them now — with their
transitions restricted so the pre-commitment escapes (`CANCELLED`, `EXPIRED`)
are unreachable once `SIGNED` — means the *recovery* logic for them can be
designed, tested, and hostile-reviewed before there is a signer to make them
real. Nothing in this repository can reach these states except an explicit
local call from a test or (later) an adapter; there is no signer and no
network in V0A.

## `SAFE_HALT` is reachable from everywhere non-terminal and leads nowhere

Once external truth is ambiguous — a signed/submitted/included/confirmed
action whose outcome is unknown at restart, or a fill receipt that lands
outside its committed bounds — the only legal next state is `SAFE_HALT`, and
`SAFE_HALT` has no outbound transitions. Recovery never resolves ambiguity by
guessing; see `qntyspot/ledger/recovery.py` and `docs/AUTHORITY.md`.

`SAFE_HALT` also **quarantines** any reservation the intent was holding
(`ReservationStatus.QUARANTINED`) rather than releasing it: an action that may
still settle must keep counting against the caps, or the portfolio could
commit the same capital twice.

## Restart recovery

`qntyspot.ledger.recovery.recover` classifies every non-terminal intent by
state alone, never by elapsed time or absence of evidence:

- **`ABANDON`** — `ARMED` through `RESERVED`. Nothing venue-visible could have
  happened; the action is cancelled and its budget released. Its
  `EconomicActionID` stays consumed forever, so the same rung of the same
  cycle can never be armed a second time.
- **`RECONCILIATION_REQUIRED`** — `SIGNED`, `SUBMITTED`, `INCLUDED`,
  `CONFIRMED`, or `RECONCILED` without a receipt. The action may already exist
  outside this process; the ledger cannot resolve the outcome on its own, so
  it moves to `SAFE_HALT`.
- **`COMPLETE_FROM_RECEIPT`** — `RECONCILED` with a durable fill receipt
  already recorded. Finishing to `FILLED` is bookkeeping over evidence that
  already exists, not a new economic action.

`tests/test_crash_model.py` drives a ledger to each lifecycle boundary, kills
the connection without a graceful close, reopens the same database file, and
asserts the disposition above — including that recovery is idempotent and that
a recovered ledger still replays exactly.
