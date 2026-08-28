# QntySpot Program B — pre-live execution contract V0

```
CONTRACT                  = QNTY_SPOT_PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0
PHASE_KIND                = CONTRACT / ARCHITECTURE FREEZE
CANONICAL_PARENT          = a890de49e68486476b2385f70ef9c9558896f5b7
PROGRAM_A                 = CLOSED
PHASE_GRANTED_AUTHORITY   = LEVEL 0 (SHADOW)

SIGNING_AUTHORIZED        = NO
LIVE_CAPITAL_AUTHORIZED   = NO
CAPITAL_AUTHORITY         = NONE
```

This document defines the execution system that later implementation phases
must satisfy. It authorizes nothing. It does not authorize live capital,
funding, token approval, private-key access, transaction signing, transaction
broadcast, transaction submission, autonomous execution, daemon activation, or
another 0x qualification request. `NETWORK_AUTHORIZED` remains exactly what
[AUTHORITY.md](AUTHORITY.md) already permits.

Architecture is not authority. Freezing the shape of a signable envelope does
not make one signable; `qntyspot/execution_contract.py` refuses every
capability above `SHADOW` at runtime, and `tests/test_execution_contract.py`
proves it for every level and every capability.

## 1. What is reused, and the gaps that justified anything new

The following existing QntySpot primitives are the contract's vocabulary. None
is duplicated, replaced, or shadowed by a parallel concept.

| Primitive | Module | Role in Program B |
|---|---|---|
| `EconomicActionID` | `qntyspot/domain.py` | the one economic identity, unchanged |
| `EconomicBounds` | `qntyspot/domain.py` | the absolute limit an envelope must carry |
| `ExecutionPlanV0` | `qntyspot/domain.py` | referenced by an envelope as evidence |
| `IntentState` | `qntyspot/states.py` | the one lifecycle state machine, unchanged |
| `ReservationStatus` | `qntyspot/domain.py` | the one capital accounting model, unchanged |
| `FillReceiptV0` | `qntyspot/domain.py` | the only settlement record |
| `QuoteSource` / `ExecutionVenueAdapter` / `ChainTruthSource` / `Reconciler` | `qntyspot/boundary.py` | the seams the future implementation attaches to |
| `intents` / `budget_reservations` / `state_events` / `fill_receipts` | `qntyspot/ledger/schema.py` | reused by foreign key, never duplicated |

No new top-level state machine is introduced. No alternate economic identity
system is introduced.

Four semantic gaps were found and are documented here before the model is
extended:

- **G-1 — an approval is an external effect with no settlement.** An ERC-20
  approval changes what a third party may do with capital, but it settles
  nothing, so it has no `EconomicActionID` and cannot borrow one. It needs its
  own identity: `ApprovalActionV0`.
- **G-2 — there is no runtime session identity.** Nothing in the existing model
  binds a decision to the commit, implementation, runtime, schema, policy,
  authority grant, taker, chain and adapter version that produced it. I-14
  requires that binding: `ExecutionSessionV0`.
- **G-3 — transaction identity is not economic identity.** One economic action
  corresponds to at most one signed transaction, but a signed transaction has
  its own identity (its payload digest), its own retransmission semantics, and
  its own nonce. Conflating them would make an exact-byte retransmission look
  like a second economic action: `SignedTransactionRecordV0`.
- **G-4 — there is no representation of external evidence.** `boundary.py`
  declares that chain truth decides settlement but models no evidence at all:
  `ChainObservationV0`, `FinalityPolicyV0`, `ChainTruthV0`.

`external_actions` unifies G-1 and the economic case, and it is explicitly not
a fifth identity: a database CHECK requires
`external_action_id = COALESCE(economic_action_id, approval_action_id)`, so the
identity of an economic external action *is* its `EconomicActionID`.

## 2. The normative invariants

These are binding on every later implementation phase. The named test that
protects each one lives in `tests/test_execution_contract.py` unless stated.

| ID | Invariant | Enforced by |
|---|---|---|
| I-01 | quote success ≠ execution readiness ≠ signing authority ≠ capital authority ≠ profitability | `ExecutionReadiness` is a verdict about the venue; `require_capability` is the only gate that speaks about authority |
| I-02 | one `EconomicActionID` produces at most one economic settlement | `intents` PK/UNIQUE (existing) plus `signed_transactions.external_action_id` UNIQUE |
| I-03 | reserve before external effect | `RESERVE_CAPITAL` sits below `SUBMIT_EXACT_BYTES` on the ladder; the mandatory envelope gate requires an explicit held-capital projection |
| I-04 | unknown outcome holds capital | `release_permitted`; `SAFE_HALT` quarantines (existing) |
| I-05 | no economic retry | `signed_transaction_id` is a function of envelope identity and payload digest; a rebuilt transaction is a different identity the database refuses |
| I-06 | chain truth is settlement authority | `reconcile_to_receipt` is the only path to a `FillReceiptV0` and requires `CONFIRMED` |
| I-07 | actor ≠ verifier | `min_agreeing_providers`; `SubmissionAttemptV0.assert_hash_agreement` |
| I-08 | economic bounds survive into the transaction | the mandatory composite envelope gate requires the venue-enforced minimum output to carry the envelope bound |
| I-09 | code cannot self-escalate capital authority | `AuthorityPolicyRefV0` pins commit, implementation, network, taker and venue; envelope and approval gates reuse the binding |
| I-10 | kill switch semantics | `KILL_SWITCH_PRESERVED_CAPABILITIES` |
| I-11 | key isolation | `assert_no_secret_bearing_fields`; detector coverage rejects key, keystore, mnemonic, payload and signature-component field shapes |
| I-12 | untrusted provider response | `evaluate_zero_x_execution_readiness` |
| I-13 | approval is an external action | `ApprovalActionV0`, token-bound `approval_actions`, the mandatory response-backed approval gate, and receipt-kind guards |
| I-14 | exact session identity | `ExecutionSessionV0.identity_digest` |
| I-15 | execution qualification ≠ alpha | §8 of this document; no qualification stage produces a return estimate |
| I-16 | RWA API access ≠ legal eligibility | §6 of this document |

### I-01 in one sentence

A structurally valid 0x quote with `liquidityAvailable = true` is a fact about
a venue at a block. It is not a statement that the taker may trade, that the
runtime may sign, that capital exists, or that the trade is profitable. The V0D
R2R1 evidence is exactly such a quote and it carried both a balance issue and
an allowance issue; it remains the canonical example of why the four claims are
separate.

### I-09 in mechanical form

`AuthorityPolicyRefV0` names an `authority_root_id` outside this repository and
pins the commit and implementation digest it covers. Editing QntySpot changes
its implementation digest, which invalidates every grant that named the old
one. Raising the ceiling therefore requires an act by the independently rooted
authority, not an edit to the code being evaluated. **The authority service
itself is not implemented in this phase** — only the grant's shape and the
validator that refuses a mismatched grant.

## 3. Authority ladder

Monotone. Each level strictly extends the one below. Authority moves upward
only through a separately explicit later phase.

| Level | Name | Adds | May not |
|---|---|---|---|
| 0 | `SHADOW` | observe market, decide offline | anything external |
| 1 | `RECONCILE_ONLY` | observe chain, reconcile, quarantine accounting, reserve capital | sign, submit |
| 2 | `SUBMIT_EXACT_SIGNED_BYTES` | submit one already-signed frozen identity | create a signature, alter bytes, construct the transaction |
| 3 | `HUMAN_SIGNED_EXECUTION` | construct a validated envelope, authorize an approval | create a signature |
| 4 | `AUTONOMOUS_BOUNDED_SIGNER` | produce a signature | act outside its independently rooted capital policy |

Reserving capital sits at level 1 because a reservation causes no external
effect and is required in order to account for an externally created
transaction. Constructing an envelope sits at level 3 because level 2 submits
bytes that were constructed and signed elsewhere.

**Program B grants none of levels 1–4.** `PHASE_GRANTED_AUTHORITY_LEVEL` is
`SHADOW` and `require_capability` applies the phase ceiling before it consults
the caller's level, so a caller cannot obtain a higher capability by passing a
higher level.

### Kill switch (I-10)

Engaging the kill switch — and, identically, entering `SAFE_HALT` — removes
`RESERVE_CAPITAL`, `CONSTRUCT_ENVELOPE`, `AUTHORIZE_APPROVAL`,
`PRODUCE_SIGNATURE` and `SUBMIT_EXACT_BYTES` at every level, and preserves
`OBSERVE_MARKET`, `DECIDE_OFFLINE`, `OBSERVE_CHAIN`, `RECONCILE` and
`ACCOUNT_QUARANTINE`. A halted runtime can still find out what happened; it can
never cause anything new.

## 4. The domain objects

### `ExecutionSessionV0`

Portable identity (`identity_digest`): repository commit, implementation
digest, runtime identity, database schema version, policy id,
authority-policy digest, taker address, network id, venue id, venue adapter
version.

Instance identity (`session_id`): the identity digest plus the explicitly
supplied `started_at_epoch_s` and `session_ordinal`.

Deliberately excluded from identity: filesystem paths, machine names, RPC and
API URLs, and any clock reading. A future authority root is expected to pin
`identity_digest`; an ambient input would make that pin unpinnable. The
`runtime_identity` validator refuses absolute paths, URLs, dotted host
suffixes, whitespace and mixed case. Shape alone cannot *prove* portability,
and the contract does not claim it does — the value must be declared by the
operator, never discovered from the environment.

### `ExecutionEnvelopeV0`

The four-way partition is the point of this record.

- **IDENTITY** (forms `envelope_id`): stable session identity, economic action, chain, taker,
  both instruments, `max_input_atomic`, `min_output_atomic`, transaction
  target, transaction value, calldata digest and length, allowance target,
  account nonce, gas limit ceiling, fee ceilings, deadline, authority-policy
  digest.
- **EVIDENCE** (separate `evidence_digest`): plan id, quote id, quote
  observation digest, venue block number, construction time.
- **MUTABLE OBSERVATION**: never on the envelope. Allowances, balances and head
  blocks live on `ApprovalActionV0` and `ChainObservationV0`, because an
  envelope whose identity moved when the chain moved could not be pinned by a
  signer.
- **AUTHORITY**: `authority_policy_digest`, which is identity rather than
  evidence — an envelope authorized under one grant is not the same envelope
  under another.

The originating `session_id` is retained as provenance, but is excluded from
identity. The stable `session_identity_digest` is part of `envelope_id`, so a
restart with a different start time or ordinal reconstructs the same envelope
for the same portable session identity. The database's primary key then turns
reconstruction into a no-op rather than a duplicate. A changed portable
identity is a different authority scope and cannot reconstruct the envelope.

Deliberately absent: raw signed bytes, signature components, key material,
provider URLs.

### `ApprovalActionV0`

Identity: session, taker, token, spender, requested allowance, authority-policy
digest, and the causally bound economic action if there is one. Records the
observed prior allowance as evidence. V0 refusals enforced in the type: an
unlimited allowance is refused, there is no field that could carry a Permit2
signature, and the spender must be the exact allowance target the *current*
validated venue response reports.

### `SignedTransactionRecordV0`

`signed_transaction_id = sha256(envelope_id, raw_signed_sha256)`. Exact-byte
retransmission is therefore the same identity; a rebuilt transaction is a
different one. Stores a digest, a length, a hash and a non-secret signer label
— never the payload.

### `SubmissionAttemptV0`

One attempt against one provider. `ACCEPTED` is an acknowledgment, not a
settlement. A provider that reports a different transaction hash has not
acknowledged this action, and `assert_hash_agreement` raises.

### `ChainObservationV0`, `FinalityPolicyV0`, `ChainTruthV0`

See §5.

## 5. Chain truth and finality contract

Each evidence class supports exactly one claim. No claim is inferred from a
depth alone.

| Evidence | Claim it supports | Requirement |
|---|---|---|
| submitted | a provider took the bytes | an `ACCEPTED` attempt whose reported hash equals the locally derived hash |
| visible | the transaction exists off-chain or is being proposed | ≥1 `PENDING` or `INCLUDED` observation |
| included | the transaction is in a block | `min_agreeing_providers` observations agreeing on block number, block hash, parent hash, receipt status and effective amounts |
| confirmed | the inclusion block is `min_confirmation_depth` blocks behind **every** agreeing provider's head | as above plus a head reading from every agreeing provider |
| reverted | the transaction consumed its nonce and settled nothing | confirmed evidence with `receipt_status = REVERTED` |
| reconciled | a canonical `FillReceiptV0` exists | `CONFIRMED` plus the settled amounts inside the committed bounds |

Verdict mapping: `INCLUDED → IntentState.INCLUDED`, `CONFIRMED → CONFIRMED`,
`REVERTED → REJECTED`, `AMBIGUOUS → SAFE_HALT`. `NO_EVIDENCE` and `VISIBLE`
justify no transition at all: waiting is always permitted, guessing never is.

**Contradiction always wins before terminal reconciliation.** Truth uses each
provider's latest observation for confirmation. An inclusion followed by a
later `PENDING` or `ABSENT` observation is retained as a contradiction, not
silently outweighed by stale inclusion history. Two providers disagreeing
about the block, one provider changing its mind about the block (a replacement
or a reorg), or a provider reporting absence while another reports inclusion,
all yield `AMBIGUOUS`. Absence everywhere after an acknowledged submission is
also `AMBIGUOUS`: the contract never converts "we cannot find it" into "it did
not happen".

`ChainTruthV0` carries the exact economic action, transaction, chain, and taker
from the expectation. `reconcile_to_receipt` verifies all four bindings before
it can mint a `FillReceiptV0`; its expectation is economic-only, never an
approval action. Observations remain append-only. A reconciliation is one
terminal snapshot per external action: contradictory evidence discovered
before the finality claim is satisfied records `AMBIGUOUS`/`SAFE_HALT`, while
post-terminal reorg recovery is outside this bounded V0 contract and must not
rewrite a settled receipt. B1 cannot treat the depth claim as protocol finality
without discharging that limitation.

`min_confirmation_depth` supports one claim and no more: the inclusion block is
N blocks behind every agreeing provider's head on that chain's own history. It
is **not** an L1 finality claim, **not** a data-availability claim, and **not**
a sequencer-safety claim.

### What a future V0 dust experiment requires, and what is deferred

Required: two independently operated providers agreeing, a confirmation depth
of 32, block-hash and parent-hash agreement, receipt status, and decoded
effective input and output amounts attributable to the taker.

Deferred: L1 data-availability and settlement finality for Robinhood Chain;
proving that a transaction can never land (the nonce-consumed-by-another-
transaction argument); automatic reorg re-reconciliation. Under this contract
all three resolve to `AMBIGUOUS` / `SAFE_HALT`.

**Open precondition.** `ROBINHOOD_V0_FINALITY` requires two agreeing providers.
Whether chain 4663 exposes two independently operated, publicly readable
providers is not assumed here; establishing it is matrix stage D. If only one
exists, a dust experiment cannot reach `CONFIRMED` under this contract and must
halt.

## 6. Robinhood-specific pre-live contract

```
CHAIN                = Robinhood Chain mainnet, chain id 4663
TESTNET              = chain id 46630
PAIR                 = USDG <-> SPY Stock Token (the V0D pair)
VENUE                = 0x Swap API v2, AllowanceHolder
DUST_CAPITAL         = NOT CHOSEN, NOT AUTHORIZED
```

The historical V0D qualification amount is **not** frozen as future dust
capital. Future dust capital is a separate choice requiring separate authority.

Before any future execution, `evaluate_zero_x_execution_readiness` validates
the current response against the frozen contract. A mismatch on chain, taker,
sell token, buy token, exact sell amount, quote mode, transaction value,
transaction target versus allowance target, allowance spender versus allowance
target, or a minimum output weaker than the policy bound is a **contract
violation that raises**, not a "not ready" verdict — such a response must never
influence anything. Missing liquidity, an incomplete simulation, an invalid
source, an insufficient balance, and a stale or future-dated quote are facts
about the world and return `NOT_EXECUTABLE`. A missing allowance returns
`APPROVAL_REQUIRED`, which is a request for a separate, separately authorized
external action and never an instruction to perform one.

The approval target is never inferred from a hardcoded historical address. It
comes from the current validated response, and `assert_approval_admissible`
refuses any approval whose spender or amount differs from what that response
requires.

Not authorized in V0: Permit2, unlimited allowance, Settler approval, native
value transfer (`transaction.value` must be zero).

**I-16.** 0x quote entitlement is an API fact. It is not a statement about the
user's or the jurisdiction's eligibility to execute an RWA trade. Legal
eligibility is out of scope for this contract and is a precondition for V0H,
not an output of any qualification stage.

## 7. SQLite authority model

One transactional SQLite surface, not a multi-file protocol. The lesson already
paid for in Qnty is that a database here, a receipt file there, and a marker
file to tie them together has no atomic commit point. Raw provider payloads may
remain content-addressed on disk as evidence; authority over what happened
lives in these tables.

`qntyspot/ledger/execution_schema.py` defines them. All are `STRICT`, foreign
keys are on for every connection, and the historical-fact tables are
append-only in the engine via `BEFORE UPDATE`/`BEFORE DELETE` triggers.

| Table | Kind | Key database-enforced rule |
|---|---|---|
| `execution_sessions` | fact | UNIQUE (identity digest, start, ordinal) |
| `execution_envelopes` | state | partial UNIQUE: one `AUTHORIZED` envelope per economic action; partial UNIQUE: one `AUTHORIZED` envelope per (taker, chain, nonce); identity-bearing columns are immutable after authorization |
| `approval_actions` | state | partial UNIQUE: one `AUTHORIZED` approval per (taker, token, spender); identity-bearing columns are immutable after authorization |
| `external_actions` | identity | `external_action_id = COALESCE(economic_action_id, approval_action_id)`; exactly one of the two set; kind agrees |
| `signed_transactions` | append-only fact | **UNIQUE `external_action_id`**, subtype must agree with the external action, and UNIQUE (chain, taker, nonce) |
| `submission_attempts` | append-only fact | UNIQUE (signed transaction, provider, ordinal) |
| `chain_observations` | append-only fact | `INCLUDED` ⇔ block identity and receipt status; non-included rows carry no block/receipt facts; effective amounts require `SUCCESS` and head cannot precede inclusion |
| `reconciliations` | append-only fact | one terminal snapshot per external action; `SETTLED` ⇔ a receipt is present, and receipts are restricted to economic actions |
| `operator_control_events` | append-only fact | kill-switch state is a projection of the log, never a mutable row |

`intents`, `budget_reservations`, `state_events`, `fill_receipts`,
`policies` and `instruments` are reused by foreign key. Nothing is duplicated.

**The critical invariant.** `signed_transactions.external_action_id` is UNIQUE,
so one `EconomicActionID` can never be associated with two economically
distinct signed transactions. Retransmitting identical signed bytes reuses the
same row, because `signed_transaction_id` is a digest of the envelope identity
and the payload digest; a retransmission adds a `submission_attempts` row.
Retransmission is *not* authorized by this contract; its identity is frozen now
so that a future study of it cannot quietly become a retry.

The envelope and approval rows retain an originating session instance for
provenance, but their authority identity uses the stable session identity
digest. Once a row leaves `DRAFT`, SQLite prevents deletion or mutation of its
identity-bearing facts; only the lifecycle may advance.

`EXECUTION_SCHEMA_VERSION` is `1`. The surface is applied on demand and stamped
separately from the core `SCHEMA_VERSION`; whether it folds into the core
schema is a B1 decision. Applying it does not disturb the core snapshot, and
`tests/test_execution_schema.py` proves the core still replays exactly with the
surface present.

## 8. Pre-live qualification matrix

Orthogonal stages. Each answers one question and none of them says anything
about trading edge (I-15).

| Stage | Question | Capital | Authority needed beyond this contract |
|---|---|---|---|
| A — offline deterministic | do the state transitions, the SQLite authority surface, and the invariants hold under fault injection? | zero | none |
| B — Robinhood testnet (46630) | does a real EVM lifecycle work end to end: construct, sign with a disposable non-value test key, submit, observe, reconcile, crash, restart? | zero real | **yes** — a test-only signing/network amendment. Do not assume 0x offers the same venue path on testnet |
| C — mainnet fork | do the *current* mainnet contract and calldata semantics behave as expected against pinned chain state with fake local balances? | zero | fork tooling only; no external mainnet transaction |
| D — mainnet read-only preflight | is the live venue and chain state what the contract requires, including whether two independent providers exist? | zero | within current read authority |
| E — mainnet dust | — | real | **out of scope**; requires separate V0H authority |

Stage A is the only stage this phase's work belongs to, and it is already
partly discharged: `tests/test_execution_contract.py` and
`tests/test_execution_schema.py` are its first cases.

**I-15.** No testnet, fork, or dust execution result may be used to infer
trading edge. These stages answer "does the machinery work", never "does the
policy make money".

## 9. Invariant test contract

The 114 frozen V0E hostile cases are untouched and are not reopened. The
Program B invariant family is separate and ongoing. Every property must protect
a named invariant; a property that exists to raise a test count does not belong
in the family, and there is no random fuzzing.

Properties currently discharged:

- reserved capital ≤ per-action and cumulative authority ceilings, with
  quarantined capital still counted
- one `EconomicActionID` → at most one signed transaction (database)
- `SAFE_HALT` → no signing or submission capability at any level
- unknown external outcome → reservation held, never released
- wrong chain / wrong taker / wrong token → no admissible envelope
- `max_input` exceeded → rejected
- `min_output` weakened → rejected
- deadline expired or beyond the bound → rejected
- transaction target mismatch → rejected
- allowance spender mismatch → rejected
- authority-policy digest mismatch → rejected
- runtime/session identity mismatch → rejected
- implementation digest or commit outside the grant → rejected (I-09)
- `FILLED` requires independently reconciled external truth
- envelope identity is stable across reconstruction and moves on every identity
  field, so a crash at any boundary reconstructs rather than duplicates
- the core ledger still replays exactly with the execution surface applied

Deferred to B1, because they need a runtime rather than a contract: crash
injection at every execution-state boundary against a live SQLite surface,
concurrent-worker races on the envelope and signed-transaction tables, and
replay of the execution surface itself.

## 10. Obligations on B1

These are known, named, and must be discharged by
`QNTY_SPOT_PROGRAM_B1_PRELIVE_EXECUTION_IMPLEMENTATION_V0`.

- **B1-O-01 — narrow post-submission release.** `IntentState.REJECTED` is
  currently reachable from `SUBMITTED` and `INCLUDED`, and
  `qntyspot/ledger/store.py` releases the reservation on `REJECTED`. Under
  I-04 that transition is only sound when external truth has confirmed a
  revert. The contract's `release_permitted` already refuses every other case;
  B1 must gate the ledger transition on a recorded `REVERTED` reconciliation.
  The current behaviour is safe in shadow, where nothing is ever submitted, and
  is pinned by a test so it cannot drift unnoticed.
- **B1-O-02 — calldata bound extraction.** I-08 requires the economic bound to
  live *inside* the transaction. V0 verifies the venue-reported
  `minBuyAmount` and pins the calldata digest; it cannot yet decode the
  calldata to confirm the encoded minimum, because there is no ABI decoder in
  this repository. B1 must decode and compare.
- **B1-O-03 — locally derived transaction hash.** The contract requires a
  submission acknowledgment to name the hash the runtime derived itself. B1
  must derive it locally rather than adopt the provider's.
- **B1-O-04 — authority root verification.** `AuthorityPolicyRefV0` names a
  root; nothing verifies a grant against it yet. B1 or a later phase must add
  that verification, and it must not live in the source tree whose ceiling it
  governs.
- **B1-O-05 — execution surface replay.** The core ledger replays from its
  event log. The execution surface has no replay yet; B1 must either fold its
  facts into `state_events` or give it an equivalent reconstruction proof.

## 11. What this phase implemented

Contract only:

- `qntyspot/execution_contract.py` — dataclasses, digests, the authority
  ladder, and deterministic validators. No I/O, no clock, no network, no
  signer, no key access.
- `qntyspot/ledger/execution_schema.py` — the SQLite authority surface, created
  on demand, written by nothing.
- `tests/test_execution_contract.py`, `tests/test_execution_schema.py`,
  `tests/execution_support.py`.

Not implemented, and explicitly deferred: private-key reading, wallet
integrations, Rabby automation, raw transaction broadcast, 0x approval
transactions, live AllowanceHolder approvals, transaction signing, submission,
testnet signing, mainnet signing, live capital, daemon activation.

## 12. Next phase

Exactly one:

```
QNTY_SPOT_PROGRAM_B1_PRELIVE_EXECUTION_IMPLEMENTATION_V0
```

It does not begin here.
