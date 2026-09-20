# Authority — external authority-root contract phase

This document is the binding statement of what the current phase of QntySpot
authorizes and forbids. If any other document in this repository (or any
sibling repository) appears to contradict it, this document wins for the
scope of `qntyspot/`.

```
PROJECT                 = QntySpot
ACTIVE_PHASE            = INK_V0F_HUMAN_SIGNED_EXECUTION_SOURCE_TRANSITION_V0
AUTHORITY               = INK_V0F_HUMAN_SIGNED_EXECUTION_PREGRANT
SOURCE_PHASE_CEILING    = HUMAN_SIGNED_EXECUTION
EFFECTIVE_LEVEL_3_AUTHORITY_REQUIRES_CURRENT_EXTERNAL_GRANT = YES
NETWORK_AUTHORIZED      = YES (bounded public reads through reviewed adapters)
SIGNING_AUTHORIZED      = NO (QntySpot cannot produce a signature)
LIVE_CAPITAL_AUTHORIZED = NO (no production Level-3 grant provisioned)
CAPITAL_AUTHORITY       = NONE UNTIL MATCHING EXTERNAL GRANT
```

These flags are also exported at runtime as `qntyspot.AUTHORITY`,
`qntyspot.NETWORK_AUTHORIZED`, `qntyspot.SIGNING_AUTHORIZED`, and
`qntyspot.LIVE_CAPITAL_AUTHORIZED`.

The Level-3 source ceiling is only one half of authority. A current,
independently verified AuthorityRoot grant bound to the exact implementation,
network, taker, venue, capital ceilings, and validity window is required for
every action that can create a new external effect and for ordinary Level-1+
runtime authority. The only post-expiry exception is an accounting-only
recovery proof for the exact already-bound session: it may observe chain truth,
reconcile that truth, and account quarantined capital, but it cannot reserve,
construct, approve, sign, submit, or create another transaction origin. No
production Level-3 grant is provisioned by this source transition, so
production execution remains denied.
`SIGNING_AUTHORIZED = NO` means QntySpot cannot produce a signature; Level 3
uses only complete bytes signed by the externally controlled human account.
`LIVE_CAPITAL_AUTHORIZED = NO` records the current pregrant deployment state,
not a claim that the reviewed Level-3 source path is absent.

The frozen external-root consumer contract is documented in
[docs/EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0.md](EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0.md).
QntySpot consumes a serialized receipt plus an explicit external trust
configuration. It does not contain or select root private material, does not
self-issue, and does not treat a verified receipt as sufficient to escape the
source phase ceiling. The external root consumer is already implemented and remains mandatory. This
phase does not issue, embed, discover, or provision a production grant.

## The Level-3 source ceiling authorizes only when the external grant also authorizes

- Deterministic, immutable domain models (`qntyspot/domain.py`,
  `qntyspot/identity.py`)
- Strict, fail-closed policy parsing (`qntyspot/policy.py`)
- SQLite state transitions with database-enforced invariants
  (`qntyspot/ledger/`)
- The offline Program B1 execution runtime over the existing SQLite core and
  execution schema (`qntyspot/ledger/execution.py`), including durable
  session, accounting-only reservation, external transaction references,
  observation, reconciliation, kill-switch, and deterministic replay facts
- Deterministic replay from an empty database plus canonical policies and the
  event log (`qntyspot/ledger/replay.py`)
- Accounting primitives: atomic budget reservation, commit, release, and
  quarantine (`qntyspot/ledger/store.py`)
- Tests, including tests that simulate crash/restart and concurrent workers
- The already-merged bounded Ink shadow implementation remains available as
  historical V0B code; this phase does not change it
- The already-merged bounded Solana shadow implementation remains available as
  historical V0C code; this phase does not change it
- One bounded read-only Robinhood testnet chain-truth observation for an
  explicitly supplied transaction, taker, and token pair on `evm:46630` under
  the current venue identity
  `robinhood-chain-testnet-external-transaction`; this identity is not a 0x
  route, DEX, liquidity claim, successful swap, or QntySpot-created transaction
- Bounded finalized Solana RPC reads for exactly two policy-supplied mint
  accounts on one frozen cluster
- Current official Jupiter Swap V2 `GET /swap/v2/build` read-only quotes for
  an exact input size and exact mint pair
- Exact mint identity including the Token vs Token-2022 owner program,
  decimals, atomic amounts, route split, program identities, and explicit
  version-0/address-lookup-table semantics
- Deterministic policy-bound shadow decisions with canonical SHA-256 evidence
  and offline replay from frozen live evidence
- The reviewed Ink V0F atomic preauthorization path: exact reservation,
  envelope construction, and exact approval authorization
- Submission of only the complete externally signed byte string that validates
  against the frozen envelope and current grant
- The human-signing handoff and exact signed-swap validation path; no signature
  production occurs inside QntySpot

## The Level-3 source ceiling still forbids

- private-key access
- wallet signing
- arbitrary or unbounded transaction construction
- any transaction broadcast outside the exact grant-bound submission entrypoint
- execution or any new external effect without a current matching external grant
- using an expired-grant recovery proof for reserve/construct/approve/sign/submit authority
- venue discovery
- automatic token selection
- bridging
- OpenSea execution
- wallet-secret access
- unlimited or caller-selected approvals
- transaction mutation after human signing
- signature production
- autonomous signing or autonomous execution
- production live capital before the separately provisioned exact Level-3 grant

The public-read implementations are limited to `qntyspot/ink.py`,
`qntyspot/ink_v0f_preauth.py`, `qntyspot/solana.py`,
`qntyspot/robinhood.py`, and the injected-transport
`qntyspot/robinhood_chain_truth.py`. The Ink V0F preauth module may verify
the frozen router and ERC-20 allowance at the exact market-observation block,
and its durable Level-3 entrypoints remain capability-gated. They are
reachable only when a current exact external grant independently permits the
same Level-3 session scope. The Solana path validates Jupiter's raw instruction
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
The historical Robinhood mainnet SHADOW path reads one 0x Swap API v2
AllowanceHolder quote on chain 4663. It remains separate from the current
testnet chain-truth identity `robinhood-chain-testnet-external-transaction`,
which does not imply 0x routing, a DEX, liquidity, a successful swap,
transaction construction, approval creation, signing, submission, or live
capital. Returned mainnet calldata is evidence only and is never submitted.

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
PHASE_GRANTED_AUTHORITY_LEVEL = LEVEL 3 (HUMAN_SIGNED_EXECUTION)
SOURCE_CEILING_ALONE_SUFFICIENT = NO
EFFECTIVE_AUTHORITY = MIN(SOURCE_PHASE_CEILING, VERIFIED_EXTERNAL_GRANT_LEVEL)
```

`qntyspot/authority_root.py` intersects the source ceiling with a current
`VerifiedAuthorityGrantV0` at every runtime consumption point. Without a valid matching grant, every Level-1+ capability is denied. A grant
below Level 3 reduces effective authority to that lower level. A grant above
Level 3 is clipped to Level 3, so `PRODUCE_SIGNATURE` remains impossible.
The source transition by itself therefore cannot submit, approve, or move
capital.

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
`QuoteSource`; V0D adds the Robinhood shadow `QuoteSource`; this phase adds a
bounded injected-transport Robinhood testnet `ChainTruthSource` under the
repaired external-transaction identity. The B1
runtime uses the existing chain-truth and reconciliation rules over either a
historical signed record or an explicit externally created transaction
reference. It records an accepted-but-absent or contradictory outcome as
`SAFE_HALT`, and releases a reservation only after an exact database-bound
`REVERTED` reconciliation.

Program B gives that rule an evidence contract:
`qntyspot.execution_contract.evaluate_chain_truth` decides what a set of
provider observations may conclude, and `reconcile_to_receipt` is the only path
from external truth to a `FillReceiptV0`. Both are pure functions over records
the caller supplies; neither reads a chain. The bounded adapter implements only
`ChainTruthSource`; the B1 runtime continues to consume persisted records and
the existing reconciliation path.

## Changing this document

Any change that would set `NETWORK_AUTHORIZED`, `SIGNING_AUTHORIZED`, or
`LIVE_CAPITAL_AUTHORIZED` to `YES` is a phase transition (see
[docs/ROADMAP.md](ROADMAP.md)), not a routine edit, and requires its own
review.
