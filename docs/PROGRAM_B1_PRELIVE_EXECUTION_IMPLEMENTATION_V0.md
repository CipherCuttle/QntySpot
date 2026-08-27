# Program B1 — pre-live execution implementation

This phase implements the frozen Program B execution contract as an offline
SQLite runtime. It does not reopen V0D, V0E, or Program A, and it does not
change the authority ceiling.

```text
ACTIVE_PHASE            = QNTY_SPOT_PROGRAM_B1_PRELIVE_EXECUTION_IMPLEMENTATION_V0
CANONICAL_PARENT        = bcb7973efdf5d4d6a7510c0d0725897a7d290836
AUTHORITY               = ROBINHOOD_SHADOW_READ_ONLY
NETWORK_AUTHORIZED      = YES (historical bounded public-read ceiling only)
EXECUTION_NETWORK_CALLS = ZERO
SIGNING_AUTHORIZED      = NO
LIVE_CAPITAL_AUTHORIZED = NO
CAPITAL_AUTHORITY       = NONE
```

The runtime in `qntyspot/ledger/execution.py` is the sole writer for the B1
execution surface. It accepts explicit caller-supplied records and bytes,
uses the existing `SpotLedger` transaction boundary, and stores no raw signed
bytes or credentials. Its durable facts include sessions, reservations,
envelopes, approvals, signed-transaction metadata, submission attempts, chain
observations, reconciliations, and operator control events.

## B1 obligations

- O01: a post-submission rejection cannot release capital without an exact
  database-bound `REVERTED` reconciliation; unresolved or contradictory truth
  is held or quarantined in `SAFE_HALT`.
- O02: the decoder validates the bounded nested
  `AllowanceHolder.exec(..., Settler.execute(...))` ABI shape, extracts the
  outer token/amount and nested recipient/buy-token/minimum-output fields, and
  rejects unknown or malformed action data.
- O03: transaction identity is derived locally with Ethereum Keccak-256 from
  explicit signed bytes, while only digest, length, hash, and signer label are
  persisted.
- O04: the external authority-root consumer is present as a typed seam and
  always fails closed until an independently rooted verifier is supplied.
- O05: execution facts have deterministic snapshots and replay validation;
  core rejection replay consumes only a validated source-side revert binding.

Failure injection covers before-commit rollback and after-commit durability.
SQLite uniqueness, foreign keys, append-only triggers, and transactional
`BEGIN IMMEDIATE` writes provide the database-level race and idempotency
boundary. The kill switch blocks new runtime effects while observation and
reconciliation remain available for safe resolution.

No B1 path constructs a transaction, reads a secret, calls an RPC or venue, or
changes `SIGNING_AUTHORIZED`, `LIVE_CAPITAL_AUTHORIZED`, or `CAPITAL_AUTHORITY`.
The next phase, if separately approved, is zero-capital Robinhood testnet
qualification on chain 46630 under a new test-only signing/network amendment.
