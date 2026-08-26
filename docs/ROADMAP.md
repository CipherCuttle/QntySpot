# Roadmap

```
V0A  OFFLINE CORE                     <- merged
V0B  INK SHADOW                       <- merged
V0C  SOLANA SHADOW                    <- merged
V0D  ROBINHOOD SHADOW                 <- merged
V0E  HOSTILE FAILURE SUITE            <- registry frozen (114 cases), suite merged
PROGRAM A  CONTROL PLANE CLOSURE      <- closed
PROGRAM B  PRE-LIVE EXECUTION CONTRACT   <- current phase, design only
PROGRAM B1 PRE-LIVE EXECUTION IMPLEMENTATION
V0F  INK DUST LIVE
V0G  SOLANA DUST LIVE
V0H  ROBINHOOD DUST LIVE
V1   QntyLab-assisted ladder research
```

No phase past Program B is authorized. `SIGNING_AUTHORIZED` and
`LIVE_CAPITAL_AUTHORIZED` are `NO`, and V0H is not live.

```
DEFERRED_LATER:
OpenSea / NFT execution adapter
```

## V0A — Offline core (merged prerequisite)

Deterministic domain model, strict policy admission, SQLite ledger with
database-enforced exactly-once economic identity and atomic budget
reservation, deterministic replay, and restart recovery. No network, no
signer, no live-capital authority. See `docs/AUTHORITY.md`.

## V0B — Ink shadow (merged)

The first adapter behind `qntyspot.boundary.ExecutionVenueAdapter`/
`QuoteSource`/`ChainTruthSource` for the Ink chain (EVM). "Shadow" means it
observes and simulates against real market data without submitting
transactions — it is the first phase in which `NETWORK_AUTHORIZED` becomes
relevant, but not yet `SIGNING_AUTHORIZED` or `LIVE_CAPITAL_AUTHORIZED`.
KRAKMASK, as a user-selected instrument, becomes reachable once this adapter
exists — see `docs/AUTHORITY.md`.

The bounded implementation is the KRAKMASK/WETH9 InkySwap V2 fixture in
`qntyspot/ink.py`. It requires two agreeing public RPC observations at one
common block, pins the verified pool bytecode hash and factory identity, and
persists only canonical market observations and shadow decisions. It does not
discover assets or venues and does not simulate transaction construction.

## V0C — Solana shadow (merged)

A bounded Jupiter Swap V2 and finalized Solana RPC adapter for Solana SPL /
Token-2022 spot, shadow mode only. It exercises the `SolanaInstrumentRef`
identity path already present in V0A (cluster, mint address, token program),
uses no ticker lookup, and records explicit route/program and version-0/ALT
semantics for deterministic replay.

## V0D — Robinhood shadow (merged)

An adapter for Robinhood Chain Stock Tokens (EVM), shadow mode only. The
qualification lineage and its result records are frozen under
`qualifications/robinhood_v0d*`; `PHASE_CLAIM` is
`READ_ONLY_SHADOW_INTEGRATION_QUALIFIED`, and neither balance nor allowance
readiness is claimed. See
[docs/PROGRAM_A_CONTROL_PLANE_CLOSURE_V0.md](PROGRAM_A_CONTROL_PLANE_CLOSURE_V0.md).

## V0E — Hostile failure suite (merged, registry frozen)

A dedicated adversarial test phase across all shadow adapters: network
partitions, malformed venue responses, reconciliation ambiguity, and
concurrent-worker scenarios beyond what V0A's offline crash model can exercise
without a network. The 114-case registry in
`docs/V0E_HOSTILE_FAILURE_SUITE_PREREG_V0.md` is frozen by digest in
`scripts/check_authority_continuity.py` and is not reopened.

## Program A — control-plane closure (closed)

Reconciled the repaired Robinhood shadow lineage, the operations-hardening
substrate, and the frozen V0E suite. See
[docs/PROGRAM_A_CONTROL_PLANE_CLOSURE_V0.md](PROGRAM_A_CONTROL_PLANE_CLOSURE_V0.md).

## Program B — pre-live execution contract (current)

A contract and architecture freeze, not an implementation. It defines the
execution session, envelope, approval, signed-transaction, submission,
observation and reconciliation contracts, the monotone authority ladder, the
SQLite execution authority surface, and the pre-live qualification matrix. It
grants no runtime authority above `SHADOW` and changes no authority flag. See
[docs/PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md](PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md).

## Program B1 — pre-live execution implementation

The runtime that must satisfy the Program B contract, together with the
obligations B1-O-01 through B1-O-05 the contract names. Not started, and not
authorized to sign, submit, approve, or deploy capital.

## V0F / V0G / V0H — Dust live

The first phases in which `SIGNING_AUTHORIZED` and `LIVE_CAPITAL_AUTHORIZED`
may become true, one venue at a time (Ink, Solana, Robinhood), starting at
dust size. Each requires its own authority review; none is granted by any phase
merged so far, and none is granted by the Program B contract. The dust size
itself is a separate choice: the historical V0D qualification amount is not
frozen as future dust capital.

## V1 — QntyLab-assisted ladder research

Uses QntyLab's exploratory research tooling to inform ladder/policy parameter
choices. QntyLab remains exploratory-only per its own governance; V1 does not
grant it trading authority.

## Deferred: OpenSea / NFT execution adapter

Not scheduled against a `V0*`/`V1` milestone. `qntyspot/identity.py`'s
`AssetClass` enum exists so the core states fungibility as a fact rather than
assuming it, which is the only accommodation V0A makes. A future adapter would
introduce its own Instrument/Intent semantics and a `VenueAdapter` behind the
same `qntyspot.boundary.ExecutionVenueAdapter` seam, without changing the
fungible V0 execution contracts. See `docs/ARCHITECTURE.md#future_deferred-nft-execution`.
