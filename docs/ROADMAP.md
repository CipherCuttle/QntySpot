# Roadmap

```
V0A  OFFLINE CORE                     <- merged prerequisite
V0B  INK SHADOW                        <- this repository, current phase
V0C  SOLANA SHADOW
V0D  ROBINHOOD SHADOW
V0E  HOSTILE FAILURE SUITE
V0F  INK DUST LIVE
V0G  SOLANA DUST LIVE
V0H  ROBINHOOD DUST LIVE
V1   QntyLab-assisted ladder research
```

```
DEFERRED_LATER:
OpenSea / NFT execution adapter
```

## V0A — Offline core (merged prerequisite)

Deterministic domain model, strict policy admission, SQLite ledger with
database-enforced exactly-once economic identity and atomic budget
reservation, deterministic replay, and restart recovery. No network, no
signer, no live-capital authority. See `docs/AUTHORITY.md`.

## V0B — Ink shadow (current)

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

## V0C — Solana shadow

A Jupiter-based adapter for Solana SPL / Token-2022 spot, shadow mode only.
Exercises the `SolanaInstrumentRef` identity path already present in V0A
(cluster, mint address, token program) against a second, structurally
different chain namespace.

## V0D — Robinhood shadow

An adapter for Robinhood Chain Stock Tokens (EVM), shadow mode only.

## V0E — Hostile failure suite

A dedicated adversarial test phase across all shadow adapters: network
partitions, malformed venue responses, reconciliation ambiguity, and
concurrent-worker scenarios beyond what V0A's offline crash model can exercise
without a network.

## V0F / V0G / V0H — Dust live

The first phases in which `SIGNING_AUTHORIZED` and `LIVE_CAPITAL_AUTHORIZED`
may become true, one venue at a time (Ink, Solana, Robinhood), starting at
dust size. Each requires its own authority review; none is granted by this
repository's V0A phase.

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
