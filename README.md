# QntySpot

QntySpot is intended to become a **deterministic, policy-bound, multi-chain
spot execution runtime**. It will eventually support:

1. Ink ERC-20 spot, including KRAKMASK as an intended user-selected asset
2. Robinhood Chain Stock Tokens
3. Solana SPL / Token-2022 spot, initially via a Jupiter adapter
4. much later: OpenSea NFT execution/scalping as a separate venue adapter

## V0D status: `ROBINHOOD_SHADOW_READ_ONLY`

This repository currently implements the merged **V0A** offline deterministic
core, the merged **V0B** Ink and **V0C** Solana/Jupiter shadow adapters, and
the bounded **V0D** Robinhood Chain Stock Token shadow adapter.
See [docs/AUTHORITY.md](docs/AUTHORITY.md) for the binding statement of what
this phase authorizes and forbids. In short:

**V0D authorizes:** everything in V0C plus bounded Robinhood REST/RPC,
Chainlink, and one 0x Swap API v2 firm-quote read for an explicit Stock Token /
USDG pair, exact multiplier-aware unit semantics, canonical evidence, and
offline replay.

**V0D forbids:** private-key access, wallet secrets, approvals, transaction
submission, live capital, and eligibility inference.

**V0C historically authorized:** bounded finalized Solana RPC mint
reads, current Jupiter Swap V2 exact-input quote reads for the frozen exact
mint pair, deterministic route/program evidence, shadow policy decisions,
immutable evidence, and offline replay.

**V0C historically forbade:** private-key access, wallet signing, transaction construction,
transaction broadcast, live trading, venue discovery, automatic token
selection, bridging, Robinhood execution, and OpenSea execution.

Asset selection belongs to the user. Runtime asset admission is concerned with
**exact identity and execution constraints**, not with judging whether a
project is good, bad, legitimate, or likely to rug.

## What is here

- An immutable domain model (`qntyspot/domain.py`, `qntyspot/identity.py`)
- A strict, fail-closed policy reader (`qntyspot/policy.py`)
- The absolute economic-limit contract (`qntyspot/economics.py`)
- An append-only SQLite ledger with database-enforced exactly-once economic
  identity and atomic budget reservation (`qntyspot/ledger/`)
- Deterministic replay and restart recovery that never retries an action whose
  outcome is unknown (`qntyspot/ledger/replay.py`, `qntyspot/ledger/recovery.py`)
- Typed interfaces for the chain/venue truth boundary (`qntyspot/boundary.py`)
- The bounded Ink adapter (`qntyspot/ink.py`) with canonical evidence and replay
- The bounded Solana/Jupiter adapter (`qntyspot/solana.py`) with exact mint,
  route/program, stale-slot, version-0/ALT, canonical evidence, and replay
- The bounded Robinhood adapter (`qntyspot/robinhood.py`) with authoritative
  Stock Token identity, ERC-8056 multiplier semantics, Chainlink validation,
  one 0x firm quote, canonical evidence, and offline replay

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The offline test suite never requires network access; `tests/conftest.py`
disables the `socket` module for the whole session. The source scan retains
the no-secret/no-signing boundary while allowing the one standard-library
public-read transports used by V0B, V0C, and V0D.

```python
from qntyspot.policy import load_policy_file
from qntyspot.ledger import open_ledger

policy = load_policy_file("tests/fixtures/krakmask_ink_buy.policy.json")
with open_ledger("spot.sqlite3") as ledger:
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=1_700_000_100)
```

## Documentation

- [AGENTS.md](AGENTS.md) — entrypoint and constraints for agents working in this repo
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — module map and data flow
- [docs/AUTHORITY.md](docs/AUTHORITY.md) — what this phase authorizes and forbids
- [docs/STATE_MACHINE.md](docs/STATE_MACHINE.md) — the intent lifecycle
- [docs/POLICY_V0.md](docs/POLICY_V0.md) — the PolicyV0 schema
- [docs/ROADMAP.md](docs/ROADMAP.md) — phases beyond V0C
- [docs/SOLANA_V0C.md](docs/SOLANA_V0C.md) — frozen Solana/Jupiter semantics
- [docs/INK_V0B.md](docs/INK_V0B.md) — frozen Ink fixture and semantics

## KRAKMASK

KRAKMASK is present only as the user-selected V0B Ink fixture. Its presence is
not an endorsement, a safety claim, or an assertion of legitimacy. See
`tests/fixtures/README.md`.
