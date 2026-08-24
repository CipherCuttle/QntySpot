# QntySpot

QntySpot is intended to become a **deterministic, policy-bound, multi-chain
spot execution runtime**. It will eventually support:

1. Ink ERC-20 spot, including KRAKMASK as an intended user-selected asset
2. Robinhood Chain Stock Tokens
3. Solana SPL / Token-2022 spot, initially via a Jupiter adapter
4. much later: OpenSea NFT execution/scalping as a separate venue adapter

## V0A status: `OFFLINE_CORE_ONLY`

This repository currently implements **V0A**, the offline deterministic core.
See [docs/AUTHORITY.md](docs/AUTHORITY.md) for the binding statement of what
this phase authorizes and forbids. In short:

**V0A authorizes:** deterministic domain models, strict policy parsing, SQLite
state transitions, replay, accounting primitives, tests.

**V0A forbids:** RPC access, API access, private-key access, wallet signing,
transaction construction, transaction broadcast, live trading, shadow network
calls, venue discovery, automatic token selection, bridging, OpenSea
execution.

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
- Typed interfaces for the future chain/venue truth boundary, with **no
  implementation** (`qntyspot/boundary.py`)

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

No network access, no secrets, and no signing capability are required to run
the test suite; this is enforced both at runtime (`tests/conftest.py` disables
the `socket` module for the whole session) and statically
(`tests/test_no_network.py` scans every module for forbidden imports and
tokens).

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
- [docs/ROADMAP.md](docs/ROADMAP.md) — phases beyond V0A

## KRAKMASK

KRAKMASK appears in this repository only as a **future user-selected Ink
fixture**, once a V0B Ink shadow adapter exists. Its presence here is not an
endorsement, a safety claim, or an assertion of legitimacy. See
`tests/fixtures/README.md`.
