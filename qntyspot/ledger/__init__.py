"""SQLite ledger for QntySpot V0A.

The ledger is not a cache. ``state_events`` is the append-only log of every
economic fact, and every other table is a projection of that log plus the set
of admitted canonical policies. Replay rebuilds all projections from exactly
those two inputs; see :mod:`qntyspot.ledger.replay`.
"""

from .schema import SCHEMA_VERSION, EventType, apply_schema, read_schema_version
from .store import SpotLedger, open_ledger
from .replay import replay_into, reconstruct, assert_replay_equivalence
from .recovery import RecoveryAction, recover

__all__ = [
    "SCHEMA_VERSION",
    "EventType",
    "apply_schema",
    "read_schema_version",
    "SpotLedger",
    "open_ledger",
    "replay_into",
    "reconstruct",
    "assert_replay_equivalence",
    "RecoveryAction",
    "recover",
]
