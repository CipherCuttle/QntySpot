"""Schema definition and integrity rules for the QntySpot ledger.

INVARIANTS ENFORCED BY THE DATABASE, NOT BY APPLICATION CODE
------------------------------------------------------------
* ``intents`` has both a PRIMARY KEY on ``economic_action_id`` and a UNIQUE
  constraint on ``(policy_id, instrument_id, cycle_id, level_id, side)``. Two
  workers racing to create the same economic action cannot both succeed, and
  the guarantee does not depend on anyone remembering to check first.
* ``budget_reservations`` is keyed by ``economic_action_id``, so an action can
  hold at most one reservation, ever.
* ``state_events`` and ``fill_receipts`` carry BEFORE UPDATE / BEFORE DELETE
  triggers that abort. They are append-only in the engine, not by convention.
* Foreign keys are enabled on every connection.
"""

from __future__ import annotations

import sqlite3
from enum import Enum

from ..errors import LedgerError, SchemaVersionError
from .atomics import (
    non_negative_atomic_check,
    positive_atomic_check,
    register_atomic_functions,
)

__all__ = [
    "SCHEMA_VERSION",
    "SCHEMA_SQL",
    "EventType",
    "CYCLE_EVENT_TYPES",
    "apply_schema",
    "read_schema_version",
    "configure_connection",
]

SCHEMA_VERSION = 1


class EventType(str, Enum):
    CYCLE_OPENED = "CYCLE_OPENED"
    CYCLE_COMPLETED = "CYCLE_COMPLETED"
    CYCLE_HALTED = "CYCLE_HALTED"
    INTENT_CREATED = "INTENT_CREATED"
    INTENT_TRANSITION = "INTENT_TRANSITION"
    FILL_RECEIPT_APPENDED = "FILL_RECEIPT_APPENDED"


CYCLE_EVENT_TYPES = frozenset(
    {EventType.CYCLE_OPENED.value, EventType.CYCLE_COMPLETED.value, EventType.CYCLE_HALTED.value}
)

_CYCLE_TYPES_SQL = "('CYCLE_OPENED','CYCLE_COMPLETED','CYCLE_HALTED')"

_CHECKS = {
    "pos_allocation": positive_atomic_check("allocation_atomic"),
    "pos_per_order": positive_atomic_check("per_order_cap_atomic"),
    "pos_per_instrument": positive_atomic_check("per_instrument_cap_atomic"),
    "pos_per_network": positive_atomic_check("per_network_cap_atomic"),
    "pos_global": positive_atomic_check("global_cap_atomic"),
    "nn_reserved_cash": non_negative_atomic_check("reserved_cash_atomic"),
    "nn_quote_exposure": non_negative_atomic_check("quote_exposure_atomic"),
    "pos_amount": positive_atomic_check("amount_atomic"),
    "pos_input_filled": positive_atomic_check("input_atomic_filled"),
    "pos_output_filled": positive_atomic_check("output_atomic_filled"),
    "nn_fee": non_negative_atomic_check("fee_atomic"),
    "cycle_types": _CYCLE_TYPES_SQL,
}

_SCHEMA_TEMPLATE = """
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE instruments (
    instrument_id   TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL CHECK (namespace IN ('evm','solana')),
    network_id      TEXT NOT NULL,
    decimals        INTEGER NOT NULL CHECK (decimals BETWEEN 0 AND 36),
    asset_class     TEXT NOT NULL CHECK (asset_class IN ('FUNGIBLE')),
    identity_digest TEXT NOT NULL,
    identity_json   TEXT NOT NULL
);

CREATE TABLE policies (
    policy_id                  TEXT PRIMARY KEY,
    policy_name                TEXT NOT NULL,
    side                       TEXT NOT NULL CHECK (side IN ('BUY','SELL')),
    instrument_id              TEXT NOT NULL REFERENCES instruments(instrument_id),
    quote_instrument_id        TEXT NOT NULL REFERENCES instruments(instrument_id),
    network_id                 TEXT NOT NULL,
    allocation_atomic          TEXT NOT NULL CHECK {pos_allocation},
    per_order_cap_atomic       TEXT NOT NULL CHECK {pos_per_order},
    per_instrument_cap_atomic  TEXT NOT NULL CHECK {pos_per_instrument},
    per_network_cap_atomic     TEXT NOT NULL CHECK {pos_per_network},
    global_cap_atomic          TEXT NOT NULL CHECK {pos_global},
    reserved_cash_atomic       TEXT NOT NULL CHECK {nn_reserved_cash},
    max_cycles                 INTEGER NOT NULL CHECK (max_cycles >= 1),
    canonical_json             TEXT NOT NULL
);

CREATE TABLE ladder_levels (
    policy_id     TEXT NOT NULL REFERENCES policies(policy_id),
    level_id      TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('ENTRY','EXIT')),
    side          TEXT NOT NULL CHECK (side IN ('BUY','SELL')),
    level_index   INTEGER NOT NULL CHECK (level_index >= 0),
    trigger_price TEXT NOT NULL,
    input_amount  TEXT,
    input_ratio   TEXT,
    PRIMARY KEY (policy_id, level_id),
    CHECK ((input_amount IS NULL) <> (input_ratio IS NULL))
);

CREATE TABLE cycles (
    cycle_id    TEXT PRIMARY KEY,
    policy_id   TEXT NOT NULL REFERENCES policies(policy_id),
    cycle_index INTEGER NOT NULL CHECK (cycle_index >= 0),
    status      TEXT NOT NULL CHECK (status IN ('OPEN','COMPLETED','HALTED')),
    UNIQUE (policy_id, cycle_index)
);

CREATE TABLE intents (
    economic_action_id    TEXT PRIMARY KEY,
    policy_id             TEXT NOT NULL REFERENCES policies(policy_id),
    instrument_id         TEXT NOT NULL REFERENCES instruments(instrument_id),
    quote_instrument_id   TEXT NOT NULL REFERENCES instruments(instrument_id),
    network_id            TEXT NOT NULL,
    cycle_id              TEXT NOT NULL REFERENCES cycles(cycle_id),
    level_id              TEXT NOT NULL,
    side                  TEXT NOT NULL CHECK (side IN ('BUY','SELL')),
    kind                  TEXT NOT NULL CHECK (kind IN ('ENTRY','EXIT')),
    state                 TEXT NOT NULL,
    quote_exposure_atomic TEXT NOT NULL CHECK {nn_quote_exposure},
    bounds_json           TEXT NOT NULL,
    -- The exactly-once economic identity, enforced by the engine.
    UNIQUE (policy_id, instrument_id, cycle_id, level_id, side),
    FOREIGN KEY (policy_id, level_id) REFERENCES ladder_levels(policy_id, level_id)
);

CREATE INDEX idx_intents_cycle ON intents(cycle_id);
CREATE INDEX idx_intents_state ON intents(state);

CREATE TABLE state_events (
    seq                INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type         TEXT NOT NULL,
    policy_id          TEXT NOT NULL REFERENCES policies(policy_id),
    cycle_id           TEXT NOT NULL REFERENCES cycles(cycle_id),
    economic_action_id TEXT REFERENCES intents(economic_action_id),
    from_state         TEXT,
    to_state           TEXT,
    occurred_epoch_s   INTEGER NOT NULL CHECK (occurred_epoch_s >= 0),
    payload_json       TEXT NOT NULL,
    CHECK (
        (economic_action_id IS NULL) = (event_type IN {cycle_types})
    ),
    CHECK (
        (to_state IS NULL) = (event_type = 'FILL_RECEIPT_APPENDED')
    )
);

CREATE INDEX idx_state_events_action ON state_events(economic_action_id, seq);

CREATE TRIGGER state_events_no_update
BEFORE UPDATE ON state_events
BEGIN
    SELECT RAISE(ABORT, 'state_events is append-only');
END;

CREATE TRIGGER state_events_no_delete
BEFORE DELETE ON state_events
BEGIN
    SELECT RAISE(ABORT, 'state_events is append-only');
END;

CREATE TABLE budget_reservations (
    economic_action_id  TEXT PRIMARY KEY REFERENCES intents(economic_action_id),
    policy_id           TEXT NOT NULL REFERENCES policies(policy_id),
    instrument_id       TEXT NOT NULL REFERENCES instruments(instrument_id),
    quote_instrument_id TEXT NOT NULL REFERENCES instruments(instrument_id),
    network_id          TEXT NOT NULL,
    amount_atomic       TEXT NOT NULL CHECK {pos_amount},
    status              TEXT NOT NULL
                        CHECK (status IN ('ACTIVE','COMMITTED','RELEASED','QUARANTINED')),
    reserved_seq        INTEGER NOT NULL,
    settled_seq         INTEGER
);

CREATE INDEX idx_reservations_scope
    ON budget_reservations(status, network_id, instrument_id, policy_id);

CREATE TABLE fill_receipts (
    receipt_id           TEXT PRIMARY KEY,
    economic_action_id   TEXT NOT NULL REFERENCES intents(economic_action_id),
    external_ref         TEXT NOT NULL UNIQUE,
    input_atomic_filled  TEXT NOT NULL CHECK {pos_input_filled},
    output_atomic_filled TEXT NOT NULL CHECK {pos_output_filled},
    fee_atomic           TEXT NOT NULL CHECK {nn_fee},
    observed_at_epoch_s  INTEGER NOT NULL CHECK (observed_at_epoch_s >= 0),
    source               TEXT NOT NULL,
    appended_seq         INTEGER NOT NULL
);

CREATE INDEX idx_receipts_action ON fill_receipts(economic_action_id);

CREATE TRIGGER fill_receipts_no_update
BEFORE UPDATE ON fill_receipts
BEGIN
    SELECT RAISE(ABORT, 'fill_receipts is append-only');
END;

CREATE TRIGGER fill_receipts_no_delete
BEFORE DELETE ON fill_receipts
BEGIN
    SELECT RAISE(ABORT, 'fill_receipts is append-only');
END;
"""

SCHEMA_SQL = _SCHEMA_TEMPLATE.format(**_CHECKS)


def configure_connection(conn: sqlite3.Connection, *, wal: bool, busy_timeout_ms: int) -> None:
    """Apply the pragmas every QntySpot connection must have.

    ``foreign_keys`` is per-connection in SQLite and OFF by default, so this is
    not optional decoration: without it the referential invariants above are
    silently unenforced.
    """
    register_atomic_functions(conn)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
    if wal:
        conn.execute("PRAGMA journal_mode = WAL")
    enabled = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    if not enabled:
        raise LedgerError("SQLite refused to enable foreign_keys; refusing to continue")


def apply_schema(conn: sqlite3.Connection) -> None:
    """Create the schema in an empty database and stamp its version."""
    existing = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    if existing:
        raise LedgerError(
            f"refusing to apply schema over existing tables: {sorted(r[0] for r in existing)}"
        )
    # executescript() commits any pending transaction before it runs, so the
    # script carries its own BEGIN/COMMIT. Either the whole schema lands or
    # none of it does; a half-created ledger is not a state we accept.
    stamp = (
        "INSERT INTO schema_meta (key, value) VALUES\n"
        f"    ('schema_version', '{SCHEMA_VERSION}'),\n"
        "    ('authority', 'OFFLINE_CORE_ONLY: no network, no signer, "
        "no live authorization');\n"
    )
    conn.executescript("BEGIN;\n" + SCHEMA_SQL + "\n" + stamp + "COMMIT;\n")


def read_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        raise SchemaVersionError("database has no schema_version")
    try:
        return int(row[0])
    except (TypeError, ValueError) as exc:
        raise SchemaVersionError(f"unreadable schema_version {row[0]!r}") from exc
