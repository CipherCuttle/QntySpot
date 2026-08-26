"""Read-only, deterministic status reporting for a single ledger host."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any

from . import AUTHORITY, LIVE_CAPITAL_AUTHORIZED, NETWORK_AUTHORIZED, SIGNING_AUTHORIZED
from .canon import canonical_json_str
from .operations import LockState, _read_only_connection, inspect_lock, verify_database
from .states import TERMINAL_STATES

__all__ = ["StatusReport", "read_status"]


@dataclass(frozen=True, slots=True)
class StatusReport:
    database_reachable: bool
    integrity_status: str
    schema_version: int | None
    active_policy_ids: tuple[str, ...]
    unresolved_actions: int
    safe_halt_actions: int
    active_reservation_count: int
    active_reservation_value_atomic: str
    quarantined_reservation_count: int
    quarantined_reservation_value_atomic: str
    lock_state: str
    authority: str
    network_authorized: bool
    signing_authorized: bool
    live_capital_authorized: bool

    def canonical_object(self) -> dict[str, Any]:
        return {
            "active_policy_ids": list(self.active_policy_ids),
            "active_reservation_count": self.active_reservation_count,
            "active_reservation_value_atomic": self.active_reservation_value_atomic,
            "authority": self.authority,
            "database_reachable": self.database_reachable,
            "integrity_status": self.integrity_status,
            "live_capital_authorized": self.live_capital_authorized,
            "lock_state": self.lock_state,
            "network_authorized": self.network_authorized,
            "quarantined_reservation_count": self.quarantined_reservation_count,
            "quarantined_reservation_value_atomic": self.quarantined_reservation_value_atomic,
            "safe_halt_actions": self.safe_halt_actions,
            "schema_version": self.schema_version,
            "signing_authorized": self.signing_authorized,
            "unresolved_actions": self.unresolved_actions,
        }

    def canonical_json(self) -> str:
        return canonical_json_str(self.canonical_object())


def _empty_status(integrity_status: str, lock_state: str) -> StatusReport:
    return StatusReport(
        database_reachable=False,
        integrity_status=integrity_status,
        schema_version=None,
        active_policy_ids=(),
        unresolved_actions=0,
        safe_halt_actions=0,
        active_reservation_count=0,
        active_reservation_value_atomic="0",
        quarantined_reservation_count=0,
        quarantined_reservation_value_atomic="0",
        lock_state=lock_state,
        authority=AUTHORITY,
        network_authorized=NETWORK_AUTHORIZED,
        signing_authorized=SIGNING_AUTHORIZED,
        live_capital_authorized=LIVE_CAPITAL_AUTHORIZED,
    )


def _reservation_totals(conn: sqlite3.Connection, status: str) -> tuple[int, str]:
    rows = conn.execute(
        "SELECT amount_atomic FROM budget_reservations WHERE status = ? "
        "ORDER BY economic_action_id ASC",
        (status,),
    ).fetchall()
    return len(rows), str(sum(int(row[0]) for row in rows))


def read_status(
    database: str | PathLike[str],
    *,
    lock_path: str | PathLike[str] | None = None,
) -> StatusReport:
    """Read status without invoking recovery, adapters, or any write path."""
    lock_value = (
        LockState.NOT_PRESENT.value if lock_path is None else inspect_lock(lock_path).value
    )
    try:
        verification = verify_database(database)
    except Exception as exc:
        reason = getattr(exc, "reason", "diagnostic-failed")
        return _empty_status(str(reason), lock_value)

    path = Path(database).resolve()
    conn = _read_only_connection(path)
    try:
        policies = tuple(
            str(row[0])
            for row in conn.execute("SELECT policy_id FROM policies ORDER BY policy_id ASC")
        )
        terminal = tuple(state.value for state in TERMINAL_STATES)
        placeholders = ",".join("?" for _ in terminal)
        unresolved = int(
            conn.execute(
                f"SELECT COUNT(*) FROM intents WHERE state NOT IN ({placeholders})", terminal
            ).fetchone()[0]
        )
        safe_halt = int(
            conn.execute(
                "SELECT COUNT(*) FROM intents WHERE state = 'SAFE_HALT'"
            ).fetchone()[0]
        )
        active_count, active_value = _reservation_totals(conn, "ACTIVE")
        quarantine_count, quarantine_value = _reservation_totals(conn, "QUARANTINED")
    except sqlite3.DatabaseError:
        return _empty_status("diagnostic-query-failed", lock_value)
    finally:
        conn.close()

    return StatusReport(
        database_reachable=True,
        integrity_status="OK",
        schema_version=verification.schema_version,
        active_policy_ids=policies,
        unresolved_actions=unresolved,
        safe_halt_actions=safe_halt,
        active_reservation_count=active_count,
        active_reservation_value_atomic=active_value,
        quarantined_reservation_count=quarantine_count,
        quarantined_reservation_value_atomic=quarantine_value,
        lock_state=lock_value,
        authority=AUTHORITY,
        network_authorized=NETWORK_AUTHORIZED,
        signing_authorized=SIGNING_AUTHORIZED,
        live_capital_authorized=LIVE_CAPITAL_AUTHORIZED,
    )
