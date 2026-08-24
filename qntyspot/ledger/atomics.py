"""Exact big-integer atomic amounts inside SQLite.

WHY THIS EXISTS
---------------
SQLite's ``INTEGER`` is signed 64-bit. An 18-decimal token overflows it at
about 9.22 units, so storing atomic amounts as ``INTEGER`` would either cap
policies at absurdly small sizes or overflow silently on the first ETH-quoted
ladder. Neither is acceptable in a ledger.

Atomic amounts are therefore stored as TEXT holding a canonical decimal
integer -- no sign, no leading zeros, digits only -- and the arithmetic the
budget guard needs is provided as SQLite user functions backed by Python's
arbitrary-precision ``int``. The guard stays a single SQL statement, so
reservation remains atomic, and the arithmetic inside it is exact at any size.

``NULL`` propagates as "unknown", and every comparison against an unknown
bound returns false. A cap that cannot be read is a cap that cannot be passed.
"""

from __future__ import annotations

import re
import sqlite3

from ..errors import LedgerError

__all__ = [
    "encode_atomic",
    "decode_atomic",
    "register_atomic_functions",
    "positive_atomic_check",
    "non_negative_atomic_check",
]

_ATOMIC_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")


def encode_atomic(value: int, *, field: str = "amount") -> str:
    """Store form of a non-negative integer atomic amount."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerError(f"{field}: atomic amount must be an int, got {type(value).__name__}")
    if value < 0:
        raise LedgerError(f"{field}: atomic amount must be >= 0, got {value}")
    return str(value)


def decode_atomic(text: str | None, *, field: str = "amount") -> int:
    """Read form of a stored atomic amount."""
    if text is None:
        raise LedgerError(f"{field}: atomic amount is NULL")
    if not isinstance(text, str) or not _ATOMIC_RE.match(text):
        raise LedgerError(f"{field}: {text!r} is not a canonical atomic amount")
    return int(text)


def positive_atomic_check(column: str) -> str:
    """CHECK expression: ``column`` is a canonical atomic amount > 0."""
    return f"({column} GLOB '[1-9]*' AND NOT {column} GLOB '*[^0-9]*')"


def non_negative_atomic_check(column: str) -> str:
    """CHECK expression: ``column`` is a canonical atomic amount >= 0."""
    return f"({column} = '0' OR {positive_atomic_check(column)})"


def _to_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _ATOMIC_RE.match(value):
        return int(value)
    raise LedgerError(f"non-canonical atomic amount in database: {value!r}")


class _AtomicSum:
    """SUM over canonical atomic amounts. Exact at any magnitude."""

    def __init__(self) -> None:
        self._total = 0

    def step(self, value: object) -> None:
        parsed = _to_int(value)
        if parsed is not None:
            self._total += parsed

    def finalize(self) -> str:
        return str(self._total)


class _AtomicMin:
    """MIN over canonical atomic amounts, by numeric value not by text order."""

    def __init__(self) -> None:
        self._best: int | None = None

    def step(self, value: object) -> None:
        parsed = _to_int(value)
        if parsed is None:
            return
        if self._best is None or parsed < self._best:
            self._best = parsed

    def finalize(self) -> str | None:
        return None if self._best is None else str(self._best)


def _atomic_add(a: object, b: object) -> str | None:
    left, right = _to_int(a), _to_int(b)
    if left is None or right is None:
        return None
    return str(left + right)


def _atomic_sub(a: object, b: object) -> str | None:
    """Saturating difference. Never returns a negative amount."""
    left, right = _to_int(a), _to_int(b)
    if left is None or right is None:
        return None
    return str(max(left - right, 0))


def _atomic_le(a: object, b: object) -> int:
    left, right = _to_int(a), _to_int(b)
    if left is None or right is None:
        # An unreadable bound is not a bound that can be satisfied.
        return 0
    return 1 if left <= right else 0


def register_atomic_functions(conn: sqlite3.Connection) -> None:
    """Install the atomic-amount functions on a connection.

    SQLite user functions are per-connection, so every connection that reads or
    writes a QntySpot ledger must call this. :func:`configure_connection` does.
    """
    conn.create_function("atomic_add", 2, _atomic_add, deterministic=True)
    conn.create_function("atomic_sub", 2, _atomic_sub, deterministic=True)
    conn.create_function("atomic_le", 2, _atomic_le, deterministic=True)
    conn.create_aggregate("atomic_sum", 1, _AtomicSum)
    conn.create_aggregate("atomic_min", 1, _AtomicMin)
