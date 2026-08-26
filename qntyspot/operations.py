"""Authority-neutral single-host locking and SQLite file operations."""

from __future__ import annotations

import errno
import fcntl
import os
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable

from .errors import (
    BackupAliasError,
    BackupDestinationError,
    BackupError,
    BackupInterruptedError,
    BackupVerificationError,
    DatabaseIntegrityError,
    DatabaseMalformedError,
    DatabaseMissingError,
    DatabaseSchemaError,
    LockHeldError,
    LockPathError,
)
from .ledger.schema import SCHEMA_VERSION, read_schema_version
from .redaction import redact_text

__all__ = [
    "BackupReport",
    "DatabaseReport",
    "LockState",
    "ProcessLock",
    "backup_database",
    "inspect_lock",
    "restore_verify",
    "verify_database",
]


class LockState(str, Enum):
    NOT_PRESENT = "NOT_PRESENT"
    FREE = "FREE"
    HELD = "HELD"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class DatabaseReport:
    path: str
    schema_version: int
    quick_check: str
    integrity_check: str

    def canonical_object(self) -> dict[str, object]:
        return {
            "path": redact_text(self.path),
            "schema_version": self.schema_version,
            "quick_check": self.quick_check,
            "integrity_check": self.integrity_check,
        }


@dataclass(frozen=True, slots=True)
class BackupReport:
    source: str
    destination: str
    verification: DatabaseReport

    def canonical_object(self) -> dict[str, object]:
        return {
            "source": redact_text(self.source),
            "destination": redact_text(self.destination),
            "verification": self.verification.canonical_object(),
        }


class ProcessLock:
    """A non-blocking advisory lock with kernel-owned lifetime."""

    _held_paths: set[str] = set()
    _registry_guard = threading.Lock()

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._key = str(self.path.resolve(strict=False))
        self._fd: int | None = None

    @property
    def acquired(self) -> bool:
        return self._fd is not None

    def acquire(self) -> None:
        with self._registry_guard:
            if self._fd is not None or self._key in self._held_paths:
                raise LockHeldError("lock-held")
            try:
                fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
            except FileNotFoundError as exc:
                raise LockPathError("lock-directory-missing") from exc
            except PermissionError as exc:
                raise LockPathError("lock-path-unwritable") from exc
            except IsADirectoryError as exc:
                raise LockPathError("lock-path-is-directory") from exc
            except OSError as exc:
                raise LockPathError("lock-path-unavailable") from exc

            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                os.close(fd)
                raise LockHeldError("lock-held") from exc
            except OSError as exc:
                os.close(fd)
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise LockHeldError("lock-held") from exc
                raise LockPathError("lock-acquire-failed") from exc

            self._fd = fd
            self._held_paths.add(self._key)

    def close(self) -> None:
        fd = self._fd
        if fd is None:
            return
        with self._registry_guard:
            self._fd = None
            self._held_paths.discard(self._key)
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def __enter__(self) -> "ProcessLock":
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def inspect_lock(path: str | os.PathLike[str]) -> LockState:
    """Inspect a lock without creating the pathname or retaining a lock."""
    lock_path = Path(path)
    key = str(lock_path.resolve(strict=False))
    if key in ProcessLock._held_paths:
        return LockState.HELD
    if not lock_path.exists():
        return LockState.NOT_PRESENT
    try:
        fd = os.open(str(lock_path), os.O_RDONLY)
    except OSError:
        return LockState.UNAVAILABLE
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return LockState.HELD
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return LockState.HELD
            return LockState.UNAVAILABLE
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(fd)
    return LockState.FREE


_REQUIRED_TABLES = frozenset(
    {
        "schema_meta",
        "instruments",
        "policies",
        "ladder_levels",
        "cycles",
        "intents",
        "state_events",
        "budget_reservations",
        "fill_receipts",
    }
)


def _database_path(path: str | os.PathLike[str]) -> Path:
    candidate = Path(path)
    if str(candidate) in {":memory:", ""}:
        raise DatabaseMalformedError("database-path-not-file")
    if not candidate.exists():
        raise DatabaseMissingError("database-missing")
    if not candidate.is_file():
        raise DatabaseMalformedError("database-path-not-file")
    return candidate.resolve()


def _read_only_connection(path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(
            path.as_uri() + "?mode=ro", uri=True, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.DatabaseError as exc:
        raise DatabaseMalformedError("sqlite-open-failed") from exc
    except OSError as exc:
        raise DatabaseMalformedError("sqlite-open-failed") from exc


def _check_result(conn: sqlite3.Connection, pragma: str, label: str) -> str:
    try:
        rows = [str(row[0]) for row in conn.execute(pragma).fetchall()]
    except sqlite3.DatabaseError as exc:
        raise DatabaseIntegrityError("sqlite-check-failed") from exc
    if rows != ["ok"]:
        raise DatabaseIntegrityError(f"{label}-failed")
    return "ok"


def verify_database(path: str | os.PathLike[str]) -> DatabaseReport:
    """Verify a ledger read-only using SQLite checks and schema admission."""
    database = _database_path(path)
    conn = _read_only_connection(database)
    try:
        try:
            version = read_schema_version(conn)
        except sqlite3.DatabaseError as exc:
            raise DatabaseMalformedError("sqlite-schema-read-failed") from exc
        except Exception as exc:
            raise DatabaseSchemaError("schema-version-unreadable") from exc
        if version != SCHEMA_VERSION:
            raise DatabaseSchemaError("schema-version-incompatible")
        try:
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        except sqlite3.DatabaseError as exc:
            raise DatabaseMalformedError("schema-read-failed") from exc
        if not _REQUIRED_TABLES.issubset(tables):
            raise DatabaseSchemaError("required-table-missing")
        quick = _check_result(conn, "PRAGMA quick_check", "quick-check")
        integrity = _check_result(conn, "PRAGMA integrity_check", "integrity-check")
        try:
            foreign_keys = conn.execute("PRAGMA foreign_key_check").fetchall()
        except sqlite3.DatabaseError as exc:
            raise DatabaseIntegrityError("foreign-key-check-failed") from exc
        if foreign_keys:
            raise DatabaseIntegrityError("foreign-key-violation")
        return DatabaseReport(str(database), version, quick, integrity)
    except (DatabaseSchemaError, DatabaseIntegrityError, DatabaseMalformedError):
        raise
    except sqlite3.DatabaseError as exc:
        raise DatabaseMalformedError("sqlite-read-failed") from exc
    finally:
        conn.close()


def _aliases(source: Path, destination: Path) -> bool:
    source_candidates = {
        source,
        Path(str(source) + "-wal"),
        Path(str(source) + "-shm"),
    }
    destination_resolved = destination.resolve(strict=False)
    if destination_resolved in {item.resolve(strict=False) for item in source_candidates}:
        return True
    if not destination.exists():
        return False
    for candidate in source_candidates:
        try:
            if candidate.exists() and destination.samefile(candidate):
                return True
        except OSError:
            continue
    return False


def _remove_partial(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _run_backup(
    source: Path,
    destination: Path,
    *,
    pages: int,
    progress: Callable[[int, int, int], object] | None,
) -> None:
    source_conn: sqlite3.Connection | None = None
    destination_conn: sqlite3.Connection | None = None
    try:
        source_conn = _read_only_connection(source)
        try:
            destination_conn = sqlite3.connect(str(destination), isolation_level=None)
        except sqlite3.DatabaseError as exc:
            raise BackupDestinationError("backup-destination-open-failed") from exc
        try:
            source_conn.backup(destination_conn, pages=pages, progress=progress)
        except sqlite3.DatabaseError as exc:
            raise BackupError("backup-failed") from exc
        except BaseException as exc:
            raise BackupInterruptedError("backup-interrupted") from exc
    except BackupError:
        raise
    except sqlite3.DatabaseError as exc:
        raise BackupError("backup-failed") from exc
    except OSError as exc:
        raise BackupError("backup-failed") from exc
    finally:
        if destination_conn is not None:
            destination_conn.close()
        if source_conn is not None:
            source_conn.close()


def backup_database(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    pages: int = -1,
    progress: Callable[[int, int, int], object] | None = None,
) -> BackupReport:
    """Back up a verified ledger to a new, non-aliasing file and re-verify it."""
    if not isinstance(pages, int) or isinstance(pages, bool) or pages == 0 or pages < -1:
        raise BackupError("backup-pages-invalid")
    source_path = _database_path(source)
    destination_path = Path(destination)
    if str(destination_path) in {":memory:", ""}:
        raise BackupDestinationError("backup-destination-not-file")
    if _aliases(source_path, destination_path):
        raise BackupAliasError("backup-destination-aliases-source")
    if destination_path.exists():
        raise BackupDestinationError("backup-destination-exists")
    if not destination_path.parent.exists():
        raise BackupDestinationError("backup-destination-parent-missing")
    if not destination_path.parent.is_dir():
        raise BackupDestinationError("backup-destination-parent-not-directory")

    verify_database(source_path)
    try:
        _run_backup(
            source_path,
            destination_path,
            pages=pages,
            progress=progress,
        )
        verification = verify_database(destination_path)
    except (BackupError, DatabaseMissingError, DatabaseMalformedError,
            DatabaseIntegrityError, DatabaseSchemaError) as exc:
        _remove_partial(destination_path)
        if isinstance(exc, BackupError):
            raise
        raise BackupVerificationError("backup-verification-failed") from exc
    return BackupReport(str(source_path), str(destination_path.resolve()), verification)


def restore_verify(
    backup: str | os.PathLike[str],
    *,
    directory: str | os.PathLike[str] | None = None,
) -> DatabaseReport:
    """Restore a backup into a temporary file, then verify that file."""
    backup_path = _database_path(backup)
    verify_database(backup_path)
    fd, temporary_name = tempfile.mkstemp(
        prefix="qntyspot-restore-",
        suffix=".sqlite3",
        dir=None if directory is None else str(directory),
    )
    os.close(fd)
    temporary_path = Path(temporary_name)
    _remove_partial(temporary_path)
    try:
        try:
            _run_backup(backup_path, temporary_path, pages=-1, progress=None)
            return verify_database(temporary_path)
        except (BackupError, DatabaseMissingError, DatabaseMalformedError,
                DatabaseIntegrityError, DatabaseSchemaError) as exc:
            raise BackupVerificationError("restore-verification-failed") from exc
    finally:
        _remove_partial(temporary_path)
