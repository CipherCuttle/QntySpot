from __future__ import annotations

import multiprocessing
import os
import sqlite3
from pathlib import Path

import pytest

from conftest import NOW, base_policy_doc, drive
from qntyspot.economics import build_intent
from qntyspot.errors import (
    BackupAliasError,
    BackupDestinationError,
    BackupError,
    BackupInterruptedError,
    BackupVerificationError,
    DatabaseMalformedError,
    DatabaseMissingError,
    DatabaseSchemaError,
    LockHeldError,
    LockPathError,
)
from qntyspot.ledger import open_ledger
from qntyspot.operations import (
    LockState,
    ProcessLock,
    backup_database,
    inspect_lock,
    restore_verify,
    verify_database,
)
from qntyspot.policy import parse_policy
from qntyspot.redaction import redact_text
from qntyspot.status import read_status
from qntyspot.states import IntentState as S


def _hold_lock(path: str, ready: object, release: object) -> None:
    with ProcessLock(path):
        ready.set()  # type: ignore[attr-defined]
        release.wait(10)  # type: ignore[attr-defined]


def _make_database(path: Path) -> None:
    with open_ledger(str(path)):
        pass


def test_lock_is_exclusive_across_real_processes_and_releases_cleanly(tmp_path: Path) -> None:
    path = str(tmp_path / "runtime.lock")
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    child = context.Process(target=_hold_lock, args=(path, ready, release))
    child.start()
    assert ready.wait(10)
    assert inspect_lock(path) is LockState.HELD
    with pytest.raises(LockHeldError, match="lock-held"):
        ProcessLock(path).acquire()
    release.set()
    child.join(10)
    assert child.exitcode == 0
    assert inspect_lock(path) is LockState.FREE
    with ProcessLock(path):
        assert inspect_lock(path) is LockState.HELD


def test_lock_rejects_same_process_reentry_and_stale_path_is_not_ownership(tmp_path: Path) -> None:
    path = tmp_path / "runtime.lock"
    first = ProcessLock(path)
    first.acquire()
    with pytest.raises(LockHeldError, match="lock-held"):
        ProcessLock(path).acquire()
    first.close()
    assert path.exists()
    assert inspect_lock(path) is LockState.FREE
    with ProcessLock(path):
        pass


def test_lock_path_failures_are_stable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(LockPathError, match="lock-directory-missing"):
        ProcessLock(tmp_path / "missing" / "runtime.lock").acquire()

    import qntyspot.operations as operations

    real_open = operations.os.open

    def deny_open(*args: object, **kwargs: object) -> int:
        raise PermissionError("simulated")

    monkeypatch.setattr(operations.os, "open", deny_open)
    with pytest.raises(LockPathError, match="lock-path-unwritable"):
        ProcessLock(tmp_path / "runtime.lock").acquire()
    monkeypatch.setattr(operations.os, "open", real_open)


def test_verify_rejects_missing_malformed_truncated_and_incompatible_files(tmp_path: Path) -> None:
    with pytest.raises(DatabaseMissingError, match="database-missing"):
        verify_database(tmp_path / "missing.sqlite3")

    malformed = tmp_path / "malformed.sqlite3"
    malformed.write_bytes(b"not sqlite")
    with pytest.raises(DatabaseMalformedError):
        verify_database(malformed)

    truncated = tmp_path / "truncated.sqlite3"
    truncated.write_bytes(b"SQLite format 3\x00")
    with pytest.raises(DatabaseMalformedError):
        verify_database(truncated)

    incompatible = tmp_path / "incompatible.sqlite3"
    conn = sqlite3.connect(incompatible)
    conn.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO schema_meta VALUES ('schema_version', '99')")
    conn.commit()
    conn.close()
    with pytest.raises(DatabaseSchemaError, match="schema-version-incompatible"):
        verify_database(incompatible)


def test_backup_verifies_wal_snapshot_with_reader_and_survives_restart(tmp_path: Path) -> None:
    source = tmp_path / "active.sqlite3"
    destination = tmp_path / "backup.sqlite3"
    policy = parse_policy(base_policy_doc())
    with open_ledger(str(source)) as ledger:
        ledger.admit_policy(policy)
        ledger.open_cycle(policy, 0, now_epoch_s=NOW)
        reader = sqlite3.connect(source)
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM policies").fetchone()
        wal_path = Path(str(source) + "-wal")
        assert wal_path.exists()
        report = backup_database(source, destination, pages=1)
        assert report.verification.quick_check == "ok"
        assert verify_database(destination).canonical_object() == report.verification.canonical_object()
        reader.rollback()
        reader.close()
        ledger.connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()

    with open_ledger(str(source), create=False) as restarted:
        restarted.integrity_check()
    assert verify_database(destination).schema_version == 1
    assert restore_verify(destination, directory=tmp_path).schema_version == 1


def test_backup_after_unclean_close_is_verified(tmp_path: Path) -> None:
    source = tmp_path / "unclean.sqlite3"
    ledger = open_ledger(str(source))
    ledger.open_cycle  # keep the connection path explicit for this crash-like test
    ledger.connection.close()
    assert verify_database(source).schema_version == 1
    destination = tmp_path / "unclean-backup.sqlite3"
    assert backup_database(source, destination).verification.integrity_check == "ok"


def test_backup_refuses_aliases_and_existing_destinations(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    _make_database(source)
    with pytest.raises(BackupAliasError, match="aliases-source"):
        backup_database(source, source)

    hardlink = tmp_path / "hardlink.sqlite3"
    os.link(source, hardlink)
    with pytest.raises(BackupAliasError, match="aliases-source"):
        backup_database(source, hardlink)

    existing = tmp_path / "existing.sqlite3"
    existing.write_bytes(b"keep")
    with pytest.raises(BackupDestinationError, match="destination-exists"):
        backup_database(source, existing)
    assert existing.read_bytes() == b"keep"


def test_backup_destination_and_interruption_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.sqlite3"
    _make_database(source)
    destination = tmp_path / "destination.sqlite3"

    with pytest.raises(BackupDestinationError, match="parent-missing"):
        backup_database(source, tmp_path / "missing" / "destination.sqlite3")

    def interrupt(_status: int, _remaining: int, _total: int) -> None:
        raise RuntimeError("stop")

    with pytest.raises(BackupInterruptedError, match="backup-interrupted"):
        backup_database(source, destination, pages=1, progress=interrupt)
    assert not destination.exists()

    def disk_failure(_status: int, _remaining: int, _total: int) -> None:
        raise sqlite3.OperationalError("disk full")

    with pytest.raises(BackupError, match="backup-failed"):
        backup_database(source, destination, pages=1, progress=disk_failure)
    assert not destination.exists()

    import qntyspot.operations as operations

    real_connect = operations.sqlite3.connect

    def fail_destination(path: object, *args: object, **kwargs: object):
        if str(path) == str(destination):
            raise sqlite3.OperationalError("disk full")
        return real_connect(path, *args, **kwargs)

    monkeypatch.setattr(operations.sqlite3, "connect", fail_destination)
    with pytest.raises(BackupDestinationError, match="destination-open-failed"):
        backup_database(source, destination)


def test_corrupt_backup_and_restore_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "backup.sqlite3"
    _make_database(source)
    backup_database(source, destination)
    destination.write_bytes(destination.read_bytes()[:20])
    with pytest.raises(DatabaseMalformedError):
        verify_database(destination)
    with pytest.raises(DatabaseMalformedError):
        restore_verify(destination, directory=tmp_path)


def test_read_only_database_is_readable_and_status_is_non_mutating(tmp_path: Path) -> None:
    database = tmp_path / "readonly.sqlite3"
    _make_database(database)
    before = database.read_bytes()
    database.chmod(0o444)
    try:
        assert verify_database(database).schema_version == 1
        report = read_status(database)
        assert report.database_reachable is True
        assert report.canonical_json() == report.canonical_json()
        assert database.read_bytes() == before
    finally:
        database.chmod(0o600)


def test_status_accounts_for_active_and_quarantined_reservations_without_mutation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "status.sqlite3"
    policy = parse_policy(base_policy_doc())
    with open_ledger(str(database)) as ledger:
        ledger.admit_policy(policy)
        cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
        first = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
        ledger.create_intent(first, now_epoch_s=NOW)
        drive(ledger, first.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED)
        second = build_intent(policy, cycle_id, policy.level("E2"), now_epoch_s=NOW)
        ledger.create_intent(second, now_epoch_s=NOW)
        drive(ledger, second.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED, S.SAFE_HALT)
        before = ledger.snapshot().digest()
        report = read_status(database)
        after = ledger.snapshot().digest()

    assert before == after
    assert report.unresolved_actions == 1
    assert report.safe_halt_actions == 1
    assert report.active_reservation_count == 1
    assert report.active_reservation_value_atomic == "100000000"
    assert report.quarantined_reservation_count == 1
    assert report.quarantined_reservation_value_atomic == "100000000"
    assert report.signing_authorized is False
    assert report.live_capital_authorized is False


def test_redaction_covers_credentials_and_long_phrase_shapes() -> None:
    raw = (
        "api_key=abc123 bearer secret-token "
        "authorization: Bearer another-secret "
        "https://user:pass@example.invalid/path "
        "-----BEGIN PRIVATE DATA-----abc-----END PRIVATE DATA----- "
        "0x" + "a" * 64 + " "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon"
    )
    safe = redact_text(raw)
    assert "abc123" not in safe
    assert "secret-token" not in safe
    assert "another-secret" not in safe
    assert "user:pass@" not in safe
    assert "BEGIN PRIVATE DATA" not in safe
    assert "0x" + "a" * 64 not in safe
    assert "abandon abandon" not in safe
