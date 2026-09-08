"""Regression proof for the Level-2 exact-byte schema compatibility repair."""

from __future__ import annotations

import sqlite3
import hashlib
from pathlib import Path

import pytest

from conftest import NOW
from qntyspot.canon import canonical_json_bytes, strict_json_loads
from qntyspot.errors import LedgerError
from qntyspot.ledger import ExecutionRuntime
from qntyspot.ledger.execution_schema import (
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_SCHEMA_VERSION_V2,
    EXECUTION_SCHEMA_VERSION_V3,
    EXECUTION_TABLES,
    apply_execution_schema,
    migrate_execution_schema_v2_to_v3,
    migrate_execution_schema_v3_to_v4,
    read_execution_schema_version,
)
from test_execution_schema import (
    AUTHORITY_DIGEST,
    COMMIT,
    IDENTITY_DIGEST,
    SESSION_ID,
    TAKER,
    approval_row,
    economic_external_action,
    envelope_row,
    insert,
    signed_row,
)


ROOT = Path(__file__).resolve().parents[1]
REPAIR_ARTIFACT = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_SCHEMA_COMPATIBILITY_REPAIR_V0.json"
REPAIR_SIDECAR = REPAIR_ARTIFACT.with_suffix(".sha256")


LEGACY_SIGNED_TRANSACTIONS_SQL = """
CREATE TABLE signed_transactions (
    signed_transaction_id TEXT PRIMARY KEY,
    external_action_id    TEXT NOT NULL UNIQUE
                          REFERENCES external_actions(external_action_id),
    session_id            TEXT NOT NULL REFERENCES execution_sessions(session_id),
    envelope_id           TEXT REFERENCES execution_envelopes(envelope_id),
    approval_action_id    TEXT REFERENCES approval_actions(approval_action_id),
    chain_id              INTEGER NOT NULL CHECK (chain_id > 0),
    taker_address         TEXT NOT NULL,
    account_nonce         INTEGER NOT NULL CHECK (account_nonce >= 0),
    raw_signed_sha256     TEXT NOT NULL UNIQUE,
    raw_signed_length     INTEGER NOT NULL CHECK (raw_signed_length > 0),
    transaction_hash      TEXT NOT NULL UNIQUE,
    signer_identity       TEXT NOT NULL,
    frozen_at_epoch_s     INTEGER NOT NULL CHECK (frozen_at_epoch_s >= 0),
    CHECK ((envelope_id IS NULL) <> (approval_action_id IS NULL)),
    UNIQUE (chain_id, taker_address, account_nonce)
) STRICT;
"""


def _surface(armed):
    ledger, policy, cycle_id, intent = armed
    apply_execution_schema(ledger.connection)
    insert(
        ledger.connection,
        "execution_sessions",
        session_id=SESSION_ID,
        identity_digest=IDENTITY_DIGEST,
        repository_commit=COMMIT,
        implementation_digest="03" * 32,
        runtime_identity="cpython-3.14",
        db_schema_version=1,
        policy_id=policy.policy_id,
        authority_root_id="qnty-authority-root-v0",
        authority_policy_digest=AUTHORITY_DIGEST,
        authority_level=0,
        taker_address=TAKER,
        network_id="evm:57073",
        venue_id="zero-x-allowance-holder",
        venue_adapter_version="v0",
        started_at_epoch_s=NOW,
        session_ordinal=0,
    )
    return ledger, policy, cycle_id, intent


def _drop_execution_triggers(conn: sqlite3.Connection) -> None:
    names = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name IN ("
        + ",".join("?" for _ in EXECUTION_TABLES)
        + ")",
        EXECUTION_TABLES,
    ).fetchall()
    for (name,) in names:
        conn.execute(f'DROP TRIGGER "{name.replace(chr(34), chr(34) * 2)}"')


def _legacy_shape(conn: sqlite3.Connection, *, marked_version: int) -> None:
    """Turn a temporary canonical surface into the discovered old shape."""
    old_rows = [
        tuple(row[column] for column in (
            "signed_transaction_id", "external_action_id", "session_id", "envelope_id",
            "approval_action_id", "chain_id", "taker_address", "account_nonce",
            "raw_signed_sha256", "raw_signed_length", "transaction_hash",
            "signer_identity", "frozen_at_epoch_s",
        ))
        for row in conn.execute("SELECT * FROM signed_transactions ORDER BY signed_transaction_id")
    ]
    conn.execute("PRAGMA foreign_keys = OFF")
    _drop_execution_triggers(conn)
    conn.execute("DROP TABLE signed_transactions")
    conn.execute(LEGACY_SIGNED_TRANSACTIONS_SQL)
    conn.executemany(
        "INSERT INTO signed_transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        old_rows,
    )
    if marked_version == EXECUTION_SCHEMA_VERSION_V3:
        conn.execute(
            "ALTER TABLE signed_transactions ADD COLUMN origin TEXT NOT NULL DEFAULT 'ENVELOPE' "
            "CHECK (origin IN ('ENVELOPE','APPROVAL','EXTERNAL_SIGNED_BYTES'))"
        )
        conn.execute(
            "ALTER TABLE signed_transactions ADD COLUMN scope_digest TEXT NOT NULL DEFAULT ''"
        )
        conn.execute(
            "UPDATE signed_transactions SET origin='APPROVAL' WHERE approval_action_id IS NOT NULL"
        )
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        "UPDATE schema_meta SET value=? WHERE key='execution_schema_version'",
        (str(marked_version),),
    )


def _seed_historical_rows(ledger, intent) -> None:
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    economic_action_id = economic_external_action(conn, intent)
    insert(conn, "signed_transactions", **signed_row(economic_action_id))
    insert(conn, "approval_actions", **approval_row())
    insert(
        conn,
        "external_actions",
        external_action_id="20" * 32,
        kind="APPROVAL",
        economic_action_id=None,
        approval_action_id="20" * 32,
    )
    insert(
        conn,
        "signed_transactions",
        **signed_row(
            "20" * 32,
            signed_transaction_id="32" * 32,
            envelope_id=None,
            approval_action_id="20" * 32,
            origin="APPROVAL",
            account_nonce=8,
            raw_signed_sha256="33" * 32,
            transaction_hash="0x" + "ac" * 32,
        ),
    )


def _rows(conn: sqlite3.Connection, table: str) -> list[tuple[object, ...]]:
    return [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]


def test_real_legacy_xor_migrates_and_preserves_history(armed) -> None:
    ledger, _policy, _cycle_id, intent = _surface(armed)
    _seed_historical_rows(ledger, intent)
    conn = ledger.connection
    historical_before = {
        table: _rows(conn, table)
        for table in EXECUTION_TABLES
        if table != "signed_transactions"
    }
    signed_columns = (
        "signed_transaction_id", "external_action_id", "session_id", "envelope_id",
        "approval_action_id", "chain_id", "taker_address", "account_nonce",
        "raw_signed_sha256", "raw_signed_length", "transaction_hash",
        "signer_identity", "frozen_at_epoch_s",
    )
    signed_before = [
        tuple(row[column] for column in signed_columns)
        for row in conn.execute("SELECT * FROM signed_transactions ORDER BY signed_transaction_id")
    ]
    _legacy_shape(conn, marked_version=EXECUTION_SCHEMA_VERSION_V2)
    sql_before = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='signed_transactions'"
    ).fetchone()[0].upper()
    assert "IS NULL) <> (APPROVAL_ACTION_ID IS NULL)" in sql_before

    migrate_execution_schema_v2_to_v3(conn)

    assert read_execution_schema_version(conn) == EXECUTION_SCHEMA_VERSION
    assert [row[1] for row in conn.execute("PRAGMA table_info(signed_transactions)")] == [
        "signed_transaction_id", "external_action_id", "session_id", "envelope_id",
        "approval_action_id", "origin", "chain_id", "taker_address", "account_nonce",
        "raw_signed_sha256", "raw_signed_length", "transaction_hash", "scope_digest",
        "signer_identity", "frozen_at_epoch_s",
    ]
    sql_after = " ".join(conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='signed_transactions'"
    ).fetchone()[0].upper().split())
    assert "CHECK ((ENVELOPE_ID IS NULL) <> (APPROVAL_ACTION_ID IS NULL))" not in sql_after
    assert "ORIGIN" in sql_after and "SCOPE_DIGEST" in sql_after
    assert _rows(conn, "execution_envelopes") == historical_before["execution_envelopes"]
    assert _rows(conn, "approval_actions") == historical_before["approval_actions"]
    signed_after = [
        tuple(row[column] for column in signed_columns)
        for row in conn.execute("SELECT * FROM signed_transactions ORDER BY signed_transaction_id")
    ]
    assert signed_after == signed_before
    for table, before in historical_before.items():
        assert _rows(conn, table) == before
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_already_marked_defective_v3_is_repaired_or_fails_closed(armed) -> None:
    ledger, _policy, _cycle_id, intent = _surface(armed)
    _seed_historical_rows(ledger, intent)
    _legacy_shape(ledger.connection, marked_version=EXECUTION_SCHEMA_VERSION_V3)
    conn = ledger.connection
    migrate_execution_schema_v3_to_v4(conn)
    assert read_execution_schema_version(conn) == EXECUTION_SCHEMA_VERSION
    sql = " ".join(conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='signed_transactions'"
    ).fetchone()[0].upper().split())
    assert "CHECK ((ENVELOPE_ID IS NULL) <> (APPROVAL_ACTION_ID IS NULL))" not in sql


def test_repaired_schema_accepts_external_origin_but_keeps_identity_guards(armed) -> None:
    ledger, policy, cycle_id, intent = _surface(armed)
    _seed_historical_rows(ledger, intent)
    _legacy_shape(ledger.connection, marked_version=EXECUTION_SCHEMA_VERSION_V2)
    ExecutionRuntime(ledger)
    conn = ledger.connection

    from qntyspot.economics import build_intent

    external_intent = build_intent(policy, cycle_id, policy.level("E2"), now_epoch_s=NOW)
    ledger.create_intent(external_intent, now_epoch_s=NOW)
    insert(
        conn,
        "external_actions",
        external_action_id=external_intent.economic_action_id,
        kind="ECONOMIC",
        economic_action_id=external_intent.economic_action_id,
        approval_action_id=None,
        session_id=SESSION_ID,
    )
    valid = signed_row(
        external_intent.economic_action_id,
        signed_transaction_id="40" * 32,
        envelope_id=None,
        approval_action_id=None,
        origin="EXTERNAL_SIGNED_BYTES",
        scope_digest="41" * 32,
        account_nonce=9,
        raw_signed_sha256="42" * 32,
        transaction_hash="0x" + "ad" * 32,
    )
    insert(conn, "signed_transactions", **valid)

    with pytest.raises(sqlite3.IntegrityError, match="action/session"):
        insert(
            conn,
            "signed_transactions",
            **dict(valid, signed_transaction_id="43" * 32, external_action_id="44" * 32,
                   raw_signed_sha256="45" * 32, transaction_hash="0x" + "ae" * 32,
                   account_nonce=10),
        )
    second_cycle = ledger.open_cycle(policy, 1, now_epoch_s=NOW + 1)
    second_intent = build_intent(policy, second_cycle, policy.level("E1"), now_epoch_s=NOW + 1)
    ledger.create_intent(second_intent, now_epoch_s=NOW + 1)
    insert(
        conn,
        "external_actions",
        external_action_id=second_intent.economic_action_id,
        kind="ECONOMIC",
        economic_action_id=second_intent.economic_action_id,
        approval_action_id=None,
        session_id=SESSION_ID,
    )
    with pytest.raises(sqlite3.IntegrityError, match="action/session"):
        insert(
            conn,
            "signed_transactions",
            **dict(valid, signed_transaction_id="46" * 32,
                   external_action_id=second_intent.economic_action_id,
                   session_id="47" * 32,
                   raw_signed_sha256="48" * 32, transaction_hash="0x" + "af" * 32,
                   account_nonce=11),
        )
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "signed_transactions",
            **dict(valid, signed_transaction_id="49" * 32, taker_address="0x" + "11" * 20,
                   raw_signed_sha256="4a" * 32, transaction_hash="0x" + "b0" * 32,
                   account_nonce=12),
        )
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "signed_transactions", **dict(valid, signed_transaction_id="4b" * 32))
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "signed_transactions",
            **dict(valid, signed_transaction_id="4c" * 32, raw_signed_sha256="4d" * 32,
                   transaction_hash="0x" + "b1" * 32, account_nonce=9),
        )
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "signed_transactions",
            **dict(valid, signed_transaction_id="4e" * 32, raw_signed_sha256="4f" * 32,
                   transaction_hash="0x" + "b2" * 32, account_nonce=10),
        )

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM signed_transactions WHERE signed_transaction_id=?", ("40" * 32,))
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(
            "UPDATE signed_transactions SET scope_digest=? WHERE signed_transaction_id=?",
            ("50" * 32, "40" * 32),
        )


def test_repair_rolls_back_if_shape_is_unsupported(armed) -> None:
    ledger, _policy, _cycle_id, _intent = _surface(armed)
    conn = ledger.connection
    conn.execute("PRAGMA foreign_keys=OFF")
    _drop_execution_triggers(conn)
    conn.execute("DROP TABLE signed_transactions")
    conn.execute("CREATE TABLE signed_transactions (signed_transaction_id TEXT PRIMARY KEY) STRICT")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "UPDATE schema_meta SET value=? WHERE key='execution_schema_version'",
        (str(EXECUTION_SCHEMA_VERSION_V3),),
    )
    with pytest.raises(LedgerError, match="columns do not match execution schema v4"):
        migrate_execution_schema_v3_to_v4(conn)
    assert read_execution_schema_version(conn) == EXECUTION_SCHEMA_VERSION_V3


def test_repair_artifact_is_canonical_and_does_not_replace_prior_identity() -> None:
    raw = REPAIR_ARTIFACT.read_bytes()
    artifact = strict_json_loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert raw == canonical_json_bytes(artifact)
    assert REPAIR_SIDECAR.read_text(encoding="ascii") == f"{digest}  {REPAIR_ARTIFACT.name}\n"
    assert artifact["canonical_parent"] == "cf90df0b682d3ea850032ece342e362d56998d17"
    assert artifact["previous_implementation_digest"] == (
        "b74ccdd99b5a5de4f11310014cf29100a60d07d8e350a43cd1f2dc2b678936f7"
    )
    assert artifact["new_implementation_digest"] == (
        "d289031abf773114bc9dc8c57528367531961051c66f1b6efd28c9ee4addcb2a"
    )
    assert artifact["legacy_xor_present_before"] == "YES"
    assert artifact["legacy_xor_present_after"] == "NO"
    assert artifact["production_ledger_modified"] == "NO"
    assert artifact["live_grant_used"] == "NO"
    assert artifact["blockchain_transaction"] == "NO"
    assert artifact["staged_transaction_changed"] == "NO"
