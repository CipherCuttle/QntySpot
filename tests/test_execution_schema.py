"""The Program B execution authority surface, proved at the database level.

The point of these tests is that the invariants are enforced by SQLite, not by
application code being careful. Every uniqueness test therefore writes directly
against the connection: if a constraint only held because some Python function
checked first, these tests would pass while the real guarantee did not exist.

No row here signs, approves, submits, or moves capital. The tables are created
and exercised; no runtime writes them.
"""

from __future__ import annotations

import sqlite3

import pytest

from conftest import NOW, PATH_TO_FILLED, drive, full_receipt
from qntyspot.errors import LedgerError
from qntyspot.ledger.execution_schema import (
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_TABLES,
    apply_execution_schema,
    read_execution_schema_version,
)
from qntyspot.states import IntentState

SESSION_ID = "01" * 32
IDENTITY_DIGEST = "02" * 32
COMMIT = "a890de49e68486476b2385f70ef9c9558896f5b7"
IMPLEMENTATION_DIGEST = "03" * 32
AUTHORITY_DIGEST = "04" * 32
TAKER = "0x00000000000000000000000000000000000000aa"
SPENDER = "0x00000000000000000000000000000000000000dd"
TOKEN = "0x00000000000000000000000000000000000000bb"


@pytest.fixture
def surface(armed):
    """A ledger with the execution authority surface applied and a session row."""
    ledger, policy, cycle_id, intent = armed
    conn = ledger.connection
    apply_execution_schema(conn)
    insert(
        conn,
        "execution_sessions",
        session_id=SESSION_ID,
        identity_digest=IDENTITY_DIGEST,
        repository_commit=COMMIT,
        implementation_digest=IMPLEMENTATION_DIGEST,
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


def insert(conn: sqlite3.Connection, table: str, **columns: object) -> None:
    names = sorted(columns)
    conn.execute(
        f"INSERT INTO {table} ({','.join(names)}) "
        f"VALUES ({','.join(':' + n for n in names)})",
        {name: columns[name] for name in names},
    )


def envelope_row(intent, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "envelope_id": "10" * 32,
        "session_id": SESSION_ID,
        "session_identity_digest": IDENTITY_DIGEST,
        "economic_action_id": intent.economic_action_id,
        "plan_id": "11" * 32,
        "quote_id": "quote-0001",
        "quote_observation_digest": "12" * 32,
        "venue_block_number": 1_000_000,
        "chain_id": 57073,
        "taker_address": TAKER,
        "input_instrument_id": intent.quote_instrument_id,
        "output_instrument_id": intent.instrument_id,
        "max_input_atomic": "1000000",
        "min_output_atomic": "500000",
        "transaction_to": SPENDER,
        "transaction_value_atomic": "0",
        "calldata_sha256": "13" * 32,
        "calldata_length": 324,
        "allowance_target": SPENDER,
        "account_nonce": 7,
        "gas_limit_ceiling": 400_000,
        "max_fee_per_gas_ceiling_atomic": "2000000000",
        "max_priority_fee_per_gas_ceiling_atomic": "1000000",
        "deadline_epoch_s": NOW + 600,
        "authority_policy_digest": AUTHORITY_DIGEST,
        "evidence_digest": "14" * 32,
        "lifecycle": "AUTHORIZED",
        "constructed_at_epoch_s": NOW,
    }
    row.update(overrides)
    return row


def approval_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "approval_action_id": "20" * 32,
        "session_id": SESSION_ID,
        "session_identity_digest": IDENTITY_DIGEST,
        "economic_action_id": None,
        "taker_address": TAKER,
        "token_address": TOKEN,
        "spender_address": SPENDER,
        "requested_allowance_atomic": "1000000",
        "observed_prior_allowance_atomic": "0",
        "authority_policy_digest": AUTHORITY_DIGEST,
        "lifecycle": "AUTHORIZED",
        "deadline_epoch_s": NOW + 600,
        "created_at_epoch_s": NOW,
    }
    row.update(overrides)
    return row


def signed_row(action_id: str, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "signed_transaction_id": "30" * 32,
        "external_action_id": action_id,
        "session_id": SESSION_ID,
        "envelope_id": "10" * 32,
        "approval_action_id": None,
        "chain_id": 57073,
        "taker_address": TAKER,
        "account_nonce": 7,
        "raw_signed_sha256": "31" * 32,
        "raw_signed_length": 512,
        "transaction_hash": "0x" + "ab" * 32,
        "signer_identity": "external-human-controlled-account",
        "frozen_at_epoch_s": NOW,
    }
    row.update(overrides)
    return row


def economic_external_action(conn: sqlite3.Connection, intent) -> str:
    insert(
        conn,
        "external_actions",
        external_action_id=intent.economic_action_id,
        kind="ECONOMIC",
        economic_action_id=intent.economic_action_id,
        approval_action_id=None,
    )
    return intent.economic_action_id


# --------------------------------------------------------------------------
# Applying the surface
# --------------------------------------------------------------------------


def test_the_surface_applies_once_and_stamps_its_version(surface) -> None:
    ledger = surface[0]
    assert read_execution_schema_version(ledger.connection) == EXECUTION_SCHEMA_VERSION
    with pytest.raises(LedgerError, match="already applied"):
        apply_execution_schema(ledger.connection)


def test_the_surface_requires_the_core_ledger_first() -> None:
    conn = sqlite3.connect(":memory:")
    with pytest.raises(LedgerError, match="requires the core ledger"):
        apply_execution_schema(conn)


def test_every_execution_table_is_strict(surface) -> None:
    conn = surface[0].connection
    strictness = {
        row["name"]: row["strict"]
        for row in conn.execute("SELECT name, strict FROM pragma_table_list WHERE schema='main'")
    }
    for table in EXECUTION_TABLES:
        assert strictness[table] == 1, f"{table} must be STRICT"


def test_a_type_confusion_is_a_write_error(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    with pytest.raises(sqlite3.IntegrityError):
        insert(ledger.connection, "execution_envelopes", **envelope_row(intent, chain_id="not-an-int"))


def test_the_surface_reuses_the_existing_intent_table(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    insert(ledger.connection, "execution_envelopes", **envelope_row(intent))
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            ledger.connection,
            "execution_envelopes",
            **envelope_row(intent, envelope_id="19" * 32, economic_action_id="ff" * 32, lifecycle="DRAFT"),
        )


# --------------------------------------------------------------------------
# One economic action, at most one signed transaction
# --------------------------------------------------------------------------


def test_one_economic_action_cannot_hold_two_signed_transactions(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    action_id = economic_external_action(conn, intent)
    insert(conn, "signed_transactions", **signed_row(action_id))
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "signed_transactions",
            **signed_row(
                action_id,
                signed_transaction_id="39" * 32,
                raw_signed_sha256="38" * 32,
                transaction_hash="0x" + "ac" * 32,
                account_nonce=8,
            ),
        )


def test_exact_byte_retransmission_adds_an_attempt_not_a_transaction(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    action_id = economic_external_action(conn, intent)
    insert(conn, "signed_transactions", **signed_row(action_id))
    for ordinal in (0, 1):
        insert(
            conn,
            "submission_attempts",
            submission_attempt_id=f"4{ordinal}" * 32,
            signed_transaction_id="30" * 32,
            provider_id="provider-a",
            attempt_ordinal=ordinal,
            submitted_at_epoch_s=NOW + ordinal,
            acknowledgment="ACCEPTED",
            provider_reported_hash="0x" + "ab" * 32,
            error_class=None,
        )
    assert conn.execute("SELECT COUNT(*) FROM signed_transactions").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM submission_attempts").fetchone()[0] == 2
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "submission_attempts",
            submission_attempt_id="49" * 32,
            signed_transaction_id="30" * 32,
            provider_id="provider-a",
            attempt_ordinal=0,
            submitted_at_epoch_s=NOW + 5,
            acknowledgment="ACCEPTED",
            provider_reported_hash="0x" + "ab" * 32,
            error_class=None,
        )


def test_two_signed_transactions_cannot_collide_on_one_nonce(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    insert(conn, "approval_actions", **approval_row())
    action_id = economic_external_action(conn, intent)
    insert(
        conn,
        "external_actions",
        external_action_id="20" * 32,
        kind="APPROVAL",
        economic_action_id=None,
        approval_action_id="20" * 32,
    )
    insert(conn, "signed_transactions", **signed_row(action_id))
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "signed_transactions",
            **signed_row(
                "20" * 32,
                signed_transaction_id="37" * 32,
                envelope_id=None,
                approval_action_id="20" * 32,
                raw_signed_sha256="36" * 32,
                transaction_hash="0x" + "ad" * 32,
            ),
        )


def test_a_signed_transaction_belongs_to_exactly_one_kind_of_action(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    insert(conn, "approval_actions", **approval_row())
    action_id = economic_external_action(conn, intent)
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "signed_transactions", **signed_row(action_id, approval_action_id="20" * 32))
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "signed_transactions", **signed_row(action_id, envelope_id=None))


def test_signed_transaction_subtype_must_match_external_action_kind(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    insert(conn, "approval_actions", **approval_row())
    economic_id = economic_external_action(conn, intent)
    insert(
        conn,
        "external_actions",
        external_action_id="20" * 32,
        kind="APPROVAL",
        economic_action_id=None,
        approval_action_id="20" * 32,
    )
    with pytest.raises(sqlite3.IntegrityError, match="subtype"):
        insert(
            conn,
            "signed_transactions",
            **signed_row(
                "20" * 32,
                signed_transaction_id="39" * 32,
                raw_signed_sha256="38" * 32,
                transaction_hash="0x" + "ac" * 32,
                account_nonce=8,
            ),
        )
    with pytest.raises(sqlite3.IntegrityError, match="subtype"):
        insert(
            conn,
            "signed_transactions",
            **signed_row(
                economic_id,
                signed_transaction_id="37" * 32,
                envelope_id=None,
                approval_action_id="20" * 32,
                raw_signed_sha256="36" * 32,
                transaction_hash="0x" + "ad" * 32,
                account_nonce=8,
            ),
        )


# --------------------------------------------------------------------------
# External action identity is not a second identity system
# --------------------------------------------------------------------------


def test_an_economic_external_action_id_is_the_economic_action_id(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "external_actions",
            external_action_id="ee" * 32,
            kind="ECONOMIC",
            economic_action_id=intent.economic_action_id,
            approval_action_id=None,
        )


def test_an_external_action_names_exactly_one_underlying_action(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "approval_actions", **approval_row())
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "external_actions",
            external_action_id=intent.economic_action_id,
            kind="ECONOMIC",
            economic_action_id=intent.economic_action_id,
            approval_action_id="20" * 32,
        )
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "external_actions",
            external_action_id="20" * 32,
            kind="ECONOMIC",
            economic_action_id=None,
            approval_action_id="20" * 32,
        )


def test_one_economic_action_maps_to_one_external_action(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    economic_external_action(conn, intent)
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "external_actions",
            external_action_id=intent.economic_action_id,
            kind="ECONOMIC",
            economic_action_id=intent.economic_action_id,
            approval_action_id=None,
        )


# --------------------------------------------------------------------------
# At most one signable thing at a time
# --------------------------------------------------------------------------


def test_only_one_envelope_per_economic_action_may_be_authorized(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "execution_envelopes",
            **envelope_row(intent, envelope_id="18" * 32, account_nonce=8, calldata_sha256="17" * 32),
        )


def test_a_superseded_envelope_leaves_room_for_a_re_quote(surface) -> None:
    ledger, _policy, _cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent, lifecycle="SUPERSEDED"))
    insert(conn, "execution_envelopes", **envelope_row(intent, envelope_id="18" * 32, account_nonce=8))
    assert conn.execute(
        "SELECT COUNT(*) FROM execution_envelopes WHERE lifecycle = 'AUTHORIZED'"
    ).fetchone()[0] == 1


def test_two_authorized_envelopes_cannot_share_a_nonce(surface) -> None:
    ledger, _policy, cycle_id, intent = surface
    conn = ledger.connection
    from qntyspot.economics import build_intent

    other = build_intent(surface[1], cycle_id, surface[1].level("E2"), now_epoch_s=NOW)
    ledger.create_intent(other, now_epoch_s=NOW)
    insert(conn, "execution_envelopes", **envelope_row(intent))
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "execution_envelopes",
            **envelope_row(
                intent,
                envelope_id="18" * 32,
                economic_action_id=other.economic_action_id,
                calldata_sha256="17" * 32,
            ),
        )


def test_only_one_approval_per_taker_token_spender_may_be_authorized(surface) -> None:
    conn = surface[0].connection
    insert(conn, "approval_actions", **approval_row())
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "approval_actions", **approval_row(approval_action_id="21" * 32))
    insert(
        conn,
        "approval_actions",
        **approval_row(approval_action_id="21" * 32, lifecycle="SUPERSEDED"),
    )


@pytest.mark.parametrize(
    "column,value",
    [
        ("max_input_atomic", "1000001"),
        ("min_output_atomic", "499999"),
        ("transaction_to", "0x00000000000000000000000000000000000000ee"),
        ("account_nonce", 8),
    ],
)
def test_authorized_envelope_identity_facts_cannot_be_mutated(surface, column: str, value: object) -> None:
    conn = surface[0].connection
    insert(conn, "execution_envelopes", **envelope_row(surface[3]))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute(f"UPDATE execution_envelopes SET {column} = ?", (value,))


def test_authorized_envelope_cannot_be_deleted(surface) -> None:
    conn = surface[0].connection
    insert(conn, "execution_envelopes", **envelope_row(surface[3]))
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("DELETE FROM execution_envelopes")


@pytest.mark.parametrize(
    "column,value",
    [
        ("spender_address", "0x00000000000000000000000000000000000000ee"),
        ("requested_allowance_atomic", "999999"),
    ],
)
def test_authorized_approval_identity_facts_cannot_be_mutated(
    surface, column: str, value: object
) -> None:
    conn = surface[0].connection
    insert(conn, "approval_actions", **approval_row())
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute(f"UPDATE approval_actions SET {column} = ?", (value,))


def test_authorized_approval_cannot_be_deleted(surface) -> None:
    conn = surface[0].connection
    insert(conn, "approval_actions", **approval_row())
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        conn.execute("DELETE FROM approval_actions")


# --------------------------------------------------------------------------
# Append-only historical facts
# --------------------------------------------------------------------------


APPEND_ONLY = (
    "external_actions",
    "signed_transactions",
    "submission_attempts",
    "chain_observations",
    "reconciliations",
    "operator_control_events",
)


@pytest.mark.parametrize("table", APPEND_ONLY)
def test_historical_fact_tables_carry_append_only_triggers(surface, table: str) -> None:
    conn = surface[0].connection
    triggers = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name = ?", (table,)
        )
    }
    assert {f"{table}_no_update", f"{table}_no_delete"} <= triggers


def test_a_recorded_signed_transaction_cannot_be_rewritten(signed) -> None:
    conn = signed[0].connection
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE signed_transactions SET signer_identity = 'other'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM signed_transactions")


def test_the_kill_switch_log_is_append_only_and_binary(surface) -> None:
    conn = surface[0].connection
    insert(
        conn,
        "operator_control_events",
        session_id=SESSION_ID,
        control="KILL_SWITCH",
        engaged=1,
        occurred_epoch_s=NOW,
        reason="operator halted new external effects",
    )
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "operator_control_events",
            session_id=SESSION_ID,
            control="KILL_SWITCH",
            engaged=2,
            occurred_epoch_s=NOW,
            reason="not a boolean",
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM operator_control_events")


# --------------------------------------------------------------------------
# Chain evidence and reconciliation
# --------------------------------------------------------------------------


def observation_row(action_id: str, **overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "observation_id": "50" * 32,
        "external_action_id": action_id,
        "signed_transaction_id": "30" * 32,
        "provider_id": "provider-a",
        "transaction_hash": "0x" + "ab" * 32,
        "observed_at_epoch_s": NOW,
        "presence": "INCLUDED",
        "block_number": 1_000_000,
        "block_hash": "0x" + "cd" * 32,
        "block_parent_hash": "0x" + "ce" * 32,
        "head_block_number": 1_000_064,
        "head_block_hash": "0x" + "ef" * 32,
        "receipt_status": "SUCCESS",
        "effective_input_atomic": "1000000",
        "effective_output_atomic": "505000",
        "raw_evidence_sha256": "51" * 32,
    }
    row.update(overrides)
    return row


@pytest.fixture
def signed(surface):
    ledger, policy, cycle_id, intent = surface
    conn = ledger.connection
    insert(conn, "execution_envelopes", **envelope_row(intent))
    action_id = economic_external_action(conn, intent)
    insert(conn, "signed_transactions", **signed_row(action_id))
    return ledger, policy, cycle_id, intent, action_id


def test_an_included_observation_must_carry_block_identity(signed) -> None:
    conn, action_id = signed[0].connection, signed[4]
    insert(conn, "chain_observations", **observation_row(action_id))
    for override in (
        {"block_hash": None},
        {"block_number": None},
        {"block_parent_hash": None},
        {"receipt_status": None},
    ):
        with pytest.raises(sqlite3.IntegrityError):
            insert(
                conn,
                "chain_observations",
                **observation_row(action_id, observation_id="5f" * 32, **override),
            )


def test_an_absent_observation_must_not_carry_a_receipt(signed) -> None:
    conn, action_id = signed[0].connection, signed[4]
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "chain_observations",
            **observation_row(action_id, presence="ABSENT"),
        )
    insert(
        conn,
        "chain_observations",
        **observation_row(
            action_id,
            presence="ABSENT",
            block_number=None,
            block_hash=None,
            block_parent_hash=None,
            receipt_status=None,
            effective_input_atomic=None,
            effective_output_atomic=None,
        ),
    )


def test_effective_amounts_require_a_successful_receipt(signed) -> None:
    conn, action_id = signed[0].connection, signed[4]
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "chain_observations",
            **observation_row(action_id, receipt_status="REVERTED"),
        )


@pytest.mark.parametrize("presence", ["PENDING", "ABSENT"])
def test_non_included_observation_cannot_carry_settlement_amounts(signed, presence: str) -> None:
    conn, action_id = signed[0].connection, signed[4]
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "chain_observations",
            **observation_row(
                action_id,
                presence=presence,
                block_number=None,
                block_hash=None,
                block_parent_hash=None,
                receipt_status=None,
                effective_input_atomic="1000000",
                effective_output_atomic="505000",
            ),
        )


def test_included_observation_head_cannot_precede_inclusion(signed) -> None:
    conn, action_id = signed[0].connection, signed[4]
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "chain_observations",
            **observation_row(
                action_id,
                head_block_number=999_999,
                head_block_hash="0x" + "ef" * 32,
            ),
        )


def test_a_non_canonical_atomic_amount_is_refused(signed) -> None:
    conn, action_id = signed[0].connection, signed[4]
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "chain_observations",
            **observation_row(action_id, effective_output_atomic="00505000"),
        )


def test_only_a_settled_reconciliation_may_carry_a_receipt(signed) -> None:
    ledger, policy, _cycle_id, intent, action_id = signed
    conn = ledger.connection
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    receipt = full_receipt(intent)
    ledger.append_fill_receipt(receipt, now_epoch_s=NOW)
    drive(ledger, intent.economic_action_id, IntentState.RECONCILED, IntentState.FILLED)
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "reconciliations",
            reconciliation_id="60" * 32,
            external_action_id=action_id,
            verdict="AMBIGUOUS",
            receipt_id=receipt.receipt_id,
            confirmation_depth=64,
            agreeing_provider_count=2,
            reconciled_at_epoch_s=NOW,
            evidence_digest="61" * 32,
        )
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "reconciliations",
            reconciliation_id="60" * 32,
            external_action_id=action_id,
            verdict="SETTLED",
            receipt_id=None,
            confirmation_depth=64,
            agreeing_provider_count=2,
            reconciled_at_epoch_s=NOW,
            evidence_digest="61" * 32,
        )
    insert(
        conn,
        "reconciliations",
        reconciliation_id="60" * 32,
        external_action_id=action_id,
        verdict="SETTLED",
        receipt_id=receipt.receipt_id,
        confirmation_depth=64,
        agreeing_provider_count=2,
        reconciled_at_epoch_s=NOW,
        evidence_digest="61" * 32,
    )
    with pytest.raises(sqlite3.IntegrityError):
        insert(
            conn,
            "reconciliations",
            reconciliation_id="62" * 32,
            external_action_id=action_id,
            verdict="AMBIGUOUS",
            receipt_id=None,
            confirmation_depth=0,
            agreeing_provider_count=0,
            reconciled_at_epoch_s=NOW,
            evidence_digest="63" * 32,
        )


def test_approval_external_action_cannot_carry_a_fill_receipt(signed) -> None:
    conn = signed[0].connection
    insert(conn, "approval_actions", **approval_row())
    insert(
        conn,
        "external_actions",
        external_action_id="20" * 32,
        kind="APPROVAL",
        economic_action_id=None,
        approval_action_id="20" * 32,
    )
    with pytest.raises(sqlite3.IntegrityError, match="only economic"):
        insert(
            conn,
            "reconciliations",
            reconciliation_id="70" * 32,
            external_action_id="20" * 32,
            verdict="SETTLED",
            receipt_id="71" * 32,
            confirmation_depth=64,
            agreeing_provider_count=2,
            reconciled_at_epoch_s=NOW,
            evidence_digest="72" * 32,
        )


def test_the_core_ledger_still_replays_with_the_surface_applied(surface) -> None:
    """Adding the surface must not disturb the existing canonical state."""
    from qntyspot.ledger import assert_replay_equivalence

    ledger, _policy, _cycle_id, intent = surface
    insert(ledger.connection, "execution_envelopes", **envelope_row(intent))
    ledger.integrity_check()
    assert_replay_equivalence(ledger)
