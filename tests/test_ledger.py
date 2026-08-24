"""Ledger invariants that the schema itself is responsible for."""

from __future__ import annotations

import sqlite3

import pytest

from conftest import NOW, PATH_TO_FILLED, base_policy_doc, drive, full_receipt
from qntyspot.domain import CycleStatus, FillReceiptV0
from qntyspot.economics import build_intent
from qntyspot.errors import LedgerError, SchemaVersionError
from qntyspot.ledger import SCHEMA_VERSION, open_ledger
from qntyspot.ledger.atomics import decode_atomic, encode_atomic
from qntyspot.ledger.store import cycle_id_for
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState as S


def test_a_fresh_ledger_is_stamped_and_consistent(ledger) -> None:
    assert ledger.snapshot().schema_version == SCHEMA_VERSION
    ledger.integrity_check()
    authority = ledger.connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'authority'"
    ).fetchone()[0]
    assert "OFFLINE_CORE_ONLY" in authority


def test_foreign_keys_are_enforced_on_the_connection(ledger) -> None:
    assert ledger.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError):
        ledger.connection.execute(
            "INSERT INTO cycles (cycle_id, policy_id, cycle_index, status) "
            "VALUES ('c', 'no-such-policy', 0, 'OPEN')"
        )


def test_an_unknown_schema_version_is_refused(tmp_path) -> None:
    db = str(tmp_path / "v.sqlite3")
    with open_ledger(db) as led:
        led.connection.execute("UPDATE schema_meta SET value='99' WHERE key='schema_version'")
    with pytest.raises(SchemaVersionError, match="99"):
        open_ledger(db)


def test_opening_a_non_ledger_database_without_create_is_refused(tmp_path) -> None:
    db = str(tmp_path / "empty.sqlite3")
    sqlite3.connect(db).close()
    with pytest.raises(SchemaVersionError, match="no QntySpot ledger"):
        open_ledger(db, create=False)


# -- append-only ------------------------------------------------------------


def test_state_events_cannot_be_updated_or_deleted(armed) -> None:
    ledger, *_ = armed
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        ledger.connection.execute("UPDATE state_events SET to_state = 'FILLED'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        ledger.connection.execute("DELETE FROM state_events")


def test_fill_receipts_cannot_be_updated_or_deleted(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    ledger.append_fill_receipt(full_receipt(intent), now_epoch_s=NOW)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        ledger.connection.execute("UPDATE fill_receipts SET fee_atomic = '1'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        ledger.connection.execute("DELETE FROM fill_receipts")


def test_every_state_change_leaves_an_event(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.CANCELLED)
    events = [
        e for e in ledger.events() if e["economic_action_id"] == intent.economic_action_id
    ]
    assert [e["to_state"] for e in events] == [
        "ARMED", "TRIGGERED", "QUOTE_PINNED", "CANCELLED"
    ]
    assert [e["from_state"] for e in events] == [
        None, "ARMED", "TRIGGERED", "QUOTE_PINNED"
    ]


# -- policies and cycles ----------------------------------------------------


def test_admitting_the_same_policy_twice_is_idempotent(ledger, policy) -> None:
    assert ledger.admit_policy(policy) == ledger.admit_policy(policy)
    assert ledger.connection.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 1


def test_conflicting_instrument_facts_are_refused(ledger, policy) -> None:
    ledger.admit_policy(policy)
    doc = base_policy_doc()
    doc["policy_name"] = "same-token-different-decimals"
    doc["base"]["decimals"] = 8
    with pytest.raises(LedgerError, match="different identity facts"):
        ledger.admit_policy(parse_policy(doc))


def test_cycle_identity_is_deterministic(ledger, policy) -> None:
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    assert cycle_id == cycle_id_for(policy.policy_id, 0)


def test_reopening_a_cycle_is_refused(ledger, policy) -> None:
    ledger.admit_policy(policy)
    ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    with pytest.raises(LedgerError, match="already exists"):
        ledger.open_cycle(policy, 0, now_epoch_s=NOW)


def test_the_policy_cycle_limit_is_enforced(ledger, policy) -> None:
    ledger.admit_policy(policy)
    for index in range(policy.max_cycles):
        ledger.open_cycle(policy, index, now_epoch_s=NOW)
    with pytest.raises(LedgerError, match="max_cycles"):
        ledger.open_cycle(policy, policy.max_cycles, now_epoch_s=NOW)


def test_closing_a_cycle_twice_is_refused(ledger, policy) -> None:
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    ledger.close_cycle(cycle_id, CycleStatus.COMPLETED, now_epoch_s=NOW)
    with pytest.raises(LedgerError, match="already"):
        ledger.close_cycle(cycle_id, CycleStatus.HALTED, now_epoch_s=NOW)


# -- receipts ---------------------------------------------------------------


def test_a_receipt_before_submission_is_refused(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    with pytest.raises(LedgerError, match="not meaningful"):
        ledger.append_fill_receipt(full_receipt(intent), now_epoch_s=NOW)


def test_a_partial_fill_at_the_limit_price_is_within_bounds(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    half_in = intent.bounds.max_input_atomic // 2
    required_out = -((-intent.bounds.min_output_atomic * half_in)
                     // intent.bounds.max_input_atomic)
    receipt = FillReceiptV0(
        receipt_id="half", economic_action_id=intent.economic_action_id,
        external_ref="0xhalf", input_atomic_filled=half_in,
        output_atomic_filled=required_out, fee_atomic=0,
        observed_at_epoch_s=NOW, source="test",
    )
    assert ledger.append_fill_receipt(receipt, now_epoch_s=NOW) is True
    assert ledger.intent_state(intent.economic_action_id) is S.CONFIRMED


def test_a_partial_fill_at_a_worse_price_halts(armed) -> None:
    """A partial fill must honour the same price bound as a full one."""
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    half_in = intent.bounds.max_input_atomic // 2
    required_out = -((-intent.bounds.min_output_atomic * half_in)
                     // intent.bounds.max_input_atomic)
    receipt = FillReceiptV0(
        receipt_id="half-bad", economic_action_id=intent.economic_action_id,
        external_ref="0xhalfbad", input_atomic_filled=half_in,
        output_atomic_filled=required_out - 1, fee_atomic=0,
        observed_at_epoch_s=NOW, source="test",
    )
    assert ledger.append_fill_receipt(receipt, now_epoch_s=NOW) is False
    assert ledger.intent_state(intent.economic_action_id) is S.SAFE_HALT


def test_cumulative_overfill_halts(armed) -> None:
    """Two receipts that individually fit but together exceed the maximum."""
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    two_thirds = intent.bounds.max_input_atomic * 2 // 3
    out = -((-intent.bounds.min_output_atomic * two_thirds)
            // intent.bounds.max_input_atomic)
    first = FillReceiptV0(
        receipt_id="p1", economic_action_id=intent.economic_action_id,
        external_ref="0xp1", input_atomic_filled=two_thirds,
        output_atomic_filled=out, fee_atomic=0, observed_at_epoch_s=NOW, source="t",
    )
    assert ledger.append_fill_receipt(first, now_epoch_s=NOW) is True
    second = FillReceiptV0(
        receipt_id="p2", economic_action_id=intent.economic_action_id,
        external_ref="0xp2", input_atomic_filled=two_thirds,
        output_atomic_filled=out, fee_atomic=0, observed_at_epoch_s=NOW, source="t",
    )
    assert ledger.append_fill_receipt(second, now_epoch_s=NOW) is False
    assert ledger.intent_state(intent.economic_action_id) is S.SAFE_HALT


def test_an_overspending_fill_halts(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    receipt = FillReceiptV0(
        receipt_id="over", economic_action_id=intent.economic_action_id,
        external_ref="0xover",
        input_atomic_filled=intent.bounds.max_input_atomic + 1,
        output_atomic_filled=intent.bounds.min_output_atomic * 10,
        fee_atomic=0, observed_at_epoch_s=NOW, source="test",
    )
    assert ledger.append_fill_receipt(receipt, now_epoch_s=NOW) is False
    assert ledger.intent_state(intent.economic_action_id) is S.SAFE_HALT


def test_a_receipt_is_kept_even_when_it_forces_a_halt(armed) -> None:
    """External truth is recorded whether or not the ledger likes it."""
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    receipt = FillReceiptV0(
        receipt_id="kept", economic_action_id=intent.economic_action_id,
        external_ref="0xkept",
        input_atomic_filled=intent.bounds.max_input_atomic,
        output_atomic_filled=1, fee_atomic=0, observed_at_epoch_s=NOW, source="test",
    )
    ledger.append_fill_receipt(receipt, now_epoch_s=NOW)
    stored = ledger.connection.execute(
        "SELECT receipt_id, output_atomic_filled FROM fill_receipts"
    ).fetchone()
    assert stored[0] == "kept"
    assert decode_atomic(stored[1]) == 1


# -- atomic amount storage --------------------------------------------------


def test_atomic_amounts_survive_beyond_64_bit_range() -> None:
    huge = 10**30 + 7
    assert decode_atomic(encode_atomic(huge)) == huge


@pytest.mark.parametrize("bad", ["01", "", "-1", "1.0", " 1", "1e3", None, "abc"])
def test_non_canonical_stored_amounts_are_refused(bad) -> None:
    with pytest.raises(LedgerError):
        decode_atomic(bad)


@pytest.mark.parametrize("bad", [-1, 1.5, "1", True, None])
def test_only_non_negative_ints_may_be_encoded(bad) -> None:
    with pytest.raises(LedgerError):
        encode_atomic(bad)


def test_the_schema_refuses_a_non_canonical_amount(ledger, policy) -> None:
    ledger.admit_policy(policy)
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        ledger.connection.execute(
            "UPDATE policies SET allocation_atomic = '01.5'"
        )


# -- transactionality -------------------------------------------------------


def test_a_failed_write_leaves_no_trace(ledger, policy) -> None:
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    before = ledger.snapshot().digest()
    with pytest.raises(Exception):
        ledger.transition(intent.economic_action_id, S.FILLED, now_epoch_s=NOW)
    assert ledger.snapshot().digest() == before


def test_an_unknown_action_cannot_be_transitioned(ledger) -> None:
    with pytest.raises(LedgerError, match="unknown economic action"):
        ledger.transition("0" * 64, S.TRIGGERED, now_epoch_s=NOW)


def test_a_negative_timestamp_is_refused(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    with pytest.raises(LedgerError, match="non-negative"):
        ledger.transition(intent.economic_action_id, S.TRIGGERED, now_epoch_s=-1)
