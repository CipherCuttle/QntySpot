"""Exactly-once economic intent, enforced by the database."""

from __future__ import annotations

import dataclasses
import threading

import pytest

from conftest import NOW, PATH_TO_FILLED, drive, full_receipt
from qntyspot.domain import Side, economic_action_id
from qntyspot.economics import build_intent
from qntyspot.errors import DuplicateEconomicActionError, LedgerError
from qntyspot.ledger import open_ledger
from qntyspot.states import IntentState as S


def test_economic_action_id_is_determined_by_exactly_five_components() -> None:
    kwargs = dict(
        policy_id="p", instrument_id="i", cycle_id="c", level_id="l", side=Side.BUY
    )
    base = economic_action_id(**kwargs)
    assert base == economic_action_id(**kwargs)
    for field, other in [
        ("policy_id", "p2"),
        ("instrument_id", "i2"),
        ("cycle_id", "c2"),
        ("level_id", "l2"),
        ("side", Side.SELL),
    ]:
        assert economic_action_id(**{**kwargs, field: other}) != base


def test_creating_the_same_economic_action_twice_is_refused(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    with pytest.raises(DuplicateEconomicActionError):
        ledger.create_intent(intent, now_epoch_s=NOW)


def test_a_rebuilt_identical_intent_is_still_the_same_action(armed) -> None:
    ledger, policy, cycle_id, _ = armed
    rebuilt = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW + 500)
    with pytest.raises(DuplicateEconomicActionError):
        ledger.create_intent(rebuilt, now_epoch_s=NOW + 500)


def test_a_cancelled_rung_cannot_be_rearmed_within_the_same_cycle(armed) -> None:
    """Cancellation frees budget. It does not free the economic identity."""
    ledger, policy, cycle_id, intent = armed
    ledger.transition(intent.economic_action_id, S.CANCELLED, now_epoch_s=NOW)
    rebuilt = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW + 10)
    with pytest.raises(DuplicateEconomicActionError):
        ledger.create_intent(rebuilt, now_epoch_s=NOW + 10)


def test_the_same_rung_in_the_next_cycle_is_a_different_action(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    next_cycle = ledger.open_cycle(policy, 1, now_epoch_s=NOW)
    rearmed = build_intent(policy, next_cycle, policy.level("E1"), now_epoch_s=NOW)
    assert rearmed.economic_action_id != intent.economic_action_id
    ledger.create_intent(rearmed, now_epoch_s=NOW)  # accepted


def test_the_composite_constraint_catches_a_forged_action_id(armed) -> None:
    """The primary key is a digest, so a caller could in principle supply a
    different one for the same five components. The composite UNIQUE
    constraint is what makes that impossible rather than merely unlikely."""
    ledger, policy, cycle_id, intent = armed
    forged = dataclasses.replace(intent, economic_action_id="0" * 64)
    with pytest.raises(DuplicateEconomicActionError):
        ledger.create_intent(forged, now_epoch_s=NOW)


def test_an_action_can_hold_at_most_one_reservation(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED,
          S.RESERVED)
    rows = ledger.connection.execute(
        "SELECT COUNT(*) FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0]
    assert rows == 1
    # RESERVED -> RESERVED is not a legal transition, so there is no second path in.
    with pytest.raises(Exception):
        ledger.transition(intent.economic_action_id, S.RESERVED, now_epoch_s=NOW)


def test_a_duplicate_external_settlement_reference_is_refused(armed) -> None:
    ledger, policy, cycle_id, intent = armed
    drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
    receipt = full_receipt(intent, ref="0xabc")
    assert ledger.append_fill_receipt(receipt, now_epoch_s=NOW)
    with pytest.raises(LedgerError, match="duplicate fill receipt"):
        ledger.append_fill_receipt(receipt, now_epoch_s=NOW)


def test_two_workers_racing_to_create_the_same_action_produce_one_row(tmp_path) -> None:
    """Two processes' worth of concurrency, using two independent connections.

    The losing worker must fail; it must not silently proceed as though it had
    reserved the intent.
    """
    from conftest import base_policy_doc
    from qntyspot.policy import parse_policy

    db = str(tmp_path / "race.sqlite3")
    policy = parse_policy(base_policy_doc())
    with open_ledger(db) as setup:
        setup.admit_policy(policy)
        cycle_id = setup.open_cycle(policy, 0, now_epoch_s=NOW)

    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        with open_ledger(db) as led:
            barrier.wait(timeout=30)
            try:
                led.create_intent(intent, now_epoch_s=NOW)
                result = "created"
            except DuplicateEconomicActionError:
                result = "duplicate"
            except Exception as exc:  # pragma: no cover - surfaced on failure
                result = f"error:{exc!r}"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert sorted(outcomes) == ["created", "duplicate"]
    with open_ledger(db) as led:
        assert led.connection.execute("SELECT COUNT(*) FROM intents").fetchone()[0] == 1
        led.integrity_check()
