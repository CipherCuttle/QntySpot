"""Crash and restart.

Each test kills the process at a durable boundary by dropping the connection
without ceremony, reopening the same file, and running recovery. The rule under
test is one sentence: restart must never infer that an economic action should
be executed again merely because its completion is unknown.
"""

from __future__ import annotations

import pytest

from conftest import NOW, base_policy_doc, drive, full_receipt
from qntyspot.domain import FillReceiptV0
from qntyspot.economics import build_intent
from qntyspot.errors import DuplicateEconomicActionError
from qntyspot.ledger import assert_replay_equivalence, open_ledger, recover
from qntyspot.ledger.recovery import RecoveryDisposition
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState as S

TO_RESERVED = (S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED)


def crash_at(db: str, *states: S, with_receipt: bool = False):
    """Run to a boundary, then die without closing anything gracefully."""
    policy = parse_policy(base_policy_doc())
    ledger = open_ledger(db)
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    drive(ledger, intent.economic_action_id, *states)
    if with_receipt:
        ledger.append_fill_receipt(full_receipt(intent), now_epoch_s=NOW)
    # No close(), no flush, no shutdown hook: every write above was committed,
    # and anything that was not is simply gone.
    del ledger
    return policy, cycle_id, intent


@pytest.mark.parametrize(
    "states,expected_state,disposition",
    [
        pytest.param((), S.CANCELLED, RecoveryDisposition.ABANDON, id="before-trigger"),
        pytest.param(
            (S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED),
            S.CANCELLED,
            RecoveryDisposition.ABANDON,
            id="before-reservation",
        ),
        pytest.param(
            TO_RESERVED, S.CANCELLED, RecoveryDisposition.ABANDON, id="after-reservation"
        ),
        pytest.param(
            TO_RESERVED + (S.SIGNED,),
            S.SAFE_HALT,
            RecoveryDisposition.RECONCILIATION_REQUIRED,
            id="after-signed-placeholder",
        ),
        pytest.param(
            TO_RESERVED + (S.SIGNED, S.SUBMITTED),
            S.SAFE_HALT,
            RecoveryDisposition.RECONCILIATION_REQUIRED,
            id="after-submitted-placeholder",
        ),
        pytest.param(
            TO_RESERVED + (S.SIGNED, S.SUBMITTED, S.INCLUDED),
            S.SAFE_HALT,
            RecoveryDisposition.RECONCILIATION_REQUIRED,
            id="before-fill-reconciliation",
        ),
        pytest.param(
            TO_RESERVED + (S.SIGNED, S.SUBMITTED, S.INCLUDED, S.CONFIRMED),
            S.SAFE_HALT,
            RecoveryDisposition.RECONCILIATION_REQUIRED,
            id="confirmed-but-unreconciled",
        ),
    ],
)
def test_recovery_disposition_at_each_crash_boundary(
    tmp_path, states, expected_state, disposition
) -> None:
    db = str(tmp_path / "crash.sqlite3")
    policy, cycle_id, intent = crash_at(db, *states)

    with open_ledger(db) as restarted:
        actions = recover(restarted, now_epoch_s=NOW + 60)
        assert len(actions) == 1
        assert actions[0].disposition is disposition
        assert restarted.intent_state(intent.economic_action_id) is expected_state
        restarted.integrity_check()


def test_a_crash_after_the_fill_receipt_completes_from_recorded_evidence(tmp_path) -> None:
    """Bookkeeping over durable evidence is not a new economic action."""
    db = str(tmp_path / "crash-receipt.sqlite3")
    states = TO_RESERVED + (S.SIGNED, S.SUBMITTED, S.INCLUDED, S.CONFIRMED, S.RECONCILED)
    policy, cycle_id, intent = crash_at(db, *states, with_receipt=True)

    with open_ledger(db) as restarted:
        actions = recover(restarted, now_epoch_s=NOW + 60)
        assert actions[0].disposition is RecoveryDisposition.COMPLETE_FROM_RECEIPT
        assert restarted.intent_state(intent.economic_action_id) is S.FILLED
        # The capital is committed, not released: the trade happened.
        assert restarted.held_atomic() == 100_000_000


def test_reconciled_without_a_receipt_is_a_contradiction_and_halts(tmp_path) -> None:
    db = str(tmp_path / "crash-contradiction.sqlite3")
    states = TO_RESERVED + (S.SIGNED, S.SUBMITTED, S.INCLUDED, S.CONFIRMED, S.RECONCILED)
    policy, cycle_id, intent = crash_at(db, *states, with_receipt=False)

    with open_ledger(db) as restarted:
        actions = recover(restarted, now_epoch_s=NOW + 60)
        assert actions[0].disposition is RecoveryDisposition.RECONCILIATION_REQUIRED
        assert restarted.intent_state(intent.economic_action_id) is S.SAFE_HALT


@pytest.mark.parametrize(
    "states",
    [
        (),
        (S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED),
        TO_RESERVED,
        TO_RESERVED + (S.SIGNED,),
        TO_RESERVED + (S.SIGNED, S.SUBMITTED),
        TO_RESERVED + (S.SIGNED, S.SUBMITTED, S.INCLUDED, S.CONFIRMED),
    ],
    ids=["armed", "simulated", "reserved", "signed", "submitted", "confirmed"],
)
def test_restart_never_rearms_the_same_rung(tmp_path, states) -> None:
    """The point of the whole design: no crash produces a second attempt."""
    db = str(tmp_path / "crash-rearm.sqlite3")
    policy, cycle_id, intent = crash_at(db, *states)

    with open_ledger(db) as restarted:
        recover(restarted, now_epoch_s=NOW + 60)
        rebuilt = build_intent(
            policy, cycle_id, policy.level("E1"), now_epoch_s=NOW + 120
        )
        assert rebuilt.economic_action_id == intent.economic_action_id
        with pytest.raises(DuplicateEconomicActionError):
            restarted.create_intent(rebuilt, now_epoch_s=NOW + 120)


@pytest.mark.parametrize(
    "states",
    [
        (),
        TO_RESERVED,
        TO_RESERVED + (S.SIGNED, S.SUBMITTED),
    ],
    ids=["armed", "reserved", "submitted"],
)
def test_recovery_is_idempotent(tmp_path, states) -> None:
    """Recovering twice changes nothing the second time."""
    db = str(tmp_path / "crash-idem.sqlite3")
    crash_at(db, *states)

    with open_ledger(db) as restarted:
        first = recover(restarted, now_epoch_s=NOW + 60)
        assert first
        digest_after_first = restarted.snapshot().digest()
        second = recover(restarted, now_epoch_s=NOW + 120)
        assert second == ()
        assert restarted.snapshot().digest() == digest_after_first


def test_uncommitted_work_simply_vanishes(tmp_path) -> None:
    """A crash mid-transaction leaves no partial economic state behind."""
    db = str(tmp_path / "crash-partial.sqlite3")
    policy = parse_policy(base_policy_doc())
    ledger = open_ledger(db)
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)

    # Begin a write and die inside it.
    conn = ledger.connection
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "INSERT INTO intents (economic_action_id, policy_id, instrument_id, "
        "quote_instrument_id, network_id, cycle_id, level_id, side, kind, state, "
        "quote_exposure_atomic, bounds_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            intent.economic_action_id, intent.policy_id, intent.instrument_id,
            intent.quote_instrument_id, intent.network_id, intent.cycle_id,
            intent.level_id, intent.side.value, intent.kind.value, "ARMED",
            str(intent.quote_exposure_atomic), "{}",
        ),
    )
    conn.close()  # abrupt: the open transaction is never committed
    del ledger

    with open_ledger(db) as restarted:
        assert restarted.connection.execute(
            "SELECT COUNT(*) FROM intents"
        ).fetchone()[0] == 0
        assert recover(restarted, now_epoch_s=NOW + 60) == ()
        restarted.integrity_check()
        # The rung is genuinely free again, because nothing durable happened.
        restarted.create_intent(intent, now_epoch_s=NOW + 60)


def test_budget_held_across_a_crash_is_released_only_when_it_is_safe(tmp_path) -> None:
    db_pre = str(tmp_path / "pre-sign.sqlite3")
    crash_at(db_pre, *TO_RESERVED)
    with open_ledger(db_pre) as restarted:
        assert restarted.held_atomic() == 100_000_000
        recover(restarted, now_epoch_s=NOW + 60)
        # Nothing was signed, so the capital genuinely is not at risk.
        assert restarted.held_atomic() == 0

    db_post = str(tmp_path / "post-sign.sqlite3")
    crash_at(db_post, *TO_RESERVED, S.SIGNED, S.SUBMITTED)
    with open_ledger(db_post) as restarted:
        recover(restarted, now_epoch_s=NOW + 60)
        # A submitted action may still land. Releasing its budget would let the
        # portfolio commit the same capital twice, so SAFE_HALT keeps it held
        # until a human or a reconciler resolves it.
        action_id = restarted.connection.execute(
            "SELECT economic_action_id FROM intents"
        ).fetchone()[0]
        assert restarted.intent_state(action_id) is S.SAFE_HALT
        assert restarted.held_atomic() == 100_000_000
        assert restarted.connection.execute(
            "SELECT status FROM budget_reservations"
        ).fetchone()[0] == "QUARANTINED"
        restarted.integrity_check()


@pytest.mark.parametrize(
    "states",
    [(), TO_RESERVED, TO_RESERVED + (S.SIGNED, S.SUBMITTED, S.INCLUDED)],
    ids=["armed", "reserved", "included"],
)
def test_the_recovered_ledger_still_replays_exactly(tmp_path, states) -> None:
    db = str(tmp_path / "crash-replay.sqlite3")
    crash_at(db, *states)
    with open_ledger(db) as restarted:
        recover(restarted, now_epoch_s=NOW + 60)
        assert_replay_equivalence(restarted)
