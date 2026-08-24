"""Deterministic reconstruction from an empty database plus the log."""

from __future__ import annotations

import pytest

from conftest import NOW, PATH_TO_FILLED, base_policy_doc, drive, full_receipt
from qntyspot.domain import CycleStatus, FillReceiptV0
from qntyspot.economics import build_intent
from qntyspot.errors import ReplayDivergenceError
from qntyspot.ledger import assert_replay_equivalence, open_ledger, reconstruct
from qntyspot.ledger.replay import replay_into
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState as S

LIFECYCLE_BOUNDARIES = [
    (),
    (S.TRIGGERED,),
    (S.TRIGGERED, S.QUOTE_PINNED),
    (S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED),
    (S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED),
    PATH_TO_FILLED[:5],
    PATH_TO_FILLED[:6],
    PATH_TO_FILLED[:7],
    PATH_TO_FILLED,
]


def build(states=(), *, with_receipt: bool = False, terminal=None):
    """A ledger driven to a chosen point in the lifecycle."""
    policy = parse_policy(base_policy_doc())
    ledger = open_ledger()
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    drive(ledger, intent.economic_action_id, *states)
    if with_receipt:
        ledger.append_fill_receipt(full_receipt(intent), now_epoch_s=NOW)
    if terminal is not None:
        ledger.transition(intent.economic_action_id, terminal, now_epoch_s=NOW)
    return ledger, policy, cycle_id, intent


@pytest.mark.parametrize("states", LIFECYCLE_BOUNDARIES, ids=lambda s: str(len(s)))
def test_replay_reproduces_state_at_every_lifecycle_boundary(states) -> None:
    ledger, *_ = build(states)
    assert_replay_equivalence(ledger)


def test_replay_reproduces_a_completed_cycle_with_receipts() -> None:
    ledger, policy, cycle_id, intent = build(PATH_TO_FILLED, with_receipt=True)
    ledger.transition(intent.economic_action_id, S.RECONCILED, now_epoch_s=NOW)
    ledger.transition(intent.economic_action_id, S.FILLED, now_epoch_s=NOW)
    ledger.close_cycle(cycle_id, CycleStatus.COMPLETED, now_epoch_s=NOW)
    assert_replay_equivalence(ledger)


def test_replaying_twice_produces_byte_identical_state() -> None:
    ledger, policy, cycle_id, intent = build(PATH_TO_FILLED, with_receipt=True)
    first = reconstruct(ledger).snapshot()
    second = reconstruct(ledger).snapshot()
    from qntyspot.canon import canonical_json_bytes

    assert canonical_json_bytes(first.canonical_object()) == canonical_json_bytes(
        second.canonical_object()
    )
    assert first.digest() == second.digest()


def test_replay_reproduces_derived_inventory_and_proceeds() -> None:
    """Reconstruction must reproduce the conclusions, not only the log."""
    policy = parse_policy(base_policy_doc())
    ledger = open_ledger()
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)

    entry = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(entry, now_epoch_s=NOW)
    drive(ledger, entry.economic_action_id, *PATH_TO_FILLED)
    ledger.append_fill_receipt(full_receipt(entry, ref="0xbuy"), now_epoch_s=NOW)
    drive(ledger, entry.economic_action_id, S.RECONCILED, S.FILLED)

    inventory = ledger.inventory_atomic(cycle_id)
    assert inventory > 0

    exit_intent = build_intent(
        policy, cycle_id, policy.level("X1"), now_epoch_s=NOW, inventory_atomic=inventory
    )
    ledger.create_intent(exit_intent, now_epoch_s=NOW)
    drive(ledger, exit_intent.economic_action_id, *PATH_TO_FILLED)
    ledger.append_fill_receipt(full_receipt(exit_intent, ref="0xsell"), now_epoch_s=NOW)
    drive(ledger, exit_intent.economic_action_id, S.RECONCILED, S.FILLED)

    projection = ledger.cycle_projection(cycle_id)
    assert int(projection["base_acquired_atomic"]) == inventory
    assert int(projection["base_disposed_atomic"]) == inventory // 2
    assert int(projection["filled_base_inventory_atomic"]) == inventory - inventory // 2
    assert int(projection["realized_quote_proceeds_atomic"]) > 0
    assert projection["next_eligible_entry_levels"] == ["E2"]
    assert projection["next_eligible_exit_levels"] == ["X2"]

    with reconstruct(ledger) as replayed:
        assert replayed.cycle_projection(cycle_id) == projection


def test_replay_target_must_be_empty() -> None:
    ledger, *_ = build((S.TRIGGERED,))
    with pytest.raises(Exception, match="empty ledger"):
        replay_into(
            ledger,
            canonical_policies=ledger.canonical_policies(),
            events=ledger.events(),
        )


def test_a_strictly_increasing_sequence_is_required() -> None:
    ledger, *_ = build((S.TRIGGERED,))
    events = ledger.events()
    replayed_out_of_order = events + [dict(events[-1])]  # repeats the last seq
    with open_ledger() as target:
        with pytest.raises(ReplayDivergenceError, match="does not follow"):
            replay_into(
                target,
                canonical_policies=ledger.canonical_policies(),
                events=replayed_out_of_order,
            )


def test_an_out_of_order_stream_never_reconstructs_silently() -> None:
    ledger, *_ = build((S.TRIGGERED,))
    with open_ledger() as target:
        with pytest.raises(ReplayDivergenceError):
            replay_into(
                target,
                canonical_policies=ledger.canonical_policies(),
                events=list(reversed(ledger.events())),
            )


def test_a_transition_that_is_no_longer_legal_stops_replay() -> None:
    """A tampered log is refused rather than reconstructed into a fiction."""
    ledger, *_ = build((S.TRIGGERED,))
    events = [dict(e) for e in ledger.events()]
    for event in events:
        if event["to_state"] == "TRIGGERED":
            event["to_state"] = "FILLED"
    with open_ledger() as target:
        with pytest.raises(ReplayDivergenceError, match="illegal transition"):
            replay_into(
                target, canonical_policies=ledger.canonical_policies(), events=events
            )


def test_a_transition_whose_recorded_source_disagrees_stops_replay() -> None:
    ledger, *_ = build((S.TRIGGERED, S.QUOTE_PINNED))
    events = [dict(e) for e in ledger.events()]
    for event in events:
        if event["to_state"] == "QUOTE_PINNED":
            event["from_state"] = "SIMULATED"
    with open_ledger() as target:
        with pytest.raises(ReplayDivergenceError, match="from_state SIMULATED"):
            replay_into(
                target, canonical_policies=ledger.canonical_policies(), events=events
            )


def test_an_event_for_an_uncreated_action_stops_replay() -> None:
    ledger, *_ = build((S.TRIGGERED,))
    events = [e for e in ledger.events() if e["event_type"] != "INTENT_CREATED"]
    with open_ledger() as target:
        with pytest.raises(ReplayDivergenceError, match="unknown action"):
            replay_into(
                target, canonical_policies=ledger.canonical_policies(), events=events
            )


def test_a_duplicated_creation_event_stops_replay() -> None:
    ledger, *_ = build()
    events = [dict(e) for e in ledger.events()]
    created = next(e for e in events if e["event_type"] == "INTENT_CREATED")
    clone = dict(created)
    clone["seq"] = max(e["seq"] for e in events) + 1
    with open_ledger() as target:
        with pytest.raises(ReplayDivergenceError, match="created twice"):
            replay_into(
                target,
                canonical_policies=ledger.canonical_policies(),
                events=events + [clone],
            )


def test_replay_reproduces_budget_reservations_and_releases() -> None:
    ledger, policy, cycle_id, intent = build(
        (S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED), terminal=S.CANCELLED
    )
    assert ledger.held_atomic() == 0
    with reconstruct(ledger) as replayed:
        assert replayed.held_atomic() == 0
        rows = replayed.connection.execute(
            "SELECT status FROM budget_reservations"
        ).fetchall()
        assert [r[0] for r in rows] == ["RELEASED"]


def test_replay_of_a_multi_cycle_history() -> None:
    # Committed capital keeps counting against the caps -- V0A does not recycle
    # realized proceeds back into the budget -- so the allocation has to cover
    # every cycle's entry for all three cycles to run.
    doc = base_policy_doc()
    doc["capital"].update(
        allocation_quote="300",
        per_instrument_cap_quote="300",
        per_network_cap_quote="300",
        global_portfolio_cap_quote="300",
    )
    policy = parse_policy(doc)
    ledger = open_ledger()
    ledger.admit_policy(policy)
    for cycle_index in range(policy.max_cycles):
        cycle_id = ledger.open_cycle(policy, cycle_index, now_epoch_s=NOW)
        intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
        ledger.create_intent(intent, now_epoch_s=NOW)
        drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
        ledger.append_fill_receipt(
            full_receipt(intent, ref=f"0x{cycle_index}"), now_epoch_s=NOW
        )
        drive(ledger, intent.economic_action_id, S.RECONCILED, S.FILLED)
        ledger.close_cycle(cycle_id, CycleStatus.COMPLETED, now_epoch_s=NOW)
    assert_replay_equivalence(ledger)


def test_replay_preserves_the_safe_halt_produced_by_an_out_of_bounds_fill() -> None:
    ledger, policy, cycle_id, intent = build(PATH_TO_FILLED)
    bad = FillReceiptV0(
        receipt_id="r-bad",
        economic_action_id=intent.economic_action_id,
        external_ref="0xbad",
        input_atomic_filled=intent.bounds.max_input_atomic,
        output_atomic_filled=intent.bounds.min_output_atomic - 1,
        fee_atomic=0,
        observed_at_epoch_s=NOW,
        source="test",
    )
    assert ledger.append_fill_receipt(bad, now_epoch_s=NOW) is False
    assert ledger.intent_state(intent.economic_action_id) is S.SAFE_HALT
    # The fill happened, it just landed outside the committed bounds, so the
    # capital is quarantined rather than handed back to the pool.
    assert ledger.held_atomic() == intent.bounds.max_input_atomic
    ledger.integrity_check()
    assert_replay_equivalence(ledger)
