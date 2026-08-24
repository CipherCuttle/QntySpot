"""The lifecycle state machine, exhaustively."""

from __future__ import annotations

import pytest

from qntyspot.errors import StateTransitionError
from qntyspot.states import (
    BUDGET_HOLDING_STATES,
    EXTERNALLY_AMBIGUOUS_STATES,
    PRE_COMMITMENT_STATES,
    TERMINAL_STATES,
    TRANSITIONS,
    IntentState,
    all_illegal_transitions,
    assert_legal_transition,
    is_legal_transition,
)

S = IntentState

LEGAL_TRANSITIONS = sorted(
    ((src, dst) for src, targets in TRANSITIONS.items() for dst in targets),
    key=lambda pair: (pair[0].value, pair[1].value),
)

HAPPY_PATH = [
    S.ARMED,
    S.TRIGGERED,
    S.QUOTE_PINNED,
    S.SIMULATED,
    S.RESERVED,
    S.SIGNED,
    S.SUBMITTED,
    S.INCLUDED,
    S.CONFIRMED,
    S.RECONCILED,
    S.FILLED,
]


def test_every_state_appears_in_the_table() -> None:
    assert set(TRANSITIONS) == set(IntentState)


def test_the_happy_path_is_legal_end_to_end() -> None:
    for src, dst in zip(HAPPY_PATH, HAPPY_PATH[1:]):
        assert_legal_transition(src, dst)


@pytest.mark.parametrize("src,dst", LEGAL_TRANSITIONS, ids=lambda s: getattr(s, "value", s))
def test_each_legal_transition_is_accepted(src: IntentState, dst: IntentState) -> None:
    assert_legal_transition(src, dst)
    assert is_legal_transition(src, dst)


@pytest.mark.parametrize(
    "src,dst", all_illegal_transitions(), ids=lambda s: getattr(s, "value", s)
)
def test_every_illegal_transition_is_refused(src: IntentState, dst: IntentState) -> None:
    """All 187 ordered pairs the table does not enumerate, including self-pairs."""
    assert not is_legal_transition(src, dst)
    with pytest.raises(StateTransitionError, match="illegal transition"):
        assert_legal_transition(src, dst)


def test_the_two_sets_of_transitions_partition_every_ordered_pair() -> None:
    total = len(IntentState) ** 2
    assert len(LEGAL_TRANSITIONS) + len(all_illegal_transitions()) == total
    assert not set(LEGAL_TRANSITIONS) & set(all_illegal_transitions())


def test_no_state_may_transition_to_itself() -> None:
    for state in IntentState:
        assert not is_legal_transition(state, state)


def test_terminal_states_are_dead_ends() -> None:
    for state in TERMINAL_STATES:
        assert TRANSITIONS[state] == frozenset()
        for target in IntentState:
            assert not is_legal_transition(state, target)


def test_a_signed_action_can_never_be_declared_abandoned() -> None:
    """Once signed, a transaction may still land. Abandonment would be a lie."""
    for state in (S.SIGNED, S.SUBMITTED, S.INCLUDED, S.CONFIRMED, S.RECONCILED):
        assert not is_legal_transition(state, S.CANCELLED)
        assert not is_legal_transition(state, S.EXPIRED)


def test_pre_commitment_states_may_be_abandoned() -> None:
    for state in PRE_COMMITMENT_STATES:
        assert is_legal_transition(state, S.CANCELLED)
        assert is_legal_transition(state, S.EXPIRED)


def test_safe_halt_is_reachable_from_every_non_terminal_state() -> None:
    for state in IntentState:
        if state in TERMINAL_STATES:
            continue
        assert is_legal_transition(state, S.SAFE_HALT)


def test_safe_halt_never_leads_back_to_an_executable_state() -> None:
    assert TRANSITIONS[S.SAFE_HALT] == frozenset()


def test_filled_is_only_reachable_through_reconciliation() -> None:
    sources = [src for src, targets in TRANSITIONS.items() if S.FILLED in targets]
    assert sources == [S.RECONCILED]


def test_reserved_is_only_reachable_from_simulated() -> None:
    sources = [src for src, targets in TRANSITIONS.items() if S.RESERVED in targets]
    assert sources == [S.SIMULATED]


def test_state_set_partitions_are_coherent() -> None:
    assert PRE_COMMITMENT_STATES.isdisjoint(EXTERNALLY_AMBIGUOUS_STATES)
    assert PRE_COMMITMENT_STATES.isdisjoint(TERMINAL_STATES)
    assert EXTERNALLY_AMBIGUOUS_STATES.isdisjoint(TERMINAL_STATES)
    assert BUDGET_HOLDING_STATES.isdisjoint(TERMINAL_STATES)
    # Every state is either terminal, pre-commitment, externally ambiguous, or
    # RECONCILED (the one post-truth, pre-bookkeeping state).
    covered = PRE_COMMITMENT_STATES | EXTERNALLY_AMBIGUOUS_STATES | TERMINAL_STATES
    assert set(IntentState) - covered == {S.RECONCILED}


@pytest.mark.parametrize("bad", ["ARMED", None, 0, object()])
def test_non_states_are_refused(bad: object) -> None:
    assert not is_legal_transition(bad, S.ARMED)
    assert not is_legal_transition(S.ARMED, bad)
    with pytest.raises(StateTransitionError, match="unknown"):
        assert_legal_transition(bad, S.TRIGGERED)
    with pytest.raises(StateTransitionError, match="unknown"):
        assert_legal_transition(S.ARMED, bad)
