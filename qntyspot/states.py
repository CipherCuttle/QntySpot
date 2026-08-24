"""Lifecycle state machine for an economic action.

V0A models states that a future live runtime will need, and implements none of
their side effects. ``SIGNED``, ``SUBMITTED``, ``INCLUDED`` and ``CONFIRMED``
are domain labels recorded in the ledger. There is no signer, no key, no
transaction encoder and no network in this phase; nothing in this package can
cause those states to be reached by any means other than an explicit local
call in a test or a future adapter.

DESIGN NOTES
------------
* Every transition is enumerated. Anything not enumerated fails closed.
* ``CANCELLED`` and ``EXPIRED`` are unreachable from ``SIGNED`` onwards. Once
  an action is signed, a transaction may still land, so the runtime may not
  declare it abandoned. The only escapes are the outcome states and
  ``SAFE_HALT``.
* ``SAFE_HALT`` is reachable from every non-terminal state and is terminal. It
  is the sink for "external truth is unknown or contradictory", and it never
  leads back to an executable state.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Mapping

from .errors import StateTransitionError

__all__ = [
    "IntentState",
    "TRANSITIONS",
    "TERMINAL_STATES",
    "PRE_COMMITMENT_STATES",
    "EXTERNALLY_AMBIGUOUS_STATES",
    "BUDGET_HOLDING_STATES",
    "is_legal_transition",
    "assert_legal_transition",
    "all_illegal_transitions",
]


class IntentState(str, Enum):
    ARMED = "ARMED"
    TRIGGERED = "TRIGGERED"
    QUOTE_PINNED = "QUOTE_PINNED"
    SIMULATED = "SIMULATED"
    RESERVED = "RESERVED"
    SIGNED = "SIGNED"
    SUBMITTED = "SUBMITTED"
    INCLUDED = "INCLUDED"
    CONFIRMED = "CONFIRMED"
    RECONCILED = "RECONCILED"
    FILLED = "FILLED"

    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
    SAFE_HALT = "SAFE_HALT"


S = IntentState

#: States after which no further transition is permitted.
TERMINAL_STATES: frozenset[IntentState] = frozenset(
    {S.FILLED, S.CANCELLED, S.EXPIRED, S.REJECTED, S.SAFE_HALT}
)

#: States in which nothing irreversible has been attempted against a venue, so
#: a restart may safely abandon the action and release any budget it holds.
PRE_COMMITMENT_STATES: frozenset[IntentState] = frozenset(
    {S.ARMED, S.TRIGGERED, S.QUOTE_PINNED, S.SIMULATED, S.RESERVED}
)

#: States in which a future runtime cannot know, without consulting external
#: truth, whether an economic action happened. Recovery must never retry these.
EXTERNALLY_AMBIGUOUS_STATES: frozenset[IntentState] = frozenset(
    {S.SIGNED, S.SUBMITTED, S.INCLUDED, S.CONFIRMED}
)

#: States that hold a live budget reservation.
BUDGET_HOLDING_STATES: frozenset[IntentState] = frozenset(
    {S.RESERVED, S.SIGNED, S.SUBMITTED, S.INCLUDED, S.CONFIRMED, S.RECONCILED}
)

_ABANDON = (S.CANCELLED, S.EXPIRED)

TRANSITIONS: Mapping[IntentState, frozenset[IntentState]] = MappingProxyType(
    {
        S.ARMED: frozenset({S.TRIGGERED, *_ABANDON, S.REJECTED, S.SAFE_HALT}),
        S.TRIGGERED: frozenset({S.QUOTE_PINNED, *_ABANDON, S.REJECTED, S.SAFE_HALT}),
        S.QUOTE_PINNED: frozenset({S.SIMULATED, *_ABANDON, S.REJECTED, S.SAFE_HALT}),
        S.SIMULATED: frozenset({S.RESERVED, *_ABANDON, S.REJECTED, S.SAFE_HALT}),
        S.RESERVED: frozenset({S.SIGNED, *_ABANDON, S.REJECTED, S.SAFE_HALT}),
        # From here on the action may already exist outside this process.
        S.SIGNED: frozenset({S.SUBMITTED, S.REJECTED, S.SAFE_HALT}),
        S.SUBMITTED: frozenset({S.INCLUDED, S.REJECTED, S.SAFE_HALT}),
        S.INCLUDED: frozenset({S.CONFIRMED, S.REJECTED, S.SAFE_HALT}),
        S.CONFIRMED: frozenset({S.RECONCILED, S.SAFE_HALT}),
        S.RECONCILED: frozenset({S.FILLED, S.SAFE_HALT}),
        S.FILLED: frozenset(),
        S.CANCELLED: frozenset(),
        S.EXPIRED: frozenset(),
        S.REJECTED: frozenset(),
        S.SAFE_HALT: frozenset(),
    }
)

assert set(TRANSITIONS) == set(IntentState), "transition table must cover every state"
assert all(
    not TRANSITIONS[s] for s in TERMINAL_STATES
), "terminal states must have no outbound transitions"


def is_legal_transition(src: IntentState, dst: IntentState) -> bool:
    if not isinstance(src, IntentState) or not isinstance(dst, IntentState):
        return False
    return dst in TRANSITIONS[src]


def assert_legal_transition(src: IntentState, dst: IntentState) -> None:
    """Raise unless ``src -> dst`` is enumerated. Self-transitions are illegal."""
    if not isinstance(src, IntentState):
        raise StateTransitionError(f"unknown source state {src!r}")
    if not isinstance(dst, IntentState):
        raise StateTransitionError(f"unknown target state {dst!r}")
    if dst not in TRANSITIONS[src]:
        raise StateTransitionError(f"illegal transition {src.value} -> {dst.value}")


def all_illegal_transitions() -> list[tuple[IntentState, IntentState]]:
    """Every ordered pair, including self-pairs, that the table forbids."""
    return [
        (src, dst)
        for src in IntentState
        for dst in IntentState
        if dst not in TRANSITIONS[src]
    ]
