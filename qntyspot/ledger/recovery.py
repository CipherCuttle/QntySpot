"""Restart recovery.

THE RULE
--------
An unknown outcome is never resolved by acting again. Restart must never infer
that an economic action should be executed merely because its completion is
unknown.

Recovery therefore sorts every non-terminal intent into exactly one of three
buckets, by state alone -- never by elapsed time, never by absence of evidence:

``ABANDON``     the action never reached a point where anything could have
                happened outside this process (ARMED through RESERVED). It is
                cancelled and any budget it held is released. Its
                EconomicActionID remains in the ledger forever, so the same
                rung of the same cycle can never be armed a second time.

``SAFE_HALT``   the action may exist outside this process (SIGNED, SUBMITTED,
                INCLUDED, CONFIRMED). Its outcome is unknown, the local ledger
                cannot resolve it, and V0A has no reconciler. It stops.
                A human or a future reconciliation adapter must decide.

``COMPLETE``    the action is RECONCILED and a fill receipt is already durable.
                Finishing to FILLED is bookkeeping over evidence that already
                exists. No new economic action is taken. If a RECONCILED intent
                has no receipt, that is a contradiction, and it halts instead.

Nothing here retries, resubmits, re-arms or re-quotes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..states import (
    EXTERNALLY_AMBIGUOUS_STATES,
    PRE_COMMITMENT_STATES,
    TERMINAL_STATES,
    IntentState,
)
from .store import SpotLedger

__all__ = ["RecoveryDisposition", "RecoveryAction", "recover"]


class RecoveryDisposition(str, Enum):
    ABANDON = "ABANDON"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    COMPLETE_FROM_RECEIPT = "COMPLETE_FROM_RECEIPT"


@dataclass(frozen=True, slots=True)
class RecoveryAction:
    economic_action_id: str
    from_state: IntentState
    to_state: IntentState
    disposition: RecoveryDisposition
    reason: str


def recover(ledger: SpotLedger, *, now_epoch_s: int) -> tuple[RecoveryAction, ...]:
    """Bring every non-terminal intent to a state that is safe to restart from."""
    rows = ledger.connection.execute(
        """
        SELECT i.economic_action_id, i.state,
               (SELECT COUNT(*) FROM fill_receipts f
                 WHERE f.economic_action_id = i.economic_action_id) AS receipts
        FROM intents i
        ORDER BY i.economic_action_id ASC
        """
    ).fetchall()

    actions: list[RecoveryAction] = []
    for row in rows:
        state = IntentState(row["state"])
        if state in TERMINAL_STATES:
            continue
        receipts = int(row["receipts"])

        if state in PRE_COMMITMENT_STATES:
            action = RecoveryAction(
                economic_action_id=row["economic_action_id"],
                from_state=state,
                to_state=IntentState.CANCELLED,
                disposition=RecoveryDisposition.ABANDON,
                reason=(
                    "no venue-visible step was taken before the restart; the rung is "
                    "abandoned and its EconomicActionID stays consumed for this cycle"
                ),
            )
        elif state in EXTERNALLY_AMBIGUOUS_STATES:
            action = RecoveryAction(
                economic_action_id=row["economic_action_id"],
                from_state=state,
                to_state=IntentState.SAFE_HALT,
                disposition=RecoveryDisposition.RECONCILIATION_REQUIRED,
                reason=(
                    f"restart found the action in {state.value}; the outcome is only "
                    "knowable from external truth, and V0A has no reconciler"
                ),
            )
        elif state is IntentState.RECONCILED and receipts > 0:
            action = RecoveryAction(
                economic_action_id=row["economic_action_id"],
                from_state=state,
                to_state=IntentState.FILLED,
                disposition=RecoveryDisposition.COMPLETE_FROM_RECEIPT,
                reason=(
                    "a durable fill receipt already exists; completing is bookkeeping "
                    "over recorded evidence, not a new economic action"
                ),
            )
        else:
            action = RecoveryAction(
                economic_action_id=row["economic_action_id"],
                from_state=state,
                to_state=IntentState.SAFE_HALT,
                disposition=RecoveryDisposition.RECONCILIATION_REQUIRED,
                reason=(
                    f"{state.value} without a fill receipt is a contradiction the "
                    "ledger cannot resolve on its own"
                ),
            )
        actions.append(action)

    for action in actions:
        ledger.transition(
            action.economic_action_id,
            action.to_state,
            now_epoch_s=now_epoch_s,
            payload={
                "recovery": action.disposition.value,
                "reason": action.reason,
            },
        )
    return tuple(actions)
