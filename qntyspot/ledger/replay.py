"""Deterministic reconstruction.

Replay takes exactly two inputs:

    * a fresh, empty database
    * the canonical policies, plus the ``state_events`` stream in seq order

and rebuilds every projection: cycles, intents, budget reservations, fill
receipts, filled inventory, realized proceeds and next eligible rungs.

Replay does NOT re-evaluate the budget cap guard. The guard decides whether an
action may take budget; the log records that it did. Re-deciding during replay
would let a change in cap arithmetic silently rewrite history, which is the
opposite of what a ledger is for. What replay does assert is that the log is
internally consistent: sequence numbers strictly increase, every transition it
replays is legal under the current state machine, and no event references an
action it has not already seen created.

Replayed rows keep their original ``seq`` values, so a reconstructed database
is byte-identical to the source under :meth:`SpotLedger.snapshot`, and
replaying twice is identical by construction rather than by luck.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Iterable, Mapping, Sequence

from ..canon import canonical_json_str, strict_json_loads
from ..domain import CycleStatus, ReservationStatus, RuntimeStateV0, Side
from ..errors import LedgerError, ReplayDivergenceError
from ..policy import parse_policy
from ..states import IntentState, assert_legal_transition
from .atomics import decode_atomic, encode_atomic
from .schema import CYCLE_EVENT_TYPES, EventType
from .store import SpotLedger, open_ledger

__all__ = ["replay_into", "reconstruct", "assert_replay_equivalence"]

_RELEASING = {IntentState.CANCELLED, IntentState.EXPIRED, IntentState.REJECTED}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayDivergenceError(message)


def replay_into(
    target: SpotLedger,
    *,
    canonical_policies: Sequence[str],
    events: Sequence[Mapping[str, Any]],
) -> None:
    """Rebuild ``target`` (which must be empty) from policies and events."""
    conn = target.connection
    if conn.execute("SELECT COUNT(*) FROM state_events").fetchone()[0]:
        raise LedgerError("replay target must be an empty ledger")

    for raw in canonical_policies:
        target.admit_policy(parse_policy(strict_json_loads(raw)))

    known_policies = {
        r[0] for r in conn.execute("SELECT policy_id FROM policies")
    }
    seen_actions: set[str] = set()
    last_seq = 0

    with target._write() as wconn:  # noqa: SLF001 - replay is part of the ledger
        for event in events:
            seq = int(event["seq"])
            _require(seq > last_seq, f"event seq {seq} does not follow {last_seq}")
            last_seq = seq
            etype = str(event["event_type"])
            policy_id = str(event["policy_id"])
            cycle_id = str(event["cycle_id"])
            action_id = event["economic_action_id"]
            payload = strict_json_loads(event["payload_json"])
            _require(
                policy_id in known_policies,
                f"event {seq} references unknown policy {policy_id}",
            )

            if etype in CYCLE_EVENT_TYPES:
                _require(action_id is None, f"event {seq}: cycle event carries an action id")
                _apply_cycle_event(wconn, etype, policy_id, cycle_id, payload, seq)
            elif etype == EventType.INTENT_CREATED.value:
                _require(
                    action_id is not None, f"event {seq}: intent event without an action id"
                )
                _require(
                    action_id not in seen_actions,
                    f"event {seq}: economic action {action_id} created twice",
                )
                seen_actions.add(str(action_id))
                _apply_intent_created(wconn, str(action_id), payload, seq)
            elif etype == EventType.INTENT_TRANSITION.value:
                _require(
                    action_id in seen_actions,
                    f"event {seq}: transition for unknown action {action_id}",
                )
                _apply_transition(wconn, str(action_id), event, seq)
            elif etype == EventType.FILL_RECEIPT_APPENDED.value:
                _require(
                    action_id in seen_actions,
                    f"event {seq}: receipt for unknown action {action_id}",
                )
                _apply_receipt(wconn, str(action_id), payload, seq)
            else:
                raise ReplayDivergenceError(f"event {seq}: unknown event_type {etype!r}")

            wconn.execute(
                """
                INSERT INTO state_events (
                    seq, event_type, policy_id, cycle_id, economic_action_id,
                    from_state, to_state, occurred_epoch_s, payload_json
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    seq,
                    etype,
                    policy_id,
                    cycle_id,
                    action_id,
                    event["from_state"],
                    event["to_state"],
                    int(event["occurred_epoch_s"]),
                    event["payload_json"],
                ),
            )


def _apply_cycle_event(
    conn: sqlite3.Connection,
    etype: str,
    policy_id: str,
    cycle_id: str,
    payload: Mapping[str, Any],
    seq: int,
) -> None:
    if etype == EventType.CYCLE_OPENED.value:
        conn.execute(
            "INSERT INTO cycles (cycle_id, policy_id, cycle_index, status) VALUES (?,?,?,?)",
            (cycle_id, policy_id, int(payload["cycle_index"]), CycleStatus.OPEN.value),
        )
        return
    status = (
        CycleStatus.COMPLETED
        if etype == EventType.CYCLE_COMPLETED.value
        else CycleStatus.HALTED
    )
    cur = conn.execute(
        "UPDATE cycles SET status = ? WHERE cycle_id = ? AND status = ?",
        (status.value, cycle_id, CycleStatus.OPEN.value),
    )
    _require(cur.rowcount == 1, f"event {seq}: cycle {cycle_id} was not open")


def _apply_intent_created(
    conn: sqlite3.Connection, action_id: str, payload: Mapping[str, Any], seq: int
) -> None:
    _require(
        payload.get("economic_action_id") == action_id,
        f"event {seq}: payload action id disagrees with the event",
    )
    conn.execute(
        """
        INSERT INTO intents (
            economic_action_id, policy_id, instrument_id, quote_instrument_id,
            network_id, cycle_id, level_id, side, kind, state,
            quote_exposure_atomic, bounds_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            action_id,
            payload["policy_id"],
            payload["instrument_id"],
            payload["quote_instrument_id"],
            payload["network_id"],
            payload["cycle_id"],
            payload["level_id"],
            payload["side"],
            payload["kind"],
            IntentState.ARMED.value,
            encode_atomic(
                decode_atomic(
                    payload["quote_exposure_atomic"], field="quote_exposure"
                ),
                field="quote_exposure",
            ),
            canonical_json_str(payload["bounds"]),
        ),
    )


def _apply_transition(
    conn: sqlite3.Connection, action_id: str, event: Mapping[str, Any], seq: int
) -> None:
    row = conn.execute(
        """
        SELECT state, policy_id, instrument_id, quote_instrument_id, network_id,
               quote_exposure_atomic
        FROM intents WHERE economic_action_id = ?
        """,
        (action_id,),
    ).fetchone()
    _require(row is not None, f"event {seq}: no intent {action_id}")
    src = IntentState(row["state"])
    dst = IntentState(str(event["to_state"]))
    _require(
        str(event["from_state"]) == src.value,
        f"event {seq}: recorded from_state {event['from_state']} != replayed {src.value}",
    )
    try:
        assert_legal_transition(src, dst)
    except Exception as exc:
        raise ReplayDivergenceError(f"event {seq}: {exc}") from exc

    amount = decode_atomic(row["quote_exposure_atomic"], field="quote_exposure")
    if dst is IntentState.RESERVED and amount > 0:
        # Trusted: the guard already ran when this event was first written.
        conn.execute(
            """
            INSERT INTO budget_reservations (
                economic_action_id, policy_id, instrument_id, quote_instrument_id,
                network_id, amount_atomic, status, reserved_seq, settled_seq
            ) VALUES (?,?,?,?,?,?,?,?,NULL)
            """,
            (
                action_id,
                row["policy_id"],
                row["instrument_id"],
                row["quote_instrument_id"],
                row["network_id"],
                encode_atomic(amount, field="reservation amount"),
                ReservationStatus.ACTIVE.value,
                seq,
            ),
        )
    elif dst is IntentState.FILLED:
        _settle(conn, action_id, ReservationStatus.COMMITTED, seq)
    elif dst in _RELEASING:
        _settle(conn, action_id, ReservationStatus.RELEASED, seq)
    elif dst is IntentState.SAFE_HALT:
        _settle(conn, action_id, ReservationStatus.QUARANTINED, seq)

    conn.execute(
        "UPDATE intents SET state = ? WHERE economic_action_id = ?", (dst.value, action_id)
    )


def _settle(
    conn: sqlite3.Connection, action_id: str, status: ReservationStatus, seq: int
) -> None:
    conn.execute(
        "UPDATE budget_reservations SET status = ?, settled_seq = ? "
        "WHERE economic_action_id = ? AND status = ?",
        (status.value, seq, action_id, ReservationStatus.ACTIVE.value),
    )


def _apply_receipt(
    conn: sqlite3.Connection, action_id: str, payload: Mapping[str, Any], seq: int
) -> None:
    conn.execute(
        """
        INSERT INTO fill_receipts (
            receipt_id, economic_action_id, external_ref, input_atomic_filled,
            output_atomic_filled, fee_atomic, observed_at_epoch_s, source, appended_seq
        ) VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (
            payload["receipt_id"],
            action_id,
            payload["external_ref"],
            encode_atomic(
                decode_atomic(payload["input_atomic_filled"], field="input_filled"),
                field="input_filled",
            ),
            encode_atomic(
                decode_atomic(payload["output_atomic_filled"], field="output_filled"),
                field="output_filled",
            ),
            encode_atomic(decode_atomic(payload["fee_atomic"], field="fee"), field="fee"),
            int(payload["observed_at_epoch_s"]),
            payload["source"],
            seq,
        ),
    )


def reconstruct(source: SpotLedger, *, path: str = ":memory:") -> SpotLedger:
    """Build a fresh ledger from ``source``'s policies and event log."""
    target = open_ledger(path)
    replay_into(
        target,
        canonical_policies=source.canonical_policies(),
        events=source.events(),
    )
    target.integrity_check()
    return target


def assert_replay_equivalence(source: SpotLedger) -> str:
    """Reconstruct twice and require byte-equal canonical state each time.

    Returns the shared canonical state digest.
    """
    original = source.snapshot()
    digests = []
    for _ in range(2):
        with reconstruct(source) as replayed:
            snapshot = replayed.snapshot()
            if snapshot.canonical_object() != original.canonical_object():
                raise ReplayDivergenceError(
                    "replayed state does not match the source ledger"
                )
            digests.append(snapshot.digest())
    if digests[0] != digests[1]:  # pragma: no cover - defensive
        raise ReplayDivergenceError(
            f"two replays disagreed: {digests[0]} != {digests[1]}"
        )
    return digests[0]
