"""The QntySpot ledger store.

WRITE PATH
----------
``transition`` is the single way an intent's state changes, and it carries
every consequence of that change -- budget reservation, budget release, budget
commit -- inside the same SQLite transaction as the state change and the
appended event. There is no code path that moves an intent without writing the
event that explains it, and none that touches budget without moving an intent.
That is what makes the log sufficient for replay.

CONCURRENCY
-----------
Every write runs inside ``BEGIN IMMEDIATE``. Two workers racing for the last
of the budget therefore serialise at the engine: the loser re-evaluates the
cap guard against the winner's committed rows and deterministically abstains.
The cap guard itself is a single ``INSERT ... SELECT ... WHERE`` -- there is no
window between reading the remaining budget and taking it.

NUMERAIRE
---------
All caps are integer atomic units of the quote instrument, so summing them
across policies is only meaningful if those policies share a quote instrument.
V0A enforces exactly that at admission time. A multi-quote portfolio needs a
conversion rate, and inventing one offline is precisely the kind of guess this
runtime refuses to make.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Mapping, Sequence

from ..canon import canonical_json_str, format_canonical_decimal, strict_json_loads
from ..domain import (
    CycleStatus,
    FillReceiptV0,
    IntentV0,
    LadderKind,
    PolicyV0,
    ReservationStatus,
    RuntimeStateV0,
    Side,
)
from ..errors import (
    BudgetExceededError,
    DuplicateEconomicActionError,
    LedgerError,
    SchemaVersionError,
)
from ..states import BUDGET_HOLDING_STATES, IntentState, assert_legal_transition
from .atomics import decode_atomic, encode_atomic
from .schema import (
    SCHEMA_VERSION,
    EventType,
    apply_schema,
    configure_connection,
    read_schema_version,
)

__all__ = ["SpotLedger", "open_ledger", "cycle_id_for"]

#: Endings that prove the action did not happen. Only these free capital.
#: SAFE_HALT is deliberately absent: an action may be halted precisely because
#: nobody knows whether it settled, and releasing its budget would let the
#: portfolio commit the same capital twice.
_RELEASING_STATES = frozenset(
    {IntentState.CANCELLED, IntentState.EXPIRED, IntentState.REJECTED}
)

#: Everything except RELEASED counts against the caps.
_HELD_CLAUSE = "status <> 'RELEASED'"

#: States in which an external fill may legitimately be observed.
_RECEIPT_STATES = frozenset(
    {
        IntentState.SUBMITTED,
        IntentState.INCLUDED,
        IntentState.CONFIRMED,
        IntentState.RECONCILED,
    }
)


def cycle_id_for(policy_id: str, cycle_index: int) -> str:
    """Deterministic cycle identity. No counters, no clocks, no randomness."""
    if not isinstance(cycle_index, int) or isinstance(cycle_index, bool) or cycle_index < 0:
        raise LedgerError("cycle_index must be a non-negative int")
    return f"{policy_id}:{cycle_index}"


class SpotLedger:
    def __init__(self, conn: sqlite3.Connection, *, owns_connection: bool = False) -> None:
        self._conn = conn
        self._owns = owns_connection
        self._depth = 0
        version = read_schema_version(conn)
        if version != SCHEMA_VERSION:
            raise SchemaVersionError(
                f"ledger schema version {version} != supported {SCHEMA_VERSION}"
            )

    # -- lifecycle ---------------------------------------------------------

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        if self._owns:
            self._conn.close()

    def __enter__(self) -> "SpotLedger":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """A write transaction. Nested calls join the outermost transaction."""
        if self._depth:
            self._depth += 1
            try:
                yield self._conn
            finally:
                self._depth -= 1
            return
        self._conn.execute("BEGIN IMMEDIATE")
        self._depth = 1
        try:
            yield self._conn
        except BaseException:
            self._depth = 0
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._depth = 0
            self._conn.execute("COMMIT")

    # -- admission ---------------------------------------------------------

    def admit_policy(self, policy: PolicyV0) -> str:
        """Register a policy and its instruments. Idempotent by ``policy_id``."""
        policy_id = policy.policy_id
        with self._write() as conn:
            for instrument in (policy.base, policy.quote):
                self._upsert_instrument(conn, instrument)

            existing_quote = conn.execute(
                "SELECT DISTINCT quote_instrument_id FROM policies"
            ).fetchall()
            other = {
                row[0] for row in existing_quote if row[0] != policy.quote_instrument_id
            }
            if other:
                raise LedgerError(
                    "V0A requires a single quote instrument across all admitted "
                    f"policies; ledger already uses {sorted(other)} and this policy "
                    f"uses {policy.quote_instrument_id}. Cross-numeraire caps would "
                    "require a conversion rate the offline core will not invent."
                )

            row = conn.execute(
                "SELECT canonical_json FROM policies WHERE policy_id = ?", (policy_id,)
            ).fetchone()
            canonical_json = canonical_json_str(dict(policy.canonical))
            if row is not None:
                if row[0] != canonical_json:  # pragma: no cover - digest makes this impossible
                    raise LedgerError(f"policy_id {policy_id} collides with different content")
                return policy_id

            b = policy.budget
            conn.execute(
                """
                INSERT INTO policies (
                    policy_id, policy_name, side, instrument_id, quote_instrument_id,
                    network_id, allocation_atomic, per_order_cap_atomic,
                    per_instrument_cap_atomic, per_network_cap_atomic, global_cap_atomic,
                    reserved_cash_atomic, max_cycles, canonical_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    policy_id,
                    policy.policy_name,
                    policy.side.value,
                    policy.instrument_id,
                    policy.quote_instrument_id,
                    policy.network_id,
                    encode_atomic(b.allocation_atomic, field="allocation"),
                    encode_atomic(b.per_order_cap_atomic, field="per_order_cap"),
                    encode_atomic(b.per_instrument_cap_atomic, field="per_instrument_cap"),
                    encode_atomic(b.per_network_cap_atomic, field="per_network_cap"),
                    encode_atomic(b.global_cap_atomic, field="global_cap"),
                    encode_atomic(b.reserved_cash_atomic, field="reserved_cash"),
                    policy.max_cycles,
                    canonical_json,
                ),
            )
            for level in policy.levels():
                conn.execute(
                    """
                    INSERT INTO ladder_levels (
                        policy_id, level_id, kind, side, level_index,
                        trigger_price, input_amount, input_ratio
                    ) VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        policy_id,
                        level.level_id,
                        level.kind.value,
                        level.side.value,
                        level.index,
                        format_canonical_decimal(level.trigger_price),
                        None
                        if level.input_amount is None
                        else format_canonical_decimal(level.input_amount),
                        None
                        if level.input_ratio is None
                        else format_canonical_decimal(level.input_ratio),
                    ),
                )
        return policy_id

    @staticmethod
    def _upsert_instrument(conn: sqlite3.Connection, instrument: Any) -> None:
        row = conn.execute(
            "SELECT identity_digest FROM instruments WHERE instrument_id = ?",
            (instrument.instrument_id,),
        ).fetchone()
        digest = instrument.identity_digest()
        if row is not None:
            if row[0] != digest:
                raise LedgerError(
                    f"instrument {instrument.instrument_id} is already registered with "
                    "different identity facts (decimals or asset class disagree)"
                )
            return
        conn.execute(
            """
            INSERT INTO instruments (
                instrument_id, namespace, network_id, decimals, asset_class,
                identity_digest, identity_json
            ) VALUES (?,?,?,?,?,?,?)
            """,
            (
                instrument.instrument_id,
                instrument.ref.namespace,
                instrument.network_id,
                instrument.decimals,
                instrument.asset_class.value,
                digest,
                canonical_json_str(instrument.identity_object()),
            ),
        )

    # -- cycles ------------------------------------------------------------

    def open_cycle(self, policy: PolicyV0, cycle_index: int, *, now_epoch_s: int) -> str:
        policy_id = policy.policy_id
        if cycle_index >= policy.max_cycles:
            raise LedgerError(
                f"cycle_index {cycle_index} exceeds policy max_cycles {policy.max_cycles}"
            )
        cid = cycle_id_for(policy_id, cycle_index)
        with self._write() as conn:
            if conn.execute("SELECT 1 FROM cycles WHERE cycle_id = ?", (cid,)).fetchone():
                raise LedgerError(f"cycle {cid} already exists")
            conn.execute(
                "INSERT INTO cycles (cycle_id, policy_id, cycle_index, status) VALUES (?,?,?,?)",
                (cid, policy_id, cycle_index, CycleStatus.OPEN.value),
            )
            self._append_event(
                conn,
                event_type=EventType.CYCLE_OPENED,
                policy_id=policy_id,
                cycle_id=cid,
                economic_action_id=None,
                from_state=None,
                to_state=CycleStatus.OPEN.value,
                now_epoch_s=now_epoch_s,
                payload={"cycle_index": cycle_index},
            )
        return cid

    def close_cycle(self, cycle_id: str, status: CycleStatus, *, now_epoch_s: int) -> None:
        if status not in (CycleStatus.COMPLETED, CycleStatus.HALTED):
            raise LedgerError("close_cycle accepts COMPLETED or HALTED only")
        with self._write() as conn:
            row = conn.execute(
                "SELECT policy_id, status FROM cycles WHERE cycle_id = ?", (cycle_id,)
            ).fetchone()
            if row is None:
                raise LedgerError(f"unknown cycle {cycle_id}")
            policy_id, current = row
            if current != CycleStatus.OPEN.value:
                raise LedgerError(f"cycle {cycle_id} is already {current}")
            conn.execute(
                "UPDATE cycles SET status = ? WHERE cycle_id = ?", (status.value, cycle_id)
            )
            self._append_event(
                conn,
                event_type=EventType.CYCLE_COMPLETED
                if status is CycleStatus.COMPLETED
                else EventType.CYCLE_HALTED,
                policy_id=policy_id,
                cycle_id=cycle_id,
                economic_action_id=None,
                from_state=CycleStatus.OPEN.value,
                to_state=status.value,
                now_epoch_s=now_epoch_s,
                payload={},
            )

    # -- intents -----------------------------------------------------------

    def create_intent(self, intent: IntentV0, *, now_epoch_s: int) -> None:
        """Create the ARMED intent. The second attempt at the same economic
        action fails at the database, not at an application check."""
        if intent.state is not IntentState.ARMED:
            raise LedgerError("a new intent must be created in ARMED")
        with self._write() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO intents (
                        economic_action_id, policy_id, instrument_id, quote_instrument_id,
                        network_id, cycle_id, level_id, side, kind, state,
                        quote_exposure_atomic, bounds_json
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        intent.economic_action_id,
                        intent.policy_id,
                        intent.instrument_id,
                        intent.quote_instrument_id,
                        intent.network_id,
                        intent.cycle_id,
                        intent.level_id,
                        intent.side.value,
                        intent.kind.value,
                        IntentState.ARMED.value,
                        encode_atomic(
                            intent.quote_exposure_atomic, field="quote_exposure"
                        ),
                        canonical_json_str(intent.bounds.canonical_object()),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if "UNIQUE" in str(exc) or "PRIMARY KEY" in str(exc):
                    raise DuplicateEconomicActionError(
                        f"economic action already exists for "
                        f"(policy={intent.policy_id[:12]}…, cycle={intent.cycle_id}, "
                        f"level={intent.level_id}, side={intent.side.value})"
                    ) from exc
                raise LedgerError(str(exc)) from exc
            self._append_event(
                conn,
                event_type=EventType.INTENT_CREATED,
                policy_id=intent.policy_id,
                cycle_id=intent.cycle_id,
                economic_action_id=intent.economic_action_id,
                from_state=None,
                to_state=IntentState.ARMED.value,
                now_epoch_s=now_epoch_s,
                payload=intent.canonical_object(),
            )

    def intent_row(self, economic_action_id: str) -> Mapping[str, Any]:
        row = self._conn.execute(
            "SELECT * FROM intents WHERE economic_action_id = ?", (economic_action_id,)
        ).fetchone()
        if row is None:
            raise LedgerError(f"unknown economic action {economic_action_id}")
        return dict(row)

    def intent_state(self, economic_action_id: str) -> IntentState:
        return IntentState(self.intent_row(economic_action_id)["state"])

    def transition(
        self,
        economic_action_id: str,
        to_state: IntentState,
        *,
        now_epoch_s: int,
        payload: Mapping[str, Any] | None = None,
    ) -> None:
        """Move an intent, with all budget consequences, in one transaction."""
        with self._write() as conn:
            row = conn.execute(
                """
                SELECT state, policy_id, cycle_id, instrument_id, quote_instrument_id,
                       network_id, quote_exposure_atomic, side
                FROM intents WHERE economic_action_id = ?
                """,
                (economic_action_id,),
            ).fetchone()
            if row is None:
                raise LedgerError(f"unknown economic action {economic_action_id}")
            src = IntentState(row["state"])
            assert_legal_transition(src, to_state)

            if to_state is IntentState.RESERVED:
                self._reserve(conn, economic_action_id, dict(row))
            elif to_state is IntentState.FILLED:
                self._settle_reservation(
                    conn, economic_action_id, ReservationStatus.COMMITTED
                )
            elif to_state in _RELEASING_STATES:
                self._settle_reservation(
                    conn, economic_action_id, ReservationStatus.RELEASED
                )
            elif to_state is IntentState.SAFE_HALT:
                self._settle_reservation(
                    conn, economic_action_id, ReservationStatus.QUARANTINED
                )

            conn.execute(
                "UPDATE intents SET state = ? WHERE economic_action_id = ?",
                (to_state.value, economic_action_id),
            )
            self._append_event(
                conn,
                event_type=EventType.INTENT_TRANSITION,
                policy_id=row["policy_id"],
                cycle_id=row["cycle_id"],
                economic_action_id=economic_action_id,
                from_state=src.value,
                to_state=to_state.value,
                now_epoch_s=now_epoch_s,
                payload=dict(payload or {}),
            )

    # -- budget ------------------------------------------------------------

    def _reserve(
        self, conn: sqlite3.Connection, economic_action_id: str, intent: Mapping[str, Any]
    ) -> None:
        amount = decode_atomic(intent["quote_exposure_atomic"], field="quote_exposure")
        if amount == 0:
            # A SELL leg returns quote instead of consuming it. Nothing is
            # reserved, and nothing needs to be released later.
            return
        if conn.execute(
            "SELECT 1 FROM budget_reservations WHERE economic_action_id = ?",
            (economic_action_id,),
        ).fetchone():
            raise DuplicateEconomicActionError(
                f"economic action {economic_action_id[:12]}… already holds a reservation"
            )

        seq = self._next_seq(conn)
        params = {
            "aid": economic_action_id,
            "pid": intent["policy_id"],
            "iid": intent["instrument_id"],
            "qid": intent["quote_instrument_id"],
            "nid": intent["network_id"],
            "amt": encode_atomic(amount, field="reservation amount"),
            "seq": seq,
            "active": ReservationStatus.ACTIVE.value,
        }
        # One statement. The caps are read and the budget is taken inside the
        # same INSERT, so there is no interval during which another writer can
        # observe the same remaining budget.
        cur = conn.execute(
            """
            INSERT INTO budget_reservations (
                economic_action_id, policy_id, instrument_id, quote_instrument_id,
                network_id, amount_atomic, status, reserved_seq, settled_seq
            )
            SELECT :aid, :pid, :iid, :qid, :nid, :amt, :active, :seq, NULL
            WHERE
                -- per-order cap: this policy's own limit on a single action
                atomic_le(:amt,
                    (SELECT per_order_cap_atomic FROM policies WHERE policy_id = :pid))
              AND
                -- this policy's total allocation
                atomic_le(
                    atomic_add(:amt, COALESCE((SELECT atomic_sum(amount_atomic)
                                      FROM budget_reservations
                                      WHERE status <> 'RELEASED'
                                        AND policy_id = :pid), '0')),
                    (SELECT allocation_atomic FROM policies WHERE policy_id = :pid))
              AND
                -- per-instrument cap, tightest across every policy on it
                atomic_le(
                    atomic_add(:amt, COALESCE((SELECT atomic_sum(amount_atomic)
                                      FROM budget_reservations
                                      WHERE status <> 'RELEASED'
                                        AND instrument_id = :iid), '0')),
                    (SELECT atomic_min(per_instrument_cap_atomic) FROM policies
                     WHERE instrument_id = :iid))
              AND
                -- per-network cap, tightest across every policy on it
                atomic_le(
                    atomic_add(:amt, COALESCE((SELECT atomic_sum(amount_atomic)
                                      FROM budget_reservations
                                      WHERE status <> 'RELEASED'
                                        AND network_id = :nid), '0')),
                    (SELECT atomic_min(per_network_cap_atomic) FROM policies
                     WHERE network_id = :nid))
              AND
                -- global portfolio cap net of reserved cash, tightest across
                -- every admitted policy: adding a policy with a larger cap
                -- must never widen the portfolio's exposure
                atomic_le(
                    atomic_add(:amt, COALESCE((SELECT atomic_sum(amount_atomic)
                                      FROM budget_reservations
                                      WHERE status <> 'RELEASED'), '0')),
                    (SELECT atomic_min(atomic_sub(global_cap_atomic, reserved_cash_atomic))
                     FROM policies))
            """,
            params,
        )
        if cur.rowcount != 1:
            raise BudgetExceededError(
                f"reservation of {amount} atomic quote for "
                f"{economic_action_id[:12]}… would breach a configured cap; "
                "no budget was taken"
            )

    def _settle_reservation(
        self, conn: sqlite3.Connection, economic_action_id: str, status: ReservationStatus
    ) -> None:
        row = conn.execute(
            "SELECT status FROM budget_reservations WHERE economic_action_id = ?",
            (economic_action_id,),
        ).fetchone()
        if row is None or row["status"] != ReservationStatus.ACTIVE.value:
            return
        conn.execute(
            "UPDATE budget_reservations SET status = ?, settled_seq = ? "
            "WHERE economic_action_id = ?",
            (status.value, self._next_seq(conn), economic_action_id),
        )

    def held_atomic(
        self,
        *,
        policy_id: str | None = None,
        instrument_id: str | None = None,
        network_id: str | None = None,
    ) -> int:
        """Quote capital currently counted against the caps in a scope.

        Everything except RELEASED counts: open reservations, spent capital, and
        quarantined capital whose outcome nobody knows.
        """
        clauses = [_HELD_CLAUSE]
        args: list[Any] = []
        for column, value in (
            ("policy_id", policy_id),
            ("instrument_id", instrument_id),
            ("network_id", network_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                args.append(value)
        sql = (
            "SELECT COALESCE(atomic_sum(amount_atomic), '0') FROM budget_reservations WHERE "
            + " AND ".join(clauses)
        )
        return decode_atomic(self._conn.execute(sql, args).fetchone()[0], field="held")

    # -- receipts ----------------------------------------------------------

    def append_fill_receipt(self, receipt: FillReceiptV0, *, now_epoch_s: int) -> bool:
        """Record external truth about a settlement.

        Returns whether the receipt respected the bounds that were committed.
        A receipt is never refused for disagreeing with local expectation --
        the chain is authoritative about what happened. But a receipt outside
        the bounds, or one that pushes cumulative input past the committed
        maximum, drives the intent to ``SAFE_HALT`` in the same transaction.
        Ambiguity is never resolved by assuming the happy path.
        """
        with self._write() as conn:
            row = conn.execute(
                "SELECT state, policy_id, cycle_id, bounds_json FROM intents "
                "WHERE economic_action_id = ?",
                (receipt.economic_action_id,),
            ).fetchone()
            if row is None:
                raise LedgerError(f"unknown economic action {receipt.economic_action_id}")
            state = IntentState(row["state"])
            if state not in _RECEIPT_STATES:
                raise LedgerError(
                    f"a fill receipt is not meaningful while the intent is {state.value}"
                )

            seq = self._next_seq(conn)
            try:
                conn.execute(
                    """
                    INSERT INTO fill_receipts (
                        receipt_id, economic_action_id, external_ref, input_atomic_filled,
                        output_atomic_filled, fee_atomic, observed_at_epoch_s, source,
                        appended_seq
                    ) VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        receipt.receipt_id,
                        receipt.economic_action_id,
                        receipt.external_ref,
                        encode_atomic(receipt.input_atomic_filled, field="input_filled"),
                        encode_atomic(receipt.output_atomic_filled, field="output_filled"),
                        encode_atomic(receipt.fee_atomic, field="fee"),
                        receipt.observed_at_epoch_s,
                        receipt.source,
                        seq,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise LedgerError(
                    f"duplicate fill receipt ({receipt.receipt_id} / {receipt.external_ref}): {exc}"
                ) from exc

            self._append_event(
                conn,
                event_type=EventType.FILL_RECEIPT_APPENDED,
                policy_id=row["policy_id"],
                cycle_id=row["cycle_id"],
                economic_action_id=receipt.economic_action_id,
                from_state=state.value,
                to_state=None,
                now_epoch_s=now_epoch_s,
                payload=receipt.canonical_object(),
            )

            bounds = strict_json_loads(row["bounds_json"])
            ok = self._receipt_within_bounds(conn, receipt, bounds)
            if not ok:
                assert_legal_transition(state, IntentState.SAFE_HALT)
                # The fill happened, it just landed outside the committed
                # bounds. The capital is gone, so it is quarantined rather than
                # returned to the available pool.
                self._settle_reservation(
                    conn, receipt.economic_action_id, ReservationStatus.QUARANTINED
                )
                conn.execute(
                    "UPDATE intents SET state = ? WHERE economic_action_id = ?",
                    (IntentState.SAFE_HALT.value, receipt.economic_action_id),
                )
                self._append_event(
                    conn,
                    event_type=EventType.INTENT_TRANSITION,
                    policy_id=row["policy_id"],
                    cycle_id=row["cycle_id"],
                    economic_action_id=receipt.economic_action_id,
                    from_state=state.value,
                    to_state=IntentState.SAFE_HALT.value,
                    now_epoch_s=now_epoch_s,
                    payload={"reason": "FILL_OUTSIDE_COMMITTED_BOUNDS"},
                )
            return ok

    @staticmethod
    def _receipt_within_bounds(
        conn: sqlite3.Connection, receipt: FillReceiptV0, bounds: Mapping[str, Any]
    ) -> bool:
        max_input = decode_atomic(bounds["max_input_atomic"], field="bounds.max_input_atomic")
        min_output = decode_atomic(bounds["min_output_atomic"], field="bounds.min_output_atomic")
        totals = conn.execute(
            "SELECT COALESCE(atomic_sum(input_atomic_filled), '0'), "
            "COALESCE(atomic_sum(output_atomic_filled), '0') "
            "FROM fill_receipts WHERE economic_action_id = ?",
            (receipt.economic_action_id,),
        ).fetchone()
        total_in = decode_atomic(totals[0], field="total input filled")
        total_out = decode_atomic(totals[1], field="total output filled")
        if total_in > max_input:
            return False
        # A partial fill must honour the same price bound as a full one, so the
        # output floor scales with the input actually consumed. Rounded up.
        required_out = -((-min_output * total_in) // max_input)
        return total_out >= required_out

    # -- events ------------------------------------------------------------

    @staticmethod
    def _next_seq(conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM state_events").fetchone()
        return int(row[0]) + 1

    def _append_event(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: EventType,
        policy_id: str,
        cycle_id: str,
        economic_action_id: str | None,
        from_state: str | None,
        to_state: str | None,
        now_epoch_s: int,
        payload: Mapping[str, Any],
    ) -> int:
        if not isinstance(now_epoch_s, int) or isinstance(now_epoch_s, bool) or now_epoch_s < 0:
            raise LedgerError("now_epoch_s must be a non-negative int")
        cur = conn.execute(
            """
            INSERT INTO state_events (
                event_type, policy_id, cycle_id, economic_action_id,
                from_state, to_state, occurred_epoch_s, payload_json
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                event_type.value,
                policy_id,
                cycle_id,
                economic_action_id,
                from_state,
                to_state,
                now_epoch_s,
                canonical_json_str(dict(payload)),
            ),
        )
        return int(cur.lastrowid)

    def events(self) -> list[dict[str, Any]]:
        """The append-only log, in sequence order."""
        return [
            dict(r)
            for r in self._conn.execute("SELECT * FROM state_events ORDER BY seq ASC")
        ]

    def canonical_policies(self) -> list[str]:
        return [
            r[0]
            for r in self._conn.execute(
                "SELECT canonical_json FROM policies ORDER BY policy_id ASC"
            )
        ]

    # -- derived projections ----------------------------------------------

    def cycle_projection(self, cycle_id: str) -> dict[str, Any]:
        """Inventory, realized proceeds and next eligible rungs for one cycle.

        Only ``FILLED`` intents move inventory. An intent that is merely
        ``SUBMITTED`` has not moved anything as far as this ledger is
        concerned, and one in ``SAFE_HALT`` never will without human
        reconciliation.
        """
        rows = self._conn.execute(
            """
            SELECT i.economic_action_id, i.side, i.kind, i.level_id, i.state,
                   COALESCE(atomic_sum(f.input_atomic_filled), '0')  AS in_filled,
                   COALESCE(atomic_sum(f.output_atomic_filled), '0') AS out_filled
            FROM intents i
            LEFT JOIN fill_receipts f ON f.economic_action_id = i.economic_action_id
            WHERE i.cycle_id = ?
            GROUP BY i.economic_action_id
            ORDER BY i.economic_action_id ASC
            """,
            (cycle_id,),
        ).fetchall()

        base_in = base_out = quote_in = quote_out = 0
        consumed_levels: set[str] = set()
        halted = False
        for row in rows:
            consumed_levels.add(row["level_id"])
            state = IntentState(row["state"])
            if state is IntentState.SAFE_HALT:
                halted = True
            if state is not IntentState.FILLED:
                continue
            filled_in = decode_atomic(row["in_filled"], field="in_filled")
            filled_out = decode_atomic(row["out_filled"], field="out_filled")
            if Side(row["side"]) is Side.BUY:
                quote_out += filled_in
                base_in += filled_out
            else:
                base_out += filled_in
                quote_in += filled_out

        cycle = self._conn.execute(
            "SELECT policy_id, status FROM cycles WHERE cycle_id = ?", (cycle_id,)
        ).fetchone()
        if cycle is None:
            raise LedgerError(f"unknown cycle {cycle_id}")
        levels = self._conn.execute(
            "SELECT level_id, kind FROM ladder_levels WHERE policy_id = ? "
            "ORDER BY kind ASC, level_index ASC",
            (cycle["policy_id"],),
        ).fetchall()
        # A rung is eligible only if this cycle has never created an economic
        # action for it. Consumption is permanent within a cycle regardless of
        # how that action ended: re-entry is a new cycle, never a retry.
        next_entry = [
            r["level_id"]
            for r in levels
            if r["kind"] == LadderKind.ENTRY.value and r["level_id"] not in consumed_levels
        ]
        next_exit = [
            r["level_id"]
            for r in levels
            if r["kind"] == LadderKind.EXIT.value and r["level_id"] not in consumed_levels
        ]
        return {
            "cycle_id": cycle_id,
            "policy_id": cycle["policy_id"],
            "status": cycle["status"],
            "requires_reconciliation": halted,
            "filled_base_inventory_atomic": str(base_in - base_out),
            "base_acquired_atomic": str(base_in),
            "base_disposed_atomic": str(base_out),
            "realized_quote_proceeds_atomic": str(quote_in),
            "quote_spent_atomic": str(quote_out),
            "held_quote_atomic": str(self.held_atomic()),
            "next_eligible_entry_levels": next_entry,
            "next_eligible_exit_levels": next_exit,
        }

    def inventory_atomic(self, cycle_id: str) -> int:
        return int(self.cycle_projection(cycle_id)["filled_base_inventory_atomic"])

    # -- snapshot ----------------------------------------------------------

    def snapshot(self) -> RuntimeStateV0:
        """A fully ordered, comparable view of the whole ledger."""

        def rows(sql: str) -> tuple[Mapping[str, Any], ...]:
            return tuple(dict(r) for r in self._conn.execute(sql))

        cycle_ids = [r[0] for r in self._conn.execute("SELECT cycle_id FROM cycles ORDER BY cycle_id ASC")]
        return RuntimeStateV0(
            schema_version=read_schema_version(self._conn),
            policies=rows("SELECT * FROM policies ORDER BY policy_id ASC"),
            instruments=rows("SELECT * FROM instruments ORDER BY instrument_id ASC"),
            cycles=rows("SELECT * FROM cycles ORDER BY cycle_id ASC"),
            ladder_levels=rows(
                "SELECT * FROM ladder_levels ORDER BY policy_id ASC, kind ASC, level_index ASC"
            ),
            intents=rows("SELECT * FROM intents ORDER BY economic_action_id ASC"),
            state_events=rows("SELECT * FROM state_events ORDER BY seq ASC"),
            budget_reservations=rows(
                "SELECT * FROM budget_reservations ORDER BY economic_action_id ASC"
            ),
            fill_receipts=rows("SELECT * FROM fill_receipts ORDER BY receipt_id ASC"),
            derived=tuple(self.cycle_projection(cid) for cid in cycle_ids),
        )

    def integrity_check(self) -> None:
        """Structural checks the schema alone cannot express."""
        problem = self._conn.execute("PRAGMA integrity_check").fetchone()[0]
        if problem != "ok":
            raise LedgerError(f"sqlite integrity_check failed: {problem}")
        violations = self._conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise LedgerError(f"foreign key violations: {violations}")
        seqs = [r[0] for r in self._conn.execute("SELECT seq FROM state_events ORDER BY seq ASC")]
        if seqs != sorted(set(seqs)):
            raise LedgerError("state_events sequence is not strictly increasing")
        orphan = self._conn.execute(
            """
            SELECT COUNT(*) FROM budget_reservations r
            LEFT JOIN intents i ON i.economic_action_id = r.economic_action_id
            WHERE i.economic_action_id IS NULL
            """
        ).fetchone()[0]
        if orphan:
            raise LedgerError(f"{orphan} budget reservations have no intent")
        holding = sorted(s.value for s in BUDGET_HOLDING_STATES)
        stale = self._conn.execute(
            f"""
            SELECT COUNT(*) FROM budget_reservations r
            JOIN intents i ON i.economic_action_id = r.economic_action_id
            WHERE r.status = 'ACTIVE'
              AND i.state NOT IN ({','.join('?' * len(holding))})
            """,
            holding,
        ).fetchone()[0]
        if stale:
            raise LedgerError(f"{stale} active reservations are held by non-holding intents")
        mismatched = self._conn.execute(
            """
            SELECT COUNT(*) FROM budget_reservations r
            JOIN intents i ON i.economic_action_id = r.economic_action_id
            WHERE (r.status = 'QUARANTINED') <> (i.state = 'SAFE_HALT')
            """
        ).fetchone()[0]
        if mismatched:
            raise LedgerError(
                f"{mismatched} reservations disagree with their intent about quarantine"
            )


def open_ledger(
    path: str = ":memory:",
    *,
    create: bool = True,
    wal: bool = True,
    busy_timeout_ms: int = 10_000,
) -> SpotLedger:
    """Open (and if needed create) a ledger database.

    ``path`` is a local filesystem path or ``":memory:"``. There is no remote
    backend and no server; SQLite is the substrate.
    """
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    in_memory = path == ":memory:" or path.startswith("file::memory:")
    configure_connection(conn, wal=wal and not in_memory, busy_timeout_ms=busy_timeout_ms)
    has_meta = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'"
    ).fetchone()
    if not has_meta:
        if not create:
            raise SchemaVersionError(f"no QntySpot ledger at {path}")
        apply_schema(conn)
    return SpotLedger(conn, owns_connection=True)
