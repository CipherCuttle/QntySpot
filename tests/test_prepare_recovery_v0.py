"""Durable prepare-plan invariants for the native SELL operator.

These are deliberately offline.  They exercise the database ordering which
must survive process death; no signer, transport, or live authority is used.
"""

from __future__ import annotations

import inspect
import sqlite3

import pytest

from qntyspot.errors import SafeHaltError
from qntyspot.ledger.execution import ExecutionRuntime


def _plan(*, nonce: int = 1) -> dict[str, object]:
    return {
        "approval": {"nonce": nonce},
        "envelope": {"nonce": nonce + 1},
        "policy_doc": {"schema": "qntyspot.policy.v0"},
        "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.plan.v1",
    }


def _record(runtime: ExecutionRuntime, source_cycle_id: str, *, plan=None):
    return runtime.record_prepare_plan(
        operation_kind="INK_V0F_NATIVE_SELL",
        source_cycle_id=source_cycle_id,
        successor_policy_id="ab" * 32,
        authority_policy_digest="cd" * 32,
        authority_receipt_id="ef" * 32,
        plan=_plan() if plan is None else plan,
        now_epoch_s=1_700_000_000,
    )


def test_plan_is_durable_before_carry_and_byte_identical_on_resume(armed) -> None:
    ledger, _policy, source_cycle_id, _intent = armed
    runtime = ExecutionRuntime(ledger)
    first = _record(runtime, source_cycle_id)
    second = _record(runtime, source_cycle_id)
    assert first == second
    assert first.phase == "PLANNED"
    assert ledger.connection.execute("SELECT COUNT(*) FROM cycles").fetchone()[0] == 1



def test_prepare_plan_survives_after_commit_process_failure(armed) -> None:
    ledger, _policy, source_cycle_id, _intent = armed

    def crash(boundary: str, when: str) -> None:
        if boundary == "prepare_plan" and when == "after_commit":
            raise RuntimeError("INJECTED_AFTER_PLAN_COMMIT")

    runtime = ExecutionRuntime(ledger, failure_injector=crash)
    with pytest.raises(RuntimeError, match="INJECTED_AFTER_PLAN_COMMIT"):
        _record(runtime, source_cycle_id)

    resumed = ExecutionRuntime(ledger).load_prepare_plan(
        operation_kind="INK_V0F_NATIVE_SELL",
        source_cycle_id=source_cycle_id,
    )
    assert resumed is not None
    assert resumed.phase == "PLANNED"


def test_every_prepare_phase_survives_after_commit_process_failure(armed) -> None:
    ledger, _policy, source_cycle_id, _intent = armed
    record = _record(ExecutionRuntime(ledger), source_cycle_id)
    phases = (
        "POLICY_ADMITTED",
        "INVENTORY_CARRIED",
        "INTENT_SIMULATED",
        "SESSION_RECORDED",
        "PREAUTH_RECORDED",
        "PREPARED",
    )

    for expected_phase in phases:
        def crash(boundary: str, when: str) -> None:
            if boundary == "prepare_phase" and when == "after_commit":
                raise RuntimeError(f"INJECTED_AFTER_{expected_phase}")

        with pytest.raises(RuntimeError, match=f"INJECTED_AFTER_{expected_phase}"):
            ExecutionRuntime(
                ledger,
                failure_injector=crash,
            ).advance_prepare_phase(
                record.prepare_id,
                expected_phase,
                now_epoch_s=1_700_000_001,
            )

        record = ExecutionRuntime(ledger).load_prepare_plan(
            operation_kind="INK_V0F_NATIVE_SELL",
            source_cycle_id=source_cycle_id,
        )
        assert record is not None
        assert record.phase == expected_phase


def test_plan_mismatch_stops_before_another_carry(armed) -> None:
    ledger, _policy, source_cycle_id, _intent = armed
    runtime = ExecutionRuntime(ledger)
    _record(runtime, source_cycle_id)
    with pytest.raises(SafeHaltError, match="differs"):
        _record(runtime, source_cycle_id, plan=_plan(nonce=9))
    assert ledger.connection.execute("SELECT COUNT(*) FROM cycles").fetchone()[0] == 1


def test_phase_order_is_monotonic_and_identity_is_immutable(armed) -> None:
    ledger, _policy, source_cycle_id, _intent = armed
    runtime = ExecutionRuntime(ledger)
    record = _record(runtime, source_cycle_id)
    with pytest.raises(SafeHaltError, match="does not follow"):
        runtime.advance_prepare_phase(record.prepare_id, "INVENTORY_CARRIED", now_epoch_s=1_700_000_001)
    record = runtime.advance_prepare_phase(record.prepare_id, "POLICY_ADMITTED", now_epoch_s=1_700_000_001)
    assert record.phase == "POLICY_ADMITTED"
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        ledger.connection.execute(
            "UPDATE prepare_records SET plan_json = '{}' WHERE prepare_id = ?", (record.prepare_id,)
        )



def test_native_sell_preauth_accepts_frozen_resume_bundle_parameters() -> None:
    signature = inspect.signature(
        ExecutionRuntime.record_ink_v0f_native_sell_preauth_bundle
    )
    assert "frozen_approval" in signature.parameters
    assert "frozen_envelope" in signature.parameters
    assert "frozen_prepare_id" in signature.parameters
    assert signature.parameters["frozen_approval"].default is None
    assert signature.parameters["frozen_envelope"].default is None
    assert signature.parameters["frozen_prepare_id"].default is None


def test_active_successor_does_not_change_prepare_identity(armed) -> None:
    ledger, _policy, source_cycle_id, _intent = armed
    runtime = ExecutionRuntime(ledger)
    record = _record(runtime, source_cycle_id)
    for phase in (
        "POLICY_ADMITTED", "INVENTORY_CARRIED", "INTENT_SIMULATED",
        "SESSION_RECORDED", "PREAUTH_RECORDED", "PREPARED",
    ):
        record = runtime.advance_prepare_phase(record.prepare_id, phase, now_epoch_s=1_700_000_001)
    resumed = runtime.load_prepare_plan(
        operation_kind="INK_V0F_NATIVE_SELL", source_cycle_id=source_cycle_id
    )
    assert resumed is not None
    assert resumed.prepare_id == record.prepare_id
    assert resumed.phase == "PREPARED"
