"""Regression proof for the Level-2 SAFE_HALT exact-bytes resume repair.

Every surface here is a temporary SQLite clone. The signed-byte fixture is the
public detached test vector; no production ledger, grant, or byte string is
touched, and no test ever signs, reaches a network, or issues a real submit:
the transport is always a spy, so TRANSPORT_CALL_COUNT stays observable.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import NOW, base_policy_doc, drive
from qntyspot.canon import canonical_json_bytes, sha256_hex, strict_json_loads
from qntyspot.errors import (
    AuthorityCeilingError,
    AuthorityVerificationError,
    ChainTruthError,
    EnvelopeValidationError,
    LedgerError,
    SafeHaltError,
)
from qntyspot.economics import build_intent
from qntyspot.execution_contract import (
    AuthorityLevel,
    ChainObservationV0,
    ChainPresence,
    ExternalTransactionReferenceV0,
    FinalityPolicyV0,
    ReceiptStatus,
)
from qntyspot.exact_signed_bytes import (
    ExactSignedBytesAdmissionV0,
    ExactSignedBytesScopeV0,
    ExactSignedTransactionRecordV0,
    ParsedExactSignedBytesV0,
    ValidatedExactSignedBytesV0,
)
from qntyspot.ledger import (
    ExactBytesResumeResultV0,
    ExecutionRuntime,
    assert_execution_replay_equivalence,
    open_ledger,
)
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

from test_external_authority_root import _receipt, _root_for, _session
from test_submit_exact_signed_bytes_v0 import RAW

ROOT = Path(__file__).resolve().parents[1]
REPAIR_ARTIFACT = ROOT / "artifacts/SUBMIT_EXACT_SIGNED_BYTES_SAFE_HALT_RESUME_REPAIR_V0.json"
REPAIR_SIDECAR = REPAIR_ARTIFACT.with_suffix(".sha256")

RAW_SHA256 = sha256_hex(RAW)
TX_HASH = "0x7508482061b00d5775609a79956af4b58b07a969aa030ac99c3444c7573e129b"
RAW_EVIDENCE = "77" * 32
CALLDATA_SHA256 = sha256_hex(b"")
RECOVERY_AT = NOW + 10
EVIDENCE_MAX_AGE_S = 600


class TransportSpy:
    """Counts transport invocations; the proof is that this stays empty."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def submit_exact_signed_bytes(self, signed_bytes: bytes) -> str:
        self.calls.append(bytes(signed_bytes))
        return TX_HASH


def _absent(provider: str, *, observed_at: int = RECOVERY_AT - 5, tx_hash: str = TX_HASH) -> ChainObservationV0:
    return ChainObservationV0(
        provider_id=provider,
        transaction_hash=tx_hash,
        observed_at_epoch_s=observed_at,
        presence=ChainPresence.ABSENT,
        raw_evidence_sha256=RAW_EVIDENCE,
    )


def _admission(action_id: str, session) -> ExactSignedBytesAdmissionV0:
    scope = ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=session.chain_id,
        taker_address=session.taker_address,
        target_address="0x1111111111111111111111111111111111111111",
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=CALLDATA_SHA256,
        calldata_length=0,
        account_nonce=0,
    )
    parsed = ParsedExactSignedBytesV0(
        transaction_type="eip-1559",
        chain_id=session.chain_id,
        account_nonce=0,
        gas_limit=100_000,
        max_fee_per_gas=20_000_000,
        max_priority_fee_per_gas=20_000_000,
        target_address="0x1111111111111111111111111111111111111111",
        value_atomic=0,
        calldata=b"",
        sender_address=session.taker_address,
        transaction_hash=TX_HASH,
    )
    validated = ValidatedExactSignedBytesV0(
        scope=scope,
        parsed=parsed,
        signed_bytes_sha256=RAW_SHA256,
        signed_bytes_length=len(RAW),
    )
    record = ExactSignedTransactionRecordV0(
        economic_action_id=action_id,
        scope_digest=scope.scope_digest,
        signed_bytes_sha256=RAW_SHA256,
        signed_bytes_length=len(RAW),
        transaction_hash=TX_HASH,
        chain_id=session.chain_id,
        account_nonce=0,
        taker_address=session.taker_address,
        signer_identity="evm-recovered:" + session.taker_address,
    )
    return ExactSignedBytesAdmissionV0(RAW, record, validated)


def _insert_signed_row(
    ledger, action_id: str, session, admission, *, raw_sha: str = RAW_SHA256
) -> None:
    conn = ledger.connection
    conn.execute(
        """
        INSERT INTO signed_transactions (
            signed_transaction_id, external_action_id, session_id, envelope_id,
            approval_action_id, origin, chain_id, taker_address, account_nonce,
            raw_signed_sha256, raw_signed_length, transaction_hash, scope_digest,
            signer_identity, frozen_at_epoch_s
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            admission.record.signed_transaction_id,
            action_id,
            session.session_id,
            None,
            None,
            "EXTERNAL_SIGNED_BYTES",
            session.chain_id,
            session.taker_address,
            0,
            raw_sha,
            len(RAW),
            TX_HASH,
            admission.record.scope_digest,
            admission.record.signer_identity,
            NOW,
        ),
    )


def verify_authority_grant(receipt, session):
    from qntyspot.authority_root import verify_authority_grant as verify

    return verify(
        receipt=receipt,
        trusted_root=_root_for(receipt.root_id),
        session=session,
        now_epoch_s=NOW,
    )


def _surface(
    tmp_path: Path,
    *,
    to_state: IntentState | None = IntentState.SAFE_HALT,
    signed_row: bool = True,
    raw_sha: str = RAW_SHA256,
):
    """A temporary clone of the serial-2 episode shape at the requested state."""
    policy_doc = base_policy_doc()
    policy_doc["entry_ladder"]["levels"][0]["input_amount"] = "1"
    policy = parse_policy(policy_doc)
    ledger = open_ledger(str(tmp_path / "resume-repair.sqlite3"))
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    drive(ledger, intent.economic_action_id, IntentState.TRIGGERED, IntentState.QUOTE_PINNED, IntentState.SIMULATED)
    # The public fixture's high claim intersects down to the Level-2 source
    # ceiling (same pattern as test_execution_runtime.py), granting exactly
    # SUBMIT_EXACT_BYTES and nothing above it.
    receipt = _high_receipt()
    session = replace(_session(receipt), policy_id=policy.policy_id, db_schema_version=4)
    grant = verify_authority_grant(receipt, session)
    runtime = ExecutionRuntime(ledger)
    runtime.create_execution_session(session, grant, now_epoch_s=NOW)
    runtime.reserve_action(
        intent.economic_action_id, session=session, verified_grant=grant, now_epoch_s=NOW
    )
    admission = _admission(intent.economic_action_id, session)
    if signed_row:
        _insert_signed_row(
            ledger, intent.economic_action_id, session, admission, raw_sha=raw_sha
        )
    if to_state is IntentState.SIGNED:
        drive(ledger, intent.economic_action_id, IntentState.SIGNED)
    elif to_state is IntentState.SAFE_HALT:
        drive(ledger, intent.economic_action_id, IntentState.SIGNED, IntentState.SAFE_HALT)
    spy = TransportSpy()
    return ledger, runtime, intent, session, grant, admission, spy


def _resume(runtime, intent, session, grant, *, observations=None, **overrides):
    parameters = {
        "economic_action_id": intent.economic_action_id,
        "session": session,
        "verified_grant": grant,
        "signed_bytes_sha256": RAW_SHA256,
        "transaction_hash": TX_HASH,
        "chain_id": session.chain_id,
        "taker_address": session.taker_address,
        "account_nonce": 0,
        "absence_observations": (
            _absent("provider-a"),
            _absent("provider-b"),
        )
        if observations is None
        else observations,
        "evidence_max_age_s": EVIDENCE_MAX_AGE_S,
        "recovery_timestamp_epoch_s": RECOVERY_AT,
    }
    parameters.update(overrides)
    return runtime.resume_quarantined_exact_signed_bytes(**parameters)


def _assert_resumed(ledger, intent) -> None:
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SIGNED
    status = ledger.connection.execute(
        "SELECT status FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0]
    assert status == "ACTIVE"
    ledger.integrity_check()


# -- Root problem 1: the transport seam is unreachable from bad shapes -------


def test_01_submit_from_safe_halt_fails_before_transport(tmp_path: Path) -> None:
    _ledger, runtime, intent, _session_row, grant, admission, spy = _surface(tmp_path)
    assert _ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT
    with pytest.raises(SafeHaltError, match="SIGNED"):
        runtime.submit_exact_signed_bytes(
            admission, spy, _session_row, grant, provider_id="spy",
            submitted_at_epoch_s=NOW,
        )
    assert spy.calls == []


def test_02_submit_with_quarantined_reservation_fails_before_transport(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, admission, spy = _surface(
        tmp_path, to_state=IntentState.SIGNED
    )
    # Hostile shape that ordinary flows cannot produce: SIGNED intent holding a
    # QUARANTINED reservation. The gate must fail closed anyway.
    _ledger.connection.execute(
        "UPDATE budget_reservations SET status = 'QUARANTINED' WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    )
    with pytest.raises(SafeHaltError, match="ACTIVE reservation"):
        runtime.submit_exact_signed_bytes(
            admission, spy, session, grant, provider_id="spy", submitted_at_epoch_s=NOW
        )
    assert spy.calls == []


def test_03_valid_signed_active_reaches_fake_transport(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, admission, spy = _surface(
        tmp_path, to_state=IntentState.SIGNED
    )
    attempt = runtime.submit_exact_signed_bytes(
        admission, spy, session, grant, provider_id="spy", submitted_at_epoch_s=NOW
    )
    assert spy.calls == [RAW]
    assert attempt.acknowledgment.value == "ACCEPTED"
    assert _ledger.intent_state(intent.economic_action_id) is IntentState.SUBMITTED


def test_03b_submit_with_wrong_durable_digest_fails_before_transport(tmp_path: Path) -> None:
    # The signed_transactions row is append-only, so build a separate clone
    # whose durable row was admitted with different bytes than the admission.
    _ledger, runtime, intent, session, grant, admission, spy = _surface(
        tmp_path, to_state=IntentState.SIGNED, raw_sha="99" * 32
    )
    with pytest.raises(EnvelopeValidationError, match="digest"):
        runtime.submit_exact_signed_bytes(
            admission, spy, session, grant, provider_id="spy", submitted_at_epoch_s=NOW
        )
    assert spy.calls == []


def test_03c_submit_from_filled_external_episode_fails_before_transport(tmp_path: Path) -> None:
    """A genuinely FILLED episode (external-reference origin) cannot submit."""
    ledger, runtime, intent, session, grant = _filled_surface(tmp_path)
    spy = TransportSpy()
    admission = _admission(intent.economic_action_id, session)
    with pytest.raises(LedgerError, match="not durable"):
        runtime.submit_exact_signed_bytes(
            admission, spy, session, grant, provider_id="spy", submitted_at_epoch_s=NOW
        )
    assert spy.calls == []
    assert ledger.intent_state(intent.economic_action_id) is IntentState.FILLED


def _high_receipt():
    return _receipt(AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER)


def _filled_surface(tmp_path: Path):
    ledger, runtime, intent, session, grant, _admission_handle, _spy = _surface(
        tmp_path, to_state=None, signed_row=False
    )
    reference = ExternalTransactionReferenceV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=intent.economic_action_id,
        transaction_hash="0x" + "ab" * 32,
        chain_id=session.chain_id,
        taker_address=session.taker_address,
        authority_policy_digest=session.authority_policy_digest,
    )
    runtime.record_external_transaction_reference(reference, session, grant, now_epoch_s=NOW)
    finality = FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=2)
    for provider in ("provider-a", "provider-b"):
        runtime.record_chain_observation(
            ChainObservationV0(
                provider_id=provider,
                transaction_hash=reference.transaction_hash,
                observed_at_epoch_s=NOW,
                presence=ChainPresence.INCLUDED,
                raw_evidence_sha256=RAW_EVIDENCE,
                block_number=7,
                block_hash="0x" + "cd" * 32,
                block_parent_hash="0x" + "ce" * 32,
                head_block_number=9,
                head_block_hash="0x" + "cf" * 32,
                receipt_status=ReceiptStatus.SUCCESS,
                effective_input_atomic=1_000_000,
                effective_output_atomic=1_200_000_000_000_000_000,
            ),
            external_action_id=intent.economic_action_id,
            external_transaction_ref_id=reference.external_transaction_ref_id,
            session=session,
            verified_grant=grant,
            now_epoch_s=NOW,
            finality=finality,
        )
    runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
        finality=finality,
        receipt_id="receipt-filled-gate",
    )
    runtime.complete_settlement(intent.economic_action_id, now_epoch_s=NOW)
    return ledger, runtime, intent, session, grant


# -- Root problem 2: the narrow resume primitive -----------------------------


def test_04_resume_requires_safe_halt(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(
        tmp_path, to_state=IntentState.SIGNED
    )
    with pytest.raises(LedgerError, match="SAFE_HALT"):
        _resume(runtime, intent, session, grant)
    assert spy.calls == []


def test_05_resume_requires_quarantined_reservation(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    # Hostile shape: SAFE_HALT intent whose reservation is no longer quarantined.
    _ledger.connection.execute(
        "UPDATE budget_reservations SET status = 'ACTIVE' WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    )
    with pytest.raises(LedgerError, match="QUARANTINED"):
        _resume(runtime, intent, session, grant)
    assert spy.calls == []


@pytest.mark.parametrize("acknowledgment", ["ACCEPTED", "UNKNOWN"])
def test_06_and_07_resume_rejects_any_prior_submission_attempt(
    tmp_path: Path, acknowledgment: str
) -> None:
    _ledger, runtime, intent, session, grant, admission, spy = _surface(tmp_path)
    _ledger.connection.execute(
        """
        INSERT INTO submission_attempts (
            submission_attempt_id, signed_transaction_id, provider_id,
            attempt_ordinal, submitted_at_epoch_s, acknowledgment,
            provider_reported_hash, error_class
        ) VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            "ea" * 32,
            admission.record.signed_transaction_id,
            "provider-x",
            0,
            NOW,
            acknowledgment,
            TX_HASH if acknowledgment == "ACCEPTED" else None,
            None if acknowledgment == "ACCEPTED" else "TestError",
        ),
    )
    with pytest.raises(SafeHaltError, match="submission_attempt"):
        _resume(runtime, intent, session, grant)
    assert spy.calls == []


def test_08_resume_rejects_mismatched_signed_bytes(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    with pytest.raises(LedgerError, match="disagrees"):
        _resume(runtime, intent, session, grant, signed_bytes_sha256="88" * 32)
    assert spy.calls == []


def test_09_resume_rejects_mismatched_tx_hash(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    with pytest.raises(LedgerError, match="disagrees"):
        _resume(runtime, intent, session, grant, transaction_hash="0x" + "fe" * 32)
    assert spy.calls == []


def test_10_resume_rejects_wrong_session_binding(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    other_session = replace(session, session_ordinal=1)
    _other_grant = verify_authority_grant(_high_receipt(), other_session)
    runtime.create_execution_session(other_session, _other_grant, now_epoch_s=NOW)
    with pytest.raises(AuthorityVerificationError, match="session"):
        _resume(runtime, intent, other_session, _other_grant)
    assert spy.calls == []


def test_11_resume_rejects_expired_grant(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    with pytest.raises((AuthorityCeilingError, AuthorityVerificationError)):
        _resume(runtime, intent, session, grant, recovery_timestamp_epoch_s=NOW + 2_000)
    assert spy.calls == []


def test_12_resume_rejects_wrong_authority_level(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, _grant, _a, spy = _surface(tmp_path)
    shadow_receipt = _receipt(AuthorityLevel.SHADOW)
    shadow_session = replace(
        _session(shadow_receipt), policy_id=session.policy_id, db_schema_version=4, session_ordinal=2
    )
    shadow_grant = verify_authority_grant(shadow_receipt, shadow_session)
    runtime.create_execution_session(shadow_session, shadow_grant, now_epoch_s=NOW)
    with pytest.raises((AuthorityCeilingError, AuthorityVerificationError)):
        _resume(runtime, intent, shadow_session, shadow_grant)
    assert spy.calls == []


def test_13_resume_requires_distinct_providers(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    with pytest.raises(ChainTruthError, match="distinct"):
        _resume(
            runtime, intent, session, grant,
            observations=(_absent("provider-a"), _absent("provider-a")),
        )
    assert spy.calls == []


def test_14_resume_requires_two_provider_observations(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    with pytest.raises(ChainTruthError, match="two"):
        _resume(runtime, intent, session, grant, observations=(_absent("provider-a"),))
    assert spy.calls == []


def test_15_resume_rejects_pending_evidence(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    pending = ChainObservationV0(
        provider_id="provider-a",
        transaction_hash=TX_HASH,
        observed_at_epoch_s=RECOVERY_AT - 5,
        presence=ChainPresence.PENDING,
        raw_evidence_sha256=RAW_EVIDENCE,
    )
    with pytest.raises(ChainTruthError, match="ABSENT"):
        _resume(
            runtime, intent, session, grant,
            observations=(pending, _absent("provider-b")),
        )
    assert spy.calls == []


def test_16_resume_rejects_included_evidence(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    included = ChainObservationV0(
        provider_id="provider-a",
        transaction_hash=TX_HASH,
        observed_at_epoch_s=RECOVERY_AT - 5,
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=RAW_EVIDENCE,
        block_number=7,
        block_hash="0x" + "cd" * 32,
        block_parent_hash="0x" + "ce" * 32,
        head_block_number=9,
        head_block_hash="0x" + "cf" * 32,
        receipt_status=ReceiptStatus.SUCCESS,
        effective_input_atomic=1_000_000,
        effective_output_atomic=1_200_000_000_000_000_000,
    )
    with pytest.raises(ChainTruthError, match="ABSENT"):
        _resume(
            runtime, intent, session, grant,
            observations=(included, _absent("provider-b")),
        )
    assert spy.calls == []


def test_16b_resume_rejects_stale_absence_evidence(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    with pytest.raises(ChainTruthError, match="fresh"):
        _resume(
            runtime, intent, session, grant,
            observations=(
                _absent("provider-a", observed_at=RECOVERY_AT - EVIDENCE_MAX_AGE_S),
                _absent("provider-b", observed_at=RECOVERY_AT - EVIDENCE_MAX_AGE_S),
            ),
        )
    assert spy.calls == []


def test_17_resume_does_not_create_a_new_economic_action(tmp_path: Path) -> None:
    ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    result = _resume(runtime, intent, session, grant)
    assert isinstance(result, ExactBytesResumeResultV0) and not result.already_resumed
    assert spy.calls == []
    rows = ledger.connection.execute(
        "SELECT economic_action_id FROM intents"
    ).fetchall()
    assert [row[0] for row in rows] == [intent.economic_action_id]
    _assert_resumed(ledger, intent)


def test_18_resume_does_not_create_a_new_reservation(tmp_path: Path) -> None:
    ledger, runtime, intent, session, grant, _a, _spy = _surface(tmp_path)
    _resume(runtime, intent, session, grant)
    rows = ledger.connection.execute(
        "SELECT economic_action_id, status FROM budget_reservations"
    ).fetchall()
    assert [(row[0], row[1]) for row in rows] == [
        (intent.economic_action_id, "ACTIVE")
    ]


def test_19_resume_does_not_create_a_new_signed_transaction(tmp_path: Path) -> None:
    ledger, runtime, intent, session, grant, admission, _spy = _surface(tmp_path)
    _resume(runtime, intent, session, grant)
    rows = ledger.connection.execute(
        "SELECT signed_transaction_id, origin, raw_signed_sha256, transaction_hash, "
        "chain_id, taker_address, account_nonce FROM signed_transactions"
    ).fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["signed_transaction_id"] == admission.record.signed_transaction_id
    assert row["origin"] == "EXTERNAL_SIGNED_BYTES"
    assert row["raw_signed_sha256"] == RAW_SHA256
    assert row["transaction_hash"] == TX_HASH
    assert row["chain_id"] == session.chain_id
    assert row["taker_address"] == session.taker_address
    assert row["account_nonce"] == 0


def test_20_reservation_becomes_active_atomically_with_resumed_state(tmp_path: Path) -> None:
    ledger, runtime, intent, session, grant, _a, _spy = _surface(tmp_path)
    result = _resume(runtime, intent, session, grant)
    assert result.recovery_digest
    _assert_resumed(ledger, intent)
    events = ledger.connection.execute(
        "SELECT event_type, from_state, to_state FROM state_events "
        "WHERE event_type = 'EXACT_BYTES_RESUMED'"
    ).fetchall()
    assert [(e["from_state"], e["to_state"]) for e in events] == [("SAFE_HALT", "SIGNED")]
    payload = strict_json_loads(
        ledger.connection.execute(
            "SELECT payload_json FROM state_events WHERE event_type = 'EXACT_BYTES_RESUMED'"
        ).fetchone()[0]
    )
    assert payload["recovery_type"] == "ZERO_SUBMISSION_EXACT_BYTES_RESUME"
    assert payload["prior_intent_state"] == "SAFE_HALT"
    assert payload["prior_reservation_status"] == "QUARANTINED"
    assert payload["authority_receipt_id"]
    assert payload["signed_transaction_id"]
    assert payload["absence_evidence_digest"]
    assert len(payload["absence_evidence"]) == 2
    assert payload["recovered_at_epoch_s"] == RECOVERY_AT


def test_21_replay_is_identical_after_recovery(tmp_path: Path) -> None:
    ledger, runtime, intent, session, grant, _a, _spy = _surface(tmp_path)
    _resume(runtime, intent, session, grant)
    _assert_resumed(ledger, intent)
    assert_execution_replay_equivalence(ledger)


def test_22_second_recovery_is_an_idempotent_no_op(tmp_path: Path) -> None:
    ledger, runtime, intent, session, grant, _a, _spy = _surface(tmp_path)
    first = _resume(runtime, intent, session, grant)
    second = _resume(runtime, intent, session, grant)
    assert first.already_resumed is False
    assert second.already_resumed is True
    assert second.recovery_digest == first.recovery_digest
    count = ledger.connection.execute(
        "SELECT COUNT(*) FROM state_events WHERE event_type = 'EXACT_BYTES_RESUMED'"
    ).fetchone()[0]
    assert count == 1
    _assert_resumed(ledger, intent)


def test_22b_resume_forbidden_after_release_or_commit_shape(tmp_path: Path) -> None:
    _ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    _ledger.connection.execute(
        "UPDATE budget_reservations SET status = 'RELEASED' WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    )
    with pytest.raises(LedgerError, match="QUARANTINED"):
        _resume(runtime, intent, session, grant)
    assert spy.calls == []


def test_23_transport_remains_zero_during_recovery(tmp_path: Path) -> None:
    ledger, runtime, intent, session, grant, _a, spy = _surface(tmp_path)
    _resume(runtime, intent, session, grant)
    _resume(runtime, intent, session, grant)
    _assert_resumed(ledger, intent)
    assert spy.calls == []


# -- Artifact binding ---------------------------------------------------------


def test_24_repair_artifact_is_canonical_and_bound_to_this_repair() -> None:
    raw = REPAIR_ARTIFACT.read_bytes()
    artifact = strict_json_loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert raw == canonical_json_bytes(artifact)
    assert REPAIR_SIDECAR.read_text(encoding="ascii") == f"{digest}  {REPAIR_ARTIFACT.name}\n"
    assert artifact["canonical_parent"] == "e01c5da205eedaa67c301ff30425f9d17f2fbc54"
    assert artifact["prior_implementation_digest"] == (
        "d289031abf773114bc9dc8c57528367531961051c66f1b6efd28c9ee4addcb2a"
    )
    assert artifact["defect"] == (
        "SAFE_HALT_ZERO_SUBMISSION_EXACT_BYTES_CANNOT_RESUME_AND_SUBMIT_STATE_IS_CHECKED_AFTER_TRANSPORT"
    )
    assert artifact["production_ledger_modified"] == "NO"
    assert artifact["authority_grant_issued"] == "NO"
    assert artifact["blockchain_transaction"] == "NO"
    assert artifact["staged_transaction_changed"] == "NO"
    assert artifact["level3_authorized"] == "NO"
    assert artifact["new_implementation_digest"] != artifact["prior_implementation_digest"]
