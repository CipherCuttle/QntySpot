"""Runtime safety tests for the reconcile-only external-transaction path."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sqlite3

import pytest

from conftest import NOW, base_policy_doc, drive
from qntyspot.authority_root import (
    verify_authority_grant,
    verify_expired_authority_grant_for_recovery,
)
from qntyspot.domain import FillReceiptV0
from qntyspot.economics import build_intent
from qntyspot.errors import (
    AuthorityCeilingError,
    AuthorityVerificationError,
    ChainTruthError,
    LedgerError,
    SafeHaltError,
)
from qntyspot.execution_contract import (
    AuthorityLevel,
    ChainObservationV0,
    ChainPresence,
    ExternalTransactionReferenceV0,
    FinalityPolicyV0,
    ReceiptStatus,
)
from qntyspot.ledger import ExecutionRuntime, assert_execution_replay_equivalence, open_ledger
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

from test_external_authority_root import _receipt, _root_for, _session


FINALITY = FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=2)
REVERT_FINALITY = FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=1)
TX_HASH = "0x" + "ab" * 32
RAW_EVIDENCE = "77" * 32


def _external_observation(
    reference: ExternalTransactionReferenceV0,
    provider: str,
    *,
    status: ReceiptStatus = ReceiptStatus.SUCCESS,
    block_hash: str = "0x" + "cd" * 32,
    input_amount: int = 1_000_000,
    output_amount: int = 1_200_000_000_000_000_000,
) -> ChainObservationV0:
    return ChainObservationV0(
        provider_id=provider,
        transaction_hash=reference.transaction_hash,
        observed_at_epoch_s=NOW,
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=RAW_EVIDENCE,
        block_number=7,
        block_hash=block_hash,
        block_parent_hash="0x" + "ce" * 32,
        head_block_number=9,
        head_block_hash="0x" + "cf" * 32,
        receipt_status=status,
        effective_input_atomic=input_amount if status is ReceiptStatus.SUCCESS else None,
        effective_output_atomic=output_amount if status is ReceiptStatus.SUCCESS else None,
    )


def setup_runtime(tmp_path: Path):
    policy_doc = base_policy_doc()
    policy_doc["entry_ladder"]["levels"][0]["input_amount"] = "1"
    policy = parse_policy(policy_doc)
    ledger = open_ledger(str(tmp_path / "runtime.sqlite3"))
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    drive(
        ledger,
        intent.economic_action_id,
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
    )

    # This is a public detached-signature fixture from the authority-consumer
    # tests. The source ceiling intersects its high claim down to Level 1.
    receipt = _receipt(AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER)
    session_seed = _session(receipt)
    session = replace(session_seed, policy_id=policy.policy_id, db_schema_version=2)
    grant = verify_authority_grant(
        receipt=receipt,
        trusted_root=_root_for(receipt.root_id),
        session=session,
        now_epoch_s=NOW,
    )
    runtime = ExecutionRuntime(ledger)
    runtime.create_execution_session(session, grant, now_epoch_s=NOW)
    runtime.reserve_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
    )
    reference = ExternalTransactionReferenceV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=intent.economic_action_id,
        transaction_hash=TX_HASH,
        chain_id=session.chain_id,
        taker_address=session.taker_address,
        authority_policy_digest=session.authority_policy_digest,
    )
    runtime.record_external_transaction_reference(
        reference, session, grant, now_epoch_s=NOW
    )
    return ledger, runtime, intent, reference, session, grant


def _observe(
    runtime: ExecutionRuntime,
    intent,
    reference: ExternalTransactionReferenceV0,
    session,
    grant,
    observation: ChainObservationV0,
    *,
    finality: FinalityPolicyV0 = FINALITY,
) -> bool:
    return runtime.record_chain_observation(
        observation,
        external_action_id=intent.economic_action_id,
        external_transaction_ref_id=reference.external_transaction_ref_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
        finality=finality,
    )


def test_epoch6_same_epoch_authority_receipt_renewal_is_monotonic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import qntyspot.ledger.execution as execution_module

    class FakePolicy:
        def __init__(self, network_id: str) -> None:
            self.permitted_network_id = network_id

        def assert_valid_at(self, now_epoch_s: int) -> None:
            assert now_epoch_s >= 0

    class FakeReceipt:
        def __init__(self, *, epoch: int, issued_at: int) -> None:
            self.authority_epoch = epoch
            self.issued_at_epoch_s = issued_at

    class FakeVerified:
        def __init__(
            self,
            *,
            receipt_id: str,
            issued_at: int,
            network_id: str = "evm:57073",
        ) -> None:
            self.trust_config_digest = "aa" * 32
            self.root_id = "qnty-authority-root-v0"
            self.public_key_fingerprint = "bb" * 32
            self.minimum_authority_epoch = 1
            self.receipt_id = receipt_id
            self.receipt = FakeReceipt(epoch=6, issued_at=issued_at)
            self.authority_policy = FakePolicy(network_id)

    monkeypatch.setattr(
        execution_module,
        "VerifiedAuthorityGrantV0",
        FakeVerified,
    )

    with open_ledger(str(tmp_path / "renewable-authority.sqlite3")) as ledger:
        runtime = ExecutionRuntime(ledger)
        first = FakeVerified(receipt_id="11" * 32, issued_at=100)
        assert runtime.record_verified_authority(first, accepted_at_epoch_s=110)

        successor = FakeVerified(receipt_id="22" * 32, issued_at=1_000)
        assert runtime.record_verified_authority(successor, accepted_at_epoch_s=1_010)
        assert not runtime.record_verified_authority(
            successor,
            accepted_at_epoch_s=1_011,
        )

        row = ledger.connection.execute(
            "SELECT * FROM authority_root_state WHERE trust_config_digest = ?",
            (first.trust_config_digest,),
        ).fetchone()
        assert row["highest_accepted_epoch"] == 6
        assert row["highest_accepted_receipt_id"] == successor.receipt_id
        assert row["highest_accepted_at_epoch_s"] == 1_010

        stale = FakeVerified(receipt_id="33" * 32, issued_at=1_000)
        with pytest.raises(
            AuthorityVerificationError,
            match="does not advance local continuity",
        ):
            runtime.record_verified_authority(stale, accepted_at_epoch_s=1_020)

        non_ink = FakeVerified(
            receipt_id="44" * 32,
            issued_at=2_000,
            network_id="evm:46630",
        )
        with pytest.raises(
            AuthorityVerificationError,
            match="different authority receipt at an accepted epoch",
        ):
            runtime.record_verified_authority(non_ink, accepted_at_epoch_s=2_010)

        with pytest.raises(sqlite3.IntegrityError, match="rollback"):
            ledger.connection.execute(
                "UPDATE authority_root_state SET highest_accepted_receipt_id = ? "
                "WHERE trust_config_digest = ?",
                ("55" * 32, first.trust_config_digest),
            )


def test_external_lifecycle_reconciles_once_and_replays(tmp_path: Path) -> None:
    ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    _observe(runtime, intent, reference, session, grant, _external_observation(reference, "provider-a"))
    _observe(runtime, intent, reference, session, grant, _external_observation(reference, "provider-b"))
    assert ledger.intent_state(intent.economic_action_id) is IntentState.CONFIRMED
    runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
        finality=FINALITY,
        receipt_id="receipt-external-1",
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RECONCILED
    runtime.complete_settlement(intent.economic_action_id, now_epoch_s=NOW)
    assert ledger.intent_state(intent.economic_action_id) is IntentState.FILLED
    assert ledger.connection.execute("SELECT COUNT(*) FROM signed_transactions").fetchone()[0] == 0
    assert ledger.connection.execute("SELECT COUNT(*) FROM execution_envelopes").fetchone()[0] == 0
    assert_execution_replay_equivalence(ledger)


def test_expired_grant_can_finish_safe_halted_bound_chain_truth(tmp_path: Path) -> None:
    ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    ledger.transition(
        intent.economic_action_id,
        IntentState.SAFE_HALT,
        now_epoch_s=NOW + 1,
        payload={"test": "crash_recovery_quarantine"},
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT
    assert ledger.held_atomic() == intent.bounds.max_input_atomic

    expired_at = grant.authority_policy.not_after_epoch_s
    recovery = verify_expired_authority_grant_for_recovery(
        receipt=grant.receipt,
        trusted_root=_root_for(grant.root_id),
        session=session,
        now_epoch_s=expired_at,
    )
    first = replace(
        _external_observation(reference, "provider-a"),
        observed_at_epoch_s=expired_at,
    )
    second = replace(
        _external_observation(reference, "provider-b"),
        observed_at_epoch_s=expired_at,
    )

    with pytest.raises((AuthorityCeilingError, AuthorityVerificationError)):
        runtime.record_chain_observation(
            first,
            external_action_id=intent.economic_action_id,
            external_transaction_ref_id=reference.external_transaction_ref_id,
            session=session,
            verified_grant=recovery,  # type: ignore[arg-type]
            now_epoch_s=expired_at,
            finality=FINALITY,
        )

    runtime.record_chain_observation(
        first,
        external_action_id=intent.economic_action_id,
        external_transaction_ref_id=reference.external_transaction_ref_id,
        session=session,
        verified_grant=recovery,
        now_epoch_s=expired_at,
        finality=FINALITY,
        expired_recovery=True,
    )
    runtime.record_chain_observation(
        second,
        external_action_id=intent.economic_action_id,
        external_transaction_ref_id=reference.external_transaction_ref_id,
        session=session,
        verified_grant=recovery,
        now_epoch_s=expired_at,
        finality=FINALITY,
        expired_recovery=True,
    )
    # Observation while halted records truth but never reopens execution.
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT

    truth = runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=recovery,
        now_epoch_s=expired_at,
        finality=FINALITY,
        receipt_id="receipt-expired-recovery",
        expired_recovery=True,
    )
    assert truth.verdict.value == "CONFIRMED"
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RECONCILED
    runtime.complete_settlement(intent.economic_action_id, now_epoch_s=expired_at)
    assert ledger.intent_state(intent.economic_action_id) is IntentState.FILLED
    assert_execution_replay_equivalence(ledger)


def test_expired_grant_can_release_safe_halt_after_confirmed_revert(tmp_path: Path) -> None:
    ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    ledger.transition(
        intent.economic_action_id,
        IntentState.SAFE_HALT,
        now_epoch_s=NOW + 1,
        payload={"test": "crash_recovery_quarantine"},
    )
    expired_at = grant.authority_policy.not_after_epoch_s
    recovery = verify_expired_authority_grant_for_recovery(
        receipt=grant.receipt,
        trusted_root=_root_for(grant.root_id),
        session=session,
        now_epoch_s=expired_at,
    )
    reverted = replace(
        _external_observation(
            reference,
            "provider-a",
            status=ReceiptStatus.REVERTED,
        ),
        observed_at_epoch_s=expired_at,
    )
    runtime.record_chain_observation(
        reverted,
        external_action_id=intent.economic_action_id,
        external_transaction_ref_id=reference.external_transaction_ref_id,
        session=session,
        verified_grant=recovery,
        now_epoch_s=expired_at,
        finality=REVERT_FINALITY,
        expired_recovery=True,
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT

    truth = runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=recovery,
        now_epoch_s=expired_at,
        finality=REVERT_FINALITY,
        expired_recovery=True,
    )
    assert truth.verdict.value == "REVERTED"
    assert ledger.intent_state(intent.economic_action_id) is IntentState.REJECTED
    assert ledger.held_atomic() == 0
    assert_execution_replay_equivalence(ledger)


def test_external_reference_has_one_origin_and_no_second_settlement(tmp_path: Path) -> None:
    ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    assert runtime.read_execution_state()["tables"]["external_transaction_refs"]
    assert _observe(runtime, intent, reference, session, grant, _external_observation(reference, "provider-a"))
    with pytest.raises((LedgerError, sqlite3.IntegrityError)) as error:
        runtime.record_external_transaction_reference(
            replace(reference, transaction_hash="0x" + "dd" * 32),
            session,
            grant,
            now_epoch_s=NOW,
        )
    assert "external" in str(error.value).lower() or "unique" in str(error.value).lower()
    _observe(runtime, intent, reference, session, grant, _external_observation(reference, "provider-b"))
    runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
        finality=FINALITY,
        receipt_id="receipt-external-2",
    )
    with pytest.raises(LedgerError, match="different execution facts"):
        runtime.reconcile_external_action(
            intent.economic_action_id,
            session=session,
            verified_grant=grant,
            now_epoch_s=NOW,
            finality=FINALITY,
            receipt_id="receipt-external-conflict",
        )


def test_ambiguous_external_truth_quarantines_without_retry(tmp_path: Path) -> None:
    ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    _observe(runtime, intent, reference, session, grant, _external_observation(reference, "provider-a"))
    _observe(
        runtime,
        intent,
        reference,
        session,
        grant,
        _external_observation(reference, "provider-b", block_hash="0x" + "ef" * 32),
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT
    assert ledger.held_atomic() == intent.bounds.max_input_atomic
    truth = runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
        finality=FINALITY,
    )
    assert truth.verdict.value == "AMBIGUOUS"
    assert ledger.connection.execute("SELECT COUNT(*) FROM fill_receipts").fetchone()[0] == 0


def test_confirmed_external_revert_rejects_and_releases(tmp_path: Path) -> None:
    ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    _observe(
        runtime,
        intent,
        reference,
        session,
        grant,
        _external_observation(reference, "provider-a", status=ReceiptStatus.REVERTED),
        finality=REVERT_FINALITY,
    )
    runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
        finality=REVERT_FINALITY,
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.REJECTED
    assert ledger.held_atomic() == 0
    assert_execution_replay_equivalence(ledger)


def test_kill_switch_blocks_reservation_but_allows_observation_and_reconciliation(tmp_path: Path) -> None:
    ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    runtime.engage_kill_switch(now_epoch_s=NOW, reason="operator stop")
    with pytest.raises(AuthorityCeilingError):
        runtime.reserve_action(
            intent.economic_action_id,
            session=session,
            verified_grant=grant,
            now_epoch_s=NOW,
        )
    _observe(runtime, intent, reference, session, grant, _external_observation(reference, "provider-a"))
    _observe(runtime, intent, reference, session, grant, _external_observation(reference, "provider-b"))
    runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW,
        finality=FINALITY,
        receipt_id="receipt-kill-switch",
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RECONCILED


def test_higher_level_paths_are_denied_at_level_one(tmp_path: Path) -> None:
    _ledger, runtime, _intent, _reference, session, grant = setup_runtime(tmp_path)
    with pytest.raises(AuthorityCeilingError):
        runtime.record_execution_envelope(object(), session, grant, object(), object(), object(), b"x", now_epoch_s=NOW)  # type: ignore[arg-type]
    with pytest.raises(AuthorityCeilingError):
        runtime.record_approval_action(object(), session, grant, object(), object(), now_epoch_s=NOW)  # type: ignore[arg-type]
    with pytest.raises(AuthorityCeilingError):
        runtime.record_signed_transaction_metadata(object(), b"x", frozen_at_epoch_s=NOW)  # type: ignore[arg-type]
    with pytest.raises(AuthorityCeilingError):
        runtime.record_submission_attempt(object())  # type: ignore[arg-type]


def test_direct_receipt_append_remains_database_bound(tmp_path: Path) -> None:
    ledger, _runtime, intent, reference, _session, _grant = setup_runtime(tmp_path)
    receipt = FillReceiptV0(
        receipt_id="direct-receipt",
        economic_action_id=intent.economic_action_id,
        external_ref=reference.transaction_hash,
        input_atomic_filled=intent.bounds.max_input_atomic,
        output_atomic_filled=intent.bounds.min_output_atomic,
        fee_atomic=0,
        observed_at_epoch_s=NOW,
        source="direct-caller",
    )
    with pytest.raises(LedgerError, match="ExecutionRuntime"):
        ledger.append_fill_receipt(receipt, now_epoch_s=NOW)


def test_observation_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    _ledger, runtime, intent, reference, session, grant = setup_runtime(tmp_path)
    with pytest.raises(ChainTruthError):
        _observe(
            runtime,
            intent,
            reference,
            session,
            grant,
            replace(_external_observation(reference, "provider-a"), transaction_hash="0x" + "ff" * 32),
        )
