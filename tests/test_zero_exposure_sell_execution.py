from __future__ import annotations

from dataclasses import replace

from conftest import NOW, base_policy_doc, drive
from qntyspot.canon import sha256_hex
from qntyspot.economics import build_intent
from qntyspot.execution_contract import (
    AuthorityLevel,
    ChainObservationV0,
    ChainPresence,
    FinalityPolicyV0,
    ReceiptStatus,
)
from qntyspot.exact_signed_bytes import ExactSignedBytesScopeV0
from qntyspot.ledger import (
    ExecutionRuntime,
    assert_execution_replay_equivalence,
    open_ledger,
)
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

from test_execution_schema import envelope_row, insert
from test_external_authority_root import _receipt, _root_for, _session
from test_submit_exact_signed_bytes_v0 import RAW, TAKER, TARGET

TX_HASH = "0x7508482061b00d5775609a79956af4b58b07a969aa030ac99c3444c7573e129b"
FINALITY = FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=2)


class TransportSpy:
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def submit_exact_signed_bytes(self, signed_bytes: bytes) -> str:
        self.calls.append(bytes(signed_bytes))
        return TX_HASH


def _surface(tmp_path):
    policy = parse_policy(base_policy_doc())
    ledger = open_ledger(str(tmp_path / "zero-exposure-sell.sqlite3"))
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(
        policy,
        cycle_id,
        policy.level("X1"),
        now_epoch_s=NOW,
        inventory_atomic=2_000_000,
    )
    assert intent.quote_exposure_atomic == 0
    ledger.create_intent(intent, now_epoch_s=NOW)
    drive(
        ledger,
        intent.economic_action_id,
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
    )

    receipt = _receipt(AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER)
    session = replace(
        _session(receipt),
        policy_id=policy.policy_id,
        db_schema_version=5,
    )
    assert session.chain_id == 46_630
    assert session.taker_address == TAKER
    from qntyspot.authority_root import verify_authority_grant

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
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RESERVED
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0] == 0

    scope = ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=intent.economic_action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=session.chain_id,
        taker_address=session.taker_address,
        target_address=TARGET,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=sha256_hex(b""),
        calldata_length=0,
        account_nonce=0,
        gas_limit_ceiling=21_000,
        max_fee_per_gas_ceiling=2,
        max_priority_fee_per_gas_ceiling=1,
    )
    insert(
        ledger.connection,
        "execution_envelopes",
        **envelope_row(
            intent,
            session_id=session.session_id,
            session_identity_digest=session.identity_digest,
            economic_action_id=intent.economic_action_id,
            chain_id=session.chain_id,
            taker_address=session.taker_address,
            transaction_to=scope.target_address,
            transaction_value_atomic="0",
            calldata_sha256=scope.calldata_sha256,
            calldata_length=scope.calldata_length,
            account_nonce=scope.account_nonce,
            gas_limit_ceiling=scope.gas_limit_ceiling,
            max_fee_per_gas_ceiling_atomic=str(scope.max_fee_per_gas_ceiling),
            max_priority_fee_per_gas_ceiling_atomic=str(
                scope.max_priority_fee_per_gas_ceiling
            ),
            authority_policy_digest=session.authority_policy_digest,
            lifecycle="AUTHORIZED",
        ),
    )
    admission = runtime.admit_exact_signed_bytes(
        scope,
        RAW,
        session,
        grant,
        frozen_at_epoch_s=NOW,
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SIGNED
    return ledger, runtime, intent, session, grant, admission


def _included(
    transaction_hash: str,
    provider_id: str,
    intent,
    *,
    status: ReceiptStatus = ReceiptStatus.SUCCESS,
) -> ChainObservationV0:
    return ChainObservationV0(
        provider_id=provider_id,
        transaction_hash=transaction_hash,
        observed_at_epoch_s=NOW + 2,
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=("11" if provider_id == "provider-a" else "22") * 32,
        block_number=7,
        block_hash="0x" + "33" * 32,
        block_parent_hash="0x" + "44" * 32,
        head_block_number=9,
        head_block_hash="0x" + "55" * 32,
        receipt_status=status,
        effective_input_atomic=(
            intent.bounds.max_input_atomic
            if status is ReceiptStatus.SUCCESS
            else None
        ),
        effective_output_atomic=(
            intent.bounds.min_output_atomic
            if status is ReceiptStatus.SUCCESS
            else None
        ),
    )


def test_zero_exposure_sell_submits_without_budget_reservation(tmp_path) -> None:
    ledger, runtime, intent, session, grant, admission = _surface(tmp_path)
    spy = TransportSpy()

    attempt = runtime.submit_exact_signed_bytes(
        admission,
        spy,
        session,
        grant,
        provider_id="spy",
        submitted_at_epoch_s=NOW + 1,
    )

    assert spy.calls == [RAW]
    assert attempt.acknowledgment.value == "ACCEPTED"
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SUBMITTED
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0] == 0


def test_zero_exposure_sell_safe_halt_terminal_truth_recovers_and_replays(
    tmp_path,
) -> None:
    ledger, runtime, intent, session, grant, admission = _surface(tmp_path)
    spy = TransportSpy()
    runtime.submit_exact_signed_bytes(
        admission,
        spy,
        session,
        grant,
        provider_id="spy",
        submitted_at_epoch_s=NOW + 1,
    )
    ledger.transition(
        intent.economic_action_id,
        IntentState.SAFE_HALT,
        now_epoch_s=NOW + 1,
        payload={"test": "post-submit-ambiguity"},
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0] == 0

    signed_id = admission.record.signed_transaction_id
    for provider_id in ("provider-a", "provider-b"):
        runtime.record_chain_observation(
            _included(admission.record.transaction_hash, provider_id, intent),
            external_action_id=intent.economic_action_id,
            signed_transaction_id=signed_id,
            session=session,
            verified_grant=grant,
            now_epoch_s=NOW + 2,
            finality=FINALITY,
        )

    truth = runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=grant,
        now_epoch_s=NOW + 2,
        finality=FINALITY,
        receipt_id="zero-exposure-sell-fill",
    )
    assert truth.verdict.value == "CONFIRMED"
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RECONCILED

    runtime.complete_settlement(intent.economic_action_id, now_epoch_s=NOW + 2)
    assert ledger.intent_state(intent.economic_action_id) is IntentState.FILLED
    assert ledger.connection.execute(
        "SELECT COUNT(*) FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0] == 0
    assert_execution_replay_equivalence(ledger)
