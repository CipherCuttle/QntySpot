"""Focused B1 runtime tests; all bytes and chain facts are synthetic."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import INK_CHAIN_ID, NOW, base_policy_doc, drive
from execution_support import (
    ALLOWANCE_TARGET,
    CHAIN_ID,
    MAX_INPUT,
    MIN_OUTPUT,
    TAKER,
)
from qntyspot.canon import digest_object, sha256_hex
from qntyspot.domain import Side
from qntyspot.economics import build_intent
from qntyspot.errors import (
    AuthorityCeilingError,
    ChainTruthError,
    EnvelopeValidationError,
    LedgerError,
    SafeHaltError,
    StateTransitionError,
)
from qntyspot.execution_contract import (
    AuthorityLevel,
    ChainObservationV0,
    ChainPresence,
    FinalityPolicyV0,
    ReceiptStatus,
    SignedTransactionRecordV0,
    SubmissionAcknowledgment,
    SubmissionAttemptV0,
    VenueQuoteResponseV0,
    ZeroXExecutionExpectationV0,
    derive_transaction_hash,
    decode_allowance_holder_calldata,
)
from qntyspot.keccak import keccak256_hex
from qntyspot.ledger import (
    B1_O04_EXTERNAL_ROOT_BLOCKED,
    ExecutionRuntime,
    assert_execution_replay_equivalence,
    open_ledger,
)
from qntyspot.ledger.execution import ExternalAuthorityProofV0, verify_external_authority_proof
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

RUNTIME_CHAIN_ID = INK_CHAIN_ID

SETTLER = "0x00000000000000000000000000000000000000ee"
POOL = "0x00000000000000000000000000000000000000ef"
RAW_EVIDENCE = "77" * 32
FINALITY = FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=2)


def _word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _address(value: str) -> bytes:
    return bytes.fromhex(value[2:]).rjust(32, b"\0")


def allowance_holder_calldata(*, sell_token: str, buy_token: str, sell_amount: int, min_output: int, taker: str) -> bytes:
    """Encode the exact nested form accepted by the bounded decoder."""
    basic = bytes.fromhex(keccak256_hex(b"BASIC(address,uint256,address,uint256,bytes)")[:8])
    basic_args = (
        _address(sell_token)
        + _word(1_000_000)
        + _address(POOL)
        + _word(160)
        + _word(160)
        + _word(0)
    )
    action_value = basic + basic_args
    action = _word(len(action_value)) + action_value + b"\0" * ((-len(action_value)) % 32)
    actions = _word(1) + _word(64) + action
    settler_selector = bytes.fromhex(
        keccak256_hex(b"execute((address,address,uint256),bytes[],bytes32)")[:8]
    )
    settler = (
        settler_selector
        + _address(taker)
        + _address(buy_token)
        + _word(min_output)
        + _word(160)
        + _word(0)
        + actions
    )
    exec_selector = bytes.fromhex(
        keccak256_hex(b"exec(address,address,uint256,address,bytes)")[:8]
    )
    outer_args = (
        _address(SETTLER)
        + _address(sell_token)
        + _word(sell_amount)
        + _address(SETTLER)
        + _word(160)
    )
    return exec_selector + outer_args + _word(len(settler)) + settler + b"\0" * ((-len(settler)) % 32)


def setup_runtime(tmp_path: Path):
    policy = parse_policy(base_policy_doc())
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
    from qntyspot.execution_contract import AuthorityPolicyRefV0, ExecutionSessionV0

    grant = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.SHADOW,
        permitted_repository_commit="a890de49e68486476b2385f70ef9c9558896f5b7",
        permitted_implementation_digest="11" * 32,
        permitted_network_id=policy.network_id,
        permitted_taker_address=TAKER,
        permitted_venue_id="zero-x-allowance-holder",
        max_reservation_atomic=intent.bounds.max_input_atomic,
        max_cumulative_atomic=intent.bounds.max_input_atomic * 4,
        not_before_epoch_s=NOW - 3600,
        not_after_epoch_s=NOW + 3600,
    )
    active_session = ExecutionSessionV0(
        repository_commit=grant.permitted_repository_commit,
        implementation_digest=grant.permitted_implementation_digest,
        runtime_identity="cpython-3.14",
        db_schema_version=1,
        policy_id=policy.policy_id,
        authority_policy_digest=grant.authority_policy_digest,
        taker_address=TAKER,
        network_id=policy.network_id,
        venue_id=grant.permitted_venue_id,
        venue_adapter_version="v0",
        started_at_epoch_s=NOW - 60,
    )
    runtime = ExecutionRuntime(ledger)
    runtime.create_execution_session(active_session, grant)
    return ledger, runtime, policy, intent, grant, active_session


def build_envelope(active_session, grant, intent, calldata, response):
    from qntyspot.execution_contract import ExecutionEnvelopeV0

    return ExecutionEnvelopeV0(
        session_id=active_session.session_id,
        session_identity_digest=active_session.identity_digest,
        economic_action_id=intent.economic_action_id,
        chain_id=RUNTIME_CHAIN_ID,
        taker_address=TAKER,
        input_instrument_id=intent.bounds.input_instrument_id,
        output_instrument_id=intent.bounds.output_instrument_id,
        max_input_atomic=intent.bounds.max_input_atomic,
        min_output_atomic=intent.bounds.min_output_atomic,
        transaction_to=response.transaction_to,
        transaction_value_atomic=0,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        allowance_target=response.allowance_target,
        account_nonce=7,
        gas_limit_ceiling=400_000,
        max_fee_per_gas_ceiling_atomic=2_000_000_000,
        max_priority_fee_per_gas_ceiling_atomic=1_000_000,
        deadline_epoch_s=intent.bounds.deadline_epoch_s,
        authority_policy_digest=grant.authority_policy_digest,
        plan_id=digest_object({"plan": intent.economic_action_id}),
        quote_id="quote-0001",
        quote_observation_digest="44" * 32,
        venue_block_number=1_000_000,
        constructed_at_epoch_s=NOW - 5,
    )


def build_response(intent, calldata):
    return VenueQuoteResponseV0(
        chain_id=RUNTIME_CHAIN_ID,
        taker_address=TAKER,
        sell_token=intent.bounds.input_instrument_id.split(":")[-1],
        buy_token=intent.bounds.output_instrument_id.split(":")[-1],
        sell_amount_atomic=intent.bounds.max_input_atomic,
        buy_amount_atomic=intent.bounds.min_output_atomic + 10,
        min_buy_amount_atomic=intent.bounds.min_output_atomic,
        allowance_target=ALLOWANCE_TARGET,
        transaction_to=ALLOWANCE_TARGET,
        transaction_value_atomic=0,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        block_number=1_000_000,
        quote_mode="exact_in",
        quoted_at_epoch_s=NOW - 5,
        liquidity_available=True,
        simulation_incomplete=False,
    )


def prepare_submitted(tmp_path: Path):
    ledger, runtime, policy, intent, grant, active_session = setup_runtime(tmp_path)
    calldata = allowance_holder_calldata(
        sell_token=intent.bounds.input_instrument_id.split(":")[-1],
        buy_token=intent.bounds.output_instrument_id.split(":")[-1],
        sell_amount=intent.bounds.max_input_atomic,
        min_output=intent.bounds.min_output_atomic,
        taker=TAKER,
    )
    response = build_response(intent, calldata)
    runtime.reserve_action(intent.economic_action_id, now_epoch_s=NOW)
    envelope = build_envelope(active_session, grant, intent, calldata, response)
    runtime.record_execution_envelope(
        envelope,
        active_session,
        grant,
        intent.bounds,
        __import__("qntyspot.execution_contract", fromlist=["ZeroXExecutionExpectationV0"]).ZeroXExecutionExpectationV0(
            chain_id=RUNTIME_CHAIN_ID,
            taker_address=TAKER,
            sell_token=response.sell_token,
            buy_token=response.buy_token,
            sell_amount_atomic=response.sell_amount_atomic,
            min_output_atomic=response.min_buy_amount_atomic,
            max_quote_age_s=30,
        ),
        response,
        calldata,
        now_epoch_s=NOW,
    )
    raw = b"synthetic-signed-transaction"
    record = SignedTransactionRecordV0(
        envelope_id=envelope.envelope_id,
        raw_signed_sha256=hashlib.sha256(raw).hexdigest(),
        raw_signed_length=len(raw),
        transaction_hash=derive_transaction_hash(raw),
            chain_id=RUNTIME_CHAIN_ID,
        account_nonce=7,
        taker_address=TAKER,
        signer_identity="external-human-controlled-account",
    )
    runtime.record_signed_transaction_metadata(record, raw, frozen_at_epoch_s=NOW)
    attempt = SubmissionAttemptV0(
        signed_transaction_id=record.signed_transaction_id,
        provider_id="provider-a",
        attempt_ordinal=0,
        submitted_at_epoch_s=NOW,
        acknowledgment=SubmissionAcknowledgment.ACCEPTED,
        provider_reported_hash=record.transaction_hash,
    )
    runtime.record_submission_attempt(attempt)
    return ledger, runtime, intent, record, envelope, response


def observation(
    record,
    provider,
    *,
    status=ReceiptStatus.SUCCESS,
    observed=NOW,
    input_amount=MAX_INPUT,
    output_amount=MIN_OUTPUT,
):
    return ChainObservationV0(
        provider_id=provider,
        transaction_hash=record.transaction_hash,
        observed_at_epoch_s=observed,
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=RAW_EVIDENCE,
        block_number=7,
        block_hash="0x" + "ab" * 32,
        block_parent_hash="0x" + "ac" * 32,
        head_block_number=9,
        head_block_hash="0x" + "ad" * 32,
        receipt_status=status,
        effective_input_atomic=input_amount if status is ReceiptStatus.SUCCESS else None,
        effective_output_atomic=output_amount if status is ReceiptStatus.SUCCESS else None,
    )


def test_calldata_decoder_binds_nested_economic_fields() -> None:
    data = allowance_holder_calldata(
        sell_token="0x00000000000000000000000000000000000000bb",
        buy_token="0x00000000000000000000000000000000000000cc",
        sell_amount=MAX_INPUT,
        min_output=MIN_OUTPUT,
        taker=TAKER,
    )
    decoded = decode_allowance_holder_calldata(
        data,
        expected_entry_point=ALLOWANCE_TARGET,
        expected_allowance_target=ALLOWANCE_TARGET,
        expected_sell_token="0x00000000000000000000000000000000000000bb",
        expected_buy_token="0x00000000000000000000000000000000000000cc",
        expected_sell_amount_atomic=MAX_INPUT,
        expected_taker_address=TAKER,
        expected_min_output_atomic=MIN_OUTPUT,
    )
    assert decoded.sell_amount_atomic == MAX_INPUT
    assert decoded.min_output_atomic == MIN_OUTPUT
    assert decoded.settler_target == SETTLER


def test_calldata_decoder_keeps_allowance_holder_distinct_from_settler() -> None:
    data = allowance_holder_calldata(
        sell_token="0x00000000000000000000000000000000000000bb",
        buy_token="0x00000000000000000000000000000000000000cc",
        sell_amount=MAX_INPUT,
        min_output=MIN_OUTPUT,
        taker=TAKER,
    )
    with pytest.raises(EnvelopeValidationError, match="distinct"):
        decode_allowance_holder_calldata(
            data,
            expected_entry_point=SETTLER,
            expected_allowance_target=SETTLER,
        )


def test_calldata_mutation_fails_even_if_api_values_are_unchanged() -> None:
    data = bytearray(
        allowance_holder_calldata(
            sell_token="0x00000000000000000000000000000000000000bb",
            buy_token="0x00000000000000000000000000000000000000cc",
            sell_amount=MAX_INPUT,
            min_output=MIN_OUTPUT,
            taker=TAKER,
        )
    )
    # Inner AllowedSlippage.minAmountOut: outer dynamic offset 160, inner
    # selector + recipient + buyToken + minAmountOut.
    inner_start = 4 + 160 + 32
    data[inner_start + 4 + 64 : inner_start + 4 + 96] = _word(MIN_OUTPUT - 1)
    with pytest.raises(EnvelopeValidationError):
        decode_allowance_holder_calldata(bytes(data), expected_min_output_atomic=MIN_OUTPUT)


def test_keccak_is_not_standard_sha3() -> None:
    assert derive_transaction_hash(b"abc") == "0x" + "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    assert derive_transaction_hash(b"abc") != "0x" + hashlib.sha3_256(b"abc").hexdigest()


def test_runtime_full_offline_lifecycle_and_replay(tmp_path: Path) -> None:
    ledger, runtime, intent, record, _envelope, _response = prepare_submitted(tmp_path)
    runtime.record_chain_observation(
        observation(
            record,
            "provider-a",
            input_amount=intent.bounds.max_input_atomic,
            output_amount=intent.bounds.min_output_atomic,
        ),
        external_action_id=intent.economic_action_id,
        signed_transaction_id=record.signed_transaction_id,
        finality=FINALITY,
    )
    runtime.record_chain_observation(
        observation(
            record,
            "provider-b",
            input_amount=intent.bounds.max_input_atomic,
            output_amount=intent.bounds.min_output_atomic,
        ),
        external_action_id=intent.economic_action_id,
        signed_transaction_id=record.signed_transaction_id,
        finality=FINALITY,
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.CONFIRMED
    runtime.reconcile_external_action(
        intent.economic_action_id,
        now_epoch_s=NOW,
        finality=FINALITY,
        receipt_id="receipt-runtime-1",
        fee_atomic=0,
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RECONCILED
    runtime.reconcile_external_action(
        intent.economic_action_id,
        now_epoch_s=NOW + 1,
        finality=FINALITY,
        receipt_id="receipt-runtime-1",
        fee_atomic=0,
    )
    with pytest.raises(LedgerError, match="different execution facts"):
        runtime.reconcile_external_action(
            intent.economic_action_id,
            now_epoch_s=NOW,
            finality=FINALITY,
            receipt_id="receipt-runtime-conflict",
            fee_atomic=0,
        )
    runtime.complete_settlement(intent.economic_action_id, now_epoch_s=NOW)
    assert ledger.intent_state(intent.economic_action_id) is IntentState.FILLED
    assert_execution_replay_equivalence(ledger)


def test_runtime_uses_persisted_bounds_not_caller_supplied_bounds(tmp_path: Path) -> None:
    ledger, runtime, _policy, intent, grant, session = setup_runtime(tmp_path)
    runtime.reserve_action(intent.economic_action_id, now_epoch_s=NOW)
    calldata = allowance_holder_calldata(
        sell_token=intent.bounds.input_instrument_id.split(":")[-1],
        buy_token=intent.bounds.output_instrument_id.split(":")[-1],
        sell_amount=intent.bounds.max_input_atomic,
        min_output=1,
        taker=TAKER,
    )
    response = replace(
        build_response(intent, calldata),
        buy_amount_atomic=2,
        min_buy_amount_atomic=1,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
    )
    envelope = replace(build_envelope(session, grant, intent, calldata, response), min_output_atomic=1)
    with pytest.raises(EnvelopeValidationError, match="persisted intent bounds"):
        runtime.record_execution_envelope(
            envelope,
            session,
            grant,
            replace(intent.bounds, min_output_atomic=1),
            ZeroXExecutionExpectationV0(
                chain_id=RUNTIME_CHAIN_ID,
                taker_address=TAKER,
                sell_token=response.sell_token,
                buy_token=response.buy_token,
                sell_amount_atomic=response.sell_amount_atomic,
                min_output_atomic=response.min_buy_amount_atomic,
                max_quote_age_s=30,
            ),
            response,
            calldata,
            now_epoch_s=NOW,
        )


def test_authority_root_and_policy_ceiling_are_not_caller_selected(tmp_path: Path) -> None:
    ledger, runtime, _policy, _intent, grant, session = setup_runtime(tmp_path)
    with pytest.raises(AuthorityCeilingError, match="frozen shadow authority-root"):
        runtime.create_execution_session(
            replace(session, authority_policy_digest=replace(grant, authority_root_id="attacker").authority_policy_digest),
            replace(grant, authority_root_id="attacker"),
        )
    with pytest.raises(AuthorityCeilingError, match="per-order cap"):
        runtime.create_execution_session(
            replace(
                session,
                authority_policy_digest=replace(
                    grant, max_reservation_atomic=10**30, max_cumulative_atomic=10**31
                ).authority_policy_digest,
                session_ordinal=2,
            ),
            replace(grant, max_reservation_atomic=10**30, max_cumulative_atomic=10**31),
        )


def test_reconciled_and_filled_require_settlement_facts(tmp_path: Path) -> None:
    ledger, runtime, intent, _record, _envelope, _response = prepare_submitted(tmp_path)
    ledger.transition(intent.economic_action_id, IntentState.INCLUDED, now_epoch_s=NOW)
    ledger.transition(intent.economic_action_id, IntentState.CONFIRMED, now_epoch_s=NOW)
    with pytest.raises(LedgerError, match="SETTLED reconciliation"):
        ledger.transition(intent.economic_action_id, IntentState.RECONCILED, now_epoch_s=NOW)


def test_post_submission_rejection_never_releases_without_bound_revert(tmp_path: Path) -> None:
    ledger, runtime, intent, record, _envelope, _response = prepare_submitted(tmp_path)
    with pytest.raises(LedgerError, match="REVERTED reconciliation"):
        ledger.transition(intent.economic_action_id, IntentState.REJECTED, now_epoch_s=NOW)
    assert ledger.held_atomic() == intent.bounds.max_input_atomic
    runtime.record_chain_observation(
        observation(record, "provider-a", status=ReceiptStatus.REVERTED),
        external_action_id=intent.economic_action_id,
        signed_transaction_id=record.signed_transaction_id,
        finality=FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=1),
    )
    runtime.reconcile_external_action(
        intent.economic_action_id,
        now_epoch_s=NOW,
        finality=FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=1),
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.REJECTED
    assert ledger.held_atomic() == 0
    assert_execution_replay_equivalence(ledger)


def test_accepted_then_absent_quarantines_and_keeps_capital(tmp_path: Path) -> None:
    ledger, runtime, intent, record, _envelope, _response = prepare_submitted(tmp_path)
    absent = ChainObservationV0(
        provider_id="provider-a",
        transaction_hash=record.transaction_hash,
        observed_at_epoch_s=NOW + 1,
        presence=ChainPresence.ABSENT,
        raw_evidence_sha256=RAW_EVIDENCE,
    )
    runtime.record_chain_observation(
        absent,
        external_action_id=intent.economic_action_id,
        signed_transaction_id=record.signed_transaction_id,
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT
    assert ledger.held_atomic() == intent.bounds.max_input_atomic
    with pytest.raises(StateTransitionError):
        ledger.transition(intent.economic_action_id, IntentState.REJECTED, now_epoch_s=NOW)


def test_conflicting_provider_evidence_is_persisted_as_safe_halt(tmp_path: Path) -> None:
    ledger, runtime, intent, record, _envelope, _response = prepare_submitted(tmp_path)
    first = observation(
        record,
        "provider-a",
        input_amount=intent.bounds.max_input_atomic,
        output_amount=intent.bounds.min_output_atomic,
    )
    second = replace(
        observation(
            record,
            "provider-b",
            input_amount=intent.bounds.max_input_atomic,
            output_amount=intent.bounds.min_output_atomic,
        ),
        block_hash="0x" + "ff" * 32,
    )
    runtime.record_chain_observation(
        first,
        external_action_id=intent.economic_action_id,
        signed_transaction_id=record.signed_transaction_id,
        finality=FINALITY,
    )
    runtime.record_chain_observation(
        second,
        external_action_id=intent.economic_action_id,
        signed_transaction_id=record.signed_transaction_id,
        finality=FINALITY,
    )
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SAFE_HALT
    runtime.reconcile_external_action(
        intent.economic_action_id,
        now_epoch_s=NOW,
        finality=FINALITY,
    )
    row = ledger.connection.execute(
        "SELECT verdict FROM reconciliations WHERE external_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()
    assert row["verdict"] == "AMBIGUOUS"
    assert_execution_replay_equivalence(ledger)


def test_kill_switch_blocks_new_effects_but_allows_observation(tmp_path: Path) -> None:
    ledger, runtime, intent, record, _envelope, _response = prepare_submitted(tmp_path)
    runtime.engage_kill_switch(now_epoch_s=NOW, reason="operator stop")
    assert runtime.read_execution_state()["kill_switch_engaged"] is True
    with pytest.raises(SafeHaltError):
        runtime.reserve_action(intent.economic_action_id, now_epoch_s=NOW)
    duplicate = observation(
        record,
        "provider-a",
        input_amount=intent.bounds.max_input_atomic,
        output_amount=intent.bounds.min_output_atomic,
    )
    assert runtime.record_chain_observation(
        duplicate,
        external_action_id=intent.economic_action_id,
        signed_transaction_id=record.signed_transaction_id,
    ) is True


def test_provider_hash_mismatch_and_authority_root_spoof_fail_closed(tmp_path: Path) -> None:
    _ledger, runtime, _intent, record, _envelope, _response = prepare_submitted(tmp_path)
    bad = replace(
        SubmissionAttemptV0(
            signed_transaction_id=record.signed_transaction_id,
            provider_id="provider-b",
            attempt_ordinal=0,
            submitted_at_epoch_s=NOW,
            acknowledgment=SubmissionAcknowledgment.ACCEPTED,
            provider_reported_hash="0x" + "ff" * 32,
        ),
    )
    with pytest.raises(ChainTruthError):
        runtime.record_submission_attempt(bad)
    assert B1_O04_EXTERNAL_ROOT_BLOCKED is True
    with pytest.raises(AuthorityCeilingError, match="independently rooted"):
        verify_external_authority_proof(
            object(), object(), repository_commit="x", implementation_digest="y"  # type: ignore[arg-type]
        )


def test_crash_injector_before_commit_rolls_back_after_commit_persists(tmp_path: Path) -> None:
    points: list[str] = []

    def fail(point: str) -> None:
        points.append(point)
        if point == "reservation:before_commit":
            raise RuntimeError("crash")

    ledger, runtime, _policy, intent, _grant, _session = setup_runtime(tmp_path)
    runtime._failure_injector = fail  # noqa: SLF001 - boundary test
    with pytest.raises(RuntimeError):
        runtime.reserve_action(intent.economic_action_id, now_epoch_s=NOW)
    assert ledger.intent_state(intent.economic_action_id) is IntentState.SIMULATED
    assert ledger.held_atomic() == 0
    runtime._failure_injector = None  # noqa: SLF001 - boundary test
    runtime.reserve_action(intent.economic_action_id, now_epoch_s=NOW)
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RESERVED
    assert points == ["reservation:before_commit"]


def test_after_commit_failure_leaves_the_committed_fact_durable(tmp_path: Path) -> None:
    points: list[str] = []

    def fail(point: str) -> None:
        points.append(point)
        if point == "reservation:after_commit":
            raise RuntimeError("post-commit crash")

    ledger, runtime, _policy, intent, _grant, _session = setup_runtime(tmp_path)
    runtime._failure_injector = fail  # noqa: SLF001 - boundary test
    with pytest.raises(RuntimeError, match="post-commit crash"):
        runtime.reserve_action(intent.economic_action_id, now_epoch_s=NOW)
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RESERVED
    assert ledger.held_atomic() == intent.bounds.max_input_atomic
    assert points == ["reservation:before_commit", "reservation:after_commit"]


def test_sqlite_race_on_same_envelope_is_exactly_once(tmp_path: Path) -> None:
    ledger, _runtime, intent, _record, envelope, response = prepare_submitted(tmp_path)
    calldata = allowance_holder_calldata(
        sell_token=response.sell_token,
        buy_token=response.buy_token,
        sell_amount=response.sell_amount_atomic,
        min_output=response.min_buy_amount_atomic,
        taker=TAKER,
    )
    from qntyspot.execution_contract import AuthorityPolicyRefV0, ExecutionSessionV0, ZeroXExecutionExpectationV0

    session_row = ledger.connection.execute(
        "SELECT * FROM execution_sessions ORDER BY session_id LIMIT 1"
    ).fetchone()
    session = ExecutionSessionV0(
        repository_commit=session_row["repository_commit"],
        implementation_digest=session_row["implementation_digest"],
        runtime_identity=session_row["runtime_identity"],
        db_schema_version=session_row["db_schema_version"],
        policy_id=session_row["policy_id"],
        authority_policy_digest=session_row["authority_policy_digest"],
        taker_address=session_row["taker_address"],
        network_id=session_row["network_id"],
        venue_id=session_row["venue_id"],
        venue_adapter_version=session_row["venue_adapter_version"],
        started_at_epoch_s=session_row["started_at_epoch_s"],
        session_ordinal=session_row["session_ordinal"],
    )
    authority = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.SHADOW,
        permitted_repository_commit=session.repository_commit,
        permitted_implementation_digest=session.implementation_digest,
        permitted_network_id=session.network_id,
        permitted_taker_address=session.taker_address,
        permitted_venue_id=session.venue_id,
        max_reservation_atomic=intent.bounds.max_input_atomic,
        max_cumulative_atomic=intent.bounds.max_input_atomic * 4,
        not_before_epoch_s=NOW - 3600,
        not_after_epoch_s=NOW + 3600,
    )
    expectation = ZeroXExecutionExpectationV0(
        chain_id=RUNTIME_CHAIN_ID,
        taker_address=TAKER,
        sell_token=response.sell_token,
        buy_token=response.buy_token,
        sell_amount_atomic=response.sell_amount_atomic,
        min_output_atomic=response.min_buy_amount_atomic,
        max_quote_age_s=30,
    )
    results: list[object] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        try:
            with open_ledger(str(tmp_path / "runtime.sqlite3")) as other_ledger:
                other_runtime = ExecutionRuntime(other_ledger)
                other_runtime.create_execution_session(session, authority)
                barrier.wait(timeout=5)
                results.append(
                    other_runtime.record_execution_envelope(
                        envelope,
                        session,
                        authority,
                        intent.bounds,
                        expectation,
                        response,
                        calldata,
                        now_epoch_s=NOW,
                    )
                )
        except BaseException as exc:  # make worker failures assertion-visible
            results.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert len(results) == 2
    assert all(result is False for result in results), results
    assert ledger.connection.execute("SELECT COUNT(*) FROM execution_envelopes").fetchone()[0] == 1
