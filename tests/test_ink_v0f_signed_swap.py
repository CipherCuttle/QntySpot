from __future__ import annotations

from fractions import Fraction
import inspect

import pytest
import rlp
from eth_keys import keys

import qntyspot.ink_v0f_human_signing as human
import qntyspot.ink_v0f_signed_swap as signed_swap_mod
from qntyspot.canon import sha256_hex
from qntyspot.domain import EconomicBounds, IntentV0, LadderKind, Side
from qntyspot.errors import AuthorityVerificationError, EnvelopeValidationError, SafeHaltError
from qntyspot.execution_contract import (
    AuthorityLevel,
    Capability,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    LADDER,
    PHASE_GRANTED_AUTHORITY_LEVEL,
)
from qntyspot.exact_signed_bytes import ExactSignedBytesScopeV0
from qntyspot.ink import INK_CHAIN_ID, KRAKMASK_ADDRESS, WETH9_ADDRESS
from qntyspot.ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    encode_swap_exact_tokens_for_tokens,
)
from qntyspot.ink_v0f_human_signing import (
    InkV0FSameAmountRevalidationV0,
    InkV0FSwapSigningRequestV0,
)
from qntyspot.ink_v0f_signed_swap import (
    InkV0FSignedSwapAdmissionV0,
    run_ink_v0f_zero_money_rehearsal,
    validate_ink_v0f_signed_swap,
)
from qntyspot.keccak import keccak256


ACTION_ID = "11" * 32
POLICY_ID = "22" * 32
AUTHORITY_ID = "33" * 32
DEADLINE = 1_800_000_600


def _int_bytes(value: int) -> bytes:
    return b"" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")


def _sign_type2(fields: dict[str, object], key: keys.PrivateKey) -> bytes:
    unsigned = [
        _int_bytes(int(fields["chainId"])),
        _int_bytes(int(fields["nonce"])),
        _int_bytes(int(fields["maxPriorityFeePerGas"])),
        _int_bytes(int(fields["maxFeePerGas"])),
        _int_bytes(int(fields["gas"])),
        bytes.fromhex(str(fields["to"])[2:]),
        _int_bytes(int(fields["value"])),
        bytes.fromhex(str(fields["data"])[2:]),
        [],
    ]
    message_hash = keccak256(b"\x02" + rlp.encode(unsigned))
    signature = key.sign_msg_hash(message_hash)
    signed = unsigned + [
        _int_bytes(signature.v),
        _int_bytes(signature.r),
        _int_bytes(signature.s),
    ]
    return b"\x02" + rlp.encode(signed)


def _session(*, taker: str) -> ExecutionSessionV0:
    return ExecutionSessionV0(
        repository_commit="44" * 20,
        implementation_digest="55" * 32,
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id=POLICY_ID,
        authority_policy_digest=AUTHORITY_ID,
        taker_address=taker,
        network_id=f"evm:{INK_CHAIN_ID}",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=1_800_000_000,
        session_ordinal=0,
    )


def _intent() -> IntentV0:
    return IntentV0(
        economic_action_id=ACTION_ID,
        policy_id=POLICY_ID,
        instrument_id="KRAKMASK",
        quote_instrument_id="WETH",
        network_id=f"evm:{INK_CHAIN_ID}",
        cycle_id="cycle-1",
        level_id="level-1",
        side=Side.BUY,
        kind=LadderKind.ENTRY,
        bounds=EconomicBounds(
            side=Side.BUY,
            input_instrument_id="WETH",
            output_instrument_id="KRAKMASK",
            max_input_atomic=1_000,
            min_output_atomic=900,
            limit_price=Fraction(1, 1),
            max_price_impact_bps=100,
            max_slippage_bps=50,
            deadline_epoch_s=DEADLINE,
        ),
        quote_exposure_atomic=1_000,
    )


def _fixture(*, taker: str):
    sess = _session(taker=taker)
    calldata = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=1_000,
        amount_out_min_atomic=900,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=taker,
        deadline_epoch_s=DEADLINE,
    )
    envelope = ExecutionEnvelopeV0(
        session_id=sess.session_id,
        session_identity_digest=sess.identity_digest,
        economic_action_id=ACTION_ID,
        chain_id=INK_CHAIN_ID,
        taker_address=taker,
        input_instrument_id="WETH",
        output_instrument_id="KRAKMASK",
        max_input_atomic=1_000,
        min_output_atomic=900,
        transaction_to=INK_V0F_ROUTER_ADDRESS,
        transaction_value_atomic=0,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        allowance_target=INK_V0F_ROUTER_ADDRESS,
        account_nonce=8,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling_atomic=2_000_000_000,
        max_priority_fee_per_gas_ceiling_atomic=100_000_000,
        deadline_epoch_s=DEADLINE,
        authority_policy_digest=sess.authority_policy_digest,
        plan_id="66" * 32,
        quote_id="ink-v0f-v2",
        quote_observation_digest="77" * 32,
        venue_block_number=100,
        constructed_at_epoch_s=1_800_000_001,
    )
    scope = ExactSignedBytesScopeV0(
        session_id=sess.session_id,
        session_identity_digest=sess.identity_digest,
        economic_action_id=ACTION_ID,
        authority_policy_digest=sess.authority_policy_digest,
        chain_id=INK_CHAIN_ID,
        taker_address=taker,
        target_address=INK_V0F_ROUTER_ADDRESS,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        account_nonce=8,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
    )
    request = InkV0FSwapSigningRequestV0(scope=scope, calldata=calldata)
    revalidation = InkV0FSameAmountRevalidationV0(
        swap_request=request,
        market_observation_digest="81" * 32,
        router_observation_digest="82" * 32,
        allowance_observation_digest="83" * 32,
        signer_state_digest="84" * 32,
        fresh_quote_output_atomic=1_000,
        fresh_required_min_output_atomic=900,
        common_block=200,
        revalidated_at_epoch_s=1_800_000_050,
        _token=human._REVALIDATION_TOKEN,
    )
    return sess, envelope, revalidation


def test_source_ceiling_is_level_three_without_internal_signature_authority() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert Capability.SUBMIT_EXACT_BYTES in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.CONSTRUCT_ENVELOPE in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.AUTHORIZE_APPROVAL in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.PRODUCE_SIGNATURE not in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]


def test_direct_revalidation_construction_is_rejected(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    _, _, revalidation = _fixture(taker=taker)
    with pytest.raises(SafeHaltError, match="live revalidator"):
        InkV0FSameAmountRevalidationV0(
            swap_request=revalidation.swap_request,
            market_observation_digest=revalidation.market_observation_digest,
            router_observation_digest=revalidation.router_observation_digest,
            allowance_observation_digest=revalidation.allowance_observation_digest,
            signer_state_digest=revalidation.signer_state_digest,
            fresh_quote_output_atomic=revalidation.fresh_quote_output_atomic,
            fresh_required_min_output_atomic=revalidation.fresh_required_min_output_atomic,
            common_block=revalidation.common_block,
            revalidated_at_epoch_s=revalidation.revalidated_at_epoch_s,
        )


def test_exact_external_swap_bytes_are_admitted_without_reencoding(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(signed_swap_mod, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    sess, envelope, revalidation = _fixture(taker=taker)

    raw = _sign_type2(revalidation.swap_request.eip1559_signing_fields(), key)
    admission = validate_ink_v0f_signed_swap(
        revalidation,
        envelope,
        raw,
        admitted_at_epoch_s=1_800_000_100,
    )

    assert admission.signed_bytes == raw
    assert admission.validated.parsed.sender_address == taker
    assert admission.validated.parsed.target_address == INK_V0F_ROUTER_ADDRESS
    assert admission.validated.parsed.calldata == revalidation.swap_request.calldata
    assert admission.validated.scope.economic_action_id == ACTION_ID
    assert admission.revalidation.revalidation_id == revalidation.revalidation_id
    assert envelope.calldata_sha256 == sha256_hex(admission.validated.parsed.calldata)
    assert sess.identity_digest == admission.validated.scope.session_identity_digest


def test_mutated_signed_swap_bytes_fail_closed(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(signed_swap_mod, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    _, envelope, revalidation = _fixture(taker=taker)

    raw = bytearray(_sign_type2(revalidation.swap_request.eip1559_signing_fields(), key))
    raw[-1] ^= 1
    with pytest.raises(EnvelopeValidationError):
        validate_ink_v0f_signed_swap(
            revalidation,
            envelope,
            bytes(raw),
            admitted_at_epoch_s=1_800_000_100,
        )


def test_signed_swap_admission_rejects_direct_caller_construction(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(signed_swap_mod, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    _, envelope, revalidation = _fixture(taker=taker)
    raw = _sign_type2(revalidation.swap_request.eip1559_signing_fields(), key)
    admitted = validate_ink_v0f_signed_swap(
        revalidation,
        envelope,
        raw,
        admitted_at_epoch_s=1_800_000_100,
    )

    with pytest.raises(EnvelopeValidationError, match="exact-byte validation"):
        InkV0FSignedSwapAdmissionV0(
            revalidation=revalidation,
            envelope=envelope,
            admitted_at_epoch_s=1_800_000_100,
            signed_bytes=raw,
            validated=admitted.validated,
        )


def test_signed_swap_rejects_stale_revalidation_and_envelope_drift(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(signed_swap_mod, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    sess, envelope, revalidation = _fixture(taker=taker)
    raw = _sign_type2(revalidation.swap_request.eip1559_signing_fields(), key)

    with pytest.raises(SafeHaltError, match="too old"):
        validate_ink_v0f_signed_swap(
            revalidation,
            envelope,
            raw,
            admitted_at_epoch_s=1_800_000_171,
        )

    drifted = ExecutionEnvelopeV0(
        session_id=envelope.session_id,
        session_identity_digest=envelope.session_identity_digest,
        economic_action_id=envelope.economic_action_id,
        chain_id=envelope.chain_id,
        taker_address=envelope.taker_address,
        input_instrument_id=envelope.input_instrument_id,
        output_instrument_id=envelope.output_instrument_id,
        max_input_atomic=envelope.max_input_atomic,
        min_output_atomic=envelope.min_output_atomic,
        transaction_to=envelope.transaction_to,
        transaction_value_atomic=envelope.transaction_value_atomic,
        calldata_sha256=envelope.calldata_sha256,
        calldata_length=envelope.calldata_length,
        allowance_target=envelope.allowance_target,
        account_nonce=envelope.account_nonce + 1,
        gas_limit_ceiling=envelope.gas_limit_ceiling,
        max_fee_per_gas_ceiling_atomic=envelope.max_fee_per_gas_ceiling_atomic,
        max_priority_fee_per_gas_ceiling_atomic=envelope.max_priority_fee_per_gas_ceiling_atomic,
        deadline_epoch_s=envelope.deadline_epoch_s,
        authority_policy_digest=envelope.authority_policy_digest,
        plan_id=envelope.plan_id,
        quote_id=envelope.quote_id,
        quote_observation_digest=envelope.quote_observation_digest,
        venue_block_number=envelope.venue_block_number,
        constructed_at_epoch_s=envelope.constructed_at_epoch_s,
    )
    with pytest.raises(EnvelopeValidationError, match="frozen envelope"):
        validate_ink_v0f_signed_swap(
            revalidation,
            drifted,
            raw,
            admitted_at_epoch_s=1_800_000_100,
        )
    assert sess.identity_digest == envelope.session_identity_digest


def test_zero_money_rehearsal_has_no_transport_or_chain_truth_escape(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(signed_swap_mod, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    sess, envelope, revalidation = _fixture(taker=taker)
    raw = _sign_type2(revalidation.swap_request.eip1559_signing_fields(), key)
    admission = validate_ink_v0f_signed_swap(
        revalidation,
        envelope,
        raw,
        admitted_at_epoch_s=1_800_000_100,
    )

    transcript = run_ink_v0f_zero_money_rehearsal(
        session=sess,
        intent=_intent(),
        envelope=envelope,
        signed_swap=admission,
        rehearsed_at_epoch_s=1_800_000_100,
    )

    assert transcript.source_authority_level is AuthorityLevel.HUMAN_SIGNED_EXECUTION
    assert transcript.mock_submission.transport_invoked is False
    assert transcript.mock_submission.external_effect is False
    assert transcript.reconciliation.persistable_as_chain_truth is False
    assert transcript.reconciliation.external_effect is False
    assert transcript.reconciliation.simulated_result == "SIMULATED_CONFIRMED_NO_CHAIN_EFFECT"
    assert transcript.signed_swap_admission_id == admission.admission_id
    assert transcript.revalidation_id == revalidation.revalidation_id
    assert transcript.rehearsal_id

    params = inspect.signature(run_ink_v0f_zero_money_rehearsal).parameters
    assert "transport" not in params
    assert "provider" not in params


def test_rehearsal_rejects_cross_action_scope(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(signed_swap_mod, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    sess, envelope, revalidation = _fixture(taker=taker)
    raw = _sign_type2(revalidation.swap_request.eip1559_signing_fields(), key)
    admission = validate_ink_v0f_signed_swap(
        revalidation,
        envelope,
        raw,
        admitted_at_epoch_s=1_800_000_100,
    )

    wrong_intent = IntentV0(
        economic_action_id="99" * 32,
        policy_id=POLICY_ID,
        instrument_id="KRAKMASK",
        quote_instrument_id="WETH",
        network_id=f"evm:{INK_CHAIN_ID}",
        cycle_id="cycle-1",
        level_id="level-1",
        side=Side.BUY,
        kind=LadderKind.ENTRY,
        bounds=_intent().bounds,
        quote_exposure_atomic=1_000,
    )
    with pytest.raises(EnvelopeValidationError, match="different economic actions"):
        run_ink_v0f_zero_money_rehearsal(
            session=sess,
            intent=wrong_intent,
            envelope=envelope,
            signed_swap=admission,
            rehearsed_at_epoch_s=1_800_000_100,
        )


def test_rehearsal_output_records_cannot_be_caller_minted(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(signed_swap_mod, "INK_V0F_TAKER_ADDRESS", taker)
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    sess, envelope, revalidation = _fixture(taker=taker)
    raw = _sign_type2(revalidation.swap_request.eip1559_signing_fields(), key)
    admission = validate_ink_v0f_signed_swap(
        revalidation,
        envelope,
        raw,
        admitted_at_epoch_s=1_800_000_100,
    )
    transcript = run_ink_v0f_zero_money_rehearsal(
        session=sess,
        intent=_intent(),
        envelope=envelope,
        signed_swap=admission,
        rehearsed_at_epoch_s=1_800_000_100,
    )

    with pytest.raises(EnvelopeValidationError, match="rehearsal runner"):
        signed_swap_mod.InkV0FMockSubmissionV0(
            signed_swap_admission_id=admission.admission_id,
            transaction_hash=admission.transaction_hash,
            signed_bytes_sha256=admission.validated.signed_bytes_sha256,
            rehearsed_at_epoch_s=1_800_000_100,
        )

    with pytest.raises(EnvelopeValidationError, match="rehearsal runner"):
        signed_swap_mod.InkV0FRehearsalReconciliationV0(
            mock_submission_id=transcript.reconciliation.mock_submission_id,
            economic_action_id=ACTION_ID,
            simulated_result="SIMULATED_CONFIRMED_NO_CHAIN_EFFECT",
        )
