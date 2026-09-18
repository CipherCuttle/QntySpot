from __future__ import annotations

from fractions import Fraction
from types import SimpleNamespace

import pytest
import rlp
from eth_keys import keys

import qntyspot.ink_v0f_human_signing as human
from qntyspot.canon import sha256_hex
from qntyspot.domain import EconomicBounds, IntentV0, LadderKind, Side
from qntyspot.errors import EnvelopeValidationError, SafeHaltError
from qntyspot.execution_contract import (
    ApprovalActionV0,
    AuthorityLevel,
    ChainPresence,
    ChainTruthVerdict,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    FinalityPolicyV0,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    ReceiptStatus,
)
from qntyspot.exact_signed_bytes import ParsedExactSignedBytesV0, ValidatedExactSignedBytesV0
from qntyspot.ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    INKYSWAP_V2_FACTORY,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    V2_FEE_DENOMINATOR,
    V2_FEE_NUMERATOR,
    WETH9_ADDRESS,
    InkMarketObservationV0,
)
from qntyspot.ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    encode_swap_exact_tokens_for_tokens,
)
from qntyspot.ink_v0f_human_signing import (
    InkV0FApprovalChainObservationV0,
    InkV0FApprovalKind,
    InkV0FApprovalSettlementState,
    InkV0FApprovalSettlementV0,
    InkV0FSignerStateObservationV0,
    build_ink_v0f_approval_signing_request,
    build_ink_v0f_revoke_signing_request,
    evaluate_ink_v0f_approval_truth,
    reconcile_ink_v0f_approval,
    revalidate_ink_v0f_same_amount,
    validate_ink_v0f_signed_approval,
)
from qntyspot.ink_v0f_preauth import InkV0FAllowanceObservationV0
from qntyspot.keccak import keccak256


ACTION_ID = "11" * 32
POLICY_ID = "22" * 32
AUTHORITY_ID = "33" * 32
DEADLINE = 1_800_000_600


def session(*, taker: str = INK_V0F_TAKER_ADDRESS) -> ExecutionSessionV0:
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


def approval_and_envelope(*, amount: int = 1_000, min_output: int = 900):
    sess = session()
    calldata = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=amount,
        amount_out_min_atomic=min_output,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=sess.taker_address,
        deadline_epoch_s=DEADLINE,
    )
    approval = ApprovalActionV0(
        session_id=sess.session_id,
        session_identity_digest=sess.identity_digest,
        taker_address=sess.taker_address,
        token_address=WETH9_ADDRESS,
        spender_address=INK_V0F_ROUTER_ADDRESS,
        requested_allowance_atomic=amount,
        observed_prior_allowance_atomic=0,
        authority_policy_digest=sess.authority_policy_digest,
        deadline_epoch_s=DEADLINE,
        economic_action_id=ACTION_ID,
    )
    envelope = ExecutionEnvelopeV0(
        session_id=sess.session_id,
        session_identity_digest=sess.identity_digest,
        economic_action_id=ACTION_ID,
        chain_id=INK_CHAIN_ID,
        taker_address=sess.taker_address,
        input_instrument_id="WETH",
        output_instrument_id="KRAKMASK",
        max_input_atomic=amount,
        min_output_atomic=min_output,
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
    return sess, approval, envelope


def test_source_ceiling_stays_reconcile_only() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.RECONCILE_ONLY


def test_approval_nonce_must_immediately_precede_frozen_swap_nonce() -> None:
    sess, approval, envelope = approval_and_envelope()
    request = build_ink_v0f_approval_signing_request(
        approval=approval,
        envelope=envelope,
        session=sess,
        approval_nonce=7,
        gas_limit_ceiling=80_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=1_800_000_010,
    )
    fields = request.eip1559_signing_fields()
    assert fields["nonce"] == 7
    assert fields["to"] == WETH9_ADDRESS
    assert request.allowance_atomic == envelope.max_input_atomic

    with pytest.raises(EnvelopeValidationError, match="exactly one after"):
        build_ink_v0f_approval_signing_request(
            approval=approval,
            envelope=envelope,
            session=sess,
            approval_nonce=6,
            gas_limit_ceiling=80_000,
            max_fee_per_gas_ceiling=2_000_000_000,
            max_priority_fee_per_gas_ceiling=100_000_000,
            constructed_at_epoch_s=1_800_000_010,
        )


def test_revoke_is_exact_zero_allowance_to_same_router() -> None:
    sess, approval, _ = approval_and_envelope()
    request = build_ink_v0f_revoke_signing_request(
        approval=approval,
        session=sess,
        revoke_nonce=9,
        gas_limit_ceiling=80_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=1_800_000_020,
    )
    fields = request.eip1559_signing_fields()
    calldata = bytes.fromhex(fields["data"][2:])
    assert request.kind is InkV0FApprovalKind.REVOKE_TO_ZERO
    assert request.allowance_atomic == 0
    assert fields["to"] == approval.token_address
    assert calldata[-32:] == b"\x00" * 32


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


def test_externally_signed_approval_bytes_are_recovered_and_exact(monkeypatch) -> None:
    key = keys.PrivateKey(bytes.fromhex("01" * 32))
    taker = "0x" + keccak256(key.public_key.to_bytes())[-20:].hex()
    monkeypatch.setattr(human, "INK_V0F_TAKER_ADDRESS", taker)
    sess = session(taker=taker)
    calldata = human.encode_approve(INK_V0F_ROUTER_ADDRESS, 123)
    scope = human._approval_scope(
        session=sess,
        action_id="88" * 32,
        token_address=WETH9_ADDRESS,
        calldata=calldata,
        account_nonce=3,
        gas_limit_ceiling=80_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
    )
    request = human.InkV0FApprovalSigningRequestV0(
        kind=InkV0FApprovalKind.EXACT_APPROVAL,
        approval_action_id="88" * 32,
        economic_action_id=ACTION_ID,
        token_address=WETH9_ADDRESS,
        spender_address=INK_V0F_ROUTER_ADDRESS,
        allowance_atomic=123,
        scope=scope,
        constructed_at_epoch_s=1,
    )
    raw = _sign_type2(request.eip1559_signing_fields(), key)
    admitted = validate_ink_v0f_signed_approval(request, raw)
    assert admitted.validated.parsed.sender_address == taker
    assert admitted.validated.parsed.target_address == WETH9_ADDRESS

    bad = bytearray(raw)
    bad[-1] ^= 1
    with pytest.raises(EnvelopeValidationError):
        validate_ink_v0f_signed_approval(request, bytes(bad))


def _signed_stub(request):
    parsed = ParsedExactSignedBytesV0(
        transaction_type="eip-1559",
        chain_id=INK_CHAIN_ID,
        account_nonce=request.scope.account_nonce or 0,
        gas_limit=50_000,
        max_fee_per_gas=1,
        max_priority_fee_per_gas=1,
        target_address=request.token_address,
        value_atomic=0,
        calldata=b"",
        sender_address=request.scope.taker_address,
        transaction_hash="0x" + "aa" * 32,
    )
    validated = ValidatedExactSignedBytesV0(
        scope=request.scope,
        parsed=parsed,
        signed_bytes_sha256="bb" * 32,
        signed_bytes_length=100,
    )
    return human.InkV0FSignedApprovalV0(request=request, validated=validated)


def _approval_observation(provider_id: str, *, status=ReceiptStatus.SUCCESS, block=100, head=103):
    return InkV0FApprovalChainObservationV0(
        provider_id=provider_id,
        transaction_hash="0x" + "aa" * 32,
        observed_at_epoch_s=1_800_000_100,
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=("01" if provider_id == "ink-rpc-a" else "02") * 32,
        block_number=block,
        block_hash="0x" + "cc" * 32,
        block_parent_hash="0x" + "dd" * 32,
        head_block_number=head,
        head_block_hash="0x" + "ee" * 32,
        receipt_status=status,
    )


def test_two_provider_approval_truth_confirms_without_fake_swap_amounts() -> None:
    sess, approval, envelope = approval_and_envelope()
    request = build_ink_v0f_approval_signing_request(
        approval=approval,
        envelope=envelope,
        session=sess,
        approval_nonce=7,
        gas_limit_ceiling=80_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=1,
    )
    truth = evaluate_ink_v0f_approval_truth(
        _signed_stub(request),
        (_approval_observation("ink-rpc-a"), _approval_observation("ink-rpc-b")),
        FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=2),
        submission_acknowledged=True,
    )
    assert truth.verdict is ChainTruthVerdict.CONFIRMED
    assert truth.agreeing_provider_count == 2
    assert truth.confirmation_depth == 3


def test_provider_disagreement_on_approval_is_ambiguous() -> None:
    sess, approval, envelope = approval_and_envelope()
    request = build_ink_v0f_approval_signing_request(
        approval=approval,
        envelope=envelope,
        session=sess,
        approval_nonce=7,
        gas_limit_ceiling=80_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=1,
    )
    truth = evaluate_ink_v0f_approval_truth(
        _signed_stub(request),
        (
            _approval_observation("ink-rpc-a"),
            _approval_observation("ink-rpc-b", status=ReceiptStatus.REVERTED),
        ),
        FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=2),
        submission_acknowledged=True,
    )
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS


def _allowance(amount: int, *, block: int = 103) -> InkV0FAllowanceObservationV0:
    return InkV0FAllowanceObservationV0(
        token_address=WETH9_ADDRESS,
        owner_address=INK_V0F_TAKER_ADDRESS,
        spender_address=INK_V0F_ROUTER_ADDRESS,
        allowance_atomic=amount,
        common_block=block,
        provider_heads={INK_RPC_ENDPOINTS[0]: block + 1, INK_RPC_ENDPOINTS[1]: block + 2},
        provider_evidence=({}, {}),
    )


def test_settlement_requires_exact_post_approval_allowance() -> None:
    sess, approval, envelope = approval_and_envelope()
    request = build_ink_v0f_approval_signing_request(
        approval=approval,
        envelope=envelope,
        session=sess,
        approval_nonce=7,
        gas_limit_ceiling=80_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=1,
    )
    signed = _signed_stub(request)
    truth = evaluate_ink_v0f_approval_truth(
        signed,
        (_approval_observation("ink-rpc-a"), _approval_observation("ink-rpc-b")),
        FinalityPolicyV0(min_confirmation_depth=2, min_agreeing_providers=2),
        submission_acknowledged=True,
    )
    settled = reconcile_ink_v0f_approval(request, signed, truth, _allowance(1_000))
    assert settled.state is InkV0FApprovalSettlementState.SETTLED
    assert settled.requires_revoke is False

    mismatch = reconcile_ink_v0f_approval(request, signed, truth, _allowance(999))
    assert mismatch.state is InkV0FApprovalSettlementState.SAFE_HALT
    assert mismatch.requires_revoke is True


def _market() -> InkMarketObservationV0:
    return InkMarketObservationV0(
        schema="INK_MARKET_OBSERVATION_V0",
        chain_id=INK_CHAIN_ID,
        pool_address=INKYSWAP_V2_POOL,
        factory_address=INKYSWAP_V2_FACTORY,
        token0=KRAKMASK_ADDRESS,
        token1=WETH9_ADDRESS,
        common_block=200,
        provider_heads={INK_RPC_ENDPOINTS[0]: 201, INK_RPC_ENDPOINTS[1]: 202},
        bytecode_present=True,
        bytecode_sha256="99" * 32,
        bytecode_length=1,
        reserve0_atomic=10**12,
        reserve1_atomic=10**12,
        reserve_timestamp=1,
        provider_evidence=({}, {}),
        v2_fee_numerator=V2_FEE_NUMERATOR,
        v2_fee_denominator=V2_FEE_DENOMINATOR,
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


def test_same_amount_revalidation_returns_frozen_swap_or_stops(monkeypatch) -> None:
    sess, approval, envelope = approval_and_envelope()
    settlement = InkV0FApprovalSettlementV0(
        state=InkV0FApprovalSettlementState.SETTLED,
        request_id="aa" * 32,
        transaction_hash="0x" + "ab" * 32,
        expected_allowance_atomic=1_000,
        observed_allowance_atomic=1_000,
        allowance_observation_digest="ac" * 32,
        chain_truth_evidence_digest="ad" * 32,
        requires_revoke=False,
    )
    live = object.__new__(human.InkV0FLiveVerifier)
    market = _market()
    monkeypatch.setattr(human.InkV0FLiveVerifier, "observe_market", lambda self: market)
    monkeypatch.setattr(
        human.InkV0FLiveVerifier,
        "observe_router_for_market",
        lambda self, observation: SimpleNamespace(
            router_address=INK_V0F_ROUTER_ADDRESS,
            digest="ba" * 32,
        ),
    )
    monkeypatch.setattr(
        human.InkV0FLiveVerifier,
        "observe_allowance_for_market",
        lambda self, observation, token_address: _allowance(1_000, block=200),
    )
    monkeypatch.setattr(
        human,
        "observe_ink_v0f_signer_state_for_market",
        lambda verifier, observation: InkV0FSignerStateObservationV0(
            common_block=200,
            account_nonce=8,
            base_fee_per_gas=1,
            block_hash="0x" + "bc" * 32,
            provider_evidence=({}, {}),
        ),
    )
    monkeypatch.setattr(
        human.InkShadowAdapter,
        "_quote",
        staticmethod(
            lambda observation, side, amount: SimpleNamespace(
                input_atomic=amount,
                output_atomic=1_000,
            )
        ),
    )
    monkeypatch.setattr(
        human,
        "build_ink_v0f_human_signing_preview",
        lambda **kwargs: SimpleNamespace(
            swap=SimpleNamespace(amount_in_atomic=envelope.max_input_atomic)
        ),
    )
    monkeypatch.setattr(human, "amount_out_min_atomic", lambda *args, **kwargs: 900)

    result = revalidate_ink_v0f_same_amount(
        live_verifier=live,
        risk_policy=SimpleNamespace(),
        router_identity=SimpleNamespace(address=INK_V0F_ROUTER_ADDRESS),
        ledger=SimpleNamespace(),
        intent=_intent(),
        session=sess,
        approval=approval,
        envelope=envelope,
        approval_settlement=settlement,
        now_epoch_s=1_800_000_100,
    )
    assert result.swap_request.scope.account_nonce == envelope.account_nonce
    assert sha256_hex(result.swap_request.calldata) == envelope.calldata_sha256

    monkeypatch.setattr(human, "amount_out_min_atomic", lambda *args, **kwargs: 901)
    with pytest.raises(SafeHaltError, match="looser"):
        revalidate_ink_v0f_same_amount(
            live_verifier=live,
            risk_policy=SimpleNamespace(),
            router_identity=SimpleNamespace(address=INK_V0F_ROUTER_ADDRESS),
            ledger=SimpleNamespace(),
            intent=_intent(),
            session=sess,
            approval=approval,
            envelope=envelope,
            approval_settlement=settlement,
            now_epoch_s=1_800_000_100,
        )
