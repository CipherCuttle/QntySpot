from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

import qntyspot
from qntyspot.domain import EconomicBounds, Side, ceil_div
from qntyspot.errors import (
    AuthorityVerificationError,
    EnvelopeValidationError,
    LevelNotExecutableError,
)
from qntyspot.execution_contract import (
    PHASE_GRANTED_AUTHORITY_LEVEL,
    AuthorityLevel,
    ExecutionSessionV0,
)
from qntyspot.ink import (
    INKYSWAP_V2_BYTECODE_SHA256,
    INKYSWAP_V2_FACTORY,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    V2_FEE_DENOMINATOR,
    V2_FEE_NUMERATOR,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    InkShadowAdapter,
)
from qntyspot.ink_v0f_execution import (
    APPROVE_SELECTOR,
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_ROUTER_ARTIFACT_DIGEST,
    INK_V0F_ROUTER_BYTECODE_SHA256,
    INK_V0F_TAKER_ADDRESS,
    SWAP_EXACT_TOKENS_SELECTOR,
    amount_out_min_atomic,
    build_ink_v0f_human_signing_preview,
    consume_ink_v0f_router_artifact,
    decode_approve,
    decode_swap_exact_tokens_for_tokens,
    encode_approve,
    encode_swap_exact_tokens_for_tokens,
)
from qntyspot.ink_v0f_risk import (
    INK_V0F_BASE_INSTRUMENT_ID,
    INK_V0F_QUOTE_INSTRUMENT_ID,
    consume_ink_v0f_risk_artifact,
)
from qntyspot.keccak import keccak256
from qntyspot.prelive_economics import PositionConcurrencySnapshotV0

ROOT = Path(__file__).resolve().parents[1]
ROUTER_ARTIFACT = ROOT / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json"
RISK_ARTIFACT = ROOT / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json"


def router():
    return consume_ink_v0f_router_artifact(ROUTER_ARTIFACT.read_bytes())


def risk():
    return consume_ink_v0f_risk_artifact(RISK_ARTIFACT.read_bytes())


def observation(*, reserve0: int = 10**21, reserve1: int = 10**21):
    return InkMarketObservationV0(
        schema="INK_MARKET_OBSERVATION_V0",
        chain_id=57_073,
        pool_address=INKYSWAP_V2_POOL,
        factory_address=INKYSWAP_V2_FACTORY,
        token0=KRAKMASK_ADDRESS,
        token1=WETH9_ADDRESS,
        common_block=123,
        provider_heads={"https://a.example": 123, "https://b.example": 123},
        bytecode_present=True,
        bytecode_sha256=INKYSWAP_V2_BYTECODE_SHA256,
        bytecode_length=1,
        reserve0_atomic=reserve0,
        reserve1_atomic=reserve1,
        reserve_timestamp=1,
        provider_evidence=({}, {}),
        v2_fee_numerator=V2_FEE_NUMERATOR,
        v2_fee_denominator=V2_FEE_DENOMINATOR,
    )


def session() -> ExecutionSessionV0:
    return ExecutionSessionV0(
        repository_commit="7b10a1a74607a9d2bf35438b89f02755b689d4ec",
        implementation_digest="0df376585a874e773d65b5dda0010a3d2eca28c541da474c6ca1cc60b3e929ec",
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id="11" * 32,
        authority_policy_digest="22" * 32,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id="evm:57073",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f-1",
        started_at_epoch_s=1_800_000_000,
        session_ordinal=0,
    )


def bounds(side: Side, input_atomic: int, min_output_atomic: int) -> EconomicBounds:
    if side is Side.BUY:
        input_id, output_id = INK_V0F_QUOTE_INSTRUMENT_ID, INK_V0F_BASE_INSTRUMENT_ID
    else:
        input_id, output_id = INK_V0F_BASE_INSTRUMENT_ID, INK_V0F_QUOTE_INSTRUMENT_ID
    return EconomicBounds(
        side=side,
        input_instrument_id=input_id,
        output_instrument_id=output_id,
        max_input_atomic=input_atomic,
        min_output_atomic=min_output_atomic,
        limit_price=Fraction(1),
        max_price_impact_bps=100,
        max_slippage_bps=50,
        deadline_epoch_s=1_800_000_600,
    )


def preview(side: Side):
    obs = observation()
    input_atomic = 10**15 if side is Side.BUY else 5 * 10**14
    quote = InkShadowAdapter._quote(obs, side, input_atomic)
    b = bounds(side, input_atomic, max(1, quote.output_atomic * 99 // 100))
    kwargs = dict(
        policy=risk(),
        router=router(),
        observation=obs,
        quote=quote,
        bounds=b,
        session=session(),
        economic_action_id="33" * 32,
        account_nonce=7,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=1_800_000_001,
    )
    if side is Side.BUY:
        kwargs.update(
            cumulative_entry_atomic_after=input_atomic,
            concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
        )
    else:
        kwargs.update(settled_inventory_base_atomic=10**15)
    return build_ink_v0f_human_signing_preview(**kwargs)


def test_router_artifact_is_exact_and_content_addressed() -> None:
    identity = router()
    assert identity.address == INK_V0F_ROUTER_ADDRESS
    assert identity.deployed_bytecode_sha256 == INK_V0F_ROUTER_BYTECODE_SHA256
    assert INK_V0F_ROUTER_ARTIFACT_DIGEST == (
        "985d10917c17058c1a564af9ce0f3c8118ce794d4dbdb12946b0390fad6bad0c"
    )
    sidecar = ROUTER_ARTIFACT.with_suffix(".sha256")
    assert sidecar.read_text(encoding="ascii") == (
        f"{INK_V0F_ROUTER_ARTIFACT_DIGEST}  {ROUTER_ARTIFACT.name}\n"
    )


def test_any_router_artifact_byte_change_fails_closed() -> None:
    with pytest.raises(AuthorityVerificationError, match="digest mismatch"):
        consume_ink_v0f_router_artifact(ROUTER_ARTIFACT.read_bytes() + b" ")


def test_function_selectors_are_derived_from_keccak() -> None:
    assert APPROVE_SELECTOR == bytes.fromhex("095ea7b3")
    assert SWAP_EXACT_TOKENS_SELECTOR == bytes.fromhex("38ed1739")
    assert APPROVE_SELECTOR == keccak256(b"approve(address,uint256)")[:4]
    assert SWAP_EXACT_TOKENS_SELECTOR == keccak256(
        b"swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"
    )[:4]


def test_approval_codec_is_exact_amount_and_router_only() -> None:
    data = encode_approve(INK_V0F_ROUTER_ADDRESS, 123)
    assert len(data) == 68
    assert decode_approve(data) == (INK_V0F_ROUTER_ADDRESS, 123)
    hostile = bytearray(data)
    hostile[0] ^= 1
    with pytest.raises(EnvelopeValidationError, match="selector"):
        decode_approve(bytes(hostile))


def test_swap_codec_roundtrips_only_canonical_two_token_path() -> None:
    data = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=123,
        amount_out_min_atomic=100,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=1_800_000_600,
    )
    assert len(data) == 260
    assert decode_swap_exact_tokens_for_tokens(data) == (
        123,
        100,
        (WETH9_ADDRESS, KRAKMASK_ADDRESS),
        INK_V0F_TAKER_ADDRESS,
        1_800_000_600,
    )
    hostile = bytearray(data)
    hostile[4 + 64 + 31] = 0x80
    with pytest.raises(EnvelopeValidationError, match="offset"):
        decode_swap_exact_tokens_for_tokens(bytes(hostile))


def test_entry_preview_binds_weth_to_krakmask_and_exact_approval() -> None:
    result = preview(Side.BUY)
    assert result.swap.path == (WETH9_ADDRESS, KRAKMASK_ADDRESS)
    assert result.approval.token_address == WETH9_ADDRESS
    assert result.approval.spender_address == INK_V0F_ROUTER_ADDRESS
    assert result.approval.amount_atomic == result.swap.amount_in_atomic == 10**15
    assert result.swap.recipient == INK_V0F_TAKER_ADDRESS
    assert result.signed_bytes_scope.target_address == INK_V0F_ROUTER_ADDRESS
    assert result.signed_bytes_scope.min_value_atomic == 0
    assert result.signed_bytes_scope.max_value_atomic == 0
    fields = result.eip1559_signing_fields()
    assert fields["chainId"] == 57_073
    assert fields["nonce"] == 7
    assert fields["to"] == INK_V0F_ROUTER_ADDRESS
    assert fields["value"] == 0
    assert fields["data"] == "0x" + result.swap.calldata.hex()


def test_minimum_output_is_never_weaker_than_policy_or_fifty_bps() -> None:
    obs = observation()
    q = InkShadowAdapter._quote(obs, Side.BUY, 10**15)
    b = bounds(Side.BUY, 10**15, q.output_atomic - 1)
    minimum = amount_out_min_atomic(risk(), bounds=b, quote=q)
    policy_floor = b.min_output_atomic
    slippage_floor = ceil_div(q.output_atomic * 9_950, 10_000)
    assert minimum == max(policy_floor, slippage_floor)
    assert minimum >= slippage_floor


def test_exit_preview_is_inventory_bound_and_reverses_path() -> None:
    result = preview(Side.SELL)
    assert result.swap.path == (KRAKMASK_ADDRESS, WETH9_ADDRESS)
    assert result.approval.token_address == KRAKMASK_ADDRESS
    assert result.approval.amount_atomic == result.swap.amount_in_atomic
    assert result.swap.recipient == INK_V0F_TAKER_ADDRESS


def test_exit_cannot_exceed_settled_inventory() -> None:
    obs = observation()
    q = InkShadowAdapter._quote(obs, Side.SELL, 5 * 10**14)
    with pytest.raises(LevelNotExecutableError, match="settled base inventory"):
        build_ink_v0f_human_signing_preview(
            policy=risk(),
            router=router(),
            observation=obs,
            quote=q,
            bounds=bounds(Side.SELL, 5 * 10**14, max(1, q.output_atomic * 99 // 100)),
            session=session(),
            economic_action_id="33" * 32,
            account_nonce=7,
            gas_limit_ceiling=250_000,
            max_fee_per_gas_ceiling=2_000_000_000,
            max_priority_fee_per_gas_ceiling=100_000_000,
            constructed_at_epoch_s=1_800_000_001,
            settled_inventory_base_atomic=5 * 10**14 - 1,
        )


def test_forged_exit_quote_is_rejected_by_reserve_recomputation() -> None:
    obs = observation()
    q = InkShadowAdapter._quote(obs, Side.SELL, 5 * 10**14)
    forged = replace(q, output_atomic=q.output_atomic + 1)
    with pytest.raises(LevelNotExecutableError, match="canonical reserve-derived"):
        build_ink_v0f_human_signing_preview(
            policy=risk(),
            router=router(),
            observation=obs,
            quote=forged,
            bounds=bounds(Side.SELL, 5 * 10**14, max(1, q.output_atomic * 99 // 100)),
            session=session(),
            economic_action_id="33" * 32,
            account_nonce=7,
            gas_limit_ceiling=250_000,
            max_fee_per_gas_ceiling=2_000_000_000,
            max_priority_fee_per_gas_ceiling=100_000_000,
            constructed_at_epoch_s=1_800_000_001,
            settled_inventory_base_atomic=10**15,
        )


def test_preview_phase_cannot_authorize_submission_or_live_capital() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.RECONCILE_ONLY
    assert qntyspot.AUTHORITY == "INK_V0F_RECONCILE_ONLY"
    assert qntyspot.SIGNING_AUTHORIZED is False
    assert qntyspot.LIVE_CAPITAL_AUTHORIZED is False
