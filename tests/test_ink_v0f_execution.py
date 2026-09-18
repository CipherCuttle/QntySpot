from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

import qntyspot
from qntyspot.domain import FillReceiptV0, Side, ceil_div
from qntyspot.economics import build_intent
from qntyspot.errors import (
    AuthorityVerificationError,
    EnvelopeValidationError,
    LevelNotExecutableError,
    LedgerError,
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
from qntyspot.ink_v0f_risk import consume_ink_v0f_risk_artifact
from qntyspot.keccak import keccak256
from qntyspot.ledger import open_ledger
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

ROOT = Path(__file__).resolve().parents[1]
ROUTER_ARTIFACT = ROOT / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json"
RISK_ARTIFACT = ROOT / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json"
NOW = 1_800_000_000


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


def policy_doc():
    return {
        "schema": "qntyspot.policy.v0",
        "policy_name": "ink-v0f-preview",
        "side": "BUY",
        "base": {
            "ref": {
                "namespace": "evm",
                "chain_id": 57_073,
                "contract_address": KRAKMASK_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "KRAKMASK",
        },
        "quote": {
            "ref": {
                "namespace": "evm",
                "chain_id": 57_073,
                "contract_address": WETH9_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "WETH",
        },
        "entry_ladder": {
            "levels": [{"level_id": "E1", "trigger_price": "1", "input_amount": "0.001"}]
        },
        "exit_ladder": {
            "levels": [{"level_id": "X1", "trigger_price": "1", "input_ratio": "1"}]
        },
        "capital": {
            "allocation_quote": "0.001",
            "per_order_cap_quote": "0.001",
            "per_instrument_cap_quote": "0.001",
            "per_network_cap_quote": "0.001",
            "global_portfolio_cap_quote": "0.001",
            "reserved_cash_quote": "0",
        },
        "limits": {
            "max_executable_price": "1.005",
            "min_executable_price": "0.995",
            "max_price_impact_bps": 100,
            "max_slippage_bps": 50,
        },
        "timing": {
            "valid_from_epoch_s": NOW - 10,
            "expiry_epoch_s": NOW + 3600,
            "quote_ttl_s": 600,
        },
        "reentry": {
            "max_cycles": 1,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
        "profit": {
            "profit_recycle_ratio": "0",
            "banked_profit_ratio": "1",
        },
    }


def reserve(ledger, action_id: str) -> None:
    for state in (
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
        IntentState.RESERVED,
    ):
        ledger.transition(action_id, state, now_epoch_s=NOW)


def reserved_entry():
    ledger = open_ledger()
    policy = parse_policy(policy_doc())
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    reserve(ledger, intent.economic_action_id)
    return ledger, policy, cycle_id, intent


def reserved_exit():
    ledger, policy, cycle_id, entry = reserved_entry()
    obs = observation()
    entry_quote = InkShadowAdapter._quote(obs, Side.BUY, entry.bounds.max_input_atomic)
    for state in (
        IntentState.SIGNED,
        IntentState.SUBMITTED,
        IntentState.INCLUDED,
        IntentState.CONFIRMED,
    ):
        ledger.transition(entry.economic_action_id, state, now_epoch_s=NOW)
    receipt = FillReceiptV0(
        receipt_id="entry-fill",
        economic_action_id=entry.economic_action_id,
        external_ref="0x" + "44" * 32,
        input_atomic_filled=entry_quote.input_atomic,
        output_atomic_filled=entry_quote.output_atomic,
        fee_atomic=0,
        observed_at_epoch_s=NOW,
        source="test",
    )
    ledger.append_fill_receipt(receipt, now_epoch_s=NOW)
    ledger.transition(entry.economic_action_id, IntentState.RECONCILED, now_epoch_s=NOW)
    ledger.transition(entry.economic_action_id, IntentState.FILLED, now_epoch_s=NOW)
    inventory = ledger.inventory_atomic(cycle_id)
    exit_intent = build_intent(
        policy,
        cycle_id,
        policy.level("X1"),
        now_epoch_s=NOW,
        inventory_atomic=inventory,
    )
    ledger.create_intent(exit_intent, now_epoch_s=NOW)
    reserve(ledger, exit_intent.economic_action_id)
    return ledger, policy, cycle_id, exit_intent


def session(policy_id: str) -> ExecutionSessionV0:
    return ExecutionSessionV0(
        repository_commit="7b10a1a74607a9d2bf35438b89f02755b689d4ec",
        implementation_digest="0df376585a874e773d65b5dda0010a3d2eca28c541da474c6ca1cc60b3e929ec",
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id=policy_id,
        authority_policy_digest="22" * 32,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id="evm:57073",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f-1",
        started_at_epoch_s=NOW,
        session_ordinal=0,
    )


def preview_entry():
    ledger, policy, _, intent = reserved_entry()
    obs = observation()
    quote = InkShadowAdapter._quote(obs, Side.BUY, intent.bounds.max_input_atomic)
    result = build_ink_v0f_human_signing_preview(
        policy=risk(),
        router=router(),
        observation=obs,
        quote=quote,
        ledger=ledger,
        intent=intent,
        session=session(policy.policy_id),
        account_nonce=7,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=NOW + 1,
    )
    return ledger, policy, intent, result


def preview_exit():
    ledger, policy, _, intent = reserved_exit()
    obs = observation()
    quote = InkShadowAdapter._quote(obs, Side.SELL, intent.bounds.max_input_atomic)
    result = build_ink_v0f_human_signing_preview(
        policy=risk(),
        router=router(),
        observation=obs,
        quote=quote,
        ledger=ledger,
        intent=intent,
        session=session(policy.policy_id),
        account_nonce=8,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=NOW + 1,
    )
    return ledger, policy, intent, result


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
        deadline_epoch_s=NOW + 600,
    )
    assert len(data) == 260
    assert decode_swap_exact_tokens_for_tokens(data) == (
        123,
        100,
        (WETH9_ADDRESS, KRAKMASK_ADDRESS),
        INK_V0F_TAKER_ADDRESS,
        NOW + 600,
    )
    hostile = bytearray(data)
    hostile[4 + 64 + 31] = 0x80
    with pytest.raises(EnvelopeValidationError, match="offset"):
        decode_swap_exact_tokens_for_tokens(bytes(hostile))


def test_entry_preview_binds_durable_intent_and_exact_approval() -> None:
    ledger, _, intent, result = preview_entry()
    assert ledger.intent_state(intent.economic_action_id) is IntentState.RESERVED
    assert result.swap.path == (WETH9_ADDRESS, KRAKMASK_ADDRESS)
    assert result.approval.token_address == WETH9_ADDRESS
    assert result.approval.spender_address == INK_V0F_ROUTER_ADDRESS
    assert result.approval.amount_atomic == result.swap.amount_in_atomic
    assert result.swap.recipient == INK_V0F_TAKER_ADDRESS
    assert result.signed_bytes_scope.economic_action_id == intent.economic_action_id
    assert result.signed_bytes_scope.target_address == INK_V0F_ROUTER_ADDRESS
    assert result.signed_bytes_scope.min_value_atomic == 0
    assert result.signed_bytes_scope.max_value_atomic == 0


def test_preview_refuses_non_reserved_or_mismatched_durable_intent() -> None:
    ledger = open_ledger()
    policy = parse_policy(policy_doc())
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    obs = observation()
    quote = InkShadowAdapter._quote(obs, Side.BUY, intent.bounds.max_input_atomic)
    with pytest.raises(LevelNotExecutableError, match="RESERVED"):
        build_ink_v0f_human_signing_preview(
            policy=risk(), router=router(), observation=obs, quote=quote,
            ledger=ledger, intent=intent, session=session(policy.policy_id),
            account_nonce=7, gas_limit_ceiling=250_000,
            max_fee_per_gas_ceiling=2_000_000_000,
            max_priority_fee_per_gas_ceiling=100_000_000,
            constructed_at_epoch_s=NOW + 1,
        )

    reserve(ledger, intent.economic_action_id)
    forged = replace(intent, economic_action_id="ff" * 32)
    with pytest.raises(LedgerError, match="unknown economic action"):
        build_ink_v0f_human_signing_preview(
            policy=risk(), router=router(), observation=obs, quote=quote,
            ledger=ledger, intent=forged, session=session(policy.policy_id),
            account_nonce=7, gas_limit_ceiling=250_000,
            max_fee_per_gas_ceiling=2_000_000_000,
            max_priority_fee_per_gas_ceiling=100_000_000,
            constructed_at_epoch_s=NOW + 1,
        )


def test_minimum_output_is_never_weaker_than_policy_or_fifty_bps() -> None:
    ledger, _, intent, result = preview_entry()
    del ledger
    obs = observation()
    q = InkShadowAdapter._quote(obs, Side.BUY, intent.bounds.max_input_atomic)
    minimum = amount_out_min_atomic(risk(), bounds=intent.bounds, quote=q)
    policy_floor = intent.bounds.min_output_atomic
    slippage_floor = ceil_div(q.output_atomic * 9_950, 10_000)
    assert minimum == max(policy_floor, slippage_floor)
    assert result.swap.amount_out_min_atomic == minimum


def test_exit_preview_is_bound_to_settled_inventory_and_reverses_path() -> None:
    ledger, _, intent, result = preview_exit()
    assert intent.bounds.max_input_atomic == ledger.inventory_atomic(intent.cycle_id)
    assert result.swap.path == (KRAKMASK_ADDRESS, WETH9_ADDRESS)
    assert result.approval.token_address == KRAKMASK_ADDRESS
    assert result.approval.amount_atomic == result.swap.amount_in_atomic
    assert result.swap.recipient == INK_V0F_TAKER_ADDRESS


def test_exit_preview_rejects_bounds_that_do_not_match_durable_ledger() -> None:
    ledger, policy, _, intent = reserved_exit()
    obs = observation()
    quote = InkShadowAdapter._quote(obs, Side.SELL, intent.bounds.max_input_atomic)
    hostile_bounds = replace(intent.bounds, max_input_atomic=intent.bounds.max_input_atomic + 1)
    hostile_intent = replace(intent, bounds=hostile_bounds)
    with pytest.raises(AuthorityVerificationError, match="bounds differ"):
        build_ink_v0f_human_signing_preview(
            policy=risk(), router=router(), observation=obs, quote=quote,
            ledger=ledger, intent=hostile_intent, session=session(policy.policy_id),
            account_nonce=8, gas_limit_ceiling=250_000,
            max_fee_per_gas_ceiling=2_000_000_000,
            max_priority_fee_per_gas_ceiling=100_000_000,
            constructed_at_epoch_s=NOW + 1,
        )


def test_forged_exit_quote_is_rejected_by_reserve_recomputation() -> None:
    ledger, policy, _, intent = reserved_exit()
    obs = observation()
    q = InkShadowAdapter._quote(obs, Side.SELL, intent.bounds.max_input_atomic)
    forged = replace(q, output_atomic=q.output_atomic + 1)
    with pytest.raises(LevelNotExecutableError, match="canonical reserve-derived"):
        build_ink_v0f_human_signing_preview(
            policy=risk(), router=router(), observation=obs, quote=forged,
            ledger=ledger, intent=intent, session=session(policy.policy_id),
            account_nonce=8, gas_limit_ceiling=250_000,
            max_fee_per_gas_ceiling=2_000_000_000,
            max_priority_fee_per_gas_ceiling=100_000_000,
            constructed_at_epoch_s=NOW + 1,
        )


def test_preview_phase_cannot_authorize_submission_or_live_capital() -> None:
    _, _, _, result = preview_entry()
    fields = result.eip1559_signing_fields()
    assert fields["chainId"] == 57_073
    assert fields["to"] == INK_V0F_ROUTER_ADDRESS
    assert fields["value"] == 0
    assert fields["data"] == "0x" + result.swap.calldata.hex()
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.RECONCILE_ONLY
    assert qntyspot.AUTHORITY == "INK_V0F_RECONCILE_ONLY"
    assert qntyspot.SIGNING_AUTHORIZED is False
    assert qntyspot.LIVE_CAPITAL_AUTHORIZED is False
