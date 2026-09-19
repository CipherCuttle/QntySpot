from __future__ import annotations

from pathlib import Path

from qntyspot.domain import FillReceiptV0, Side
from qntyspot.economics import build_intent
from qntyspot.execution_contract import ExecutionSessionV0
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
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    build_ink_v0f_human_signing_preview,
    consume_ink_v0f_router_artifact,
)
from qntyspot.ink_v0f_native_sell import (
    SWAP_EXACT_TOKENS_FOR_ETH_SELECTOR,
    build_ink_v0f_native_sell_envelope,
    build_ink_v0f_native_sell_preview,
    decode_swap_exact_tokens_for_eth,
    encode_swap_exact_tokens_for_eth,
)
from qntyspot.ink_v0f_preauth import (
    InkV0FRouterObservationV0,
    build_ink_v0f_execution_envelope,
)
from qntyspot.ink_v0f_risk import consume_ink_v0f_risk_artifact
from qntyspot.ledger import open_ledger
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

ROOT = Path(__file__).resolve().parents[1]
ROUTER_ARTIFACT = ROOT / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json"
RISK_ARTIFACT = ROOT / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json"
NOW = 1_800_000_000


def observation() -> InkMarketObservationV0:
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
        reserve0_atomic=10**21,
        reserve1_atomic=10**21,
        reserve_timestamp=1,
        provider_evidence=({}, {}),
        v2_fee_numerator=V2_FEE_NUMERATOR,
        v2_fee_denominator=V2_FEE_DENOMINATOR,
    )


def policy_doc() -> dict:
    return {
        "schema": "qntyspot.policy.v0",
        "policy_name": "ink-v0f-native-sell-test",
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
    }


def reserve(ledger, action_id: str) -> None:
    for state in (
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
        IntentState.RESERVED,
    ):
        ledger.transition(action_id, state, now_epoch_s=NOW)


def exit_fixture():
    ledger = open_ledger()
    policy = parse_policy(policy_doc())
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    entry = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(entry, now_epoch_s=NOW)
    reserve(ledger, entry.economic_action_id)

    obs = observation()
    entry_quote = InkShadowAdapter._quote(obs, Side.BUY, entry.bounds.max_input_atomic)
    for state in (
        IntentState.SIGNED,
        IntentState.SUBMITTED,
        IntentState.INCLUDED,
        IntentState.CONFIRMED,
    ):
        ledger.transition(entry.economic_action_id, state, now_epoch_s=NOW)
    ledger.append_fill_receipt(
        FillReceiptV0(
            receipt_id="native-sell-entry-fill",
            economic_action_id=entry.economic_action_id,
            external_ref="0x" + "44" * 32,
            input_atomic_filled=entry_quote.input_atomic,
            output_atomic_filled=entry_quote.output_atomic,
            fee_atomic=0,
            observed_at_epoch_s=NOW,
            source="test",
        ),
        now_epoch_s=NOW,
    )
    ledger.transition(entry.economic_action_id, IntentState.RECONCILED, now_epoch_s=NOW)
    ledger.transition(entry.economic_action_id, IntentState.FILLED, now_epoch_s=NOW)

    inventory = ledger.inventory_atomic(cycle_id)
    intent = build_intent(
        policy,
        cycle_id,
        policy.level("X1"),
        now_epoch_s=NOW,
        inventory_atomic=inventory,
    )
    ledger.create_intent(intent, now_epoch_s=NOW)
    reserve(ledger, intent.economic_action_id)

    session = ExecutionSessionV0(
        repository_commit="11" * 20,
        implementation_digest="22" * 32,
        runtime_identity="cpython-test",
        db_schema_version=1,
        policy_id=policy.policy_id,
        authority_policy_digest="33" * 32,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id="evm:57073",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=NOW,
        session_ordinal=0,
    )
    risk = consume_ink_v0f_risk_artifact(RISK_ARTIFACT.read_bytes())
    router = consume_ink_v0f_router_artifact(ROUTER_ARTIFACT.read_bytes())
    quote = InkShadowAdapter._quote(obs, Side.SELL, intent.bounds.max_input_atomic)
    token_preview = build_ink_v0f_human_signing_preview(
        policy=risk,
        router=router,
        observation=obs,
        quote=quote,
        ledger=ledger,
        intent=intent,
        session=session,
        account_nonce=8,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
        constructed_at_epoch_s=NOW + 1,
    )
    router_obs = InkV0FRouterObservationV0(
        chain_id=57_073,
        router_address=router.address,
        common_block=obs.common_block,
        provider_heads=dict(obs.provider_heads),
        bytecode_sha256=router.deployed_bytecode_sha256,
        bytecode_length=router.deployed_bytecode_length,
        factory_address=router.factory_address,
        weth_address=router.weth_address,
        provider_evidence=({}, {}),
    )
    token_envelope = build_ink_v0f_execution_envelope(
        token_preview,
        router_obs,
        session,
    )
    return token_preview, token_envelope, router_obs


def test_native_sell_selector_and_codec_are_canonical() -> None:
    assert SWAP_EXACT_TOKENS_FOR_ETH_SELECTOR.hex() == "18cbafe5"
    data = encode_swap_exact_tokens_for_eth(
        amount_in_atomic=123,
        amount_out_min_atomic=100,
        path=(KRAKMASK_ADDRESS, WETH9_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=NOW + 600,
    )
    assert len(data) == 260
    assert decode_swap_exact_tokens_for_eth(data) == (
        123,
        100,
        (KRAKMASK_ADDRESS, WETH9_ADDRESS),
        INK_V0F_TAKER_ADDRESS,
        NOW + 600,
    )


def test_native_sell_reuses_exact_approval_but_settles_eth() -> None:
    token_preview, token_envelope, router_obs = exit_fixture()
    native_preview = build_ink_v0f_native_sell_preview(
        token_preview,
        token_envelope,
        router_obs,
    )
    envelope = build_ink_v0f_native_sell_envelope(native_preview)

    assert token_preview.approval.token_address == KRAKMASK_ADDRESS
    assert token_preview.approval.amount_atomic == envelope.max_input_atomic
    assert envelope.allowance_target == INK_V0F_ROUTER_ADDRESS
    assert envelope.transaction_value_atomic == 0
    assert envelope.calldata_sha256 != token_envelope.calldata_sha256
    assert native_preview.native_calldata[:4] == SWAP_EXACT_TOKENS_FOR_ETH_SELECTOR
    fields = native_preview.eip1559_signing_fields()
    assert fields["to"] == INK_V0F_ROUTER_ADDRESS
    assert fields["value"] == 0
    assert str(fields["data"]).startswith("0x18cbafe5")
