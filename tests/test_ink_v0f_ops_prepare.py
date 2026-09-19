from __future__ import annotations

import importlib.util
from decimal import Decimal
from pathlib import Path

from qntyspot.economics import build_intent
from qntyspot.policy import parse_policy

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ops" / "ink_v0f_native_live_prepare_v0.py"
NOW = 1_800_000_000


def _helper():
    spec = importlib.util.spec_from_file_location("ink_v0f_native_live_prepare_ops", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_live_price_precision_survives_slippage_bound_serialization() -> None:
    helper = _helper()
    spot = Decimal(
        "0.00000026577308469831098152844786455781542105070335951215928438698627683414189929445304"
    )
    trigger = helper._decimal_text(spot)
    max_price = helper._decimal_text(spot * Decimal("1.02"))
    min_price = helper._decimal_text(spot * Decimal("0.50"))

    policy = parse_policy(
        {
            "schema": "qntyspot.policy.v0",
            "policy_name": "ops-live-precision-regression",
            "side": "BUY",
            "base": {
                "ref": {
                    "namespace": "evm",
                    "chain_id": 57073,
                    "contract_address": "0x32bcb803f696c99eb263d60a05cafd8689026575",
                },
                "decimals": 18,
                "display_symbol": "KRAKMASK",
            },
            "quote": {
                "ref": {
                    "namespace": "evm",
                    "chain_id": 57073,
                    "contract_address": "0x4200000000000000000000000000000000000006",
                },
                "decimals": 18,
                "display_symbol": "WETH",
            },
            "entry_ladder": {
                "levels": [
                    {
                        "level_id": "E1",
                        "trigger_price": trigger,
                        "input_amount": "0.001",
                    }
                ]
            },
            "exit_ladder": {
                "levels": [
                    {
                        "level_id": "X1",
                        "trigger_price": trigger,
                        "input_ratio": "1",
                    }
                ]
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
                "max_executable_price": max_price,
                "min_executable_price": min_price,
                "max_price_impact_bps": 100,
                "max_slippage_bps": 50,
            },
            "timing": {
                "valid_from_epoch_s": NOW - 5,
                "expiry_epoch_s": NOW + 600,
                "quote_ttl_s": 300,
            },
            "reentry": {
                "max_cycles": 1,
                "rearm_hysteresis_bps": 200,
                "rearm_cooldown_s": 600,
            },
            "recycling": {
                "profit_recycle_ratio": "0",
                "banked_profit_ratio": "1",
            },
        }
    )
    intent = build_intent(policy, "11" * 32, policy.level("E1"), now_epoch_s=NOW)

    # This exact serialization is where the first live attempt failed when
    # trigger_price used all 30 fractional digits before a 50-bps widening.
    obj = intent.bounds.canonical_object()
    assert obj["max_input_atomic"] == "1000000000000000"
    assert len(obj["limit_price"].split(".", 1)[1]) <= 30


def test_ops_helper_is_bound_to_current_durable_envelope_runtime() -> None:
    helper = _helper()
    assert helper.BOUND_REPOSITORY_COMMIT == "928b110ee9e5202d411487ee1ede52a022e097c0"
    assert helper.BOUND_IMPLEMENTATION_DIGEST == (
        "0eebedcd5028ada31899dde2794fc783970df13e461dfd85353ed61c22aa4e8d"
    )
