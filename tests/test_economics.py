"""The economic-limit contract: bounds a fill cannot legitimately escape."""

from __future__ import annotations

from fractions import Fraction

import pytest

from conftest import NOW, base_policy_doc, doc_with
from qntyspot.canon import format_canonical_decimal
from qntyspot.domain import LadderKind, Side
from qntyspot.economics import (
    action_deadline,
    build_bounds,
    build_intent,
    exit_input_atomic,
    leg_limit_price,
    min_output_atomic,
    rearm_threshold_price,
)
from qntyspot.errors import LevelNotExecutableError, QntySpotError
from qntyspot.policy import parse_policy


def test_buy_bounds_encode_a_ceiling_on_what_may_be_spent(policy) -> None:
    bounds = build_bounds(policy, policy.level("E1"), now_epoch_s=NOW)
    assert bounds.side is Side.BUY
    assert bounds.input_instrument_id == policy.quote_instrument_id
    assert bounds.output_instrument_id == policy.instrument_id
    # 100 USDC at 6 decimals.
    assert bounds.max_input_atomic == 100_000_000
    # With zero slippage the limit is the rung's own trigger, 0.9, which is
    # tighter than the policy ceiling of 1. Spending 100 quote at no worse than
    # 0.9 must return at least 100/0.9 base, rounded UP.
    assert bounds.limit_price == Fraction(9, 10)
    assert bounds.min_output_atomic == -((-100 * 10**18 * 10) // 9)
    assert bounds.min_output_atomic == 111_111_111_111_111_111_112


def test_sell_bounds_encode_a_floor_on_what_must_be_received(policy) -> None:
    inventory = 100 * 10**18
    bounds = build_bounds(
        policy, policy.level("X1"), now_epoch_s=NOW, inventory_atomic=inventory
    )
    assert bounds.side is Side.SELL
    assert bounds.input_instrument_id == policy.instrument_id
    assert bounds.output_instrument_id == policy.quote_instrument_id
    assert bounds.max_input_atomic == inventory // 2
    # limit price is max(trigger*(1-slip), min_executable) = max(1.2, 1) = 1.2
    assert bounds.limit_price == Fraction(12, 10)
    assert bounds.min_output_atomic == 60_000_000


def test_slippage_widens_the_limit_but_never_past_the_policy_ceiling() -> None:
    doc = base_policy_doc()
    doc["limits"]["max_slippage_bps"] = 500  # 5%
    doc["limits"]["max_executable_price"] = "1.5"
    policy = parse_policy(doc)
    # E1 triggers at 0.9; 0.9 * 1.05 = 0.945, below the 1.5 ceiling.
    assert leg_limit_price(policy, policy.level("E1")) == Fraction(945, 1000)

    doc["limits"]["max_executable_price"] = "0.92"
    doc["limits"]["min_executable_price"] = "0.92"
    doc["exit_ladder"]["levels"] = [
        {"level_id": "X1", "trigger_price": "1.2", "input_ratio": "1"}
    ]
    doc["entry_ladder"]["levels"] = [
        {"level_id": "E1", "trigger_price": "0.9", "input_amount": "100"}
    ]
    clamped = parse_policy(doc)
    # 0.945 would exceed the 0.92 ceiling, so the ceiling wins.
    assert leg_limit_price(clamped, clamped.level("E1")) == Fraction(92, 100)


def test_sell_slippage_is_clamped_by_the_price_floor() -> None:
    doc = base_policy_doc()
    doc["limits"]["max_slippage_bps"] = 5000  # 50%
    doc["limits"]["min_executable_price"] = "1"
    policy = parse_policy(doc)
    # 1.2 * 0.5 = 0.6, below the floor of 1, so the floor wins.
    assert leg_limit_price(policy, policy.level("X1")) == 1


def test_minimum_output_rounds_up_so_the_bound_is_never_loosened() -> None:
    # 1 atomic quote unit at price 3 must demand a strictly positive base
    # amount even though the exact answer is fractional.
    out = min_output_atomic(
        side=Side.BUY,
        input_atomic=1,
        limit_price=Fraction(3),
        base_decimals=0,
        quote_decimals=0,
    )
    assert out == 1  # ceil(1/3)


@pytest.mark.parametrize("input_atomic", [1, 7, 999_999, 10**24 + 1])
@pytest.mark.parametrize("price", ["0.3", "1", "1.7", "12345.6789"])
def test_encoded_bounds_never_permit_a_worse_price_than_the_limit(
    input_atomic: int, price: str
) -> None:
    """The core invariant: honouring the bound implies honouring the limit."""
    from qntyspot.canon import parse_canonical_decimal

    limit = parse_canonical_decimal(price)
    bd, qd = 18, 6

    buy_out = min_output_atomic(
        side=Side.BUY,
        input_atomic=input_atomic,
        limit_price=limit,
        base_decimals=bd,
        quote_decimals=qd,
    )
    # effective price = (in / 10**qd) / (out / 10**bd) must be <= limit
    effective = Fraction(input_atomic, 10**qd) / Fraction(buy_out, 10**bd)
    assert effective <= limit

    sell_out = min_output_atomic(
        side=Side.SELL,
        input_atomic=input_atomic,
        limit_price=limit,
        base_decimals=bd,
        quote_decimals=qd,
    )
    effective = Fraction(sell_out, 10**qd) / Fraction(input_atomic, 10**bd)
    assert effective >= limit


def test_exit_quantity_floors_and_never_oversells(policy) -> None:
    level = policy.level("X1")  # ratio 0.5
    assert exit_input_atomic(level, 101) == 50
    assert exit_input_atomic(level, 2) == 1


def test_an_exit_that_rounds_to_nothing_is_not_executable(policy) -> None:
    with pytest.raises(LevelNotExecutableError, match="zero-sized"):
        exit_input_atomic(policy.level("X1"), 1)


def test_exit_ratios_leave_a_residual_rather_than_silently_absorbing_it(policy) -> None:
    inventory = 101
    disposed = sum(
        exit_input_atomic(policy.level(lid), inventory) for lid in ("X1", "X2")
    )
    assert disposed == 100
    assert inventory - disposed == 1  # visible residual, not quietly swept up


def test_entry_rungs_reject_an_inventory_argument(policy) -> None:
    with pytest.raises(QntySpotError, match="not applicable"):
        build_bounds(policy, policy.level("E1"), now_epoch_s=NOW, inventory_atomic=1)


def test_exit_rungs_require_an_inventory_argument(policy) -> None:
    with pytest.raises(QntySpotError, match="required"):
        build_bounds(policy, policy.level("X1"), now_epoch_s=NOW)


# -- time -------------------------------------------------------------------


def test_deadline_is_the_tighter_of_quote_ttl_and_policy_expiry(policy) -> None:
    assert action_deadline(policy, NOW) == NOW + policy.quote_ttl_s
    near_expiry = policy.expiry_epoch_s - 5
    assert action_deadline(policy, near_expiry) == policy.expiry_epoch_s


def test_a_policy_outside_its_validity_window_yields_no_action(policy) -> None:
    with pytest.raises(LevelNotExecutableError, match="not yet valid"):
        action_deadline(policy, policy.valid_from_epoch_s - 1)
    with pytest.raises(LevelNotExecutableError, match="expired"):
        action_deadline(policy, policy.expiry_epoch_s)


def test_time_must_be_supplied_explicitly(policy) -> None:
    with pytest.raises(QntySpotError, match="must be an int"):
        action_deadline(policy, "now")


# -- hysteresis -------------------------------------------------------------


def test_rearm_threshold_requires_recovery_past_the_trigger(policy) -> None:
    # 200 bps of hysteresis on a BUY rung triggering at 0.9.
    assert rearm_threshold_price(policy, policy.level("E1")) == Fraction(9, 10) * Fraction(
        102, 100
    )
    # and downward for a SELL rung triggering at 1.2
    assert rearm_threshold_price(policy, policy.level("X1")) == Fraction(12, 10) * Fraction(
        98, 100
    )


# -- intents ----------------------------------------------------------------


def test_intent_exposure_is_quote_capital_for_buys_and_zero_for_sells(policy) -> None:
    buy = build_intent(policy, "cycle-0", policy.level("E1"), now_epoch_s=NOW)
    assert buy.quote_exposure_atomic == buy.bounds.max_input_atomic

    sell = build_intent(
        policy,
        "cycle-0",
        policy.level("X1"),
        now_epoch_s=NOW,
        inventory_atomic=100 * 10**18,
    )
    # A SELL returns quote rather than consuming it, so it reserves nothing.
    assert sell.quote_exposure_atomic == 0
    assert sell.kind is LadderKind.EXIT


def test_intent_identity_is_a_pure_function_of_its_five_components(policy) -> None:
    a = build_intent(policy, "cycle-0", policy.level("E1"), now_epoch_s=NOW)
    b = build_intent(policy, "cycle-0", policy.level("E1"), now_epoch_s=NOW + 1000)
    assert a.economic_action_id == b.economic_action_id  # time is not identity

    other_cycle = build_intent(policy, "cycle-1", policy.level("E1"), now_epoch_s=NOW)
    other_level = build_intent(policy, "cycle-0", policy.level("E2"), now_epoch_s=NOW)
    assert len({a.economic_action_id, other_cycle.economic_action_id,
                other_level.economic_action_id}) == 3


def test_an_intent_over_the_per_order_cap_is_refused() -> None:
    doc = base_policy_doc()
    doc["capital"]["per_order_cap_quote"] = "100"
    policy = parse_policy(doc)
    # Admissible at 100; nudge the cap check by rebuilding with a larger rung.
    doc["entry_ladder"]["levels"] = [
        {"level_id": "E1", "trigger_price": "0.9", "input_amount": "100"}
    ]
    doc["capital"]["per_order_cap_quote"] = "100"
    ok = parse_policy(doc)
    assert build_intent(ok, "c0", ok.level("E1"), now_epoch_s=NOW)

    # A SELL-cycle exit rung is a BUY leg whose size comes from inventory, so
    # the per-order cap is enforced at intent time rather than at parse time.
    doc = base_policy_doc()
    doc["side"] = "SELL"
    doc["entry_ladder"]["levels"] = [
        {"level_id": "E1", "trigger_price": "1.2", "input_amount": "10"}
    ]
    doc["exit_ladder"]["levels"] = [
        {"level_id": "X1", "trigger_price": "0.9", "input_ratio": "1"}
    ]
    doc["capital"]["per_order_cap_quote"] = "1"
    doc["capital"]["allocation_quote"] = "1"
    doc["capital"]["per_instrument_cap_quote"] = "1"
    doc["capital"]["per_network_cap_quote"] = "1"
    doc["capital"]["global_portfolio_cap_quote"] = "1"
    sell_policy = parse_policy(doc)
    with pytest.raises(LevelNotExecutableError, match="per_order_cap"):
        build_intent(
            sell_policy,
            "c0",
            sell_policy.level("X1"),
            now_epoch_s=NOW,
            inventory_atomic=1_000_000_000,
        )


def test_canonical_bounds_render_atomic_amounts_as_strings(policy) -> None:
    """Atomic amounts exceed 2**53; JSON numbers would be a rounding hazard."""
    raw = build_bounds(policy, policy.level("E1"), now_epoch_s=NOW)
    bounds = raw.canonical_object()
    assert raw.min_output_atomic > 2**63
    assert bounds["min_output_atomic"] == str(raw.min_output_atomic)
    assert isinstance(bounds["max_input_atomic"], str)
    assert bounds["limit_price"] == format_canonical_decimal(Fraction(9, 10))
