"""Turning a policy rung into an absolute economic limit.

THE CONTRACT THIS MODULE EXISTS FOR
-----------------------------------
    Acquire or reduce a specified exposure ONLY IF the executable economic
    result satisfies an absolute policy limit.

A trigger price says when to look. It says nothing about what may be paid. The
bound produced here is what a future adapter must encode into the transaction
or venue order itself, so that a fill outside the policy is not merely
detected after the fact but is not representable.

All arithmetic is exact rational or integer. Every rounding is in the
direction that makes the bound stricter, never looser:

* ``min_output_atomic`` rounds UP (demand at least this much back).
* exit quantities derived from a ratio of inventory round DOWN (never dispose
  of more than is held).

TIME
----
Nothing in this package reads a clock. ``now_epoch_s`` is always an explicit
argument. That is what makes replay byte-reproducible, and it is enforced by
``tests/test_no_network.py``.
"""

from __future__ import annotations

from fractions import Fraction

from .domain import (
    BPS_DENOMINATOR,
    EconomicBounds,
    IntentV0,
    LadderKind,
    LadderLevelV0,
    PolicyV0,
    Side,
    ceil_div,
    economic_action_id,
)
from .errors import LevelNotExecutableError, QntySpotError
from .states import IntentState

__all__ = [
    "leg_limit_price",
    "min_output_atomic",
    "exit_input_atomic",
    "action_deadline",
    "rearm_threshold_price",
    "build_bounds",
    "build_intent",
]


def leg_limit_price(policy: PolicyV0, level: LadderLevelV0) -> Fraction:
    """The absolute price limit for this rung, in quote per base.

    The rung's own trigger, widened by the policy's slippage tolerance, is then
    clamped by the policy's hard executable-price limit. The clamp is what
    guarantees no rung can widen its way past the policy ceiling/floor.
    """
    slip = Fraction(policy.max_slippage_bps, BPS_DENOMINATOR)
    if level.side is Side.BUY:
        widened = level.trigger_price * (1 + slip)
        return min(widened, policy.max_executable_price)
    widened = level.trigger_price * (1 - slip)
    return max(widened, policy.min_executable_price)


def min_output_atomic(
    *,
    side: Side,
    input_atomic: int,
    limit_price: Fraction,
    base_decimals: int,
    quote_decimals: int,
) -> int:
    """Minimum acceptable output, in atomic units of the output instrument.

    ``limit_price`` is quote per base. For a BUY the input is quote and the
    output is base; for a SELL it is the other way round. Rounded UP.
    """
    pn, pd = limit_price.numerator, limit_price.denominator
    if side is Side.BUY:
        # base_out >= quote_in / price
        return ceil_div(input_atomic * (10**base_decimals) * pd, pn * (10**quote_decimals))
    # quote_out >= base_in * price
    return ceil_div(input_atomic * pn * (10**quote_decimals), pd * (10**base_decimals))


def exit_input_atomic(level: LadderLevelV0, inventory_atomic: int) -> int:
    """How much of the held inventory this exit rung disposes of.

    Floor division: the ladder never disposes of more than is held, and the
    last rung is not silently topped up to absorb the remainder. A residual is
    a residual, and it stays visible.
    """
    if level.kind is not LadderKind.EXIT or level.input_ratio is None:
        raise QntySpotError(f"level {level.level_id} is not an exit rung")
    if inventory_atomic < 0:
        raise QntySpotError("inventory_atomic must be >= 0")
    amount = (inventory_atomic * level.input_ratio.numerator) // level.input_ratio.denominator
    if amount <= 0:
        raise LevelNotExecutableError(
            f"exit level {level.level_id}: inventory {inventory_atomic} yields a "
            "zero-sized action"
        )
    return amount


def action_deadline(policy: PolicyV0, now_epoch_s: int) -> int:
    """Latest epoch second at which this action may still settle.

    The tighter of the quote's time-to-live and the policy's own expiry. If the
    policy has already expired the level is not executable at all.
    """
    if not isinstance(now_epoch_s, int) or isinstance(now_epoch_s, bool):
        raise QntySpotError("now_epoch_s must be an int")
    if now_epoch_s < policy.valid_from_epoch_s:
        raise LevelNotExecutableError(
            f"policy is not yet valid at {now_epoch_s} "
            f"(valid_from {policy.valid_from_epoch_s})"
        )
    if now_epoch_s >= policy.expiry_epoch_s:
        raise LevelNotExecutableError(
            f"policy expired at {policy.expiry_epoch_s}, now {now_epoch_s}"
        )
    return min(now_epoch_s + policy.quote_ttl_s, policy.expiry_epoch_s)


def rearm_threshold_price(policy: PolicyV0, level: LadderLevelV0) -> Fraction:
    """Price the market must reclaim before this rung may arm again.

    Hysteresis exists so a price oscillating around a trigger cannot produce a
    stream of re-entries. It is a necessary condition for re-arming, not a
    sufficient one: a rung already consumed in a cycle can never be re-armed
    within that cycle, because its EconomicActionID already exists.
    """
    hysteresis = Fraction(policy.rearm_hysteresis_bps, BPS_DENOMINATOR)
    if level.side is Side.BUY:
        # A BUY rung re-arms only after price recovers above its trigger.
        return level.trigger_price * (1 + hysteresis)
    return level.trigger_price * (1 - hysteresis)


def build_bounds(
    policy: PolicyV0,
    level: LadderLevelV0,
    *,
    now_epoch_s: int,
    inventory_atomic: int | None = None,
) -> EconomicBounds:
    """Absolute economic bounds for one rung of one cycle.

    ``inventory_atomic`` is required for EXIT rungs (the holding the ratio
    applies to) and forbidden for ENTRY rungs.
    """
    deadline = action_deadline(policy, now_epoch_s)
    limit_price = leg_limit_price(policy, level)
    bd, qd = policy.base.decimals, policy.quote.decimals

    if level.kind is LadderKind.ENTRY:
        if inventory_atomic is not None:
            raise QntySpotError("inventory_atomic is not applicable to an entry rung")
        assert level.input_amount is not None  # guaranteed by LadderLevelV0
        input_decimals = qd if level.side is Side.BUY else bd
        scaled = level.input_amount * (10**input_decimals)
        if scaled.denominator != 1:
            raise LevelNotExecutableError(
                f"entry level {level.level_id}: input_amount is not exactly "
                f"representable in {input_decimals} decimals"
            )
        input_atomic = int(scaled.numerator)
    else:
        if inventory_atomic is None:
            raise QntySpotError("inventory_atomic is required for an exit rung")
        input_atomic = exit_input_atomic(level, inventory_atomic)

    out_atomic = min_output_atomic(
        side=level.side,
        input_atomic=input_atomic,
        limit_price=limit_price,
        base_decimals=bd,
        quote_decimals=qd,
    )
    if out_atomic <= 0:
        raise LevelNotExecutableError(
            f"level {level.level_id}: minimum output rounds to zero at this size"
        )

    if level.side is Side.BUY:
        input_id, output_id = policy.quote_instrument_id, policy.instrument_id
    else:
        input_id, output_id = policy.instrument_id, policy.quote_instrument_id

    return EconomicBounds(
        side=level.side,
        input_instrument_id=input_id,
        output_instrument_id=output_id,
        max_input_atomic=input_atomic,
        min_output_atomic=out_atomic,
        limit_price=limit_price,
        max_price_impact_bps=policy.max_price_impact_bps,
        max_slippage_bps=policy.max_slippage_bps,
        deadline_epoch_s=deadline,
    )


def build_intent(
    policy: PolicyV0,
    cycle_id: str,
    level: LadderLevelV0,
    *,
    now_epoch_s: int,
    inventory_atomic: int | None = None,
) -> IntentV0:
    """Construct the ARMED intent for one rung of one cycle.

    Quote-denominated exposure is the capital this action puts at risk, and it
    is what the budget layer reserves. A SELL leg returns quote rather than
    consuming it, so its exposure is zero and it takes no reservation.
    """
    bounds = build_bounds(
        policy, level, now_epoch_s=now_epoch_s, inventory_atomic=inventory_atomic
    )
    exposure = bounds.max_input_atomic if level.side is Side.BUY else 0
    if level.side is Side.BUY and exposure > policy.budget.per_order_cap_atomic:
        raise LevelNotExecutableError(
            f"level {level.level_id}: quote exposure {exposure} exceeds "
            f"per_order_cap {policy.budget.per_order_cap_atomic}"
        )
    return IntentV0(
        economic_action_id=economic_action_id(
            policy_id=policy.policy_id,
            instrument_id=policy.instrument_id,
            cycle_id=cycle_id,
            level_id=level.level_id,
            side=level.side,
        ),
        policy_id=policy.policy_id,
        instrument_id=policy.instrument_id,
        quote_instrument_id=policy.quote_instrument_id,
        network_id=policy.network_id,
        cycle_id=cycle_id,
        level_id=level.level_id,
        side=level.side,
        kind=level.kind,
        bounds=bounds,
        quote_exposure_atomic=exposure,
        state=IntentState.ARMED,
    )
