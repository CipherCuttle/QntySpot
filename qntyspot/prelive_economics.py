"""Deterministic pre-live capital economics.

This module adds no execution, signing, submission, or live-capital authority.
It contains only pure arithmetic and explicit fail-closed contracts needed
before a dust-live phase may be considered.

Three seams live here:

* execution-size narrowing keeps a precommitted intent price bound when a
  later venue/liquidity check elects to execute less than the maximum;
* dust-live concurrency ceilings are explicit rather than ambient;
* realized trading profit is separated from principal and external quote-
  denominated costs before any amount can become recyclable capital.

The current FillReceiptV0 fee field does not declare a universal denomination.
Accordingly this module never guesses how to convert it. Callers must supply
external costs already normalized into atomic units of the quote instrument.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Iterable

from .domain import EconomicBounds, Side, ceil_div
from .errors import LevelNotExecutableError, QntySpotError

__all__ = [
    "DustLiveConcurrencyV0",
    "PositionConcurrencySnapshotV0",
    "ExecutedTradeV0",
    "ProfitAllocationV0",
    "prorated_min_output_atomic",
    "assert_new_entry_concurrency",
    "compute_profit_allocation",
]


def _positive_int(value: int, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise QntySpotError(f"{field} must be a positive integer")
    return value


def _non_negative_int(value: int, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise QntySpotError(f"{field} must be a non-negative integer")
    return value


def _unit_ratio(value: Fraction, *, field: str) -> Fraction:
    if not isinstance(value, Fraction):
        raise QntySpotError(f"{field} must be an exact Fraction")
    if value < 0 or value > 1:
        raise QntySpotError(f"{field} must be in [0, 1]")
    return value


def prorated_min_output_atomic(bounds: EconomicBounds, input_atomic: int) -> int:
    """Carry the original limit price into a smaller exact-input execution.

    bounds.min_output_atomic is the minimum for the full
    bounds.max_input_atomic. A narrowed envelope must demand the same price or
    better, so the output floor scales linearly and rounds UP.
    """

    _positive_int(input_atomic, field="input_atomic")
    if input_atomic > bounds.max_input_atomic:
        raise QntySpotError("input_atomic exceeds the committed maximum input")
    return ceil_div(
        bounds.min_output_atomic * input_atomic,
        bounds.max_input_atomic,
    )


@dataclass(frozen=True, slots=True)
class DustLiveConcurrencyV0:
    """Explicit first-live position/action ceilings.

    This contract is intentionally separate from PolicyV0 and the currently
    frozen authority-root schema. A future V0F authority grant must bind these
    values before they become a live admission gate.
    """

    max_open_positions_global: int
    max_open_positions_per_network: int
    max_open_positions_per_instrument: int
    max_in_flight_entries: int

    def __post_init__(self) -> None:
        _positive_int(self.max_open_positions_global, field="max_open_positions_global")
        _positive_int(
            self.max_open_positions_per_network,
            field="max_open_positions_per_network",
        )
        _positive_int(
            self.max_open_positions_per_instrument,
            field="max_open_positions_per_instrument",
        )
        _positive_int(self.max_in_flight_entries, field="max_in_flight_entries")
        if self.max_open_positions_per_network > self.max_open_positions_global:
            raise QntySpotError(
                "per-network position ceiling cannot exceed the global ceiling"
            )
        if (
            self.max_open_positions_per_instrument
            > self.max_open_positions_per_network
        ):
            raise QntySpotError(
                "per-instrument position ceiling cannot exceed the network ceiling"
            )


@dataclass(frozen=True, slots=True)
class PositionConcurrencySnapshotV0:
    """Canonical counts supplied by the future live ledger projection."""

    open_positions_global: int
    open_positions_network: int
    open_positions_instrument: int
    in_flight_entries: int

    def __post_init__(self) -> None:
        _non_negative_int(self.open_positions_global, field="open_positions_global")
        _non_negative_int(self.open_positions_network, field="open_positions_network")
        _non_negative_int(
            self.open_positions_instrument, field="open_positions_instrument"
        )
        _non_negative_int(self.in_flight_entries, field="in_flight_entries")
        if self.open_positions_network > self.open_positions_global:
            raise QntySpotError(
                "network open-position count exceeds the global count"
            )
        if self.open_positions_instrument > self.open_positions_network:
            raise QntySpotError(
                "instrument open-position count exceeds the network count"
            )


def assert_new_entry_concurrency(
    ceiling: DustLiveConcurrencyV0,
    snapshot: PositionConcurrencySnapshotV0,
) -> None:
    """Fail closed before an ENTRY would create more live exposure.

    Exit/reconciliation paths do not call this guard: a position ceiling must
    never trap the system inside exposure by preventing an exit.
    """

    failures: list[str] = []
    if snapshot.open_positions_global >= ceiling.max_open_positions_global:
        failures.append("GLOBAL_POSITION_CEILING")
    if (
        snapshot.open_positions_network
        >= ceiling.max_open_positions_per_network
    ):
        failures.append("NETWORK_POSITION_CEILING")
    if (
        snapshot.open_positions_instrument
        >= ceiling.max_open_positions_per_instrument
    ):
        failures.append("INSTRUMENT_POSITION_CEILING")
    if snapshot.in_flight_entries >= ceiling.max_in_flight_entries:
        failures.append("IN_FLIGHT_ENTRY_CEILING")
    if failures:
        raise LevelNotExecutableError(
            "new entry exceeds dust-live concurrency: " + "+".join(failures)
        )


@dataclass(frozen=True, slots=True)
class ExecutedTradeV0:
    """One chronologically ordered settled trade in quote-accounting terms."""

    side: Side
    base_atomic: int
    quote_atomic: int
    external_cost_quote_atomic: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.side, Side):
            raise QntySpotError("trade side must be Side")
        _positive_int(self.base_atomic, field="base_atomic")
        _positive_int(self.quote_atomic, field="quote_atomic")
        _non_negative_int(
            self.external_cost_quote_atomic,
            field="external_cost_quote_atomic",
        )


@dataclass(frozen=True, slots=True)
class ProfitAllocationV0:
    """Exact realized-PnL and conservative integer recycling result."""

    realized_pnl_quote_atomic: Fraction
    realized_profit_quote_atomic: Fraction
    realized_loss_quote_atomic: Fraction
    remaining_inventory_base_atomic: int
    remaining_cost_basis_quote_atomic: Fraction
    recyclable_profit_quote_atomic: int
    banked_profit_quote_atomic: int
    retained_profit_quote_atomic: Fraction
    external_cost_quote_atomic: int


def compute_profit_allocation(
    trades: Iterable[ExecutedTradeV0],
    *,
    profit_recycle_ratio: Fraction,
    banked_profit_ratio: Fraction,
) -> ProfitAllocationV0:
    """Apply weighted-average cost basis and split realized positive profit.

    Principal never becomes profit merely because a sale returned quote.
    BUY-side external quote costs join cost basis; SELL-side external quote
    costs reduce proceeds. Only positive realized PnL is eligible for
    recycling/banking. Integer allocations round DOWN, so rounding can never
    create spendable capital.
    """

    recycle_ratio = _unit_ratio(
        profit_recycle_ratio, field="profit_recycle_ratio"
    )
    bank_ratio = _unit_ratio(
        banked_profit_ratio, field="banked_profit_ratio"
    )
    if recycle_ratio + bank_ratio > 1:
        raise QntySpotError(
            "profit_recycle_ratio + banked_profit_ratio must not exceed 1"
        )

    inventory = 0
    cost_basis = Fraction(0)
    realized = Fraction(0)
    external_cost_total = 0

    for trade in trades:
        external_cost_total += trade.external_cost_quote_atomic
        if trade.side is Side.BUY:
            inventory += trade.base_atomic
            cost_basis += Fraction(
                trade.quote_atomic + trade.external_cost_quote_atomic
            )
            continue

        if trade.base_atomic > inventory:
            raise QntySpotError(
                "settled SELL exceeds accounted base inventory"
            )
        released_basis = cost_basis * Fraction(trade.base_atomic, inventory)
        net_proceeds = Fraction(
            trade.quote_atomic - trade.external_cost_quote_atomic
        )
        realized += net_proceeds - released_basis
        inventory -= trade.base_atomic
        cost_basis -= released_basis
        if inventory == 0:
            cost_basis = Fraction(0)

    realized_profit = max(realized, Fraction(0))
    realized_loss = max(-realized, Fraction(0))
    recyclable_fraction = realized_profit * recycle_ratio
    banked_fraction = realized_profit * bank_ratio
    recyclable = recyclable_fraction.numerator // recyclable_fraction.denominator
    banked = banked_fraction.numerator // banked_fraction.denominator
    retained = realized_profit - recyclable - banked

    return ProfitAllocationV0(
        realized_pnl_quote_atomic=realized,
        realized_profit_quote_atomic=realized_profit,
        realized_loss_quote_atomic=realized_loss,
        remaining_inventory_base_atomic=inventory,
        remaining_cost_basis_quote_atomic=cost_basis,
        recyclable_profit_quote_atomic=recyclable,
        banked_profit_quote_atomic=banked,
        retained_profit_quote_atomic=retained,
        external_cost_quote_atomic=external_cost_total,
    )
