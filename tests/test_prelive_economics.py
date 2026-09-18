"""Pre-live capital economics: deterministic sizing, concurrency and recycling."""

from __future__ import annotations

from fractions import Fraction

import pytest

from qntyspot.domain import EconomicBounds, Side
from qntyspot.errors import LevelNotExecutableError, QntySpotError
from qntyspot.prelive_economics import (
    DustLiveConcurrencyV0,
    ExecutedTradeV0,
    PositionConcurrencySnapshotV0,
    assert_new_entry_concurrency,
    compute_profit_allocation,
    prorated_min_output_atomic,
)


def _bounds() -> EconomicBounds:
    return EconomicBounds(
        side=Side.BUY,
        input_instrument_id="evm:1:0x0000000000000000000000000000000000000001",
        output_instrument_id="evm:1:0x0000000000000000000000000000000000000002",
        max_input_atomic=1_000,
        min_output_atomic=777,
        limit_price=Fraction(2),
        max_price_impact_bps=100,
        max_slippage_bps=50,
        deadline_epoch_s=1_800_000_000,
    )


def test_prorated_minimum_rounds_up_and_never_weakens_price_bound() -> None:
    bounds = _bounds()
    assert prorated_min_output_atomic(bounds, 500) == 389
    assert prorated_min_output_atomic(bounds, 1_000) == 777
    with pytest.raises(QntySpotError, match="exceeds"):
        prorated_min_output_atomic(bounds, 1_001)


def test_first_live_concurrency_blocks_new_entries_at_every_scope() -> None:
    ceiling = DustLiveConcurrencyV0(
        max_open_positions_global=3,
        max_open_positions_per_network=2,
        max_open_positions_per_instrument=1,
        max_in_flight_entries=1,
    )
    assert_new_entry_concurrency(
        ceiling,
        PositionConcurrencySnapshotV0(
            open_positions_global=1,
            open_positions_network=1,
            open_positions_instrument=0,
            in_flight_entries=0,
        ),
    )

    with pytest.raises(LevelNotExecutableError, match="INSTRUMENT_POSITION_CEILING"):
        assert_new_entry_concurrency(
            ceiling,
            PositionConcurrencySnapshotV0(
                open_positions_global=1,
                open_positions_network=1,
                open_positions_instrument=1,
                in_flight_entries=0,
            ),
        )

    with pytest.raises(LevelNotExecutableError, match="IN_FLIGHT_ENTRY_CEILING"):
        assert_new_entry_concurrency(
            ceiling,
            PositionConcurrencySnapshotV0(
                open_positions_global=1,
                open_positions_network=1,
                open_positions_instrument=0,
                in_flight_entries=1,
            ),
        )


def test_concurrency_contract_rejects_incoherent_counts_and_ceilings() -> None:
    with pytest.raises(QntySpotError, match="per-instrument"):
        DustLiveConcurrencyV0(
            max_open_positions_global=2,
            max_open_positions_per_network=1,
            max_open_positions_per_instrument=2,
            max_in_flight_entries=1,
        )
    with pytest.raises(QntySpotError, match="instrument open-position"):
        PositionConcurrencySnapshotV0(
            open_positions_global=1,
            open_positions_network=0,
            open_positions_instrument=1,
            in_flight_entries=0,
        )


def test_realized_profit_uses_cost_basis_not_gross_sale_proceeds() -> None:
    result = compute_profit_allocation(
        (
            ExecutedTradeV0(Side.BUY, base_atomic=100, quote_atomic=100),
            ExecutedTradeV0(Side.SELL, base_atomic=50, quote_atomic=75),
        ),
        profit_recycle_ratio=Fraction(2, 5),
        banked_profit_ratio=Fraction(2, 5),
    )
    assert result.realized_pnl_quote_atomic == 25
    assert result.remaining_inventory_base_atomic == 50
    assert result.remaining_cost_basis_quote_atomic == 50
    assert result.recyclable_profit_quote_atomic == 10
    assert result.banked_profit_quote_atomic == 10
    assert result.retained_profit_quote_atomic == 5


def test_external_quote_costs_reduce_profit_before_recycling() -> None:
    result = compute_profit_allocation(
        (
            ExecutedTradeV0(
                Side.BUY,
                base_atomic=100,
                quote_atomic=100,
                external_cost_quote_atomic=5,
            ),
            ExecutedTradeV0(
                Side.SELL,
                base_atomic=100,
                quote_atomic=130,
                external_cost_quote_atomic=2,
            ),
        ),
        profit_recycle_ratio=Fraction(1, 2),
        banked_profit_ratio=Fraction(1, 4),
    )
    assert result.realized_pnl_quote_atomic == 23
    assert result.external_cost_quote_atomic == 7
    assert result.recyclable_profit_quote_atomic == 11
    assert result.banked_profit_quote_atomic == 5
    assert result.retained_profit_quote_atomic == 7


def test_losses_and_fractional_profit_never_create_spendable_recycling() -> None:
    loss = compute_profit_allocation(
        (
            ExecutedTradeV0(Side.BUY, base_atomic=10, quote_atomic=10),
            ExecutedTradeV0(Side.SELL, base_atomic=10, quote_atomic=9),
        ),
        profit_recycle_ratio=Fraction(1),
        banked_profit_ratio=Fraction(0),
    )
    assert loss.realized_pnl_quote_atomic == -1
    assert loss.recyclable_profit_quote_atomic == 0
    assert loss.banked_profit_quote_atomic == 0

    one = compute_profit_allocation(
        (
            ExecutedTradeV0(Side.BUY, base_atomic=2, quote_atomic=2),
            ExecutedTradeV0(Side.SELL, base_atomic=2, quote_atomic=3),
        ),
        profit_recycle_ratio=Fraction(1, 2),
        banked_profit_ratio=Fraction(1, 2),
    )
    assert one.realized_profit_quote_atomic == 1
    assert one.recyclable_profit_quote_atomic == 0
    assert one.banked_profit_quote_atomic == 0
    assert one.retained_profit_quote_atomic == 1


def test_recycling_fails_closed_on_oversell_or_ratio_overallocation() -> None:
    with pytest.raises(QntySpotError, match="exceeds accounted"):
        compute_profit_allocation(
            (ExecutedTradeV0(Side.SELL, base_atomic=1, quote_atomic=1),),
            profit_recycle_ratio=Fraction(0),
            banked_profit_ratio=Fraction(0),
        )

    with pytest.raises(QntySpotError, match="must not exceed 1"):
        compute_profit_allocation(
            (),
            profit_recycle_ratio=Fraction(3, 4),
            banked_profit_ratio=Fraction(1, 2),
        )
