from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from qntyspot.domain import EconomicBounds, Side
from qntyspot.errors import AuthorityVerificationError, LevelNotExecutableError
from qntyspot.ink import (
    INKYSWAP_V2_BYTECODE_SHA256,
    INKYSWAP_V2_FACTORY,
    KRAKMASK_ADDRESS,
    V2_FEE_DENOMINATOR,
    V2_FEE_NUMERATOR,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    InkQuoteV0,
    InkShadowAdapter,
)
from qntyspot.ink_v0f_risk import (
    AUTHORITY_ROOT_SOURCE_MERGE_SHA,
    AUTHORITY_ROOT_SOURCE_REPOSITORY,
    INK_V0F_BASE_INSTRUMENT_ID,
    INK_V0F_NETWORK_ID,
    INK_V0F_POOL_ADDRESS,
    INK_V0F_QUOTE_INSTRUMENT_ID,
    INK_V0F_RISK_ARTIFACT_DIGEST,
    INK_V0F_VENUE_ID,
    assert_ink_v0f_entry_admissible,
    assert_ink_v0f_grant_window_admissible,
    consume_ink_v0f_risk_artifact,
)
from qntyspot.prelive_economics import PositionConcurrencySnapshotV0

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")


def verified_policy():
    return consume_ink_v0f_risk_artifact(ARTIFACT.read_bytes())


def observation(*, reserve0: int = 10**21, reserve1: int = 10**21) -> InkMarketObservationV0:
    return InkMarketObservationV0(
        schema="INK_MARKET_OBSERVATION_V0",
        chain_id=57_073,
        pool_address=INK_V0F_POOL_ADDRESS,
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


def bounds(*, max_input_atomic: int = 10**15, impact: int = 100, slippage: int = 50) -> EconomicBounds:
    return EconomicBounds(
        side=Side.BUY,
        input_instrument_id=INK_V0F_QUOTE_INSTRUMENT_ID,
        output_instrument_id=INK_V0F_BASE_INSTRUMENT_ID,
        max_input_atomic=max_input_atomic,
        min_output_atomic=1,
        limit_price=Fraction(1),
        max_price_impact_bps=impact,
        max_slippage_bps=slippage,
        deadline_epoch_s=1_800_000_000,
    )


def quote(obs: InkMarketObservationV0, *, input_atomic: int = 10**15) -> InkQuoteV0:
    return InkShadowAdapter._quote(obs, Side.BUY, input_atomic)


def test_vendored_artifact_is_exact_external_authority_root_identity() -> None:
    policy = verified_policy()
    assert AUTHORITY_ROOT_SOURCE_REPOSITORY == "CipherCuttle/QntyAuthorityRoot"
    assert AUTHORITY_ROOT_SOURCE_MERGE_SHA == "4f32c5b984e91c1b0704081cb4173666ec24251b"
    assert INK_V0F_RISK_ARTIFACT_DIGEST == (
        "c7058aec58f3fbcb4f2b390a6eac35bdb9d8cab2484a2ff22731f2dc586e8ee3"
    )
    assert SIDECAR.read_text(encoding="ascii") == (
        f"{INK_V0F_RISK_ARTIFACT_DIGEST}  {ARTIFACT.name}\n"
    )
    assert policy.max_entry_atomic == 1_000_000_000_000_000
    assert policy.max_cumulative_entry_atomic == 1_000_000_000_000_000
    assert policy.concurrency.max_open_positions_global == 1
    assert policy.concurrency.max_open_positions_per_network == 1
    assert policy.concurrency.max_open_positions_per_instrument == 1
    assert policy.concurrency.max_in_flight_entries == 1
    assert policy.max_price_impact_bps == 100
    assert policy.max_slippage_bps == 50
    assert policy.profit_recycle_ratio == Fraction(0, 1)
    assert policy.banked_profit_ratio == Fraction(1, 1)


def test_any_artifact_byte_change_fails_before_policy_use() -> None:
    raw = ARTIFACT.read_bytes()
    with pytest.raises(AuthorityVerificationError, match="digest mismatch"):
        consume_ink_v0f_risk_artifact(raw + b" ")


def test_entry_is_bound_to_observation_quote_and_committed_bounds() -> None:
    policy = verified_policy()
    obs = observation()
    assert_ink_v0f_entry_admissible(
        policy,
        observation=obs,
        quote=quote(obs),
        bounds=bounds(),
        cumulative_entry_atomic_after=10**15,
        concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
    )


def test_quote_from_a_different_observation_fails_closed() -> None:
    policy = verified_policy()
    obs = observation()
    other = replace(obs, common_block=124)
    with pytest.raises(LevelNotExecutableError, match="not bound"):
        assert_ink_v0f_entry_admissible(
            policy,
            observation=other,
            quote=quote(obs),
            bounds=bounds(),
            cumulative_entry_atomic_after=10**15,
            concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
        )


@pytest.mark.parametrize(
    ("bound_kwargs", "quote_input", "quote_impact", "message"),
    (
        ({"max_input_atomic": 10**15 + 1}, 10**15, Fraction(100), "committed input"),
        ({"impact": 101}, 10**15, Fraction(100), "policy price-impact"),
        ({"slippage": 51}, 10**15, Fraction(100), "policy slippage"),
        ({}, 10**15 + 1, Fraction(100), "quote input"),
        ({}, 10**15, Fraction(101), "canonical reserve-derived"),
    ),
)
def test_entry_widening_fails_closed(bound_kwargs, quote_input, quote_impact, message) -> None:
    policy = verified_policy()
    obs = observation()
    with pytest.raises(LevelNotExecutableError, match=message):
        assert_ink_v0f_entry_admissible(
            policy,
            observation=obs,
            quote=(
                replace(quote(obs, input_atomic=quote_input), price_impact_bps=quote_impact)
                if quote_impact != quote(obs, input_atomic=quote_input).price_impact_bps
                else quote(obs, input_atomic=quote_input)
            ),
            bounds=bounds(**bound_kwargs),
            cumulative_entry_atomic_after=max(quote_input, 10**15),
            concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
        )


def test_wrong_instrument_scope_and_concurrency_fail_closed() -> None:
    policy = verified_policy()
    obs = observation()
    wrong_bounds = EconomicBounds(
        side=Side.BUY,
        input_instrument_id=INK_V0F_BASE_INSTRUMENT_ID,
        output_instrument_id=INK_V0F_QUOTE_INSTRUMENT_ID,
        max_input_atomic=1,
        min_output_atomic=1,
        limit_price=Fraction(1),
        max_price_impact_bps=1,
        max_slippage_bps=1,
        deadline_epoch_s=1_800_000_000,
    )
    with pytest.raises(LevelNotExecutableError, match="input instrument"):
        assert_ink_v0f_entry_admissible(
            policy,
            observation=obs,
            quote=quote(obs, input_atomic=1),
            bounds=wrong_bounds,
            cumulative_entry_atomic_after=1,
            concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
        )

    with pytest.raises(LevelNotExecutableError, match="POSITION_CEILING"):
        assert_ink_v0f_entry_admissible(
            policy,
            observation=obs,
            quote=quote(obs, input_atomic=1),
            bounds=bounds(max_input_atomic=1, impact=1, slippage=1),
            cumulative_entry_atomic_after=1,
            concurrency_snapshot=PositionConcurrencySnapshotV0(1, 1, 1, 0),
        )


def test_canonical_reserve_derived_quote_above_impact_cap_fails_closed() -> None:
    policy = verified_policy()
    obs = observation(reserve0=5 * 10**16, reserve1=5 * 10**16)
    q = quote(obs, input_atomic=10**15)
    assert q.price_impact_bps > 100
    with pytest.raises(LevelNotExecutableError, match="quoted price impact"):
        assert_ink_v0f_entry_admissible(
            policy,
            observation=obs,
            quote=q,
            bounds=bounds(),
            cumulative_entry_atomic_after=10**15,
            concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
        )


def test_grant_window_must_fit_the_external_dust_policy() -> None:
    policy = verified_policy()
    assert_ink_v0f_grant_window_admissible(
        policy,
        not_before_epoch_s=1_700_000_000,
        not_after_epoch_s=1_700_000_900,
    )
    with pytest.raises(LevelNotExecutableError, match="exceeds"):
        assert_ink_v0f_grant_window_admissible(
            policy,
            not_before_epoch_s=1_700_000_000,
            not_after_epoch_s=1_700_000_901,
        )
