from __future__ import annotations

from fractions import Fraction
from pathlib import Path

import pytest

from qntyspot.errors import AuthorityVerificationError, LevelNotExecutableError
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
    consume_ink_v0f_risk_artifact,
)
from qntyspot.prelive_economics import PositionConcurrencySnapshotV0

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")


def verified_policy():
    return consume_ink_v0f_risk_artifact(ARTIFACT.read_bytes())


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
    mutated = raw[:-1] + (b"}" if raw[-1:] != b"}" else b" ")
    with pytest.raises(AuthorityVerificationError, match="digest mismatch"):
        consume_ink_v0f_risk_artifact(mutated)


def test_entry_inside_every_frozen_bound_is_admissible() -> None:
    policy = verified_policy()
    assert_ink_v0f_entry_admissible(
        policy,
        network_id=INK_V0F_NETWORK_ID,
        venue_id=INK_V0F_VENUE_ID,
        pool_address=INK_V0F_POOL_ADDRESS,
        base_instrument_id=INK_V0F_BASE_INSTRUMENT_ID,
        quote_instrument_id=INK_V0F_QUOTE_INSTRUMENT_ID,
        entry_atomic=1_000_000_000_000_000,
        cumulative_entry_atomic_after=1_000_000_000_000_000,
        price_impact_bps=100,
        slippage_bps=50,
        concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("entry_atomic", 1_000_000_000_000_001, "entry exceeds"),
        ("cumulative_entry_atomic_after", 1_000_000_000_000_001, "cumulative"),
        ("price_impact_bps", 101, "price impact"),
        ("slippage_bps", 51, "slippage"),
    ),
)
def test_entry_widening_fails_closed(field: str, value: int, message: str) -> None:
    policy = verified_policy()
    kwargs = dict(
        network_id=INK_V0F_NETWORK_ID,
        venue_id=INK_V0F_VENUE_ID,
        pool_address=INK_V0F_POOL_ADDRESS,
        base_instrument_id=INK_V0F_BASE_INSTRUMENT_ID,
        quote_instrument_id=INK_V0F_QUOTE_INSTRUMENT_ID,
        entry_atomic=1_000_000_000_000_000,
        cumulative_entry_atomic_after=1_000_000_000_000_000,
        price_impact_bps=100,
        slippage_bps=50,
        concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
    )
    kwargs[field] = value
    with pytest.raises(LevelNotExecutableError, match=message):
        assert_ink_v0f_entry_admissible(policy, **kwargs)


def test_wrong_scope_and_concurrency_fail_closed() -> None:
    policy = verified_policy()
    with pytest.raises(LevelNotExecutableError, match="venue_id"):
        assert_ink_v0f_entry_admissible(
            policy,
            network_id=INK_V0F_NETWORK_ID,
            venue_id="other-venue",
            pool_address=INK_V0F_POOL_ADDRESS,
            base_instrument_id=INK_V0F_BASE_INSTRUMENT_ID,
            quote_instrument_id=INK_V0F_QUOTE_INSTRUMENT_ID,
            entry_atomic=1,
            cumulative_entry_atomic_after=1,
            price_impact_bps=1,
            slippage_bps=1,
            concurrency_snapshot=PositionConcurrencySnapshotV0(0, 0, 0, 0),
        )
    with pytest.raises(LevelNotExecutableError, match="POSITION_CEILING"):
        assert_ink_v0f_entry_admissible(
            policy,
            network_id=INK_V0F_NETWORK_ID,
            venue_id=INK_V0F_VENUE_ID,
            pool_address=INK_V0F_POOL_ADDRESS,
            base_instrument_id=INK_V0F_BASE_INSTRUMENT_ID,
            quote_instrument_id=INK_V0F_QUOTE_INSTRUMENT_ID,
            entry_atomic=1,
            cumulative_entry_atomic_after=1,
            price_impact_bps=1,
            slippage_bps=1,
            concurrency_snapshot=PositionConcurrencySnapshotV0(1, 1, 1, 0),
        )
