"""Fail-closed consumer for the canonical Ink V0F dust-risk artifact.

This module grants no signing, submission, approval, or live-capital authority.
It consumes one exact immutable artifact produced by CipherCuttle/QntyAuthorityRoot
and exposes only deterministic admission checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .canon import canonical_json_bytes, sha256_hex, strict_json_loads
from .errors import AuthorityVerificationError, LevelNotExecutableError
from .prelive_economics import (
    DustLiveConcurrencyV0,
    PositionConcurrencySnapshotV0,
    assert_new_entry_concurrency,
)

AUTHORITY_ROOT_SOURCE_REPOSITORY = "CipherCuttle/QntyAuthorityRoot"
AUTHORITY_ROOT_SOURCE_MERGE_SHA = "4f32c5b984e91c1b0704081cb4173666ec24251b"
INK_V0F_RISK_SCHEMA = "qnty.authority_root.ink_v0f_dust_risk_policy.v0"
INK_V0F_RISK_ARTIFACT_DIGEST = (
    "c7058aec58f3fbcb4f2b390a6eac35bdb9d8cab2484a2ff22731f2dc586e8ee3"
)

INK_V0F_NETWORK_ID = "evm:57073"
INK_V0F_VENUE_ID = "inkyswap-v2-ink-mainnet"
INK_V0F_POOL_ADDRESS = "0xed11ed4b195e84ba9b74c4d6ce13b7a43b354264"
INK_V0F_BASE_INSTRUMENT_ID = (
    "evm:57073:0x32bcb803f696c99eb263d60a05cafd8689026575"
)
INK_V0F_QUOTE_INSTRUMENT_ID = (
    "evm:57073:0x4200000000000000000000000000000000000006"
)

_EXPECTED_FIELDS = {
    "banked_profit_ratio",
    "base_instrument_id",
    "max_cumulative_entry_atomic",
    "max_entry_atomic",
    "max_grant_duration_s",
    "max_in_flight_entries",
    "max_open_positions_global",
    "max_open_positions_per_instrument",
    "max_open_positions_per_network",
    "max_price_impact_bps",
    "max_slippage_bps",
    "network_id",
    "pool_address",
    "profit_recycle_ratio",
    "quote_instrument_id",
    "repository_identity",
    "schema",
    "venue_id",
}


def _atomic_string(value: Any, *, field: str) -> int:
    if type(value) is not str or not value or not value.isdigit():
        raise AuthorityVerificationError(f"{field}: expected canonical positive atomic string")
    if value.startswith("0"):
        raise AuthorityVerificationError(f"{field}: leading zero is forbidden")
    parsed = int(value)
    if parsed <= 0 or str(parsed) != value:
        raise AuthorityVerificationError(f"{field}: non-canonical atomic value")
    return parsed


def _positive_int(value: Any, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise AuthorityVerificationError(f"{field}: expected positive integer")
    return value


def _bps(value: Any, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 10_000:
        raise AuthorityVerificationError(f"{field}: expected basis points in [0, 10000]")
    return value


def _ratio(value: Any, *, field: str) -> Fraction:
    if type(value) is not dict or set(value) != {"numerator", "denominator"}:
        raise AuthorityVerificationError(f"{field}: malformed exact ratio")
    numerator = value["numerator"]
    denominator = value["denominator"]
    if type(numerator) is not str or type(denominator) is not str:
        raise AuthorityVerificationError(f"{field}: ratio parts must be integer strings")
    if not numerator.isdigit() or not denominator.isdigit() or denominator == "0":
        raise AuthorityVerificationError(f"{field}: invalid ratio")
    if (numerator != "0" and numerator.startswith("0")) or denominator.startswith("0"):
        raise AuthorityVerificationError(f"{field}: non-canonical ratio")
    return Fraction(int(numerator), int(denominator))


@dataclass(frozen=True, slots=True)
class InkV0FRiskPolicyV0:
    repository_identity: str
    network_id: str
    venue_id: str
    pool_address: str
    base_instrument_id: str
    quote_instrument_id: str
    max_entry_atomic: int
    max_cumulative_entry_atomic: int
    concurrency: DustLiveConcurrencyV0
    max_price_impact_bps: int
    max_slippage_bps: int
    max_grant_duration_s: int
    profit_recycle_ratio: Fraction
    banked_profit_ratio: Fraction
    artifact_digest: str = INK_V0F_RISK_ARTIFACT_DIGEST

    def __post_init__(self) -> None:
        if self.repository_identity != "CipherCuttle/QntySpot":
            raise AuthorityVerificationError("risk artifact targets the wrong repository")
        if self.network_id != INK_V0F_NETWORK_ID:
            raise AuthorityVerificationError("risk artifact targets the wrong network")
        if self.venue_id != INK_V0F_VENUE_ID:
            raise AuthorityVerificationError("risk artifact targets the wrong venue")
        if self.pool_address != INK_V0F_POOL_ADDRESS:
            raise AuthorityVerificationError("risk artifact targets the wrong pool")
        if self.base_instrument_id != INK_V0F_BASE_INSTRUMENT_ID:
            raise AuthorityVerificationError("risk artifact targets the wrong base instrument")
        if self.quote_instrument_id != INK_V0F_QUOTE_INSTRUMENT_ID:
            raise AuthorityVerificationError("risk artifact targets the wrong quote instrument")
        if self.max_entry_atomic != 1_000_000_000_000_000:
            raise AuthorityVerificationError("unexpected Ink V0F entry cap")
        if self.max_cumulative_entry_atomic != 1_000_000_000_000_000:
            raise AuthorityVerificationError("unexpected Ink V0F cumulative cap")
        if self.concurrency != DustLiveConcurrencyV0(1, 1, 1, 1):
            raise AuthorityVerificationError("unexpected Ink V0F concurrency envelope")
        if self.max_price_impact_bps != 100:
            raise AuthorityVerificationError("unexpected Ink V0F price-impact cap")
        if self.max_slippage_bps != 50:
            raise AuthorityVerificationError("unexpected Ink V0F slippage cap")
        if self.max_grant_duration_s != 900:
            raise AuthorityVerificationError("unexpected Ink V0F grant duration")
        if self.profit_recycle_ratio != Fraction(0, 1):
            raise AuthorityVerificationError("Ink V0F profit recycling must be disabled")
        if self.banked_profit_ratio != Fraction(1, 1):
            raise AuthorityVerificationError("Ink V0F profit banking must be 100%")


def consume_ink_v0f_risk_artifact(raw: bytes) -> InkV0FRiskPolicyV0:
    """Verify exact external bytes and return the frozen internal contract."""

    if type(raw) is not bytes:
        raise AuthorityVerificationError("Ink V0F risk artifact must be explicit bytes")
    digest = sha256_hex(raw)
    if digest != INK_V0F_RISK_ARTIFACT_DIGEST:
        raise AuthorityVerificationError(
            f"Ink V0F risk artifact digest mismatch: expected "
            f"{INK_V0F_RISK_ARTIFACT_DIGEST}, got {digest}"
        )
    try:
        document = strict_json_loads(raw)
    except Exception as exc:
        raise AuthorityVerificationError("Ink V0F risk artifact is not strict JSON") from exc
    if type(document) is not dict or set(document) != _EXPECTED_FIELDS:
        raise AuthorityVerificationError("Ink V0F risk artifact has unknown or missing fields")
    if canonical_json_bytes(document) != raw:
        raise AuthorityVerificationError("Ink V0F risk artifact is not canonical JSON")
    if document["schema"] != INK_V0F_RISK_SCHEMA:
        raise AuthorityVerificationError("Ink V0F risk artifact schema mismatch")

    return InkV0FRiskPolicyV0(
        repository_identity=document["repository_identity"],
        network_id=document["network_id"],
        venue_id=document["venue_id"],
        pool_address=document["pool_address"],
        base_instrument_id=document["base_instrument_id"],
        quote_instrument_id=document["quote_instrument_id"],
        max_entry_atomic=_atomic_string(document["max_entry_atomic"], field="max_entry_atomic"),
        max_cumulative_entry_atomic=_atomic_string(
            document["max_cumulative_entry_atomic"],
            field="max_cumulative_entry_atomic",
        ),
        concurrency=DustLiveConcurrencyV0(
            _positive_int(document["max_open_positions_global"], field="max_open_positions_global"),
            _positive_int(document["max_open_positions_per_network"], field="max_open_positions_per_network"),
            _positive_int(
                document["max_open_positions_per_instrument"],
                field="max_open_positions_per_instrument",
            ),
            _positive_int(document["max_in_flight_entries"], field="max_in_flight_entries"),
        ),
        max_price_impact_bps=_bps(document["max_price_impact_bps"], field="max_price_impact_bps"),
        max_slippage_bps=_bps(document["max_slippage_bps"], field="max_slippage_bps"),
        max_grant_duration_s=_positive_int(
            document["max_grant_duration_s"], field="max_grant_duration_s"
        ),
        profit_recycle_ratio=_ratio(
            document["profit_recycle_ratio"], field="profit_recycle_ratio"
        ),
        banked_profit_ratio=_ratio(
            document["banked_profit_ratio"], field="banked_profit_ratio"
        ),
    )


def assert_ink_v0f_entry_admissible(
    policy: InkV0FRiskPolicyV0,
    *,
    network_id: str,
    venue_id: str,
    pool_address: str,
    base_instrument_id: str,
    quote_instrument_id: str,
    entry_atomic: int,
    cumulative_entry_atomic_after: int,
    price_impact_bps: int,
    slippage_bps: int,
    concurrency_snapshot: PositionConcurrencySnapshotV0,
) -> None:
    """Fail closed unless an ENTRY is inside every frozen V0F risk bound."""

    if type(policy) is not InkV0FRiskPolicyV0:
        raise AuthorityVerificationError("Ink V0F policy object is not verified")
    for field, actual, expected in (
        ("network_id", network_id, policy.network_id),
        ("venue_id", venue_id, policy.venue_id),
        ("pool_address", pool_address, policy.pool_address),
        ("base_instrument_id", base_instrument_id, policy.base_instrument_id),
        ("quote_instrument_id", quote_instrument_id, policy.quote_instrument_id),
    ):
        if actual != expected:
            raise LevelNotExecutableError(f"Ink V0F {field} is outside the frozen scope")

    if type(entry_atomic) is not int or isinstance(entry_atomic, bool) or entry_atomic <= 0:
        raise LevelNotExecutableError("Ink V0F entry amount must be positive integer atomics")
    if entry_atomic > policy.max_entry_atomic:
        raise LevelNotExecutableError("Ink V0F entry exceeds the dust cap")
    if (
        type(cumulative_entry_atomic_after) is not int
        or isinstance(cumulative_entry_atomic_after, bool)
        or cumulative_entry_atomic_after < entry_atomic
    ):
        raise LevelNotExecutableError("Ink V0F cumulative entry accounting is invalid")
    if cumulative_entry_atomic_after > policy.max_cumulative_entry_atomic:
        raise LevelNotExecutableError("Ink V0F cumulative entry capital exceeds the dust cap")
    if _bps(price_impact_bps, field="price_impact_bps") > policy.max_price_impact_bps:
        raise LevelNotExecutableError("Ink V0F price impact exceeds the frozen cap")
    if _bps(slippage_bps, field="slippage_bps") > policy.max_slippage_bps:
        raise LevelNotExecutableError("Ink V0F slippage exceeds the frozen cap")
    assert_new_entry_concurrency(policy.concurrency, concurrency_snapshot)
