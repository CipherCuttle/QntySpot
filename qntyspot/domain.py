"""Immutable domain model for QntySpot V0A.

Everything here is a frozen dataclass. Nothing here performs I/O, reads the
environment, or touches a network. Amounts are integer atomic units; prices and
ratios are exact :class:`~fractions.Fraction` values.

In ``canonical_object()`` output -- the form that gets digested and written to
the log -- every atomic amount is rendered as a decimal STRING and every price
as a canonical decimal string. Atomic amounts routinely exceed 2**53 and 2**63
(an 18-decimal token passes both at trivial sizes), so emitting them as JSON
numbers would hand a rounding bug to any consumer whose integers are not
arbitrary precision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from typing import Any, Mapping

from .canon import digest_object, format_canonical_decimal
from .errors import PolicySchemaError, QntySpotError
from .identity import InstrumentV0
from .states import IntentState

__all__ = [
    "Side",
    "LadderKind",
    "CycleStatus",
    "ReservationStatus",
    "LadderLevelV0",
    "LadderV0",
    "PolicyV0",
    "CycleV0",
    "EconomicBounds",
    "IntentV0",
    "QuoteV0",
    "ExecutionPlanV0",
    "FillReceiptV0",
    "PortfolioBudgetV0",
    "RuntimeStateV0",
    "economic_action_id",
    "ceil_div",
]

BPS_DENOMINATOR = 10_000


def ceil_div(num: int, den: int) -> int:
    """Integer ceiling division. ``den`` must be positive."""
    if den <= 0:
        raise QntySpotError("ceil_div denominator must be positive")
    return -((-num) // den)


class Side(str, Enum):
    BUY = "BUY"
    SELL = "SELL"

    @property
    def opposite(self) -> "Side":
        return Side.SELL if self is Side.BUY else Side.BUY


class LadderKind(str, Enum):
    """Which half of a cycle a ladder level belongs to.

    ``ENTRY`` levels open exposure in the policy's ``side``. ``EXIT`` levels
    close it in the opposite side. A BUY policy therefore has BUY entries and
    SELL exits; a SELL policy has SELL entries and BUY exits.
    """

    ENTRY = "ENTRY"
    EXIT = "EXIT"


class CycleStatus(str, Enum):
    OPEN = "OPEN"
    COMPLETED = "COMPLETED"
    HALTED = "HALTED"


class ReservationStatus(str, Enum):
    #: Held against the caps, outcome still open.
    ACTIVE = "ACTIVE"
    #: The action filled. The capital is spent and keeps counting.
    COMMITTED = "COMMITTED"
    #: The action provably did not and cannot happen. The capital is free.
    RELEASED = "RELEASED"
    #: The action's outcome is unknown and the ledger cannot resolve it. The
    #: capital stays counted against every cap until a human or a future
    #: reconciler decides. Releasing it would let the portfolio commit the same
    #: capital a second time while the original may still settle.
    QUARANTINED = "QUARANTINED"


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LadderLevelV0:
    """One explicit rung. V0A has no generated ladders: every rung is written down."""

    level_id: str
    kind: LadderKind
    side: Side
    index: int
    trigger_price: Fraction
    #: ENTRY only. Amount of the leg's input currency to spend at this rung.
    input_amount: Fraction | None = None
    #: EXIT only. Fraction of the inventory accumulated by the entry ladder.
    input_ratio: Fraction | None = None

    def __post_init__(self) -> None:
        if self.kind is LadderKind.ENTRY:
            if self.input_amount is None or self.input_ratio is not None:
                raise PolicySchemaError(
                    f"entry level {self.level_id}: requires input_amount, forbids input_ratio"
                )
            if self.input_amount <= 0:
                raise PolicySchemaError(
                    f"entry level {self.level_id}: input_amount must be > 0"
                )
        else:
            if self.input_ratio is None or self.input_amount is not None:
                raise PolicySchemaError(
                    f"exit level {self.level_id}: requires input_ratio, forbids input_amount"
                )
            if not (0 < self.input_ratio <= 1):
                raise PolicySchemaError(
                    f"exit level {self.level_id}: input_ratio must be in (0, 1]"
                )
        if self.trigger_price <= 0:
            raise PolicySchemaError(
                f"level {self.level_id}: trigger_price must be > 0"
            )

    def canonical_object(self) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "level_id": self.level_id,
            "trigger_price": format_canonical_decimal(self.trigger_price),
        }
        if self.input_amount is not None:
            obj["input_amount"] = format_canonical_decimal(self.input_amount)
        if self.input_ratio is not None:
            obj["input_ratio"] = format_canonical_decimal(self.input_ratio)
        return obj


@dataclass(frozen=True, slots=True)
class LadderV0:
    kind: LadderKind
    side: Side
    levels: tuple[LadderLevelV0, ...]

    def __post_init__(self) -> None:
        if not self.levels:
            raise PolicySchemaError(f"{self.kind.value} ladder must have at least one level")
        # Strict monotonicity in the direction the side implies. A BUY leg
        # ladders down into weakness; a SELL leg ladders up into strength.
        # Non-monotone ladders make "next eligible level" ambiguous during
        # replay, and ambiguity is not permitted to resolve itself.
        descending = self.side is Side.BUY
        for prev, cur in zip(self.levels, self.levels[1:]):
            ok = cur.trigger_price < prev.trigger_price if descending else cur.trigger_price > prev.trigger_price
            if not ok:
                direction = "strictly decreasing" if descending else "strictly increasing"
                raise PolicySchemaError(
                    f"{self.kind.value} ladder trigger prices must be {direction} "
                    f"for a {self.side.value} leg (at level {cur.level_id})"
                )

    def canonical_object(self) -> dict[str, Any]:
        return {"levels": [lvl.canonical_object() for lvl in self.levels]}


@dataclass(frozen=True, slots=True)
class PortfolioBudgetV0:
    """Quote-denominated caps, in atomic units of the quote instrument.

    Only quote capital is reserved. A SELL leg returns quote rather than
    consuming it, so it takes no reservation; the BUY legs of a cycle are what
    put capital at risk.
    """

    allocation_atomic: int
    per_order_cap_atomic: int
    per_instrument_cap_atomic: int
    per_network_cap_atomic: int
    global_cap_atomic: int
    reserved_cash_atomic: int

    def __post_init__(self) -> None:
        for name in (
            "allocation_atomic",
            "per_order_cap_atomic",
            "per_instrument_cap_atomic",
            "per_network_cap_atomic",
            "global_cap_atomic",
        ):
            if getattr(self, name) <= 0:
                raise PolicySchemaError(f"{name} must be > 0")
        if self.reserved_cash_atomic < 0:
            raise PolicySchemaError("reserved_cash_atomic must be >= 0")
        if self.per_order_cap_atomic > self.allocation_atomic:
            raise PolicySchemaError("per_order_cap must not exceed allocation")
        if self.allocation_atomic > self.per_instrument_cap_atomic:
            raise PolicySchemaError("allocation must not exceed per_instrument_cap")
        if self.per_instrument_cap_atomic > self.per_network_cap_atomic:
            raise PolicySchemaError("per_instrument_cap must not exceed per_network_cap")
        if self.per_network_cap_atomic > self.global_cap_atomic:
            raise PolicySchemaError("per_network_cap must not exceed global_cap")
        if self.reserved_cash_atomic >= self.global_cap_atomic:
            raise PolicySchemaError(
                "reserved_cash must be strictly less than global_cap, "
                "otherwise no order can ever be admitted"
            )

    @property
    def spendable_global_atomic(self) -> int:
        """Global cap net of the cash that must remain unspent."""
        return self.global_cap_atomic - self.reserved_cash_atomic


@dataclass(frozen=True, slots=True)
class PolicyV0:
    """An admitted policy. Its ``policy_id`` is the SHA-256 of its canonical form."""

    policy_name: str
    base: InstrumentV0
    quote: InstrumentV0
    side: Side
    entry_ladder: LadderV0
    exit_ladder: LadderV0
    budget: PortfolioBudgetV0
    max_executable_price: Fraction
    min_executable_price: Fraction
    max_price_impact_bps: int
    max_slippage_bps: int
    valid_from_epoch_s: int
    expiry_epoch_s: int
    quote_ttl_s: int
    max_cycles: int
    rearm_hysteresis_bps: int
    rearm_cooldown_s: int
    profit_recycle_ratio: Fraction
    banked_profit_ratio: Fraction
    canonical: Mapping[str, Any] = field(repr=False)

    @property
    def policy_id(self) -> str:
        return digest_object(dict(self.canonical))

    @property
    def instrument_id(self) -> str:
        return self.base.instrument_id

    @property
    def quote_instrument_id(self) -> str:
        return self.quote.instrument_id

    @property
    def network_id(self) -> str:
        return self.base.network_id

    def levels(self) -> tuple[LadderLevelV0, ...]:
        return self.entry_ladder.levels + self.exit_ladder.levels

    def level(self, level_id: str) -> LadderLevelV0:
        for lvl in self.levels():
            if lvl.level_id == level_id:
                return lvl
        raise PolicySchemaError(f"unknown level_id {level_id!r} for policy {self.policy_name}")


# --------------------------------------------------------------------------
# Runtime records
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CycleV0:
    cycle_id: str
    policy_id: str
    cycle_index: int
    status: CycleStatus

    def __post_init__(self) -> None:
        if self.cycle_index < 0:
            raise QntySpotError("cycle_index must be >= 0")


def economic_action_id(
    *,
    policy_id: str,
    instrument_id: str,
    cycle_id: str,
    level_id: str,
    side: Side,
) -> str:
    """Deterministic identity of one economic action.

    The tuple ``(policy_id, instrument_id, cycle_id, level_id, side)`` names an
    action that may happen at most once, ever. The same digest is enforced as a
    PRIMARY KEY and as a UNIQUE constraint over the component columns in the
    SQLite schema, so uniqueness does not depend on any application-level
    check-then-insert.
    """
    return digest_object(
        {
            "v": "qntyspot.economic_action.v0",
            "policy_id": policy_id,
            "instrument_id": instrument_id,
            "cycle_id": cycle_id,
            "level_id": level_id,
            "side": side.value,
        }
    )


@dataclass(frozen=True, slots=True)
class EconomicBounds:
    """The absolute economic limit a future execution adapter must encode.

    A pre-trade trigger is not a limit. These bounds are what a transaction or
    venue order must carry so that it cannot legitimately settle outside the
    policy, regardless of what happens between decision and settlement:

    ``BUY``   ``max_input_atomic`` is max_total_input (quote spent),
              ``min_output_atomic`` is the minimum base received, and
              ``limit_price`` is max_effective_price.

    ``SELL``  ``max_input_atomic`` is the maximum base quantity released,
              ``min_output_atomic`` is minimum_total_output (quote received),
              and ``limit_price`` is min_effective_price.

    ``min_output_atomic`` is derived from ``max_input_atomic`` and
    ``limit_price`` by exact rational arithmetic rounded UP, so the encoded
    bound is never looser than the policy's limit.
    """

    side: Side
    input_instrument_id: str
    output_instrument_id: str
    max_input_atomic: int
    min_output_atomic: int
    limit_price: Fraction
    max_price_impact_bps: int
    max_slippage_bps: int
    deadline_epoch_s: int

    def __post_init__(self) -> None:
        if self.max_input_atomic <= 0:
            raise QntySpotError("max_input_atomic must be > 0")
        if self.min_output_atomic <= 0:
            raise QntySpotError("min_output_atomic must be > 0")
        if self.limit_price <= 0:
            raise QntySpotError("limit_price must be > 0")
        if self.input_instrument_id == self.output_instrument_id:
            raise QntySpotError("input and output instruments must differ")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "side": self.side.value,
            "input_instrument_id": self.input_instrument_id,
            "output_instrument_id": self.output_instrument_id,
            "max_input_atomic": str(self.max_input_atomic),
            "min_output_atomic": str(self.min_output_atomic),
            "limit_price": format_canonical_decimal(self.limit_price),
            "max_price_impact_bps": self.max_price_impact_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "deadline_epoch_s": self.deadline_epoch_s,
        }


@dataclass(frozen=True, slots=True)
class IntentV0:
    economic_action_id: str
    policy_id: str
    instrument_id: str
    quote_instrument_id: str
    network_id: str
    cycle_id: str
    level_id: str
    side: Side
    kind: LadderKind
    bounds: EconomicBounds
    #: Quote-denominated capital this intent puts at risk. Zero for SELL legs.
    quote_exposure_atomic: int
    state: IntentState = IntentState.ARMED

    def canonical_object(self) -> dict[str, Any]:
        return {
            "economic_action_id": self.economic_action_id,
            "policy_id": self.policy_id,
            "instrument_id": self.instrument_id,
            "quote_instrument_id": self.quote_instrument_id,
            "network_id": self.network_id,
            "cycle_id": self.cycle_id,
            "level_id": self.level_id,
            "side": self.side.value,
            "kind": self.kind.value,
            "bounds": self.bounds.canonical_object(),
            "quote_exposure_atomic": str(self.quote_exposure_atomic),
        }


@dataclass(frozen=True, slots=True)
class QuoteV0:
    """A pinned, offline-supplied quote.

    V0A never fetches a quote. A quote reaches the core only as an explicit
    local input (a fixture, or a future adapter's already-obtained result).
    """

    quote_id: str
    economic_action_id: str
    input_atomic: int
    output_atomic: int
    pinned_at_epoch_s: int
    expires_at_epoch_s: int
    source: str

    def __post_init__(self) -> None:
        if self.input_atomic <= 0 or self.output_atomic <= 0:
            raise QntySpotError("quote amounts must be > 0")
        if self.expires_at_epoch_s <= self.pinned_at_epoch_s:
            raise QntySpotError("quote must expire after it is pinned")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "quote_id": self.quote_id,
            "economic_action_id": self.economic_action_id,
            "input_atomic": str(self.input_atomic),
            "output_atomic": str(self.output_atomic),
            "pinned_at_epoch_s": self.pinned_at_epoch_s,
            "expires_at_epoch_s": self.expires_at_epoch_s,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class ExecutionPlanV0:
    """What a future adapter would need in order to build a transaction.

    V0A constructs no calldata, no instruction, and no order payload. This is a
    description of intent and its absolute bounds, nothing more.
    """

    plan_id: str
    economic_action_id: str
    quote_id: str
    bounds: EconomicBounds
    venue_hint: str | None = None

    def canonical_object(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "economic_action_id": self.economic_action_id,
            "quote_id": self.quote_id,
            "bounds": self.bounds.canonical_object(),
            "venue_hint": self.venue_hint,
        }


@dataclass(frozen=True, slots=True)
class FillReceiptV0:
    """External truth about what actually settled.

    In V0A a receipt only ever arrives from a local fixture. A future
    reconciler converts venue or chain truth into this shape; the core never
    invents one.
    """

    receipt_id: str
    economic_action_id: str
    external_ref: str
    input_atomic_filled: int
    output_atomic_filled: int
    fee_atomic: int
    observed_at_epoch_s: int
    source: str

    def __post_init__(self) -> None:
        if self.input_atomic_filled <= 0 or self.output_atomic_filled <= 0:
            raise QntySpotError("fill amounts must be > 0")
        if self.fee_atomic < 0:
            raise QntySpotError("fee_atomic must be >= 0")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "economic_action_id": self.economic_action_id,
            "external_ref": self.external_ref,
            "input_atomic_filled": str(self.input_atomic_filled),
            "output_atomic_filled": str(self.output_atomic_filled),
            "fee_atomic": str(self.fee_atomic),
            "observed_at_epoch_s": self.observed_at_epoch_s,
            "source": self.source,
        }

    def satisfies(self, bounds: EconomicBounds) -> bool:
        """Whether the settled amounts respect the bounds that were committed."""
        return (
            self.input_atomic_filled <= bounds.max_input_atomic
            and self.output_atomic_filled >= _prorated_min_output(self, bounds)
        )


def _prorated_min_output(receipt: FillReceiptV0, bounds: EconomicBounds) -> int:
    """Minimum output for a possibly-partial fill, at the same limit price.

    A partial fill must respect the same price bound as a full one, so the
    floor scales with how much input was actually consumed. Rounded UP, which
    is the direction that keeps the bound at least as strict.
    """
    return ceil_div(
        bounds.min_output_atomic * receipt.input_atomic_filled,
        bounds.max_input_atomic,
    )


@dataclass(frozen=True, slots=True)
class RuntimeStateV0:
    """A canonical, comparable snapshot of everything the ledger holds."""

    schema_version: int
    policies: tuple[Mapping[str, Any], ...]
    instruments: tuple[Mapping[str, Any], ...]
    cycles: tuple[Mapping[str, Any], ...]
    ladder_levels: tuple[Mapping[str, Any], ...]
    intents: tuple[Mapping[str, Any], ...]
    state_events: tuple[Mapping[str, Any], ...]
    budget_reservations: tuple[Mapping[str, Any], ...]
    fill_receipts: tuple[Mapping[str, Any], ...]
    #: Derived per-cycle projections: inventory, realized proceeds, next
    #: eligible rungs. Included in the digest so replay must reproduce the
    #: conclusions drawn from the log, not merely the log itself.
    derived: tuple[Mapping[str, Any], ...] = ()

    def canonical_object(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "policies": [dict(r) for r in self.policies],
            "instruments": [dict(r) for r in self.instruments],
            "cycles": [dict(r) for r in self.cycles],
            "ladder_levels": [dict(r) for r in self.ladder_levels],
            "intents": [dict(r) for r in self.intents],
            "state_events": [dict(r) for r in self.state_events],
            "budget_reservations": [dict(r) for r in self.budget_reservations],
            "fill_receipts": [dict(r) for r in self.fill_receipts],
            "derived": [dict(r) for r in self.derived],
        }

    def digest(self) -> str:
        return digest_object(self.canonical_object())
