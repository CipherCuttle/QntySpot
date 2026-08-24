"""Strict PolicyV0 reader.

ADMISSION RULES
---------------
* A missing policy fails startup (:class:`PolicyMissingError`).
* Malformed JSON fails closed.
* A duplicate JSON key fails closed (enforced in :mod:`qntyspot.canon`).
* An unknown key -- at any depth -- fails closed. V0A declares no extension
  point; a field the schema does not name is a field this runtime does not
  understand, and proceeding without understanding it is the failure mode the
  whole design exists to prevent.
* A JSON float fails closed. Economic values arrive as canonical decimal
  strings; counts, timestamps and basis points arrive as JSON integers.

The canonical form a policy digests to is itself an admissible policy
document: ``parse_policy(policy.canonical)`` yields the same ``policy_id``.
That is what lets replay rebuild policies from stored canonical JSON, and it
is asserted in ``tests/test_policy.py``.

Cross-field checks here reject only what could *never* execute: a rung priced
outside the hard executable-price limit, or a rung larger than the per-order
cap. Capacity questions -- whether the ladder as a whole fits inside the
allocation -- belong to the ledger's reservation guard, not to the parser.

There are no optional economic parameters with silently-chosen defaults. The
one optional block, ``recycling``, defaults to zero on both ratios, meaning
"recycle nothing, bank nothing". That is the inert choice, not a
recommendation, and this module makes no claim that any value is optimal.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any, Callable, Iterable, Mapping

from .canon import (
    format_canonical_decimal,
    parse_canonical_decimal,
    strict_json_loads,
    to_atomic,
)
from .domain import (
    BPS_DENOMINATOR,
    LadderKind,
    LadderLevelV0,
    LadderV0,
    PolicyV0,
    PortfolioBudgetV0,
    Side,
)
from .errors import PolicyMissingError, PolicySchemaError
from .identity import AssetClass, InstrumentV0, parse_instrument_ref

__all__ = ["POLICY_SCHEMA_ID", "parse_policy", "load_policy_text", "load_policy_file"]

POLICY_SCHEMA_ID = "qntyspot.policy.v0"

_MAX_LEVELS_PER_LADDER = 64
_MAX_EPOCH_S = 4_102_444_800  # 2100-01-01T00:00:00Z; a sanity ceiling, not a policy view.


class _Obj:
    """A JSON object being consumed key-by-key. Leftover keys are an error."""

    def __init__(self, raw: Any, path: str) -> None:
        if not isinstance(raw, dict):
            raise PolicySchemaError(f"{path}: expected an object, got {_kind(raw)}")
        self._raw = dict(raw)
        self._path = path

    def take(self, key: str) -> Any:
        if key not in self._raw:
            raise PolicySchemaError(f"{self._path}.{key}: required key is missing")
        return self._raw.pop(key)

    def take_optional(self, key: str) -> Any:
        return self._raw.pop(key, _MISSING)

    def done(self) -> None:
        if self._raw:
            raise PolicySchemaError(
                f"{self._path}: unknown keys {sorted(self._raw)} "
                "(V0A declares no extension point)"
            )


class _Missing:
    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "<missing>"


_MISSING = _Missing()


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    return type(value).__name__


def _int(value: Any, path: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicySchemaError(f"{path}: expected a JSON integer, got {_kind(value)}")
    if not (minimum <= value <= maximum):
        raise PolicySchemaError(f"{path}: {value} out of range [{minimum}, {maximum}]")
    return value


def _bps(value: Any, path: str) -> int:
    return _int(value, path, minimum=0, maximum=BPS_DENOMINATOR)


def _decimal(value: Any, path: str, *, allow_zero: bool = False) -> Fraction:
    frac = parse_canonical_decimal(value, field=path)
    if frac == 0 and not allow_zero:
        raise PolicySchemaError(f"{path}: must be > 0")
    return frac


def _text(value: Any, path: str, *, max_len: int = 128) -> str:
    if not isinstance(value, str):
        raise PolicySchemaError(f"{path}: expected a string, got {_kind(value)}")
    if not value or value.strip() != value:
        raise PolicySchemaError(f"{path}: must be non-empty and free of edge whitespace")
    if len(value) > max_len:
        raise PolicySchemaError(f"{path}: longer than {max_len} characters")
    return value


def _instrument(raw: Any, path: str) -> InstrumentV0:
    obj = _Obj(raw, path)
    ref = parse_instrument_ref(obj.take("ref"), field=f"{path}.ref")
    decimals = _int(obj.take("decimals"), f"{path}.decimals", minimum=0, maximum=36)
    asset_class_raw = obj.take_optional("asset_class")
    display_symbol = obj.take_optional("display_symbol")
    obj.done()

    if isinstance(asset_class_raw, _Missing):
        asset_class = AssetClass.FUNGIBLE
    else:
        try:
            asset_class = AssetClass(_text(asset_class_raw, f"{path}.asset_class"))
        except ValueError as exc:
            raise PolicySchemaError(
                f"{path}.asset_class: unknown value {asset_class_raw!r}"
            ) from exc

    symbol = (
        None
        if isinstance(display_symbol, _Missing)
        else _text(display_symbol, f"{path}.display_symbol", max_len=64)
    )
    return InstrumentV0(
        ref=ref, decimals=decimals, asset_class=asset_class, display_symbol=symbol
    )


def _ladder(
    raw: Any,
    path: str,
    *,
    kind: LadderKind,
    side: Side,
    seen_level_ids: set[str],
) -> LadderV0:
    obj = _Obj(raw, path)
    levels_raw = obj.take("levels")
    obj.done()
    if not isinstance(levels_raw, list):
        raise PolicySchemaError(f"{path}.levels: expected an array")
    if not levels_raw:
        raise PolicySchemaError(f"{path}.levels: must not be empty")
    if len(levels_raw) > _MAX_LEVELS_PER_LADDER:
        raise PolicySchemaError(
            f"{path}.levels: {len(levels_raw)} levels exceeds the limit of "
            f"{_MAX_LEVELS_PER_LADDER}"
        )

    levels: list[LadderLevelV0] = []
    for index, level_raw in enumerate(levels_raw):
        lpath = f"{path}.levels[{index}]"
        lobj = _Obj(level_raw, lpath)
        level_id = _text(lobj.take("level_id"), f"{lpath}.level_id", max_len=64)
        if level_id in seen_level_ids:
            raise PolicySchemaError(
                f"{lpath}.level_id: {level_id!r} is already used in this policy; "
                "level ids must be unique across both ladders"
            )
        seen_level_ids.add(level_id)
        trigger = _decimal(lobj.take("trigger_price"), f"{lpath}.trigger_price")
        if kind is LadderKind.ENTRY:
            amount = _decimal(lobj.take("input_amount"), f"{lpath}.input_amount")
            ratio = None
        else:
            amount = None
            ratio = _decimal(lobj.take("input_ratio"), f"{lpath}.input_ratio")
            if ratio > 1:
                raise PolicySchemaError(f"{lpath}.input_ratio: must be <= 1")
        lobj.done()
        levels.append(
            LadderLevelV0(
                level_id=level_id,
                kind=kind,
                side=side,
                index=index,
                trigger_price=trigger,
                input_amount=amount,
                input_ratio=ratio,
            )
        )
    return LadderV0(kind=kind, side=side, levels=tuple(levels))


def parse_policy(raw: Any) -> PolicyV0:
    """Admit a strict-parsed policy object, or fail closed."""
    root = _Obj(raw, "policy")

    schema = _text(root.take("schema"), "policy.schema")
    if schema != POLICY_SCHEMA_ID:
        raise PolicySchemaError(
            f"policy.schema: expected {POLICY_SCHEMA_ID!r}, got {schema!r}"
        )
    policy_name = _text(root.take("policy_name"), "policy.policy_name")

    side_raw = root.take("side")
    try:
        side = Side(_text(side_raw, "policy.side"))
    except ValueError as exc:
        raise PolicySchemaError(f"policy.side: expected BUY or SELL, got {side_raw!r}") from exc

    base = _instrument(root.take("base"), "policy.base")
    quote = _instrument(root.take("quote"), "policy.quote")
    if base.instrument_id == quote.instrument_id:
        raise PolicySchemaError("policy.quote: quote instrument must differ from base")
    if base.ref.namespace != quote.ref.namespace:
        raise PolicySchemaError(
            "policy.quote: base and quote must share a namespace; V0 performs no bridging"
        )
    if base.network_id != quote.network_id:
        raise PolicySchemaError(
            "policy.quote: base and quote must be on the same network; "
            "V0 performs no bridging"
        )

    seen_level_ids: set[str] = set()
    entry_ladder = _ladder(
        root.take("entry_ladder"),
        "policy.entry_ladder",
        kind=LadderKind.ENTRY,
        side=side,
        seen_level_ids=seen_level_ids,
    )
    exit_ladder = _ladder(
        root.take("exit_ladder"),
        "policy.exit_ladder",
        kind=LadderKind.EXIT,
        side=side.opposite,
        seen_level_ids=seen_level_ids,
    )

    exit_ratio_total = sum(
        (lvl.input_ratio for lvl in exit_ladder.levels), start=Fraction(0)
    )
    if exit_ratio_total > 1:
        raise PolicySchemaError(
            f"policy.exit_ladder: input_ratio values sum to "
            f"{format_canonical_decimal(exit_ratio_total)}, which exceeds 1"
        )

    # --- capital -----------------------------------------------------------
    cap = _Obj(root.take("capital"), "policy.capital")
    allocation = _decimal(cap.take("allocation_quote"), "policy.capital.allocation_quote")
    per_order = _decimal(cap.take("per_order_cap_quote"), "policy.capital.per_order_cap_quote")
    per_instrument = _decimal(
        cap.take("per_instrument_cap_quote"), "policy.capital.per_instrument_cap_quote"
    )
    per_network = _decimal(
        cap.take("per_network_cap_quote"), "policy.capital.per_network_cap_quote"
    )
    global_cap = _decimal(
        cap.take("global_portfolio_cap_quote"), "policy.capital.global_portfolio_cap_quote"
    )
    reserved_cash = _decimal(
        cap.take("reserved_cash_quote"), "policy.capital.reserved_cash_quote", allow_zero=True
    )
    cap.done()

    qd = quote.decimals
    budget = PortfolioBudgetV0(
        allocation_atomic=to_atomic(allocation, qd, field="policy.capital.allocation_quote"),
        per_order_cap_atomic=to_atomic(per_order, qd, field="policy.capital.per_order_cap_quote"),
        per_instrument_cap_atomic=to_atomic(
            per_instrument, qd, field="policy.capital.per_instrument_cap_quote"
        ),
        per_network_cap_atomic=to_atomic(
            per_network, qd, field="policy.capital.per_network_cap_quote"
        ),
        global_cap_atomic=to_atomic(
            global_cap, qd, field="policy.capital.global_portfolio_cap_quote"
        ),
        reserved_cash_atomic=to_atomic(
            reserved_cash, qd, field="policy.capital.reserved_cash_quote"
        ),
    )

    # --- limits ------------------------------------------------------------
    lim = _Obj(root.take("limits"), "policy.limits")
    max_exec_price = _decimal(
        lim.take("max_executable_price"), "policy.limits.max_executable_price"
    )
    min_exec_price = _decimal(
        lim.take("min_executable_price"), "policy.limits.min_executable_price"
    )
    max_impact_bps = _bps(lim.take("max_price_impact_bps"), "policy.limits.max_price_impact_bps")
    max_slippage_bps = _bps(lim.take("max_slippage_bps"), "policy.limits.max_slippage_bps")
    lim.done()
    if min_exec_price > max_exec_price:
        raise PolicySchemaError(
            "policy.limits: min_executable_price must not exceed max_executable_price"
        )

    # --- timing ------------------------------------------------------------
    tim = _Obj(root.take("timing"), "policy.timing")
    valid_from = _int(
        tim.take("valid_from_epoch_s"), "policy.timing.valid_from_epoch_s", minimum=0, maximum=_MAX_EPOCH_S
    )
    expiry = _int(
        tim.take("expiry_epoch_s"), "policy.timing.expiry_epoch_s", minimum=0, maximum=_MAX_EPOCH_S
    )
    quote_ttl = _int(tim.take("quote_ttl_s"), "policy.timing.quote_ttl_s", minimum=1, maximum=86_400)
    tim.done()
    if expiry <= valid_from:
        raise PolicySchemaError("policy.timing: expiry_epoch_s must be after valid_from_epoch_s")

    # --- re-entry ----------------------------------------------------------
    ree = _Obj(root.take("reentry"), "policy.reentry")
    max_cycles = _int(ree.take("max_cycles"), "policy.reentry.max_cycles", minimum=1, maximum=10_000)
    rearm_hysteresis_bps = _bps(
        ree.take("rearm_hysteresis_bps"), "policy.reentry.rearm_hysteresis_bps"
    )
    rearm_cooldown_s = _int(
        ree.take("rearm_cooldown_s"), "policy.reentry.rearm_cooldown_s", minimum=0, maximum=_MAX_EPOCH_S
    )
    ree.done()

    # --- recycling (optional block, both keys required when present) --------
    recycling_raw = root.take_optional("recycling")
    if isinstance(recycling_raw, _Missing):
        profit_recycle_ratio = Fraction(0)
        banked_profit_ratio = Fraction(0)
    else:
        rec = _Obj(recycling_raw, "policy.recycling")
        profit_recycle_ratio = _decimal(
            rec.take("profit_recycle_ratio"),
            "policy.recycling.profit_recycle_ratio",
            allow_zero=True,
        )
        banked_profit_ratio = _decimal(
            rec.take("banked_profit_ratio"),
            "policy.recycling.banked_profit_ratio",
            allow_zero=True,
        )
        rec.done()
        if profit_recycle_ratio + banked_profit_ratio > 1:
            raise PolicySchemaError(
                "policy.recycling: profit_recycle_ratio + banked_profit_ratio must not exceed 1"
            )

    root.done()

    # --- cross-field capital coherence -------------------------------------
    # NOTE: the entry ladder's total notional is deliberately NOT required to
    # fit inside allocation_quote. A ladder may be provisioned deeper than the
    # capital behind it -- "ladder down to 0.5, but never commit more than
    # 200 total" is a coherent instruction. The allocation cap is enforced
    # per-reservation in the ledger, where it can account for releases and for
    # what other actions already hold. Checking it here as well would make the
    # runtime cap unreachable within a single policy, which is exactly the cap
    # that has to work when several rungs trigger at once.
    if side is Side.BUY:
        for lvl in entry_ladder.levels:
            level_atomic = to_atomic(
                lvl.input_amount, qd, field=f"policy.entry_ladder level {lvl.level_id}"
            )
            if level_atomic > budget.per_order_cap_atomic:
                # Unlike the ladder total, a single rung above the per-order cap
                # can never be reserved under any market condition. It is dead
                # on arrival, and a dead rung is a policy error.
                raise PolicySchemaError(
                    f"policy.entry_ladder: level {lvl.level_id} input_amount exceeds "
                    "per_order_cap_quote, so the level could never execute"
                )
            if lvl.trigger_price > max_exec_price:
                raise PolicySchemaError(
                    f"policy.entry_ladder: level {lvl.level_id} trigger_price exceeds "
                    "limits.max_executable_price, so the level could never execute"
                )
        for lvl in exit_ladder.levels:
            if lvl.trigger_price < min_exec_price:
                raise PolicySchemaError(
                    f"policy.exit_ladder: level {lvl.level_id} trigger_price is below "
                    "limits.min_executable_price, so the level could never execute"
                )
    else:
        for lvl in entry_ladder.levels:
            if lvl.trigger_price < min_exec_price:
                raise PolicySchemaError(
                    f"policy.entry_ladder: level {lvl.level_id} trigger_price is below "
                    "limits.min_executable_price, so the level could never execute"
                )
        for lvl in exit_ladder.levels:
            if lvl.trigger_price > max_exec_price:
                raise PolicySchemaError(
                    f"policy.exit_ladder: level {lvl.level_id} trigger_price exceeds "
                    "limits.max_executable_price, so the level could never execute"
                )

    canonical = {
        "schema": POLICY_SCHEMA_ID,
        "policy_name": policy_name,
        "side": side.value,
        "base": base.policy_object(),
        "quote": quote.policy_object(),
        "entry_ladder": entry_ladder.canonical_object(),
        "exit_ladder": exit_ladder.canonical_object(),
        "capital": {
            "allocation_quote": format_canonical_decimal(allocation),
            "per_order_cap_quote": format_canonical_decimal(per_order),
            "per_instrument_cap_quote": format_canonical_decimal(per_instrument),
            "per_network_cap_quote": format_canonical_decimal(per_network),
            "global_portfolio_cap_quote": format_canonical_decimal(global_cap),
            "reserved_cash_quote": format_canonical_decimal(reserved_cash),
        },
        "limits": {
            "max_executable_price": format_canonical_decimal(max_exec_price),
            "min_executable_price": format_canonical_decimal(min_exec_price),
            "max_price_impact_bps": max_impact_bps,
            "max_slippage_bps": max_slippage_bps,
        },
        "timing": {
            "valid_from_epoch_s": valid_from,
            "expiry_epoch_s": expiry,
            "quote_ttl_s": quote_ttl,
        },
        "reentry": {
            "max_cycles": max_cycles,
            "rearm_hysteresis_bps": rearm_hysteresis_bps,
            "rearm_cooldown_s": rearm_cooldown_s,
        },
        "recycling": {
            "profit_recycle_ratio": format_canonical_decimal(profit_recycle_ratio),
            "banked_profit_ratio": format_canonical_decimal(banked_profit_ratio),
        },
    }

    return PolicyV0(
        policy_name=policy_name,
        base=base,
        quote=quote,
        side=side,
        entry_ladder=entry_ladder,
        exit_ladder=exit_ladder,
        budget=budget,
        max_executable_price=max_exec_price,
        min_executable_price=min_exec_price,
        max_price_impact_bps=max_impact_bps,
        max_slippage_bps=max_slippage_bps,
        valid_from_epoch_s=valid_from,
        expiry_epoch_s=expiry,
        quote_ttl_s=quote_ttl,
        max_cycles=max_cycles,
        rearm_hysteresis_bps=rearm_hysteresis_bps,
        rearm_cooldown_s=rearm_cooldown_s,
        profit_recycle_ratio=profit_recycle_ratio,
        banked_profit_ratio=banked_profit_ratio,
        canonical=canonical,
    )


def load_policy_text(text: str | bytes | None) -> PolicyV0:
    """Admit a policy from JSON text. ``None`` or blank fails startup."""
    if text is None:
        raise PolicyMissingError("no policy supplied; refusing to start")
    if isinstance(text, bytes):
        blank = not text.strip()
    else:
        blank = not text.strip()
    if blank:
        raise PolicyMissingError("policy document is empty; refusing to start")
    return parse_policy(strict_json_loads(text))


def load_policy_file(path: Any) -> PolicyV0:
    """Admit a policy from a local file path. A missing file fails startup."""
    import os

    if not os.path.isfile(path):
        raise PolicyMissingError(f"policy file not found: {path}")
    with open(path, "rb") as fh:
        return load_policy_text(fh.read())
