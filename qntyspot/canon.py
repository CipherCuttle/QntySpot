"""Canonical representation contract for QntySpot V0A.

NUMERIC CONTRACT
----------------
Binary floating point is forbidden anywhere an economic quantity is
represented. This module is the only place numbers cross the boundary between
text and machine representation.

Two representations exist and no others:

* ``int``      -- atomic units of a token (already scaled by the instrument's
                  ``decimals``). Exact by construction.
* ``Fraction`` -- exact rational, used for prices and ratios. ``Fraction`` is
                  backed by two Python ints, so it is exact for every value
                  reachable from a canonical decimal string, and it never
                  silently rounds the way ``Decimal`` does at context
                  precision. ``Decimal`` interop is provided for callers that
                  want it (:func:`fraction_to_decimal`), but no internal
                  arithmetic is performed in ``Decimal``.

CANONICAL FORM CONTRACT
-----------------------
The contract has two layers and they are deliberately different:

1. VALUE LAYER -- REJECT. A decimal number arriving as text must already be in
   the single canonical spelling. Non-canonical spellings are not repaired,
   they are refused. See :func:`parse_canonical_decimal`.

2. DOCUMENT LAYER -- CANONICALIZE. A JSON document's key order and whitespace
   carry no meaning, so the digest is taken over a re-serialization with
   sorted keys, minimal separators and ASCII escaping. Duplicate keys and
   JSON floats are refused outright by the reader, so canonicalizing the
   document can never launder an ambiguous input.

Both layers are covered by tests in ``tests/test_canon.py``.
"""

from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from fractions import Fraction
from typing import Any

__all__ = [
    "CANONICAL_DECIMAL_RE",
    "MAX_INT_DIGITS",
    "MAX_FRAC_DIGITS",
    "parse_canonical_decimal",
    "format_canonical_decimal",
    "fraction_to_decimal",
    "decimal_to_fraction",
    "to_atomic",
    "from_atomic",
    "strict_json_loads",
    "canonical_json_bytes",
    "canonical_json_str",
    "sha256_hex",
    "digest_object",
]

from .errors import CanonicalFormError

MAX_INT_DIGITS = 30
MAX_FRAC_DIGITS = 30

#: The single admissible spelling of a non-negative decimal number.
#:
#: * no sign, no exponent, no underscores, no whitespace
#: * integer part is ``0`` or has no leading zero
#: * fractional part, if present, is non-empty and has no trailing zero
#:
#: So ``0``, ``0.5``, ``12.25`` are canonical; ``+1``, ``01``, ``1.``, ``.5``,
#: ``1.0``, ``0.50``, ``1e3``, ``-0`` are not.
CANONICAL_DECIMAL_RE = re.compile(
    r"^(?:0|[1-9][0-9]{0,%d})(?:\.[0-9]{0,%d}[1-9])?$"
    % (MAX_INT_DIGITS - 1, MAX_FRAC_DIGITS - 1)
)


def parse_canonical_decimal(text: Any, *, field: str = "<value>") -> Fraction:
    """Parse a canonical decimal string into an exact :class:`Fraction`.

    Only ``str`` is accepted. Passing an ``int``, ``float`` or ``Decimal`` is
    an error: numbers reach this system as text so that their spelling is
    part of the audited contract.
    """
    if not isinstance(text, str):
        raise CanonicalFormError(
            f"{field}: decimal must be a JSON string, got {type(text).__name__}"
        )
    if not CANONICAL_DECIMAL_RE.match(text):
        raise CanonicalFormError(
            f"{field}: {text!r} is not a canonical decimal string "
            "(no sign, no exponent, no leading zeros, no trailing fractional zeros)"
        )
    if "." in text:
        int_part, frac_part = text.split(".", 1)
        return Fraction(int(int_part + frac_part), 10 ** len(frac_part))
    return Fraction(int(text), 1)


def format_canonical_decimal(value: Fraction, *, field: str = "<value>") -> str:
    """Render an exact :class:`Fraction` back to its canonical decimal string.

    Raises if the value has no terminating decimal expansion. Every value this
    system produces does terminate: inputs are decimals and the only divisors
    introduced internally are powers of ten and 10000 (basis points), whose
    prime factors are 2 and 5.
    """
    if not isinstance(value, Fraction):
        raise CanonicalFormError(
            f"{field}: expected Fraction, got {type(value).__name__}"
        )
    if value < 0:
        raise CanonicalFormError(f"{field}: negative values are not representable")
    num, den = value.numerator, value.denominator
    twos = fives = 0
    d = den
    while d % 2 == 0:
        d //= 2
        twos += 1
    while d % 5 == 0:
        d //= 5
        fives += 1
    if d != 1:
        raise CanonicalFormError(
            f"{field}: {num}/{den} has no terminating decimal expansion"
        )
    scale = max(twos, fives)
    if scale > MAX_FRAC_DIGITS:
        raise CanonicalFormError(
            f"{field}: value needs {scale} fractional digits, limit is {MAX_FRAC_DIGITS}"
        )
    scaled = num * (10**scale) // den
    text = str(scaled).rjust(scale + 1, "0")
    if scale == 0:
        out = text
    else:
        out = (text[:-scale] + "." + text[-scale:]).rstrip("0").rstrip(".")
    if not CANONICAL_DECIMAL_RE.match(out):  # pragma: no cover - defensive
        raise CanonicalFormError(f"{field}: produced non-canonical rendering {out!r}")
    return out


def fraction_to_decimal(value: Fraction, *, field: str = "<value>") -> Decimal:
    """Exact ``Decimal`` view of a fraction, via its canonical string."""
    return Decimal(format_canonical_decimal(value, field=field))


def decimal_to_fraction(value: Decimal, *, field: str = "<value>") -> Fraction:
    """Exact ``Fraction`` from a ``Decimal``, requiring canonical spelling."""
    if not isinstance(value, Decimal):
        raise CanonicalFormError(
            f"{field}: expected Decimal, got {type(value).__name__}"
        )
    return parse_canonical_decimal(_decimal_plain_string(value), field=field)


def _decimal_plain_string(value: Decimal) -> str:
    """Plain (non-exponent) spelling of a Decimal, with trailing zeros trimmed."""
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):  # NaN / Infinity
        raise CanonicalFormError(f"non-finite Decimal {value!r} is not representable")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def to_atomic(value: Fraction, decimals: int, *, field: str = "<value>") -> int:
    """Convert an exact human-scale amount to integer atomic units.

    The conversion must be exact. An amount that cannot be expressed in the
    instrument's atomic units is refused rather than rounded: silently
    truncating dust is a class of accounting bug this runtime must not have.
    """
    if not isinstance(decimals, int) or isinstance(decimals, bool) or decimals < 0:
        raise CanonicalFormError(f"{field}: decimals must be a non-negative int")
    scaled = value * (10**decimals)
    if scaled.denominator != 1:
        raise CanonicalFormError(
            f"{field}: {format_canonical_decimal(value)} is not exactly representable "
            f"in {decimals} decimals"
        )
    return int(scaled.numerator)


def from_atomic(atomic: int, decimals: int) -> Fraction:
    """Exact human-scale amount from integer atomic units."""
    if not isinstance(atomic, int) or isinstance(atomic, bool):
        raise CanonicalFormError("atomic amount must be an int")
    return Fraction(atomic, 10**decimals)


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise CanonicalFormError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_float(text: str) -> Any:
    raise CanonicalFormError(
        f"JSON number {text!r} would be parsed as binary float; "
        "economic values must be canonical decimal strings"
    )


def _reject_constant(text: str) -> Any:
    raise CanonicalFormError(f"JSON constant {text!r} is not admissible")


def strict_json_loads(raw: str | bytes) -> Any:
    """Parse JSON under the V0A admission rules.

    Refuses: duplicate object keys, any non-integer JSON number, and the
    ``NaN`` / ``Infinity`` / ``-Infinity`` extensions. Integers are accepted
    (they are exact) but the policy schema still restricts where they may
    appear.
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalFormError(f"policy bytes are not valid UTF-8: {exc}") from exc
    if not isinstance(raw, str):
        raise CanonicalFormError(f"expected str or bytes, got {type(raw).__name__}")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalFormError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalFormError(f"malformed JSON: {exc}") from exc


def canonical_json_str(obj: Any) -> str:
    """Deterministic JSON text: sorted keys, minimal separators, ASCII only."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_json_bytes(obj: Any) -> bytes:
    return canonical_json_str(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_object(obj: Any) -> str:
    """SHA-256 over the canonical JSON encoding of ``obj``."""
    return sha256_hex(canonical_json_bytes(obj))
