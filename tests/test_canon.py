"""The canonical representation contract."""

from __future__ import annotations

from decimal import Decimal
from fractions import Fraction

import pytest

from qntyspot.canon import (
    canonical_json_bytes,
    decimal_to_fraction,
    digest_object,
    format_canonical_decimal,
    fraction_to_decimal,
    from_atomic,
    parse_canonical_decimal,
    strict_json_loads,
    to_atomic,
)
from qntyspot.errors import CanonicalFormError

CANONICAL = ["0", "1", "12", "0.5", "1.25", "1000000", "0.000001"]
NON_CANONICAL = [
    "1.0",      # trailing fractional zero
    "0.50",     # trailing fractional zero
    "01",       # leading zero
    "00",       # leading zero
    ".5",       # missing integer part
    "1.",       # trailing point
    "+1",       # explicit sign
    "-1",       # negative
    "-0",       # negative zero
    "1e3",      # exponent
    "1E3",      # exponent
    " 1",       # whitespace
    "1 ",       # whitespace
    "1_000",    # separator
    "",         # empty
    "abc",      # not a number
    "Infinity",
    "NaN",
]


@pytest.mark.parametrize("text", CANONICAL)
def test_canonical_decimals_round_trip(text: str) -> None:
    value = parse_canonical_decimal(text)
    assert format_canonical_decimal(value) == text


@pytest.mark.parametrize("text", NON_CANONICAL)
def test_non_canonical_decimals_are_refused(text: str) -> None:
    with pytest.raises(CanonicalFormError):
        parse_canonical_decimal(text)


@pytest.mark.parametrize("value", [1, 1.5, Decimal("1"), None, True, [], {}])
def test_only_strings_are_accepted_as_decimals(value: object) -> None:
    with pytest.raises(CanonicalFormError):
        parse_canonical_decimal(value)


def test_decimal_interop_round_trip() -> None:
    for text in CANONICAL:
        frac = parse_canonical_decimal(text)
        dec = fraction_to_decimal(frac)
        assert isinstance(dec, Decimal)
        assert decimal_to_fraction(dec) == frac


def test_non_terminating_fraction_cannot_be_rendered() -> None:
    with pytest.raises(CanonicalFormError, match="terminating"):
        format_canonical_decimal(Fraction(1, 3))


def test_atomic_round_trip_is_exact() -> None:
    for text, decimals in [("1", 18), ("0.000001", 6), ("123.456", 3), ("0", 0)]:
        frac = parse_canonical_decimal(text)
        atomic = to_atomic(frac, decimals)
        assert isinstance(atomic, int)
        assert from_atomic(atomic, decimals) == frac
        assert format_canonical_decimal(from_atomic(atomic, decimals)) == text


def test_atomic_conversion_refuses_to_truncate_dust() -> None:
    # 0.0000001 needs 7 decimals; a 6-decimal token cannot hold it exactly.
    frac = parse_canonical_decimal("0.0000001")
    with pytest.raises(CanonicalFormError, match="not exactly representable"):
        to_atomic(frac, 6)


def test_eighteen_decimal_amounts_exceed_int64_and_stay_exact() -> None:
    atomic = to_atomic(parse_canonical_decimal("1000"), 18)
    assert atomic == 10**21
    assert atomic > 2**63 - 1
    assert from_atomic(atomic, 18) == Fraction(1000)


# -- JSON admission --------------------------------------------------------


def test_duplicate_keys_are_refused() -> None:
    with pytest.raises(CanonicalFormError, match="duplicate JSON key"):
        strict_json_loads('{"a": 1, "a": 2}')


def test_duplicate_keys_are_refused_when_nested() -> None:
    with pytest.raises(CanonicalFormError, match="duplicate JSON key"):
        strict_json_loads('{"outer": {"b": 1, "b": 2}}')


@pytest.mark.parametrize("raw", ['{"a": 1.5}', '{"a": 1e3}', '{"a": -0.0}'])
def test_json_floats_are_refused(raw: str) -> None:
    with pytest.raises(CanonicalFormError, match="binary float"):
        strict_json_loads(raw)


@pytest.mark.parametrize("raw", ['{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'])
def test_json_non_finite_constants_are_refused(raw: str) -> None:
    with pytest.raises(CanonicalFormError):
        strict_json_loads(raw)


@pytest.mark.parametrize("raw", ["{", "", "not json", "{'a': 1}", '{"a": 1,}'])
def test_malformed_json_is_refused(raw: str) -> None:
    with pytest.raises(CanonicalFormError):
        strict_json_loads(raw)


def test_invalid_utf8_is_refused() -> None:
    with pytest.raises(CanonicalFormError, match="UTF-8"):
        strict_json_loads(b'{"a": "\xff"}')


def test_json_integers_are_accepted_exactly() -> None:
    assert strict_json_loads('{"a": 12345678901234567890}') == {"a": 12345678901234567890}


# -- digests ---------------------------------------------------------------


def test_digest_ignores_key_order_and_whitespace() -> None:
    a = strict_json_loads('{"b": 1, "a": {"d": 2, "c": 3}}')
    b = strict_json_loads('{ "a" : { "c" : 3 , "d" : 2 } , "b" : 1 }')
    assert digest_object(a) == digest_object(b)


def test_digest_is_stable_across_calls() -> None:
    obj = {"z": [1, 2, {"y": "x"}], "a": "b"}
    assert digest_object(obj) == digest_object(obj)


def test_digest_distinguishes_content() -> None:
    assert digest_object({"a": 1}) != digest_object({"a": 2})
    assert digest_object({"a": "1"}) != digest_object({"a": 1})


def test_canonical_json_is_ascii_and_minimally_separated() -> None:
    raw = canonical_json_bytes({"b": 1, "a": "é"})
    assert raw == b'{"a":"\\u00e9","b":1}'
