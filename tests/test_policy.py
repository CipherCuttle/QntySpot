"""PolicyV0 admission: fail closed on anything the schema does not name."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from conftest import base_policy_doc, doc_with
from qntyspot.canon import canonical_json_str
from qntyspot.errors import (
    CanonicalFormError,
    IdentityError,
    PolicyMissingError,
    PolicySchemaError,
)
from qntyspot.policy import load_policy_file, load_policy_text, parse_policy

SOLANA_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def test_the_fixture_policy_is_admissible() -> None:
    policy = parse_policy(base_policy_doc())
    assert policy.side.value == "BUY"
    assert [lvl.level_id for lvl in policy.levels()] == ["E1", "E2", "X1", "X2"]


# -- missing / malformed ----------------------------------------------------


@pytest.mark.parametrize("text", [None, "", "   ", b"", b"  \n "])
def test_missing_policy_fails_startup(text: Any) -> None:
    with pytest.raises(PolicyMissingError):
        load_policy_text(text)


def test_missing_policy_file_fails_startup(tmp_path: Any) -> None:
    with pytest.raises(PolicyMissingError):
        load_policy_file(tmp_path / "nope.json")


@pytest.mark.parametrize("raw", ["{", "[]x", "not json", "{'a': 1}"])
def test_malformed_json_fails_closed(raw: str) -> None:
    with pytest.raises(CanonicalFormError):
        load_policy_text(raw)


def test_duplicate_json_key_fails_closed() -> None:
    raw = canonical_json_str(base_policy_doc())
    injected = raw.replace('"side":"BUY"', '"side":"BUY","side":"SELL"', 1)
    assert injected != raw
    with pytest.raises(CanonicalFormError, match="duplicate JSON key"):
        load_policy_text(injected)


def test_json_float_fails_closed() -> None:
    raw = canonical_json_str(base_policy_doc()).replace(
        '"max_price_impact_bps":100', '"max_price_impact_bps":100.0'
    )
    with pytest.raises(CanonicalFormError, match="binary float"):
        load_policy_text(raw)


def test_a_top_level_array_is_refused() -> None:
    with pytest.raises(PolicySchemaError):
        load_policy_text("[]")


# -- unknown keys -----------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("capital",),
        ("limits",),
        ("timing",),
        ("reentry",),
        ("base",),
        ("quote",),
        ("entry_ladder",),
    ],
)
def test_unknown_key_fails_closed_at_every_depth(path: tuple[str, ...]) -> None:
    doc = base_policy_doc()
    target = doc
    for key in path:
        target = target[key]
    target["surprise_field"] = "anything"
    with pytest.raises(PolicySchemaError, match="unknown keys"):
        parse_policy(doc)


def test_unknown_key_inside_a_ladder_level_fails_closed() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"][0]["urgency"] = "high"
    with pytest.raises(PolicySchemaError, match="unknown keys"):
        parse_policy(doc)


def test_unknown_key_inside_an_instrument_ref_fails_closed() -> None:
    doc = base_policy_doc()
    doc["base"]["ref"]["symbol"] = "FIXTURE"
    with pytest.raises(IdentityError, match="unknown keys"):
        parse_policy(doc)


@pytest.mark.parametrize(
    "section,key",
    [
        (None, "schema"),
        (None, "side"),
        (None, "base"),
        (None, "entry_ladder"),
        (None, "exit_ladder"),
        (None, "capital"),
        (None, "limits"),
        (None, "timing"),
        (None, "reentry"),
        ("capital", "allocation_quote"),
        ("capital", "reserved_cash_quote"),
        ("limits", "max_executable_price"),
        ("limits", "min_executable_price"),
        ("limits", "max_slippage_bps"),
        ("limits", "max_price_impact_bps"),
        ("timing", "expiry_epoch_s"),
        ("reentry", "max_cycles"),
    ],
)
def test_every_required_key_is_actually_required(section: str | None, key: str) -> None:
    doc = base_policy_doc()
    (doc if section is None else doc[section]).pop(key)
    with pytest.raises(PolicySchemaError, match="missing"):
        parse_policy(doc)


def test_wrong_schema_id_is_refused() -> None:
    with pytest.raises(PolicySchemaError, match="schema"):
        parse_policy(doc_with(schema="qntyspot.policy.v1"))


# -- numeric contract -------------------------------------------------------


@pytest.mark.parametrize("value", ["1.0", "01", "+1", "-1", "1e2", "0.50", 100, 100.0, None])
def test_non_canonical_capital_amounts_are_refused(value: Any) -> None:
    doc = base_policy_doc()
    doc["capital"]["allocation_quote"] = value
    with pytest.raises((CanonicalFormError, PolicySchemaError)):
        parse_policy(doc)


@pytest.mark.parametrize("field", ["allocation_quote", "per_order_cap_quote"])
def test_zero_capital_amounts_are_refused(field: str) -> None:
    doc = base_policy_doc()
    doc["capital"][field] = "0"
    with pytest.raises(PolicySchemaError, match="must be > 0"):
        parse_policy(doc)


def test_zero_reserved_cash_is_allowed() -> None:
    doc = base_policy_doc()
    doc["capital"]["reserved_cash_quote"] = "0"
    assert parse_policy(doc).budget.reserved_cash_atomic == 0


def test_zero_trigger_price_is_refused() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"][0]["trigger_price"] = "0"
    with pytest.raises(PolicySchemaError, match="must be > 0"):
        parse_policy(doc)


def test_zero_entry_amount_is_refused() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"][0]["input_amount"] = "0"
    with pytest.raises(PolicySchemaError, match="must be > 0"):
        parse_policy(doc)


@pytest.mark.parametrize("bps", [-1, 10001, "100", 100.0, True, None])
def test_out_of_range_basis_points_are_refused(bps: Any) -> None:
    doc = base_policy_doc()
    doc["limits"]["max_slippage_bps"] = bps
    with pytest.raises(PolicySchemaError):
        parse_policy(doc)


def test_capital_amount_needing_more_precision_than_the_quote_is_refused() -> None:
    # quote has 6 decimals; 7 fractional digits cannot be held exactly.
    doc = base_policy_doc()
    doc["capital"]["allocation_quote"] = "200.0000001"
    with pytest.raises(CanonicalFormError, match="not exactly representable"):
        parse_policy(doc)


# -- identity ---------------------------------------------------------------


def test_invalid_chain_identity_is_refused() -> None:
    doc = base_policy_doc()
    doc["base"]["ref"]["chain_id"] = 0
    with pytest.raises(IdentityError):
        parse_policy(doc)


def test_invalid_solana_identity_representation_is_refused() -> None:
    doc = base_policy_doc()
    for side in ("base", "quote"):
        doc[side]["ref"] = {
            "namespace": "solana",
            "cluster": "mainnet-beta",
            # an EVM-style address in the Solana namespace
            "mint_address": "0xc0ffee0000000000000000000000000000000001",
            "token_program": "SPL_TOKEN",
        }
    with pytest.raises(IdentityError, match="base58"):
        parse_policy(doc)


def test_a_valid_solana_policy_is_admissible() -> None:
    doc = base_policy_doc()
    doc["base"]["ref"] = {
        "namespace": "solana",
        "cluster": "mainnet-beta",
        "mint_address": SOLANA_MINT,
        "token_program": "TOKEN_2022",
    }
    doc["base"]["decimals"] = 9
    doc["quote"]["ref"] = {
        "namespace": "solana",
        "cluster": "mainnet-beta",
        "mint_address": "So11111111111111111111111111111111111111112",
        "token_program": "SPL_TOKEN",
    }
    policy = parse_policy(doc)
    assert policy.network_id == "solana:mainnet-beta"


def test_base_and_quote_must_differ() -> None:
    doc = base_policy_doc()
    doc["quote"] = copy.deepcopy(doc["base"])
    with pytest.raises(PolicySchemaError, match="must differ"):
        parse_policy(doc)


def test_cross_namespace_pair_is_refused_because_v0_does_not_bridge() -> None:
    doc = base_policy_doc()
    doc["quote"]["ref"] = {
        "namespace": "solana",
        "cluster": "mainnet-beta",
        "mint_address": SOLANA_MINT,
        "token_program": "SPL_TOKEN",
    }
    with pytest.raises(PolicySchemaError, match="bridging"):
        parse_policy(doc)


def test_cross_chain_pair_is_refused_because_v0_does_not_bridge() -> None:
    doc = base_policy_doc()
    doc["quote"]["ref"]["chain_id"] = 1
    with pytest.raises(PolicySchemaError, match="bridging"):
        parse_policy(doc)


# -- ladders ----------------------------------------------------------------


def test_buy_entry_ladder_must_descend() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"][1]["trigger_price"] = "0.95"
    with pytest.raises(PolicySchemaError, match="strictly decreasing"):
        parse_policy(doc)


def test_sell_exit_ladder_must_ascend() -> None:
    doc = base_policy_doc()
    doc["exit_ladder"]["levels"][1]["trigger_price"] = "1.1"
    with pytest.raises(PolicySchemaError, match="strictly increasing"):
        parse_policy(doc)


def test_repeated_trigger_prices_are_refused() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"][1]["trigger_price"] = doc["entry_ladder"]["levels"][0][
        "trigger_price"
    ]
    with pytest.raises(PolicySchemaError, match="strictly decreasing"):
        parse_policy(doc)


def test_duplicate_level_ids_are_refused_across_both_ladders() -> None:
    doc = base_policy_doc()
    doc["exit_ladder"]["levels"][0]["level_id"] = "E1"
    with pytest.raises(PolicySchemaError, match="already used"):
        parse_policy(doc)


def test_empty_ladder_is_refused() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"] = []
    with pytest.raises(PolicySchemaError, match="must not be empty"):
        parse_policy(doc)


def test_exit_ratios_may_not_exceed_one_in_total() -> None:
    doc = base_policy_doc()
    doc["exit_ladder"]["levels"][0]["input_ratio"] = "0.8"
    with pytest.raises(PolicySchemaError, match="exceeds 1"):
        parse_policy(doc)


def test_entry_level_may_not_carry_a_ratio() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"][0]["input_ratio"] = "0.5"
    with pytest.raises(PolicySchemaError, match="unknown keys"):
        parse_policy(doc)


# -- cross-field coherence --------------------------------------------------


def test_entry_ladder_may_not_exceed_the_allocation() -> None:
    doc = base_policy_doc()
    doc["entry_ladder"]["levels"][0]["input_amount"] = "150"
    with pytest.raises(PolicySchemaError, match="exceeds"):
        parse_policy(doc)


def test_a_level_may_not_exceed_the_per_order_cap() -> None:
    doc = base_policy_doc()
    doc["capital"]["per_order_cap_quote"] = "50"
    with pytest.raises(PolicySchemaError, match="per_order_cap"):
        parse_policy(doc)


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"per_order_cap_quote": "300"}, "per_order_cap"),
        ({"per_instrument_cap_quote": "100"}, "allocation"),
        ({"per_network_cap_quote": "100"}, "per_instrument_cap"),
        ({"global_portfolio_cap_quote": "100"}, "per_network_cap"),
        ({"reserved_cash_quote": "400"}, "reserved_cash"),
    ],
)
def test_incoherent_cap_ordering_is_refused(overrides: dict, match: str) -> None:
    doc = base_policy_doc()
    doc["capital"].update(overrides)
    with pytest.raises(PolicySchemaError, match=match):
        parse_policy(doc)


def test_an_entry_above_the_hard_price_ceiling_is_refused() -> None:
    doc = base_policy_doc()
    doc["limits"]["max_executable_price"] = "0.85"
    doc["limits"]["min_executable_price"] = "0.85"
    with pytest.raises(PolicySchemaError, match="could never execute"):
        parse_policy(doc)


def test_min_price_above_max_price_is_refused() -> None:
    doc = base_policy_doc()
    doc["limits"]["min_executable_price"] = "2"
    with pytest.raises(PolicySchemaError, match="min_executable_price"):
        parse_policy(doc)


def test_expiry_must_follow_validity() -> None:
    doc = base_policy_doc()
    doc["timing"]["expiry_epoch_s"] = doc["timing"]["valid_from_epoch_s"]
    with pytest.raises(PolicySchemaError, match="expiry"):
        parse_policy(doc)


def test_recycling_ratios_may_not_exceed_one_in_total() -> None:
    doc = base_policy_doc()
    doc["recycling"] = {"profit_recycle_ratio": "0.7", "banked_profit_ratio": "0.7"}
    with pytest.raises(PolicySchemaError, match="must not exceed 1"):
        parse_policy(doc)


def test_recycling_block_requires_both_keys_when_present() -> None:
    doc = base_policy_doc()
    doc["recycling"] = {"profit_recycle_ratio": "0.5"}
    with pytest.raises(PolicySchemaError, match="banked_profit_ratio"):
        parse_policy(doc)


def test_absent_recycling_means_zero_not_a_recommended_value() -> None:
    policy = parse_policy(base_policy_doc())
    assert policy.profit_recycle_ratio == 0
    assert policy.banked_profit_ratio == 0
    assert policy.canonical["recycling"] == {
        "profit_recycle_ratio": "0",
        "banked_profit_ratio": "0",
    }


# -- digest identity --------------------------------------------------------


def test_policy_id_is_a_sha256_hex_digest() -> None:
    policy_id = parse_policy(base_policy_doc()).policy_id
    assert len(policy_id) == 64
    assert set(policy_id) <= set("0123456789abcdef")


def test_policy_id_is_stable_across_key_order_and_whitespace() -> None:
    doc = base_policy_doc()
    compact = parse_policy(json.loads(json.dumps(doc, sort_keys=True)))
    spaced = load_policy_text(json.dumps(doc, indent=4))
    assert compact.policy_id == spaced.policy_id


def test_policy_id_ignores_display_symbol() -> None:
    a = parse_policy(base_policy_doc())
    doc = base_policy_doc()
    doc["base"]["display_symbol"] = "SOMETHING-ELSE"
    doc["quote"].pop("display_symbol")
    assert parse_policy(doc).policy_id == a.policy_id


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["capital"].update(global_portfolio_cap_quote="500"),
        lambda d: d["limits"].update(max_slippage_bps=1),
        lambda d: d["entry_ladder"]["levels"][0].update(trigger_price="0.91"),
        lambda d: d.update(policy_name="renamed"),
        lambda d: d["base"].update(decimals=17),
        lambda d: d["reentry"].update(max_cycles=4),
    ],
)
def test_policy_id_changes_when_any_economic_field_changes(mutate: Any) -> None:
    base = parse_policy(base_policy_doc()).policy_id
    doc = base_policy_doc()
    mutate(doc)
    assert parse_policy(doc).policy_id != base


def test_canonical_form_is_itself_an_admissible_policy() -> None:
    policy = parse_policy(base_policy_doc())
    reparsed = parse_policy(dict(policy.canonical))
    assert reparsed.policy_id == policy.policy_id
    assert dict(reparsed.canonical) == dict(policy.canonical)
