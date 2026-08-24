"""Shared fixtures, plus the session-wide proof that offline tests stay offline.

The socket guard is installed for the entire test session. It is not a mock of
anything the code under test uses -- nothing in ``qntyspot`` imports ``socket``
at all -- it exists so that "the suite passes offline" is enforced rather than
asserted. Any accidental future import that reaches for the network turns into
a loud failure here instead of a silent dependency on the developer's wifi.
"""

from __future__ import annotations

import copy
import socket
from typing import Any, Callable

import pytest

from qntyspot.domain import FillReceiptV0, PolicyV0, Side
from qntyspot.economics import build_intent
from qntyspot.ledger import SpotLedger, open_ledger
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

NOW = 1_700_000_100

BASE_ADDRESS = "0xc0ffee0000000000000000000000000000000001"
QUOTE_ADDRESS = "0xc0ffee0000000000000000000000000000000002"
INK_CHAIN_ID = 57073


class _NetworkAccessDenied(RuntimeError):
    """Raised if any test path attempts to open a socket."""


def _denied(*_args: Any, **_kwargs: Any) -> Any:
    raise _NetworkAccessDenied("offline unit tests must not require network access")


@pytest.fixture(scope="session", autouse=True)
def _no_network() -> Any:
    saved = {
        name: getattr(socket, name)
        for name in ("socket", "create_connection", "getaddrinfo", "socketpair")
        if hasattr(socket, name)
    }
    for name in saved:
        setattr(socket, name, _denied)
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(socket, name, value)


# --------------------------------------------------------------------------
# Policy documents
# --------------------------------------------------------------------------


def base_policy_doc() -> dict[str, Any]:
    """A minimal, admissible BUY policy. Every address here is synthetic."""
    return {
        "schema": "qntyspot.policy.v0",
        "policy_name": "fixture-buy",
        "side": "BUY",
        "base": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": BASE_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "FIXTURE",
        },
        "quote": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": QUOTE_ADDRESS,
            },
            "decimals": 6,
            "display_symbol": "USDC",
        },
        "entry_ladder": {
            "levels": [
                {"level_id": "E1", "trigger_price": "0.9", "input_amount": "100"},
                {"level_id": "E2", "trigger_price": "0.8", "input_amount": "100"},
            ]
        },
        "exit_ladder": {
            "levels": [
                {"level_id": "X1", "trigger_price": "1.2", "input_ratio": "0.5"},
                {"level_id": "X2", "trigger_price": "1.5", "input_ratio": "0.5"},
            ]
        },
        "capital": {
            "allocation_quote": "200",
            "per_order_cap_quote": "100",
            "per_instrument_cap_quote": "200",
            "per_network_cap_quote": "300",
            "global_portfolio_cap_quote": "400",
            "reserved_cash_quote": "0",
        },
        "limits": {
            "max_executable_price": "1",
            "min_executable_price": "1",
            "max_price_impact_bps": 100,
            "max_slippage_bps": 0,
        },
        "timing": {
            "valid_from_epoch_s": 1_700_000_000,
            "expiry_epoch_s": 1_800_000_000,
            "quote_ttl_s": 30,
        },
        "reentry": {
            "max_cycles": 3,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
    }


def doc_with(**overrides: Any) -> dict[str, Any]:
    """A base document with top-level sections deep-merged from ``overrides``."""
    doc = base_policy_doc()
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(doc.get(key), dict):
            merged = copy.deepcopy(doc[key])
            merged.update(value)
            doc[key] = merged
        else:
            doc[key] = value
    return doc


@pytest.fixture
def policy_doc() -> dict[str, Any]:
    return base_policy_doc()


@pytest.fixture
def policy(policy_doc: dict[str, Any]) -> PolicyV0:
    return parse_policy(policy_doc)


@pytest.fixture
def ledger() -> Any:
    with open_ledger() as led:
        yield led


@pytest.fixture
def armed(policy: PolicyV0, ledger: SpotLedger) -> Any:
    """A ledger with the policy admitted, cycle 0 open, and E1 armed."""
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
    ledger.create_intent(intent, now_epoch_s=NOW)
    return ledger, policy, cycle_id, intent


def drive(
    ledger: SpotLedger,
    action_id: str,
    *states: IntentState,
    now_epoch_s: int = NOW,
) -> None:
    for state in states:
        ledger.transition(action_id, state, now_epoch_s=now_epoch_s)


def full_receipt(intent: Any, *, ref: str = "0xfeed", now_epoch_s: int = NOW) -> FillReceiptV0:
    """A receipt that fills exactly at the committed bounds."""
    return FillReceiptV0(
        receipt_id=f"receipt-{ref}",
        economic_action_id=intent.economic_action_id,
        external_ref=ref,
        input_atomic_filled=intent.bounds.max_input_atomic,
        output_atomic_filled=intent.bounds.min_output_atomic,
        fee_atomic=0,
        observed_at_epoch_s=now_epoch_s,
        source="test-fixture",
    )


PATH_TO_FILLED = (
    IntentState.TRIGGERED,
    IntentState.QUOTE_PINNED,
    IntentState.SIMULATED,
    IntentState.RESERVED,
    IntentState.SIGNED,
    IntentState.SUBMITTED,
    IntentState.INCLUDED,
    IntentState.CONFIRMED,
)
