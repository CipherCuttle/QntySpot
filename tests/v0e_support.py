"""Small deterministic primitives shared by the V0E hostile tests.

This module is test-only.  It deliberately models transport faults at the
same callable seams used by the three bounded adapters; it never opens a
socket and it never supplies a signer or a wallet.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from qntyspot.canon import canonical_json_bytes, digest_object


@dataclass(frozen=True, slots=True)
class FaultStep:
    """One deterministic response or exception in a scripted sequence."""

    label: str
    value: bytes | BaseException


class ScriptedRpcTransport:
    """Finite JSON-RPC transport with observable, deterministic call count."""

    def __init__(self, steps: Iterable[FaultStep]) -> None:
        self._steps = tuple(steps)
        self.calls = 0

    def __call__(self, _payload: bytes) -> bytes:
        index = self.calls
        self.calls += 1
        if index >= len(self._steps):
            raise AssertionError("scripted RPC transport exhausted")
        step = self._steps[index]
        if isinstance(step.value, BaseException):
            raise step.value
        return step.value


class ScriptedHttpTransport:
    """Finite HTTP callable; the adapter still owns parsing and bounds."""

    def __init__(self, steps: Iterable[FaultStep]) -> None:
        self._steps = tuple(steps)
        self.calls = 0
        self.targets: list[str] = []

    def __call__(self, target: str, _query: bytes, _headers: dict[str, str]) -> bytes:
        index = self.calls
        self.calls += 1
        self.targets.append(target)
        if index >= len(self._steps):
            raise AssertionError("scripted HTTP transport exhausted")
        step = self._steps[index]
        if isinstance(step.value, BaseException):
            raise step.value
        return step.value


@dataclass(frozen=True, slots=True)
class DeterministicClock:
    """An explicit clock value; no test may consult wall-clock state."""

    epoch_s: int

    def now_epoch_s(self) -> int:
        return self.epoch_s


@dataclass(frozen=True, slots=True)
class Scenario:
    scenario_id: str
    adapter: str
    injected_fault: str
    expected_terminal_class: str


@dataclass(frozen=True, slots=True)
class ScenarioReceipt:
    scenario_id: str
    adapter: str
    injected_fault: str
    expected_terminal_class: str
    observed_terminal_class: str
    reason_code: str
    economic_action_id: str | None
    reservation_disposition: str | None
    network_read_count: int
    secret_read_count: int
    signing_count: int
    broadcast_count: int

    def canonical_object(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "broadcast_count": self.broadcast_count,
            "economic_action_id": self.economic_action_id,
            "expected_terminal_class": self.expected_terminal_class,
            "injected_fault": self.injected_fault,
            "network_read_count": self.network_read_count,
            "observed_terminal_class": self.observed_terminal_class,
            "reason_code": self.reason_code,
            "reservation_disposition": self.reservation_disposition,
            "scenario_id": self.scenario_id,
            "secret_read_count": self.secret_read_count,
            "signing_count": self.signing_count,
        }

    def digest(self) -> str:
        return digest_object(self.canonical_object())


def preregistered_scenarios(text: str) -> tuple[Scenario, ...]:
    """Read the frozen registry rather than maintaining a second ID list."""

    pattern = re.compile(
        r"\| `(V0E-[A-Z0-9]+)` \| ([^|]+) \| ([^|]+) \| `([^`]+)` \|"
    )
    scenarios = tuple(
        Scenario(
            scenario_id=match.group(1),
            adapter=match.group(2).strip(),
            injected_fault=match.group(3).strip(),
            expected_terminal_class=match.group(4),
        )
        for match in pattern.finditer(text)
    )
    if not scenarios:
        raise AssertionError("frozen V0E preregistration contains no scenario rows")
    ids = [scenario.scenario_id for scenario in scenarios]
    if len(ids) != len(set(ids)):
        raise AssertionError("frozen V0E preregistration contains duplicate IDs")
    return scenarios


def stable_reason(exc: BaseException) -> str:
    """Normalize exception evidence so temporary paths cannot affect a digest."""

    text = str(exc)
    text = re.sub(r"/tmp/[^\s:]+", "<tmp>", text)
    text = re.sub(r"/home/[^\s:]+", "<path>", text)
    return f"{type(exc).__name__}:{text}"


def receipt_for(
    scenario: Scenario,
    operation: Callable[[], Any],
    *,
    economic_action_id: str | None = None,
    reservation_disposition: str | None = None,
    transport_calls: int = 0,
    secret_read_count: int = 0,
) -> ScenarioReceipt:
    """Run one real boundary operation and convert its result into evidence."""

    try:
        result = operation()
        if economic_action_id is None:
            economic_action_id = getattr(result, "economic_action_id", None)
        if isinstance(result, str):
            observed = result
            reason = result
        else:
            observed = getattr(result, "decision", None)
            if observed not in {"ABSTAIN", "WOULD_EXECUTE"}:
                observed = "REJECTED"
            reason = getattr(result, "reason_code", type(result).__name__)
    except BaseException as exc:  # receipt creation must include hostile failures
        observed = {
            "SafeHaltError": "SAFE_HALT",
            "DuplicateEconomicActionError": "REJECTED",
            "BudgetExceededError": "REJECTED",
            "StateTransitionError": "REJECTED",
            "LevelNotExecutableError": "REJECTED",
            "CanonicalFormError": "REJECTED",
            "PolicySchemaError": "REJECTED",
            "IdentityError": "REJECTED",
            "RobinhoodProtocolError": "REJECTED",
            "SolanaProtocolError": "REJECTED",
            "RpcProtocolError": "REJECTED",
            "RpcResponseTooLargeError": "REJECTED",
            "SolanaResponseTooLargeError": "REJECTED",
            "RobinhoodTransportError": "SAFE_HALT",
            "RpcTimeoutError": "SAFE_HALT",
            "RpcTransportError": "SAFE_HALT",
            "SolanaTimeoutError": "SAFE_HALT",
            "SolanaTransportError": "SAFE_HALT",
        }.get(type(exc).__name__, "REJECTED")
        reason = stable_reason(exc)
    return ScenarioReceipt(
        scenario_id=scenario.scenario_id,
        adapter=scenario.adapter,
        injected_fault=scenario.injected_fault,
        expected_terminal_class=scenario.expected_terminal_class,
        observed_terminal_class=observed,
        reason_code=reason,
        economic_action_id=economic_action_id,
        reservation_disposition=reservation_disposition,
        # Scripted transport calls are not network reads.  The suite's
        # network-read counter is explicitly the real-network count.
        network_read_count=0,
        secret_read_count=secret_read_count,
        signing_count=0,
        broadcast_count=0,
    )


def receipt_bytes(receipts: Iterable[ScenarioReceipt]) -> bytes:
    """Canonical bytes for a whole run, sorted by immutable ScenarioID."""

    objects = [receipt.canonical_object() for receipt in sorted(receipts, key=lambda item: item.scenario_id)]
    return canonical_json_bytes({"receipts": objects, "schema": "V0E_HOSTILE_RECEIPTS_V0"})


def receipt_digest(receipts: Iterable[ScenarioReceipt]) -> str:
    return hashlib.sha256(receipt_bytes(receipts)).hexdigest()
