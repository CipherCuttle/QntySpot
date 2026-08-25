"""Small deterministic primitives shared by the V0E hostile tests.

This module is test-only.  It deliberately models transport faults at the
same callable seams used by the three bounded adapters; it never opens a
socket and it never supplies a signer or a wallet.
"""

from __future__ import annotations

import builtins
import hashlib
import http.client
import inspect
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from qntyspot.canon import canonical_json_bytes, digest_object
from qntyspot.errors import (
    BudgetExceededError,
    CanonicalFormError,
    CycleLimitError,
    DuplicateEconomicActionError,
    IdentityError,
    InkError,
    JupiterApiError,
    LedgerError,
    LevelNotExecutableError,
    PolicyError,
    PolicyMissingError,
    PolicyParseError,
    PolicySchemaError,
    ReplayDivergenceError,
    RobinhoodError,
    RobinhoodProtocolError,
    RobinhoodTransportError,
    RpcError,
    RpcProtocolError,
    RpcResponseTooLargeError,
    RpcTimeoutError,
    RpcTransportError,
    SafeHaltError,
    SchemaVersionError,
    SolanaError,
    SolanaProtocolError,
    SolanaResponseTooLargeError,
    SolanaTimeoutError,
    SolanaTransportError,
    StateTransitionError,
    ZeroXApiError,
    ZeroXApiKeyRequired,
)


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


class NetworkTripwire:
    """Fail-closed instrumentation for every standard-library market seam."""

    def __init__(self) -> None:
        self.attempts = 0
        self.surfaces: list[str] = []

    def _trip(self, surface: str, *_args: Any, **_kwargs: Any) -> Any:
        self.attempts += 1
        self.surfaces.append(surface)
        raise AssertionError(f"market network escape at {surface}")

    @contextmanager
    def installed(self) -> Iterable[None]:
        targets = (
            (socket, "socket", "socket.socket"),
            (socket, "create_connection", "socket.create_connection"),
            (socket, "getaddrinfo", "socket.getaddrinfo"),
            (socket, "socketpair", "socket.socketpair"),
            (urllib.request, "urlopen", "urllib.request.urlopen"),
            (urllib.request.OpenerDirector, "open", "urllib.request.OpenerDirector.open"),
            (http.client.HTTPConnection, "connect", "http.client.HTTPConnection.connect"),
            (http.client.HTTPSConnection, "connect", "http.client.HTTPSConnection.connect"),
        )
        saved = [(owner, name, getattr(owner, name)) for owner, name, _ in targets]
        for owner, name, label in targets:
            setattr(owner, name, lambda *args, _label=label, **kwargs: self._trip(_label, *args, **kwargs))
        try:
            yield
        finally:
            for owner, name, value in saved:
                setattr(owner, name, value)


class AmbientSecretTripwire:
    """Count and reject ambient environment-secret reads."""

    def __init__(self) -> None:
        self.attempts = 0
        self.surfaces: list[str] = []

    def _trip(self, surface: str, *_args: Any, **_kwargs: Any) -> Any:
        self.attempts += 1
        self.surfaces.append(surface)
        raise AssertionError(f"ambient secret access at {surface}")

    @staticmethod
    def _is_secret_name(value: object) -> bool:
        if not isinstance(value, str):
            return False
        name = value.upper()
        return any(token in name for token in ("KEY", "SECRET", "SEED", "WALLET", "MNEMONIC", "PRIVATE"))

    @contextmanager
    def installed(self) -> Iterable[None]:
        environ_type = type(os.environ)
        targets = (
            (os, "getenv", "os.getenv"),
            (environ_type, "get", "os.environ.get"),
            (environ_type, "__getitem__", "os.environ.__getitem__"),
        )
        saved = [(owner, name, getattr(owner, name)) for owner, name, _ in targets]
        for owner, name, label in targets:
            original = getattr(owner, name)

            def guarded(*args: Any, _label: str = label, _original: Any = original, **kwargs: Any) -> Any:
                if args and self._is_secret_name(args[0]):
                    return self._trip(_label, *args, **kwargs)
                return _original(*args, **kwargs)

            setattr(owner, name, guarded)
        try:
            yield
        finally:
            for owner, name, value in saved:
                setattr(owner, name, value)


class AuthorityTripwire:
    """Dynamic guard for private-key files, wallet CLIs, and env secrets."""

    def __init__(self) -> None:
        self.attempts = 0
        self.surfaces: list[str] = []

    def _trip(self, surface: str, *_args: Any, **_kwargs: Any) -> Any:
        self.attempts += 1
        self.surfaces.append(surface)
        raise AssertionError(f"forbidden authority boundary at {surface}")

    @staticmethod
    def _is_authority_name(value: object) -> bool:
        if not isinstance(value, str):
            return False
        name = value.upper()
        return any(token in name for token in ("ZEROX_API_KEY", "PRIVATE_KEY", "SEED", "WALLET", "MNEMONIC", "KEYSTORE", "SIGNER"))

    @contextmanager
    def installed(self) -> Iterable[None]:
        environ_type = type(os.environ)
        targets = (
            (builtins, "open", "builtins.open"),
            (Path, "open", "pathlib.Path.open"),
            (Path, "read_bytes", "pathlib.Path.read_bytes"),
            (Path, "read_text", "pathlib.Path.read_text"),
            (subprocess, "run", "subprocess.run"),
            (subprocess, "Popen", "subprocess.Popen"),
            (subprocess, "check_call", "subprocess.check_call"),
            (subprocess, "check_output", "subprocess.check_output"),
            (os, "system", "os.system"),
            (os, "getenv", "os.getenv"),
            (environ_type, "get", "os.environ.get"),
            (environ_type, "__getitem__", "os.environ.__getitem__"),
        )
        saved = [(owner, name, getattr(owner, name)) for owner, name, _ in targets]
        for owner, name, label in targets:
            original = getattr(owner, name)
            if owner is os and name == "getenv" or name in {"get", "__getitem__"}:
                def guarded_env(*args: Any, _label: str = label, _original: Any = original, **kwargs: Any) -> Any:
                    if args and self._is_authority_name(args[-1] if len(args) > 1 else args[0]):
                        return self._trip(_label, *args, **kwargs)
                    return _original(*args, **kwargs)

                setattr(owner, name, guarded_env)
            else:
                setattr(owner, name, lambda *args, _label=label, **kwargs: self._trip(_label, *args, **kwargs))
        try:
            yield
        finally:
            for owner, name, value in saved:
                setattr(owner, name, value)


class SideEffectTripwire:
    """Instrument any callable authority-like seam exposed by qntyspot."""

    def __init__(self) -> None:
        self.signing_attempts = 0
        self.approval_attempts = 0
        self.broadcast_attempts = 0
        self.surfaces: list[str] = []

    def _trip(self, module_name: str, attribute: str, *_args: Any, **_kwargs: Any) -> Any:
        lowered = attribute.lower()
        if "broadcast" in lowered or "submit" in lowered:
            self.broadcast_attempts += 1
        elif "approv" in lowered:
            self.approval_attempts += 1
        else:
            self.signing_attempts += 1
        self.surfaces.append(f"{module_name}.{attribute}")
        raise AssertionError(f"forbidden side effect at {module_name}.{attribute}")

    @contextmanager
    def installed(self) -> Iterable[None]:
        targets: list[tuple[Any, str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for module_name, module in tuple(sys.modules.items()):
            if not module_name.startswith("qntyspot.") or module is None:
                continue
            for attribute, value in vars(module).items():
                owners = ((module, attribute, value),)
                if inspect.isclass(value) and getattr(value, "__module__", "").startswith("qntyspot."):
                    owners += tuple((value, child_name, child_value) for child_name, child_value in vars(value).items())
                for owner, child_name, child_value in owners:
                    lowered = child_name.lower()
                    if not callable(child_value):
                        continue
                    authority_name = lowered.strip("_")
                    if not (
                        authority_name in {"sign", "signature", "approve", "approval", "broadcast", "submit", "wallet", "keystore", "private_key", "seed"}
                        or authority_name.startswith(("sign_", "approve_", "broadcast_", "submit_", "wallet_", "keystore_", "private_key_", "seed_"))
                    ):
                        continue
                    key = (id(owner), child_name)
                    if key not in seen:
                        seen.add(key)
                        targets.append((owner, child_name, child_value))
        for module, attribute, _value in targets:
            module_name = module.__name__
            setattr(module, attribute, lambda *args, _module_name=module_name, _attribute=attribute, **kwargs: self._trip(_module_name, _attribute, *args, **kwargs))
        try:
            yield
        finally:
            for module, attribute, value in targets:
                setattr(module, attribute, value)


@contextmanager
def wall_clock_tripwire() -> Iterable[None]:
    """Reject replay implementations that consult ambient wall-clock state."""

    saved = [(time, name, getattr(time, name)) for name in ("time", "monotonic", "perf_counter")]
    for _owner, name, _value in saved:
        setattr(time, name, lambda *_args, _name=name, **_kwargs: (_ for _ in ()).throw(
            AssertionError(f"replay consulted time.{_name}")
        ))
    try:
        yield
    finally:
        for owner, name, value in saved:
            setattr(owner, name, value)


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
class ScenarioOutcome:
    """A real operation's terminal classification plus receipt metadata."""

    terminal_class: str
    reason_code: str
    economic_action_id: str | None = None
    reservation_disposition: str | None = None


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
    approval_count: int
    broadcast_count: int

    def canonical_object(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "approval_count": self.approval_count,
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
    secret_read_count: int | Callable[[], int] = 0,
    network_read_count: int | Callable[[], int] = 0,
    signing_count: int | Callable[[], int] = 0,
    approval_count: int | Callable[[], int] = 0,
    broadcast_count: int | Callable[[], int] = 0,
) -> ScenarioReceipt:
    """Run one real boundary operation and convert its result into evidence."""

    try:
        result = operation()
        if isinstance(result, ScenarioOutcome):
            observed = result.terminal_class
            reason = result.reason_code
            if economic_action_id is None:
                economic_action_id = result.economic_action_id
            if reservation_disposition is None:
                reservation_disposition = result.reservation_disposition
        else:
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
    except AssertionError:
        # Tripwires and fixture assertions are evidence failures, never a
        # terminal class that the receipt layer may normalize.
        raise
    except BaseException as exc:  # receipt creation must include enumerated hostile failures
        terminal_map = {
            SafeHaltError: "SAFE_HALT",
            DuplicateEconomicActionError: "REJECTED",
            BudgetExceededError: "REJECTED",
            LedgerError: "REJECTED",
            ReplayDivergenceError: "REJECTED",
            SchemaVersionError: "REJECTED",
            StateTransitionError: "REJECTED",
            LevelNotExecutableError: "REJECTED",
            CycleLimitError: "REJECTED",
            CanonicalFormError: "REJECTED",
            PolicyError: "REJECTED",
            PolicyMissingError: "REJECTED",
            PolicyParseError: "REJECTED",
            PolicySchemaError: "REJECTED",
            IdentityError: "REJECTED",
            InkError: "REJECTED",
            RpcError: "REJECTED",
            RobinhoodProtocolError: "REJECTED",
            RobinhoodError: "REJECTED",
            ZeroXApiError: "REJECTED",
            ZeroXApiKeyRequired: "REJECTED",
            SolanaError: "REJECTED",
            JupiterApiError: "REJECTED",
            SolanaProtocolError: "REJECTED",
            RpcProtocolError: "REJECTED",
            RpcResponseTooLargeError: "REJECTED",
            SolanaResponseTooLargeError: "REJECTED",
            RobinhoodTransportError: "SAFE_HALT",
            RpcTimeoutError: "SAFE_HALT",
            RpcTransportError: "SAFE_HALT",
            SolanaTimeoutError: "SAFE_HALT",
            SolanaTransportError: "SAFE_HALT",
        }
        if type(exc) not in terminal_map:
            raise
        observed = terminal_map[type(exc)]
        reason = stable_reason(exc)
    observed_network_reads = (
        network_read_count() if callable(network_read_count) else network_read_count
    )
    observed_secret_reads = (
        secret_read_count() if callable(secret_read_count) else secret_read_count
    )
    observed_signing = signing_count() if callable(signing_count) else signing_count
    observed_approvals = approval_count() if callable(approval_count) else approval_count
    observed_broadcasts = broadcast_count() if callable(broadcast_count) else broadcast_count
    return ScenarioReceipt(
        scenario_id=scenario.scenario_id,
        adapter=scenario.adapter,
        injected_fault=scenario.injected_fault,
        expected_terminal_class=scenario.expected_terminal_class,
        observed_terminal_class=observed,
        reason_code=reason,
        economic_action_id=economic_action_id,
        reservation_disposition=reservation_disposition,
        # Scripted transports are not network reads.  The caller supplies the
        # count observed by NetworkTripwire around the real operation.
        network_read_count=observed_network_reads,
        secret_read_count=observed_secret_reads,
        signing_count=observed_signing,
        approval_count=observed_approvals,
        broadcast_count=observed_broadcasts,
    )


def receipt_bytes(receipts: Iterable[ScenarioReceipt]) -> bytes:
    """Canonical bytes for a whole run, sorted by immutable ScenarioID."""

    objects = [receipt.canonical_object() for receipt in sorted(receipts, key=lambda item: item.scenario_id)]
    return canonical_json_bytes({"receipts": objects, "schema": "V0E_HOSTILE_RECEIPTS_V0"})


def receipt_digest(receipts: Iterable[ScenarioReceipt]) -> str:
    return hashlib.sha256(receipt_bytes(receipts)).hexdigest()
