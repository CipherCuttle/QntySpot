"""Architectural enforcement of the V0D read-only authority boundary.

These tests do not exercise live behaviour. They read the package source and
assert that signing, key access, transaction construction/broadcast, and
ambient nondeterminism are not present. Public transport imports are allowed
because V0D includes bounded Robinhood/Chainlink/0x shadow reads.

The complementary runtime guard lives in ``conftest.py``, which disables the
socket module for the whole session.
"""

from __future__ import annotations

import ast
import socket
from pathlib import Path

import pytest

import qntyspot

PACKAGE_ROOT = Path(qntyspot.__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parent
SOURCES = sorted(PACKAGE_ROOT.rglob("*.py"))


def module_name(path: Path) -> str:
    return str(path.relative_to(PACKAGE_ROOT))


#: Anything that could sign, construct a transaction, or reach another chain.
FORBIDDEN_IMPORTS = frozenset(
    {
        # transport choices outside the one explicit urllib read path
        "socket", "ssl", "select", "selectors", "asyncio", "http", "http.client",
        "urllib3", "requests", "httpx", "aiohttp", "websocket", "websockets", "grpc",
        # evm
        "web3", "eth_account", "eth_abi", "eth_keys", "eth_utils", "hexbytes",
        "viem", "ethers",
        # solana
        "solana", "solders", "anchorpy", "spl",
        # process / external state
        "subprocess", "multiprocessing", "shutil", "ctypes", "signal",
        # non-determinism
        "random", "secrets", "uuid",
    }
)

#: Names whose mere appearance would mean the core reads ambient state.
FORBIDDEN_SOURCE_TOKENS = (
    "os.environ",
    "os.getenv",
    "getenv(",
    "environ[",
    "PRIVATE_KEY",
    "MNEMONIC",
    "SEED_PHRASE",
    "KEYSTORE",
    "keystore",
    "wallet",
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "sendTransaction",
    "signTransaction",
    "sign_transaction",
)


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
                found.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import, inside the package
                continue
            if node.module:
                found.add(node.module)
                found.add(node.module.split(".", 1)[0])
    return found


def test_the_package_has_source_files_to_check() -> None:
    assert len(SOURCES) >= 10, "the scan must actually be scanning something"


@pytest.mark.parametrize("path", SOURCES, ids=module_name)
def test_no_module_imports_a_signing_dependency(path: Path) -> None:
    offenders = sorted(imported_modules(path) & FORBIDDEN_IMPORTS)
    assert not offenders, f"{module_name(path)} imports {offenders}"


@pytest.mark.parametrize("path", SOURCES, ids=module_name)
def test_no_module_reads_ambient_secrets_or_signs_anything(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    # Docstrings legitimately name what is forbidden. Strip them before the
    # scan so prose about "no wallet signing" does not trip the check on
    # itself, while any real code reference still does.
    tree = ast.parse(source, filename=str(path))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    scannable = source
    for doc in docstrings:
        scannable = scannable.replace(doc, "")
    lowered_tokens = [
        token
        for token in FORBIDDEN_SOURCE_TOKENS
        if token.lower() in scannable.lower()
    ]
    assert not lowered_tokens, f"{module_name(path)} mentions {lowered_tokens} in code"


@pytest.mark.parametrize("path", SOURCES, ids=module_name)
def test_no_module_uses_binary_floating_point(path: Path) -> None:
    """No float literals, no float() calls, no float annotations."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, float):
            pytest.fail(f"{module_name(path)}:{node.lineno} has a float literal")
        if isinstance(node, ast.Name) and node.id == "float":
            pytest.fail(f"{module_name(path)}:{node.lineno} references float")
        if isinstance(node, ast.Attribute) and node.attr == "float":
            pytest.fail(f"{module_name(path)}:{node.lineno} references float")


@pytest.mark.parametrize("path", SOURCES, ids=module_name)
def test_no_module_reads_a_clock(path: Path) -> None:
    """Time is always an explicit argument. That is what makes replay exact."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    banned = {"time", "monotonic", "now", "today", "utcnow", "time_ns", "perf_counter"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in banned:
                pytest.fail(
                    f"{module_name(path)}:{node.lineno} calls .{node.func.attr}(); "
                    "pass now_epoch_s explicitly instead"
                )


def test_the_declared_dependency_set_is_empty() -> None:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in pyproject
    for forbidden in ("web3", "viem", "solana", "solders", "requests", "httpx", "aiohttp"):
        assert f'"{forbidden}' not in pyproject, f"{forbidden} must not be a dependency"


def test_the_package_declares_its_phase_as_read_only_shadow() -> None:
    assert qntyspot.AUTHORITY == "ROBINHOOD_SHADOW_READ_ONLY"
    assert qntyspot.NETWORK_AUTHORIZED is True
    assert qntyspot.SIGNING_AUTHORIZED is False
    assert qntyspot.LIVE_CAPITAL_AUTHORIZED is False


def test_the_boundary_protocols_have_no_implementations() -> None:
    """The venue and chain-truth seams are types, not code."""
    import qntyspot.boundary as boundary

    for name in ("QuoteSource", "ExecutionVenueAdapter", "ChainTruthSource", "Reconciler"):
        protocol = getattr(boundary, name)
        assert getattr(protocol, "_is_protocol", False), f"{name} must stay a Protocol"


def test_the_socket_guard_is_actually_armed() -> None:
    """Proof that the session-wide network block is in force, not just declared."""
    with pytest.raises(RuntimeError, match="offline unit tests"):
        socket.socket()
    with pytest.raises(RuntimeError, match="offline unit tests"):
        socket.create_connection(("example.invalid", 80))


def test_a_full_lifecycle_completes_with_the_network_blocked(tmp_path) -> None:
    """The end-to-end path runs to FILLED while sockets are unavailable."""
    from conftest import NOW, PATH_TO_FILLED, base_policy_doc, drive, full_receipt
    from qntyspot.economics import build_intent
    from qntyspot.ledger import assert_replay_equivalence, open_ledger
    from qntyspot.policy import parse_policy
    from qntyspot.states import IntentState

    policy = parse_policy(base_policy_doc())
    with open_ledger(str(tmp_path / "offline.sqlite3")) as ledger:
        ledger.admit_policy(policy)
        cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=NOW)
        intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=NOW)
        ledger.create_intent(intent, now_epoch_s=NOW)
        drive(ledger, intent.economic_action_id, *PATH_TO_FILLED)
        ledger.append_fill_receipt(full_receipt(intent), now_epoch_s=NOW)
        drive(ledger, intent.economic_action_id, IntentState.RECONCILED, IntentState.FILLED)
        assert ledger.intent_state(intent.economic_action_id) is IntentState.FILLED
        assert_replay_equivalence(ledger)
