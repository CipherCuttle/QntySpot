#!/usr/bin/env python3
"""Verify QntySpot's deterministic, authority-neutral continuity floor."""

from __future__ import annotations

import ast
import hashlib
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "qntyspot"
CLOSURE_PATH = ROOT / "docs/PROGRAM_A_CONTROL_PLANE_CLOSURE_V0.md"
PROGRAM_B_PATH = ROOT / "docs/PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md"
REGISTRY_PATH = ROOT / "docs/V0E_HOSTILE_FAILURE_SUITE_PREREG_V0.md"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from qntyspot.canon import canonical_json_bytes, digest_object, strict_json_loads

FORBIDDEN_IMPORTS = frozenset(
    {
        "socket",
        "ssl",
        "select",
        "selectors",
        "asyncio",
        "http",
        "urllib3",
        "requests",
        "httpx",
        "aiohttp",
        "websocket",
        "websockets",
        "grpc",
        "web3",
        "eth_account",
        "eth_abi",
        "eth_keys",
        "eth_utils",
        "hexbytes",
        "viem",
        "ethers",
        "solana",
        "solders",
        "anchorpy",
        "spl",
        "subprocess",
        "multiprocessing",
        "shutil",
        "ctypes",
        "signal",
        "random",
        "secrets",
        "uuid",
    }
)

FORBIDDEN_SOURCE_TOKENS = (
    "os.environ",
    "os.getenv",
    "getenv(",
    "environ[",
    "PRIVATE_KEY",
    "MNEMONIC",
    "SEED_PHRASE",
    "KEYSTORE",
    "eth_sendRawTransaction",
    "eth_sendTransaction",
    "sendTransaction",
    "signTransaction",
    "sign_transaction",
)

REGISTRY_ROW = re.compile(
    r"\| `(V0E-[A-Z0-9]+)` \| ([^|]+) \| ([^|]+) \| `([^`]+)` \|"
)

FROZEN_V0E_REGISTRY_SHA256 = "b3ac34d263ee124524d6e90d09a1462b814b93a1109f80d2c85d634b3048076b"
FROZEN_V0E_SCENARIO_IDENTITY_SHA256 = "b0cc2ed473691e4fd6590c9cb6a86b79f69495d1d366eece0932cd1eeebf6f2b"
FROZEN_QUALIFICATION_SNAPSHOT_SHA256 = {
    "robinhood_v0d": "b9970efa82ca5c3a6735be3e093f6ee0103b09c47daaef35ce263fedbc5ea552",
    "robinhood_v0d_r1": "ccc6c9c65bc6f586f9088889d3894d6a283ddbfc6ea1dc76c1a9cd04b7cefd0a",
    "robinhood_v0d_r2": "d4d1411acba0eabcf39e8b0931fe30700306b5a89994256d7ff27a971c8dbfcf",
    "robinhood_v0d_r2r1": "1e78a0ec86fcedda8931213b71b7952999660207c9eebd4bbaf0d9ac167dd893",
}
FROZEN_RESULT_SHA256 = {
    "robinhood_v0d_r1": "15af5b3aba152827c8e49818afe38473811f627e0c2f0d83868d90b380c8726c",
    "robinhood_v0d_r2": "5ced257b466b0782316880d1f720d941cdc51e34b39ae89d2f4de03a36202b18",
    "robinhood_v0d_r2r1": "4a7cef4fd8b40d41098df792c8368b6e365c89ee0ec26769f630ac3794b9d42d",
}


def _imports(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module.split(".", 1)[0])
    return found


def _without_docstrings(source: str, tree: ast.AST) -> str:
    docstrings: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)
    for doc in docstrings:
        source = source.replace(doc, "")
    return source


def _static_authority_report() -> dict[str, Any]:
    offenders: list[str] = []
    token_hits: list[str] = []
    float_hits: list[str] = []
    clock_hits: list[str] = []
    modules = sorted(PACKAGE_ROOT.rglob("*.py"))
    for path in modules:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        relative = path.relative_to(ROOT).as_posix()
        for name in sorted(_imports(tree) & FORBIDDEN_IMPORTS):
            offenders.append(f"{relative}:import:{name}")
        scannable = _without_docstrings(source, tree).lower()
        for token in FORBIDDEN_SOURCE_TOKENS:
            if token.lower() in scannable:
                token_hits.append(f"{relative}:{token}")
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, float):
                float_hits.append(f"{relative}:{node.lineno}")
            if isinstance(node, ast.Name) and node.id == "float":
                float_hits.append(f"{relative}:{node.lineno}")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"time", "monotonic", "perf_counter", "time_ns"}:
                    clock_hits.append(f"{relative}:{node.lineno}")
    if offenders or token_hits or float_hits or clock_hits:
        raise SystemExit(
            "authority continuity failed: "
            + "; ".join(offenders + token_hits + float_hits + clock_hits)
        )
    return {
        "module_count": len(modules),
        "forbidden_imports": [],
        "forbidden_source_tokens": [],
        "binary_float_hits": [],
        "ambient_clock_hits": [],
    }


def _registry_report() -> dict[str, Any]:
    text = REGISTRY_PATH.read_text(encoding="utf-8")
    rows = [
        {
            "adapter": match.group(2).strip(),
            "expected_terminal_class": match.group(4),
            "injected_fault": match.group(3).strip(),
            "scenario_id": match.group(1),
        }
        for match in REGISTRY_ROW.finditer(text)
    ]
    ids = [row["scenario_id"] for row in rows]
    registry_sha256 = hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest()
    scenario_identity_sha256 = hashlib.sha256(_canonical_bytes(rows)).hexdigest()
    if (
        len(rows) != 114
        or len(ids) != len(set(ids))
        or registry_sha256 != FROZEN_V0E_REGISTRY_SHA256
        or scenario_identity_sha256 != FROZEN_V0E_SCENARIO_IDENTITY_SHA256
    ):
        raise SystemExit("authority continuity failed: V0E registry identity")
    if ids[0] != "V0E-T01" or ids[-1] != "V0E-A11":
        raise SystemExit("authority continuity failed: V0E registry bounds")
    return {
        "count": len(rows),
        "first_id": ids[0],
        "last_id": ids[-1],
        "registry_sha256": registry_sha256,
        "scenario_identity_sha256": scenario_identity_sha256,
    }


def _canonical_bytes(value: Any) -> bytes:
    return canonical_json_bytes(value)


def _qualification_snapshot_sha256(root: Path) -> str:
    inventory = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            content = path.read_bytes()
            inventory.append(
                {
                    "bytes": len(content),
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
    return hashlib.sha256(_canonical_bytes(inventory)).hexdigest()


def _evidence_report() -> dict[str, Any]:
    qualifications = tuple(
        ROOT / "qualifications" / name
        for name in (
            "robinhood_v0d",
            "robinhood_v0d_r1",
            "robinhood_v0d_r2",
            "robinhood_v0d_r2r1",
        )
    )
    response_count = 0
    manifest_count = 0
    for qualification in qualifications:
        qualification_name = qualification.name
        expected_snapshot = FROZEN_QUALIFICATION_SNAPSHOT_SHA256[qualification_name]
        if _qualification_snapshot_sha256(qualification) != expected_snapshot:
            raise SystemExit(f"authority continuity failed: qualification snapshot {qualification_name}")
        response_paths = sorted((qualification / "RAW_EVIDENCE_V0" / "responses").glob("*.bin"))
        manifest_paths = sorted((qualification / "RAW_EVIDENCE_V0" / "manifests").glob("*.json"))
        response_count += len(response_paths)
        manifest_count += len(manifest_paths)
        for path in response_paths:
            if path.stem != hashlib.sha256(path.read_bytes()).hexdigest():
                raise SystemExit(f"authority continuity failed: {path}")
        for path in manifest_paths:
            document = strict_json_loads(path.read_bytes())
            response = qualification / "RAW_EVIDENCE_V0" / document["response_path"]
            if not response.is_file():
                raise SystemExit(f"authority continuity failed: missing {response}")
            response_bytes = response.read_bytes()
            if (
                document["response_sha256"] != hashlib.sha256(response_bytes).hexdigest()
                or document["response_bytes"] != len(response_bytes)
                or document["request_sha256"] != digest_object(document["request"])
                or path.read_bytes() != _canonical_bytes(document)
            ):
                raise SystemExit(f"authority continuity failed: manifest {path}")
    result_paths = {
        "robinhood_v0d_r1": ROOT / "qualifications/robinhood_v0d_r1/R1_RESULT.md",
        "robinhood_v0d_r2": ROOT / "qualifications/robinhood_v0d_r2/R2_RESULT.md",
        "robinhood_v0d_r2r1": ROOT / "qualifications/robinhood_v0d_r2r1/R2R1_RESULT.md",
    }
    for qualification_name, path in result_paths.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != FROZEN_RESULT_SHA256[qualification_name]:
            raise SystemExit(f"authority continuity failed: result snapshot {qualification_name}")
    r2_result = result_paths["robinhood_v0d_r2"].read_text(encoding="utf-8")
    r2r1_result = result_paths["robinhood_v0d_r2r1"].read_text(encoding="utf-8")
    if "V0D_R2_NOT_QUALIFIED" not in r2_result:
        raise SystemExit("authority continuity failed: R2 result was rewritten")
    if "VALID_QUOTE_WITH_BALANCE_ISSUE_AND_ALLOWANCE_ISSUE" not in r2r1_result:
        raise SystemExit("authority continuity failed: R2R1 result identity")
    return {
        "qualification_directories": [path.name for path in qualifications],
        "response_count": response_count,
        "manifest_count": manifest_count,
        "r1_preserved": (ROOT / "qualifications/robinhood_v0d_r1/R1_RESULT.md").is_file(),
        "r2_preserved": "V0D_R2_NOT_QUALIFIED" in r2_result,
        "r2r1_preserved": "LIVE_ELIGIBILITY_CONFIRMED = NO" in r2r1_result,
    }


def _closure_report() -> dict[str, Any]:
    text = CLOSURE_PATH.read_text(encoding="utf-8")
    expected = {
        "phase_claim": "PHASE_CLAIM                      = READ_ONLY_SHADOW_INTEGRATION_QUALIFIED",
        "quote_qualified": "ROBINHOOD_SHADOW_QUOTE_QUALIFIED = YES",
        "firm_quote_valid": "ZEROX_FIRM_QUOTE_VALID            = YES",
        "liquidity_available": "LIQUIDITY_AVAILABLE               = YES",
        "balance_ready": "BALANCE_READY                     = NO",
        "allowance_ready": "ALLOWANCE_READY                   = NO",
        "live_execution_authorized": "LIVE_EXECUTION_AUTHORIZED         = NO",
        "live_execution_evaluated": "LIVE_EXECUTION_EVALUATED          = NO",
        "capital_authorized": "CAPITAL_AUTHORIZED                = NO",
    }
    missing = [name for name, line in expected.items() if line not in text]
    if missing:
        raise SystemExit(f"authority continuity failed: closure fields {missing}")
    return {
        "path": CLOSURE_PATH.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(CLOSURE_PATH.read_bytes()).hexdigest(),
        "phase_claim": "READ_ONLY_SHADOW_INTEGRATION_QUALIFIED",
        "live_execution_authorized": False,
        "capital_authorized": False,
    }


def _program_b_report() -> dict[str, Any]:
    """Program B must remain a contract freeze that grants no runtime authority."""
    from qntyspot.execution_contract import (
        CONTRACT_VERSION,
        KILL_SWITCH_PRESERVED_CAPABILITIES,
        LADDER,
        PHASE_GRANTED_AUTHORITY_LEVEL,
        AuthorityLevel,
        Capability,
        require_capability,
    )
    from qntyspot.errors import AuthorityCeilingError
    from qntyspot.ledger.execution_schema import EXECUTION_SCHEMA_VERSION, EXECUTION_TABLES

    if PHASE_GRANTED_AUTHORITY_LEVEL is not AuthorityLevel.SHADOW:
        raise SystemExit("authority continuity failed: Program B phase ceiling moved")
    ordered = sorted(AuthorityLevel)
    if any(LADDER[lower] >= LADDER[higher] for lower, higher in zip(ordered, ordered[1:])):
        raise SystemExit("authority continuity failed: authority ladder is not monotone")
    escalating = (
        Capability.RESERVE_CAPITAL,
        Capability.CONSTRUCT_ENVELOPE,
        Capability.AUTHORIZE_APPROVAL,
        Capability.PRODUCE_SIGNATURE,
        Capability.SUBMIT_EXACT_BYTES,
    )
    for capability in escalating:
        for level in AuthorityLevel:
            try:
                require_capability(capability, level)
            except AuthorityCeilingError:
                continue
            raise SystemExit(
                f"authority continuity failed: {capability.value} reachable at {level.name}"
            )
        if capability in KILL_SWITCH_PRESERVED_CAPABILITIES:
            raise SystemExit(
                f"authority continuity failed: kill switch preserves {capability.value}"
            )
    for capability in (Capability.RECONCILE, Capability.ACCOUNT_QUARANTINE, Capability.OBSERVE_CHAIN):
        if capability not in KILL_SWITCH_PRESERVED_CAPABILITIES:
            raise SystemExit(
                f"authority continuity failed: kill switch suspends {capability.value}"
            )
    if not PROGRAM_B_PATH.is_file():
        raise SystemExit("authority continuity failed: Program B contract is missing")
    text = PROGRAM_B_PATH.read_text(encoding="utf-8")
    expected = (
        "SIGNING_AUTHORIZED        = NO",
        "LIVE_CAPITAL_AUTHORIZED   = NO",
        "CAPITAL_AUTHORITY         = NONE",
        "PHASE_GRANTED_AUTHORITY   = LEVEL 0 (SHADOW)",
    )
    if missing := [line for line in expected if line not in text]:
        raise SystemExit(f"authority continuity failed: Program B fields {missing}")
    return {
        "contract_version": CONTRACT_VERSION,
        "execution_schema_version": EXECUTION_SCHEMA_VERSION,
        "execution_table_count": len(EXECUTION_TABLES),
        "granted_authority_level": int(PHASE_GRANTED_AUTHORITY_LEVEL),
        "ladder_is_monotone": True,
        "path": PROGRAM_B_PATH.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(PROGRAM_B_PATH.read_bytes()).hexdigest(),
    }


def _state_machine_report() -> dict[str, Any]:
    from qntyspot.states import (
        BUDGET_HOLDING_STATES,
        EXTERNALLY_AMBIGUOUS_STATES,
        PRE_COMMITMENT_STATES,
        TERMINAL_STATES,
        TRANSITIONS,
        IntentState,
    )

    if set(TRANSITIONS) != set(IntentState):
        raise SystemExit("authority continuity failed: incomplete state table")
    if any(TRANSITIONS[state] for state in TERMINAL_STATES):
        raise SystemExit("authority continuity failed: terminal state has an exit")
    if any(state in TRANSITIONS[IntentState.SIGNED] for state in (IntentState.CANCELLED, IntentState.EXPIRED)):
        raise SystemExit("authority continuity failed: signed action can be abandoned")
    if not EXTERNALLY_AMBIGUOUS_STATES.issubset(BUDGET_HOLDING_STATES):
        raise SystemExit("authority continuity failed: ambiguous reservation accounting")
    if not PRE_COMMITMENT_STATES.isdisjoint(EXTERNALLY_AMBIGUOUS_STATES):
        raise SystemExit("authority continuity failed: state classification overlap")
    return {
        "state_count": len(IntentState),
        "terminal_state_count": len(TERMINAL_STATES),
        "externally_ambiguous_state_count": len(EXTERNALLY_AMBIGUOUS_STATES),
    }


def _workflow_report() -> dict[str, Any]:
    workflow_paths = (
        ROOT / ".github/workflows/qntyspot-full-suite.yml",
        ROOT / ".github/workflows/qntyspot-authority-continuity.yml",
    )
    forbidden_requirements = ("ZEROX_API_KEY", "QNTYSPOT_QUALIFICATION_TAKER")
    for path in workflow_paths:
        text = path.read_text(encoding="utf-8")
        if any(value in text for value in forbidden_requirements):
            raise SystemExit(f"authority continuity failed: secret requirement in {path}")
    return {
        "workflow_count": len(workflow_paths),
        "ordinary_ci_requires_zero_x_key": False,
    }


def build_report() -> dict[str, Any]:
    static = _static_authority_report()
    report = {
        "authority": {
            "authority": "ROBINHOOD_SHADOW_READ_ONLY",
            "live_capital_authorized": False,
            "network_authorized": True,
            "signing_authorized": False,
        },
        "closure": _closure_report(),
        "evidence": _evidence_report(),
        "program_b": _program_b_report(),
        "registry": _registry_report(),
        "static": static,
        "state_machine": _state_machine_report(),
        "workflows": _workflow_report(),
    }
    first = _canonical_bytes(report)
    second = _canonical_bytes(report)
    if first != second:
        raise SystemExit("authority continuity failed: non-deterministic canonical output")
    report["canonical_report_sha256"] = hashlib.sha256(first).hexdigest()
    return report


def main() -> int:
    import json

    print(json.dumps(build_report(), ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
