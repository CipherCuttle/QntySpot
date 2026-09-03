"""Focused validation for the nonsecret Robinhood testnet taker declaration."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from qntyspot.canon import canonical_json_bytes, strict_json_loads
from qntyspot.errors import RobinhoodProtocolError
from qntyspot.robinhood import validate_qualification_taker
from scripts.derive_deployment_identity import build_identity

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")

PARENT_COMMIT = "152fe888e24e7cc3e0260242530b326c511c3d3f"
IMPLEMENTATION_DIGEST = "2da5b936e8cb657d5204a161c27cc94862a18099db838a1c97e77deccb6b9f9d"
TAKER_ADDRESS = "0x1324d87e24e1657f6fe6805de814bb6873052106"
HISTORICAL_SYNTHETIC_TAKER = "0x0000000000000000000000000000000000000001"

EXPECTED_DECLARATION = {
    "schema": "qntyspot.robinhood_testnet_taker_declaration.v0",
    "purpose": "first-production-authority-receipt-shadow-path-proof",
    "qntyspot_parent_commit": PARENT_COMMIT,
    "implementation_identity_method": "sha256-canonical-source-manifest-v2",
    "implementation_digest": IMPLEMENTATION_DIGEST,
    "network_id": "evm:46630",
    "role": "qntyspot-robinhood-testnet-taker",
    "taker_address": TAKER_ADDRESS,
    "venue_id": "0x-swap-v2-robinhood-chain",
    "venue_adapter_version": "NOT_CANONICALLY_ASSIGNED",
    "source_phase_ceiling": "SHADOW",
    "signing_authorized": False,
    "capital_authorized": False,
    "account_control_proven": False,
    "private_key_control_proven": False,
}


def test_declaration_is_exact_canonical_nonsecret_identity_binding() -> None:
    raw = ARTIFACT.read_bytes()
    declaration = strict_json_loads(raw)

    assert declaration == EXPECTED_DECLARATION
    assert raw == canonical_json_bytes(declaration)
    assert set(declaration) == set(EXPECTED_DECLARATION)
    assert b"-----BEGIN" not in raw
    assert b"mnemonic" not in raw.lower()
    assert b"seed phrase" not in raw.lower()


def test_declared_taker_is_lowercase_canonical_nonzero_and_not_sentinel() -> None:
    assert re.fullmatch(r"0x[0-9a-f]{40}", TAKER_ADDRESS)
    assert int(TAKER_ADDRESS[2:], 16) != 0
    assert TAKER_ADDRESS != HISTORICAL_SYNTHETIC_TAKER
    assert validate_qualification_taker(TAKER_ADDRESS) == TAKER_ADDRESS

    with pytest.raises(RobinhoodProtocolError):
        validate_qualification_taker(HISTORICAL_SYNTHETIC_TAKER)


def test_declaration_sidecar_covers_exact_artifact_bytes() -> None:
    artifact_digest = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    assert SIDECAR.read_text(encoding="ascii") == f"{artifact_digest}  {ARTIFACT.name}\n"


def test_declaration_keeps_implementation_digest_unchanged() -> None:
    identity = build_identity(ROOT, PARENT_COMMIT)
    assert identity["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert identity["implementation_digest"] == IMPLEMENTATION_DIGEST
    assert identity["provenance"]["repository_commit"] == PARENT_COMMIT
