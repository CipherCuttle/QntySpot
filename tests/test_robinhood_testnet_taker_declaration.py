"""Focused validation for the nonsecret Robinhood testnet taker declaration."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from qntyspot.canon import canonical_json_bytes, strict_json_loads
from qntyspot.errors import AuthorityCeilingError, RobinhoodProtocolError, SessionIdentityError
from qntyspot.execution_contract import AuthorityLevel, AuthorityPolicyRefV0
from qntyspot.robinhood import RobinhoodShadowAdapter, validate_qualification_taker
from scripts.derive_deployment_identity import build_identity

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_ARTIFACT = ROOT / "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0.json"
HISTORICAL_SIDECAR = HISTORICAL_ARTIFACT.with_suffix(".sha256")
ARTIFACT = ROOT / "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R1.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")

CANONICAL_PARENT_COMMIT = "46ab538de59c67a8af8f230bb7e494378392b614"
HISTORICAL_PARENT_COMMIT = "152fe888e24e7cc3e0260242530b326c511c3d3f"
HISTORICAL_IMPLEMENTATION_DIGEST = "2da5b936e8cb657d5204a161c27cc94862a18099db838a1c97e77deccb6b9f9d"
REPAIRED_IMPLEMENTATION_DIGEST = "d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de"
TAKER_ADDRESS = "0x1324d87e24e1657f6fe6805de814bb6873052106"
HISTORICAL_SYNTHETIC_TAKER = "0x0000000000000000000000000000000000000001"
OLD_VENUE_ID = "0x-swap-v2-robinhood-chain"
NEW_VENUE_ID = "zero-x-swap-v2-robinhood-chain"

EXPECTED_DECLARATION = {
    "schema": "qntyspot.robinhood_testnet_taker_declaration.v0r1",
    "purpose": "first-production-authority-receipt-shadow-path-proof",
    "qntyspot_parent_commit": CANONICAL_PARENT_COMMIT,
    "implementation_identity_method": "sha256-canonical-source-manifest-v2",
    "implementation_digest": REPAIRED_IMPLEMENTATION_DIGEST,
    "network_id": "evm:46630",
    "role": "qntyspot-robinhood-testnet-taker",
    "taker_address": TAKER_ADDRESS,
    "venue_id": NEW_VENUE_ID,
    "venue_adapter_version": "NOT_CANONICALLY_ASSIGNED",
    "source_phase_ceiling": "SHADOW",
    "signing_authorized": False,
    "capital_authorized": False,
    "account_control_proven": False,
    "private_key_control_proven": False,
    "supersedes_schema": "qntyspot.robinhood_testnet_taker_declaration.v0",
    "supersedes_artifact_digest": "e2f787c03cb79cb072ac705e111a49152cc16bdcae3061b410aaf35ca5f7992f",
    "repair_reason": "canonical venue identity was not representable by the frozen portable AuthorityPolicyRefV0 identity grammar",
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


def test_historical_v0_declaration_is_unchanged() -> None:
    raw = HISTORICAL_ARTIFACT.read_bytes()
    declaration = strict_json_loads(raw)

    assert declaration["schema"] == "qntyspot.robinhood_testnet_taker_declaration.v0"
    assert declaration["venue_id"] == OLD_VENUE_ID
    assert declaration["implementation_digest"] == HISTORICAL_IMPLEMENTATION_DIGEST
    assert declaration["qntyspot_parent_commit"] == HISTORICAL_PARENT_COMMIT
    assert raw == canonical_json_bytes(declaration)
    assert HISTORICAL_SIDECAR.read_text(encoding="ascii") == (
        f"e2f787c03cb79cb072ac705e111a49152cc16bdcae3061b410aaf35ca5f7992f  "
        f"{HISTORICAL_ARTIFACT.name}\n"
    )


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
    identity = build_identity(ROOT, CANONICAL_PARENT_COMMIT)
    assert identity["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert identity["implementation_digest"] == REPAIRED_IMPLEMENTATION_DIGEST
    assert identity["implementation_digest"] != HISTORICAL_IMPLEMENTATION_DIGEST
    assert identity["provenance"]["repository_commit"] == CANONICAL_PARENT_COMMIT


def _authority_policy(venue_id: str) -> AuthorityPolicyRefV0:
    return AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.SHADOW,
        permitted_repository_commit=CANONICAL_PARENT_COMMIT,
        permitted_implementation_digest=REPAIRED_IMPLEMENTATION_DIGEST,
        permitted_network_id="evm:46630",
        permitted_taker_address=TAKER_ADDRESS,
        permitted_venue_id=venue_id,
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        not_before_epoch_s=1_000,
        not_after_epoch_s=1_300,
    )


def test_runtime_and_qntyspot_authority_identity_are_exactly_the_new_venue() -> None:
    authority = _authority_policy(NEW_VENUE_ID)

    assert RobinhoodShadowAdapter.venue_id == NEW_VENUE_ID
    assert authority.permitted_venue_id == RobinhoodShadowAdapter.venue_id


def test_old_venue_is_rejected_by_qntyspot_portable_authority_identity_grammar() -> None:
    with pytest.raises((AuthorityCeilingError, SessionIdentityError)):
        _authority_policy(OLD_VENUE_ID)
