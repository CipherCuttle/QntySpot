"""Focused proof of the qualification venue-binding repair evidence."""

from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import tempfile
from pathlib import Path

from qntyspot.canon import canonical_json_bytes, strict_json_loads
from qntyspot.robinhood_chain_truth import (
    READ_ONLY_RPC_METHODS,
    ROBINHOOD_MAINNET_CHAIN_ID,
    ROBINHOOD_TESTNET_CHAIN_ID,
    ROBINHOOD_TESTNET_NETWORK_ID,
    ROBINHOOD_TESTNET_VENUE_ID,
)
from scripts.derive_deployment_identity import build_identity


ROOT = Path(__file__).resolve().parents[1]
BASE = "095572b0d94d7edf055246a3829de94467fc07d0"
REPAIR_COMMIT = "0e977b5801e932101d31b4ca131df71e93634efb"
REPAIRED_IMPLEMENTATION_DIGEST = "7fdd08cbb60de858d4eab7031a8463f29b62648be4b88104f6bd031c23a32826"
# Advanced by QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_AUTH_V0 from the
# pre-publication-auth successor digest 8a285e73…; the historical repaired
# digest above remains immutable and distinct from current runtime identity.
CURRENT_IMPLEMENTATION_DIGEST = "5859ec4f23ccb3f77f697d7f3b6f70ee0c9b6700be82e44b4aff51867c6a993f"
OLD_IMPLEMENTATION_DIGEST = "3195730dcc9368847cab61d9250279c0ed1f13c9b93691360a2d01b109c5b9d6"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
OLD_VENUE = "zero-x-swap-v2-robinhood-chain"
NEW_VENUE = "robinhood-chain-testnet-external-transaction"
V0R1_DIGEST = "f11b20d7b417571eb235010989c5479e2fd2c31a16d1e06df453ea870ebcba06"
V0R2_DIGEST = "469a438528facd8fdacae1078a94c4cdb611dcb0f3c05de8b159ba0088745c20"

V0R2 = ROOT / "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R2.json"
V0R2_SIDECAR = V0R2.with_suffix(".sha256")
REPAIR = ROOT / "artifacts/RECONCILE_ONLY_QUALIFICATION_VENUE_BINDING_REPAIR_V0.json"
REPAIR_SIDECAR = REPAIR.with_suffix(".sha256")

HISTORICAL_ARTIFACTS = (
    "artifacts/RECONCILE_ONLY_SOURCE_CEILING_DESIGN_V0.json",
    "artifacts/RECONCILE_ONLY_SOURCE_CEILING_DESIGN_V0.sha256",
    "artifacts/RECONCILE_ONLY_SOURCE_CEILING_IMPLEMENTATION_V0.json",
    "artifacts/RECONCILE_ONLY_SOURCE_CEILING_IMPLEMENTATION_V0.sha256",
    "artifacts/RECONCILE_ONLY_QUALIFICATION_FEASIBILITY_V0.json",
    "artifacts/RECONCILE_ONLY_QUALIFICATION_FEASIBILITY_V0.sha256",
    "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R1.json",
    "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R1.sha256",
)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.rstrip("\n")


def _historical_identity(commit: str) -> dict[str, object]:
    archive = subprocess.run(
        ["git", "archive", "--format=tar", commit],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="qntyspot-historical-") as temporary_root:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            tar.extractall(temporary_root)
        return build_identity(temporary_root, commit)


def test_repair_preserves_prior_commit_and_ends_on_canonical_base_lineage() -> None:
    assert _git("rev-parse", REPAIR_COMMIT) == REPAIR_COMMIT
    assert _git("merge-base", BASE, "HEAD") == BASE
    assert _git("merge-base", REPAIR_COMMIT, "HEAD") == REPAIR_COMMIT


def test_historical_artifacts_are_byte_identical_to_canonical_base() -> None:
    for relative_path in HISTORICAL_ARTIFACTS:
        current = (ROOT / relative_path).read_bytes()
        canonical = subprocess.run(
            ["git", "show", f"{BASE}:{relative_path}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        assert current == canonical, relative_path


def test_repaired_runtime_binding_keeps_chain_truth_boundaries() -> None:
    assert ROBINHOOD_TESTNET_VENUE_ID == NEW_VENUE
    assert ROBINHOOD_TESTNET_CHAIN_ID == 46630
    assert ROBINHOOD_TESTNET_NETWORK_ID == "evm:46630"
    assert ROBINHOOD_MAINNET_CHAIN_ID == 4663
    assert READ_ONLY_RPC_METHODS == frozenset(
        {
            "eth_chainId",
            "eth_blockNumber",
            "eth_getBlockByNumber",
            "eth_getBlockByHash",
            "eth_getTransactionByHash",
            "eth_getTransactionReceipt",
        }
    )


def test_v0r2_declaration_is_canonical_and_binds_successor_identity() -> None:
    raw = V0R2.read_bytes()
    declaration = strict_json_loads(raw)

    assert raw == canonical_json_bytes(declaration)
    assert hashlib.sha256(raw).hexdigest() == V0R2_DIGEST
    assert V0R2_SIDECAR.read_text(encoding="ascii") == f"{V0R2_DIGEST}  {V0R2.name}\n"
    assert declaration["schema"] == "qntyspot.robinhood_testnet_taker_declaration.v0r2"
    assert declaration["base_qntyspot_canonical"] == BASE
    assert declaration["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert declaration["implementation_digest"] == REPAIRED_IMPLEMENTATION_DIGEST
    assert declaration["network_id"] == "evm:46630"
    assert declaration["taker_address"] == TAKER
    assert declaration["venue_id"] == NEW_VENUE
    assert declaration["transaction_origin"] == "EXTERNAL_TO_QNTYSPOT"
    assert declaration["source_phase_ceiling"] == "RECONCILE_ONLY"
    assert declaration["supersedes_schema"] == "qntyspot.robinhood_testnet_taker_declaration.v0r1"
    assert declaration["supersedes_artifact_digest"] == V0R1_DIGEST
    assert declaration["signing_authorized"] is False
    assert declaration["transaction_construction_authorized"] is False
    assert declaration["approval_authorized"] is False
    assert declaration["submission_authorized"] is False
    assert declaration["capital_authorized"] is False
    assert declaration["account_control_proven"] is False
    assert declaration["private_key_control_proven"] is False


def test_repair_evidence_is_canonical_and_cross_binds_successor_artifacts() -> None:
    raw = REPAIR.read_bytes()
    evidence = strict_json_loads(raw)

    assert raw == canonical_json_bytes(evidence)
    assert hashlib.sha256(raw).hexdigest() == "04931e55b81276c7c7f101e44f106d6fd7c360057c0c64c53f29b9f5808481d0"
    assert REPAIR_SIDECAR.read_text(encoding="ascii") == (
        "04931e55b81276c7c7f101e44f106d6fd7c360057c0c64c53f29b9f5808481d0  "
        f"{REPAIR.name}\n"
    )
    assert evidence["phase"] == "QNTY_SPOT_RECONCILE_ONLY_QUALIFICATION_VENUE_BINDING_REPAIR_V0"
    assert evidence["base_canonical"] == BASE
    assert evidence["feasibility_artifact_digest"] == "a50cc308ba7bedfa16789050182ae5e0c0bf0dfd02fea4798474b67e1dab6738"
    assert evidence["authority_root_canonical"] == "618b05f1e780f7f20443f8c020bac0f676e66ff9"
    assert evidence["old_implementation_digest"] == OLD_IMPLEMENTATION_DIGEST
    assert evidence["new_repaired_implementation_digest"] == REPAIRED_IMPLEMENTATION_DIGEST
    assert evidence["old_testnet_venue_id"] == OLD_VENUE
    assert evidence["new_testnet_venue_id"] == NEW_VENUE
    assert evidence["network"] == "evm:46630"
    assert evidence["taker"] == TAKER
    assert evidence["transaction_origin"] == "EXTERNAL_TO_QNTYSPOT"
    assert evidence["v0r1_declaration_digest"] == V0R1_DIGEST
    assert evidence["v0r2_declaration_digest"] == V0R2_DIGEST
    assert evidence["mainnet_0x_shadow_path_changed"] == "NO"
    assert evidence["current_level_1_external_grant"] == "NONE"
    assert evidence["current_effective_level_1_authority"] == "DENIED"
    assert evidence["network_activity"] == 0
    assert evidence["testnet_transactions"] == 0


def test_historical_venue_binding_identity_is_distinct_from_current_successor() -> None:
    historical_identity = _historical_identity(REPAIR_COMMIT)
    current_identity = build_identity(ROOT, _git("rev-parse", "HEAD"))

    assert historical_identity["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert historical_identity["implementation_digest"] == REPAIRED_IMPLEMENTATION_DIGEST
    assert current_identity["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert current_identity["implementation_digest"] == CURRENT_IMPLEMENTATION_DIGEST
    assert current_identity["implementation_digest"] != REPAIRED_IMPLEMENTATION_DIGEST
    assert historical_identity["implementation_digest"] != OLD_IMPLEMENTATION_DIGEST
