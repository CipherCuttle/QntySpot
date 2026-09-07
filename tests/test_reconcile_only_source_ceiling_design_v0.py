"""Design-only contract tests for the future QntySpot Level-1 ceiling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from qntyspot.execution_contract import (
    Capability,
    KILL_SWITCH_PRESERVED_CAPABILITIES,
    LADDER,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    AuthorityLevel,
)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/RECONCILE_ONLY_SOURCE_CEILING_DESIGN_V0.json"
SIDECAR = ROOT / "artifacts/RECONCILE_ONLY_SOURCE_CEILING_DESIGN_V0.sha256"


def design() -> dict[str, object]:
    return json.loads(ARTIFACT.read_bytes())


def test_current_source_ceiling_and_design_target_are_distinct() -> None:
    document = design()

    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert document["input_qntyspot"]["current_source_phase_ceiling"] == "SHADOW"
    assert document["source_ceiling_design"]["target"] == "RECONCILE_ONLY"
    assert document["source_ceiling_design"]["runtime_change_in_this_phase"] == "NO"
    assert document["input_qntyspot"]["current_runtime_authority_changed"] == "NO"
    assert document["level_1_contract"]["permitted_capabilities"]
    assert document["design_id"] == "QNTY_SPOT_RECONCILE_ONLY_SOURCE_CEILING_DESIGN_V0"
    assert document["network_and_qualification"]["target"] == "ROBINHOOD_TESTNET_RECONCILE_ONLY"


def test_implementation_source_now_matches_the_frozen_design_target() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert Capability.SUBMIT_EXACT_BYTES in LADDER[AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES]


def test_level_1_capabilities_match_frozen_program_b() -> None:
    document = design()
    expected = {
        "OBSERVE_MARKET",
        "DECIDE_OFFLINE",
        "OBSERVE_CHAIN",
        "RECONCILE",
        "ACCOUNT_QUARANTINE",
        "RESERVE_CAPITAL",
    }

    assert set(document["level_1_contract"]["permitted_capabilities"]) == expected
    assert set(document["level_1_contract"]["forbidden_capabilities"]) == {
        "SUBMIT_EXACT_BYTES",
        "CONSTRUCT_ENVELOPE",
        "AUTHORIZE_APPROVAL",
        "PRODUCE_SIGNATURE",
    }


def test_level_1_forbids_signing_submission_approval_and_construction() -> None:
    forbidden = set(design()["level_1_contract"]["forbidden_capabilities"])

    assert forbidden == {
        Capability.SUBMIT_EXACT_BYTES.value,
        Capability.CONSTRUCT_ENVELOPE.value,
        Capability.AUTHORIZE_APPROVAL.value,
        Capability.PRODUCE_SIGNATURE.value,
    }
    assert design()["level_1_contract"]["signing_authorized"] == "NO"
    assert design()["level_1_contract"]["live_capital_authorized"] == "NO"
    assert design()["level_1_contract"]["capital_authority"] == "NONE"


def test_reserve_capital_is_internal_durable_accounting_only() -> None:
    reserve = design()["level_1_contract"]["reserve_capital"]

    assert reserve["included_at_level_1"] == "YES"
    assert reserve["external_effect"] == "NO"
    assert reserve["durable_accounting_only"] == "YES"
    assert reserve["testnet_accounting_reservation_is_not_live_capital_authority"] == "YES"
    assert design()["level_1_contract"]["live_capital_authorized"] == "NO"


def test_dual_control_is_mandatory_and_source_ceiling_alone_is_insufficient() -> None:
    document = design()
    dual = document["future_level_1_authorization_entrypoints"]

    assert dual["must_use_external_root_consumer_path"] == "YES"
    assert dual["must_not_activate_level_1_via_only"] == [
        "require_capability(...)",
        "granted_capabilities(...)",
    ]
    assert document["future_implementation_acceptance_gates"]
    assert "effective authority is MIN(SOURCE_PHASE_CEILING, VERIFIED_EXTERNAL_GRANT_LEVEL)" in document[
        "future_implementation_acceptance_gates"
    ]
    assert document["input_qntyspot"]["current_runtime_authority_changed"] == "NO"


def test_no_missing_expired_or_shadow_only_external_grant_can_activate_level_1() -> None:
    gates = " ".join(design()["future_implementation_acceptance_gates"])
    entrypoints = design()["future_level_1_authorization_entrypoints"]

    assert "missing, expired, SHADOW-only, wrong-commit, wrong-digest, wrong-network, wrong-taker, and wrong-venue grants deny Level 1" in gates
    assert entrypoints["record_verified_authority"].startswith("evidence persistence only")


def test_expired_shadow_receipt_is_historical_evidence_only_and_not_reusable() -> None:
    receipt = design()["authority_root_prerequisite"]["historical_shadow_receipt"]

    assert receipt["request_id"] == "qnty-first-production-shadow-grant-v0r1"
    assert receipt["serial"] == 1
    assert receipt["receipt_id"] == "e33c11d648113f03a00c7afacbfa34e6b95cc891be2a2166d6216d0b1a0c5871"
    assert receipt["receipt_sha256"] == "83a075f507f1944e129ffea73f145fa430f24293ce40268bca9f2c69819d4e09"
    assert receipt["verified_level"] == "SHADOW"
    assert receipt["status"] == "EXPIRED"
    assert receipt["evidence_only"] == "YES"
    assert receipt["reusable"] == "NO"
    assert receipt["refreshable"] == "NO"
    assert receipt["upgradeable"] == "NO"


def test_future_grant_pins_future_implementation_identity_and_is_not_issued_here() -> None:
    grant = design()["future_grant_requirement"]

    assert grant["required"] == "YES"
    assert grant["new_independently_issued_grant_after_canonical_implementation"] == "YES"
    assert grant["final_commit_must_not_be_precomputed"] == "YES"
    assert grant["final_digest_must_not_be_precomputed"] == "YES"
    assert grant["not_issued_in_this_phase"] == "YES"
    assert grant["duration"] == "EXPLICIT_DURATION_REQUIRED"
    assert grant["accounting_ceilings"] == "EXPLICIT_ACCOUNTING_CEILINGS_REQUIRED"
    assert set(grant["required_pins"]) == {
        "permitted_repository_commit",
        "permitted_implementation_digest",
        "granted_level=RECONCILE_ONLY",
        "permitted_network_id",
        "permitted_taker_address",
        "permitted_venue_id",
        "not_before_epoch_s",
        "not_after_epoch_s",
        "max_reservation_atomic",
        "max_cumulative_atomic",
    }


def test_exact_network_taker_venue_and_mainnet_exclusion() -> None:
    target = design()["network_and_qualification"]

    assert target["network"] == "evm:46630"
    assert target["forbidden_network"] == "evm:4663"
    assert target["robinhood_mainnet_level_1_authorized"] == "NO"
    assert target["taker"] == "0x1324d87e24e1657f6fe6805de814bb6873052106"
    assert target["venue"] == "zero-x-swap-v2-robinhood-chain"


def test_qualification_transaction_must_be_external_to_qntyspot() -> None:
    target = design()["network_and_qualification"]

    assert target["transaction_origin"] == "EXTERNAL_TO_QNTYSPOT"
    assert target["externally_created_testnet_transaction"] == "OBSERVE_AND_RECONCILE_ONLY"
    assert target["qntyspot_created_transaction"] == "FORBIDDEN"
    assert target["zero_production_capital"] == "YES"
    assert target["zero_qntyspot_signing"] == "YES"
    assert target["zero_qntyspot_submission"] == "YES"


def test_qntyspot_transaction_construction_signing_and_submission_remain_forbidden() -> None:
    forbidden = set(design()["network_and_qualification"]["qntyspot_must_not"])

    assert forbidden == {
        "build the transaction",
        "modify the transaction",
        "sign the transaction",
        "submit the transaction",
        "retry the transaction",
        "create an approval for the transaction",
    }


def test_kill_switch_preserves_exact_observation_reconciliation_quarantine_set() -> None:
    preserved = set(design()["kill_switch_semantics"]["preserved_capabilities"])
    removed = set(design()["kill_switch_semantics"]["removed_capabilities"])

    assert preserved == {cap.value for cap in KILL_SWITCH_PRESERVED_CAPABILITIES}
    assert removed == {
        "RESERVE_CAPITAL",
        "SUBMIT_EXACT_BYTES",
        "CONSTRUCT_ENVELOPE",
        "AUTHORIZE_APPROVAL",
        "PRODUCE_SIGNATURE",
    }
    assert design()["kill_switch_semantics"]["halted_runtime_may_determine_what_happened"] == "YES"
    assert design()["kill_switch_semantics"]["halted_runtime_may_initiate_anything_new"] == "NO"


def test_implementation_scope_is_present_and_unambiguous() -> None:
    scope = design()["implementation_scope"]

    assert scope["determination"] == "B"
    assert scope["existing_b1_observation_reconciliation_sufficient_alone"] == "NO"
    assert scope["answer"].startswith("source-ceiling/authorization wiring plus")
    assert scope["minimum_future_read_only_surface"]
    assert set(scope["required_absences"]) >= {
        "signer",
        "submission method",
        "approval method",
        "transaction encoder",
        "private-key access",
        "ambient secret discovery",
        "venue discovery",
        "automatic account discovery",
        "automatic asset discovery",
    }


def test_input_identity_and_closed_authorityroot_prerequisite_are_bound() -> None:
    document = design()

    assert document["input_qntyspot"]["canonical_commit"] == "6a23171e790e8ae95c9b7bf6c2b55fe6d06a66bf"
    assert document["input_qntyspot"]["implementation_digest"] == "d06b6eb98c5a33ae9ef7a12af7ef2626d9a176894ef13dad97fafe99481812de"
    root = document["authority_root_prerequisite"]
    assert root["canonical_commit"] == "618b05f1e780f7f20443f8c020bac0f676e66ff9"
    assert root["closure_artifact_digest"] == "150f9a839f48ceb38b5fc8328b7252b2364cfdc3b9c339bc95d8cea057eade07"
    assert root["production_authority_root_to_qntyspot_receipt_path_proven"] == "YES"
    assert root["first_grant_program_complete"] == "YES"


def test_artifact_is_canonical_and_sidecar_covers_exact_bytes() -> None:
    raw = ARTIFACT.read_bytes()
    parsed = json.loads(raw)
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")

    assert raw == canonical
    digest = hashlib.sha256(raw).hexdigest()
    assert SIDECAR.read_text(encoding="ascii") == f"{digest}  {ARTIFACT.name}\n"


def test_next_phase_and_design_only_counters_are_exact() -> None:
    document = design()

    assert document["status"] == "DESIGN_ONLY_PENDING_CANONICALIZATION"
    assert document["design_only"] == "YES"
    assert document["verification_counters"] == {
        "network_activity": 0,
        "private_key_accessed": "NO",
        "blockchain_signatures": 0,
        "capital_deployed": 0,
        "authority_root_grants_issued": 0,
        "testnet_activity": 0,
        "source_files_changed": 0,
        "authority_root_files_changed": 0,
    }
    assert document["next_phase"] == "QNTY_SPOT_RECONCILE_ONLY_SOURCE_CEILING_IMPLEMENTATION_V0"
