"""Focused proof for the reconcile-only qualification feasibility artifact."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qntyspot.authority_root import AuthorityIssuancePolicyV0, assert_issuance_request_admissible
from qntyspot.errors import AuthorityVerificationError, SafeHaltError
from qntyspot.execution_contract import (
    AuthorityLevel,
    ChainObservationV0,
    ChainPresence,
    EconomicActionIDV0,
    FinalityPolicyV0,
    ReceiptStatus,
    SettlementExpectationV0,
    _validated_economic_action_from_database,
    evaluate_chain_truth,
    next_state_for_verdict,
    reconcile_to_receipt,
    release_permitted,
)
from qntyspot.canon import canonical_json_bytes
from qntyspot.states import IntentState


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/RECONCILE_ONLY_QUALIFICATION_FEASIBILITY_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
TX_HASH = "0x" + "ab" * 32
BLOCK_HASH = "0x" + "cd" * 32
PARENT_HASH = "0x" + "ce" * 32


def _artifact() -> dict[str, object]:
    document = json.loads(ARTIFACT.read_bytes())
    assert isinstance(document, dict)
    return document


def _reverted_observation(provider_id: str) -> ChainObservationV0:
    return ChainObservationV0(
        provider_id=provider_id,
        transaction_hash=TX_HASH,
        observed_at_epoch_s=1_800_000_000,
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=("11" if provider_id == "robinhood-public-rpc" else "22") * 32,
        block_number=7,
        block_hash=BLOCK_HASH,
        block_parent_hash=PARENT_HASH,
        head_block_number=39,
        head_block_hash="0x" + "ef" * 32,
        receipt_status=ReceiptStatus.REVERTED,
    )


def test_artifact_is_canonical_and_has_the_required_frozen_identity() -> None:
    document = _artifact()
    raw = ARTIFACT.read_bytes()
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == (
        f"{hashlib.sha256(raw).hexdigest()}  {ARTIFACT.name}\n"
    )
    inputs = document["canonical_inputs"]
    assert inputs["qntyspot_canonical"] == "1a6d95c852cdec2c3789dfa9a7dccdd4b04279a8"
    assert inputs["implementation_digest"] == "3195730dcc9368847cab61d9250279c0ed1f13c9b93691360a2d01b109c5b9d6"
    assert inputs["implementation_artifact_digest"] == "4b802519bdc214e3326140d32c4190b2585701c4ee65b609ebac902ab5e88df3"
    assert inputs["authority_root_canonical"] == "618b05f1e780f7f20443f8c020bac0f676e66ff9"
    assert inputs["source_phase_ceiling"] == "RECONCILE_ONLY"
    assert inputs["current_level_1_external_grant"] == "NONE"
    assert inputs["current_effective_level_1_authority"] == "DENIED"


def test_official_compatibility_finding_refuses_0x_testnet_and_mainnet_escape() -> None:
    document = _artifact()
    assert document["zero_x_testnet_support"] == "NO"
    assert document["qualification_feasibility"] == "REQUIRES_VENUE_BINDING_REPAIR"
    assert document["proposed_qualification_venue"] == "robinhood-chain-testnet-external-transaction"
    frozen = document["current_frozen_qualification"]
    assert frozen["network"] == "evm:46630"
    assert frozen["venue"] == "zero-x-swap-v2-robinhood-chain"
    assert frozen["transaction_origin"] == "EXTERNAL_TO_QNTYSPOT"
    refusal = document["mainnet_refusal"]
    assert refusal["robinhood_mainnet_level_1_authorized"] == "NO"
    assert refusal["production_capital_authorized"] == "NO"
    assert refusal["live_capital_authorized"] == "NO"
    assert refusal["forbidden_substitution"] == "evm:4663"
    sources = document["authoritative_external_compatibility_findings"]
    assert all("robinhood.com" in item["url"] for item in sources["robinhood"])
    assert all("0x.org" in item["url"] or "help.0x.org" in item["url"] for item in sources["zero_x"])
    assert "do not support testnets" in sources["zero_x"][0]["finding"]


def test_reverted_chain_truth_is_terminal_reconciliation_without_a_fill_receipt() -> None:
    expectation = SettlementExpectationV0(
        economic_action_id=EconomicActionIDV0("33" * 32),
        transaction_hash=TX_HASH,
        chain_id=46630,
        taker_address=TAKER,
        submission_acknowledged=False,
    )
    finality = FinalityPolicyV0(min_confirmation_depth=32, min_agreeing_providers=2)
    truth = evaluate_chain_truth(
        expectation,
        (_reverted_observation("robinhood-public-rpc"), _reverted_observation("alchemy-robinhood-testnet")),
        finality,
    )
    assert truth.verdict.value == "REVERTED"
    assert truth.agreeing_provider_count == 2
    assert truth.confirmation_depth == 32
    assert next_state_for_verdict(truth.verdict) is IntentState.REJECTED
    assert release_permitted(IntentState.RESERVED, truth.verdict) is True
    assert truth.effective_input_atomic is None
    assert truth.effective_output_atomic is None
    with pytest.raises(SafeHaltError, match="only CONFIRMED may produce a receipt"):
        reconcile_to_receipt(
            expectation,
            truth,
            object(),  # type: ignore[arg-type]
            validated_action=_validated_economic_action_from_database(
                expectation.economic_action_id,
                expectation.transaction_hash,
                expectation.chain_id,
                expectation.taker_address,
            ),
            receipt_id="44" * 32,
            fee_atomic=0,
            observed_at_epoch_s=1_800_000_000,
            source="qualification-feasibility-test",
        )


def test_artifact_requires_two_providers_and_does_not_lower_independence() -> None:
    document = _artifact()
    finality = document["provider_finality_feasibility"]["required_finality"]
    assert finality["min_confirmation_depth"] == 32
    assert finality["min_agreeing_providers"] == 2
    assert finality["provider_count_may_be_lowered"] == "NO"
    assert document["provider_finality_feasibility"]["actor_must_not_equal_verifier"] is True
    assert {item["provider_id"] for item in document["provider_finality_feasibility"]["provider_plan"]} == {
        "robinhood-public-rpc",
        "alchemy-robinhood-testnet",
    }


def test_fixture_addresses_are_explicitly_test_only_and_not_qualification_identity() -> None:
    raw = ARTIFACT.read_text(encoding="utf-8")
    for fixture in (
        "0x00000000000000000000000000000000000000b1",
        "0x00000000000000000000000000000000000000b2",
    ):
        assert fixture in raw
        assert raw.count(fixture) == 1
    assert _artifact()["identity_and_fixture_boundary"]["fixture_status"] == "TEST_ONLY"
    assert _artifact()["identity_and_fixture_boundary"]["qualification_token_identities"].startswith("UNFROZEN")


def test_current_shadow_capped_issuer_cannot_issue_level_one() -> None:
    document = _artifact()
    frozen = document["current_frozen_qualification"]
    issuer = AuthorityIssuancePolicyV0(
        root_id="qnty-authority-root-v0",
        repository_identity="CipherCuttle/QntySpot",
        maximum_issuable_level=AuthorityLevel.SHADOW,
        allowed_network_ids=("evm:46630",),
        allowed_taker_addresses=(TAKER,),
        allowed_venue_ids=(frozen["venue"],),
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        max_grant_duration_s=300,
    )
    request = document["canonical_inputs"]
    from qntyspot.execution_contract import AuthorityPolicyRefV0

    policy_ref = AuthorityPolicyRefV0(
        authority_root_id="qnty-authority-root-v0",
        granted_level=AuthorityLevel.RECONCILE_ONLY,
        permitted_repository_commit=request["qntyspot_canonical"],
        permitted_implementation_digest=request["implementation_digest"],
        permitted_network_id=frozen["network"],
        permitted_taker_address=frozen["taker"],
        permitted_venue_id=frozen["venue"],
        max_reservation_atomic=1,
        max_cumulative_atomic=1,
        not_before_epoch_s=1,
        not_after_epoch_s=301,
    )
    with pytest.raises(AuthorityVerificationError, match="issuance level exceeds issuer policy"):
        assert_issuance_request_admissible(
            issuer,
            policy_ref,
            repository_identity="CipherCuttle/QntySpot",
        )


def test_no_effects_and_no_authority_escalation_are_claimed() -> None:
    document = _artifact()
    counters = document["zero_effect_counters"]
    assert counters["NETWORK_ACTIVITY"] == 0
    assert counters["TESTNET_TRANSACTIONS"] == 0
    assert counters["PRIVATE_KEY_ACCESSED"] == "NO"
    assert counters["BLOCKCHAIN_SIGNATURES"] == 0
    assert counters["CAPITAL_DEPLOYED"] == 0
    assert document["authority_root_consequence"]["do_not_issue_authority_root_grant"] is True
    assert document["authority_root_consequence"]["mainnet_escape"] == "FORBIDDEN"
    assert document["hostile_review"]["review_count"] == 1
    assert document["hostile_review"]["critical"] == 0
    assert document["hostile_review"]["high"] == 0
