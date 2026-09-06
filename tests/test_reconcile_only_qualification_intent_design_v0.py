"""Focused proof for the reconcile-only qualification intent design."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from qntyspot.canon import canonical_json_bytes
from qntyspot.execution_contract import (
    ChainObservationV0,
    ChainPresence,
    ChainTruthVerdict,
    EconomicActionIDV0,
    FinalityPolicyV0,
    ReceiptStatus,
    SettlementExpectationV0,
    evaluate_chain_truth,
    next_state_for_verdict,
    release_permitted,
)
from qntyspot.robinhood_chain_truth import (
    READ_ONLY_RPC_METHODS,
    ROBINHOOD_MAINNET_CHAIN_ID,
    ROBINHOOD_TESTNET_CHAIN_ID,
    ROBINHOOD_TESTNET_NETWORK_ID,
    ROBINHOOD_TESTNET_VENUE_ID,
)
from qntyspot.states import IntentState
from scripts.derive_deployment_identity import build_identity


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0.json"
SIDECAR = ARTIFACT.with_suffix(".sha256")
BASE = "9b12c7d30873feeafdae0e7541516e3abe3ec41d"
VENUE_REPAIR_HEAD = "53ec6061ae959a46b8f1da0240b0645ba785ac66"
IMPLEMENTATION_DIGEST = "7fdd08cbb60de858d4eab7031a8463f29b62648be4b88104f6bd031c23a32826"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
NETWORK = "evm:46630"
VENUE = "robinhood-chain-testnet-external-transaction"
BASE_INSTRUMENT = "evm:46630:0x33e4191705c386532ba27cbf171db86919200b94"
QUOTE_INSTRUMENT = "evm:46630:0xbf4479c07dc6fdc6daa764a0cca06969e894275f"
TX_HASH = "0x" + "ab" * 32
BLOCK_HASH = "0x" + "cd" * 32
PARENT_HASH = "0x" + "ce" * 32


def artifact() -> dict[str, object]:
    value = json.loads(ARTIFACT.read_bytes())
    assert isinstance(value, dict)
    return value


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.rstrip("\n")


def reverted_observation(provider_id: str) -> ChainObservationV0:
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


def test_artifact_is_canonical_and_sidecar_matches() -> None:
    document = artifact()
    raw = ARTIFACT.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert raw == canonical_json_bytes(document)
    assert SIDECAR.read_text(encoding="ascii") == f"{digest}  {ARTIFACT.name}\n"


def test_exact_canonical_inputs_and_repaired_source_digest() -> None:
    document = artifact()
    inputs = document["canonical_inputs"]
    assert inputs["qntyspot_main_canonical"] == BASE
    assert inputs["venue_binding_repair_pr_head"] == VENUE_REPAIR_HEAD
    assert inputs["repaired_implementation_digest"] == IMPLEMENTATION_DIGEST
    assert build_identity(ROOT, VENUE_REPAIR_HEAD)["implementation_digest"] == IMPLEMENTATION_DIGEST
    assert inputs["feasibility_artifact_digest"] == "a50cc308ba7bedfa16789050182ae5e0c0bf0dfd02fea4798474b67e1dab6738"
    assert inputs["venue_binding_repair_artifact_digest"] == "04931e55b81276c7c7f101e44f106d6fd7c360057c0c64c53f29b9f5808481d0"
    assert inputs["v0r2_declaration_digest"] == "469a438528facd8fdacae1078a94c4cdb611dcb0f3c05de8b159ba0088745c20"
    assert inputs["authority_root_canonical"] == "618b05f1e780f7f20443f8c020bac0f676e66ff9"
    assert inputs["current_issuer_policy_digest"] == "680b0bc9076413e7d09f53d9259503ac33482a978c7546f8da2b0c4a21a2b7ed"
    assert inputs["current_issuer_max_level"] == "SHADOW"


def test_design_changes_only_the_three_permitted_files_and_not_runtime_source() -> None:
    document = artifact()
    assert document["change_boundary"]["runtime_source_changed"] is False
    assert git("diff", "--name-only", "--", "qntyspot") == ""
    assert git("diff", "--name-only", "--", "docs") == ""
    assert git("diff", "--name-only", "--", "qntyspot/authority_root.py") == ""
    assert document["change_boundary"]["allowed_changed_paths"] == [
        "artifacts/RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0.json",
        "artifacts/RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0.sha256",
        "tests/test_reconcile_only_qualification_intent_design_v0.py",
    ]


def test_repaired_venue_is_testnet_only_and_mainnet_0x_is_not_rebound() -> None:
    document = artifact()
    outcome = document["qualification_outcome"]
    assert ROBINHOOD_TESTNET_CHAIN_ID == 46630
    assert ROBINHOOD_TESTNET_NETWORK_ID == NETWORK
    assert ROBINHOOD_TESTNET_VENUE_ID == VENUE
    assert ROBINHOOD_MAINNET_CHAIN_ID == 4663
    assert outcome["qualification_network"] == NETWORK
    assert outcome["qualification_venue"] == VENUE
    assert outcome["transaction_origin"] == "EXTERNAL_TO_QNTYSPOT"
    assert outcome["outcome"] == "REVERTED"
    assert document["accounting_instruments"]["mainnet_address_reuse"] == "NO"
    assert git("diff", "--name-only", "--", "qntyspot/robinhood.py") == ""
    assert document["forbidden_success_path_requirements"]


def test_exact_one_positive_accounting_reservation_and_independent_justification() -> None:
    document = artifact()
    intent = document["qualification_intent"]
    determination = intent["one_atomic_unit_determination"]
    assert intent["quote_exposure_atomic"] == 1
    assert intent["reservation_must_be_positive"] is True
    assert intent["zero_reservation_is_forbidden"] is True
    assert intent["accounting_reservation_external_effect"] == "NO"
    assert intent["accounting_reservation_is_durable_local_accounting_only"] == "YES"
    assert intent["economic_action_count"] == 1
    assert intent["max_concurrent_reservations"] == 1
    assert determination["local_policy_per_order_cap_atomic"] >= 1
    assert determination["local_policy_global_cap_atomic"] >= 1
    assert determination["same_numeric_value_as_historical_shadow_floor"] == "COINCIDENTAL"
    assert determination["new_independent_justification"] == "YES"
    assert document["future_authority_root_input_contract"]["max_reservation_atomic"] == 1
    assert document["future_authority_root_input_contract"]["max_cumulative_atomic"] == 1


def test_accounting_instruments_use_exact_testnet_addresses_and_not_symbols_or_fixtures() -> None:
    document = artifact()
    instruments = document["accounting_instruments"]
    assert instruments["base_instrument_id"] == BASE_INSTRUMENT
    assert instruments["quote_instrument_id"] == QUOTE_INSTRUMENT
    assert instruments["base_decimals"] == 18
    assert instruments["quote_decimals"] == 18
    assert instruments["base_instrument_id"] != "evm:46630:WETH"
    assert instruments["quote_instrument_id"] != "evm:46630:USDC"
    assert instruments["testnet_contracts_are_not_synthetic_fixture_addresses"] is True
    assert instruments["testnet_contracts_are_not_robinhood_mainnet_addresses"] is True
    assert document["identity_and_fixture_boundary"]["symbols_are_labels_only"] is True
    for address in document["identity_and_fixture_boundary"]["synthetic_fixture_addresses_forbidden"]:
        assert address not in {instruments["base_contract_address"], instruments["quote_contract_address"]}


def test_revert_does_not_semantically_require_observation_token_selectors() -> None:
    document = artifact()
    semantics = document["token_selector_semantics"]
    repair = document["conditional_source_repair"]
    assert semantics["selectors_semantically_required_for_revert"] == "NO"
    assert semantics["selectors_semantically_required_for_success"] == "YES"
    assert semantics["economic_instrument_and_observation_selector_are_distinct"] is True
    assert semantics["unrelated_selector_substitution"] == "FORBIDDEN"
    assert repair["required"] is True
    assert repair["repair_reason"] == "REVERT_OBSERVATION_TOKEN_SELECTOR_COUPLING"
    assert repair["target_file"] == "qntyspot/robinhood_chain_truth.py"
    assert repair["next_action"] == "QNTY_SPOT_RECONCILE_ONLY_REVERT_OBSERVATION_MINIMALITY_REPAIR_V0"
    assert repair["must_not_change"] == [
        "RPC method allowlist",
        "chain-id validation",
        "taker validation",
        "transaction-hash validation",
        "receipt validation",
        "block validation",
        "finality",
        "provider independence",
        "reconciliation",
        "ledger model",
    ]


def test_external_revert_contract_has_no_target_overbinding_or_qntyspot_transaction_authority() -> None:
    document = artifact()
    contract = document["external_transaction_contract"]
    target = document["target_binding"]
    assert contract["required_network"] == NETWORK
    assert contract["from_taker_must_equal"] == TAKER
    assert contract["receipt_status_required"] == 0
    assert contract["transaction_reference_count"] == 1
    assert contract["actor_is_not_verifier"] is True
    assert target["qualification_tx_target_authority_binding"] == "NOT_REQUIRED"
    assert target["to_address"] == "NOT_FROZEN"
    assert target["calldata"] == "NOT_FROZEN"
    assert target["gas_limit"] == "NOT_FROZEN"
    assert target["native_value"] == "NOT_FROZEN"
    assert target["specific_revert_contract"] == "NOT_FROZEN"
    forbidden = set(contract["qntyspot_must_not"])
    assert {"construct", "sign", "submit", "approve", "broadcast", "retry"} <= forbidden
    assert document["gas_semantics"]["external_actor_testnet_gas_effect"] == "YES"
    assert document["gas_semantics"]["qntyspot_capital_effect"] == "NO"
    assert document["gas_semantics"]["qntyspot_gas_authority"] == "NO"


def test_two_independent_providers_and_32_block_finality_are_unchanged() -> None:
    document = artifact()
    plan = document["provider_plan"]
    assert plan["min_agreeing_providers"] == 2
    assert plan["min_confirmation_depth"] == 32
    assert plan["provider_count_may_be_lowered"] == "NO"
    assert plan["actor_ne_verifier"] == "YES"
    assert {item["provider_id"] for item in plan["providers"]} == {
        "robinhood-public-rpc",
        "alchemy-robinhood-testnet",
    }
    assert {item["operator"] for item in plan["providers"]} == {"Robinhood", "Alchemy"}
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


def test_existing_chain_truth_rejects_revert_without_a_fill_receipt() -> None:
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
        (
            reverted_observation("robinhood-public-rpc"),
            reverted_observation("alchemy-robinhood-testnet"),
        ),
        finality,
    )
    assert truth.verdict is ChainTruthVerdict.REVERTED
    assert truth.agreeing_provider_count == 2
    assert truth.confirmation_depth == 32
    assert truth.effective_input_atomic is None
    assert truth.effective_output_atomic is None
    assert next_state_for_verdict(truth.verdict) is IntentState.REJECTED
    assert release_permitted(IntentState.RESERVED, truth.verdict) is True
    assert document_state_sequence(artifact())[8]["intent_state"] == "REJECTED"


def document_state_sequence(document: dict[str, object]) -> list[dict[str, object]]:
    sequence = document["state_sequence"]
    assert isinstance(sequence, list)
    return sequence


def test_state_sequence_and_replay_are_the_existing_model_not_a_parallel_machine() -> None:
    sequence = document_state_sequence(artifact())
    assert [step["intent_state"] for step in sequence[:4]] == [
        "SIMULATED",
        "SIMULATED",
        "RESERVED",
        "RESERVED",
    ]
    assert sequence[7]["chain_truth_verdict"] == "REVERTED"
    assert sequence[7]["intent_state"] == "RESERVED"
    assert sequence[8]["intent_state"] == "REJECTED"
    assert sequence[8]["reservation_status"] == "RELEASED"
    assert sequence[9]["fill_receipt_count"] == 0
    assert sequence[10]["replay_terminal_intent_state"] == "REJECTED"
    assert sequence[10]["replay_reservation_status"] == "RELEASED"
    assert sequence[10]["replay_fill_receipt_count"] == 0


def test_no_retry_one_action_and_no_grant_or_effects() -> None:
    document = artifact()
    single = document["single_action_contract"]
    counters = document["zero_effect_counters"]
    assert single["qualification_economic_action_count"] == 1
    assert single["qualification_external_transaction_count"] == 1
    assert single["max_concurrent_reservations"] == 1
    assert single["automatic_retry"] == "NO"
    assert single["second_economic_settlement"] == "FORBIDDEN"
    assert single["second_qualification_transaction"] == "FORBIDDEN"
    assert counters["network_activity"] == 0
    assert counters["testnet_transactions"] == 0
    assert counters["private_key_accessed"] == "NO"
    assert counters["blockchain_signatures"] == 0
    assert counters["capital_deployed"] == 0
    assert counters["authority_root_grants_issued"] == 0
    assert document["authority_freeze"]["current_level_1_external_grant"] == "NONE"
    assert document["authority_freeze"]["current_effective_level_1_authority"] == "DENIED"


def test_duration_is_bounded_and_derived_under_the_hard_maximum() -> None:
    document = artifact()
    duration = document["grant_duration"]
    derivation = duration["derivation"]
    assert duration["requirement"] == "BOUNDED_AT_ISSUANCE"
    assert duration["requirement_s"] == 900
    assert duration["hard_max_s"] == 3600
    assert sum(value for key, value in derivation.items() if key.endswith("_s") and key != "sum_s") == derivation["sum_s"] == 900
    assert duration["expiry_behavior"].startswith("If the bounded episode")


def test_determination_b_defers_future_commit_and_digest_until_repair() -> None:
    document = artifact()
    assert document["exact_next_phase"] == "B_MINIMAL_REVERT_OBSERVATION_REPAIR_REQUIRED"
    assert document["final_phase_verdict"] == "QNTY_SPOT_RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0_CANONICAL_CLOSED_PASS"
    future = document["future_authority_root_input_contract"]
    assert future["granted_level"] == "RECONCILE_ONLY"
    assert future["permitted_repository_commit"] == "DEFERRED_UNTIL_REPAIR_CANONICALIZATION"
    assert future["permitted_implementation_digest"] == "DEFERRED_UNTIL_REPAIR_CANONICALIZATION"
    assert future["permitted_network_id"] == NETWORK
    assert future["permitted_taker_address"] == TAKER
    assert future["permitted_venue_id"] == VENUE
    assert document["conditional_source_repair"]["post_repair_repository_commit"] == "DEFERRED_UNTIL_REPAIR_CANONICALIZATION"
    assert document["conditional_source_repair"]["post_repair_implementation_digest"] == "DEFERRED_UNTIL_REPAIR_CANONICALIZATION"


def test_exactly_one_hostile_review_is_passed_without_critical_or_high_findings() -> None:
    review = artifact()["hostile_review"]
    assert review["review_count"] == 1
    assert review["critical"] == 0
    assert review["high"] == 0
    assert review["targeted_rereview_required"] is False
    assert review["verdict"] == "PASS"
