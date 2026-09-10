from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from qntyspot.accepted_execution_intent_v2 import (
    QNTY_ACCEPTANCE_SOURCE_COMMIT,
    QNTY_INTENT_V2_CONTRACT_MERGE,
    QNTYSPOT_IMPLEMENTATION_VERSION,
    AcceptedIntentV2Rejected,
    consume_accepted_execution_intent_v2,
)
from qntyspot.canon import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "qualifications/h003_bridge_v0/QNTY_ACCEPTED_EXECUTION_INTENT_V2.json"
FIXTURE_SHA = ROOT / "qualifications/h003_bridge_v0/QNTY_ACCEPTED_EXECUTION_INTENT_V2.sha256"
QNTYSPOT_COMMIT = "9cbcfefa0e74a5589e9a94ca00b7c37889290bce"
EXPECTED_INTENT_DIGEST = "18d9f32c5afe5ba3c6f15b4596d4bb44a1ef9c8175e6d4715c9ccba23508f48f"
EXPECTED_FILE_SHA256 = "262f2eeea5c7fea979f1500538ffd146686e9c4ac8069a1ac5ae4d3ae7cd76db"


def _intent() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _rehash(intent: dict[str, object]) -> None:
    probe = copy.deepcopy(intent)
    probe["intent_digest"] = ""
    intent["intent_digest"] = hashlib.sha256(canonical_json_bytes(probe)).hexdigest()


def _encoded(intent: dict[str, object]) -> bytes:
    return canonical_json_bytes(intent) + b"\n"


def test_published_v2_fixture_is_consumed_as_non_authoritative_no_action() -> None:
    output = consume_accepted_execution_intent_v2(FIXTURE, qntyspot_commit=QNTYSPOT_COMMIT)

    assert output["schema_name"] == "QNTYSPOT_ACCEPTED_INTENT_DECISION_V2"
    assert output["input_intent_digest"] == EXPECTED_INTENT_DIGEST
    assert output["qnty_producer"] == {
        "acceptance_schema": "H003_ACCEPTANCE_V0",
        "acceptance_source_commit": QNTY_ACCEPTANCE_SOURCE_COMMIT,
        "contract_merge": QNTY_INTENT_V2_CONTRACT_MERGE,
        "repository": "CipherCuttle/Qnty",
    }
    assert output["qntyspot_implementation"] == {
        "commit": QNTYSPOT_COMMIT,
        "repository": "CipherCuttle/QntySpot",
        "version": QNTYSPOT_IMPLEMENTATION_VERSION,
    }
    assert output["decision"] == {
        "current_target": "LONG",
        "effective_source_timestamp": "2026-09-08T20:00:00Z",
        "execution_action_required": False,
        "previous_target": "LONG",
        "transition": "NO_ACTION",
    }
    assert output["admission"] == {
        "schema_and_self_digest": "VERIFIED",
        "origin_authentication": "UNPROVEN_BY_V2_BYTES",
        "policy_admission_authorized": "NO",
        "trusted_transport_required": "YES",
    }
    assert output["projection"] == {
        "consumer_result": "NO_ACTION",
        "network_required": "NO",
        "policy_evaluation_required": "NO",
        "qntyspot_side": "NONE",
    }
    assert output["authority"] == {
        "capital": "NONE",
        "execution": "FORBIDDEN",
        "signing": "NONE",
        "submission": "NONE",
    }


def test_producer_fixture_bytes_and_sidecar_are_frozen() -> None:
    raw = FIXTURE.read_bytes()
    intent = _intent()
    assert raw == canonical_json_bytes(intent) + b"\n"
    assert intent["intent_digest"] == EXPECTED_INTENT_DIGEST
    assert FIXTURE_SHA.read_text(encoding="utf-8") == EXPECTED_INTENT_DIGEST + "\n"
    assert hashlib.sha256(raw).hexdigest() == EXPECTED_FILE_SHA256


def test_dynamic_target_change_is_observable_but_cannot_wake_policy() -> None:
    intent = _intent()
    decision = intent["decision"]
    assert isinstance(decision, dict)
    decision.update(
        previous_target="FLAT",
        current_target="LONG",
        transition="TARGET_CHANGE",
        execution_action_required=True,
        effective_source_timestamp="2026-09-05T08:00:00Z",
    )
    provenance = intent["provenance"]
    assert isinstance(provenance, dict)
    provenance["upstream_handoff_digest"] = "1" * 64
    provenance["qnty_acceptance_record_id"] = "H003_ACCEPTANCE_V0:" + "1" * 64
    provenance["qnty_acceptance_receipt_digest"] = "2" * 64
    _rehash(intent)

    output = consume_accepted_execution_intent_v2(_encoded(intent), qntyspot_commit=QNTYSPOT_COMMIT)

    assert output["decision"]["transition"] == "TARGET_CHANGE"
    assert output["decision"]["execution_action_required"] is True
    assert output["projection"]["consumer_result"] == "TARGET_CHANGE_OBSERVED"
    assert output["projection"]["policy_evaluation_required"] == "NO"
    assert output["projection"]["network_required"] == "NO"
    assert output["projection"]["qntyspot_side"] == "NONE"
    assert output["admission"]["schema_and_self_digest"] == "VERIFIED"
    assert output["admission"]["origin_authentication"] == "UNPROVEN_BY_V2_BYTES"
    assert output["admission"]["policy_admission_authorized"] == "NO"


def test_multiple_dynamic_intents_need_no_event_digest_allowlist() -> None:
    transitions: list[str] = []
    cases = [
        (3, "LONG", "LONG"),
        (4, "LONG", "FLAT"),
        (5, "FLAT", "LONG"),
    ]
    for digit, previous, current in cases:
        intent = _intent()
        decision = intent["decision"]
        provenance = intent["provenance"]
        assert isinstance(decision, dict)
        assert isinstance(provenance, dict)
        changed = previous != current
        decision.update(
            previous_target=previous,
            current_target=current,
            transition="TARGET_CHANGE" if changed else "NO_ACTION",
            execution_action_required=changed,
            effective_source_timestamp=f"2026-09-0{digit}T08:00:00Z",
        )
        provenance["upstream_handoff_digest"] = str(digit) * 64
        provenance["qnty_acceptance_record_id"] = "H003_ACCEPTANCE_V0:" + str(digit) * 64
        provenance["qnty_acceptance_receipt_digest"] = str(digit + 1) * 64
        _rehash(intent)
        output = consume_accepted_execution_intent_v2(
            _encoded(intent), qntyspot_commit=QNTYSPOT_COMMIT
        )
        transitions.append(output["decision"]["transition"])
        assert output["admission"]["policy_admission_authorized"] == "NO"

    assert transitions == ["NO_ACTION", "TARGET_CHANGE", "TARGET_CHANGE"]


def test_digest_tampering_fails_closed() -> None:
    raw = FIXTURE.read_bytes().replace(
        b'"previous_target":"LONG"', b'"previous_target":"FLAT"'
    )
    with pytest.raises(AcceptedIntentV2Rejected, match="ARTIFACT_DIGEST|DECISION_INVALID"):
        consume_accepted_execution_intent_v2(raw, qntyspot_commit=QNTYSPOT_COMMIT)


def test_rehashed_authority_escalation_fails_closed() -> None:
    intent = _intent()
    authority = intent["authority"]
    assert isinstance(authority, dict)
    authority["execution"] = "ALLOWED"
    _rehash(intent)
    with pytest.raises(AcceptedIntentV2Rejected, match="AUTHORITY_ESCALATION"):
        consume_accepted_execution_intent_v2(_encoded(intent), qntyspot_commit=QNTYSPOT_COMMIT)


def test_rehashed_acceptance_record_substitution_fails_closed() -> None:
    intent = _intent()
    provenance = intent["provenance"]
    assert isinstance(provenance, dict)
    provenance["qnty_acceptance_record_id"] = "H003_ACCEPTANCE_V0:" + "0" * 64
    _rehash(intent)
    with pytest.raises(AcceptedIntentV2Rejected, match="PROVENANCE_MISMATCH"):
        consume_accepted_execution_intent_v2(_encoded(intent), qntyspot_commit=QNTYSPOT_COMMIT)


def test_duplicate_keys_and_json_floats_fail_closed() -> None:
    duplicate = FIXTURE.read_bytes().replace(
        b'"schema_version":"V2"',
        b'"schema_version":"V2","schema_version":"V2"',
    )
    with pytest.raises(AcceptedIntentV2Rejected):
        consume_accepted_execution_intent_v2(duplicate, qntyspot_commit=QNTYSPOT_COMMIT)

    floating = FIXTURE.read_bytes().replace(b'"fast":48', b'"fast":48.0')
    with pytest.raises(AcceptedIntentV2Rejected):
        consume_accepted_execution_intent_v2(floating, qntyspot_commit=QNTYSPOT_COMMIT)


def test_replay_is_deterministic() -> None:
    first = consume_accepted_execution_intent_v2(FIXTURE, qntyspot_commit=QNTYSPOT_COMMIT)
    second = consume_accepted_execution_intent_v2(FIXTURE, qntyspot_commit=QNTYSPOT_COMMIT)
    assert first == second
    probe = dict(first)
    probe["decision_digest"] = ""
    assert first["decision_digest"] == hashlib.sha256(canonical_json_bytes(probe)).hexdigest()


def test_v2_source_has_no_event_specific_allowlist_or_sibling_runtime_import() -> None:
    source = (ROOT / "qntyspot/accepted_execution_intent_v2.py").read_text(encoding="utf-8")
    assert "CANONICAL_ARTIFACT_DIGEST" not in source
    assert EXPECTED_INTENT_DIGEST not in source
    assert "import Qnty" not in source
    assert "import QntyLab" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source
