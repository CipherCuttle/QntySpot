from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from qntyspot.accepted_execution_intent_publication import (
    ED25519_SIGNATURE_ALGORITHM,
    PUBLICATION_PURPOSE,
    PUBLICATION_RECEIPT_SCHEMA,
    PUBLICATION_ROOT_ID,
    PUBLICATION_TRUST_CONFIG_SCHEMA,
    QntyPublicationReceiptV0,
    VerifiedQntyPublicationV0,
    authenticate_accepted_execution_intent_v2,
    load_trusted_qnty_publication_root,
)
from qntyspot.accepted_execution_intent_v2 import (
    ACCEPTED_INTENT_SCHEMA_NAME,
    ACCEPTED_INTENT_SCHEMA_VERSION,
)
from qntyspot.accepted_intent_policy_bridge import (
    POLICY_BRIDGE_CONTRACT_VERSION,
    POLICY_EVALUATION_REQUEST_SCHEMA,
    AcceptedIntentPolicyEvaluationRequestV0,
    PolicyBridgeError,
    bridge_authenticated_intent_to_policy_request,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex, strict_json_loads

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "qualifications/h003_bridge_v0"
INTENT = QUALIFICATION / "QNTY_ACCEPTED_EXECUTION_INTENT_V2.json"
RECEIPT = QUALIFICATION / "QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_RECEIPT_V0.json"
QNTYSPOT_COMMIT = "556991970c3fa419f7adec7f0548c55c5de1b62c"
QNTY_PUBLICATION_COMMIT = "2ebed2af94127f2e018de46069d1bbe27178ca8a"
TEST_PUBLIC_KEY_BYTES = bytes.fromhex(
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
)
TARGET_CHANGE_SIGNATURE_HEX = (
    "ca97ac85c858a229d766e7587bc26eca811f834354edda9bf334c405dddfbc08"
    "a764f8a7f7a118aa3fc2351157cd39534ea4515ac102a7e042fede4d8dc7ee0a"
)
TARGET_CHANGE_INTENT_DIGEST = "1d558fd8067b466394a97a27e630c47bffe70933ab4d8e605805b04200ef49e5"
TARGET_CHANGE_FILE_SHA256 = "337b5d9ce09f4536b7a7728670892f85f8bd2ac4b34efb3cf5382dfcbc1de089"


def _trust_material() -> tuple[bytes, str, bytes]:
    config = {
        "minimum_publication_epoch": 1,
        "public_key_fingerprint": sha256_hex(TEST_PUBLIC_KEY_BYTES),
        "purpose": PUBLICATION_PURPOSE,
        "root_id": PUBLICATION_ROOT_ID,
        "schema": PUBLICATION_TRUST_CONFIG_SCHEMA,
        "signature_algorithm": ED25519_SIGNATURE_ALGORITHM,
        "trust_config_version": 1,
    }
    config_bytes = canonical_json_bytes(config)
    return config_bytes, sha256_hex(config_bytes), TEST_PUBLIC_KEY_BYTES


def _trusted_root():
    config_bytes, config_digest, anchor_bytes = _trust_material()
    return load_trusted_qnty_publication_root(
        config_bytes,
        expected_config_digest=config_digest,
        anchor_bytes=anchor_bytes,
    )


def _rehash_intent(intent: dict[str, object]) -> None:
    probe = copy.deepcopy(intent)
    probe["intent_digest"] = ""
    intent["intent_digest"] = hashlib.sha256(canonical_json_bytes(probe)).hexdigest()


def _target_change_raw() -> bytes:
    intent = json.loads(INTENT.read_text(encoding="utf-8"))
    intent["decision"] = {
        "current_target": "LONG",
        "effective_source_timestamp": "2026-09-05T08:00:00Z",
        "execution_action_required": True,
        "previous_target": "FLAT",
        "transition": "TARGET_CHANGE",
    }
    intent["provenance"]["upstream_handoff_digest"] = "3" * 64
    intent["provenance"]["qnty_acceptance_record_id"] = "H003_ACCEPTANCE_V0:" + "3" * 64
    intent["provenance"]["qnty_acceptance_receipt_digest"] = "4" * 64
    _rehash_intent(intent)
    raw = canonical_json_bytes(intent) + b"\n"
    assert intent["intent_digest"] == TARGET_CHANGE_INTENT_DIGEST
    assert hashlib.sha256(raw).hexdigest() == TARGET_CHANGE_FILE_SHA256
    return raw


def _target_change_receipt(raw: bytes) -> QntyPublicationReceiptV0:
    intent = json.loads(raw)
    return QntyPublicationReceiptV0(
        root_id=PUBLICATION_ROOT_ID,
        purpose=PUBLICATION_PURPOSE,
        public_key_fingerprint=sha256_hex(TEST_PUBLIC_KEY_BYTES),
        signature_algorithm=ED25519_SIGNATURE_ALGORITHM,
        publication_epoch=1,
        serial=2,
        published_at_epoch_s=1789056614,
        qnty_repository="CipherCuttle/Qnty",
        qnty_repository_commit=QNTY_PUBLICATION_COMMIT,
        accepted_intent_schema_name=ACCEPTED_INTENT_SCHEMA_NAME,
        accepted_intent_schema_version=ACCEPTED_INTENT_SCHEMA_VERSION,
        intent_digest=intent["intent_digest"],
        artifact_sha256=hashlib.sha256(raw).hexdigest(),
        signature=bytes.fromhex(TARGET_CHANGE_SIGNATURE_HEX),
        schema=PUBLICATION_RECEIPT_SCHEMA,
    )


def _bridge(intent_bytes: bytes, receipt_bytes: bytes):
    config_bytes, config_digest, anchor_bytes = _trust_material()
    return bridge_authenticated_intent_to_policy_request(
        intent_bytes,
        receipt_bytes=receipt_bytes,
        trust_config_bytes=config_bytes,
        expected_trust_config_digest=config_digest,
        anchor_bytes=anchor_bytes,
        qntyspot_commit=QNTYSPOT_COMMIT,
    )


def _target_change_request():
    raw = _target_change_raw()
    return _bridge(raw, _target_change_receipt(raw).serialized)


def test_authenticated_no_action_does_not_wake_policy() -> None:
    assert _bridge(INTENT.read_bytes(), RECEIPT.read_bytes()) is None


def test_authenticated_target_change_yields_policy_evaluation_request_only() -> None:
    request = _target_change_request()
    assert request is not None
    document = request.to_object()

    assert document["schema"] == POLICY_EVALUATION_REQUEST_SCHEMA
    assert document["contract_version"] == POLICY_BRIDGE_CONTRACT_VERSION
    assert document["decision"] == {
        "current_target": "LONG",
        "effective_source_timestamp": "2026-09-05T08:00:00Z",
        "previous_target": "FLAT",
        "transition": "TARGET_CHANGE",
    }
    assert document["policy"] == {
        "binding_status": "UNBOUND",
        "evaluation_requested": "YES",
        "independent_policy_binding_required": "YES",
        "policy_admission_authorized": "NO",
    }
    assert document["authority"] == {
        "capital_authorized": "NO",
        "economic_action_authorized": "NO",
        "network_authorized": "NO",
        "signing_authorized": "NO",
        "submission_authorized": "NO",
    }
    assert document["provenance"]["source_intent_digest"] == TARGET_CHANGE_INTENT_DIGEST
    assert document["provenance"]["qnty_repository_commit"] == QNTY_PUBLICATION_COMMIT
    assert document["provenance"]["qntyspot_repository_commit"] == QNTYSPOT_COMMIT
    assert document["provenance"]["qntyspot_implementation_version"] == (
        "QNTYSPOT_ACCEPTED_EXECUTION_INTENT_DYNAMIC_CONSUMER_V2"
    )
    assert len(document["request_id"]) == 64


def test_policy_request_is_canonical_immutable_and_deterministic() -> None:
    first = _target_change_request()
    second = _target_change_request()
    assert first is not None and second is not None
    assert first == second
    assert first.serialized == second.serialized
    assert strict_json_loads(first.serialized) == first.to_object()
    assert canonical_json_bytes(first.to_object()) == first.serialized

    with pytest.raises(AttributeError):
        first.current_target = "FLAT"


def test_policy_request_constructor_is_opaque() -> None:
    with pytest.raises(TypeError, match="only constructed by the authenticated bridge"):
        AcceptedIntentPolicyEvaluationRequestV0(
            publication_receipt_id="0" * 64,
            publication_signed_body_digest="1" * 64,
            publication_trust_config_digest="2" * 64,
            source_intent_digest="3" * 64,
            qnty_repository_commit="4" * 40,
            qntyspot_repository_commit="5" * 40,
            qntyspot_implementation_version="test",
            effective_source_timestamp="2026-09-05T08:00:00Z",
            previous_target="FLAT",
            current_target="LONG",
            transition="TARGET_CHANGE",
            request_id="6" * 64,
            _construction_token=None,
        )


def test_retained_or_forged_proof_objects_are_not_bridge_inputs() -> None:
    verified = authenticate_accepted_execution_intent_v2(
        INTENT.read_bytes(),
        receipt=RECEIPT.read_bytes(),
        trusted_root=_trusted_root(),
        qntyspot_commit=QNTYSPOT_COMMIT,
    )
    forged = object.__new__(VerifiedQntyPublicationV0)
    object.__setattr__(forged, "accepted_intent_projection_bytes", b"{}")

    config_bytes, config_digest, anchor_bytes = _trust_material()
    for proof in (verified, forged):
        with pytest.raises(PolicyBridgeError, match="accepted intent must be supplied as exact bytes"):
            bridge_authenticated_intent_to_policy_request(  # type: ignore[arg-type]
                proof,
                receipt_bytes=RECEIPT.read_bytes(),
                trust_config_bytes=config_bytes,
                expected_trust_config_digest=config_digest,
                anchor_bytes=anchor_bytes,
                qntyspot_commit=QNTYSPOT_COMMIT,
            )


def test_mutating_a_legitimate_proof_cannot_change_bridge_result() -> None:
    verified = authenticate_accepted_execution_intent_v2(
        INTENT.read_bytes(),
        receipt=RECEIPT.read_bytes(),
        trusted_root=_trusted_root(),
        qntyspot_commit=QNTYSPOT_COMMIT,
    )
    forged_projection = verified.evidence_object()
    forged_projection["decision"] = {
        "current_target": "LONG",
        "effective_source_timestamp": "2026-09-05T08:00:00Z",
        "previous_target": "FLAT",
        "transition": "TARGET_CHANGE",
        "upstream_execution_action_required": True,
    }
    object.__setattr__(
        verified,
        "accepted_intent_projection_bytes",
        canonical_json_bytes(forged_projection),
    )

    # The retained proof is never consumed. The bridge re-authenticates the
    # original signed bytes and therefore preserves the signed NO_ACTION.
    assert _bridge(INTENT.read_bytes(), RECEIPT.read_bytes()) is None


def test_tampered_exact_intent_bytes_fail_publication_reauthentication() -> None:
    raw = _target_change_raw()
    receipt_bytes = _target_change_receipt(raw).serialized
    tampered = json.loads(raw)
    tampered["decision"]["effective_source_timestamp"] = "2026-09-05T09:00:00Z"
    _rehash_intent(tampered)
    tampered_raw = canonical_json_bytes(tampered) + b"\n"

    with pytest.raises(PolicyBridgeError, match="publication reauthentication failed"):
        _bridge(tampered_raw, receipt_bytes)


def test_mutable_receipt_and_trust_objects_are_not_accepted_at_bridge_boundary() -> None:
    raw = _target_change_raw()
    receipt = _target_change_receipt(raw)
    config_bytes, config_digest, anchor_bytes = _trust_material()

    with pytest.raises(PolicyBridgeError, match="publication receipt must be supplied as exact bytes"):
        bridge_authenticated_intent_to_policy_request(
            raw,
            receipt_bytes=receipt,  # type: ignore[arg-type]
            trust_config_bytes=config_bytes,
            expected_trust_config_digest=config_digest,
            anchor_bytes=anchor_bytes,
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_policy_request_contains_no_executable_policy_or_venue_parameters() -> None:
    request = _target_change_request()
    assert request is not None
    document = request.to_object()
    serialized_keys = set()

    def collect_keys(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                serialized_keys.add(key)
                collect_keys(child)
        elif isinstance(value, list):
            for child in value:
                collect_keys(child)

    collect_keys(document)
    forbidden_fields = {
        "amount",
        "base",
        "instrument",
        "max_price_impact_bps",
        "max_slippage_bps",
        "network_id",
        "price",
        "quote",
        "side",
        "signed_transaction",
        "taker_address",
        "transaction",
        "venue_id",
    }
    assert serialized_keys.isdisjoint(forbidden_fields)
    assert "policy_id" not in serialized_keys


def test_bridge_has_no_policy_parser_execution_or_io_dependency() -> None:
    source = (ROOT / "qntyspot/accepted_intent_policy_bridge.py").read_text(encoding="utf-8")
    forbidden_imports = (
        "from .policy",
        "import policy",
        "from .execution_contract",
        "from .authority_root",
        "import requests",
        "from requests",
        "import urllib",
        "from urllib",
        "import socket",
        "from socket",
        "os.environ",
        "getenv(",
    )
    for token in forbidden_imports:
        assert token not in source
