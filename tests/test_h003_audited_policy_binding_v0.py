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
)
from qntyspot.accepted_execution_intent_v2 import (
    ACCEPTED_INTENT_SCHEMA_NAME,
    ACCEPTED_INTENT_SCHEMA_VERSION,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex, strict_json_loads
from qntyspot.h003_audited_policy_binding import (
    H003_AUDITED_POLICY_BINDING_CONTRACT_VERSION,
    H003_AUDITED_POLICY_BINDING_SCHEMA,
    H003_POLICY_DOCUMENT_SHA256,
    H003_TRANSLATION_AUDIT_DIGEST,
    H003AuditedPolicyBindingError,
    bind_authenticated_h003_target_to_audited_policy,
)
from qntyspot.policy import load_policy_file

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "qualifications/h003_bridge_v0"
INTENT = QUALIFICATION / "QNTY_ACCEPTED_EXECUTION_INTENT_V2.json"
RECEIPT = QUALIFICATION / "QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_RECEIPT_V0.json"
AUDIT = QUALIFICATION / "INSTRUMENT_TRANSLATION_AUDIT_V0.json"
POLICY = ROOT / "qualifications/solana_v0c/sol_usdc_buy.policy.json"
QNTYSPOT_COMMIT = "c597b18319035e35bbe41c4566e898b433f70970"
QNTY_PUBLICATION_COMMIT = "2ebed2af94127f2e018de46069d1bbe27178ca8a"
TEST_PUBLIC_KEY_BYTES = bytes.fromhex(
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
)
TARGET_CHANGE_SIGNATURE_HEX = (
    "ca97ac85c858a229d766e7587bc26eca811f834354edda9bf334c405dddfbc08"
    "a764f8a7f7a118aa3fc2351157cd39534ea4515ac102a7e042fede4d8dc7ee0a"
)
TARGET_CHANGE_INTENT_DIGEST = "1d558fd8067b466394a97a27e630c47bffe70933ab4d8e605805b04200ef49e5"


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
    return raw


def _target_change_receipt(raw: bytes) -> bytes:
    intent = json.loads(raw)
    receipt = QntyPublicationReceiptV0(
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
    return receipt.serialized


def _bind(intent_bytes: bytes, receipt_bytes: bytes, *, policy_bytes: bytes | None = None, audit_bytes: bytes | None = None):
    config_bytes, config_digest, anchor_bytes = _trust_material()
    return bind_authenticated_h003_target_to_audited_policy(
        intent_bytes,
        receipt_bytes=receipt_bytes,
        trust_config_bytes=config_bytes,
        expected_trust_config_digest=config_digest,
        anchor_bytes=anchor_bytes,
        qntyspot_commit=QNTYSPOT_COMMIT,
        policy_bytes=POLICY.read_bytes() if policy_bytes is None else policy_bytes,
        translation_audit_bytes=AUDIT.read_bytes() if audit_bytes is None else audit_bytes,
    )


def _target_binding_bytes() -> bytes:
    raw = _target_change_raw()
    result = _bind(raw, _target_change_receipt(raw))
    assert result is not None
    return result


def test_authenticated_no_action_stays_inert_before_policy_binding() -> None:
    # The policy/audit are deliberately invalid here. NO_ACTION must stop before
    # any attempt to bind an executable policy surface.
    result = _bind(
        INTENT.read_bytes(),
        RECEIPT.read_bytes(),
        policy_bytes=b"not-a-policy",
        audit_bytes=b"not-an-audit",
    )
    assert result is None


def test_authenticated_long_target_binds_to_frozen_audited_policy_direction() -> None:
    raw = _target_binding_bytes()
    document = strict_json_loads(raw)
    policy = load_policy_file(POLICY)

    assert document["schema"] == H003_AUDITED_POLICY_BINDING_SCHEMA
    assert document["contract_version"] == H003_AUDITED_POLICY_BINDING_CONTRACT_VERSION
    assert document["binding"] == {
        "binding_status": "VERIFIED_AUDITED_POLICY_BINDING",
        "market_observation_required": "YES",
        "policy_time_evaluation_required": "YES",
        "quote_evaluation_required": "YES",
    }
    assert document["mapping"] == {
        "candidate_level_ids": ["USDC-SOL-1"],
        "current_target": "LONG",
        "exactin_pair": "USDC->WSOL",
        "policy_side": "SELL",
        "previous_target": "FLAT",
        "transition": "TARGET_CHANGE",
    }
    assert document["policy"] == {
        "policy_document_sha256": H003_POLICY_DOCUMENT_SHA256,
        "policy_id": policy.policy_id,
        "policy_name": "solana-v0c-technical-sol-usdc-buy",
    }
    assert document["provenance"]["source_intent_digest"] == TARGET_CHANGE_INTENT_DIGEST
    assert document["provenance"]["translation_audit_digest"] == H003_TRANSLATION_AUDIT_DIGEST
    assert document["provenance"]["qnty_repository_commit"] == QNTY_PUBLICATION_COMMIT
    assert document["provenance"]["qntyspot_repository_commit"] == QNTYSPOT_COMMIT
    assert len(document["provenance"]["research_identity_digest"]) == 64


def test_binding_remains_explicitly_non_authoritative() -> None:
    document = strict_json_loads(_target_binding_bytes())
    assert document["authority"] == {
        "capital_authorized": "NO",
        "economic_action_authorized": "NO",
        "market_observation_authorized": "NO",
        "network_authorized": "NO",
        "policy_admission_authorized": "NO",
        "signing_authorized": "NO",
        "submission_authorized": "NO",
    }


def test_binding_bytes_are_canonical_deterministic_and_self_digesting() -> None:
    first = _target_binding_bytes()
    second = _target_binding_bytes()
    assert first == second
    document = strict_json_loads(first)
    assert first == canonical_json_bytes(document)
    declared = document["binding_digest"]
    probe = dict(document)
    probe["binding_digest"] = ""
    assert sha256_hex(canonical_json_bytes(probe)) == declared


def test_policy_bytes_must_match_exact_frozen_policy_audited_digest() -> None:
    raw = _target_change_raw()
    altered_policy = POLICY.read_bytes() + b"\n"
    with pytest.raises(H003AuditedPolicyBindingError, match="policy bytes do not match"):
        _bind(raw, _target_change_receipt(raw), policy_bytes=altered_policy)


def test_self_consistent_but_modified_translation_audit_is_rejected_by_governed_digest() -> None:
    raw = _target_change_raw()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    audit["mapping_table"]["long"]["policy_side"] = "BUY"
    material = {key: value for key, value in audit.items() if key != "artifact_digest"}
    audit["artifact_digest"] = sha256_hex(canonical_json_bytes(material))
    altered = canonical_json_bytes(audit) + b"\n"

    with pytest.raises(H003AuditedPolicyBindingError, match="not the governed H003 audit"):
        _bind(raw, _target_change_receipt(raw), audit_bytes=altered)


def test_tampered_signal_cannot_reach_policy_binding_with_old_signature() -> None:
    raw = _target_change_raw()
    receipt = _target_change_receipt(raw)
    tampered = json.loads(raw)
    tampered["decision"]["effective_source_timestamp"] = "2026-09-05T09:00:00Z"
    _rehash_intent(tampered)

    with pytest.raises(H003AuditedPolicyBindingError, match="authenticated policy bridge rejected input"):
        _bind(canonical_json_bytes(tampered) + b"\n", receipt)


def test_binding_output_contains_no_amount_price_quote_or_transaction_authority() -> None:
    document = strict_json_loads(_target_binding_bytes())
    keys: set[str] = set()

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                keys.add(key)
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(document)
    forbidden = {
        "amount",
        "max_input_atomic",
        "min_output_atomic",
        "price",
        "quote_id",
        "signed_transaction",
        "slippage_bps",
        "taker_address",
        "transaction",
        "venue_id",
    }
    assert keys.isdisjoint(forbidden)


def test_binding_runtime_has_no_market_execution_or_ambient_io_dependency() -> None:
    source = (ROOT / "qntyspot/h003_audited_policy_binding.py").read_text(encoding="utf-8")
    forbidden_imports = (
        "from .solana",
        "import solana",
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
