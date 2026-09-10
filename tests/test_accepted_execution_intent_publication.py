from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qntyspot.accepted_execution_intent_publication import (
    ED25519_SIGNATURE_ALGORITHM,
    PUBLICATION_AUTH_CONTRACT_VERSION,
    PUBLICATION_PURPOSE,
    PUBLICATION_RECEIPT_SCHEMA,
    PUBLICATION_ROOT_ID,
    PUBLICATION_TRUST_CONFIG_SCHEMA,
    PublicationAuthenticationError,
    QntyPublicationReceiptV0,
    VerifiedQntyPublicationV0,
    authenticate_accepted_execution_intent_v2,
    load_trusted_qnty_publication_root,
)
from qntyspot.accepted_execution_intent_v2 import (
    ACCEPTED_INTENT_SCHEMA_NAME,
    ACCEPTED_INTENT_SCHEMA_VERSION,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "qualifications/h003_bridge_v0/QNTY_ACCEPTED_EXECUTION_INTENT_V2.json"
QNTYSPOT_COMMIT = "f2680ffed1dd8fa3d288ca916226940210f371f9"
QNTY_PUBLICATION_COMMIT = "2ebed2af94127f2e018de46069d1bbe27178ca8a"
EXPECTED_FILE_SHA256 = "262f2eeea5c7fea979f1500538ffd146686e9c4ac8069a1ac5ae4d3ae7cd76db"
TEST_PRIVATE_KEY_BYTES = bytes.fromhex("11" * 32)
ALT_PRIVATE_KEY_BYTES = bytes.fromhex("22" * 32)


def _private_key(raw: bytes = TEST_PRIVATE_KEY_BYTES) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def _public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _trusted_root(
    private_key: Ed25519PrivateKey | None = None, *, minimum_publication_epoch: int = 1
):
    key = private_key or _private_key()
    public_key = _public_key_bytes(key)
    config = {
        "minimum_publication_epoch": minimum_publication_epoch,
        "public_key_fingerprint": sha256_hex(public_key),
        "purpose": PUBLICATION_PURPOSE,
        "root_id": PUBLICATION_ROOT_ID,
        "schema": PUBLICATION_TRUST_CONFIG_SCHEMA,
        "signature_algorithm": ED25519_SIGNATURE_ALGORITHM,
        "trust_config_version": 1,
    }
    config_bytes = canonical_json_bytes(config)
    return load_trusted_qnty_publication_root(
        config_bytes,
        expected_config_digest=sha256_hex(config_bytes),
        anchor_bytes=public_key,
    )


def _receipt(
    raw_intent: bytes,
    *,
    private_key: Ed25519PrivateKey | None = None,
    publication_epoch: int = 1,
    serial: int = 1,
    qnty_commit: str = QNTY_PUBLICATION_COMMIT,
) -> QntyPublicationReceiptV0:
    key = private_key or _private_key()
    intent = json.loads(raw_intent)
    unsigned = QntyPublicationReceiptV0(
        root_id=PUBLICATION_ROOT_ID,
        purpose=PUBLICATION_PURPOSE,
        public_key_fingerprint=sha256_hex(_public_key_bytes(key)),
        signature_algorithm=ED25519_SIGNATURE_ALGORITHM,
        publication_epoch=publication_epoch,
        serial=serial,
        published_at_epoch_s=1789056614,
        qnty_repository="CipherCuttle/Qnty",
        qnty_repository_commit=qnty_commit,
        accepted_intent_schema_name=ACCEPTED_INTENT_SCHEMA_NAME,
        accepted_intent_schema_version=ACCEPTED_INTENT_SCHEMA_VERSION,
        intent_digest=intent["intent_digest"],
        artifact_sha256=hashlib.sha256(raw_intent).hexdigest(),
        signature=b"\x00" * 64,
        schema=PUBLICATION_RECEIPT_SCHEMA,
    )
    return replace(unsigned, signature=key.sign(unsigned.signed_body_bytes))


def _rehash_intent(intent: dict[str, object]) -> None:
    probe = copy.deepcopy(intent)
    probe["intent_digest"] = ""
    intent["intent_digest"] = hashlib.sha256(canonical_json_bytes(probe)).hexdigest()


def test_signed_publication_authenticates_exact_producer_fixture_without_policy_authority() -> None:
    raw = FIXTURE.read_bytes()
    verified = authenticate_accepted_execution_intent_v2(
        raw,
        receipt=_receipt(raw).serialized,
        trusted_root=_trusted_root(),
        qntyspot_commit=QNTYSPOT_COMMIT,
    )
    evidence = verified.evidence_object()

    assert evidence["admission"] == {
        "origin_authentication": "VERIFIED_BY_QNTY_PUBLICATION_ROOT",
        "policy_admission_authorized": "NO",
        "policy_bridge_eligible": "YES",
        "publication_authentication": "VERIFIED",
        "schema_and_self_digest": "VERIFIED",
        "trusted_transport_required": "SATISFIED",
    }
    assert evidence["publication_authentication"]["contract_version"] == PUBLICATION_AUTH_CONTRACT_VERSION
    assert evidence["publication_authentication"]["exact_artifact_sha256"] == EXPECTED_FILE_SHA256
    assert evidence["publication_authentication"]["qnty_repository_commit"] == QNTY_PUBLICATION_COMMIT
    assert evidence["projection"] == {
        "consumer_result": "NO_ACTION",
        "network_required": "NO",
        "policy_evaluation_required": "NO",
        "qntyspot_execution_action_authorized": "NO",
        "qntyspot_side": "NONE",
    }
    assert evidence["authority"] == {
        "capital": "NONE",
        "execution": "FORBIDDEN",
        "signing": "NONE",
        "submission": "NONE",
    }


def test_authenticated_target_change_is_only_policy_bridge_eligible_not_policy_admitted() -> None:
    intent = json.loads(FIXTURE.read_text(encoding="utf-8"))
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

    evidence = authenticate_accepted_execution_intent_v2(
        raw,
        receipt=_receipt(raw, serial=2).serialized,
        trusted_root=_trusted_root(),
        qntyspot_commit=QNTYSPOT_COMMIT,
    ).evidence_object()

    assert evidence["decision"]["transition"] == "TARGET_CHANGE"
    assert evidence["decision"]["upstream_execution_action_required"] is True
    assert evidence["admission"]["origin_authentication"] == "VERIFIED_BY_QNTY_PUBLICATION_ROOT"
    assert evidence["admission"]["policy_bridge_eligible"] == "YES"
    assert evidence["admission"]["policy_admission_authorized"] == "NO"
    assert evidence["projection"]["consumer_result"] == "TARGET_CHANGE_OBSERVED"
    assert evidence["projection"]["policy_evaluation_required"] == "NO"
    assert evidence["projection"]["network_required"] == "NO"
    assert evidence["projection"]["qntyspot_execution_action_authorized"] == "NO"
    assert evidence["projection"]["qntyspot_side"] == "NONE"


def test_semantically_identical_but_byte_different_artifact_is_rejected() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _receipt(raw)
    without_trailing_newline = raw.rstrip(b"\n")
    with pytest.raises(PublicationAuthenticationError, match="exact received bytes"):
        authenticate_accepted_execution_intent_v2(
            without_trailing_newline,
            receipt=receipt,
            trusted_root=_trusted_root(),
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_rehashed_intent_substitution_cannot_reuse_old_publication_receipt() -> None:
    original = FIXTURE.read_bytes()
    receipt = _receipt(original)
    intent = json.loads(original)
    intent["decision"]["effective_source_timestamp"] = "2026-09-09T20:00:00Z"
    _rehash_intent(intent)
    substituted = canonical_json_bytes(intent) + b"\n"

    with pytest.raises(PublicationAuthenticationError, match="intent_digest"):
        authenticate_accepted_execution_intent_v2(
            substituted,
            receipt=receipt,
            trusted_root=_trusted_root(),
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_invalid_signature_fails_closed_even_with_self_consistent_receipt_object() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _receipt(raw)
    forged_signature = bytes([receipt.signature[0] ^ 1]) + receipt.signature[1:]
    forged = replace(receipt, signature=forged_signature)

    with pytest.raises(PublicationAuthenticationError, match="signature is invalid"):
        authenticate_accepted_execution_intent_v2(
            raw,
            receipt=forged,
            trusted_root=_trusted_root(),
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_wrong_publication_root_fails_closed() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _receipt(raw)
    other_root = _trusted_root(_private_key(ALT_PRIVATE_KEY_BYTES))

    with pytest.raises(PublicationAuthenticationError, match="fingerprint differs"):
        authenticate_accepted_execution_intent_v2(
            raw,
            receipt=receipt,
            trusted_root=other_root,
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_publication_epoch_floor_is_external_and_fail_closed() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _receipt(raw, publication_epoch=1)
    root = _trusted_root(minimum_publication_epoch=2)

    with pytest.raises(PublicationAuthenticationError, match="below the external minimum epoch"):
        authenticate_accepted_execution_intent_v2(
            raw,
            receipt=receipt,
            trusted_root=root,
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_trust_configuration_is_canonical_digest_pinned_and_exact_schema() -> None:
    key = _private_key()
    public_key = _public_key_bytes(key)
    config = {
        "minimum_publication_epoch": 1,
        "public_key_fingerprint": sha256_hex(public_key),
        "purpose": PUBLICATION_PURPOSE,
        "root_id": PUBLICATION_ROOT_ID,
        "schema": PUBLICATION_TRUST_CONFIG_SCHEMA,
        "signature_algorithm": ED25519_SIGNATURE_ALGORITHM,
        "trust_config_version": 1,
    }
    config_bytes = canonical_json_bytes(config)

    with pytest.raises(PublicationAuthenticationError, match="digest mismatch"):
        load_trusted_qnty_publication_root(
            config_bytes,
            expected_config_digest="0" * 64,
            anchor_bytes=public_key,
        )

    with pytest.raises(PublicationAuthenticationError, match="not canonical"):
        load_trusted_qnty_publication_root(
            config_bytes + b"\n",
            expected_config_digest=sha256_hex(config_bytes + b"\n"),
            anchor_bytes=public_key,
        )

    extra = dict(config)
    extra["authority_level"] = 3
    extra_bytes = canonical_json_bytes(extra)
    with pytest.raises(PublicationAuthenticationError, match="unknown or missing fields"):
        load_trusted_qnty_publication_root(
            extra_bytes,
            expected_config_digest=sha256_hex(extra_bytes),
            anchor_bytes=public_key,
        )


def test_receipt_round_trip_is_canonical_and_rejects_unknown_fields() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _receipt(raw)
    reparsed = QntyPublicationReceiptV0.from_bytes(receipt.serialized)
    assert reparsed == receipt

    document = receipt.to_object()
    document["authority_level"] = 3
    with pytest.raises(PublicationAuthenticationError, match="unknown or missing fields"):
        QntyPublicationReceiptV0.from_bytes(canonical_json_bytes(document))


def test_verified_publication_is_opaque_and_evidence_replay_is_deterministic() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _receipt(raw)
    root = _trusted_root()
    first = authenticate_accepted_execution_intent_v2(
        raw,
        receipt=receipt.serialized,
        trusted_root=root,
        qntyspot_commit=QNTYSPOT_COMMIT,
    )
    second = authenticate_accepted_execution_intent_v2(
        raw,
        receipt=receipt.serialized,
        trusted_root=root,
        qntyspot_commit=QNTYSPOT_COMMIT,
    )
    assert first.evidence_object() == second.evidence_object()

    with pytest.raises(TypeError, match="only constructed by authentication"):
        VerifiedQntyPublicationV0(
            receipt=receipt,
            trust_config_digest=root.trust_config_digest,
            public_key_fingerprint=root.public_key_fingerprint,
            exact_artifact_sha256=EXPECTED_FILE_SHA256,
            accepted_intent_projection={},
            _construction_token=None,
        )


def test_publication_verifier_has_no_issuer_private_key_or_economic_authority_dependency() -> None:
    source = (ROOT / "qntyspot/accepted_execution_intent_publication.py").read_text(
        encoding="utf-8"
    )
    assert "Ed25519PrivateKey" not in source
    assert "from .authority_root" not in source
    assert "import authority_root" not in source
    assert "os.environ" not in source
    assert "getenv(" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source
