from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

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

# Fixed verification vectors were generated outside QntySpot. The repository
# contains public verification material and signatures only; it never creates
# or handles signing-key material, including in tests.
TEST_PUBLIC_KEY_BYTES = bytes.fromhex(
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
)
ALT_PUBLIC_KEY_BYTES = bytes.fromhex(
    "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"
)
FIXTURE_SIGNATURE_HEX = (
    "138d0c26efd28d6634611ee3754fe0b51e82b01559f34efd5d41888028645f9f"
    "051e8cecec4410ef79282012f339a9da9367c2974f2dfd0bbeae8068be6e8609"
)
TARGET_CHANGE_SIGNATURE_HEX = (
    "ca97ac85c858a229d766e7587bc26eca811f834354edda9bf334c405dddfbc08"
    "a764f8a7f7a118aa3fc2351157cd39534ea4515ac102a7e042fede4d8dc7ee0a"
)
TARGET_CHANGE_INTENT_DIGEST = "1d558fd8067b466394a97a27e630c47bffe70933ab4d8e605805b04200ef49e5"
TARGET_CHANGE_FILE_SHA256 = "337b5d9ce09f4536b7a7728670892f85f8bd2ac4b34efb3cf5382dfcbc1de089"


def _trusted_root(
    public_key: bytes = TEST_PUBLIC_KEY_BYTES, *, minimum_publication_epoch: int = 1
):
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
    signature_hex: str,
    publication_epoch: int = 1,
    serial: int = 1,
    qnty_commit: str = QNTY_PUBLICATION_COMMIT,
) -> QntyPublicationReceiptV0:
    intent = json.loads(raw_intent)
    return QntyPublicationReceiptV0(
        root_id=PUBLICATION_ROOT_ID,
        purpose=PUBLICATION_PURPOSE,
        public_key_fingerprint=sha256_hex(TEST_PUBLIC_KEY_BYTES),
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
        signature=bytes.fromhex(signature_hex),
        schema=PUBLICATION_RECEIPT_SCHEMA,
    )


def _fixture_receipt(raw: bytes) -> QntyPublicationReceiptV0:
    return _receipt(raw, signature_hex=FIXTURE_SIGNATURE_HEX)


def _rehash_intent(intent: dict[str, object]) -> None:
    probe = copy.deepcopy(intent)
    probe["intent_digest"] = ""
    intent["intent_digest"] = hashlib.sha256(canonical_json_bytes(probe)).hexdigest()


def _target_change_raw() -> bytes:
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
    assert intent["intent_digest"] == TARGET_CHANGE_INTENT_DIGEST
    assert hashlib.sha256(raw).hexdigest() == TARGET_CHANGE_FILE_SHA256
    return raw


def test_signed_publication_authenticates_exact_producer_fixture_without_policy_authority() -> None:
    raw = FIXTURE.read_bytes()
    verified = authenticate_accepted_execution_intent_v2(
        raw,
        receipt=_fixture_receipt(raw).serialized,
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
    raw = _target_change_raw()
    receipt = _receipt(
        raw,
        signature_hex=TARGET_CHANGE_SIGNATURE_HEX,
        serial=2,
    )
    evidence = authenticate_accepted_execution_intent_v2(
        raw,
        receipt=receipt.serialized,
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
    receipt = _fixture_receipt(raw)
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
    receipt = _fixture_receipt(original)
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
    receipt = _fixture_receipt(raw)
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
    receipt = _fixture_receipt(raw)
    other_root = _trusted_root(ALT_PUBLIC_KEY_BYTES)

    with pytest.raises(PublicationAuthenticationError, match="fingerprint differs"):
        authenticate_accepted_execution_intent_v2(
            raw,
            receipt=receipt,
            trusted_root=other_root,
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_publication_epoch_floor_is_external_and_fail_closed() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _fixture_receipt(raw)
    root = _trusted_root(minimum_publication_epoch=2)

    with pytest.raises(PublicationAuthenticationError, match="below the external minimum epoch"):
        authenticate_accepted_execution_intent_v2(
            raw,
            receipt=receipt,
            trusted_root=root,
            qntyspot_commit=QNTYSPOT_COMMIT,
        )


def test_trust_configuration_is_canonical_digest_pinned_and_exact_schema() -> None:
    public_key = TEST_PUBLIC_KEY_BYTES
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
    receipt = _fixture_receipt(raw)
    reparsed = QntyPublicationReceiptV0.from_bytes(receipt.serialized)
    assert reparsed == receipt

    document = receipt.to_object()
    document["authority_level"] = 3
    with pytest.raises(PublicationAuthenticationError, match="unknown or missing fields"):
        QntyPublicationReceiptV0.from_bytes(canonical_json_bytes(document))


def test_verified_publication_is_opaque_immutable_and_deterministic() -> None:
    raw = FIXTURE.read_bytes()
    receipt = _fixture_receipt(raw)
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
    baseline = first.evidence_object()
    assert baseline == second.evidence_object()
    assert isinstance(first.accepted_intent_projection_bytes, bytes)

    detached = first.evidence_object()
    detached["decision"]["current_target"] = "FLAT"
    detached["admission"]["origin_authentication"] = "FORGED"
    assert first.evidence_object() == baseline

    with pytest.raises(AttributeError):
        first.accepted_intent_projection_bytes = b"{}"

    with pytest.raises(TypeError, match="only constructed by authentication"):
        VerifiedQntyPublicationV0(
            receipt=receipt,
            trust_config_digest=root.trust_config_digest,
            public_key_fingerprint=root.public_key_fingerprint,
            exact_artifact_sha256=EXPECTED_FILE_SHA256,
            accepted_intent_projection={},
            _construction_token=None,
        )


def test_repository_contains_only_public_verification_vectors_for_publication_auth() -> None:
    test_source = Path(__file__).read_text(encoding="utf-8")
    runtime_source = (ROOT / "qntyspot/accepted_execution_intent_publication.py").read_text(
        encoding="utf-8"
    )
    forbidden = (
        "Ed25519" + "PrivateKey",
        "from_" + "private_bytes",
        ".si" + "gn(",
    )
    for token in forbidden:
        assert token not in test_source
        assert token not in runtime_source


def test_publication_verifier_has_no_issuer_or_economic_authority_dependency() -> None:
    source = (ROOT / "qntyspot/accepted_execution_intent_publication.py").read_text(
        encoding="utf-8"
    )
    assert "from .authority_root" not in source
    assert "import authority_root" not in source
    assert "os.environ" not in source
    assert "getenv(" not in source
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source
