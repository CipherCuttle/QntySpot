from __future__ import annotations

import hashlib
from pathlib import Path

from qntyspot.accepted_execution_intent_publication import (
    ED25519_SIGNATURE_ALGORITHM,
    PUBLICATION_PURPOSE,
    PUBLICATION_ROOT_ID,
    PUBLICATION_TRUST_CONFIG_SCHEMA,
    authenticate_accepted_execution_intent_v2,
    load_trusted_qnty_publication_root,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex, strict_json_loads

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "qualifications/h003_bridge_v0"
INTENT = QUALIFICATION / "QNTY_ACCEPTED_EXECUTION_INTENT_V2.json"
RECEIPT = QUALIFICATION / "QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_RECEIPT_V0.json"
RECEIPT_SIDECAR = RECEIPT.with_suffix(".sha256")
SOURCE = QUALIFICATION / "QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_RECEIPT_V0.source.json"

QNTY_FIXTURE_SOURCE_MERGE = "610f66f6c5660e09a6c0560ae1b4262f0bfd5578"
QNTY_DECLARED_INTENT_COMMIT = "2ebed2af94127f2e018de46069d1bbe27178ca8a"
QNTYSPOT_INTEROP_BASE = "0bfec38c0695b002830d52ed4c8968d48bbdfbb9"
EXPECTED_RECEIPT_SHA256 = "9087abfbded6eba0947f29fbbeb005d0f230669f97a3cacd59bbaab689890c8e"
EXPECTED_INTENT_SHA256 = "262f2eeea5c7fea979f1500538ffd146686e9c4ac8069a1ac5ae4d3ae7cd76db"
EXPECTED_RECEIPT_ID = "393a5decca6d325acd72f9016e8004022a6234460007552573ba172983cb1488"
TEST_PUBLIC_KEY_BYTES = bytes.fromhex(
    "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
)


def _trusted_root():
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
    return load_trusted_qnty_publication_root(
        config_bytes,
        expected_config_digest=sha256_hex(config_bytes),
        anchor_bytes=TEST_PUBLIC_KEY_BYTES,
    )


def test_imported_qnty_receipt_has_exact_merged_source_provenance() -> None:
    receipt_bytes = RECEIPT.read_bytes()
    source_bytes = SOURCE.read_bytes()
    source = strict_json_loads(source_bytes)

    assert hashlib.sha256(receipt_bytes).hexdigest() == EXPECTED_RECEIPT_SHA256
    assert RECEIPT_SIDECAR.read_bytes() == (EXPECTED_RECEIPT_SHA256 + "\n").encode("ascii")
    assert canonical_json_bytes(source) == source_bytes
    assert source == {
        "artifact_sha256": EXPECTED_RECEIPT_SHA256,
        "declared_qnty_repository_commit": QNTY_DECLARED_INTENT_COMMIT,
        "schema": "qntyspot.cross_repo_fixture_source.v0",
        "source_merge_commit": QNTY_FIXTURE_SOURCE_MERGE,
        "source_path": "tests/fixtures/QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_RECEIPT_V0.json",
        "source_repository": "CipherCuttle/Qnty",
    }


def test_merged_qnty_receipt_authenticates_in_qntyspot_without_authority() -> None:
    assert hashlib.sha256(INTENT.read_bytes()).hexdigest() == EXPECTED_INTENT_SHA256
    evidence = authenticate_accepted_execution_intent_v2(
        INTENT.read_bytes(),
        receipt=RECEIPT.read_bytes(),
        trusted_root=_trusted_root(),
        qntyspot_commit=QNTYSPOT_INTEROP_BASE,
    ).evidence_object()

    assert evidence["publication_authentication"]["publication_receipt_id"] == EXPECTED_RECEIPT_ID
    assert evidence["publication_authentication"]["exact_artifact_sha256"] == EXPECTED_INTENT_SHA256
    assert evidence["publication_authentication"]["qnty_repository_commit"] == QNTY_DECLARED_INTENT_COMMIT
    assert evidence["admission"]["origin_authentication"] == "VERIFIED_BY_QNTY_PUBLICATION_ROOT"
    assert evidence["admission"]["publication_authentication"] == "VERIFIED"
    assert evidence["admission"]["policy_bridge_eligible"] == "YES"
    assert evidence["admission"]["policy_admission_authorized"] == "NO"
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
