"""Authenticate Qnty accepted-intent V2 publication origin without granting authority.

This module is deliberately separate from the economic authority-root contract.
It verifies a domain-separated Ed25519 publication receipt against an explicit
operator-supplied publication trust root. Successful verification proves that
the exact accepted-intent bytes were signed by that publication root; it does
not grant policy, execution, signing, submission, venue, network, or capital
authority.

The module never issues receipts, loads private keys, reads ambient trust from
environment variables, or imports Qnty/QntyLab runtime code.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .accepted_execution_intent_v2 import (
    ACCEPTED_INTENT_SCHEMA_NAME,
    ACCEPTED_INTENT_SCHEMA_VERSION,
    QNTY_REPOSITORY,
    consume_accepted_execution_intent_v2,
)
from .canon import canonical_json_bytes, sha256_hex, strict_json_loads
from .errors import CanonicalFormError

__all__ = [
    "PUBLICATION_AUTH_CONTRACT_VERSION",
    "PUBLICATION_PURPOSE",
    "PUBLICATION_ROOT_ID",
    "PUBLICATION_TRUST_CONFIG_SCHEMA",
    "PUBLICATION_RECEIPT_SCHEMA",
    "ED25519_SIGNATURE_ALGORITHM",
    "PublicationAuthenticationError",
    "TrustedQntyPublicationRootV0",
    "QntyPublicationReceiptV0",
    "VerifiedQntyPublicationV0",
    "load_trusted_qnty_publication_root",
    "authenticate_accepted_execution_intent_v2",
]

PUBLICATION_AUTH_CONTRACT_VERSION = "QNTY_ACCEPTED_EXECUTION_INTENT_PUBLICATION_AUTH_V0"
PUBLICATION_PURPOSE = "QNTY_ACCEPTED_INTENT_ORIGIN_AUTHENTICATION_ONLY"
PUBLICATION_ROOT_ID = "qnty-accepted-intent-publication"
PUBLICATION_TRUST_CONFIG_SCHEMA = "qntyspot.qnty_publication_auth.v0.trust_config"
PUBLICATION_RECEIPT_SCHEMA = "qntyspot.qnty_publication_auth.v0.receipt"
PUBLICATION_RECEIPT_ID_SCHEMA = "qntyspot.qnty_publication_auth.v0.receipt_id"
ED25519_SIGNATURE_ALGORITHM = "Ed25519"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
_VERIFIED_TOKEN = object()


class PublicationAuthenticationError(ValueError):
    """Publication authentication failed closed."""


def _sha256_text(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise PublicationAuthenticationError(
            f"{field_name}: expected lowercase 64-character SHA-256 hex"
        )
    return value


def _git_commit(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _GIT_COMMIT_RE.fullmatch(value):
        raise PublicationAuthenticationError(
            f"{field_name}: expected lowercase 40-character Git commit"
        )
    return value


def _positive_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise PublicationAuthenticationError(f"{field_name}: expected positive integer")
    return value


def _non_negative_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise PublicationAuthenticationError(
            f"{field_name}: expected non-negative integer"
        )
    return value


def _read_exact_bytes(value: bytes | str | Path) -> bytes:
    if isinstance(value, Path):
        try:
            return value.read_bytes()
        except OSError as exc:
            raise PublicationAuthenticationError(f"intent input unreadable: {exc}") from exc
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise PublicationAuthenticationError(
        "accepted intent must be UTF-8 JSON bytes, text, or a Path"
    )


@dataclass(frozen=True, slots=True)
class TrustedQntyPublicationRootV0:
    """Explicit external publication trust root; contains public material only."""

    root_id: str
    purpose: str
    signature_algorithm: str
    public_key_fingerprint: str
    minimum_publication_epoch: int
    trust_config_version: int
    trust_config_digest: str
    anchor_bytes: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.root_id != PUBLICATION_ROOT_ID:
            raise PublicationAuthenticationError("unexpected publication root_id")
        if self.purpose != PUBLICATION_PURPOSE:
            raise PublicationAuthenticationError("unexpected publication root purpose")
        if self.signature_algorithm != ED25519_SIGNATURE_ALGORITHM:
            raise PublicationAuthenticationError("publication root must use Ed25519")
        _sha256_text(
            self.public_key_fingerprint, field_name="public_key_fingerprint"
        )
        if type(self.anchor_bytes) is not bytes or len(self.anchor_bytes) != 32:
            raise PublicationAuthenticationError(
                "publication anchor_bytes must be exactly 32 public-key bytes"
            )
        if sha256_hex(self.anchor_bytes) != self.public_key_fingerprint:
            raise PublicationAuthenticationError(
                "publication public-key fingerprint does not match anchor bytes"
            )
        _positive_int(
            self.minimum_publication_epoch, field_name="minimum_publication_epoch"
        )
        _positive_int(self.trust_config_version, field_name="trust_config_version")
        _sha256_text(self.trust_config_digest, field_name="trust_config_digest")
        if sha256_hex(canonical_json_bytes(self.canonical_object())) != self.trust_config_digest:
            raise PublicationAuthenticationError(
                "trust_config_digest does not bind publication root configuration"
            )

    def canonical_object(self) -> dict[str, Any]:
        return {
            "minimum_publication_epoch": self.minimum_publication_epoch,
            "public_key_fingerprint": self.public_key_fingerprint,
            "purpose": self.purpose,
            "root_id": self.root_id,
            "schema": PUBLICATION_TRUST_CONFIG_SCHEMA,
            "signature_algorithm": self.signature_algorithm,
            "trust_config_version": self.trust_config_version,
        }


def load_trusted_qnty_publication_root(
    config_bytes: bytes,
    *,
    expected_config_digest: str,
    anchor_bytes: bytes,
) -> TrustedQntyPublicationRootV0:
    """Load canonical, digest-pinned publication trust supplied explicitly."""

    if type(config_bytes) is not bytes:
        raise PublicationAuthenticationError(
            "publication trust configuration must be explicit bytes"
        )
    _sha256_text(expected_config_digest, field_name="expected_config_digest")
    if sha256_hex(config_bytes) != expected_config_digest:
        raise PublicationAuthenticationError(
            "publication trust configuration digest mismatch"
        )
    try:
        document = strict_json_loads(config_bytes)
    except (CanonicalFormError, TypeError, ValueError) as exc:
        raise PublicationAuthenticationError(
            f"malformed publication trust configuration: {exc}"
        ) from exc
    expected_fields = {
        "minimum_publication_epoch",
        "public_key_fingerprint",
        "purpose",
        "root_id",
        "schema",
        "signature_algorithm",
        "trust_config_version",
    }
    if type(document) is not dict or set(document) != expected_fields:
        raise PublicationAuthenticationError(
            "publication trust configuration has unknown or missing fields"
        )
    if canonical_json_bytes(document) != config_bytes:
        raise PublicationAuthenticationError(
            "publication trust configuration is not canonical JSON"
        )
    if document["schema"] != PUBLICATION_TRUST_CONFIG_SCHEMA:
        raise PublicationAuthenticationError(
            "unknown publication trust configuration schema"
        )
    return TrustedQntyPublicationRootV0(
        root_id=document["root_id"],
        purpose=document["purpose"],
        signature_algorithm=document["signature_algorithm"],
        public_key_fingerprint=document["public_key_fingerprint"],
        minimum_publication_epoch=document["minimum_publication_epoch"],
        trust_config_version=document["trust_config_version"],
        trust_config_digest=expected_config_digest,
        anchor_bytes=anchor_bytes,
    )


@dataclass(frozen=True, slots=True)
class QntyPublicationReceiptV0:
    """Externally issued signature binding exact Qnty accepted-intent bytes."""

    root_id: str
    purpose: str
    public_key_fingerprint: str
    signature_algorithm: str
    publication_epoch: int
    serial: int
    published_at_epoch_s: int
    qnty_repository: str
    qnty_repository_commit: str
    accepted_intent_schema_name: str
    accepted_intent_schema_version: str
    intent_digest: str
    artifact_sha256: str
    signature: bytes
    schema: str = PUBLICATION_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if self.root_id != PUBLICATION_ROOT_ID:
            raise PublicationAuthenticationError("unexpected receipt root_id")
        if self.purpose != PUBLICATION_PURPOSE:
            raise PublicationAuthenticationError("unexpected receipt purpose")
        if self.signature_algorithm != ED25519_SIGNATURE_ALGORITHM:
            raise PublicationAuthenticationError("publication receipt must use Ed25519")
        _sha256_text(
            self.public_key_fingerprint, field_name="public_key_fingerprint"
        )
        _positive_int(self.publication_epoch, field_name="publication_epoch")
        _positive_int(self.serial, field_name="serial")
        _non_negative_int(self.published_at_epoch_s, field_name="published_at_epoch_s")
        if self.qnty_repository != QNTY_REPOSITORY:
            raise PublicationAuthenticationError("receipt qnty_repository is not canonical")
        _git_commit(self.qnty_repository_commit, field_name="qnty_repository_commit")
        if self.accepted_intent_schema_name != ACCEPTED_INTENT_SCHEMA_NAME:
            raise PublicationAuthenticationError(
                "receipt accepted_intent_schema_name is not V2"
            )
        if self.accepted_intent_schema_version != ACCEPTED_INTENT_SCHEMA_VERSION:
            raise PublicationAuthenticationError(
                "receipt accepted_intent_schema_version is not V2"
            )
        _sha256_text(self.intent_digest, field_name="intent_digest")
        _sha256_text(self.artifact_sha256, field_name="artifact_sha256")
        if type(self.signature) is not bytes or len(self.signature) != 64:
            raise PublicationAuthenticationError(
                "publication signature must be exactly 64 Ed25519 bytes"
            )
        if self.schema != PUBLICATION_RECEIPT_SCHEMA:
            raise PublicationAuthenticationError("unknown publication receipt schema")

    def signed_body_object(self) -> dict[str, Any]:
        return {
            "accepted_intent_schema_name": self.accepted_intent_schema_name,
            "accepted_intent_schema_version": self.accepted_intent_schema_version,
            "artifact_sha256": self.artifact_sha256,
            "intent_digest": self.intent_digest,
            "publication_epoch": self.publication_epoch,
            "published_at_epoch_s": self.published_at_epoch_s,
            "public_key_fingerprint": self.public_key_fingerprint,
            "purpose": self.purpose,
            "qnty_repository": self.qnty_repository,
            "qnty_repository_commit": self.qnty_repository_commit,
            "root_id": self.root_id,
            "schema": self.schema,
            "serial": self.serial,
            "signature_algorithm": self.signature_algorithm,
        }

    @property
    def signed_body_bytes(self) -> bytes:
        return canonical_json_bytes(self.signed_body_object())

    @property
    def signed_body_digest(self) -> str:
        return sha256_hex(self.signed_body_bytes)

    @property
    def receipt_id(self) -> str:
        return sha256_hex(
            canonical_json_bytes(
                {
                    "public_key_fingerprint": self.public_key_fingerprint,
                    "root_id": self.root_id,
                    "schema": PUBLICATION_RECEIPT_ID_SCHEMA,
                    "signature_digest": sha256_hex(self.signature),
                    "signed_body_digest": self.signed_body_digest,
                }
            )
        )

    def to_object(self) -> dict[str, Any]:
        document = self.signed_body_object()
        document.update(
            {
                "receipt_id": self.receipt_id,
                "signature": self.signature.hex(),
            }
        )
        return document

    @property
    def serialized(self) -> bytes:
        return canonical_json_bytes(self.to_object())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "QntyPublicationReceiptV0":
        if type(raw) is not bytes:
            raise PublicationAuthenticationError(
                "publication receipt must be explicit bytes"
            )
        try:
            document = strict_json_loads(raw)
        except (CanonicalFormError, TypeError, ValueError) as exc:
            raise PublicationAuthenticationError(
                f"malformed publication receipt: {exc}"
            ) from exc
        expected_fields = {
            "accepted_intent_schema_name",
            "accepted_intent_schema_version",
            "artifact_sha256",
            "intent_digest",
            "publication_epoch",
            "published_at_epoch_s",
            "public_key_fingerprint",
            "purpose",
            "qnty_repository",
            "qnty_repository_commit",
            "receipt_id",
            "root_id",
            "schema",
            "serial",
            "signature",
            "signature_algorithm",
        }
        if type(document) is not dict or set(document) != expected_fields:
            raise PublicationAuthenticationError(
                "publication receipt has unknown or missing fields"
            )
        if canonical_json_bytes(document) != raw:
            raise PublicationAuthenticationError(
                "publication receipt is not canonical JSON"
            )
        signature_hex = document["signature"]
        if not isinstance(signature_hex, str) or not _HEX128_RE.fullmatch(signature_hex):
            raise PublicationAuthenticationError(
                "publication signature must be lowercase 64-byte hex"
            )
        receipt = cls(
            root_id=document["root_id"],
            purpose=document["purpose"],
            public_key_fingerprint=document["public_key_fingerprint"],
            signature_algorithm=document["signature_algorithm"],
            publication_epoch=document["publication_epoch"],
            serial=document["serial"],
            published_at_epoch_s=document["published_at_epoch_s"],
            qnty_repository=document["qnty_repository"],
            qnty_repository_commit=document["qnty_repository_commit"],
            accepted_intent_schema_name=document["accepted_intent_schema_name"],
            accepted_intent_schema_version=document["accepted_intent_schema_version"],
            intent_digest=document["intent_digest"],
            artifact_sha256=document["artifact_sha256"],
            signature=bytes.fromhex(signature_hex),
            schema=document["schema"],
        )
        if document["receipt_id"] != receipt.receipt_id:
            raise PublicationAuthenticationError("publication receipt_id mismatch")
        return receipt


@dataclass(frozen=True, slots=True, init=False)
class VerifiedQntyPublicationV0:
    """Opaque verified publication proof produced only by authentication.

    The accepted-intent projection is snapshotted as canonical immutable bytes
    at construction so callers cannot mutate verified semantics after the
    signature boundary has been crossed.
    """

    receipt: QntyPublicationReceiptV0
    trust_config_digest: str
    public_key_fingerprint: str
    exact_artifact_sha256: str
    accepted_intent_projection_bytes: bytes = field(repr=False)

    def __init__(
        self,
        *,
        receipt: QntyPublicationReceiptV0,
        trust_config_digest: str,
        public_key_fingerprint: str,
        exact_artifact_sha256: str,
        accepted_intent_projection: dict[str, Any],
        _construction_token: object,
    ) -> None:
        if _construction_token is not _VERIFIED_TOKEN:
            raise TypeError(
                "VerifiedQntyPublicationV0 is only constructed by authentication"
            )
        if type(accepted_intent_projection) is not dict:
            raise TypeError("accepted_intent_projection must be a dict")
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "trust_config_digest", trust_config_digest)
        object.__setattr__(self, "public_key_fingerprint", public_key_fingerprint)
        object.__setattr__(self, "exact_artifact_sha256", exact_artifact_sha256)
        object.__setattr__(
            self,
            "accepted_intent_projection_bytes",
            canonical_json_bytes(accepted_intent_projection),
        )

    def evidence_object(self) -> dict[str, Any]:
        projection = strict_json_loads(self.accepted_intent_projection_bytes)
        if type(projection) is not dict:  # pragma: no cover - construction invariant
            raise PublicationAuthenticationError(
                "verified accepted-intent projection snapshot is not an object"
            )
        projection["admission"] = {
            **projection["admission"],
            "origin_authentication": "VERIFIED_BY_QNTY_PUBLICATION_ROOT",
            "policy_admission_authorized": "NO",
            "policy_bridge_eligible": "YES",
            "publication_authentication": "VERIFIED",
            "trusted_transport_required": "SATISFIED",
        }
        projection["publication_authentication"] = {
            "contract_version": PUBLICATION_AUTH_CONTRACT_VERSION,
            "exact_artifact_sha256": self.exact_artifact_sha256,
            "publication_epoch": self.receipt.publication_epoch,
            "publication_receipt_id": self.receipt.receipt_id,
            "publication_root_id": self.receipt.root_id,
            "public_key_fingerprint": self.public_key_fingerprint,
            "qnty_repository_commit": self.receipt.qnty_repository_commit,
            "signed_body_digest": self.receipt.signed_body_digest,
            "trust_config_digest": self.trust_config_digest,
        }
        probe = dict(projection)
        probe["decision_digest"] = ""
        projection["decision_digest"] = sha256_hex(canonical_json_bytes(probe))
        return projection


def authenticate_accepted_execution_intent_v2(
    intent: bytes | str | Path,
    *,
    receipt: QntyPublicationReceiptV0 | bytes,
    trusted_root: TrustedQntyPublicationRootV0,
    qntyspot_commit: str,
) -> VerifiedQntyPublicationV0:
    """Authenticate exact V2 bytes without granting downstream policy authority."""

    raw = _read_exact_bytes(intent)
    projection = consume_accepted_execution_intent_v2(
        raw, qntyspot_commit=qntyspot_commit
    )
    try:
        intent_document = strict_json_loads(raw)
    except (CanonicalFormError, TypeError, ValueError) as exc:
        raise PublicationAuthenticationError(
            f"malformed accepted intent during authentication: {exc}"
        ) from exc
    if type(intent_document) is not dict:
        raise PublicationAuthenticationError("accepted intent must be a JSON object")
    if isinstance(receipt, bytes):
        receipt = QntyPublicationReceiptV0.from_bytes(receipt)
    if not isinstance(receipt, QntyPublicationReceiptV0):
        raise PublicationAuthenticationError(
            "receipt is not QntyPublicationReceiptV0"
        )
    if not isinstance(trusted_root, TrustedQntyPublicationRootV0):
        raise PublicationAuthenticationError(
            "trusted_root must be external publication configuration"
        )
    if receipt.root_id != trusted_root.root_id:
        raise PublicationAuthenticationError(
            "publication receipt is signed by a different root identity"
        )
    if receipt.purpose != trusted_root.purpose:
        raise PublicationAuthenticationError(
            "publication receipt purpose differs from trust root"
        )
    if receipt.signature_algorithm != trusted_root.signature_algorithm:
        raise PublicationAuthenticationError(
            "publication receipt signature algorithm differs from trust root"
        )
    if receipt.public_key_fingerprint != trusted_root.public_key_fingerprint:
        raise PublicationAuthenticationError(
            "publication receipt public-key fingerprint differs from trust anchor"
        )
    if receipt.publication_epoch < trusted_root.minimum_publication_epoch:
        raise PublicationAuthenticationError(
            "publication receipt is below the external minimum epoch"
        )
    if receipt.intent_digest != intent_document.get("intent_digest"):
        raise PublicationAuthenticationError(
            "publication receipt intent_digest does not bind accepted intent"
        )
    exact_artifact_sha256 = hashlib.sha256(raw).hexdigest()
    if receipt.artifact_sha256 != exact_artifact_sha256:
        raise PublicationAuthenticationError(
            "publication receipt artifact_sha256 does not bind exact received bytes"
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise PublicationAuthenticationError(
            "Ed25519 publication verifier unavailable; refusing authentication"
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(trusted_root.anchor_bytes).verify(
            receipt.signature,
            receipt.signed_body_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise PublicationAuthenticationError(
            "publication receipt signature is invalid"
        ) from exc
    return VerifiedQntyPublicationV0(
        receipt=receipt,
        trust_config_digest=trusted_root.trust_config_digest,
        public_key_fingerprint=trusted_root.public_key_fingerprint,
        exact_artifact_sha256=exact_artifact_sha256,
        accepted_intent_projection=projection,
        _construction_token=_VERIFIED_TOKEN,
    )
