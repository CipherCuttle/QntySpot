"""The QntySpot external authority-root consumer contract.

This module is deliberately an issuer-free boundary.  QntySpot receives a
serialized receipt and an operator-supplied trust anchor; it never creates a
grant, reads an anchor from ambient process state, or imports an issuer
repository.  The source phase ceiling remains the other half of authority:
the effective level is the intersection of the source ceiling and a
successfully verified receipt.

Ed25519 verification is delegated to the mature ``cryptography`` package when
the verifier is called.  The package is intentionally optional for the
offline core: an unavailable verifier fails closed rather than silently
accepting a receipt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .canon import canonical_json_bytes, digest_object, sha256_hex, strict_json_loads
from .errors import (
    AuthorityCeilingError,
    AuthorityVerificationError,
    CanonicalFormError,
)
from .execution_contract import (
    KILL_SWITCH_PRESERVED_CAPABILITIES,
    LADDER,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    Capability,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    ExecutionSessionV0,
    _assert_authority_session_binding,
)

__all__ = [
    "AUTHORITY_ROOT_CONTRACT_VERSION",
    "AUTHORITY_ROOT_SCHEMA",
    "ED25519_SIGNATURE_ALGORITHM",
    "TRUST_CONFIG_SCHEMA",
    "TrustedAuthorityRootV0",
    "AuthorityIssuancePolicyV0",
    "AuthorityGrantReceiptV0",
    "VerifiedAuthorityGrantV0",
    "load_trusted_authority_root",
    "verify_authority_grant",
    "assert_issuance_request_admissible",
    "effective_authority_level",
    "effective_capabilities",
    "effective_capital_ceilings",
    "assert_effective_capital_within",
]

AUTHORITY_ROOT_CONTRACT_VERSION = "QNTY_SPOT_EXTERNAL_AUTHORITY_ROOT_CONTRACT_V0"
AUTHORITY_ROOT_SCHEMA = "qntyspot.authority_root.v0"
TRUST_CONFIG_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".trust_config"
GRANT_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".grant"
GRANT_ID_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".grant_id"
RECEIPT_ID_SCHEMA = AUTHORITY_ROOT_SCHEMA + ".receipt_id"
ED25519_SIGNATURE_ALGORITHM = "Ed25519"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_PORTABLE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[0-9]+)*$")
_REPOSITORY_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_AUTHORITY_POLICY_SCHEMA = "qntyspot.program_b.v0.authority_policy"
_VERIFIED_TOKEN = object()


def _portable(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _PORTABLE_RE.fullmatch(value) or len(value) > 64:
        raise AuthorityVerificationError(f"{field_name}: non-portable identity")
    return value


def _digest(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
        raise AuthorityVerificationError(f"{field_name}: expected lowercase SHA-256 hex")
    return value


def _positive_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise AuthorityVerificationError(f"{field_name}: expected positive integer")
    return value


def _non_negative_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise AuthorityVerificationError(f"{field_name}: expected non-negative integer")
    return value


def _hex_bytes(value: Any, *, field_name: str, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise AuthorityVerificationError(f"{field_name}: expected {length}-byte lowercase hex")
    if not re.fullmatch(r"[0-9a-f]+", value):
        raise AuthorityVerificationError(f"{field_name}: expected lowercase hex")
    return bytes.fromhex(value)


def _canonical_atomic(value: Any, *, field_name: str, positive: bool) -> int:
    if not isinstance(value, str):
        raise AuthorityVerificationError(f"{field_name}: atomic amount must be a string")
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise AuthorityVerificationError(f"{field_name}: non-canonical atomic amount")
    amount = int(value)
    if positive and amount <= 0:
        raise AuthorityVerificationError(f"{field_name}: expected positive atomic amount")
    return amount


@dataclass(frozen=True, slots=True)
class TrustedAuthorityRootV0:
    """An external trust configuration plus its explicitly supplied anchor.

    ``anchor_bytes`` is public verification material, not an issuer secret.
    It is deliberately not part of the serialized config object: the config
    supplies its SHA-256 fingerprint and the operator supplies these bytes at
    the same explicit boundary.  A source edit cannot replace this object
    unless deployment configuration is also changed.
    """

    root_id: str
    signature_algorithm: str
    public_key_fingerprint: str
    minimum_authority_epoch: int
    trust_config_version: int
    trust_config_digest: str
    anchor_bytes: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _portable(self.root_id, field_name="root_id")
        if self.signature_algorithm != ED25519_SIGNATURE_ALGORITHM:
            raise AuthorityVerificationError("signature_algorithm must be Ed25519")
        _digest(self.public_key_fingerprint, field_name="public_key_fingerprint")
        if type(self.anchor_bytes) is not bytes or len(self.anchor_bytes) != 32:
            raise AuthorityVerificationError("anchor_bytes must be exactly 32 public-key bytes")
        if sha256_hex(self.anchor_bytes) != self.public_key_fingerprint:
            raise AuthorityVerificationError("public-key fingerprint does not match anchor bytes")
        _positive_int(self.minimum_authority_epoch, field_name="minimum_authority_epoch")
        _positive_int(self.trust_config_version, field_name="trust_config_version")
        _digest(self.trust_config_digest, field_name="trust_config_digest")
        if sha256_hex(canonical_json_bytes(self.canonical_object())) != self.trust_config_digest:
            raise AuthorityVerificationError("trust_config_digest does not bind root configuration")

    def canonical_object(self) -> dict[str, Any]:
        """The exact operator-config object whose bytes are digest-pinned."""
        return {
            "minimum_authority_epoch": self.minimum_authority_epoch,
            "public_key_fingerprint": self.public_key_fingerprint,
            "root_id": self.root_id,
            "schema": TRUST_CONFIG_SCHEMA,
            "signature_algorithm": self.signature_algorithm,
            "trust_config_version": self.trust_config_version,
        }


@dataclass(frozen=True, slots=True)
class AuthorityIssuancePolicyV0:
    """A future issuer-policy seam; this consumer never issues receipts."""

    root_id: str
    repository_identity: str
    maximum_issuable_level: AuthorityLevel
    allowed_network_ids: tuple[str, ...]
    allowed_taker_addresses: tuple[str, ...]
    allowed_venue_ids: tuple[str, ...]
    max_reservation_atomic: int
    max_cumulative_atomic: int
    max_grant_duration_s: int
    schema: str = AUTHORITY_ROOT_SCHEMA + ".issuance_policy"

    def __post_init__(self) -> None:
        _portable(self.root_id, field_name="root_id")
        repository_parts = (
            self.repository_identity.split("/")
            if isinstance(self.repository_identity, str)
            else []
        )
        if (
            len(repository_parts) != 2
            or not all(_REPOSITORY_PART_RE.fullmatch(part or "") for part in repository_parts)
            or self.repository_identity.strip() != self.repository_identity
        ):
            raise AuthorityVerificationError("repository_identity must be an explicit owner/name")
        if not isinstance(self.maximum_issuable_level, AuthorityLevel):
            raise AuthorityVerificationError("maximum_issuable_level is not an AuthorityLevel")
        for field_name, values in (
            ("allowed_network_ids", self.allowed_network_ids),
            ("allowed_taker_addresses", self.allowed_taker_addresses),
            ("allowed_venue_ids", self.allowed_venue_ids),
        ):
            if type(values) is not tuple or not values:
                raise AuthorityVerificationError(f"{field_name} must be a non-empty tuple")
            for value in values:
                if not isinstance(value, str) or value in {"*", "latest", "any"}:
                    raise AuthorityVerificationError(f"{field_name} contains a wildcard")
        _positive_int(self.max_reservation_atomic, field_name="max_reservation_atomic")
        _positive_int(self.max_cumulative_atomic, field_name="max_cumulative_atomic")
        if self.max_reservation_atomic > self.max_cumulative_atomic:
            raise AuthorityVerificationError("issuance per-action ceiling exceeds cumulative ceiling")
        _positive_int(self.max_grant_duration_s, field_name="max_grant_duration_s")
        if self.schema != AUTHORITY_ROOT_SCHEMA + ".issuance_policy":
            raise AuthorityVerificationError("unknown issuance policy schema")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "allowed_network_ids": sorted(self.allowed_network_ids),
            "allowed_taker_addresses": sorted(self.allowed_taker_addresses),
            "allowed_venue_ids": sorted(self.allowed_venue_ids),
            "max_cumulative_atomic": str(self.max_cumulative_atomic),
            "max_grant_duration_s": self.max_grant_duration_s,
            "max_reservation_atomic": str(self.max_reservation_atomic),
            "maximum_issuable_level": int(self.maximum_issuable_level),
            "repository_identity": self.repository_identity,
            "root_id": self.root_id,
            "schema": self.schema,
        }


def assert_issuance_request_admissible(
    policy: AuthorityIssuancePolicyV0,
    request: AuthorityPolicyRefV0,
    *,
    repository_identity: str,
) -> None:
    """Validate a future issuer request without issuing anything."""
    if not isinstance(policy, AuthorityIssuancePolicyV0):
        raise AuthorityVerificationError("issuance policy is not AuthorityIssuancePolicyV0")
    if not isinstance(request, AuthorityPolicyRefV0):
        raise AuthorityVerificationError("issuance request is not AuthorityPolicyRefV0")
    if repository_identity != policy.repository_identity:
        raise AuthorityVerificationError("issuance request targets a different repository")
    if request.authority_root_id != policy.root_id:
        raise AuthorityVerificationError("issuance request targets a different root")
    if request.granted_level > policy.maximum_issuable_level:
        raise AuthorityVerificationError("issuance level exceeds issuer policy")
    if request.permitted_network_id not in policy.allowed_network_ids:
        raise AuthorityVerificationError("issuance network is not allowed")
    if request.permitted_taker_address not in policy.allowed_taker_addresses:
        raise AuthorityVerificationError("issuance taker is not allowed")
    if request.permitted_venue_id not in policy.allowed_venue_ids:
        raise AuthorityVerificationError("issuance venue is not allowed")
    if request.max_reservation_atomic > policy.max_reservation_atomic:
        raise AuthorityVerificationError("issuance reservation ceiling exceeds issuer policy")
    if request.max_cumulative_atomic > policy.max_cumulative_atomic:
        raise AuthorityVerificationError("issuance cumulative ceiling exceeds issuer policy")
    if request.not_after_epoch_s - request.not_before_epoch_s > policy.max_grant_duration_s:
        raise AuthorityVerificationError("issuance duration exceeds issuer policy")


def load_trusted_authority_root(
    config_bytes: bytes,
    *,
    expected_config_digest: str,
    anchor_bytes: bytes,
) -> TrustedAuthorityRootV0:
    """Load an explicit, canonical, digest-pinned operator configuration.

    No filesystem or environment access occurs here.  The caller supplies
    both the config bytes and the independently obtained expected digest.
    """
    if type(config_bytes) is not bytes:
        raise AuthorityVerificationError("trust configuration must be explicit bytes")
    _digest(expected_config_digest, field_name="expected_config_digest")
    if sha256_hex(config_bytes) != expected_config_digest:
        raise AuthorityVerificationError("external trust configuration digest mismatch")
    try:
        document = strict_json_loads(config_bytes)
        if type(document) is not dict:
            raise AuthorityVerificationError("trust configuration must be a JSON object")
        expected_fields = {
            "minimum_authority_epoch",
            "public_key_fingerprint",
            "root_id",
            "schema",
            "signature_algorithm",
            "trust_config_version",
        }
        if set(document) != expected_fields:
            raise AuthorityVerificationError("trust configuration has unknown or missing fields")
        if canonical_json_bytes(document) != config_bytes:
            raise AuthorityVerificationError("trust configuration is not canonical JSON")
        if document["schema"] != TRUST_CONFIG_SCHEMA:
            raise AuthorityVerificationError("unknown trust configuration schema")
        return TrustedAuthorityRootV0(
            root_id=document["root_id"],
            signature_algorithm=document["signature_algorithm"],
            public_key_fingerprint=document["public_key_fingerprint"],
            minimum_authority_epoch=document["minimum_authority_epoch"],
            trust_config_version=document["trust_config_version"],
            trust_config_digest=expected_config_digest,
            anchor_bytes=anchor_bytes,
        )
    except (AuthorityVerificationError, CanonicalFormError, TypeError, ValueError) as exc:
        if isinstance(exc, AuthorityVerificationError):
            raise
        raise AuthorityVerificationError(f"malformed trust configuration: {exc}") from exc


@dataclass(frozen=True, slots=True)
class AuthorityGrantReceiptV0:
    """A complete externally issued grant, without any private material."""

    root_id: str
    public_key_fingerprint: str
    signature_algorithm: str
    authority_epoch: int
    serial: int
    issued_at_epoch_s: int
    authority_policy: AuthorityPolicyRefV0
    signature: bytes
    schema: str = GRANT_SCHEMA

    def __post_init__(self) -> None:
        _portable(self.root_id, field_name="root_id")
        _digest(self.public_key_fingerprint, field_name="public_key_fingerprint")
        if self.signature_algorithm != ED25519_SIGNATURE_ALGORITHM:
            raise AuthorityVerificationError("signature_algorithm must be Ed25519")
        _positive_int(self.authority_epoch, field_name="authority_epoch")
        _positive_int(self.serial, field_name="serial")
        _non_negative_int(self.issued_at_epoch_s, field_name="issued_at_epoch_s")
        if not isinstance(self.authority_policy, AuthorityPolicyRefV0):
            raise AuthorityVerificationError("authority_policy must be AuthorityPolicyRefV0")
        if self.authority_policy.schema != _AUTHORITY_POLICY_SCHEMA:
            raise AuthorityVerificationError("unknown authority policy schema")
        if self.authority_policy.authority_root_id != self.root_id:
            raise AuthorityVerificationError("receipt root_id disagrees with authority policy")
        if self.authority_policy.permitted_network_id == "*":
            raise AuthorityVerificationError("wildcard network grants are forbidden")
        if type(self.signature) is not bytes or len(self.signature) != 64:
            raise AuthorityVerificationError("signature must be exactly 64 Ed25519 bytes")
        if self.schema != GRANT_SCHEMA:
            raise AuthorityVerificationError("unknown authority grant schema")

    @property
    def authority_policy_digest(self) -> str:
        return self.authority_policy.authority_policy_digest

    @property
    def grant_id(self) -> str:
        """Stable grant identity; it intentionally excludes issuance time."""
        return digest_object(
            {
                "authority_epoch": self.authority_epoch,
                "authority_policy_digest": self.authority_policy_digest,
                "root_id": self.root_id,
                "schema": GRANT_ID_SCHEMA,
                "serial": self.serial,
            }
        )

    def signed_body_object(self) -> dict[str, Any]:
        return {
            "authority_epoch": self.authority_epoch,
            "authority_policy": self.authority_policy.canonical_object(),
            "authority_policy_digest": self.authority_policy_digest,
            "grant_id": self.grant_id,
            "issued_at_epoch_s": self.issued_at_epoch_s,
            "public_key_fingerprint": self.public_key_fingerprint,
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
        """Stable receipt identity with no circular dependency on itself."""
        return digest_object(
            {
                "grant_id": self.grant_id,
                "public_key_fingerprint": self.public_key_fingerprint,
                "root_id": self.root_id,
                "schema": RECEIPT_ID_SCHEMA,
                "signature_algorithm": self.signature_algorithm,
                "signature_digest": sha256_hex(self.signature),
                "signed_body_digest": self.signed_body_digest,
            }
        )

    def to_object(self) -> dict[str, Any]:
        document = self.signed_body_object()
        document.update({"receipt_id": self.receipt_id, "signature": self.signature.hex()})
        return document

    @property
    def serialized(self) -> bytes:
        return canonical_json_bytes(self.to_object())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AuthorityGrantReceiptV0":
        if type(raw) is not bytes:
            raise AuthorityVerificationError("authority receipt must be explicit bytes")
        try:
            document = strict_json_loads(raw)
            if type(document) is not dict:
                raise AuthorityVerificationError("authority receipt must be a JSON object")
            expected_fields = {
                "authority_epoch",
                "authority_policy",
                "authority_policy_digest",
                "grant_id",
                "issued_at_epoch_s",
                "public_key_fingerprint",
                "receipt_id",
                "root_id",
                "schema",
                "serial",
                "signature",
                "signature_algorithm",
            }
            if set(document) != expected_fields:
                raise AuthorityVerificationError("authority receipt has unknown or missing fields")
            if canonical_json_bytes(document) != raw:
                raise AuthorityVerificationError("authority receipt is not canonical JSON")
            policy = _authority_policy_from_object(document["authority_policy"])
            signature = _hex_bytes(document["signature"], field_name="signature", length=64)
            receipt = cls(
                root_id=document["root_id"],
                public_key_fingerprint=document["public_key_fingerprint"],
                signature_algorithm=document["signature_algorithm"],
                authority_epoch=document["authority_epoch"],
                serial=document["serial"],
                issued_at_epoch_s=document["issued_at_epoch_s"],
                authority_policy=policy,
                signature=signature,
                schema=document["schema"],
            )
            if document["authority_policy_digest"] != receipt.authority_policy_digest:
                raise AuthorityVerificationError("authority policy digest mismatch")
            if document["grant_id"] != receipt.grant_id:
                raise AuthorityVerificationError("grant identity mismatch")
            if document["receipt_id"] != receipt.receipt_id:
                raise AuthorityVerificationError("receipt identity mismatch")
            return receipt
        except (AuthorityVerificationError, CanonicalFormError, TypeError, ValueError) as exc:
            if isinstance(exc, AuthorityVerificationError):
                raise
            raise AuthorityVerificationError(f"malformed authority receipt: {exc}") from exc


def _authority_policy_from_object(document: Any) -> AuthorityPolicyRefV0:
    if type(document) is not dict:
        raise AuthorityVerificationError("authority_policy must be a JSON object")
    expected_fields = {
        "authority_root_id",
        "granted_level",
        "max_cumulative_atomic",
        "max_reservation_atomic",
        "not_after_epoch_s",
        "not_before_epoch_s",
        "permitted_implementation_digest",
        "permitted_network_id",
        "permitted_repository_commit",
        "permitted_taker_address",
        "permitted_venue_id",
        "schema",
    }
    if set(document) != expected_fields:
        raise AuthorityVerificationError("authority policy has unknown or missing fields")
    if type(document["granted_level"]) is not int:
        raise AuthorityVerificationError("granted_level must be an integer")
    try:
        level = AuthorityLevel(document["granted_level"])
        return AuthorityPolicyRefV0(
            authority_root_id=document["authority_root_id"],
            granted_level=level,
            permitted_repository_commit=document["permitted_repository_commit"],
            permitted_implementation_digest=document["permitted_implementation_digest"],
            permitted_network_id=document["permitted_network_id"],
            permitted_taker_address=document["permitted_taker_address"],
            permitted_venue_id=document["permitted_venue_id"],
            max_reservation_atomic=_canonical_atomic(
                document["max_reservation_atomic"],
                field_name="max_reservation_atomic",
                positive=True,
            ),
            max_cumulative_atomic=_canonical_atomic(
                document["max_cumulative_atomic"],
                field_name="max_cumulative_atomic",
                positive=True,
            ),
            not_before_epoch_s=document["not_before_epoch_s"],
            not_after_epoch_s=document["not_after_epoch_s"],
            schema=document["schema"],
        )
    except AuthorityVerificationError:
        raise
    except (AuthorityCeilingError, TypeError, ValueError) as exc:
        raise AuthorityVerificationError(f"malformed authority policy: {exc}") from exc


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAuthorityGrantV0:
    """An opaque proof result produced only by :func:`verify_authority_grant`."""

    receipt: AuthorityGrantReceiptV0
    root_id: str
    public_key_fingerprint: str
    trust_config_digest: str
    minimum_authority_epoch: int
    signed_body_digest: str
    receipt_id: str

    def __init__(
        self,
        *,
        receipt: AuthorityGrantReceiptV0,
        root_id: str,
        public_key_fingerprint: str,
        trust_config_digest: str,
        minimum_authority_epoch: int,
        signed_body_digest: str,
        receipt_id: str,
        _construction_token: object,
    ) -> None:
        if _construction_token is not _VERIFIED_TOKEN:
            raise TypeError("VerifiedAuthorityGrantV0 is only constructed by verification")
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "root_id", root_id)
        object.__setattr__(self, "public_key_fingerprint", public_key_fingerprint)
        object.__setattr__(self, "trust_config_digest", trust_config_digest)
        object.__setattr__(self, "minimum_authority_epoch", minimum_authority_epoch)
        object.__setattr__(self, "signed_body_digest", signed_body_digest)
        object.__setattr__(self, "receipt_id", receipt_id)

    @property
    def authority_policy(self) -> AuthorityPolicyRefV0:
        return self.receipt.authority_policy


def verify_authority_grant(
    *,
    receipt: AuthorityGrantReceiptV0 | bytes,
    trusted_root: TrustedAuthorityRootV0,
    session: ExecutionSessionV0,
    now_epoch_s: int,
) -> VerifiedAuthorityGrantV0:
    """Verify a receipt against external trust and the exact runtime session."""
    if isinstance(receipt, bytes):
        receipt = AuthorityGrantReceiptV0.from_bytes(receipt)
    if not isinstance(receipt, AuthorityGrantReceiptV0):
        raise AuthorityVerificationError("receipt is not an authority grant")
    if not isinstance(trusted_root, TrustedAuthorityRootV0):
        raise AuthorityVerificationError("trusted_root must be external configuration")
    if not isinstance(session, ExecutionSessionV0):
        raise AuthorityVerificationError("session must be ExecutionSessionV0")
    if receipt.root_id != trusted_root.root_id:
        raise AuthorityVerificationError("receipt is signed by a different root identity")
    if receipt.signature_algorithm != trusted_root.signature_algorithm:
        raise AuthorityVerificationError("receipt uses a different signature algorithm")
    if receipt.public_key_fingerprint != trusted_root.public_key_fingerprint:
        raise AuthorityVerificationError("receipt public-key fingerprint differs from trust anchor")
    if receipt.authority_epoch < trusted_root.minimum_authority_epoch:
        raise AuthorityVerificationError("authority receipt is below the external minimum epoch")
    try:
        _assert_authority_session_binding(
            session,
            receipt.authority_policy,
            now_epoch_s=now_epoch_s,
            error=AuthorityVerificationError,
        )
    except AuthorityVerificationError:
        raise
    except (AuthorityCeilingError, TypeError, ValueError) as exc:
        raise AuthorityVerificationError(f"authority/session binding failed: {exc}") from exc
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise AuthorityVerificationError("Ed25519 verifier is unavailable; refusing authority") from exc
    try:
        Ed25519PublicKey.from_public_bytes(trusted_root.anchor_bytes).verify(
            receipt.signature,
            receipt.signed_body_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthorityVerificationError("authority receipt signature is invalid") from exc
    return VerifiedAuthorityGrantV0(
        receipt=receipt,
        root_id=trusted_root.root_id,
        public_key_fingerprint=trusted_root.public_key_fingerprint,
        trust_config_digest=trusted_root.trust_config_digest,
        minimum_authority_epoch=trusted_root.minimum_authority_epoch,
        signed_body_digest=receipt.signed_body_digest,
        receipt_id=receipt.receipt_id,
        _construction_token=_VERIFIED_TOKEN,
    )


def _require_verified(grant: Any) -> VerifiedAuthorityGrantV0:
    if not isinstance(grant, VerifiedAuthorityGrantV0):
        raise AuthorityVerificationError("effective authority requires a verified grant")
    return grant


def effective_authority_level(
    *,
    source_phase_ceiling: AuthorityLevel,
    verified_grant: VerifiedAuthorityGrantV0,
) -> AuthorityLevel:
    """Apply the two independent authority gates by intersection."""
    grant = _require_verified(verified_grant)
    if not isinstance(source_phase_ceiling, AuthorityLevel):
        raise AuthorityCeilingError("source_phase_ceiling is not an AuthorityLevel")
    if source_phase_ceiling > PHASE_GRANTED_AUTHORITY_LEVEL:
        raise AuthorityCeilingError(
            "source_phase_ceiling exceeds the current reviewed phase ceiling"
        )
    return min(source_phase_ceiling, grant.authority_policy.granted_level)


def effective_capabilities(
    *,
    source_phase_ceiling: AuthorityLevel,
    verified_grant: VerifiedAuthorityGrantV0,
    kill_switch: bool = False,
    safe_halt: bool = False,
) -> frozenset[Capability]:
    """Return capabilities only after both source and external gates agree."""
    level = effective_authority_level(
        source_phase_ceiling=source_phase_ceiling,
        verified_grant=verified_grant,
    )
    capabilities = LADDER[level]
    if kill_switch or safe_halt:
        capabilities &= KILL_SWITCH_PRESERVED_CAPABILITIES
    return frozenset(capabilities)


def effective_capital_ceilings(
    *,
    local_per_action_atomic: int,
    local_cumulative_atomic: int,
    verified_grant: VerifiedAuthorityGrantV0,
) -> tuple[int, int]:
    """Intersect local policy ceilings with the external upper bound."""
    grant = _require_verified(verified_grant)
    _positive_int(local_per_action_atomic, field_name="local_per_action_atomic")
    _positive_int(local_cumulative_atomic, field_name="local_cumulative_atomic")
    if local_per_action_atomic > local_cumulative_atomic:
        raise AuthorityVerificationError("local per-action ceiling exceeds cumulative ceiling")
    policy = grant.authority_policy
    return (
        min(local_per_action_atomic, policy.max_reservation_atomic),
        min(local_cumulative_atomic, policy.max_cumulative_atomic),
    )


def assert_effective_capital_within(
    *,
    requested_atomic: int,
    held_atomic: int,
    local_per_action_atomic: int,
    local_cumulative_atomic: int,
    verified_grant: VerifiedAuthorityGrantV0,
) -> None:
    """Reject an action outside the intersection of local and external caps."""
    if type(requested_atomic) is not int or requested_atomic <= 0:
        raise AuthorityCeilingError("requested_atomic must be a positive integer")
    if type(held_atomic) is not int or held_atomic < 0:
        raise AuthorityCeilingError("held_atomic must be a non-negative integer")
    per_action, cumulative = effective_capital_ceilings(
        local_per_action_atomic=local_per_action_atomic,
        local_cumulative_atomic=local_cumulative_atomic,
        verified_grant=verified_grant,
    )
    if requested_atomic > per_action:
        raise AuthorityCeilingError("requested capital exceeds the effective per-action ceiling")
    if held_atomic + requested_atomic > cumulative:
        raise AuthorityCeilingError("requested capital exceeds the effective cumulative ceiling")
