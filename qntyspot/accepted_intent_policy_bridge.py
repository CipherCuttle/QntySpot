"""Bridge authenticated Qnty target changes into policy-evaluation requests only.

This module is deliberately narrower than policy admission and execution. Its
only admissible input is an opaque ``VerifiedQntyPublicationV0`` produced by
the publication-authentication boundary. A verified NO_ACTION remains inert.
A verified TARGET_CHANGE may produce one deterministic, immutable request for
an independently governed policy layer to evaluate.

The request carries no instrument, venue, amount, price, slippage, transaction,
network destination, signing, submission, or capital parameters. It cannot
construct or parse PolicyV0 and it grants no economic authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .accepted_execution_intent_publication import VerifiedQntyPublicationV0
from .canon import canonical_json_bytes, sha256_hex

__all__ = [
    "POLICY_BRIDGE_CONTRACT_VERSION",
    "POLICY_EVALUATION_REQUEST_SCHEMA",
    "PolicyBridgeError",
    "AcceptedIntentPolicyEvaluationRequestV0",
    "bridge_authenticated_intent_to_policy_request",
]

POLICY_BRIDGE_CONTRACT_VERSION = "QNTYSPOT_AUTHENTICATED_ACCEPTED_INTENT_POLICY_BRIDGE_V0"
POLICY_EVALUATION_REQUEST_SCHEMA = "qntyspot.accepted_intent_policy_evaluation_request.v0"
_POLICY_EVALUATION_REQUEST_ID_SCHEMA = POLICY_EVALUATION_REQUEST_SCHEMA + ".request_id"
_REQUEST_TOKEN = object()
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class PolicyBridgeError(ValueError):
    """Authenticated accepted-intent policy bridging failed closed."""


def _required_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise PolicyBridgeError(f"{field}: expected non-empty canonical text")
    return value


def _digest(value: Any, *, field: str) -> str:
    text = _required_text(value, field=field)
    if not _SHA256_RE.fullmatch(text):
        raise PolicyBridgeError(f"{field}: expected lowercase SHA-256 hex")
    return text


def _commit(value: Any, *, field: str) -> str:
    text = _required_text(value, field=field)
    if not _COMMIT_RE.fullmatch(text):
        raise PolicyBridgeError(f"{field}: expected lowercase 40-character Git commit")
    return text


@dataclass(frozen=True, slots=True, init=False)
class AcceptedIntentPolicyEvaluationRequestV0:
    """Opaque request for policy evaluation, not an execution authorization."""

    publication_receipt_id: str
    publication_signed_body_digest: str
    publication_trust_config_digest: str
    source_intent_digest: str
    qnty_repository_commit: str
    qntyspot_repository_commit: str
    qntyspot_implementation_version: str
    effective_source_timestamp: str
    previous_target: str
    current_target: str
    transition: str
    request_id: str

    def __init__(
        self,
        *,
        publication_receipt_id: str,
        publication_signed_body_digest: str,
        publication_trust_config_digest: str,
        source_intent_digest: str,
        qnty_repository_commit: str,
        qntyspot_repository_commit: str,
        qntyspot_implementation_version: str,
        effective_source_timestamp: str,
        previous_target: str,
        current_target: str,
        transition: str,
        request_id: str,
        _construction_token: object,
    ) -> None:
        if _construction_token is not _REQUEST_TOKEN:
            raise TypeError(
                "AcceptedIntentPolicyEvaluationRequestV0 is only constructed by the authenticated bridge"
            )
        for field_name, value in (
            ("publication_receipt_id", publication_receipt_id),
            ("publication_signed_body_digest", publication_signed_body_digest),
            ("publication_trust_config_digest", publication_trust_config_digest),
            ("source_intent_digest", source_intent_digest),
            ("request_id", request_id),
        ):
            _digest(value, field=field_name)
        _commit(qnty_repository_commit, field="qnty_repository_commit")
        _commit(qntyspot_repository_commit, field="qntyspot_repository_commit")
        _required_text(qntyspot_implementation_version, field="qntyspot_implementation_version")
        _required_text(effective_source_timestamp, field="effective_source_timestamp")
        if previous_target not in {"FLAT", "LONG"} or current_target not in {"FLAT", "LONG"}:
            raise PolicyBridgeError("targets must be FLAT or LONG")
        if previous_target == current_target:
            raise PolicyBridgeError("policy-evaluation request requires an actual target change")
        if transition != "TARGET_CHANGE":
            raise PolicyBridgeError("policy-evaluation request transition must be TARGET_CHANGE")
        object.__setattr__(self, "publication_receipt_id", publication_receipt_id)
        object.__setattr__(self, "publication_signed_body_digest", publication_signed_body_digest)
        object.__setattr__(self, "publication_trust_config_digest", publication_trust_config_digest)
        object.__setattr__(self, "source_intent_digest", source_intent_digest)
        object.__setattr__(self, "qnty_repository_commit", qnty_repository_commit)
        object.__setattr__(self, "qntyspot_repository_commit", qntyspot_repository_commit)
        object.__setattr__(self, "qntyspot_implementation_version", qntyspot_implementation_version)
        object.__setattr__(self, "effective_source_timestamp", effective_source_timestamp)
        object.__setattr__(self, "previous_target", previous_target)
        object.__setattr__(self, "current_target", current_target)
        object.__setattr__(self, "transition", transition)
        object.__setattr__(self, "request_id", request_id)

    def to_object(self) -> dict[str, Any]:
        return {
            "authority": {
                "capital_authorized": "NO",
                "economic_action_authorized": "NO",
                "network_authorized": "NO",
                "signing_authorized": "NO",
                "submission_authorized": "NO",
            },
            "contract_version": POLICY_BRIDGE_CONTRACT_VERSION,
            "decision": {
                "current_target": self.current_target,
                "effective_source_timestamp": self.effective_source_timestamp,
                "previous_target": self.previous_target,
                "transition": self.transition,
            },
            "policy": {
                "binding_status": "UNBOUND",
                "evaluation_requested": "YES",
                "independent_policy_binding_required": "YES",
                "policy_admission_authorized": "NO",
            },
            "provenance": {
                "publication_receipt_id": self.publication_receipt_id,
                "publication_signed_body_digest": self.publication_signed_body_digest,
                "publication_trust_config_digest": self.publication_trust_config_digest,
                "qnty_repository_commit": self.qnty_repository_commit,
                "qntyspot_implementation_version": self.qntyspot_implementation_version,
                "qntyspot_repository_commit": self.qntyspot_repository_commit,
                "source_intent_digest": self.source_intent_digest,
            },
            "request_id": self.request_id,
            "schema": POLICY_EVALUATION_REQUEST_SCHEMA,
        }

    @property
    def serialized(self) -> bytes:
        return canonical_json_bytes(self.to_object())


def _request_id(
    *,
    publication_receipt_id: str,
    publication_signed_body_digest: str,
    publication_trust_config_digest: str,
    source_intent_digest: str,
    qnty_repository_commit: str,
    qntyspot_repository_commit: str,
    qntyspot_implementation_version: str,
    effective_source_timestamp: str,
    previous_target: str,
    current_target: str,
) -> str:
    return sha256_hex(
        canonical_json_bytes(
            {
                "current_target": current_target,
                "effective_source_timestamp": effective_source_timestamp,
                "previous_target": previous_target,
                "publication_receipt_id": publication_receipt_id,
                "publication_signed_body_digest": publication_signed_body_digest,
                "publication_trust_config_digest": publication_trust_config_digest,
                "qnty_repository_commit": qnty_repository_commit,
                "qntyspot_implementation_version": qntyspot_implementation_version,
                "qntyspot_repository_commit": qntyspot_repository_commit,
                "schema": _POLICY_EVALUATION_REQUEST_ID_SCHEMA,
                "source_intent_digest": source_intent_digest,
                "transition": "TARGET_CHANGE",
            }
        )
    )


def bridge_authenticated_intent_to_policy_request(
    verified: VerifiedQntyPublicationV0,
) -> AcceptedIntentPolicyEvaluationRequestV0 | None:
    """Return a policy-evaluation request only for an authenticated target change."""

    if not isinstance(verified, VerifiedQntyPublicationV0):
        raise PolicyBridgeError(
            "policy bridge requires VerifiedQntyPublicationV0 from publication authentication"
        )
    evidence = verified.evidence_object()
    admission = evidence.get("admission")
    decision = evidence.get("decision")
    projection = evidence.get("projection")
    publication = evidence.get("publication_authentication")
    qntyspot_implementation = evidence.get("qntyspot_implementation")
    if not all(
        isinstance(value, dict)
        for value in (admission, decision, projection, publication, qntyspot_implementation)
    ):
        raise PolicyBridgeError("verified publication evidence has an unexpected shape")
    if admission.get("origin_authentication") != "VERIFIED_BY_QNTY_PUBLICATION_ROOT":
        raise PolicyBridgeError("publication origin is not authenticated")
    if admission.get("publication_authentication") != "VERIFIED":
        raise PolicyBridgeError("publication authentication is not verified")
    if admission.get("policy_bridge_eligible") != "YES":
        raise PolicyBridgeError("verified publication is not policy-bridge eligible")
    if admission.get("policy_admission_authorized") != "NO":
        raise PolicyBridgeError("upstream evidence attempted to pre-authorize policy admission")
    if projection.get("policy_evaluation_required") != "NO":
        raise PolicyBridgeError("upstream projection already attempted to wake policy")
    if projection.get("network_required") != "NO":
        raise PolicyBridgeError("upstream projection attempted to require network activity")
    if projection.get("qntyspot_execution_action_authorized") != "NO":
        raise PolicyBridgeError("upstream projection attempted to authorize execution")
    if projection.get("qntyspot_side") != "NONE":
        raise PolicyBridgeError("upstream projection attempted to select an execution side")

    transition = decision.get("transition")
    upstream_action_required = decision.get("upstream_execution_action_required")
    if transition == "NO_ACTION":
        if upstream_action_required is not False or projection.get("consumer_result") != "NO_ACTION":
            raise PolicyBridgeError("NO_ACTION evidence is internally inconsistent")
        return None
    if transition != "TARGET_CHANGE":
        raise PolicyBridgeError("unknown authenticated intent transition")
    if upstream_action_required is not True:
        raise PolicyBridgeError("TARGET_CHANGE is missing upstream action-required evidence")
    if projection.get("consumer_result") != "TARGET_CHANGE_OBSERVED":
        raise PolicyBridgeError("TARGET_CHANGE projection is internally inconsistent")

    previous_target = decision.get("previous_target")
    current_target = decision.get("current_target")
    effective_source_timestamp = _required_text(
        decision.get("effective_source_timestamp"), field="effective_source_timestamp"
    )
    if previous_target not in {"FLAT", "LONG"} or current_target not in {"FLAT", "LONG"}:
        raise PolicyBridgeError("authenticated decision targets are invalid")
    if previous_target == current_target:
        raise PolicyBridgeError("TARGET_CHANGE did not change the target")

    publication_receipt_id = _digest(
        publication.get("publication_receipt_id"), field="publication_receipt_id"
    )
    publication_signed_body_digest = _digest(
        publication.get("signed_body_digest"), field="publication_signed_body_digest"
    )
    publication_trust_config_digest = _digest(
        publication.get("trust_config_digest"), field="publication_trust_config_digest"
    )
    source_intent_digest = _digest(
        evidence.get("input_intent_digest"), field="source_intent_digest"
    )
    qnty_repository_commit = _commit(
        publication.get("qnty_repository_commit"), field="qnty_repository_commit"
    )
    qntyspot_repository_commit = _commit(
        qntyspot_implementation.get("commit"), field="qntyspot_repository_commit"
    )
    qntyspot_implementation_version = _required_text(
        qntyspot_implementation.get("version"), field="qntyspot_implementation_version"
    )

    request_id = _request_id(
        publication_receipt_id=publication_receipt_id,
        publication_signed_body_digest=publication_signed_body_digest,
        publication_trust_config_digest=publication_trust_config_digest,
        source_intent_digest=source_intent_digest,
        qnty_repository_commit=qnty_repository_commit,
        qntyspot_repository_commit=qntyspot_repository_commit,
        qntyspot_implementation_version=qntyspot_implementation_version,
        effective_source_timestamp=effective_source_timestamp,
        previous_target=previous_target,
        current_target=current_target,
    )
    return AcceptedIntentPolicyEvaluationRequestV0(
        publication_receipt_id=publication_receipt_id,
        publication_signed_body_digest=publication_signed_body_digest,
        publication_trust_config_digest=publication_trust_config_digest,
        source_intent_digest=source_intent_digest,
        qnty_repository_commit=qnty_repository_commit,
        qntyspot_repository_commit=qntyspot_repository_commit,
        qntyspot_implementation_version=qntyspot_implementation_version,
        effective_source_timestamp=effective_source_timestamp,
        previous_target=previous_target,
        current_target=current_target,
        transition="TARGET_CHANGE",
        request_id=request_id,
        _construction_token=_REQUEST_TOKEN,
    )
