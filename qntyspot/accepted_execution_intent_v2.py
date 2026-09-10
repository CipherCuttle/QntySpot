"""Fail-closed, non-authoritative consumer for Qnty accepted-intent V2.

The V2 bytes carry a canonical self-digest, not Qnty origin authenticity.
Accordingly this consumer may surface directional semantics but it cannot wake
policy, quote, network, signing, submission, or capital machinery. A separate
authenticated transport/publication boundary is required before any downstream
economic authority can consume a TARGET_CHANGE.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .canon import canonical_json_bytes, sha256_hex, strict_json_loads
from .errors import CanonicalFormError

__all__ = [
    "ACCEPTED_INTENT_SCHEMA_NAME",
    "ACCEPTED_INTENT_SCHEMA_VERSION",
    "QNTY_ACCEPTANCE_SOURCE_COMMIT",
    "QNTY_INTENT_V2_CONTRACT_MERGE",
    "QNTYSPOT_IMPLEMENTATION_VERSION",
    "AcceptedIntentV2Rejected",
    "consume_accepted_execution_intent_v2",
]

ACCEPTED_INTENT_SCHEMA_NAME = "QNTY_ACCEPTED_EXECUTION_INTENT_V2"
ACCEPTED_INTENT_SCHEMA_VERSION = "V2"
DECISION_SCHEMA_NAME = "QNTYSPOT_ACCEPTED_INTENT_DECISION_V2"
DECISION_SCHEMA_VERSION = "V2"

QNTY_REPOSITORY = "CipherCuttle/Qnty"
QNTYLAB_REPOSITORY = "CipherCuttle/QntyLab"
QNTY_ACCEPTANCE_SOURCE_COMMIT = "0cc8fe3b863b2deea548cb01268419c359ff89eb"
QNTY_INTENT_V2_CONTRACT_MERGE = "3cfe0d607920313c8f2ec21e1511a195f5f63d38"
QNTYLAB_SOURCE_COMMIT = "d7ed51f02e2e9a0a5fde74b54f6b8b9174847c7c"
QNTYSPOT_REPOSITORY = "CipherCuttle/QntySpot"
QNTYSPOT_IMPLEMENTATION_VERSION = "QNTYSPOT_ACCEPTED_EXECUTION_INTENT_DYNAMIC_CONSUMER_V2"

AUTHORITY_NONE = {
    "capital": "NONE",
    "execution": "FORBIDDEN",
    "signing": "NONE",
    "submission": "NONE",
}

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_GIT_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")


class AcceptedIntentV2Rejected(ValueError):
    """The external V2 accepted-intent artifact failed closed."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _keys(value: Any, expected: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptedIntentV2Rejected("SCHEMA_INVALID", f"{where} must be an object")
    actual = set(value)
    if actual != expected:
        raise AcceptedIntentV2Rejected(
            "SCHEMA_FIELDS",
            f"{where} keys differ; missing={sorted(expected - actual)} unknown={sorted(actual - expected)}",
        )
    return value


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise AcceptedIntentV2Rejected("VALUE_INVALID", f"{where} must be a string")
    return value


def _sha(value: Any, where: str) -> str:
    text = _text(value, where)
    if not _SHA256.fullmatch(text):
        raise AcceptedIntentV2Rejected("DIGEST_INVALID", f"{where} must be lowercase sha256")
    return text


def _commit(value: Any, where: str) -> str:
    text = _text(value, where)
    if not _GIT_COMMIT.fullmatch(text):
        raise AcceptedIntentV2Rejected("PROVENANCE_INVALID", f"{where} must be a full lowercase git commit")
    return text


def _boolean(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise AcceptedIntentV2Rejected("VALUE_INVALID", f"{where} must be a JSON boolean")
    return value


def _canonical_digest(value: dict[str, Any], field: str) -> str:
    probe = dict(value)
    probe[field] = ""
    return sha256_hex(canonical_json_bytes(probe))


def _read_external_json(value: bytes | str | Path) -> dict[str, Any]:
    if isinstance(value, Path):
        try:
            raw = value.read_bytes()
        except OSError as exc:
            raise AcceptedIntentV2Rejected("INPUT_UNREADABLE", str(exc)) from exc
    elif isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise AcceptedIntentV2Rejected("INPUT_TYPE", "accepted intent must be UTF-8 JSON bytes, text, or a Path")

    try:
        parsed = strict_json_loads(raw)
    except (CanonicalFormError, UnicodeError) as exc:
        raise AcceptedIntentV2Rejected("INPUT_JSON", str(exc)) from exc
    if not isinstance(parsed, dict):
        raise AcceptedIntentV2Rejected("INPUT_SHAPE", "accepted intent must be a JSON object")
    canonical = canonical_json_bytes(parsed)
    if raw not in (canonical, canonical + b"\n"):
        raise AcceptedIntentV2Rejected("NON_CANONICAL_JSON", "accepted intent bytes are not canonical JSON")
    return parsed


def _validate_intent(value: bytes | str | Path) -> dict[str, Any]:
    intent = _read_external_json(value)
    _keys(
        intent,
        {"authority", "decision", "intent_digest", "provenance", "research_identity", "schema_name", "schema_version"},
        "intent",
    )
    if intent["schema_name"] != ACCEPTED_INTENT_SCHEMA_NAME or intent["schema_version"] != ACCEPTED_INTENT_SCHEMA_VERSION:
        raise AcceptedIntentV2Rejected("SCHEMA_INVALID", "schema_name/schema_version is not Qnty accepted-intent V2")

    declared_digest = _sha(intent["intent_digest"], "intent.intent_digest")
    if _canonical_digest(intent, "intent_digest") != declared_digest:
        raise AcceptedIntentV2Rejected("ARTIFACT_DIGEST", "intent digest recomputation failed")

    authority = _keys(intent["authority"], {"capital", "execution", "signing", "submission"}, "intent.authority")
    if authority != AUTHORITY_NONE:
        raise AcceptedIntentV2Rejected("AUTHORITY_ESCALATION", "accepted intent authority is not NONE/FORBIDDEN")

    provenance = _keys(
        intent["provenance"],
        {
            "qnty_acceptance_receipt_digest",
            "qnty_acceptance_record_id",
            "qnty_acceptance_schema",
            "qnty_acceptance_source_commit",
            "qnty_repository",
            "qntylab_repository",
            "qntylab_source_commit",
            "upstream_handoff_digest",
            "upstream_handoff_schema",
        },
        "intent.provenance",
    )
    if provenance["qnty_repository"] != QNTY_REPOSITORY:
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "qnty_repository is not canonical")
    if provenance["qnty_acceptance_source_commit"] != QNTY_ACCEPTANCE_SOURCE_COMMIT:
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "Qnty acceptance source commit is not canonical")
    if provenance["qnty_acceptance_schema"] != "H003_ACCEPTANCE_V0":
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "Qnty acceptance schema is not canonical")
    if provenance["qntylab_repository"] != QNTYLAB_REPOSITORY:
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "qntylab_repository is not canonical")
    if provenance["qntylab_source_commit"] != QNTYLAB_SOURCE_COMMIT:
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "QntyLab source commit is not governed")
    if provenance["upstream_handoff_schema"] != "H003_SIGNAL_INTENT_V0":
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "upstream handoff schema is not canonical")
    _sha(provenance["qnty_acceptance_receipt_digest"], "intent.provenance.qnty_acceptance_receipt_digest")
    handoff_digest = _sha(provenance["upstream_handoff_digest"], "intent.provenance.upstream_handoff_digest")
    record_id = _text(provenance["qnty_acceptance_record_id"], "intent.provenance.qnty_acceptance_record_id")
    if record_id != f"H003_ACCEPTANCE_V0:{handoff_digest}":
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "acceptance record id is not bound to handoff digest")

    identity = _keys(
        intent["research_identity"],
        {"candidate_id", "parameters", "source_semantic", "strategy_id", "variant_id"},
        "intent.research_identity",
    )
    expected_identity = {
        "candidate_id": "CANDIDATE_H003_MA_48_192_LONG_FLAT",
        "source_semantic": "BINANCE_SPOT_SOLUSDT_1H",
        "strategy_id": "H003_moving_average",
        "variant_id": "variant_00eb140f03a5f6ab40600160",
    }
    for field, expected in expected_identity.items():
        if identity[field] != expected:
            raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", f"research_identity.{field} is not governed")
    parameters = _keys(identity["parameters"], {"fast", "mode", "slow"}, "research_identity.parameters")
    if parameters != {"fast": 48, "mode": "long_flat", "slow": 192}:
        raise AcceptedIntentV2Rejected("PROVENANCE_MISMATCH", "H003 parameters are not governed")

    decision = _keys(
        intent["decision"],
        {"current_target", "effective_source_timestamp", "execution_action_required", "previous_target", "transition"},
        "intent.decision",
    )
    if decision["previous_target"] not in {"LONG", "FLAT"} or decision["current_target"] not in {"LONG", "FLAT"}:
        raise AcceptedIntentV2Rejected("DECISION_INVALID", "targets must be LONG or FLAT")
    expected_transition = "NO_ACTION" if decision["previous_target"] == decision["current_target"] else "TARGET_CHANGE"
    if decision["transition"] != expected_transition:
        raise AcceptedIntentV2Rejected("DECISION_INVALID", "transition is not derived from targets")
    if _boolean(decision["execution_action_required"], "intent.decision.execution_action_required") != (expected_transition == "TARGET_CHANGE"):
        raise AcceptedIntentV2Rejected("DECISION_INVALID", "execution_action_required is not derived from targets")
    timestamp = _text(decision["effective_source_timestamp"], "intent.decision.effective_source_timestamp")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AcceptedIntentV2Rejected("DECISION_INVALID", "effective_source_timestamp is not ISO-8601") from exc
    if parsed_timestamp.utcoffset() is None:
        raise AcceptedIntentV2Rejected("DECISION_INVALID", "effective_source_timestamp must include UTC offset")
    return intent


def consume_accepted_execution_intent_v2(
    value: bytes | str | Path, *, qntyspot_commit: str
) -> dict[str, Any]:
    """Validate one dynamic V2 intent and return a deterministic, non-authoritative projection."""
    intent = _validate_intent(value)
    implementation_commit = _commit(qntyspot_commit, "qntyspot_commit")
    decision = intent["decision"]
    transition = decision["transition"]

    output: dict[str, Any] = {
        "admission": {
            "schema_and_self_digest": "VERIFIED",
            "origin_authentication": "UNPROVEN_BY_V2_BYTES",
            "policy_admission_authorized": "NO",
            "trusted_transport_required": "YES",
        },
        "authority": dict(AUTHORITY_NONE),
        "decision": {
            "current_target": decision["current_target"],
            "effective_source_timestamp": decision["effective_source_timestamp"],
            "execution_action_required": decision["execution_action_required"],
            "previous_target": decision["previous_target"],
            "transition": transition,
        },
        "decision_digest": "",
        "input_intent_digest": intent["intent_digest"],
        "projection": {
            "consumer_result": "NO_ACTION" if transition == "NO_ACTION" else "TARGET_CHANGE_OBSERVED",
            "network_required": "NO",
            "policy_evaluation_required": "NO",
            "qntyspot_side": "NONE",
        },
        "qnty_producer": {
            "acceptance_schema": "H003_ACCEPTANCE_V0",
            "acceptance_source_commit": QNTY_ACCEPTANCE_SOURCE_COMMIT,
            "contract_merge": QNTY_INTENT_V2_CONTRACT_MERGE,
            "repository": QNTY_REPOSITORY,
        },
        "qntyspot_implementation": {
            "commit": implementation_commit,
            "repository": QNTYSPOT_REPOSITORY,
            "version": QNTYSPOT_IMPLEMENTATION_VERSION,
        },
        "schema_name": DECISION_SCHEMA_NAME,
        "schema_version": DECISION_SCHEMA_VERSION,
    }
    output["decision_digest"] = _canonical_digest(output, "decision_digest")
    return output
