"""Fail-closed consumer for Qnty's accepted execution intent.

This module consumes the serialized ``QNTY_ACCEPTED_EXECUTION_INTENT_V1``
artifact as an immutable external input. It does not import sibling-repository
runtime code, repeat upstream acceptance, evaluate a policy, quote a venue, or
perform an external effect.

``qnty_source_commit`` is pinned as the Qnty acceptance-source commit because
the canonical Qnty producer labels it that way. The accepted-intent producer
merge is a separate QntySpot trust pin.
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
    "ACCEPTANCE_SOURCE_COMMIT",
    "CANONICAL_ARTIFACT_DIGEST",
    "QNTY_INTENT_PRODUCER_CANONICAL_MERGE",
    "QNTYSPOT_IMPLEMENTATION_VERSION",
    "AcceptedIntentRejected",
    "consume_accepted_execution_intent",
]

ACCEPTED_INTENT_SCHEMA_NAME = "QNTY_ACCEPTED_EXECUTION_INTENT_V1"
ACCEPTED_INTENT_SCHEMA_VERSION = "V1"
DECISION_SCHEMA_NAME = "QNTYSPOT_ACCEPTED_INTENT_DECISION_V1"
DECISION_SCHEMA_VERSION = "V1"

QNTY_REPOSITORY = "CipherCuttle/Qnty"
QNTYLAB_REPOSITORY = "CipherCuttle/QntyLab"
ACCEPTANCE_SOURCE_COMMIT = "cfee758e9b37037c0f6ef33ea43e43df55cf5f2a"
QNTY_INTENT_PRODUCER_CANONICAL_MERGE = (
    "382cb00ca4868811e994801fa6fee4ca6932927c"
)
QNTYLAB_SOURCE_COMMIT = "d7ed51f02e2e9a0a5fde74b54f6b8b9174847c7c"
CANONICAL_ARTIFACT_DIGEST = (
    "f3cd36b567f4083229a9bd097123a77913533ef87515e5d85ac8ba08a3e6893f"
)
CANONICAL_EFFECTIVE_SOURCE_TIMESTAMP = "2026-09-08T20:00:00Z"
QNTYSPOT_REPOSITORY = "CipherCuttle/QntySpot"
QNTYSPOT_IMPLEMENTATION_VERSION = (
    "QNTYSPOT_ACCEPTED_EXECUTION_INTENT_CONSUMER_V1"
)

AUTHORITY_NONE = {
    "capital": "NONE",
    "execution": "FORBIDDEN",
    "signing": "NONE",
    "submission": "NONE",
}

_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_GIT_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")


class AcceptedIntentRejected(ValueError):
    """The external accepted-intent artifact failed closed."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _keys(value: Any, expected: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcceptedIntentRejected("SCHEMA_INVALID", f"{where} must be an object")
    actual = set(value)
    if actual != expected:
        raise AcceptedIntentRejected(
            "SCHEMA_FIELDS",
            f"{where} keys differ; missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}",
        )
    return value


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise AcceptedIntentRejected("VALUE_INVALID", f"{where} must be a string")
    return value


def _sha(value: Any, where: str) -> str:
    text = _text(value, where)
    if not _SHA256.fullmatch(text):
        raise AcceptedIntentRejected("DIGEST_INVALID", f"{where} must be lowercase sha256")
    return text


def _commit(value: Any, where: str) -> str:
    text = _text(value, where)
    if not _GIT_COMMIT.fullmatch(text):
        raise AcceptedIntentRejected(
            "PROVENANCE_INVALID", f"{where} must be a full lowercase git commit"
        )
    return text


def _boolean(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise AcceptedIntentRejected("VALUE_INVALID", f"{where} must be a JSON boolean")
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
            raise AcceptedIntentRejected("INPUT_UNREADABLE", str(exc)) from exc
    elif isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raise AcceptedIntentRejected(
            "INPUT_TYPE", "accepted intent must be UTF-8 JSON bytes, text, or a Path"
        )

    try:
        parsed = strict_json_loads(raw)
    except (CanonicalFormError, UnicodeError) as exc:
        raise AcceptedIntentRejected("INPUT_JSON", str(exc)) from exc
    if not isinstance(parsed, dict):
        raise AcceptedIntentRejected("INPUT_SHAPE", "accepted intent must be a JSON object")

    canonical = canonical_json_bytes(parsed)
    if raw not in (canonical, canonical + b"\n"):
        raise AcceptedIntentRejected(
            "NON_CANONICAL_JSON", "accepted intent bytes are not canonical JSON"
        )
    return parsed


def _validate_intent(value: bytes | str | Path) -> dict[str, Any]:
    intent = _read_external_json(value)
    _keys(
        intent,
        {
            "authority",
            "decision",
            "intent_digest",
            "provenance",
            "research_identity",
            "schema_name",
            "schema_version",
        },
        "intent",
    )
    if intent["schema_name"] != ACCEPTED_INTENT_SCHEMA_NAME:
        raise AcceptedIntentRejected("SCHEMA_INVALID", "schema_name is not Qnty's accepted-intent schema")
    if intent["schema_version"] != ACCEPTED_INTENT_SCHEMA_VERSION:
        raise AcceptedIntentRejected("SCHEMA_INVALID", "schema_version is not V1")

    declared_digest = _sha(intent["intent_digest"], "intent.intent_digest")
    if declared_digest != CANONICAL_ARTIFACT_DIGEST:
        raise AcceptedIntentRejected(
            "ARTIFACT_DIGEST", "intent digest is not the canonical accepted-intent artifact"
        )
    if _canonical_digest(intent, "intent_digest") != declared_digest:
        raise AcceptedIntentRejected("ARTIFACT_DIGEST", "intent digest recomputation failed")

    authority = _keys(
        intent["authority"], {"capital", "execution", "signing", "submission"}, "intent.authority"
    )
    if authority != AUTHORITY_NONE:
        raise AcceptedIntentRejected("AUTHORITY_ESCALATION", "accepted intent authority is not NONE/FORBIDDEN")

    provenance = _keys(
        intent["provenance"],
        {
            "qnty_acceptance_receipt_digest",
            "qnty_acceptance_schema",
            "qnty_repository",
            "qnty_source_commit",
            "qntylab_repository",
            "qntylab_source_commit",
            "upstream_handoff_digest",
            "upstream_handoff_schema",
        },
        "intent.provenance",
    )
    if provenance["qnty_repository"] != QNTY_REPOSITORY:
        raise AcceptedIntentRejected("PROVENANCE_MISMATCH", "qnty_repository is not canonical")
    if provenance["qnty_source_commit"] != ACCEPTANCE_SOURCE_COMMIT:
        raise AcceptedIntentRejected(
            "PROVENANCE_MISMATCH", "qnty_source_commit is not the acceptance-source commit"
        )
    if provenance["qnty_acceptance_schema"] != "H003_ACCEPTANCE_V0":
        raise AcceptedIntentRejected("PROVENANCE_MISMATCH", "Qnty acceptance schema is not canonical")
    if provenance["qntylab_repository"] != QNTYLAB_REPOSITORY:
        raise AcceptedIntentRejected("PROVENANCE_MISMATCH", "qntylab_repository is not canonical")
    if provenance["qntylab_source_commit"] != QNTYLAB_SOURCE_COMMIT:
        raise AcceptedIntentRejected("PROVENANCE_MISMATCH", "QntyLab source commit is not canonical")
    if provenance["upstream_handoff_schema"] != "H003_SIGNAL_INTENT_V0":
        raise AcceptedIntentRejected("PROVENANCE_MISMATCH", "upstream handoff schema is not canonical")
    _sha(provenance["qnty_acceptance_receipt_digest"], "intent.provenance.qnty_acceptance_receipt_digest")
    _sha(provenance["upstream_handoff_digest"], "intent.provenance.upstream_handoff_digest")

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
            raise AcceptedIntentRejected("PROVENANCE_MISMATCH", f"research_identity.{field} is not governed")
    parameters = _keys(identity["parameters"], {"fast", "mode", "slow"}, "research_identity.parameters")
    if parameters != {"fast": 48, "mode": "long_flat", "slow": 192}:
        raise AcceptedIntentRejected("PROVENANCE_MISMATCH", "H003 parameters are not governed")

    decision = _keys(
        intent["decision"],
        {"current_target", "effective_source_timestamp", "execution_action_required", "previous_target", "transition"},
        "intent.decision",
    )
    if decision["previous_target"] not in {"LONG", "FLAT"} or decision["current_target"] not in {"LONG", "FLAT"}:
        raise AcceptedIntentRejected("DECISION_INVALID", "targets must be LONG or FLAT")
    expected_transition = "NO_ACTION" if decision["previous_target"] == decision["current_target"] else "TARGET_CHANGE"
    if decision["transition"] != expected_transition:
        raise AcceptedIntentRejected("DECISION_INVALID", "transition is not derived from targets")
    if _boolean(decision["execution_action_required"], "intent.decision.execution_action_required") != (expected_transition == "TARGET_CHANGE"):
        raise AcceptedIntentRejected("DECISION_INVALID", "execution_action_required is not derived from targets")
    timestamp = _text(decision["effective_source_timestamp"], "intent.decision.effective_source_timestamp")
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AcceptedIntentRejected("DECISION_INVALID", "effective_source_timestamp is not ISO-8601") from exc
    if parsed_timestamp.utcoffset() is None:
        raise AcceptedIntentRejected("DECISION_INVALID", "effective_source_timestamp must include UTC")
    if timestamp != CANONICAL_EFFECTIVE_SOURCE_TIMESTAMP:
        raise AcceptedIntentRejected("DECISION_INVALID", "source timestamp is not canonical")
    return intent


def consume_accepted_execution_intent(
    value: bytes | str | Path, *, qntyspot_commit: str
) -> dict[str, Any]:
    """Consume one canonical Qnty intent and return a deterministic decision."""
    intent = _validate_intent(value)
    implementation_commit = _commit(qntyspot_commit, "qntyspot_commit")
    decision = intent["decision"]

    # The canonical artifact is LONG -> LONG. A no-op must not wake policy or
    # venue machinery merely to demonstrate that the consumer ran.
    if decision["transition"] != "NO_ACTION" or decision["execution_action_required"] is not False:
        raise AcceptedIntentRejected(
            "UNSUPPORTED_PROJECTION", "this shadow consumer only projects the canonical no-op intent"
        )

    output: dict[str, Any] = {
        "authority": dict(AUTHORITY_NONE),
        "decision": {
            "current_target": decision["current_target"],
            "execution_action_required": False,
            "previous_target": decision["previous_target"],
            "transition": "NO_ACTION",
        },
        "decision_digest": "",
        "input_intent_digest": intent["intent_digest"],
        "projection": {
            "consumer_result": "NO_ACTION",
            "jupiter_quote_required": "NO",
            "network_required": "NO",
            "policy_evaluation_required": "NO",
            "qntyspot_side": "NONE",
        },
        "qnty_producer": {
            "acceptance_schema": "H003_ACCEPTANCE_V0",
            "canonical_merge": QNTY_INTENT_PRODUCER_CANONICAL_MERGE,
            "qnty_source_commit": intent["provenance"]["qnty_source_commit"],
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
