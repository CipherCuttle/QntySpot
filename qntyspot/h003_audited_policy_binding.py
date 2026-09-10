"""Bind authenticated H003 target changes to the frozen audited Solana PolicyV0.

This module does not admit a policy, observe a market, choose an executable
quote, reserve capital, construct a transaction, sign, submit, or settle.  It
replays the authenticated policy-bridge boundary from signed bytes and then
checks the already-frozen H003 instrument-translation audit against the exact
frozen PolicyV0 document.

The result is canonical evidence bytes, not an authority token.  Any later
boundary that needs this conclusion must recompute or independently verify the
same signed/audited inputs rather than trusting a retained Python object.
"""

from __future__ import annotations

from typing import Any

from .accepted_intent_policy_bridge import (
    PolicyBridgeError,
    bridge_authenticated_intent_to_policy_request,
)
from .canon import CanonicalFormError, canonical_json_bytes, sha256_hex, strict_json_loads
from .domain import PolicyV0, Side
from .errors import PolicySchemaError
from .identity import SolanaCluster, SolanaInstrumentRef, TokenProgram
from .policy import parse_policy

__all__ = [
    "H003_AUDITED_POLICY_BINDING_CONTRACT_VERSION",
    "H003_AUDITED_POLICY_BINDING_SCHEMA",
    "H003_TRANSLATION_AUDIT_DIGEST",
    "H003_POLICY_DOCUMENT_SHA256",
    "H003AuditedPolicyBindingError",
    "bind_authenticated_h003_target_to_audited_policy",
]

H003_AUDITED_POLICY_BINDING_CONTRACT_VERSION = "QNTYSPOT_H003_AUDITED_POLICY_BINDING_V0"
H003_AUDITED_POLICY_BINDING_SCHEMA = "qntyspot.h003_audited_policy_binding.v0"
H003_TRANSLATION_AUDIT_DIGEST = "e599340ab6eeb3a8125233c5b74e4bd1ab28b756ab64caade2fd96dc757a76bc"
H003_POLICY_DOCUMENT_SHA256 = "cfa4edc38f2f71bcefbbe5affb1a82b79744627945f2cb95fc88321253d655ee"
_H003_SOURCE_SEMANTIC = "BINANCE_SPOT_SOLUSDT_1H"
_USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_WSOL_MINT = "So11111111111111111111111111111111111111112"
_EXPECTED_AUDIT_FIELDS = {
    "artifact_digest",
    "authority",
    "axes",
    "computed_at_rule",
    "digest_algorithm",
    "digest_rule",
    "frozen_evidence",
    "mapping_table",
    "no_silent_reinterpretation_declaration",
    "policy_json_sha256",
    "schema_name",
    "schema_version",
    "signal_intent",
    "stop_conditions",
}
_AUTHORITY_NONE = {
    "capital": "NONE",
    "execution": "FORBIDDEN",
    "signing": "NONE",
    "submission": "NONE",
}


class H003AuditedPolicyBindingError(ValueError):
    """The authenticated H003-to-policy binding failed closed."""


def _object(value: Any, *, field: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise H003AuditedPolicyBindingError(f"{field}: expected object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], *, field: str) -> None:
    if set(value) != expected:
        raise H003AuditedPolicyBindingError(
            f"{field}: fields differ; missing={sorted(expected - set(value))} "
            f"unknown={sorted(set(value) - expected)}"
        )


def _parse_exact_audit(audit_bytes: bytes) -> dict[str, Any]:
    if type(audit_bytes) is not bytes:
        raise H003AuditedPolicyBindingError("translation audit must be exact bytes")
    try:
        audit = strict_json_loads(audit_bytes)
    except (CanonicalFormError, TypeError, ValueError) as exc:
        raise H003AuditedPolicyBindingError(f"translation audit JSON rejected: {exc}") from exc
    audit = _object(audit, field="translation audit")
    _exact_keys(audit, _EXPECTED_AUDIT_FIELDS, field="translation audit")
    if audit_bytes != canonical_json_bytes(audit) + b"\n":
        raise H003AuditedPolicyBindingError("translation audit bytes are not canonical newline JSON")

    declared_digest = audit.get("artifact_digest")
    if declared_digest != H003_TRANSLATION_AUDIT_DIGEST:
        raise H003AuditedPolicyBindingError("translation audit is not the governed H003 audit")
    digest_material = {key: value for key, value in audit.items() if key != "artifact_digest"}
    if sha256_hex(canonical_json_bytes(digest_material)) != declared_digest:
        raise H003AuditedPolicyBindingError("translation audit self-digest mismatch")
    if audit.get("schema_name") != "H003_INSTRUMENT_TRANSLATION_AUDIT_V0" or audit.get("schema_version") != "V0":
        raise H003AuditedPolicyBindingError("translation audit schema/version mismatch")
    if audit.get("authority") != _AUTHORITY_NONE:
        raise H003AuditedPolicyBindingError("translation audit attempted authority escalation")
    if audit.get("policy_json_sha256") != H003_POLICY_DOCUMENT_SHA256:
        raise H003AuditedPolicyBindingError("translation audit policy digest is not governed")

    stop = _object(audit.get("stop_conditions"), field="translation audit stop_conditions")
    if stop.get("code_contradiction_found") is not False or stop.get("existing_code_defects_requiring_patch") != []:
        raise H003AuditedPolicyBindingError("translation audit stop condition is not clean")
    frozen = _object(audit.get("frozen_evidence"), field="translation audit frozen_evidence")
    if frozen.get("frozen_buy_fixture_reusable_for_long_entry") is not False:
        raise H003AuditedPolicyBindingError("translation audit improperly reuses BUY evidence for LONG")
    signal = _object(audit.get("signal_intent"), field="translation audit signal_intent")
    if signal.get("source_semantic") != _H003_SOURCE_SEMANTIC:
        raise H003AuditedPolicyBindingError("translation audit research source semantic mismatch")
    return audit


def _parse_governed_policy(policy_bytes: bytes, audit: dict[str, Any]) -> PolicyV0:
    if type(policy_bytes) is not bytes:
        raise H003AuditedPolicyBindingError("policy must be exact bytes")
    policy_sha = sha256_hex(policy_bytes)
    if policy_sha != H003_POLICY_DOCUMENT_SHA256 or policy_sha != audit.get("policy_json_sha256"):
        raise H003AuditedPolicyBindingError("policy bytes do not match the audited frozen policy")
    try:
        policy_document = strict_json_loads(policy_bytes)
        policy = parse_policy(policy_document)
    except (CanonicalFormError, PolicySchemaError, TypeError, ValueError) as exc:
        raise H003AuditedPolicyBindingError(f"frozen policy rejected: {exc}") from exc
    if not isinstance(policy, PolicyV0):  # pragma: no cover - parser contract
        raise H003AuditedPolicyBindingError("policy parser did not return PolicyV0")
    if policy.policy_name != "solana-v0c-technical-sol-usdc-buy" or policy.side is not Side.BUY:
        raise H003AuditedPolicyBindingError("audited policy identity/side changed")
    if not isinstance(policy.base.ref, SolanaInstrumentRef) or not isinstance(policy.quote.ref, SolanaInstrumentRef):
        raise H003AuditedPolicyBindingError("audited policy is not a Solana instrument pair")
    if (
        policy.base.ref.cluster is not SolanaCluster.MAINNET_BETA
        or policy.quote.ref.cluster is not SolanaCluster.MAINNET_BETA
        or policy.base.ref.token_program is not TokenProgram.SPL_TOKEN
        or policy.quote.ref.token_program is not TokenProgram.SPL_TOKEN
    ):
        raise H003AuditedPolicyBindingError("audited policy cluster/token-program binding changed")
    if (
        policy.base.ref.mint_address != _USDC_MINT
        or policy.base.decimals != 6
        or policy.quote.ref.mint_address != _WSOL_MINT
        or policy.quote.decimals != 9
    ):
        raise H003AuditedPolicyBindingError("audited policy mint/decimal binding changed")
    return policy


def _validate_mapping(audit: dict[str, Any], policy: PolicyV0) -> dict[str, dict[str, Any]]:
    table = _object(audit.get("mapping_table"), field="translation audit mapping_table")
    long_map = _object(table.get("long"), field="translation audit mapping_table.long")
    flat_map = _object(table.get("flat"), field="translation audit mapping_table.flat")

    expected_long_levels = [level.level_id for level in policy.exit_ladder.levels]
    expected_flat_levels = [level.level_id for level in policy.entry_ladder.levels]
    if (
        long_map.get("policy_side") != policy.exit_ladder.side.value
        or long_map.get("policy_side") != "SELL"
        or long_map.get("exactin_pair") != "USDC->WSOL"
        or long_map.get("policy_level_ids") != expected_long_levels
        or expected_long_levels != ["USDC-SOL-1"]
    ):
        raise H003AuditedPolicyBindingError("audited LONG mapping no longer matches PolicyV0")
    if (
        flat_map.get("policy_side") != policy.entry_ladder.side.value
        or flat_map.get("policy_side") != "BUY"
        or flat_map.get("exactin_pair") != "WSOL->USDC"
        or flat_map.get("policy_level_ids") != expected_flat_levels
        or expected_flat_levels != ["SOL-USDC-1"]
    ):
        raise H003AuditedPolicyBindingError("audited FLAT mapping no longer matches PolicyV0")
    return {"LONG": long_map, "FLAT": flat_map}


def bind_authenticated_h003_target_to_audited_policy(
    intent_bytes: bytes,
    *,
    receipt_bytes: bytes,
    trust_config_bytes: bytes,
    expected_trust_config_digest: str,
    anchor_bytes: bytes,
    qntyspot_commit: str,
    policy_bytes: bytes,
    translation_audit_bytes: bytes,
) -> bytes | None:
    """Return canonical non-authoritative binding evidence for a target change."""

    try:
        request = bridge_authenticated_intent_to_policy_request(
            intent_bytes,
            receipt_bytes=receipt_bytes,
            trust_config_bytes=trust_config_bytes,
            expected_trust_config_digest=expected_trust_config_digest,
            anchor_bytes=anchor_bytes,
            qntyspot_commit=qntyspot_commit,
        )
    except PolicyBridgeError as exc:
        raise H003AuditedPolicyBindingError(f"authenticated policy bridge rejected input: {exc}") from exc
    if request is None:
        return None

    audit = _parse_exact_audit(translation_audit_bytes)
    policy = _parse_governed_policy(policy_bytes, audit)
    mappings = _validate_mapping(audit, policy)

    try:
        intent_document = strict_json_loads(intent_bytes)
    except (CanonicalFormError, TypeError, ValueError) as exc:  # pragma: no cover - bridge already proved this
        raise H003AuditedPolicyBindingError(f"authenticated intent could not be re-read: {exc}") from exc
    intent_document = _object(intent_document, field="authenticated intent")
    research_identity = _object(intent_document.get("research_identity"), field="research_identity")
    if research_identity.get("source_semantic") != _H003_SOURCE_SEMANTIC:
        raise H003AuditedPolicyBindingError("authenticated research source does not match translation audit")

    request_document = request.to_object()
    decision = _object(request_document.get("decision"), field="policy request decision")
    current_target = decision.get("current_target")
    if current_target not in mappings:
        raise H003AuditedPolicyBindingError("policy request target has no audited mapping")
    mapping = mappings[current_target]

    result: dict[str, Any] = {
        "authority": {
            "capital_authorized": "NO",
            "economic_action_authorized": "NO",
            "market_observation_authorized": "NO",
            "network_authorized": "NO",
            "policy_admission_authorized": "NO",
            "signing_authorized": "NO",
            "submission_authorized": "NO",
        },
        "binding": {
            "binding_status": "VERIFIED_AUDITED_POLICY_BINDING",
            "market_observation_required": "YES",
            "policy_time_evaluation_required": "YES",
            "quote_evaluation_required": "YES",
        },
        "binding_digest": "",
        "contract_version": H003_AUDITED_POLICY_BINDING_CONTRACT_VERSION,
        "mapping": {
            "candidate_level_ids": list(mapping["policy_level_ids"]),
            "current_target": current_target,
            "exactin_pair": mapping["exactin_pair"],
            "policy_side": mapping["policy_side"],
            "previous_target": decision.get("previous_target"),
            "transition": decision.get("transition"),
        },
        "policy": {
            "policy_document_sha256": H003_POLICY_DOCUMENT_SHA256,
            "policy_id": policy.policy_id,
            "policy_name": policy.policy_name,
        },
        "provenance": {
            "policy_request_id": request_document["request_id"],
            "qnty_repository_commit": request_document["provenance"]["qnty_repository_commit"],
            "qntyspot_repository_commit": request_document["provenance"]["qntyspot_repository_commit"],
            "research_identity_digest": sha256_hex(canonical_json_bytes(research_identity)),
            "source_intent_digest": request_document["provenance"]["source_intent_digest"],
            "translation_audit_digest": H003_TRANSLATION_AUDIT_DIGEST,
        },
        "schema": H003_AUDITED_POLICY_BINDING_SCHEMA,
    }
    digest_material = dict(result)
    digest_material["binding_digest"] = ""
    result["binding_digest"] = sha256_hex(canonical_json_bytes(digest_material))
    return canonical_json_bytes(result)
