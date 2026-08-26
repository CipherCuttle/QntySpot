"""The Program B pre-live execution contract, as executable invariants.

Every test here protects one of the sixteen named invariants in
``docs/PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0.md``. There is no random
fuzzing and no property that exists to raise a test count: a case that does not
name an invariant does not belong in this family.

These tests are offline, deterministic, and free of any signing, approval,
submission, or capital effect. The V0E hostile suite is a separate, frozen
family and is not touched by this one.
"""

from __future__ import annotations

from dataclasses import replace
from fractions import Fraction

import pytest

from execution_support import (
    ALLOWANCE_TARGET,
    BUY_INSTRUMENT,
    BUY_TOKEN,
    CHAIN_ID,
    MAX_INPUT,
    MIN_OUTPUT,
    NOW,
    SELL_INSTRUMENT,
    TAKER,
    TX_HASH,
    absent,
    approval,
    authority,
    bounds,
    economic_action,
    envelope,
    expectation,
    included,
    pending,
    session,
    signed_record,
    venue_response,
)
from qntyspot.errors import (
    ApprovalContractError,
    AuthorityCeilingError,
    ChainTruthError,
    EnvelopeValidationError,
    SafeHaltError,
    SessionIdentityError,
)
from qntyspot.execution_contract import (
    CONTRACT_VERSION,
    KILL_SWITCH_PRESERVED_CAPABILITIES,
    LADDER,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    ApprovalActionV0,
    AuthorityLevel,
    Capability,
    ChainObservationV0,
    ChainPresence,
    ChainTruthVerdict,
    EconomicActionIDV0,
    ExecutionEnvelopeV0,
    ExecutionReadiness,
    ExecutionSessionV0,
    FinalityPolicyV0,
    ReceiptStatus,
    SettlementExpectationV0,
    SignedTransactionRecordV0,
    SubmissionAcknowledgment,
    SubmissionAttemptV0,
    assert_approval_admissible,
    assert_envelope_admissible,
    assert_envelope_matches_venue_response,
    assert_no_secret_bearing_fields,
    assert_phase_ceiling,
    assert_within_capital_ceiling,
    evaluate_chain_truth,
    evaluate_zero_x_execution_readiness,
    granted_capabilities,
    next_state_for_verdict,
    reconcile_to_receipt,
    release_permitted,
    require_capability,
)
from qntyspot.states import (
    BUDGET_HOLDING_STATES,
    EXTERNALLY_AMBIGUOUS_STATES,
    PRE_COMMITMENT_STATES,
    IntentState,
)

STRICT_FINALITY = FinalityPolicyV0(min_confirmation_depth=32, min_agreeing_providers=2)


def admit(env=None, **kwargs) -> None:
    """Run the full admissibility gate over an envelope."""
    grant = kwargs.pop("grant", None) or authority()
    active = kwargs.pop("active_session", None) or session(grant)
    env = env if env is not None else envelope(active, grant)
    assert_envelope_admissible(
        env,
        active,
        grant,
        kwargs.pop("economic_bounds", None) or bounds(),
        economic_action_id=kwargs.pop("economic_action_id", economic_action()),
        expectation=kwargs.pop("expectation", expectation()),
        venue_response=kwargs.pop("venue_response", venue_response()),
        held_atomic=kwargs.pop("held_atomic", 0),
        now_epoch_s=kwargs.pop("now_epoch_s", NOW),
    )


# --------------------------------------------------------------------------
# I-09 / phase freeze: the contract grants no runtime authority
# --------------------------------------------------------------------------


def test_the_phase_grants_only_shadow_authority() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.SHADOW
    assert_phase_ceiling(AuthorityLevel.SHADOW)
    for level in AuthorityLevel:
        if level is AuthorityLevel.SHADOW:
            continue
        with pytest.raises(AuthorityCeilingError, match="exceeds the granted phase ceiling"):
            assert_phase_ceiling(level)


@pytest.mark.parametrize(
    "capability",
    [
        Capability.RESERVE_CAPITAL,
        Capability.CONSTRUCT_ENVELOPE,
        Capability.AUTHORIZE_APPROVAL,
        Capability.PRODUCE_SIGNATURE,
        Capability.SUBMIT_EXACT_BYTES,
        Capability.RECONCILE,
        Capability.OBSERVE_CHAIN,
    ],
)
def test_no_capability_above_shadow_is_reachable_in_this_phase(capability: Capability) -> None:
    """A caller cannot buy authority by passing a higher level."""
    for level in AuthorityLevel:
        with pytest.raises(AuthorityCeilingError):
            require_capability(capability, level)


def test_shadow_capabilities_are_reachable() -> None:
    for capability in (Capability.OBSERVE_MARKET, Capability.DECIDE_OFFLINE):
        require_capability(capability, AuthorityLevel.SHADOW)


def test_the_authority_ladder_is_monotone() -> None:
    ordered = sorted(AuthorityLevel)
    for lower, higher in zip(ordered, ordered[1:]):
        assert LADDER[lower] < LADDER[higher], f"{higher.name} must strictly extend {lower.name}"


def test_signing_lives_only_at_the_top_of_the_ladder() -> None:
    for level in AuthorityLevel:
        signs = Capability.PRODUCE_SIGNATURE in LADDER[level]
        assert signs == (level is AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER)


def test_submission_requires_at_least_level_two() -> None:
    for level in AuthorityLevel:
        submits = Capability.SUBMIT_EXACT_BYTES in LADDER[level]
        assert submits == (level >= AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES)


# --------------------------------------------------------------------------
# I-10 kill switch, and SAFE_HALT as its equivalent
# --------------------------------------------------------------------------


@pytest.mark.parametrize("level", list(AuthorityLevel))
@pytest.mark.parametrize("halted", [False, True])
def test_the_kill_switch_stops_every_new_external_effect(level: AuthorityLevel, halted: bool) -> None:
    if level > PHASE_GRANTED_AUTHORITY_LEVEL:
        with pytest.raises(AuthorityCeilingError):
            granted_capabilities(level, kill_switch_engaged=not halted, safe_halted=halted)
        return
    permitted = granted_capabilities(level, kill_switch_engaged=not halted, safe_halted=halted)
    for capability in (
        Capability.RESERVE_CAPITAL,
        Capability.AUTHORIZE_APPROVAL,
        Capability.PRODUCE_SIGNATURE,
        Capability.SUBMIT_EXACT_BYTES,
        Capability.CONSTRUCT_ENVELOPE,
    ):
        assert capability not in permitted


@pytest.mark.parametrize("level", [AuthorityLevel.RECONCILE_ONLY, AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER])
def test_the_kill_switch_leaves_reconciliation_and_accounting_working(level: AuthorityLevel) -> None:
    permitted = LADDER[level] & KILL_SWITCH_PRESERVED_CAPABILITIES
    for capability in (
        Capability.OBSERVE_CHAIN,
        Capability.RECONCILE,
        Capability.ACCOUNT_QUARANTINE,
    ):
        assert capability in permitted
    assert permitted <= KILL_SWITCH_PRESERVED_CAPABILITIES


def test_safe_halt_grants_no_new_signing_or_submission_authority() -> None:
    """I-03/I-10: a halted runtime may still verify; it may never act again."""
    with pytest.raises(AuthorityCeilingError):
        granted_capabilities(AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER, safe_halted=True)
    permitted = LADDER[AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER] & KILL_SWITCH_PRESERVED_CAPABILITIES
    assert Capability.PRODUCE_SIGNATURE not in permitted
    assert Capability.SUBMIT_EXACT_BYTES not in permitted
    assert Capability.RECONCILE in permitted


# --------------------------------------------------------------------------
# I-14 session identity
# --------------------------------------------------------------------------


def test_session_identity_excludes_everything_ambient() -> None:
    """A path, a machine name, a URL or a clock must not move the identity."""
    base = session()
    assert base.identity_digest == replace(base, started_at_epoch_s=NOW + 999).identity_digest
    assert base.identity_digest == replace(base, session_ordinal=9).identity_digest
    assert "started_at_epoch_s" not in base.identity_object()
    assert "session_ordinal" not in base.identity_object()


def test_session_instances_are_distinguishable_and_deterministic() -> None:
    base = session()
    assert base.session_id == session().session_id
    assert base.session_id != replace(base, session_ordinal=1).session_id
    assert base.session_id != replace(base, started_at_epoch_s=NOW + 1).session_id


def test_envelope_reconstruction_uses_stable_session_identity_across_restart() -> None:
    first = session()
    restarted = session(started_at_epoch_s=NOW + 1)
    assert first.identity_digest == restarted.identity_digest
    assert envelope(first).envelope_id == envelope(restarted).envelope_id
    admit(envelope(restarted), active_session=restarted)


@pytest.mark.parametrize(
    "runtime_identity",
    [
        "/home/operator/.venv",
        "build-host-07.internal",
        "https://rpc.example.invalid",
        "CPython-3.14",
        "cpython 3.14",
        "",
    ],
)
def test_a_non_portable_runtime_token_cannot_become_identity(runtime_identity: str) -> None:
    with pytest.raises(SessionIdentityError):
        session(runtime_identity=runtime_identity)


@pytest.mark.parametrize(
    "field",
    [
        "repository_commit",
        "implementation_digest",
        "runtime_identity",
        "db_schema_version",
        "policy_id",
        "authority_policy_digest",
        "taker_address",
        "network_id",
        "venue_id",
        "venue_adapter_version",
    ],
)
def test_every_declared_identity_input_participates_in_the_session_digest(field: str) -> None:
    assert field in session().identity_object()


# --------------------------------------------------------------------------
# Envelope identity / evidence partition
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field, value",
    [
        ("plan_id", "99" * 32),
        ("quote_id", "quote-9999"),
        ("quote_observation_digest", "98" * 32),
        ("venue_block_number", 2_000_000),
        ("constructed_at_epoch_s", NOW - 1),
    ],
)
def test_evidence_does_not_move_envelope_identity(field: str, value: object) -> None:
    """Reconstruction after a crash must produce the same envelope, not a new one."""
    base = envelope()
    assert replace(base, **{field: value}).envelope_id == base.envelope_id
    assert replace(base, **{field: value}).evidence_digest != base.evidence_digest


@pytest.mark.parametrize(
    "field, value",
    [
        ("chain_id", 1),
        ("session_identity_digest", "99" * 32),
        ("taker_address", "0x00000000000000000000000000000000000000ee"),
        ("max_input_atomic", MAX_INPUT - 1),
        ("min_output_atomic", MIN_OUTPUT + 1),
        ("transaction_to", "0x00000000000000000000000000000000000000ef"),
        ("transaction_value_atomic", 1),
        ("calldata_sha256", "56" * 32),
        ("calldata_length", 325),
        ("allowance_target", "0x00000000000000000000000000000000000000fa"),
        ("account_nonce", 8),
        ("gas_limit_ceiling", 400_001),
        ("deadline_epoch_s", NOW + 601),
    ],
)
def test_every_identity_field_moves_envelope_identity(field: str, value: object) -> None:
    base = envelope()
    assert replace(base, **{field: value}).envelope_id != base.envelope_id


def test_envelope_identity_is_deterministic_across_reconstruction() -> None:
    assert envelope().envelope_id == envelope().envelope_id


# --------------------------------------------------------------------------
# Envelope admissibility -- the rejection family
# --------------------------------------------------------------------------


def test_a_well_formed_envelope_is_admissible() -> None:
    admit()


def test_wrong_chain_cannot_produce_a_signable_envelope() -> None:
    grant = authority()
    active = session(grant)
    with pytest.raises(EnvelopeValidationError, match="chain"):
        admit(envelope(active, grant, chain_id=1), grant=grant, active_session=active)


def test_wrong_taker_cannot_produce_a_signable_envelope() -> None:
    grant = authority()
    active = session(grant)
    other = "0x00000000000000000000000000000000000000ee"
    with pytest.raises(EnvelopeValidationError, match="taker"):
        admit(envelope(active, grant, taker_address=other), grant=grant, active_session=active)


@pytest.mark.parametrize("field", ["input_instrument_id", "output_instrument_id"])
def test_wrong_token_cannot_produce_a_signable_envelope(field: str) -> None:
    grant = authority()
    active = session(grant)
    other = f"evm:{CHAIN_ID}:0x00000000000000000000000000000000000000fe"
    with pytest.raises(EnvelopeValidationError, match="token|instrument"):
        admit(envelope(active, grant, **{field: other}), grant=grant, active_session=active)


def test_a_token_from_another_chain_is_refused() -> None:
    grant = authority()
    active = session(grant)
    foreign = "evm:1:0x00000000000000000000000000000000000000bb"
    with pytest.raises(EnvelopeValidationError):
        admit(
            envelope(active, grant, input_instrument_id=foreign),
            grant=grant,
            active_session=active,
            economic_bounds=bounds(input_instrument_id=foreign),
        )


def test_max_input_exceeded_is_rejected() -> None:
    grant = authority()
    active = session(grant)
    with pytest.raises(EnvelopeValidationError):
        admit(
            envelope(active, grant, max_input_atomic=MAX_INPUT + 1),
            grant=grant,
            active_session=active,
        )


def test_min_output_weakened_is_rejected() -> None:
    grant = authority()
    active = session(grant)
    with pytest.raises(EnvelopeValidationError, match="weaker minimum output"):
        admit(
            envelope(active, grant, min_output_atomic=MIN_OUTPUT - 1),
            grant=grant,
            active_session=active,
        )


def test_deadline_expired_is_rejected() -> None:
    grant = authority()
    active = session(grant)
    with pytest.raises(EnvelopeValidationError, match="deadline has already passed"):
        admit(
            grant=grant,
            active_session=active,
            venue_response=venue_response(quoted_at_epoch_s=NOW + 580),
            now_epoch_s=NOW + 601,
        )


def test_a_deadline_beyond_the_bound_is_rejected() -> None:
    grant = authority()
    active = session(grant)
    with pytest.raises(EnvelopeValidationError, match="outlives"):
        admit(
            envelope(active, grant, deadline_epoch_s=NOW + 601),
            grant=grant,
            active_session=active,
        )


def test_authority_policy_digest_mismatch_is_rejected() -> None:
    grant = authority()
    active = session(grant)
    other = authority(max_reservation_atomic=MAX_INPUT * 2)
    with pytest.raises(EnvelopeValidationError, match="different authority policy"):
        admit(
            envelope(active, other),
            grant=grant,
            active_session=active,
        )


def test_session_identity_mismatch_is_rejected() -> None:
    grant = authority()
    active = session(grant)
    other = session(grant, runtime_identity="cpython-3.15")
    with pytest.raises(EnvelopeValidationError, match="different session identity"):
        admit(envelope(other, grant), grant=grant, active_session=active)


def test_a_different_economic_action_is_rejected() -> None:
    with pytest.raises(EnvelopeValidationError, match="different economic action"):
        admit(economic_action_id="ab" * 32)


def test_source_change_invalidates_the_authority_grant() -> None:
    """I-09: editing the evaluated code cannot raise its own ceiling."""
    grant = authority()
    edited = session(grant, implementation_digest="12" * 32)
    with pytest.raises(AuthorityCeilingError, match="implementation digest"):
        admit(envelope(edited, grant), grant=grant, active_session=edited)


def test_a_different_commit_invalidates_the_authority_grant() -> None:
    grant = authority()
    moved = session(grant, repository_commit="b" * 40)
    with pytest.raises(AuthorityCeilingError, match="repository commit"):
        admit(envelope(moved, grant), grant=grant, active_session=moved)


def test_an_expired_authority_grant_is_refused() -> None:
    grant = authority(not_after_epoch_s=NOW - 1, not_before_epoch_s=NOW - 100)
    active = session(grant)
    with pytest.raises(AuthorityCeilingError, match="not valid"):
        admit(envelope(active, grant), grant=grant, active_session=active)


# --------------------------------------------------------------------------
# Capital ceiling
# --------------------------------------------------------------------------


def test_reserved_capital_never_exceeds_the_per_action_ceiling() -> None:
    grant = authority()
    assert_within_capital_ceiling(requested_atomic=MAX_INPUT, held_atomic=0, authority=grant)
    with pytest.raises(AuthorityCeilingError, match="per-action ceiling"):
        assert_within_capital_ceiling(
            requested_atomic=MAX_INPUT + 1, held_atomic=0, authority=grant
        )


def test_reserved_capital_never_exceeds_the_cumulative_ceiling() -> None:
    grant = authority()
    with pytest.raises(AuthorityCeilingError, match="cumulative ceiling"):
        assert_within_capital_ceiling(
            requested_atomic=MAX_INPUT, held_atomic=MAX_INPUT * 4, authority=grant
        )


def test_quarantined_capital_still_counts_against_the_ceiling() -> None:
    """I-04: held capital is capital, whether or not anyone knows its fate."""
    grant = authority(max_cumulative_atomic=MAX_INPUT * 2)
    assert_within_capital_ceiling(
        requested_atomic=MAX_INPUT, held_atomic=MAX_INPUT, authority=grant
    )
    with pytest.raises(AuthorityCeilingError):
        assert_within_capital_ceiling(
            requested_atomic=1, held_atomic=MAX_INPUT * 2, authority=grant
        )


def test_envelope_admission_composes_the_cumulative_capital_ceiling() -> None:
    grant = authority(max_cumulative_atomic=MAX_INPUT * 2)
    active = session(grant)
    with pytest.raises(AuthorityCeilingError, match="cumulative ceiling"):
        admit(
            grant=grant,
            active_session=active,
            held_atomic=MAX_INPUT * 2,
        )


# --------------------------------------------------------------------------
# I-12 the venue response is untrusted
# --------------------------------------------------------------------------


def test_a_clean_response_is_executable_and_that_is_not_an_authority() -> None:
    readiness = evaluate_zero_x_execution_readiness(
        expectation(), venue_response(), now_epoch_s=NOW
    )
    assert readiness.verdict is ExecutionReadiness.EXECUTABLE
    # I-01: readiness is a fact about the venue, never a capability.
    with pytest.raises(AuthorityCeilingError):
        require_capability(Capability.SUBMIT_EXACT_BYTES, AuthorityLevel.HUMAN_SIGNED_EXECUTION)


@pytest.mark.parametrize(
    "override, match",
    [
        ({"chain_id": 1}, "chain"),
        ({"taker_address": "0x00000000000000000000000000000000000000ee"}, "taker"),
        ({"sell_token": "0x00000000000000000000000000000000000000fe"}, "sell token"),
        ({"buy_token": "0x00000000000000000000000000000000000000fe"}, "buy token"),
        ({"quote_mode": "exact_out"}, "mode"),
        ({"sell_amount_atomic": MAX_INPUT - 1}, "different amount"),
        ({"transaction_value_atomic": 1}, "native-value"),
        ({"transaction_to": "0x00000000000000000000000000000000000000fe"}, "target disagrees"),
        ({"min_buy_amount_atomic": None}, "no minimum buy amount"),
        ({"min_buy_amount_atomic": MIN_OUTPUT - 1}, "weaker than the policy bound"),
    ],
)
def test_a_hostile_venue_response_fails_closed(override: dict, match: str) -> None:
    with pytest.raises(EnvelopeValidationError, match=match):
        evaluate_zero_x_execution_readiness(
            expectation(), venue_response(**override), now_epoch_s=NOW
        )


def test_a_venue_that_redirects_the_approval_spender_fails_closed() -> None:
    """The approval target is never inferred and never quietly redirected."""
    hostile = venue_response(
        allowance_issue_actual_atomic=0,
        allowance_issue_spender="0x00000000000000000000000000000000000000fe",
    )
    with pytest.raises(EnvelopeValidationError, match="allowance spender disagrees"):
        evaluate_zero_x_execution_readiness(expectation(), hostile, now_epoch_s=NOW)


@pytest.mark.parametrize(
    "override, reason",
    [
        ({"liquidity_available": False}, "LIQUIDITY_UNAVAILABLE"),
        ({"simulation_incomplete": True}, "SIMULATION_INCOMPLETE"),
        ({"invalid_sources": ("Bad",)}, "INVALID_SOURCES"),
        ({"balance_issue": True}, "INSUFFICIENT_BALANCE"),
        ({"quoted_at_epoch_s": NOW - 31}, "STALE_QUOTE"),
        ({"quoted_at_epoch_s": NOW + 1}, "QUOTE_TIME_IN_THE_FUTURE"),
    ],
)
def test_a_not_ready_world_returns_not_executable(override: dict, reason: str) -> None:
    readiness = evaluate_zero_x_execution_readiness(
        expectation(), venue_response(**override), now_epoch_s=NOW
    )
    assert readiness.verdict is ExecutionReadiness.NOT_EXECUTABLE
    assert reason in readiness.reasons


def test_a_missing_allowance_asks_for_a_separate_external_action() -> None:
    readiness = evaluate_zero_x_execution_readiness(
        expectation(),
        venue_response(allowance_issue_actual_atomic=0, allowance_issue_spender=ALLOWANCE_TARGET),
        now_epoch_s=NOW,
    )
    assert readiness.verdict is ExecutionReadiness.APPROVAL_REQUIRED
    assert readiness.required_spender == ALLOWANCE_TARGET
    assert readiness.required_allowance_atomic == MAX_INPUT


def test_the_envelope_must_be_exactly_what_the_response_describes() -> None:
    assert_envelope_matches_venue_response(envelope(), venue_response())


def test_the_composite_envelope_gate_rejects_a_stale_quote() -> None:
    with pytest.raises(EnvelopeValidationError, match="STALE_QUOTE"):
        admit(venue_response=venue_response(quoted_at_epoch_s=NOW - 31))


@pytest.mark.parametrize(
    "override",
    [
        {"transaction_to": "0x00000000000000000000000000000000000000fe"},
        {"calldata_sha256": "56" * 32},
        {"calldata_length": 325},
        {"allowance_target": "0x00000000000000000000000000000000000000fe"},
        {"max_input_atomic": MAX_INPUT - 1},
        {"min_output_atomic": MIN_OUTPUT + 1},
    ],
)
def test_transaction_target_and_bound_mismatches_are_rejected(override: dict) -> None:
    with pytest.raises(EnvelopeValidationError):
        assert_envelope_matches_venue_response(envelope(**override), venue_response())


# --------------------------------------------------------------------------
# I-13 approval is its own external action
# --------------------------------------------------------------------------


def approval_readiness():
    return evaluate_zero_x_execution_readiness(
        expectation(),
        venue_response(allowance_issue_actual_atomic=0, allowance_issue_spender=ALLOWANCE_TARGET),
        now_epoch_s=NOW,
    )


def test_an_approval_matching_the_current_response_is_admissible() -> None:
    grant = authority()
    active = session(grant)
    assert_approval_admissible(
        approval(active, grant), active, grant, expectation(),
        venue_response(allowance_issue_actual_atomic=0, allowance_issue_spender=ALLOWANCE_TARGET),
        now_epoch_s=NOW,
    )


def test_an_unlimited_allowance_is_refused_in_v0() -> None:
    with pytest.raises(ApprovalContractError, match="unlimited"):
        approval(requested_allowance_atomic=2**256 - 1)


def test_an_approval_for_a_remembered_spender_is_refused() -> None:
    """The spender comes from the current response, never from history."""
    grant = authority()
    active = session(grant)
    stale = approval(active, grant, spender_address="0x00000000000000000000000000000000000000fe")
    with pytest.raises(ApprovalContractError, match="spender"):
        assert_approval_admissible(
            stale, active, grant, expectation(),
            venue_response(allowance_issue_actual_atomic=0, allowance_issue_spender=ALLOWANCE_TARGET),
            now_epoch_s=NOW,
        )


def test_an_approval_for_an_unrelated_token_is_refused() -> None:
    grant = authority()
    active = session(grant)
    unrelated = approval(
        active,
        grant,
        token_address="0x00000000000000000000000000000000000000ee",
    )
    with pytest.raises(ApprovalContractError, match="approval token"):
        assert_approval_admissible(
            unrelated,
            active,
            grant,
            expectation(),
            venue_response(
                allowance_issue_actual_atomic=0,
                allowance_issue_spender=ALLOWANCE_TARGET,
            ),
            now_epoch_s=NOW,
        )


def test_approval_reuses_the_source_and_authority_binding() -> None:
    grant = authority()
    active = session(grant)
    mismatched = authority(permitted_repository_commit="b" * 40)
    candidate = approval(active, mismatched)
    with pytest.raises(ApprovalContractError, match="authority policy"):
        assert_approval_admissible(
            candidate,
            active,
            mismatched,
            expectation(),
            venue_response(
                allowance_issue_actual_atomic=0,
                allowance_issue_spender=ALLOWANCE_TARGET,
            ),
            now_epoch_s=NOW,
        )


def test_an_approval_larger_than_the_bound_is_refused() -> None:
    grant = authority()
    active = session(grant)
    over = approval(active, grant, requested_allowance_atomic=MAX_INPUT + 1)
    with pytest.raises(ApprovalContractError, match="exact amount"):
        assert_approval_admissible(
            over, active, grant, expectation(),
            venue_response(allowance_issue_actual_atomic=0, allowance_issue_spender=ALLOWANCE_TARGET),
            now_epoch_s=NOW,
        )


def test_no_approval_is_admissible_when_none_is_required() -> None:
    grant = authority()
    active = session(grant)
    ready = evaluate_zero_x_execution_readiness(expectation(), venue_response(), now_epoch_s=NOW)
    with pytest.raises(ApprovalContractError, match="no approval is required"):
        assert_approval_admissible(
            approval(active, grant), active, grant, expectation(), venue_response(), now_epoch_s=NOW
        )


def test_an_expired_approval_deadline_is_refused() -> None:
    grant = authority()
    active = session(grant)
    with pytest.raises(ApprovalContractError, match="deadline"):
        assert_approval_admissible(
            approval(active, grant), active, grant, expectation(),
            venue_response(quoted_at_epoch_s=NOW + 580,
                           allowance_issue_actual_atomic=0,
                           allowance_issue_spender=ALLOWANCE_TARGET),
            now_epoch_s=NOW + 601,
        )


def test_approval_identity_is_deterministic_and_distinct_per_spender() -> None:
    base = approval()
    assert base.approval_action_id == approval().approval_action_id
    other = approval(spender_address="0x00000000000000000000000000000000000000fe")
    assert other.approval_action_id != base.approval_action_id


# --------------------------------------------------------------------------
# I-02 / I-05 signed transaction identity
# --------------------------------------------------------------------------


def test_exact_byte_retransmission_is_the_same_signed_identity() -> None:
    first = signed_record()
    again = signed_record(transaction_hash=TX_HASH)
    assert first.signed_transaction_id == again.signed_transaction_id


def test_different_signed_bytes_are_a_different_signed_identity() -> None:
    assert signed_record().signed_transaction_id != signed_record(
        raw_signed_sha256="67" * 32
    ).signed_transaction_id


def test_a_rebuilt_envelope_is_a_different_signed_identity() -> None:
    """I-05: a replacement transaction can never masquerade as the original."""
    rebuilt = envelope(account_nonce=8).envelope_id
    assert signed_record(envelope_id=rebuilt).signed_transaction_id != signed_record().signed_transaction_id


# --------------------------------------------------------------------------
# I-07 acknowledgment is not settlement
# --------------------------------------------------------------------------


def test_a_provider_naming_another_hash_has_not_acknowledged_this_action() -> None:
    attempt = SubmissionAttemptV0(
        signed_transaction_id=signed_record().signed_transaction_id,
        provider_id="provider-a",
        attempt_ordinal=0,
        submitted_at_epoch_s=NOW,
        acknowledgment=SubmissionAcknowledgment.ACCEPTED,
        provider_reported_hash="0x" + "ba" * 32,
    )
    with pytest.raises(ChainTruthError, match="unknown"):
        attempt.assert_hash_agreement(TX_HASH)


def test_an_acknowledged_submission_alone_produces_no_settlement() -> None:
    truth = evaluate_chain_truth(
        SettlementExpectationV0(
            economic_action_id=economic_action(),
            transaction_hash=TX_HASH,
            chain_id=CHAIN_ID,
            taker_address=TAKER,
            submission_acknowledged=True,
        ),
        (),
        STRICT_FINALITY,
    )
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS
    assert next_state_for_verdict(truth.verdict) is IntentState.SAFE_HALT


# --------------------------------------------------------------------------
# I-06 chain truth is settlement authority
# --------------------------------------------------------------------------


def expect(acknowledged: bool = True) -> SettlementExpectationV0:
    return SettlementExpectationV0(
        economic_action_id=economic_action(),
        transaction_hash=TX_HASH,
        chain_id=CHAIN_ID,
        taker_address=TAKER,
        submission_acknowledged=acknowledged,
    )


def truth_for(*observations, finality=STRICT_FINALITY, acknowledged: bool = True):
    return evaluate_chain_truth(expect(acknowledged), observations, finality)


def test_two_agreeing_providers_at_depth_confirm() -> None:
    truth = truth_for(included("provider-a"), included("provider-b"))
    assert truth.verdict is ChainTruthVerdict.CONFIRMED
    assert truth.agreeing_provider_count == 2
    assert truth.confirmation_depth == 64


def test_one_provider_is_never_enough_to_confirm() -> None:
    """I-07: the actor may not also be the only verifier."""
    truth = truth_for(included("provider-a"))
    assert truth.verdict is ChainTruthVerdict.VISIBLE
    assert next_state_for_verdict(truth.verdict) is None


def test_insufficient_depth_stops_at_included() -> None:
    truth = truth_for(
        included("provider-a", head_block_number=1_000_010),
        included("provider-b", head_block_number=1_000_010),
    )
    assert truth.verdict is ChainTruthVerdict.INCLUDED
    assert next_state_for_verdict(truth.verdict) is IntentState.INCLUDED


def test_a_provider_without_a_head_reading_cannot_contribute_depth() -> None:
    truth = truth_for(
        included("provider-a"), included("provider-b", head_block_number=None)
    )
    assert truth.verdict is ChainTruthVerdict.INCLUDED
    assert truth.confirmation_depth == 0


def test_providers_that_disagree_about_the_block_are_ambiguous() -> None:
    truth = truth_for(
        included("provider-a"), included("provider-b", block_hash="0x" + "dd" * 32)
    )
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS
    assert next_state_for_verdict(truth.verdict) is IntentState.SAFE_HALT


def test_a_provider_that_changes_its_mind_about_the_block_is_ambiguous() -> None:
    """A replacement or a reorg is a contradiction, not a fresher answer."""
    truth = truth_for(
        included("provider-a", observed_at_epoch_s=NOW - 10),
        included("provider-a", block_hash="0x" + "dd" * 32, observed_at_epoch_s=NOW),
        included("provider-b"),
    )
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS


def test_absence_beside_inclusion_is_ambiguous() -> None:
    truth = truth_for(included("provider-a"), included("provider-b"), absent("provider-c"))
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS


def test_absence_everywhere_after_an_acknowledged_submission_is_ambiguous() -> None:
    """Never convert "we cannot find it" into "it did not happen"."""
    truth = truth_for(absent("provider-a"), absent("provider-b"))
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS


def test_absence_everywhere_without_an_acknowledged_submission_is_no_evidence() -> None:
    truth = truth_for(absent("provider-a"), absent("provider-b"), acknowledged=False)
    assert truth.verdict is ChainTruthVerdict.NO_EVIDENCE


def test_a_pending_transaction_is_visible_only() -> None:
    truth = truth_for(pending("provider-a"), pending("provider-b"))
    assert truth.verdict is ChainTruthVerdict.VISIBLE


def test_latest_pending_evidence_overrules_stale_inclusion() -> None:
    observations = (
        included("provider-a", observed_at_epoch_s=NOW - 10),
        pending("provider-a", observed_at_epoch_s=NOW),
        included("provider-b", observed_at_epoch_s=NOW - 10),
    )
    truth = truth_for(*observations)
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS
    with pytest.raises(SafeHaltError):
        reconcile_to_receipt(
            expect(),
            truth,
            bounds(),
            receipt_id="99" * 32,
            fee_atomic=0,
            observed_at_epoch_s=NOW,
            source="test-fixture",
        )


def test_latest_pending_evidence_from_all_providers_cannot_mint_from_history() -> None:
    truth = truth_for(
        included("provider-a", observed_at_epoch_s=NOW - 10),
        included("provider-b", observed_at_epoch_s=NOW - 10),
        pending("provider-a", observed_at_epoch_s=NOW),
        pending("provider-b", observed_at_epoch_s=NOW),
    )
    assert truth.verdict is ChainTruthVerdict.AMBIGUOUS


def test_a_confirmed_revert_is_a_settlement_free_outcome() -> None:
    truth = truth_for(
        included("provider-a", status=ReceiptStatus.REVERTED),
        included("provider-b", status=ReceiptStatus.REVERTED),
    )
    assert truth.verdict is ChainTruthVerdict.REVERTED
    assert next_state_for_verdict(truth.verdict) is IntentState.REJECTED


def test_an_observation_of_another_transaction_cannot_settle_this_action() -> None:
    other = ChainObservationV0(
        provider_id="provider-a",
        transaction_hash="0x" + "ba" * 32,
        observed_at_epoch_s=NOW,
        presence=ChainPresence.PENDING,
        raw_evidence_sha256="77" * 32,
    )
    with pytest.raises(ChainTruthError, match="different transaction"):
        truth_for(other)


@pytest.mark.parametrize(
    "kwargs, match",
    [
        ({"presence": "INCLUDED"}, "unknown presence"),
        ({"block_hash": None}, "block identity"),
    ],
)
def test_malformed_chain_evidence_is_refused(kwargs: dict, match: str) -> None:
    base = included("provider-a")
    with pytest.raises(ChainTruthError, match=match):
        replace(base, **kwargs)


# --------------------------------------------------------------------------
# FILLED requires independently reconciled external truth
# --------------------------------------------------------------------------


def test_only_a_confirmed_verdict_may_produce_a_receipt() -> None:
    receipt = reconcile_to_receipt(
        expect(),
        truth_for(included("provider-a"), included("provider-b")),
        bounds(),
        receipt_id="receipt-0001",
        fee_atomic=0,
        observed_at_epoch_s=NOW,
        source="test-fixture",
    )
    assert receipt.external_ref == TX_HASH
    assert receipt.economic_action_id == economic_action()


@pytest.mark.parametrize(
    "observations",
    [
        (),
        (included("provider-a"),),
        (included("provider-a"), included("provider-b", block_hash="0x" + "dd" * 32)),
        (included("provider-a", head_block_number=1_000_010), included("provider-b", head_block_number=1_000_010)),
        (included("provider-a", status=ReceiptStatus.REVERTED), included("provider-b", status=ReceiptStatus.REVERTED)),
    ],
)
def test_anything_short_of_confirmed_refuses_to_produce_a_receipt(observations) -> None:
    with pytest.raises(SafeHaltError):
        reconcile_to_receipt(
            expect(),
            truth_for(*observations),
            bounds(),
            receipt_id="receipt-0001",
            fee_atomic=0,
            observed_at_epoch_s=NOW,
            source="test-fixture",
        )


def test_a_settlement_outside_the_committed_bounds_halts() -> None:
    truth = truth_for(
        included("provider-a", effective_output=MIN_OUTPUT - 1),
        included("provider-b", effective_output=MIN_OUTPUT - 1),
    )
    with pytest.raises(SafeHaltError, match="outside the committed economic bounds"):
        reconcile_to_receipt(
            expect(),
            truth,
            bounds(),
            receipt_id="receipt-0001",
            fee_atomic=0,
            observed_at_epoch_s=NOW,
            source="test-fixture",
        )


def test_chain_truth_cannot_be_reused_for_another_expectation() -> None:
    truth = truth_for(included("provider-a"), included("provider-b"))
    other = expect()
    other = SettlementExpectationV0(
        economic_action_id=EconomicActionIDV0("9" * 64),
        transaction_hash="0x" + "12" * 32,
        chain_id=999,
        taker_address="0x0000000000000000000000000000000000000055",
        submission_acknowledged=True,
    )
    with pytest.raises(ChainTruthError, match="bound to a different"):
        reconcile_to_receipt(
            other,
            truth,
            bounds(),
            receipt_id="98" * 32,
            fee_atomic=0,
            observed_at_epoch_s=NOW,
            source="test-fixture",
        )


def test_settlement_expectation_requires_an_economic_action_id() -> None:
    with pytest.raises(ChainTruthError, match="EconomicActionID"):
        SettlementExpectationV0(
            economic_action_id="9" * 64,
            transaction_hash=TX_HASH,
            chain_id=CHAIN_ID,
            taker_address=TAKER,
            submission_acknowledged=True,
        )


# --------------------------------------------------------------------------
# I-04 unknown outcome holds capital
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", sorted(PRE_COMMITMENT_STATES, key=lambda s: s.value))
def test_a_pre_commitment_action_may_release_its_capital(state: IntentState) -> None:
    assert release_permitted(state, None) is True


@pytest.mark.parametrize("state", sorted(EXTERNALLY_AMBIGUOUS_STATES, key=lambda s: s.value))
@pytest.mark.parametrize(
    "verdict",
    [None, ChainTruthVerdict.NO_EVIDENCE, ChainTruthVerdict.VISIBLE,
     ChainTruthVerdict.INCLUDED, ChainTruthVerdict.CONFIRMED, ChainTruthVerdict.AMBIGUOUS],
)
def test_an_externally_visible_action_never_releases_on_ambiguity(
    state: IntentState, verdict
) -> None:
    assert release_permitted(state, verdict) is False


@pytest.mark.parametrize("state", sorted(EXTERNALLY_AMBIGUOUS_STATES, key=lambda s: s.value))
def test_only_a_confirmed_revert_releases_capital_after_external_exposure(
    state: IntentState,
) -> None:
    assert release_permitted(state, ChainTruthVerdict.REVERTED) is True


def test_every_externally_ambiguous_state_holds_a_reservation() -> None:
    assert EXTERNALLY_AMBIGUOUS_STATES <= BUDGET_HOLDING_STATES


# --------------------------------------------------------------------------
# I-11 key isolation, expressed at the type level
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "record_type",
    [
        ExecutionSessionV0,
        ExecutionEnvelopeV0,
        ApprovalActionV0,
        SignedTransactionRecordV0,
        SubmissionAttemptV0,
        ChainObservationV0,
    ],
)
def test_no_contract_record_can_carry_signing_material(record_type: type) -> None:
    assert_no_secret_bearing_fields(record_type)


def test_the_guard_actually_catches_a_secret_bearing_field() -> None:
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Leaky:
        private_material: str

    with pytest.raises(EnvelopeValidationError, match="forbidden fields"):
        assert_no_secret_bearing_fields(Leaky)


def test_the_guard_catches_common_key_and_signature_shapes() -> None:
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Leaky:
        signer_key: str
        mnemonic: str
        keystore_json: str
        raw_signed_payload: bytes
        password: str
        priv: str
        r_component: int
        s_component: int
        v_component: int

    with pytest.raises(EnvelopeValidationError, match="forbidden fields"):
        assert_no_secret_bearing_fields(Leaky)


def test_a_signed_record_stores_a_digest_and_never_a_payload() -> None:
    names = {f.name for f in signed_record().__dataclass_fields__.values()}
    assert "raw_signed_sha256" in names
    assert not any("bytes" in name for name in names)


def test_the_contract_version_is_frozen() -> None:
    assert CONTRACT_VERSION == "QNTY_SPOT_PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0"


def test_b1_o_01_the_ledger_release_rule_is_wider_than_the_contract_allows() -> None:
    """Pin the one known divergence between the ledger and I-04.

    ``REJECTED`` is reachable from ``SUBMITTED`` and ``INCLUDED``, and the
    ledger releases a reservation on ``REJECTED``. That is sound only when
    external truth has confirmed a revert. It is harmless today because nothing
    is ever submitted in shadow, and B1-O-01 requires B1 to gate the ledger
    transition on a recorded ``REVERTED`` reconciliation. This test reads a
    private name deliberately: it exists to make the gap visible if either side
    of it moves.
    """
    from qntyspot.ledger.store import _RELEASING_STATES
    from qntyspot.states import TRANSITIONS

    assert IntentState.REJECTED in _RELEASING_STATES
    assert IntentState.REJECTED in TRANSITIONS[IntentState.SUBMITTED]
    assert release_permitted(IntentState.SUBMITTED, None) is False
    assert release_permitted(IntentState.SUBMITTED, ChainTruthVerdict.REVERTED) is True
