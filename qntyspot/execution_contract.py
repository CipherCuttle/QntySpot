"""Program B pre-live execution contract.

WHAT THIS MODULE IS
-------------------
This is the frozen, mechanical form of
``QNTY_SPOT_PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0``. It is the specification
that a future execution implementation must satisfy, expressed as immutable
dataclasses, deterministic digests, and deterministic validators.

WHAT THIS MODULE IS NOT
-----------------------
It is not an implementation of execution. There is no signer, no private-key
reader, no transaction encoder, no RPC client, no approval builder, no
broadcast surface, and no daemon here. Nothing in this module performs I/O,
reads the environment, reads a clock, or reaches a network. Every temporal
input is an explicit argument.

The phase ceiling is ``PHASE_GRANTED_AUTHORITY_LEVEL = AuthorityLevel.SHADOW``.
``require_capability`` refuses every capability above that ceiling regardless of
what any authority document claims, so this module cannot be used to authorize
signing, approval, submission, or capital deployment.

NAMING NOTE
-----------
The externally controlled account that would sign is called the *taker* here,
which is also the 0x Swap API's term for it and the term already used in
``qntyspot/robinhood.py``. The word "wallet" is a forbidden source token under
``tests/test_no_network.py``; the contract deliberately keeps the account's
role name identical to the venue's own, so there is exactly one term.

THE SIXTEEN NORMATIVE INVARIANTS
--------------------------------
I-01  Evidence does not escalate. A successful quote is not execution
      readiness, is not signing authority, is not capital authority, and is
      not profitability.
I-02  One ``EconomicActionID`` may produce at most one economic settlement.
I-03  Reserve before external effect. No signing- or submission-capable path
      may exist unless the economic action and its capital reservation have
      already committed durably.
I-04  Unknown outcome holds capital. Once external execution may have
      occurred, ambiguity never releases the reservation; it quarantines it.
I-05  No economic retry. An ambiguous prior economic action never causes
      construction or signing of a replacement economic action.
I-06  Chain truth is settlement authority. Local intent says what was
      intended; external chain truth says what happened. Only reconciliation
      may produce a ``FillReceiptV0``.
I-07  Actor is not verifier. Signer success, submission success, provider
      acknowledgment, and inclusion are each not settlement success.
I-08  Economic bounds survive into the transaction. A pre-sign check is not
      sufficient; the bound must be inside the transaction or order.
I-09  Code cannot self-escalate capital authority. The authority ceiling is
      rooted outside the evaluated source tree.
I-10  Kill switch semantics: no new reservations, approvals, signatures, or
      submissions; reconciliation, receipt observation, and quarantine
      accounting stay operational.
I-11  Key isolation. Strategy, market-data, and policy code never read signing
      secrets. No contract record carries key or signature material.
I-12  Untrusted provider response. Everything a venue or RPC returns is an
      untrusted input and is validated against the frozen contract.
I-13  Approval is an external action with its own identity, authority, state,
      receipt, and reconciliation semantics.
I-14  Exact session identity binds commit, implementation, runtime, schema,
      policy, authority policy, taker, chain, and venue adapter version.
I-15  Execution qualification is not alpha.
I-16  RWA API access is not legal eligibility.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields as dataclass_fields
from enum import Enum, IntEnum
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .canon import digest_object, sha256_hex
from .domain import EconomicBounds, FillReceiptV0
from .errors import (
    ApprovalContractError,
    AuthorityCeilingError,
    ChainTruthError,
    EnvelopeValidationError,
    SafeHaltError,
    SessionIdentityError,
)
from .states import EXTERNALLY_AMBIGUOUS_STATES, PRE_COMMITMENT_STATES, IntentState

__all__ = [
    "CONTRACT_VERSION",
    "CONTRACT_SCHEMA",
    "AuthorityLevel",
    "Capability",
    "LADDER",
    "KILL_SWITCH_PRESERVED_CAPABILITIES",
    "PHASE_GRANTED_AUTHORITY_LEVEL",
    "granted_capabilities",
    "require_capability",
    "assert_phase_ceiling",
    "AuthorityPolicyRefV0",
    "ExecutionSessionV0",
    "ExecutionEnvelopeV0",
    "ApprovalActionV0",
    "SignedTransactionRecordV0",
    "SubmissionAcknowledgment",
    "SubmissionAttemptV0",
    "ChainPresence",
    "ReceiptStatus",
    "ChainObservationV0",
    "FinalityPolicyV0",
    "ROBINHOOD_V0_FINALITY",
    "ChainTruthVerdict",
    "EconomicActionIDV0",
    "ChainTruthV0",
    "SettlementExpectationV0",
    "evaluate_chain_truth",
    "reconcile_to_receipt",
    "next_state_for_verdict",
    "ExecutionReadiness",
    "ExecutionReadinessV0",
    "VenueQuoteResponseV0",
    "ZeroXExecutionExpectationV0",
    "AllowanceHolderCalldataV0",
    "decode_allowance_holder_calldata",
    "derive_transaction_hash",
    "evaluate_zero_x_execution_readiness",
    "assert_envelope_matches_venue_response",
    "assert_envelope_admissible",
    "assert_approval_admissible",
    "assert_within_capital_ceiling",
    "release_permitted",
    "assert_no_secret_bearing_fields",
    "network_id_for_chain",
    "MAX_UINT256",
]

CONTRACT_VERSION = "QNTY_SPOT_PROGRAM_B_PRELIVE_EXECUTION_CONTRACT_V0"
CONTRACT_SCHEMA = "qntyspot.program_b.v0"

MAX_UINT256 = 2**256 - 1

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_TX_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
#: Portable identity tokens. Lowercase, dash-separated words, with dots
#: admitted only as version separators, so a dotted domain suffix
#: ("build-host-07.internal") is refused while a version ("cpython-3.14") is
#: not. Paths, URLs, whitespace and mixed case are refused outright.
_PORTABLE_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[0-9]+)*$")

#: Substrings that must never appear in a contract record's field name. A
#: record that carries one of these is carrying material this phase forbids.
_SECRET_FIELD_TOKENS = (
    "k" + "ey",
    "mne" + "monic",
    "key" + "store",
    "pay" + "load",
    "pass" + "word",
    "pri" + "v",
    "r_" + "component",
    "s_" + "component",
    "v_" + "component",
    "secret",
    "private",
    "credential",
    "signature",
    "raw_signed_bytes",
    "seed",
)


def network_id_for_chain(chain_id: int) -> str:
    """The budget/network scope string an EVM chain id belongs to."""
    _positive_int(chain_id, field="chain_id")
    return f"evm:{chain_id}"


# --------------------------------------------------------------------------
# Primitive validators
# --------------------------------------------------------------------------


def _text(value: Any, *, field: str, pattern: re.Pattern[str], error: type[Exception]) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise error(f"{field}: {value!r} is not in canonical form")
    return value


def _digest(value: Any, *, field: str, error: type[Exception] = EnvelopeValidationError) -> str:
    return _text(value, field=field, pattern=_HEX64_RE, error=error)


def _address(value: Any, *, field: str, error: type[Exception] = EnvelopeValidationError) -> str:
    address = _text(value, field=field, pattern=_ADDRESS_RE, error=error)
    if int(address, 16) == 0:
        raise error(f"{field}: the zero address is not admissible")
    return address


def _non_negative_int(value: Any, *, field: str, error: type[Exception] = EnvelopeValidationError) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise error(f"{field}: must be an int >= 0, got {value!r}")
    return value


def _positive_int(value: Any, *, field: str, error: type[Exception] = EnvelopeValidationError) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise error(f"{field}: must be an int > 0, got {value!r}")
    return value


def _atomic(value: Any, *, field: str, positive: bool, error: type[Exception] = EnvelopeValidationError) -> int:
    amount = _positive_int(value, field=field, error=error) if positive else _non_negative_int(
        value, field=field, error=error
    )
    if amount > MAX_UINT256:
        raise error(f"{field}: {amount} exceeds uint256")
    return amount


def _portable(value: Any, *, field: str) -> str:
    """A token that means the same thing on every host.

    Machine names, filesystem paths, mutable URLs and clock readings are not
    portable identity and must never reach a digest that a future authority
    root is expected to pin.

    Shape alone cannot prove that a value is portable, and this function does
    not claim to. It refuses the shapes ambient identity actually arrives in --
    absolute paths, URLs, dotted host suffixes, whitespace, mixed case -- and
    the contract separately requires the value to be declared by the operator
    rather than discovered from the environment.
    """
    token = _text(value, field=field, pattern=_PORTABLE_RE, error=SessionIdentityError)
    if len(token) > 64:
        raise SessionIdentityError(f"{field}: token is too long to be an identity")
    return token


def _label(value: Any, *, field: str, error: type[Exception] = EnvelopeValidationError) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or value.strip() != value:
        raise error(f"{field}: must be a short non-empty label")
    return value


def assert_no_secret_bearing_fields(record_type: type) -> None:
    """Refuse any contract record whose shape could carry signing material.

    This is I-11 made mechanical at the type level: a record that grows a field
    named for a key, a signature, or raw signed bytes fails here, in a test,
    long before anything could populate it.
    """
    offenders = sorted(
        f.name
        for f in dataclass_fields(record_type)
        for token in _SECRET_FIELD_TOKENS
        if token in f.name.lower()
    )
    if offenders:
        raise EnvelopeValidationError(
            f"{record_type.__name__} declares forbidden fields {offenders}"
        )


# --------------------------------------------------------------------------
# Authority ladder
# --------------------------------------------------------------------------


class AuthorityLevel(IntEnum):
    """The monotone ladder. Authority only ever moves upward, by its own phase."""

    #: Reads and deterministic decisions only.
    SHADOW = 0
    #: May observe an externally created transaction and reconcile it. Cannot
    #: sign, cannot submit.
    RECONCILE_ONLY = 1
    #: May submit one already-signed, frozen transaction identity. Cannot
    #: create a signature and cannot modify the transaction bytes.
    SUBMIT_EXACT_SIGNED_BYTES = 2
    #: QntySpot may construct a validated envelope, a human-controlled account
    #: signs it, and QntySpot may submit only that exact validated identity.
    HUMAN_SIGNED_EXECUTION = 3
    #: A future, separately authorized signer with an independently rooted
    #: capital policy and a dedicated execution account.
    AUTONOMOUS_BOUNDED_SIGNER = 4


class Capability(str, Enum):
    OBSERVE_MARKET = "OBSERVE_MARKET"
    DECIDE_OFFLINE = "DECIDE_OFFLINE"
    OBSERVE_CHAIN = "OBSERVE_CHAIN"
    RECONCILE = "RECONCILE"
    ACCOUNT_QUARANTINE = "ACCOUNT_QUARANTINE"
    RESERVE_CAPITAL = "RESERVE_CAPITAL"
    SUBMIT_EXACT_BYTES = "SUBMIT_EXACT_BYTES"
    CONSTRUCT_ENVELOPE = "CONSTRUCT_ENVELOPE"
    AUTHORIZE_APPROVAL = "AUTHORIZE_APPROVAL"
    PRODUCE_SIGNATURE = "PRODUCE_SIGNATURE"


_L0 = frozenset({Capability.OBSERVE_MARKET, Capability.DECIDE_OFFLINE})
_L1 = _L0 | {
    Capability.OBSERVE_CHAIN,
    Capability.RECONCILE,
    Capability.ACCOUNT_QUARANTINE,
    Capability.RESERVE_CAPITAL,
}
_L2 = _L1 | {Capability.SUBMIT_EXACT_BYTES}
_L3 = _L2 | {Capability.CONSTRUCT_ENVELOPE, Capability.AUTHORIZE_APPROVAL}
_L4 = _L3 | {Capability.PRODUCE_SIGNATURE}

LADDER: Mapping[AuthorityLevel, frozenset[Capability]] = MappingProxyType(
    {
        AuthorityLevel.SHADOW: _L0,
        AuthorityLevel.RECONCILE_ONLY: _L1,
        AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES: _L2,
        AuthorityLevel.HUMAN_SIGNED_EXECUTION: _L3,
        AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER: _L4,
    }
)

#: I-10. What a kill switch, and equally a ``SAFE_HALT``, must leave working.
#: Everything outside this set creates a new external effect and is suspended.
KILL_SWITCH_PRESERVED_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.OBSERVE_MARKET,
        Capability.DECIDE_OFFLINE,
        Capability.OBSERVE_CHAIN,
        Capability.RECONCILE,
        Capability.ACCOUNT_QUARANTINE,
    }
)

#: The ceiling this phase grants at runtime. Program B is a contract freeze; it
#: grants none of levels 1 through 4.
PHASE_GRANTED_AUTHORITY_LEVEL = AuthorityLevel.SHADOW

assert set(LADDER) == set(AuthorityLevel), "the ladder must cover every level"
assert all(
    LADDER[lower] <= LADDER[higher]
    for lower, higher in zip(sorted(AuthorityLevel), sorted(AuthorityLevel)[1:])
), "the ladder must be monotone"


def granted_capabilities(
    level: AuthorityLevel, *, kill_switch_engaged: bool = False, safe_halted: bool = False
) -> frozenset[Capability]:
    """What this phase actually permits under the current halt state.

    ``LADDER`` is the design-time description of future levels. This public
    helper is an authorization result, so it applies the phase ceiling too.
    """
    if not isinstance(level, AuthorityLevel):
        raise AuthorityCeilingError(f"unknown authority level {level!r}")
    assert_phase_ceiling(level)
    capabilities = LADDER[level]
    if kill_switch_engaged or safe_halted:
        capabilities = capabilities & KILL_SWITCH_PRESERVED_CAPABILITIES
    return frozenset(capabilities)


def assert_phase_ceiling(level: AuthorityLevel) -> None:
    """Refuse any level above what this phase grants, whatever a document says."""
    if not isinstance(level, AuthorityLevel):
        raise AuthorityCeilingError(f"unknown authority level {level!r}")
    if level > PHASE_GRANTED_AUTHORITY_LEVEL:
        raise AuthorityCeilingError(
            f"{level.name} exceeds the granted phase ceiling "
            f"{PHASE_GRANTED_AUTHORITY_LEVEL.name}; "
            f"{CONTRACT_VERSION} grants no runtime authority above SHADOW"
        )


def require_capability(
    capability: Capability,
    level: AuthorityLevel,
    *,
    kill_switch_engaged: bool = False,
    safe_halted: bool = False,
) -> None:
    """The single gate. It applies the phase ceiling before anything else.

    A caller cannot reach a signing, approval, or submission capability in this
    phase by supplying a higher ``level``: the phase ceiling is checked first
    and it is a constant in this source tree, not an input.
    """
    if not isinstance(capability, Capability):
        raise AuthorityCeilingError(f"unknown capability {capability!r}")
    assert_phase_ceiling(level)
    permitted = granted_capabilities(
        level, kill_switch_engaged=kill_switch_engaged, safe_halted=safe_halted
    )
    if capability not in permitted:
        raise AuthorityCeilingError(
            f"{capability.value} is not permitted at {level.name}"
            + (" while the kill switch is engaged" if kill_switch_engaged else "")
            + (" while halted" if safe_halted else "")
        )


# --------------------------------------------------------------------------
# Independently rooted authority (I-09)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuthorityPolicyRefV0:
    """A reference to an authority grant issued OUTSIDE this source tree.

    I-09 is mechanical because the grant pins ``permitted_repository_commit``
    and ``permitted_implementation_digest``. Editing QntySpot changes the
    implementation digest, which invalidates every existing grant; the only way
    to obtain a grant for the new code is for the independently rooted
    authority to issue one. A source change therefore cannot raise its own
    ceiling.

    ``authority_root_id`` names that root. This phase implements no authority
    service, performs no verification against a root, and grants nothing: it
    freezes the shape the future service must satisfy.
    """

    authority_root_id: str
    granted_level: AuthorityLevel
    permitted_repository_commit: str
    permitted_implementation_digest: str
    permitted_network_id: str
    permitted_taker_address: str
    permitted_venue_id: str
    max_reservation_atomic: int
    max_cumulative_atomic: int
    not_before_epoch_s: int
    not_after_epoch_s: int
    schema: str = CONTRACT_SCHEMA + ".authority_policy"

    def __post_init__(self) -> None:
        _portable(self.authority_root_id, field="authority_root_id")
        if not isinstance(self.granted_level, AuthorityLevel):
            raise AuthorityCeilingError(f"unknown granted_level {self.granted_level!r}")
        _text(
            self.permitted_repository_commit,
            field="permitted_repository_commit",
            pattern=_COMMIT_RE,
            error=AuthorityCeilingError,
        )
        _digest(
            self.permitted_implementation_digest,
            field="permitted_implementation_digest",
            error=AuthorityCeilingError,
        )
        _label(self.permitted_network_id, field="permitted_network_id", error=AuthorityCeilingError)
        _address(self.permitted_taker_address, field="permitted_taker_address", error=AuthorityCeilingError)
        _portable(self.permitted_venue_id, field="permitted_venue_id")
        _atomic(self.max_reservation_atomic, field="max_reservation_atomic", positive=True, error=AuthorityCeilingError)
        _atomic(self.max_cumulative_atomic, field="max_cumulative_atomic", positive=True, error=AuthorityCeilingError)
        if self.max_reservation_atomic > self.max_cumulative_atomic:
            raise AuthorityCeilingError("max_reservation must not exceed max_cumulative")
        _non_negative_int(self.not_before_epoch_s, field="not_before_epoch_s", error=AuthorityCeilingError)
        _positive_int(self.not_after_epoch_s, field="not_after_epoch_s", error=AuthorityCeilingError)
        if self.not_after_epoch_s <= self.not_before_epoch_s:
            raise AuthorityCeilingError("an authority grant must expire after it begins")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "authority_root_id": self.authority_root_id,
            "granted_level": int(self.granted_level),
            "max_cumulative_atomic": str(self.max_cumulative_atomic),
            "max_reservation_atomic": str(self.max_reservation_atomic),
            "not_after_epoch_s": self.not_after_epoch_s,
            "not_before_epoch_s": self.not_before_epoch_s,
            "permitted_implementation_digest": self.permitted_implementation_digest,
            "permitted_network_id": self.permitted_network_id,
            "permitted_repository_commit": self.permitted_repository_commit,
            "permitted_taker_address": self.permitted_taker_address,
            "permitted_venue_id": self.permitted_venue_id,
            "schema": self.schema,
        }

    @property
    def authority_policy_digest(self) -> str:
        return digest_object(self.canonical_object())

    def assert_valid_at(self, now_epoch_s: int) -> None:
        _non_negative_int(now_epoch_s, field="now_epoch_s", error=AuthorityCeilingError)
        if not (self.not_before_epoch_s <= now_epoch_s < self.not_after_epoch_s):
            raise AuthorityCeilingError(
                f"authority grant is not valid at {now_epoch_s}"
            )


# --------------------------------------------------------------------------
# ExecutionSessionV0 (I-14)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExecutionSessionV0:
    """One execution runtime session bound to immutable identity.

    IDENTITY vs INSTANCE
    --------------------
    ``identity_digest`` covers only fields that mean the same thing on every
    host: the commit, the implementation digest, a portable runtime token, the
    database schema version, the policy, the authority-policy digest, the
    taker, the network, and the venue adapter version. It deliberately excludes
    filesystem paths, machine names, RPC URLs, and wall-clock readings, because
    a future authority root is expected to pin ``identity_digest`` and an
    ambient input would make that pin unpinnable.

    ``session_id`` additionally binds the explicitly supplied
    ``started_at_epoch_s`` and ``session_ordinal``, so two runs of the same
    binary are distinguishable while both remain deterministic. No clock is
    read here; the caller passes the time.
    """

    repository_commit: str
    implementation_digest: str
    runtime_identity: str
    db_schema_version: int
    policy_id: str
    authority_policy_digest: str
    taker_address: str
    network_id: str
    venue_id: str
    venue_adapter_version: str
    started_at_epoch_s: int
    session_ordinal: int = 0
    schema: str = CONTRACT_SCHEMA + ".session"

    def __post_init__(self) -> None:
        _text(
            self.repository_commit,
            field="repository_commit",
            pattern=_COMMIT_RE,
            error=SessionIdentityError,
        )
        _digest(self.implementation_digest, field="implementation_digest", error=SessionIdentityError)
        _portable(self.runtime_identity, field="runtime_identity")
        _non_negative_int(self.db_schema_version, field="db_schema_version", error=SessionIdentityError)
        _digest(self.policy_id, field="policy_id", error=SessionIdentityError)
        _digest(self.authority_policy_digest, field="authority_policy_digest", error=SessionIdentityError)
        _address(self.taker_address, field="taker_address", error=SessionIdentityError)
        _label(self.network_id, field="network_id", error=SessionIdentityError)
        _portable(self.venue_id, field="venue_id")
        _portable(self.venue_adapter_version, field="venue_adapter_version")
        _non_negative_int(self.started_at_epoch_s, field="started_at_epoch_s", error=SessionIdentityError)
        _non_negative_int(self.session_ordinal, field="session_ordinal", error=SessionIdentityError)

    def identity_object(self) -> dict[str, Any]:
        """Portable identity only. Nothing ambient may appear here."""
        return {
            "authority_policy_digest": self.authority_policy_digest,
            "db_schema_version": self.db_schema_version,
            "implementation_digest": self.implementation_digest,
            "network_id": self.network_id,
            "policy_id": self.policy_id,
            "repository_commit": self.repository_commit,
            "runtime_identity": self.runtime_identity,
            "schema": self.schema,
            "taker_address": self.taker_address,
            "venue_adapter_version": self.venue_adapter_version,
            "venue_id": self.venue_id,
        }

    @property
    def identity_digest(self) -> str:
        return digest_object(self.identity_object())

    @property
    def session_id(self) -> str:
        return digest_object(
            {
                "identity_digest": self.identity_digest,
                "schema": self.schema + ".instance",
                "session_ordinal": self.session_ordinal,
                "started_at_epoch_s": self.started_at_epoch_s,
            }
        )

    @property
    def chain_id(self) -> int:
        match = re.match(r"^evm:([1-9][0-9]*)$", self.network_id)
        if match is None:
            raise SessionIdentityError(
                f"network_id {self.network_id!r} is not an EVM network scope"
            )
        return int(match.group(1))


def _assert_authority_session_binding(
    session: ExecutionSessionV0,
    authority: AuthorityPolicyRefV0,
    *,
    now_epoch_s: int,
    error: type[Exception],
) -> None:
    """Apply the same independently-rooted authority binding to every action."""
    if session.authority_policy_digest != authority.authority_policy_digest:
        raise error("session was bound to a different authority policy")
    if authority.permitted_repository_commit != session.repository_commit:
        raise error("the authority grant does not cover this repository commit")
    if authority.permitted_implementation_digest != session.implementation_digest:
        raise error("the authority grant does not cover this implementation digest")
    if authority.permitted_network_id != session.network_id:
        raise error("the authority grant does not cover this network")
    if authority.permitted_taker_address != session.taker_address:
        raise error("the authority grant does not cover this taker")
    if authority.permitted_venue_id != session.venue_id:
        raise error("the authority grant does not cover this venue")
    _non_negative_int(now_epoch_s, field="now_epoch_s", error=error)
    if not (authority.not_before_epoch_s <= now_epoch_s < authority.not_after_epoch_s):
        raise error(f"authority grant is not valid at {now_epoch_s}")


# --------------------------------------------------------------------------
# ExecutionEnvelopeV0
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExecutionEnvelopeV0:
    """The exact unsigned transaction intent a future signer may evaluate.

    THE FOUR-WAY PARTITION
    ----------------------
                IDENTITY    Everything that determines what the chain would do, plus who
                authorized it: stable session identity, economic action, chain, taker, both
                instruments, the economic bounds, the transaction target, its
                value, the calldata digest and length, the allowance target,
                the nonce, the gas and fee ceilings, the deadline, and the
                authority-policy digest. These, and only these, form
                ``envelope_id``.
    EVIDENCE    What justified constructing it: the plan, the quote, the quote
                observation digest, the venue block number, and the explicit
                construction time. Bound and digested separately. Two envelopes
                whose evidence differs but whose identity is byte-identical are
                the same envelope; that is the property that makes crash
                recovery reconstruct rather than duplicate.
    OBSERVATION Mutable external readings (allowances, balances, head block).
                They live on approval and chain-observation records, never
                here, because an envelope whose identity moved when the chain
                moved could not be pinned by a signer.
    AUTHORITY   ``authority_policy_digest``. It is identity, not evidence: an
                envelope authorized under one grant is not the same envelope
                under another.

    Deliberately absent: any raw signed bytes, any signature component, any key
    material, any provider URL. A signer evaluates this record; it never
    travels back through it.
    """

    # The originating instance is provenance. It is deliberately excluded
    # from envelope identity so a restart can reconstruct the same action.
    session_id: str
    session_identity_digest: str
    economic_action_id: str
    chain_id: int
    taker_address: str
    input_instrument_id: str
    output_instrument_id: str
    max_input_atomic: int
    min_output_atomic: int
    transaction_to: str
    transaction_value_atomic: int
    calldata_sha256: str
    calldata_length: int
    allowance_target: str | None
    account_nonce: int
    gas_limit_ceiling: int
    max_fee_per_gas_ceiling_atomic: int
    max_priority_fee_per_gas_ceiling_atomic: int
    deadline_epoch_s: int
    authority_policy_digest: str
    # -- evidence, excluded from identity --------------------------------
    plan_id: str
    quote_id: str
    quote_observation_digest: str
    venue_block_number: int
    constructed_at_epoch_s: int
    schema: str = CONTRACT_SCHEMA + ".envelope"

    def __post_init__(self) -> None:
        _digest(self.session_id, field="session_id")
        _digest(self.session_identity_digest, field="session_identity_digest")
        _digest(self.economic_action_id, field="economic_action_id")
        _positive_int(self.chain_id, field="chain_id")
        _address(self.taker_address, field="taker_address")
        _label(self.input_instrument_id, field="input_instrument_id")
        _label(self.output_instrument_id, field="output_instrument_id")
        if self.input_instrument_id == self.output_instrument_id:
            raise EnvelopeValidationError("input and output instruments must differ")
        _atomic(self.max_input_atomic, field="max_input_atomic", positive=True)
        _atomic(self.min_output_atomic, field="min_output_atomic", positive=True)
        _address(self.transaction_to, field="transaction_to")
        _atomic(self.transaction_value_atomic, field="transaction_value_atomic", positive=False)
        _digest(self.calldata_sha256, field="calldata_sha256")
        _positive_int(self.calldata_length, field="calldata_length")
        if self.allowance_target is not None:
            _address(self.allowance_target, field="allowance_target")
        _non_negative_int(self.account_nonce, field="account_nonce")
        _positive_int(self.gas_limit_ceiling, field="gas_limit_ceiling")
        _atomic(self.max_fee_per_gas_ceiling_atomic, field="max_fee_per_gas_ceiling_atomic", positive=True)
        _atomic(
            self.max_priority_fee_per_gas_ceiling_atomic,
            field="max_priority_fee_per_gas_ceiling_atomic",
            positive=False,
        )
        if self.max_priority_fee_per_gas_ceiling_atomic > self.max_fee_per_gas_ceiling_atomic:
            raise EnvelopeValidationError("priority fee ceiling must not exceed the fee ceiling")
        _positive_int(self.deadline_epoch_s, field="deadline_epoch_s")
        _digest(self.authority_policy_digest, field="authority_policy_digest")
        _digest(self.plan_id, field="plan_id")
        _label(self.quote_id, field="quote_id")
        _digest(self.quote_observation_digest, field="quote_observation_digest")
        _non_negative_int(self.venue_block_number, field="venue_block_number")
        _non_negative_int(self.constructed_at_epoch_s, field="constructed_at_epoch_s")

    def identity_object(self) -> dict[str, Any]:
        return {
            "account_nonce": self.account_nonce,
            "allowance_target": self.allowance_target,
            "authority_policy_digest": self.authority_policy_digest,
            "calldata_length": self.calldata_length,
            "calldata_sha256": self.calldata_sha256,
            "chain_id": self.chain_id,
            "deadline_epoch_s": self.deadline_epoch_s,
            "economic_action_id": self.economic_action_id,
            "gas_limit_ceiling": self.gas_limit_ceiling,
            "input_instrument_id": self.input_instrument_id,
            "max_fee_per_gas_ceiling_atomic": str(self.max_fee_per_gas_ceiling_atomic),
            "max_input_atomic": str(self.max_input_atomic),
            "max_priority_fee_per_gas_ceiling_atomic": str(
                self.max_priority_fee_per_gas_ceiling_atomic
            ),
            "min_output_atomic": str(self.min_output_atomic),
            "output_instrument_id": self.output_instrument_id,
            "schema": self.schema,
            "session_identity_digest": self.session_identity_digest,
            "taker_address": self.taker_address,
            "transaction_to": self.transaction_to,
            "transaction_value_atomic": str(self.transaction_value_atomic),
        }

    def evidence_object(self) -> dict[str, Any]:
        return {
            "constructed_at_epoch_s": self.constructed_at_epoch_s,
            "plan_id": self.plan_id,
            "quote_id": self.quote_id,
            "quote_observation_digest": self.quote_observation_digest,
            "schema": self.schema + ".evidence",
            "venue_block_number": self.venue_block_number,
        }

    @property
    def envelope_id(self) -> str:
        """Identity only. Reconstructing the same intent yields the same id."""
        return digest_object(self.identity_object())

    @property
    def evidence_digest(self) -> str:
        return digest_object(self.evidence_object())

    @property
    def network_id(self) -> str:
        return network_id_for_chain(self.chain_id)


# --------------------------------------------------------------------------
# ApprovalActionV0 (I-13)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApprovalActionV0:
    """An ERC-20 approval modelled as its own external action.

    An approval moves no capital by itself, but it grants a third-party
    contract the standing ability to move capital. That makes it an external
    effect with its own identity, its own authority requirement, its own
    lifecycle, its own receipt, and its own reconciliation. It is never an
    incidental helper call inside a swap path.

    V0 REFUSALS, ENFORCED HERE
    --------------------------
    * unlimited allowance is refused: ``requested_allowance_atomic`` must be a
      concrete amount and must not be the uint256 maximum
    * Permit2 is not authorized: this record has no permit, no off-chain
      signature, and no deadline-signed structure to carry one
    * a Settler approval is not authorized: the spender must be the exact
      allowance target the current venue response reports for this action
    """

    # The originating instance is provenance; stable session identity is used
    # for approval identity so restart reconstruction cannot create a new
    # external action merely because its start time changed.
    session_id: str
    session_identity_digest: str
    taker_address: str
    token_address: str
    spender_address: str
    requested_allowance_atomic: int
    observed_prior_allowance_atomic: int
    authority_policy_digest: str
    deadline_epoch_s: int
    economic_action_id: str | None = None
    schema: str = CONTRACT_SCHEMA + ".approval"

    def __post_init__(self) -> None:
        _digest(self.session_id, field="session_id", error=ApprovalContractError)
        _digest(
            self.session_identity_digest,
            field="session_identity_digest",
            error=ApprovalContractError,
        )
        _address(self.taker_address, field="taker_address", error=ApprovalContractError)
        _address(self.token_address, field="token_address", error=ApprovalContractError)
        _address(self.spender_address, field="spender_address", error=ApprovalContractError)
        _atomic(
            self.requested_allowance_atomic,
            field="requested_allowance_atomic",
            positive=True,
            error=ApprovalContractError,
        )
        if self.requested_allowance_atomic == MAX_UINT256:
            raise ApprovalContractError(
                "V0 refuses an unlimited allowance; approve the exact amount"
            )
        _atomic(
            self.observed_prior_allowance_atomic,
            field="observed_prior_allowance_atomic",
            positive=False,
            error=ApprovalContractError,
        )
        _positive_int(self.deadline_epoch_s, field="deadline_epoch_s", error=ApprovalContractError)
        _digest(self.authority_policy_digest, field="authority_policy_digest", error=ApprovalContractError)
        if self.economic_action_id is not None:
            _digest(self.economic_action_id, field="economic_action_id", error=ApprovalContractError)

    def identity_object(self) -> dict[str, Any]:
        return {
            "authority_policy_digest": self.authority_policy_digest,
            "economic_action_id": self.economic_action_id,
            "requested_allowance_atomic": str(self.requested_allowance_atomic),
            "schema": self.schema,
            "session_identity_digest": self.session_identity_digest,
            "spender_address": self.spender_address,
            "taker_address": self.taker_address,
            "token_address": self.token_address,
        }

    @property
    def approval_action_id(self) -> str:
        return digest_object(self.identity_object())


# --------------------------------------------------------------------------
# Signed transaction and submission identity (I-02, I-05, I-07, I-11)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SignedTransactionRecordV0:
    """The identity of one signed transaction. Never its bytes.

    This record stores a digest of the signed payload, its length, its
    transaction hash, and a non-secret label for who signed. It carries no key
    material and no signature components, so a database dump, a backup, or a
    replay artefact cannot leak anything that could be replayed by a third
    party beyond what the chain already publishes.

    EXACT-BYTE RETRANSMISSION
    -------------------------
    ``signed_transaction_id`` is a function of the envelope identity and the
    digest of the signed payload alone. Retransmitting the identical signed
    payload therefore produces the identical id: it is the same signed
    transaction, not a new economic action. Building a different payload for
    the same economic action produces a different id, and the database refuses
    it, which is I-02 and I-05 enforced by the engine rather than by care.

    Retransmission itself is not authorized by this contract. The identity is
    frozen now so that a future study of it cannot quietly become a retry.
    """

    envelope_id: str
    raw_signed_sha256: str
    raw_signed_length: int
    transaction_hash: str
    chain_id: int
    account_nonce: int
    taker_address: str
    signer_identity: str
    schema: str = CONTRACT_SCHEMA + ".signed_transaction"

    def __post_init__(self) -> None:
        _digest(self.envelope_id, field="envelope_id")
        _digest(self.raw_signed_sha256, field="raw_signed_sha256")
        _positive_int(self.raw_signed_length, field="raw_signed_length")
        _text(self.transaction_hash, field="transaction_hash", pattern=_TX_HASH_RE, error=EnvelopeValidationError)
        _positive_int(self.chain_id, field="chain_id")
        _non_negative_int(self.account_nonce, field="account_nonce")
        _address(self.taker_address, field="taker_address")
        _portable(self.signer_identity, field="signer_identity")

    @property
    def signed_transaction_id(self) -> str:
        return digest_object(
            {
                "envelope_id": self.envelope_id,
                "raw_signed_sha256": self.raw_signed_sha256,
                "schema": self.schema,
            }
        )


class SubmissionAcknowledgment(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class SubmissionAttemptV0:
    """One attempt to hand a frozen signed identity to one provider.

    I-07: ``ACCEPTED`` means a provider said it took the bytes. It is not
    inclusion, not confirmation, and not settlement. ``REJECTED`` is not proof
    the transaction cannot land either, because another provider may already
    hold it. Only ``evaluate_chain_truth`` may draw a settlement conclusion.
    """

    signed_transaction_id: str
    provider_id: str
    attempt_ordinal: int
    submitted_at_epoch_s: int
    acknowledgment: SubmissionAcknowledgment
    provider_reported_hash: str | None = None
    error_class: str | None = None
    schema: str = CONTRACT_SCHEMA + ".submission_attempt"

    def __post_init__(self) -> None:
        _digest(self.signed_transaction_id, field="signed_transaction_id")
        _portable(self.provider_id, field="provider_id")
        _non_negative_int(self.attempt_ordinal, field="attempt_ordinal")
        _non_negative_int(self.submitted_at_epoch_s, field="submitted_at_epoch_s")
        if not isinstance(self.acknowledgment, SubmissionAcknowledgment):
            raise EnvelopeValidationError(f"unknown acknowledgment {self.acknowledgment!r}")
        if self.provider_reported_hash is not None:
            _text(
                self.provider_reported_hash,
                field="provider_reported_hash",
                pattern=_TX_HASH_RE,
                error=EnvelopeValidationError,
            )
        if self.error_class is not None:
            _label(self.error_class, field="error_class")

    @property
    def submission_attempt_id(self) -> str:
        return digest_object(
            {
                "attempt_ordinal": self.attempt_ordinal,
                "provider_id": self.provider_id,
                "schema": self.schema,
                "signed_transaction_id": self.signed_transaction_id,
            }
        )

    def assert_hash_agreement(self, expected_transaction_hash: str) -> None:
        """A provider that names a different hash has not acknowledged this action."""
        if (
            self.provider_reported_hash is not None
            and self.provider_reported_hash != expected_transaction_hash
        ):
            raise ChainTruthError(
                "provider acknowledged a different transaction hash; "
                "the submission outcome is unknown"
            )


# --------------------------------------------------------------------------
# Chain observation and the finality contract (I-06, I-07)
# --------------------------------------------------------------------------


class ChainPresence(str, Enum):
    ABSENT = "ABSENT"
    PENDING = "PENDING"
    INCLUDED = "INCLUDED"


class ReceiptStatus(str, Enum):
    SUCCESS = "SUCCESS"
    REVERTED = "REVERTED"


@dataclass(frozen=True, slots=True)
class ChainObservationV0:
    """One provider's reading of one transaction at one explicit moment.

    Every field is a fact about the reading, so every field is identity. Two
    providers that disagree produce two records, and the disagreement is
    resolved by refusing to conclude, never by preferring one of them.
    """

    provider_id: str
    transaction_hash: str
    observed_at_epoch_s: int
    presence: ChainPresence
    raw_evidence_sha256: str
    block_number: int | None = None
    block_hash: str | None = None
    block_parent_hash: str | None = None
    head_block_number: int | None = None
    head_block_hash: str | None = None
    receipt_status: ReceiptStatus | None = None
    effective_input_atomic: int | None = None
    effective_output_atomic: int | None = None
    schema: str = CONTRACT_SCHEMA + ".chain_observation"

    def __post_init__(self) -> None:
        _portable(self.provider_id, field="provider_id")
        _text(self.transaction_hash, field="transaction_hash", pattern=_TX_HASH_RE, error=ChainTruthError)
        _non_negative_int(self.observed_at_epoch_s, field="observed_at_epoch_s", error=ChainTruthError)
        if not isinstance(self.presence, ChainPresence):
            raise ChainTruthError(f"unknown presence {self.presence!r}")
        _digest(self.raw_evidence_sha256, field="raw_evidence_sha256", error=ChainTruthError)
        included = self.presence is ChainPresence.INCLUDED
        block_fields = (self.block_number, self.block_hash, self.block_parent_hash)
        if included:
            if any(value is None for value in block_fields) or self.receipt_status is None:
                raise ChainTruthError(
                    "an INCLUDED observation must carry block identity and a receipt status"
                )
            _non_negative_int(self.block_number, field="block_number", error=ChainTruthError)
            _text(self.block_hash, field="block_hash", pattern=_TX_HASH_RE, error=ChainTruthError)
            _text(
                self.block_parent_hash,
                field="block_parent_hash",
                pattern=_TX_HASH_RE,
                error=ChainTruthError,
            )
            if not isinstance(self.receipt_status, ReceiptStatus):
                raise ChainTruthError(f"unknown receipt_status {self.receipt_status!r}")
        else:
            if any(value is not None for value in block_fields) or self.receipt_status is not None:
                raise ChainTruthError(
                    f"a {self.presence.value} observation must not carry block identity"
                )
        if (self.head_block_number is None) != (self.head_block_hash is None):
            raise ChainTruthError("head block number and hash must be observed together")
        if self.head_block_number is not None:
            _non_negative_int(self.head_block_number, field="head_block_number", error=ChainTruthError)
            _text(self.head_block_hash, field="head_block_hash", pattern=_TX_HASH_RE, error=ChainTruthError)
            if included and self.head_block_number < self.block_number:
                raise ChainTruthError("head block precedes the inclusion block")
        settled = included and self.receipt_status is ReceiptStatus.SUCCESS
        amounts = (self.effective_input_atomic, self.effective_output_atomic)
        if settled:
            if any(value is None for value in amounts):
                raise ChainTruthError("a successful receipt must carry both effective amounts")
            _atomic(self.effective_input_atomic, field="effective_input_atomic", positive=True, error=ChainTruthError)
            _atomic(self.effective_output_atomic, field="effective_output_atomic", positive=True, error=ChainTruthError)
        elif any(value is not None for value in amounts):
            raise ChainTruthError("effective amounts require a successful receipt")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "block_hash": self.block_hash,
            "block_number": self.block_number,
            "block_parent_hash": self.block_parent_hash,
            "effective_input_atomic": None
            if self.effective_input_atomic is None
            else str(self.effective_input_atomic),
            "effective_output_atomic": None
            if self.effective_output_atomic is None
            else str(self.effective_output_atomic),
            "head_block_hash": self.head_block_hash,
            "head_block_number": self.head_block_number,
            "observed_at_epoch_s": self.observed_at_epoch_s,
            "presence": self.presence.value,
            "provider_id": self.provider_id,
            "raw_evidence_sha256": self.raw_evidence_sha256,
            "receipt_status": None if self.receipt_status is None else self.receipt_status.value,
            "schema": self.schema,
            "transaction_hash": self.transaction_hash,
        }

    @property
    def observation_id(self) -> str:
        return digest_object(self.canonical_object())

    @property
    def settlement_facts(self) -> tuple[Any, ...]:
        """The subset providers must agree on before anything may be concluded."""
        return (
            self.block_number,
            self.block_hash,
            self.block_parent_hash,
            None if self.receipt_status is None else self.receipt_status.value,
            self.effective_input_atomic,
            self.effective_output_atomic,
        )


@dataclass(frozen=True, slots=True)
class FinalityPolicyV0:
    """What evidence a claim about settlement requires.

    ``min_confirmation_depth`` supports exactly one claim: *the block that
    included this transaction is at least N blocks behind every agreeing
    provider's head*. It is a technical anti-replacement bound on one chain's
    own history. It is not an L1 finality claim, not a data-availability
    claim, and not a sequencer-safety claim; those remain deferred.

    ``min_agreeing_providers`` is I-07 made quantitative: the actor is not
    permitted to be the only verifier.
    """

    min_confirmation_depth: int
    min_agreeing_providers: int
    schema: str = CONTRACT_SCHEMA + ".finality_policy"

    def __post_init__(self) -> None:
        _positive_int(self.min_confirmation_depth, field="min_confirmation_depth", error=ChainTruthError)
        _positive_int(self.min_agreeing_providers, field="min_agreeing_providers", error=ChainTruthError)

    def canonical_object(self) -> dict[str, Any]:
        return {
            "min_agreeing_providers": self.min_agreeing_providers,
            "min_confirmation_depth": self.min_confirmation_depth,
            "schema": self.schema,
        }


#: The frozen requirement for a future Robinhood Chain dust experiment. Two
#: independently operated providers must agree, and the inclusion block must be
#: 32 blocks behind both heads. If chain 4663 turns out to expose only one
#: usable provider, a dust experiment cannot reach CONFIRMED under this policy
#: and must halt; establishing that is matrix stage D, not an assumption.
ROBINHOOD_V0_FINALITY = FinalityPolicyV0(min_confirmation_depth=32, min_agreeing_providers=2)


class ChainTruthVerdict(str, Enum):
    NO_EVIDENCE = "NO_EVIDENCE"
    VISIBLE = "VISIBLE"
    INCLUDED = "INCLUDED"
    CONFIRMED = "CONFIRMED"
    REVERTED = "REVERTED"
    AMBIGUOUS = "AMBIGUOUS"


class EconomicActionIDV0(str):
    """A runtime type marker preventing approval IDs entering settlement."""

    def __new__(cls, value: str) -> "EconomicActionIDV0":
        _digest(value, field="economic_action_id", error=ChainTruthError)
        return str.__new__(cls, value)


@dataclass(frozen=True, slots=True)
class SettlementExpectationV0:
    """What the local ledger believes it asked the chain to do."""

    # This expectation is intentionally economic-only: its only consumer that
    # can produce a FillReceiptV0 must never accept an ApprovalAction ID.
    economic_action_id: EconomicActionIDV0
    transaction_hash: str
    chain_id: int
    taker_address: str
    submission_acknowledged: bool
    schema: str = CONTRACT_SCHEMA + ".settlement_expectation"

    def __post_init__(self) -> None:
        if not isinstance(self.economic_action_id, EconomicActionIDV0):
            raise ChainTruthError(
                "settlement expectations require an EconomicActionIDV0, not an external action ID"
            )
        _text(self.transaction_hash, field="transaction_hash", pattern=_TX_HASH_RE, error=ChainTruthError)
        _positive_int(self.chain_id, field="chain_id", error=ChainTruthError)
        _address(self.taker_address, field="taker_address", error=ChainTruthError)
        if not isinstance(self.submission_acknowledged, bool):
            raise ChainTruthError("submission_acknowledged must be a bool")


_SETTLEMENT_BINDING_TOKEN = object()


@dataclass(frozen=True, slots=True)
class ValidatedEconomicActionV0:
    """Database-bound settlement identity required to mint a fill receipt.

    A digest-shaped string is not sufficient to prove that an external action
    is an economic action: approval identities have the same representation.
    The runtime creates this opaque binding only after it has validated the
    corresponding SQLite external-action and signed-transaction rows.
    """

    economic_action_id: EconomicActionIDV0
    transaction_hash: str
    chain_id: int
    taker_address: str
    _token: object = field(default=None, repr=False, compare=False)

    def assert_matches(self, expectation: SettlementExpectationV0) -> None:
        if self._token is not _SETTLEMENT_BINDING_TOKEN:
            raise ChainTruthError("settlement binding was not produced by the ledger runtime")
        if (
            self.economic_action_id != expectation.economic_action_id
            or self.transaction_hash != expectation.transaction_hash
            or self.chain_id != expectation.chain_id
            or self.taker_address != expectation.taker_address
        ):
            raise ChainTruthError("database settlement binding disagrees with the expectation")


def _validated_economic_action_from_database(
    economic_action_id: EconomicActionIDV0,
    transaction_hash: str,
    chain_id: int,
    taker_address: str,
) -> "ValidatedEconomicActionV0":
    return ValidatedEconomicActionV0(
        economic_action_id=economic_action_id,
        transaction_hash=transaction_hash,
        chain_id=chain_id,
        taker_address=taker_address,
        _token=_SETTLEMENT_BINDING_TOKEN,
    )


@dataclass(frozen=True, slots=True)
class ChainTruthV0:
    """The only conclusion the contract permits to be drawn from observations.

    The action, transaction, chain, and taker are copied from the expectation
    so a truth object cannot be paired with a different settlement request.
    """

    external_action_id: str
    transaction_hash: str
    chain_id: int
    taker_address: str
    verdict: ChainTruthVerdict
    agreeing_provider_count: int
    confirmation_depth: int
    block_hash: str | None
    receipt_status: ReceiptStatus | None
    effective_input_atomic: int | None
    effective_output_atomic: int | None
    evidence_digest: str


def _latest_by_provider(
    observations: Sequence[ChainObservationV0],
) -> dict[str, ChainObservationV0]:
    latest: dict[str, ChainObservationV0] = {}
    for observation in sorted(
        observations, key=lambda o: (o.observed_at_epoch_s, o.observation_id)
    ):
        latest[observation.provider_id] = observation
    return latest


def evaluate_chain_truth(
    expectation: SettlementExpectationV0,
    observations: Sequence[ChainObservationV0],
    finality: FinalityPolicyV0,
) -> ChainTruthV0:
    """Draw the strongest conclusion the evidence supports, and no stronger.

    Contradiction always wins. A provider that changed its mind about which
    block included the transaction, two providers that disagree about the
    block or the amounts, or a provider reporting absence while another
    reports inclusion, all yield ``AMBIGUOUS``. Absence everywhere after an
    acknowledged submission is also ``AMBIGUOUS``: the contract never converts
    "we cannot find it" into "it did not happen".
    """
    if not isinstance(expectation, SettlementExpectationV0):
        raise ChainTruthError("expectation must be a SettlementExpectationV0")
    if not isinstance(finality, FinalityPolicyV0):
        raise ChainTruthError("finality must be a FinalityPolicyV0")
    records = tuple(observations)
    for observation in records:
        if not isinstance(observation, ChainObservationV0):
            raise ChainTruthError("observations must be ChainObservationV0 records")
        if observation.transaction_hash != expectation.transaction_hash:
            raise ChainTruthError(
                "an observation of a different transaction cannot settle this action"
            )

    evidence_digest = digest_object(
        {
            "expectation": {
                "chain_id": expectation.chain_id,
                "economic_action_id": expectation.economic_action_id,
                "submission_acknowledged": expectation.submission_acknowledged,
                "taker_address": expectation.taker_address,
                "transaction_hash": expectation.transaction_hash,
            },
            "finality": finality.canonical_object(),
            "observations": sorted(
                (o.canonical_object() for o in records),
                key=lambda obj: digest_object(obj),
            ),
            "schema": CONTRACT_SCHEMA + ".chain_truth_evidence",
        }
    )

    def verdict_of(
        verdict: ChainTruthVerdict,
        *,
        agreeing: int = 0,
        depth: int = 0,
        included: ChainObservationV0 | None = None,
    ) -> ChainTruthV0:
        return ChainTruthV0(
            external_action_id=expectation.economic_action_id,
            transaction_hash=expectation.transaction_hash,
            chain_id=expectation.chain_id,
            taker_address=expectation.taker_address,
            verdict=verdict,
            agreeing_provider_count=agreeing,
            confirmation_depth=depth,
            block_hash=None if included is None else included.block_hash,
            receipt_status=None if included is None else included.receipt_status,
            effective_input_atomic=None if included is None else included.effective_input_atomic,
            effective_output_atomic=None if included is None else included.effective_output_atomic,
            evidence_digest=evidence_digest,
        )

    latest = _latest_by_provider(records)
    latest_records = tuple(latest.values())
    included_records = [o for o in latest_records if o.presence is ChainPresence.INCLUDED]
    historical_included_records = [o for o in records if o.presence is ChainPresence.INCLUDED]
    fact_sets = {o.settlement_facts for o in historical_included_records}
    if len(fact_sets) > 1:
        return verdict_of(ChainTruthVerdict.AMBIGUOUS)

    # An inclusion followed by a later PENDING/ABSENT reading is a reorg or a
    # contradictory provider result. Stale inclusion history must never be
    # allowed to confirm the action, but it must also not be silently erased.
    for provider, observation in latest.items():
        if observation.presence is not ChainPresence.INCLUDED and any(
            prior.provider_id == provider and prior.presence is ChainPresence.INCLUDED
            for prior in records
        ):
            return verdict_of(ChainTruthVerdict.AMBIGUOUS)

    absent_providers = {
        provider for provider, o in latest.items() if o.presence is ChainPresence.ABSENT
    }
    non_included_providers = {
        provider for provider, o in latest.items() if o.presence is not ChainPresence.INCLUDED
    }
    if included_records and (absent_providers or non_included_providers):
        return verdict_of(ChainTruthVerdict.AMBIGUOUS)

    if not included_records:
        if any(o.presence is ChainPresence.PENDING for o in records):
            return verdict_of(ChainTruthVerdict.VISIBLE)
        if expectation.submission_acknowledged:
            # Acknowledged and then invisible. This is exactly the state in
            # which a naive runtime would rebuild and resend. I-05 forbids it.
            return verdict_of(ChainTruthVerdict.AMBIGUOUS)
        return verdict_of(ChainTruthVerdict.NO_EVIDENCE)

    exemplar = included_records[0]
    agreeing_providers = sorted({o.provider_id for o in included_records})
    agreeing = len(agreeing_providers)
    if agreeing < finality.min_agreeing_providers:
        return verdict_of(ChainTruthVerdict.VISIBLE, agreeing=agreeing, included=exemplar)

    depths: list[int] = []
    for provider in agreeing_providers:
        head = latest[provider].head_block_number
        if head is None:
            depths.append(0)
        else:
            depths.append(max(head - exemplar.block_number, 0))
    depth = min(depths)
    if depth < finality.min_confirmation_depth:
        return verdict_of(ChainTruthVerdict.INCLUDED, agreeing=agreeing, depth=depth, included=exemplar)

    settled = exemplar.receipt_status is ReceiptStatus.SUCCESS
    return verdict_of(
        ChainTruthVerdict.CONFIRMED if settled else ChainTruthVerdict.REVERTED,
        agreeing=agreeing,
        depth=depth,
        included=exemplar,
    )


def reconcile_to_receipt(
    expectation: SettlementExpectationV0,
    truth: ChainTruthV0,
    bounds: EconomicBounds,
    *,
    validated_action: ValidatedEconomicActionV0,
    receipt_id: str,
    fee_atomic: int,
    observed_at_epoch_s: int,
    source: str,
) -> FillReceiptV0:
    """The ONLY path from external truth to a canonical receipt (I-06).

    Anything short of ``CONFIRMED`` raises ``SafeHaltError``. A confirmed
    settlement that lands outside the bounds that were committed also raises:
    a fill the policy did not authorize is a reconciliation failure, not a
    fill to be recorded and moved past.
    """
    if not isinstance(truth, ChainTruthV0):
        raise ChainTruthError("truth must be a ChainTruthV0")
    if not isinstance(validated_action, ValidatedEconomicActionV0):
        raise ChainTruthError(
            "a database-validated economic action binding is required to produce a receipt"
        )
    validated_action.assert_matches(expectation)
    if (
        truth.external_action_id != expectation.economic_action_id
        or truth.transaction_hash != expectation.transaction_hash
        or truth.chain_id != expectation.chain_id
        or truth.taker_address != expectation.taker_address
    ):
        raise ChainTruthError(
            "chain truth is bound to a different economic action, transaction, chain, or taker"
        )
    if truth.verdict is not ChainTruthVerdict.CONFIRMED:
        raise SafeHaltError(
            f"chain truth is {truth.verdict.value}; only CONFIRMED may produce a receipt"
        )
    receipt = FillReceiptV0(
        receipt_id=receipt_id,
        economic_action_id=expectation.economic_action_id,
        external_ref=expectation.transaction_hash,
        input_atomic_filled=truth.effective_input_atomic,
        output_atomic_filled=truth.effective_output_atomic,
        fee_atomic=fee_atomic,
        observed_at_epoch_s=observed_at_epoch_s,
        source=source,
    )
    if not receipt.satisfies(bounds):
        raise SafeHaltError(
            "the confirmed settlement lies outside the committed economic bounds"
        )
    return receipt


#: The state a verdict justifies. ``None`` means no transition is justified
#: yet: waiting is always permitted, guessing never is.
_VERDICT_STATES: Mapping[ChainTruthVerdict, IntentState | None] = MappingProxyType(
    {
        ChainTruthVerdict.NO_EVIDENCE: None,
        ChainTruthVerdict.VISIBLE: None,
        ChainTruthVerdict.INCLUDED: IntentState.INCLUDED,
        ChainTruthVerdict.CONFIRMED: IntentState.CONFIRMED,
        ChainTruthVerdict.REVERTED: IntentState.REJECTED,
        ChainTruthVerdict.AMBIGUOUS: IntentState.SAFE_HALT,
    }
)


def next_state_for_verdict(verdict: ChainTruthVerdict) -> IntentState | None:
    if not isinstance(verdict, ChainTruthVerdict):
        raise ChainTruthError(f"unknown verdict {verdict!r}")
    return _VERDICT_STATES[verdict]


def release_permitted(
    state_before: IntentState, verdict: ChainTruthVerdict | None
) -> bool:
    """Whether capital may be RELEASED rather than held or quarantined (I-04).

    Two cases only:

    * the action never became externally visible -- it is still in a
      pre-commitment state, so nothing can settle
    * external truth confirmed a revert to the depth the finality policy
      requires, so the economic action provably did not settle

    Everything else holds. In particular an action that is ``SUBMITTED``,
    ``INCLUDED``, or ``CONFIRMED`` with no confirmed-revert verdict may never
    release, whatever an error, a timeout, or a provider rejection suggests.
    """
    if not isinstance(state_before, IntentState):
        raise EnvelopeValidationError(f"unknown state {state_before!r}")
    if state_before in PRE_COMMITMENT_STATES:
        return True
    if state_before in EXTERNALLY_AMBIGUOUS_STATES:
        return verdict is ChainTruthVerdict.REVERTED
    return False


def assert_within_capital_ceiling(
    *, requested_atomic: int, held_atomic: int, authority: AuthorityPolicyRefV0
) -> None:
    """The reserved capital bound. Held capital includes quarantined capital."""
    _atomic(requested_atomic, field="requested_atomic", positive=True, error=AuthorityCeilingError)
    _atomic(held_atomic, field="held_atomic", positive=False, error=AuthorityCeilingError)
    if requested_atomic > authority.max_reservation_atomic:
        raise AuthorityCeilingError(
            f"reservation of {requested_atomic} exceeds the per-action ceiling "
            f"{authority.max_reservation_atomic}"
        )
    if held_atomic + requested_atomic > authority.max_cumulative_atomic:
        raise AuthorityCeilingError(
            f"reservation of {requested_atomic} on top of {held_atomic} held "
            f"exceeds the cumulative ceiling {authority.max_cumulative_atomic}"
        )


# --------------------------------------------------------------------------
# Untrusted venue response (I-12) and envelope admissibility
# --------------------------------------------------------------------------


def _instrument_address(instrument_id: str, *, chain_id: int, field: str) -> str:
    """The EVM address inside a canonical ``evm:<chain>:<address>`` identity."""
    parts = instrument_id.split(":")
    if len(parts) != 3 or parts[0] != "evm":
        raise EnvelopeValidationError(f"{field}: {instrument_id!r} is not an EVM instrument id")
    if parts[1] != str(chain_id):
        raise EnvelopeValidationError(
            f"{field}: instrument belongs to chain {parts[1]}, not {chain_id}"
        )
    return _address(parts[2], field=field)


@dataclass(frozen=True, slots=True)
class VenueQuoteResponseV0:
    """A venue response, already parsed, still untrusted.

    Nothing here is believed. Every field is compared against the frozen
    contract by :func:`evaluate_zero_x_execution_readiness` before it may
    influence anything, and the fields a hostile venue would use to redirect
    capital -- the spender, the allowance target, the transaction target, the
    value, and the calldata identity -- are compared to each other as well as
    to the expectation.
    """

    chain_id: int
    taker_address: str
    sell_token: str
    buy_token: str
    sell_amount_atomic: int
    buy_amount_atomic: int
    min_buy_amount_atomic: int | None
    allowance_target: str
    transaction_to: str
    transaction_value_atomic: int
    calldata_sha256: str
    calldata_length: int
    block_number: int
    quote_mode: str
    quoted_at_epoch_s: int
    liquidity_available: bool
    simulation_incomplete: bool
    invalid_sources: tuple[str, ...] = ()
    balance_issue: bool = False
    allowance_issue_actual_atomic: int | None = None
    allowance_issue_spender: str | None = None
    schema: str = CONTRACT_SCHEMA + ".venue_quote_response"

    def __post_init__(self) -> None:
        _positive_int(self.chain_id, field="chain_id")
        _address(self.taker_address, field="response taker")
        _address(self.sell_token, field="response sellToken")
        _address(self.buy_token, field="response buyToken")
        _atomic(self.sell_amount_atomic, field="response sellAmount", positive=True)
        _atomic(self.buy_amount_atomic, field="response buyAmount", positive=True)
        if self.min_buy_amount_atomic is not None:
            _atomic(self.min_buy_amount_atomic, field="response minBuyAmount", positive=True)
        _address(self.allowance_target, field="response allowanceTarget")
        _address(self.transaction_to, field="response transaction.to")
        _atomic(self.transaction_value_atomic, field="response transaction.value", positive=False)
        _digest(self.calldata_sha256, field="response calldata digest")
        _positive_int(self.calldata_length, field="response calldata length")
        _non_negative_int(self.block_number, field="response blockNumber")
        _label(self.quote_mode, field="response mode")
        _non_negative_int(self.quoted_at_epoch_s, field="response observation time")
        for flag, name in (
            (self.liquidity_available, "liquidity_available"),
            (self.simulation_incomplete, "simulation_incomplete"),
            (self.balance_issue, "balance_issue"),
        ):
            if not isinstance(flag, bool):
                raise EnvelopeValidationError(f"response {name} must be a bool")
        if not isinstance(self.invalid_sources, tuple):
            raise EnvelopeValidationError("response invalid_sources must be a tuple")
        if self.allowance_issue_actual_atomic is not None:
            _atomic(
                self.allowance_issue_actual_atomic,
                field="response issues.allowance.actual",
                positive=False,
            )
        if self.allowance_issue_spender is not None:
            _address(self.allowance_issue_spender, field="response issues.allowance.spender")
        if (self.allowance_issue_actual_atomic is None) != (self.allowance_issue_spender is None):
            raise EnvelopeValidationError(
                "an allowance issue must report both an actual allowance and a spender"
            )


@dataclass(frozen=True, slots=True)
class ZeroXExecutionExpectationV0:
    """What the frozen contract requires a 0x AllowanceHolder response to be."""

    chain_id: int
    taker_address: str
    sell_token: str
    buy_token: str
    sell_amount_atomic: int
    min_output_atomic: int
    max_quote_age_s: int
    quote_mode: str = "exact_in"
    schema: str = CONTRACT_SCHEMA + ".zero_x_expectation"

    def __post_init__(self) -> None:
        _positive_int(self.chain_id, field="chain_id")
        _address(self.taker_address, field="expected taker")
        _address(self.sell_token, field="expected sell token")
        _address(self.buy_token, field="expected buy token")
        if self.sell_token == self.buy_token:
            raise EnvelopeValidationError("sell and buy token must differ")
        _atomic(self.sell_amount_atomic, field="expected sell amount", positive=True)
        _atomic(self.min_output_atomic, field="expected min output", positive=True)
        _positive_int(self.max_quote_age_s, field="max_quote_age_s")
        _label(self.quote_mode, field="quote_mode")


@dataclass(frozen=True, slots=True)
class AllowanceHolderCalldataV0:
    """The bounded facts extracted from one AllowanceHolder call.

    This is intentionally not a general ABI representation.  It covers the
    current 0x v2 ERC-20 AllowanceHolder form:

    ``AllowanceHolder.exec(operator, token, amount, target, bytes)`` forwarding
    to ``Settler.execute(AllowedSlippage, bytes[], bytes32)``.  The outer
    amount/token and inner slippage tuple are the economic seams this phase
    must bind; action bytes are admitted only when their selector is one of the
    supported Settler action forms.
    """

    allowance_holder_selector: str
    operator_address: str
    sell_token: str
    sell_amount_atomic: int
    settler_target: str
    settler_selector: str
    recipient: str
    buy_token: str
    min_output_atomic: int
    action_selectors: tuple[str, ...]


def _selector(text: str) -> str:
    from .keccak import keccak256_hex

    return "0x" + keccak256_hex(text.encode("ascii"))[:8]


_ALLOWANCE_HOLDER_EXEC_SELECTOR = _selector("exec(address,address,uint256,address,bytes)")
_SETTLER_EXEC_SELECTOR = _selector("execute((address,address,uint256),bytes[],bytes32)")
_ACTION_SELECTORS = {
    _selector("NATIVE_CHECK(uint256,uint256)"),
    _selector("CHECK_SLIPPAGE(bool)"),
    _selector("UNISWAPV3(address,uint256,bytes,uint256)"),
    _selector("UNISWAPV2(address,address,uint256,address,uint24,uint256)"),
    _selector("BASIC(address,uint256,address,uint256,bytes)"),
    _selector("DODOV1(address,uint256,address,bool,uint256)"),
    _selector("DODOV2(address,address,uint256,address,bool,uint256)"),
    _selector("VELODROME(address,uint256,address,uint24,uint256)"),
    _selector("MAVERICKV2(address,address,uint256,address,bool,int32,uint256)"),
    _selector("EULERSWAP(address,address,uint256,address,bool,uint256)"),
    _selector("RENEGADE(address,address,address,uint256,bool,uint256,bytes,uint256)"),
    _selector("POSITIVE_SLIPPAGE(address,address,uint256,uint256)"),
}
_NON_SETTLEMENT_ACTION_SELECTORS = {
    _selector("NATIVE_CHECK(uint256,uint256)"),
    _selector("CHECK_SLIPPAGE(bool)"),
}
_ACTION_LAYOUTS = {
    _selector("NATIVE_CHECK(uint256,uint256)"): (2, ()),
    _selector("CHECK_SLIPPAGE(bool)"): (1, ()),
    _selector("UNISWAPV3(address,uint256,bytes,uint256)"): (4, (2,)),
    _selector("UNISWAPV2(address,address,uint256,address,uint24,uint256)"): (6, ()),
    _selector("BASIC(address,uint256,address,uint256,bytes)"): (5, (4,)),
    _selector("DODOV1(address,uint256,address,bool,uint256)"): (5, ()),
    _selector("DODOV2(address,address,uint256,address,bool,uint256)"): (6, ()),
    _selector("VELODROME(address,uint256,address,uint24,uint256)"): (5, ()),
    _selector("MAVERICKV2(address,address,uint256,address,bool,int32,uint256)"): (7, ()),
    _selector("EULERSWAP(address,address,uint256,address,bool,uint256)"): (6, ()),
    _selector("RENEGADE(address,address,address,uint256,bool,uint256,bytes,uint256)"): (8, (6,)),
    _selector("POSITIVE_SLIPPAGE(address,address,uint256,uint256)"): (4, ()),
}


def _calldata_bytes(value: bytes | str) -> bytes:
    if isinstance(value, bytes):
        result = value
    elif isinstance(value, str) and value.startswith("0x") and len(value) % 2 == 0:
        try:
            result = bytes.fromhex(value[2:])
        except ValueError as exc:
            raise EnvelopeValidationError("calldata hex is malformed") from exc
    else:
        raise EnvelopeValidationError("calldata must be explicit bytes or 0x-prefixed hex")
    if not result:
        raise EnvelopeValidationError("calldata must not be empty")
    return result


def _calldata_word(data: bytes, offset: int, *, field: str) -> int:
    if offset < 0 or offset + 32 > len(data):
        raise EnvelopeValidationError(f"calldata {field} word is out of bounds")
    return int.from_bytes(data[offset : offset + 32], "big")


def _calldata_address(data: bytes, offset: int, *, field: str) -> str:
    word = data[offset : offset + 32]
    if len(word) != 32 or word[:12] != b"\x00" * 12:
        raise EnvelopeValidationError(f"calldata {field} is not a canonical address word")
    address = "0x" + word[12:].hex()
    return _address(address, field=f"calldata {field}")


def _calldata_dynamic_bytes(data: bytes, args_start: int, offset: int, *, field: str) -> bytes:
    if offset % 32 or offset < 32 * 5:
        raise EnvelopeValidationError(f"calldata {field} offset is not canonical")
    start = args_start + offset
    length = _calldata_word(data, start, field=f"{field}.length")
    end = start + 32 + length
    padded_end = start + 32 + ((length + 31) // 32) * 32
    if end > len(data) or padded_end != len(data):
        raise EnvelopeValidationError(f"calldata {field} has trailing or truncated bytes")
    if any(data[end:padded_end]):
        raise EnvelopeValidationError(f"calldata {field} has non-zero ABI padding")
    return data[start + 32 : end]


def _decode_actions(data: bytes, args_start: int, offset: int) -> tuple[str, ...]:
    if offset % 32 or offset < 32 + 32 * 4:
        raise EnvelopeValidationError("calldata actions offset is not canonical")
    array_start = args_start + offset
    count = _calldata_word(data, array_start, field="actions.length")
    if count == 0 or count > 64:
        raise EnvelopeValidationError("calldata actions must contain 1..64 calls")
    head_end = array_start + 32 + count * 32
    if head_end > len(data):
        raise EnvelopeValidationError("calldata actions head is truncated")
    starts: list[int] = []
    for index in range(count):
        relative = _calldata_word(data, array_start + 32 + index * 32, field="actions.offset")
        if relative % 32 or relative < 32 + count * 32:
            raise EnvelopeValidationError("calldata action offset is not canonical")
        start = array_start + relative
        length = _calldata_word(data, start, field="action.length")
        end = start + 32 + length
        padded_end = start + 32 + ((length + 31) // 32) * 32
        if length < 4 or padded_end > len(data):
            raise EnvelopeValidationError("calldata action is truncated")
        starts.append(start)
        action_selector = "0x" + data[start + 32 : start + 36].hex()
        if action_selector not in _ACTION_SELECTORS:
            raise EnvelopeValidationError(f"unknown Settler action selector {action_selector}")
        action_args = data[start + 36 : end]
        arg_words, dynamic_indexes = _ACTION_LAYOUTS[action_selector]
        head_size = arg_words * 32
        if len(action_args) < head_size:
            raise EnvelopeValidationError("Settler action arguments are truncated")
        if not dynamic_indexes and len(action_args) != head_size:
            raise EnvelopeValidationError("Settler action has unexpected trailing bytes")
        dynamic_starts: list[int] = []
        for dynamic_index in dynamic_indexes:
            dynamic_offset = int.from_bytes(
                action_args[dynamic_index * 32 : (dynamic_index + 1) * 32], "big"
            )
            if dynamic_offset % 32 or dynamic_offset < head_size:
                raise EnvelopeValidationError("Settler action dynamic offset is not canonical")
            if dynamic_offset + 32 > len(action_args):
                raise EnvelopeValidationError("Settler action dynamic value is truncated")
            dynamic_length = int.from_bytes(
                action_args[dynamic_offset : dynamic_offset + 32], "big"
            )
            dynamic_end = dynamic_offset + 32 + dynamic_length
            dynamic_padded_end = dynamic_offset + 32 + ((dynamic_length + 31) // 32) * 32
            if dynamic_padded_end > len(action_args) or any(
                action_args[dynamic_end:dynamic_padded_end]
            ):
                raise EnvelopeValidationError("Settler action dynamic value is malformed")
            dynamic_starts.append(dynamic_offset)
        if dynamic_starts:
            if dynamic_starts != sorted(dynamic_starts) or dynamic_starts[0] != head_size:
                raise EnvelopeValidationError("Settler action dynamic values are not canonical")
            final_offset = dynamic_starts[-1]
            final_length = int.from_bytes(
                action_args[final_offset : final_offset + 32], "big"
            )
            final_end = final_offset + 32 + ((final_length + 31) // 32) * 32
            if final_end != len(action_args):
                raise EnvelopeValidationError("Settler action has trailing bytes")
        if action_selector == _selector("CHECK_SLIPPAGE(bool)") and int.from_bytes(action_args, "big") not in (0, 1):
            raise EnvelopeValidationError("CHECK_SLIPPAGE action is malformed")
        if action_selector == _selector("NATIVE_CHECK(uint256,uint256)") and len(action_args) != 64:
            raise EnvelopeValidationError("NATIVE_CHECK action is malformed")
    if starts != sorted(starts) or len(set(starts)) != len(starts) or starts[0] != head_end:
        raise EnvelopeValidationError("calldata actions are not densely ordered")
    for index, start in enumerate(starts[:-1]):
        length = _calldata_word(data, start, field="action.length")
        padded_end = start + 32 + ((length + 31) // 32) * 32
        if padded_end != starts[index + 1]:
            raise EnvelopeValidationError("calldata actions are not densely ordered")
    # Each action is a dynamic bytes value. Requiring the final padded action
    # to end at the calldata boundary rejects hidden suffixes and aliases.
    last_start = starts[-1]
    last_length = _calldata_word(data, last_start, field="final action.length")
    final_end = last_start + 32 + ((last_length + 31) // 32) * 32
    if final_end != len(data):
        raise EnvelopeValidationError("calldata actions have trailing bytes")
    return tuple("0x" + data[start + 32 : start + 36].hex() for start in starts)


def decode_allowance_holder_calldata(
    calldata: bytes | str,
    *,
    expected_entry_point: str | None = None,
    expected_allowance_target: str | None = None,
    expected_sell_token: str | None = None,
    expected_buy_token: str | None = None,
    expected_sell_amount_atomic: int | None = None,
    expected_taker_address: str | None = None,
    expected_min_output_atomic: int | None = None,
    transaction_value_atomic: int = 0,
) -> AllowanceHolderCalldataV0:
    """Decode and bind the exact bounded ERC-20 AllowanceHolder form.

    No selector, offset, dynamic tail, action, token, amount, recipient, or
    minimum-output field is inferred. Unknown shapes and all supplied expected
    field disagreements raise ``EnvelopeValidationError``.
    """
    data = _calldata_bytes(calldata)
    if data[:4].hex() != _ALLOWANCE_HOLDER_EXEC_SELECTOR[2:]:
        raise EnvelopeValidationError("calldata is not AllowanceHolder.exec")
    if transaction_value_atomic != 0:
        raise EnvelopeValidationError("AllowanceHolder calldata requires zero transaction value")
    if len(data) < 4 + 5 * 32:
        raise EnvelopeValidationError("AllowanceHolder.exec calldata is truncated")
    args_start = 4
    operator = _calldata_address(data, args_start, field="operator")
    sell_token = _calldata_address(data, args_start + 32, field="sell token")
    sell_amount = _calldata_word(data, args_start + 64, field="sell amount")
    if sell_amount <= 0 or sell_amount > MAX_UINT256:
        raise EnvelopeValidationError("calldata sell amount is not a positive uint256")
    target = _calldata_address(data, args_start + 96, field="Settler target")
    if operator != target:
        raise EnvelopeValidationError("AllowanceHolder operator must equal the Settler target")
    inner = _calldata_dynamic_bytes(
        data, args_start, _calldata_word(data, args_start + 128, field="forwarded data offset"),
        field="forwarded data",
    )
    if len(inner) < 4 + 5 * 32 or "0x" + inner[:4].hex() != _SETTLER_EXEC_SELECTOR:
        raise EnvelopeValidationError("forwarded data is not Settler.execute")
    inner_args = 4
    recipient = _calldata_address(inner, inner_args, field="recipient")
    buy_token = _calldata_address(inner, inner_args + 32, field="buy token")
    min_output = _calldata_word(inner, inner_args + 64, field="minimum output")
    if min_output <= 0 or min_output > MAX_UINT256:
        raise EnvelopeValidationError("calldata minimum output is not positive")
    actions = _decode_actions(
        inner, inner_args, _calldata_word(inner, inner_args + 96, field="actions offset")
    )
    if not any(selector not in _NON_SETTLEMENT_ACTION_SELECTORS for selector in actions):
        raise EnvelopeValidationError("calldata contains no supported settlement action")

    # ``transaction.to`` and ``allowanceTarget`` are response fields rather
    # than calldata fields.  Validate their shapes here, but do not collapse
    # the two security concepts into the nested Settler target.
    for name, value in (("entry point", expected_entry_point), ("allowance target", expected_allowance_target)):
        if value is not None:
            _address(value, field=f"expected {name}")
    if (
        expected_entry_point is not None
        and expected_allowance_target is not None
        and expected_entry_point != expected_allowance_target
    ):
        raise EnvelopeValidationError("entry point and allowance target disagree")
    if expected_allowance_target == target:
        raise EnvelopeValidationError(
            "the approval target must be distinct from the nested Settler target"
        )
    expected = (
        ("sell token", expected_sell_token, sell_token),
        ("buy token", expected_buy_token, buy_token),
        ("sell amount", expected_sell_amount_atomic, sell_amount),
        ("taker/recipient", expected_taker_address, recipient),
    )
    for name, expected_value, actual in expected:
        if expected_value is not None and actual != expected_value:
            raise EnvelopeValidationError(f"calldata {name} disagrees with the bound")
    if expected_min_output_atomic is not None and min_output < expected_min_output_atomic:
        raise EnvelopeValidationError("calldata minimum output is weaker than the bound")
    return AllowanceHolderCalldataV0(
        allowance_holder_selector=_ALLOWANCE_HOLDER_EXEC_SELECTOR,
        operator_address=operator,
        sell_token=sell_token,
        sell_amount_atomic=sell_amount,
        settler_target=target,
        settler_selector=_SETTLER_EXEC_SELECTOR,
        recipient=recipient,
        buy_token=buy_token,
        min_output_atomic=min_output,
        action_selectors=actions,
    )


def derive_transaction_hash(raw_signed_transaction: bytes) -> str:
    """Derive an EVM transaction hash from explicit signed bytes."""
    if not isinstance(raw_signed_transaction, bytes) or not raw_signed_transaction:
        raise EnvelopeValidationError("raw signed transaction must be non-empty bytes")
    from .keccak import keccak256_hex

    return "0x" + keccak256_hex(raw_signed_transaction)


class ExecutionReadiness(str, Enum):
    """I-01. None of these values is an authority, and none implies edge."""

    EXECUTABLE = "EXECUTABLE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    NOT_EXECUTABLE = "NOT_EXECUTABLE"


@dataclass(frozen=True, slots=True)
class ExecutionReadinessV0:
    verdict: ExecutionReadiness
    reasons: tuple[str, ...]
    required_allowance_atomic: int | None = None
    required_spender: str | None = None


def evaluate_zero_x_execution_readiness(
    expectation: ZeroXExecutionExpectationV0,
    response: VenueQuoteResponseV0,
    *,
    now_epoch_s: int,
) -> ExecutionReadinessV0:
    """Validate an untrusted venue response against the frozen contract.

    A CONTRACT VIOLATION RAISES. A response that names a different chain,
    taker, token pair, amount, transaction target, or spender is not a
    "not ready" answer; it is a response that must never influence anything,
    so it fails closed with an exception rather than a verdict.

    A NOT-READY CONDITION RETURNS. Missing liquidity, an incomplete
    simulation, an invalid source, an insufficient balance, or a stale quote
    are legitimate answers about the world, so they return
    ``NOT_EXECUTABLE``. A missing allowance returns ``APPROVAL_REQUIRED``,
    which is a request for a separate, separately authorized external action
    (I-13) and never an instruction to perform one.
    """
    _non_negative_int(now_epoch_s, field="now_epoch_s")
    if response.chain_id != expectation.chain_id:
        raise EnvelopeValidationError(
            f"venue response is for chain {response.chain_id}, expected {expectation.chain_id}"
        )
    if response.taker_address != expectation.taker_address:
        raise EnvelopeValidationError("venue response names a different taker")
    if response.sell_token != expectation.sell_token:
        raise EnvelopeValidationError("venue response names a different sell token")
    if response.buy_token != expectation.buy_token:
        raise EnvelopeValidationError("venue response names a different buy token")
    if response.quote_mode != expectation.quote_mode:
        raise EnvelopeValidationError(
            f"venue response mode {response.quote_mode!r} is not {expectation.quote_mode!r}"
        )
    if response.sell_amount_atomic != expectation.sell_amount_atomic:
        raise EnvelopeValidationError(
            "venue response sells a different amount than the bound authorizes"
        )
    if response.transaction_value_atomic != 0:
        raise EnvelopeValidationError(
            "V0 authorizes no native-value transfer; transaction.value must be zero"
        )
    if response.transaction_to != response.allowance_target:
        raise EnvelopeValidationError(
            "venue transaction target disagrees with its own allowance target"
        )
    if (
        response.allowance_issue_spender is not None
        and response.allowance_issue_spender != response.allowance_target
    ):
        raise EnvelopeValidationError(
            "venue allowance spender disagrees with its own allowance target"
        )
    if response.min_buy_amount_atomic is None:
        raise EnvelopeValidationError(
            "venue reported no minimum buy amount; the bound cannot be carried into "
            "the transaction"
        )
    if response.min_buy_amount_atomic < expectation.min_output_atomic:
        raise EnvelopeValidationError(
            "venue minimum output is weaker than the policy bound"
        )
    if response.buy_amount_atomic < response.min_buy_amount_atomic:
        raise EnvelopeValidationError("venue quoted less than its own minimum output")

    reasons: list[str] = []
    if response.quoted_at_epoch_s > now_epoch_s:
        reasons.append("QUOTE_TIME_IN_THE_FUTURE")
    elif now_epoch_s - response.quoted_at_epoch_s > expectation.max_quote_age_s:
        reasons.append("STALE_QUOTE")
    if not response.liquidity_available:
        reasons.append("LIQUIDITY_UNAVAILABLE")
    if response.simulation_incomplete:
        reasons.append("SIMULATION_INCOMPLETE")
    if response.invalid_sources:
        reasons.append("INVALID_SOURCES")
    if response.balance_issue:
        reasons.append("INSUFFICIENT_BALANCE")
    if reasons:
        return ExecutionReadinessV0(
            verdict=ExecutionReadiness.NOT_EXECUTABLE, reasons=tuple(sorted(reasons))
        )
    if response.allowance_issue_actual_atomic is not None:
        return ExecutionReadinessV0(
            verdict=ExecutionReadiness.APPROVAL_REQUIRED,
            reasons=("ALLOWANCE_INSUFFICIENT",),
            required_allowance_atomic=expectation.sell_amount_atomic,
            required_spender=response.allowance_target,
        )
    return ExecutionReadinessV0(verdict=ExecutionReadiness.EXECUTABLE, reasons=())


def assert_envelope_matches_venue_response(
    envelope: ExecutionEnvelopeV0, response: VenueQuoteResponseV0
) -> None:
    """The envelope must be exactly what the validated response describes."""
    if envelope.chain_id != response.chain_id:
        raise EnvelopeValidationError("envelope chain disagrees with the venue response")
    if envelope.taker_address != response.taker_address:
        raise EnvelopeValidationError("envelope taker disagrees with the venue response")
    if envelope.transaction_to != response.transaction_to:
        raise EnvelopeValidationError("envelope transaction target disagrees with the venue response")
    if envelope.transaction_value_atomic != response.transaction_value_atomic:
        raise EnvelopeValidationError("envelope transaction value disagrees with the venue response")
    if envelope.calldata_sha256 != response.calldata_sha256:
        raise EnvelopeValidationError("envelope calldata identity disagrees with the venue response")
    if envelope.calldata_length != response.calldata_length:
        raise EnvelopeValidationError("envelope calldata length disagrees with the venue response")
    if envelope.allowance_target != response.allowance_target:
        raise EnvelopeValidationError("envelope allowance target disagrees with the venue response")
    if envelope.max_input_atomic != response.sell_amount_atomic:
        raise EnvelopeValidationError("envelope input amount disagrees with the venue response")
    if _instrument_address(
        envelope.input_instrument_id,
        chain_id=response.chain_id,
        field="envelope input instrument",
    ) != response.sell_token:
        raise EnvelopeValidationError("envelope input token disagrees with the venue response")
    if _instrument_address(
        envelope.output_instrument_id,
        chain_id=response.chain_id,
        field="envelope output instrument",
    ) != response.buy_token:
        raise EnvelopeValidationError("envelope output token disagrees with the venue response")
    if response.min_buy_amount_atomic is None or envelope.min_output_atomic > response.min_buy_amount_atomic:
        raise EnvelopeValidationError(
            "the venue-enforced minimum output does not carry the envelope's bound"
        )


def assert_envelope_admissible(
    envelope: ExecutionEnvelopeV0,
    session: ExecutionSessionV0,
    authority: AuthorityPolicyRefV0,
    bounds: EconomicBounds,
    *,
    economic_action_id: str,
    expectation: ZeroXExecutionExpectationV0,
    venue_response: VenueQuoteResponseV0,
    held_atomic: int,
    now_epoch_s: int,
    calldata: bytes | str | None = None,
) -> None:
    """The mandatory composite gate before an envelope could ever be signable.

    This gate re-evaluates the venue response itself. Callers cannot validate a
    stale response and then omit the readiness result, and held capital must be
    supplied explicitly from the canonical ledger projection. Passing it is
    still not authority; ``require_capability`` remains the phase-ceiling gate.
    """
    _non_negative_int(now_epoch_s, field="now_epoch_s")
    readiness = evaluate_zero_x_execution_readiness(
        expectation, venue_response, now_epoch_s=now_epoch_s
    )
    if readiness.verdict is not ExecutionReadiness.EXECUTABLE:
        raise EnvelopeValidationError(
            "venue response is not executable: " + ",".join(readiness.reasons)
        )
    assert_envelope_matches_venue_response(envelope, venue_response)
    if calldata is not None:
        decoded = decode_allowance_holder_calldata(
            calldata,
            expected_entry_point=venue_response.transaction_to,
            expected_allowance_target=venue_response.allowance_target,
            expected_sell_token=venue_response.sell_token,
            expected_buy_token=venue_response.buy_token,
            expected_sell_amount_atomic=venue_response.sell_amount_atomic,
            expected_taker_address=venue_response.taker_address,
            expected_min_output_atomic=expectation.min_output_atomic,
            transaction_value_atomic=venue_response.transaction_value_atomic,
        )
        calldata_bytes = _calldata_bytes(calldata)
        if envelope.calldata_sha256 != sha256_hex(calldata_bytes):
            raise EnvelopeValidationError("envelope calldata digest does not match the bytes")
        if envelope.calldata_length != len(calldata_bytes):
            raise EnvelopeValidationError("envelope calldata length does not match the bytes")
        if decoded.min_output_atomic < envelope.min_output_atomic:
            raise EnvelopeValidationError("calldata minimum output weakens the envelope bound")
    if envelope.session_identity_digest != session.identity_digest:
        raise EnvelopeValidationError("envelope was built under a different session identity")
    if envelope.economic_action_id != economic_action_id:
        raise EnvelopeValidationError("envelope names a different economic action")
    if envelope.authority_policy_digest != authority.authority_policy_digest:
        raise EnvelopeValidationError("envelope was built under a different authority policy")
    _assert_authority_session_binding(
        session, authority, now_epoch_s=now_epoch_s, error=AuthorityCeilingError
    )
    if envelope.network_id != session.network_id:
        raise EnvelopeValidationError("envelope chain disagrees with the session network")
    if envelope.taker_address != session.taker_address:
        raise EnvelopeValidationError("envelope taker disagrees with the session taker")
    if envelope.input_instrument_id != bounds.input_instrument_id:
        raise EnvelopeValidationError("envelope input instrument disagrees with the bound")
    if envelope.output_instrument_id != bounds.output_instrument_id:
        raise EnvelopeValidationError("envelope output instrument disagrees with the bound")
    _instrument_address(envelope.input_instrument_id, chain_id=envelope.chain_id, field="input instrument")
    _instrument_address(envelope.output_instrument_id, chain_id=envelope.chain_id, field="output instrument")
    if envelope.max_input_atomic > bounds.max_input_atomic:
        raise EnvelopeValidationError("envelope would spend more than the bound authorizes")
    if envelope.min_output_atomic < bounds.min_output_atomic:
        raise EnvelopeValidationError("envelope carries a weaker minimum output than the bound")
    if envelope.deadline_epoch_s > bounds.deadline_epoch_s:
        raise EnvelopeValidationError("envelope outlives the bound's deadline")
    if envelope.deadline_epoch_s <= now_epoch_s:
        raise EnvelopeValidationError("envelope deadline has already passed")
    assert_within_capital_ceiling(
        requested_atomic=envelope.max_input_atomic, held_atomic=held_atomic, authority=authority
    )


def assert_approval_admissible(
    approval: ApprovalActionV0,
    session: ExecutionSessionV0,
    authority: AuthorityPolicyRefV0,
    expectation: ZeroXExecutionExpectationV0,
    venue_response: VenueQuoteResponseV0,
    *,
    now_epoch_s: int,
) -> None:
    """The mandatory approval gate for the current validated venue response.

    The response is re-evaluated here rather than accepting a caller-supplied
    readiness verdict. The approval is bound to the exact sell token, spender,
    and amount required by this response and to the same source/session/venue
    authority binding as an execution envelope.
    """
    _non_negative_int(now_epoch_s, field="now_epoch_s", error=ApprovalContractError)
    readiness = evaluate_zero_x_execution_readiness(
        expectation, venue_response, now_epoch_s=now_epoch_s
    )
    if readiness.verdict is not ExecutionReadiness.APPROVAL_REQUIRED:
        raise ApprovalContractError(
            f"no approval is required; readiness is {readiness.verdict.value}"
        )
    if approval.session_identity_digest != session.identity_digest:
        raise ApprovalContractError("approval was built under a different session identity")
    if approval.authority_policy_digest != authority.authority_policy_digest:
        raise ApprovalContractError("approval was built under a different authority policy")
    _assert_authority_session_binding(
        session, authority, now_epoch_s=now_epoch_s, error=ApprovalContractError
    )
    if approval.taker_address != expectation.taker_address:
        raise ApprovalContractError("approval taker disagrees with the current expectation")
    if approval.token_address != expectation.sell_token:
        raise ApprovalContractError(
            "approval token is not the token whose allowance the current response requires"
        )
    if approval.spender_address != readiness.required_spender:
        raise ApprovalContractError(
            "approval spender is not the spender the current venue response requires"
        )
    if approval.requested_allowance_atomic != readiness.required_allowance_atomic:
        raise ApprovalContractError(
            "approval amount is not the exact amount the current venue response requires"
        )
    if approval.deadline_epoch_s <= now_epoch_s:
        raise ApprovalContractError("approval deadline has already passed")
