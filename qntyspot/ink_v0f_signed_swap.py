"""Ink V0F exact signed-swap admission proof and zero-money rehearsal.

This module remains below the live-execution authority transition. It validates
externally produced EIP-1559 swap bytes against the exact same-amount
revalidation scope, then can produce a deterministic rehearsal transcript.

The rehearsal has no transport parameter, performs no submission, creates no
chain-truth record, and cannot be confused with a real external effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canon import digest_object, sha256_hex
from .domain import IntentV0
from .errors import AuthorityVerificationError, EnvelopeValidationError, SafeHaltError
from .exact_signed_bytes import ValidatedExactSignedBytesV0, validate_exact_signed_bytes
from .execution_contract import (
    AuthorityLevel,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    PHASE_GRANTED_AUTHORITY_LEVEL,
)
from .ink import INK_CHAIN_ID
from .ink_v0f_execution import INK_V0F_ROUTER_ADDRESS, INK_V0F_TAKER_ADDRESS
from .ink_v0f_human_signing import (
    InkV0FSameAmountRevalidationV0,
    _REVALIDATION_TOKEN,
)

SIGNED_SWAP_ADMISSION_SCHEMA = "qntyspot.ink_v0f.signed_swap_admission.v0"
MOCK_SUBMISSION_SCHEMA = "qntyspot.ink_v0f.mock_submission.v0"
REHEARSAL_RECONCILIATION_SCHEMA = "qntyspot.ink_v0f.rehearsal_reconciliation.v0"
ZERO_MONEY_REHEARSAL_SCHEMA = "qntyspot.ink_v0f.zero_money_rehearsal.v0"

_SIGNED_SWAP_TOKEN = object()
_MOCK_SUBMISSION_TOKEN = object()
_REHEARSAL_RECONCILIATION_TOKEN = object()
_REHEARSAL_TOKEN = object()


def _digest(value: Any, *, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise EnvelopeValidationError(f"{field_name} is not a canonical digest")
    return value


def _uint(value: Any, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EnvelopeValidationError(f"{field_name} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class InkV0FSignedSwapAdmissionV0:
    """Ephemeral proof that complete external bytes equal the frozen swap."""

    revalidation: InkV0FSameAmountRevalidationV0
    signed_bytes: bytes = field(repr=False)
    validated: ValidatedExactSignedBytesV0
    schema: str = SIGNED_SWAP_ADMISSION_SCHEMA
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _SIGNED_SWAP_TOKEN:
            raise EnvelopeValidationError(
                "signed swap admission must be produced by exact-byte validation"
            )
        if self.schema != SIGNED_SWAP_ADMISSION_SCHEMA:
            raise EnvelopeValidationError("unknown signed swap admission schema")
        if self.revalidation._token is not _REVALIDATION_TOKEN:
            raise SafeHaltError(
                "signed swap admission requires live-produced same-amount revalidation"
            )
        if type(self.signed_bytes) is not bytes or not self.signed_bytes:
            raise EnvelopeValidationError("signed swap bytes must be non-empty bytes")
        if type(self.validated) is not ValidatedExactSignedBytesV0:
            raise EnvelopeValidationError("signed swap validation type is invalid")
        request = self.revalidation.swap_request
        rechecked = validate_exact_signed_bytes(self.signed_bytes, request.scope)
        if rechecked != self.validated:
            raise EnvelopeValidationError(
                "signed swap validation does not match cryptographic revalidation"
            )
        if self.validated.scope != request.scope:
            raise EnvelopeValidationError(
                "signed swap validation scope differs from revalidation"
            )
        if sha256_hex(self.signed_bytes) != self.validated.signed_bytes_sha256:
            raise EnvelopeValidationError("signed swap bytes differ from validated digest")
        if len(self.signed_bytes) != self.validated.signed_bytes_length:
            raise EnvelopeValidationError("signed swap byte length differs from validation")
        parsed = self.validated.parsed
        if parsed.transaction_type != "eip-1559":
            raise EnvelopeValidationError("Ink V0F swap admission requires EIP-1559")
        if parsed.chain_id != INK_CHAIN_ID:
            raise EnvelopeValidationError("Ink V0F signed swap is on the wrong chain")
        if parsed.sender_address != INK_V0F_TAKER_ADDRESS:
            raise EnvelopeValidationError("Ink V0F signed swap has the wrong taker")
        if parsed.target_address != INK_V0F_ROUTER_ADDRESS:
            raise EnvelopeValidationError("Ink V0F signed swap has the wrong router")
        if parsed.value_atomic != 0:
            raise EnvelopeValidationError("Ink V0F signed swap carries native value")
        if parsed.calldata != request.calldata:
            raise EnvelopeValidationError(
                "Ink V0F signed swap calldata differs from the frozen request"
            )

    @property
    def transaction_hash(self) -> str:
        return self.validated.parsed.transaction_hash

    @property
    def admission_id(self) -> str:
        return digest_object(
            {
                "revalidation_id": self.revalidation.revalidation_id,
                "schema": self.schema,
                "signed_bytes_length": self.validated.signed_bytes_length,
                "signed_bytes_sha256": self.validated.signed_bytes_sha256,
                "transaction_hash": self.transaction_hash,
            }
        )


def validate_ink_v0f_signed_swap(
    revalidation: InkV0FSameAmountRevalidationV0,
    signed_bytes: bytes,
) -> InkV0FSignedSwapAdmissionV0:
    """Validate complete signed swap bytes without changing or persisting them."""
    if type(revalidation) is not InkV0FSameAmountRevalidationV0:
        raise AuthorityVerificationError("signed swap requires canonical revalidation")
    if revalidation._token is not _REVALIDATION_TOKEN:
        raise SafeHaltError(
            "signed swap requires live-produced same-amount revalidation"
        )
    request = revalidation.swap_request
    fields = request.eip1559_signing_fields()
    if fields["type"] != 2 or fields["value"] != 0:
        raise EnvelopeValidationError("frozen Ink V0F swap signing fields are invalid")
    validated = validate_exact_signed_bytes(signed_bytes, request.scope)
    return InkV0FSignedSwapAdmissionV0(
        revalidation=revalidation,
        signed_bytes=signed_bytes,
        validated=validated,
        _token=_SIGNED_SWAP_TOKEN,
    )


@dataclass(frozen=True, slots=True)
class InkV0FMockSubmissionV0:
    """Non-authoritative rehearsal-only representation of a submission step."""

    signed_swap_admission_id: str
    transaction_hash: str
    signed_bytes_sha256: str
    rehearsed_at_epoch_s: int
    provider_id: str = "qntyspot-zero-money-rehearsal"
    transport_invoked: bool = False
    external_effect: bool = False
    schema: str = MOCK_SUBMISSION_SCHEMA
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _MOCK_SUBMISSION_TOKEN:
            raise EnvelopeValidationError(
                "mock submission must be produced by the rehearsal runner"
            )
        if self.schema != MOCK_SUBMISSION_SCHEMA:
            raise EnvelopeValidationError("unknown mock submission schema")
        _digest(self.signed_swap_admission_id, field_name="signed_swap_admission_id")
        _digest(self.signed_bytes_sha256, field_name="signed_bytes_sha256")
        _uint(self.rehearsed_at_epoch_s, field_name="rehearsed_at_epoch_s")
        if (
            not isinstance(self.transaction_hash, str)
            or len(self.transaction_hash) != 66
            or not self.transaction_hash.startswith("0x")
            or any(
                char not in "0123456789abcdef"
                for char in self.transaction_hash[2:]
            )
        ):
            raise EnvelopeValidationError("mock transaction hash is not canonical")
        if self.transport_invoked is not False or self.external_effect is not False:
            raise EnvelopeValidationError(
                "zero-money rehearsal cannot record an external submission effect"
            )

    @property
    def mock_submission_id(self) -> str:
        return digest_object(
            {
                "external_effect": self.external_effect,
                "provider_id": self.provider_id,
                "rehearsed_at_epoch_s": self.rehearsed_at_epoch_s,
                "schema": self.schema,
                "signed_bytes_sha256": self.signed_bytes_sha256,
                "signed_swap_admission_id": self.signed_swap_admission_id,
                "transaction_hash": self.transaction_hash,
                "transport_invoked": self.transport_invoked,
            }
        )


@dataclass(frozen=True, slots=True)
class InkV0FRehearsalReconciliationV0:
    """Simulation result that is intentionally not a ChainObservationV0."""

    mock_submission_id: str
    economic_action_id: str
    simulated_result: str
    persistable_as_chain_truth: bool = False
    external_effect: bool = False
    schema: str = REHEARSAL_RECONCILIATION_SCHEMA
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _REHEARSAL_RECONCILIATION_TOKEN:
            raise EnvelopeValidationError(
                "rehearsal reconciliation must be produced by the rehearsal runner"
            )
        if self.schema != REHEARSAL_RECONCILIATION_SCHEMA:
            raise EnvelopeValidationError("unknown rehearsal reconciliation schema")
        _digest(self.mock_submission_id, field_name="mock_submission_id")
        _digest(self.economic_action_id, field_name="economic_action_id")
        if self.simulated_result != "SIMULATED_CONFIRMED_NO_CHAIN_EFFECT":
            raise EnvelopeValidationError("unknown rehearsal reconciliation result")
        if self.persistable_as_chain_truth is not False or self.external_effect is not False:
            raise EnvelopeValidationError(
                "rehearsal reconciliation cannot claim real chain truth"
            )

    @property
    def reconciliation_id(self) -> str:
        return digest_object(
            {
                "economic_action_id": self.economic_action_id,
                "external_effect": self.external_effect,
                "mock_submission_id": self.mock_submission_id,
                "persistable_as_chain_truth": self.persistable_as_chain_truth,
                "schema": self.schema,
                "simulated_result": self.simulated_result,
            }
        )


@dataclass(frozen=True, slots=True)
class InkV0FZeroMoneyRehearsalV0:
    session_identity_digest: str
    economic_action_id: str
    envelope_id: str
    revalidation_id: str
    signed_swap_admission_id: str
    mock_submission: InkV0FMockSubmissionV0
    reconciliation: InkV0FRehearsalReconciliationV0
    source_authority_level: AuthorityLevel
    schema: str = ZERO_MONEY_REHEARSAL_SCHEMA
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _REHEARSAL_TOKEN:
            raise EnvelopeValidationError(
                "zero-money rehearsal must be produced by the rehearsal runner"
            )
        for field_name in (
            "session_identity_digest",
            "economic_action_id",
            "envelope_id",
            "revalidation_id",
            "signed_swap_admission_id",
        ):
            _digest(getattr(self, field_name), field_name=field_name)
        if self.source_authority_level is not AuthorityLevel.RECONCILE_ONLY:
            raise AuthorityVerificationError(
                "pre-Level-3 rehearsal requires the RECONCILE_ONLY source ceiling"
            )
        if self.mock_submission.external_effect:
            raise EnvelopeValidationError("rehearsal mock submission created an effect")
        if self.reconciliation.mock_submission_id != self.mock_submission.mock_submission_id:
            raise EnvelopeValidationError(
                "rehearsal reconciliation names another mock submission"
            )
        if self.reconciliation.economic_action_id != self.economic_action_id:
            raise EnvelopeValidationError(
                "rehearsal reconciliation names another economic action"
            )
        if self.reconciliation.persistable_as_chain_truth:
            raise EnvelopeValidationError(
                "rehearsal reconciliation became persistable chain truth"
            )

    @property
    def rehearsal_id(self) -> str:
        return digest_object(
            {
                "economic_action_id": self.economic_action_id,
                "envelope_id": self.envelope_id,
                "mock_submission_id": self.mock_submission.mock_submission_id,
                "reconciliation_id": self.reconciliation.reconciliation_id,
                "revalidation_id": self.revalidation_id,
                "schema": self.schema,
                "session_identity_digest": self.session_identity_digest,
                "signed_swap_admission_id": self.signed_swap_admission_id,
                "source_authority_level": int(self.source_authority_level),
            }
        )


def run_ink_v0f_zero_money_rehearsal(
    *,
    session: ExecutionSessionV0,
    intent: IntentV0,
    envelope: ExecutionEnvelopeV0,
    signed_swap: InkV0FSignedSwapAdmissionV0,
    rehearsed_at_epoch_s: int,
) -> InkV0FZeroMoneyRehearsalV0:
    """Produce a deterministic no-transport rehearsal transcript."""
    if PHASE_GRANTED_AUTHORITY_LEVEL is not AuthorityLevel.RECONCILE_ONLY:
        raise AuthorityVerificationError(
            "this rehearsal is defined only before the Level-3 source transition"
        )
    if type(session) is not ExecutionSessionV0:
        raise AuthorityVerificationError("rehearsal requires an execution session")
    if type(intent) is not IntentV0 or type(envelope) is not ExecutionEnvelopeV0:
        raise AuthorityVerificationError(
            "rehearsal requires canonical intent and envelope records"
        )
    if (
        type(signed_swap) is not InkV0FSignedSwapAdmissionV0
        or signed_swap._token is not _SIGNED_SWAP_TOKEN
    ):
        raise AuthorityVerificationError(
            "rehearsal requires exact-byte-validated signed swap admission"
        )
    scope = signed_swap.validated.scope
    if (
        scope.session_id != session.session_id
        or scope.session_identity_digest != session.identity_digest
        or scope.authority_policy_digest != session.authority_policy_digest
        or scope.chain_id != session.chain_id
        or scope.taker_address != session.taker_address
    ):
        raise AuthorityVerificationError(
            "signed swap scope differs from the rehearsal session"
        )
    if (
        intent.economic_action_id != envelope.economic_action_id
        or scope.economic_action_id != envelope.economic_action_id
    ):
        raise EnvelopeValidationError(
            "intent, envelope, and signed swap name different economic actions"
        )
    if (
        envelope.session_identity_digest != session.identity_digest
        or envelope.taker_address != session.taker_address
        or envelope.chain_id != INK_CHAIN_ID
        or envelope.transaction_to != INK_V0F_ROUTER_ADDRESS
        or envelope.transaction_value_atomic != 0
    ):
        raise EnvelopeValidationError(
            "rehearsal envelope differs from the frozen Ink execution scope"
        )
    if signed_swap.revalidation.swap_request.scope.scope_digest != scope.scope_digest:
        raise EnvelopeValidationError(
            "signed swap no longer matches the revalidated frozen scope"
        )
    timestamp = _uint(rehearsed_at_epoch_s, field_name="rehearsed_at_epoch_s")

    mock_submission = InkV0FMockSubmissionV0(
        signed_swap_admission_id=signed_swap.admission_id,
        transaction_hash=signed_swap.transaction_hash,
        signed_bytes_sha256=signed_swap.validated.signed_bytes_sha256,
        rehearsed_at_epoch_s=timestamp,
        _token=_MOCK_SUBMISSION_TOKEN,
    )
    reconciliation = InkV0FRehearsalReconciliationV0(
        mock_submission_id=mock_submission.mock_submission_id,
        economic_action_id=envelope.economic_action_id,
        simulated_result="SIMULATED_CONFIRMED_NO_CHAIN_EFFECT",
        _token=_REHEARSAL_RECONCILIATION_TOKEN,
    )
    return InkV0FZeroMoneyRehearsalV0(
        session_identity_digest=session.identity_digest,
        economic_action_id=envelope.economic_action_id,
        envelope_id=envelope.envelope_id,
        revalidation_id=signed_swap.revalidation.revalidation_id,
        signed_swap_admission_id=signed_swap.admission_id,
        mock_submission=mock_submission,
        reconciliation=reconciliation,
        source_authority_level=PHASE_GRANTED_AUTHORITY_LEVEL,
        _token=_REHEARSAL_TOKEN,
    )
