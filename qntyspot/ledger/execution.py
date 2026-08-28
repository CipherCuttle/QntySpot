"""Offline execution control-plane runtime for Program B1.

The runtime only accepts explicit records and bytes supplied by its caller. It
does not create a transaction, reach a venue, read a clock, or use a signing
credential. All durable facts share the configured ``SpotLedger`` connection;
the core intent transition and the execution rows commit together.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping

from ..canon import digest_object, parse_canonical_decimal, sha256_hex, strict_json_loads
from ..domain import EconomicBounds, Side
from ..errors import (
    AuthorityCeilingError,
    AuthorityVerificationError,
    ChainTruthError,
    EnvelopeValidationError,
    LedgerError,
    SafeHaltError,
)
from ..execution_contract import (
    AuthorityLevel,
    AuthorityPolicyRefV0,
    ApprovalActionV0,
    ChainObservationV0,
    ChainPresence,
    ChainTruthVerdict,
    EconomicActionIDV0,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    FinalityPolicyV0,
    ROBINHOOD_V0_FINALITY,
    SignedTransactionRecordV0,
    SubmissionAcknowledgment,
    SubmissionAttemptV0,
    ValidatedEconomicActionV0,
    _validated_economic_action_from_database,
    VenueQuoteResponseV0,
    ZeroXExecutionExpectationV0,
    assert_approval_admissible,
    assert_envelope_admissible,
    evaluate_chain_truth,
    reconcile_to_receipt,
    derive_transaction_hash,
)
from ..authority_root import VerifiedAuthorityGrantV0
from ..states import EXTERNALLY_AMBIGUOUS_STATES, IntentState
from .execution_schema import (
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_TABLES,
    apply_execution_schema,
    read_execution_schema_version,
)
from .store import SpotLedger

__all__ = [
    "B1_O04_EXTERNAL_ROOT_BLOCKED",
    "ExternalAuthorityProofV0",
    "verify_external_authority_proof",
    "ExecutionRuntime",
    "ExecutionStore",
    "FAILURE_BOUNDARIES",
]

B1_O04_EXTERNAL_ROOT_BLOCKED = True
# B1 has no authority service.  The only reference accepted by this offline
# runtime is the frozen shadow root name, and its ceilings are additionally
# bounded by the persisted policy below.  A future independently rooted
# verifier must replace this admission path before any higher authority is
# considered.
B1_SHADOW_AUTHORITY_ROOT_ID = "qnty-authority-root-v0"

FAILURE_BOUNDARIES = (
    "session",
    "reservation",
    "envelope",
    "approval",
    "signed_metadata",
    "submission_attempt",
    "chain_observation",
    "reconciliation",
    "fill_accounting",
    "kill_switch",
)

@dataclass(frozen=True, slots=True)
class ExternalAuthorityProofV0:
    """Shape of the future independently rooted grant receipt.

    B1 is a consumer seam only.  Constructing this value does not verify a
    root, and ``verify_external_authority_proof`` always fails closed until a
    separately rooted verifier is integrated.
    """

    authority_root_id: str
    authority_policy_digest: str
    permitted_repository_commit: str
    permitted_implementation_digest: str
    permitted_network_id: str
    permitted_taker_address: str
    permitted_venue_id: str
    granted_level: AuthorityLevel
    max_reservation_atomic: int
    max_cumulative_atomic: int
    not_before_epoch_s: int
    not_after_epoch_s: int
    verification_identity: str
    receipt_digest: str

    def canonical_object(self) -> dict[str, Any]:
        return {
            "authority_policy_digest": self.authority_policy_digest,
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
            "receipt_digest": self.receipt_digest,
            "verification_identity": self.verification_identity,
            "schema": "qntyspot.program_b1.v0.external_authority_proof",
        }

    @property
    def digest(self) -> str:
        return digest_object(self.canonical_object())


def verify_external_authority_proof(
    proof: ExternalAuthorityProofV0,
    authority: AuthorityPolicyRefV0,
    *,
    repository_commit: str,
    implementation_digest: str,
) -> None:
    """Fail closed because no independent authority root exists in B1."""
    del proof, authority, repository_commit, implementation_digest
    raise AuthorityCeilingError(
        "B1 has no independently rooted authority verifier; authority proof is deferred"
    )


def _record_values(row: Mapping[str, Any], values: Mapping[str, Any]) -> None:
    differences = [
        key for key, value in values.items() if row[key] != value
    ]
    if differences:
        raise LedgerError(
            "same identity was supplied with different execution facts: "
            + ",".join(sorted(differences))
        )


class ExecutionRuntime:
    """Transactional writer for the Program B execution authority surface."""

    def __init__(
        self,
        ledger: SpotLedger,
        *,
        failure_injector: Callable[..., None] | None = None,
        failure_hook: Callable[..., None] | None = None,
    ) -> None:
        if not isinstance(ledger, SpotLedger):
            raise TypeError("ExecutionRuntime requires the configured SpotLedger")
        self.ledger = ledger
        self._conn = ledger.connection
        self._failure_injector = failure_injector or failure_hook
        if self._conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise LedgerError("execution runtime requires SQLite foreign_keys=ON")
        existing_tables = {
            table for table in EXECUTION_TABLES if self._table_exists(table)
        }
        if not existing_tables:
            apply_execution_schema(self._conn)
        elif existing_tables != set(EXECUTION_TABLES):
            raise LedgerError("execution schema is partially applied")
        if read_execution_schema_version(self._conn) != EXECUTION_SCHEMA_VERSION:
            raise LedgerError("unsupported execution schema version")

    def _table_exists(self, table: str) -> bool:
        return (
            self._conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (table,)
            ).fetchone()
            is not None
        )

    def _inject(self, boundary: str, when: str) -> None:
        if self._failure_injector is None:
            return
        try:
            self._failure_injector(boundary, when)
        except TypeError as first:
            try:
                self._failure_injector(f"{boundary}:{when}")
            except TypeError:
                raise first

    def _kill_engaged(self) -> bool:
        return (
            self._conn.execute(
                "SELECT COALESCE(MAX(engaged), 0) FROM operator_control_events "
                "WHERE control = 'KILL_SWITCH'"
            ).fetchone()[0]
            == 1
        )

    def _reject_if_killed(self, operation: str) -> None:
        if self._kill_engaged():
            raise SafeHaltError(f"kill switch blocks new {operation}")

    @contextmanager
    def _transaction(self, boundary: str) -> Iterator[sqlite3.Connection]:
        with self.ledger._write() as conn:  # noqa: SLF001 - one authority surface
            yield conn
            self._inject(boundary, "before_commit")
        self._inject(boundary, "after_commit")

    @staticmethod
    def _insert_or_match(
        conn: sqlite3.Connection,
        table: str,
        key_name: str,
        key_value: object,
        values: Mapping[str, Any],
    ) -> bool:
        row = conn.execute(
            f"SELECT * FROM {table} WHERE {key_name} = ?", (key_value,)
        ).fetchone()
        if row is not None:
            _record_values(row, values)
            return False
        names = sorted(values)
        conn.execute(
            f"INSERT INTO {table} ({','.join(names)}) "
            f"VALUES ({','.join(':' + name for name in names)})",
            {name: values[name] for name in names},
        )
        return True

    def create_execution_session(
        self, session: ExecutionSessionV0, authority: AuthorityPolicyRefV0
    ) -> bool:
        if session.authority_policy_digest != authority.authority_policy_digest:
            raise AuthorityCeilingError("session and authority policy digest disagree")
        authority.assert_valid_at(session.started_at_epoch_s)
        if authority.granted_level > AuthorityLevel.SHADOW:
            raise AuthorityCeilingError("B1 runtime cannot grant authority above SHADOW")
        if authority.authority_root_id != B1_SHADOW_AUTHORITY_ROOT_ID:
            raise AuthorityCeilingError(
                "B1 accepts only the frozen shadow authority-root reference"
            )
        policy_row = self._conn.execute(
            "SELECT per_order_cap_atomic, global_cap_atomic FROM policies WHERE policy_id = ?",
            (session.policy_id,),
        ).fetchone()
        if policy_row is None:
            raise AuthorityCeilingError("the session policy is not admitted in this ledger")
        if authority.max_reservation_atomic > int(policy_row["per_order_cap_atomic"]):
            raise AuthorityCeilingError(
                "authority reservation ceiling exceeds the persisted policy per-order cap"
            )
        if authority.max_cumulative_atomic > int(policy_row["global_cap_atomic"]):
            raise AuthorityCeilingError(
                "authority cumulative ceiling exceeds the persisted policy global cap"
            )
        if (
            authority.permitted_repository_commit != session.repository_commit
            or authority.permitted_implementation_digest != session.implementation_digest
            or authority.permitted_network_id != session.network_id
            or authority.permitted_taker_address != session.taker_address
            or authority.permitted_venue_id != session.venue_id
        ):
            raise AuthorityCeilingError("session is outside the supplied authority reference")
        values = {
            "session_id": session.session_id,
            "identity_digest": session.identity_digest,
            "repository_commit": session.repository_commit,
            "implementation_digest": session.implementation_digest,
            "runtime_identity": session.runtime_identity,
            "db_schema_version": session.db_schema_version,
            "policy_id": session.policy_id,
            "authority_root_id": authority.authority_root_id,
            "authority_policy_digest": session.authority_policy_digest,
            "authority_level": int(authority.granted_level),
            "taker_address": session.taker_address,
            "network_id": session.network_id,
            "venue_id": session.venue_id,
            "venue_adapter_version": session.venue_adapter_version,
            "started_at_epoch_s": session.started_at_epoch_s,
            "session_ordinal": session.session_ordinal,
        }
        with self._transaction("session") as conn:
            self._reject_if_killed("execution sessions")
            return self._insert_or_match(
                conn, "execution_sessions", "session_id", session.session_id, values
            )

    def record_verified_authority(
        self,
        verified: VerifiedAuthorityGrantV0,
        *,
        accepted_at_epoch_s: int,
    ) -> bool:
        """Persist the external verification high-water mark only.

        This records evidence for continuity and replay.  It does not alter
        the phase ceiling, session authority, or any execution capability.
        The SQLite trigger rejects root/config identity changes and epoch
        rollback for the same externally pinned configuration.
        """
        if not isinstance(verified, VerifiedAuthorityGrantV0):
            raise AuthorityVerificationError("only a verified authority grant may be recorded")
        if isinstance(accepted_at_epoch_s, bool) or not isinstance(accepted_at_epoch_s, int) or accepted_at_epoch_s < 0:
            raise AuthorityVerificationError("accepted_at_epoch_s must be a non-negative integer")
        values = {
            "trust_config_digest": verified.trust_config_digest,
            "root_id": verified.root_id,
            "public_key_fingerprint": verified.public_key_fingerprint,
            "minimum_authority_epoch": verified.minimum_authority_epoch,
            "highest_accepted_epoch": verified.receipt.authority_epoch,
            "highest_accepted_receipt_id": verified.receipt_id,
            "highest_accepted_at_epoch_s": accepted_at_epoch_s,
        }
        with self._transaction("authority_acceptance") as conn:
            row = conn.execute(
                "SELECT * FROM authority_root_state WHERE trust_config_digest = ?",
                (verified.trust_config_digest,),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO authority_root_state "
                    "(trust_config_digest, root_id, public_key_fingerprint, "
                    "minimum_authority_epoch, highest_accepted_epoch, "
                    "highest_accepted_receipt_id, highest_accepted_at_epoch_s) "
                    "VALUES (:trust_config_digest, :root_id, :public_key_fingerprint, "
                    ":minimum_authority_epoch, :highest_accepted_epoch, "
                    ":highest_accepted_receipt_id, :highest_accepted_at_epoch_s)",
                    values,
                )
                return True
            if any(
                row[name] != values[name]
                for name in (
                    "root_id",
                    "public_key_fingerprint",
                    "minimum_authority_epoch",
                )
            ):
                raise AuthorityVerificationError("stored authority root identity disagrees")
            if verified.receipt.authority_epoch < row["highest_accepted_epoch"]:
                raise AuthorityVerificationError("authority receipt epoch rolls back local continuity")
            if verified.receipt.authority_epoch == row["highest_accepted_epoch"]:
                if verified.receipt_id != row["highest_accepted_receipt_id"]:
                    raise AuthorityVerificationError(
                        "different authority receipt at an accepted epoch"
                    )
                return False
            conn.execute(
                "UPDATE authority_root_state SET highest_accepted_epoch = ?, "
                "highest_accepted_receipt_id = ?, highest_accepted_at_epoch_s = ? "
                "WHERE trust_config_digest = ?",
                (
                    verified.receipt.authority_epoch,
                    verified.receipt_id,
                    accepted_at_epoch_s,
                    verified.trust_config_digest,
                ),
            )
            return True

    def reserve_action(self, economic_action_id: str, *, now_epoch_s: int) -> bool:
        with self._transaction("reservation"):
            self._reject_if_killed("reservations")
            state = self.ledger.intent_state(economic_action_id)
            if state is IntentState.RESERVED:
                return False
            if state is not IntentState.SIMULATED:
                raise LedgerError(f"reservation requires SIMULATED intent, got {state.value}")
            self.ledger.transition(
                economic_action_id, IntentState.RESERVED, now_epoch_s=now_epoch_s
            )
        return True

    def _require_session(self, session_id: str, conn: sqlite3.Connection) -> Mapping[str, Any]:
        row = conn.execute(
            "SELECT * FROM execution_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise LedgerError(f"unknown execution session {session_id}")
        return row

    def _require_economic_intent(self, action_id: str, conn: sqlite3.Connection) -> Mapping[str, Any]:
        row = conn.execute(
            "SELECT * FROM intents WHERE economic_action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            raise LedgerError(f"unknown economic action {action_id}")
        return row

    def _economic_external_action(self, conn: sqlite3.Connection, action_id: str) -> None:
        values = {
            "external_action_id": action_id,
            "kind": "ECONOMIC",
            "economic_action_id": action_id,
            "approval_action_id": None,
        }
        self._insert_or_match(
            conn, "external_actions", "external_action_id", action_id, values
        )

    def record_execution_envelope(
        self,
        envelope: ExecutionEnvelopeV0,
        session: ExecutionSessionV0,
        authority: AuthorityPolicyRefV0,
        bounds: EconomicBounds,
        expectation: ZeroXExecutionExpectationV0,
        venue_response: VenueQuoteResponseV0,
        calldata: bytes | str,
        *,
        held_atomic: int | None = None,
        now_epoch_s: int,
        lifecycle: str = "AUTHORIZED",
    ) -> bool:
        if lifecycle not in {"DRAFT", "AUTHORIZED", "SUPERSEDED", "VOID"}:
            raise EnvelopeValidationError(f"unknown envelope lifecycle {lifecycle!r}")
        values = {
            "envelope_id": envelope.envelope_id,
            "session_id": envelope.session_id,
            "session_identity_digest": envelope.session_identity_digest,
            "economic_action_id": envelope.economic_action_id,
            "plan_id": envelope.plan_id,
            "quote_id": envelope.quote_id,
            "quote_observation_digest": envelope.quote_observation_digest,
            "venue_block_number": envelope.venue_block_number,
            "chain_id": envelope.chain_id,
            "taker_address": envelope.taker_address,
            "input_instrument_id": envelope.input_instrument_id,
            "output_instrument_id": envelope.output_instrument_id,
            "max_input_atomic": str(envelope.max_input_atomic),
            "min_output_atomic": str(envelope.min_output_atomic),
            "transaction_to": envelope.transaction_to,
            "transaction_value_atomic": str(envelope.transaction_value_atomic),
            "calldata_sha256": envelope.calldata_sha256,
            "calldata_length": envelope.calldata_length,
            "allowance_target": envelope.allowance_target,
            "account_nonce": envelope.account_nonce,
            "gas_limit_ceiling": envelope.gas_limit_ceiling,
            "max_fee_per_gas_ceiling_atomic": str(envelope.max_fee_per_gas_ceiling_atomic),
            "max_priority_fee_per_gas_ceiling_atomic": str(envelope.max_priority_fee_per_gas_ceiling_atomic),
            "deadline_epoch_s": envelope.deadline_epoch_s,
            "authority_policy_digest": envelope.authority_policy_digest,
            "evidence_digest": envelope.evidence_digest,
            "lifecycle": lifecycle,
            "constructed_at_epoch_s": envelope.constructed_at_epoch_s,
        }
        with self._transaction("envelope") as conn:
            self._reject_if_killed("execution envelopes")
            actual_held_atomic = self.ledger.held_atomic()
            if held_atomic is not None and held_atomic != actual_held_atomic:
                raise EnvelopeValidationError(
                    "held_atomic must match the canonical ledger projection"
                )
            held_atomic = actual_held_atomic
            action_row = self._require_economic_intent(envelope.economic_action_id, conn)
            persisted_bounds = self._bounds_from_intent(action_row)
            if bounds != persisted_bounds:
                raise EnvelopeValidationError(
                    "caller-supplied bounds differ from the persisted intent bounds"
                )
            bounds = persisted_bounds
            existing = conn.execute(
                "SELECT * FROM execution_envelopes WHERE envelope_id = ?",
                (envelope.envelope_id,),
            ).fetchone()
            if existing is not None:
                _record_values(existing, values)
                session_row = self._require_session(session.session_id, conn)
                if session_row["identity_digest"] != session.identity_digest:
                    raise EnvelopeValidationError("stored session identity disagrees")
                self._economic_external_action(conn, envelope.economic_action_id)
                return False
            if IntentState(action_row["state"]) is not IntentState.RESERVED:
                raise EnvelopeValidationError(
                    "an execution envelope requires a durable reservation"
                )
            assert_envelope_admissible(
                envelope,
                session,
                authority,
                bounds,
                economic_action_id=envelope.economic_action_id,
                expectation=expectation,
                venue_response=venue_response,
                held_atomic=held_atomic,
                now_epoch_s=now_epoch_s,
                calldata=calldata,
            )
            session_row = self._require_session(session.session_id, conn)
            if session_row["identity_digest"] != session.identity_digest:
                raise EnvelopeValidationError("stored session identity disagrees")
            self._economic_external_action(conn, envelope.economic_action_id)
            return self._insert_or_match(
                conn, "execution_envelopes", "envelope_id", envelope.envelope_id, values
            )

    def record_approval_action(
        self,
        approval: ApprovalActionV0,
        session: ExecutionSessionV0,
        authority: AuthorityPolicyRefV0,
        expectation: ZeroXExecutionExpectationV0,
        venue_response: VenueQuoteResponseV0,
        *,
        now_epoch_s: int,
        lifecycle: str = "AUTHORIZED",
    ) -> bool:
        if lifecycle not in {"DRAFT", "AUTHORIZED", "SUPERSEDED", "VOID", "SETTLED"}:
            raise LedgerError(f"unknown approval lifecycle {lifecycle!r}")
        assert_approval_admissible(
            approval,
            session,
            authority,
            expectation,
            venue_response,
            now_epoch_s=now_epoch_s,
        )
        with self._transaction("approval") as conn:
            self._reject_if_killed("approval actions")
            self._require_session(session.session_id, conn)
            if approval.economic_action_id is not None:
                action_row = self._require_economic_intent(approval.economic_action_id, conn)
                bounds = self._bounds_from_intent(action_row)
                if expectation.sell_amount_atomic > bounds.max_input_atomic:
                    raise EnvelopeValidationError(
                        "approval response exceeds the persisted economic bound"
                    )
                if venue_response.sell_amount_atomic > bounds.max_input_atomic:
                    raise EnvelopeValidationError(
                        "approval venue response exceeds the persisted economic bound"
                    )
            values = {
                "approval_action_id": approval.approval_action_id,
                "session_id": approval.session_id,
                "session_identity_digest": approval.session_identity_digest,
                "economic_action_id": approval.economic_action_id,
                "taker_address": approval.taker_address,
                "token_address": approval.token_address,
                "spender_address": approval.spender_address,
                "requested_allowance_atomic": str(approval.requested_allowance_atomic),
                "observed_prior_allowance_atomic": str(approval.observed_prior_allowance_atomic),
                "authority_policy_digest": approval.authority_policy_digest,
                "lifecycle": lifecycle,
                "deadline_epoch_s": approval.deadline_epoch_s,
                "created_at_epoch_s": now_epoch_s,
            }
            inserted = self._insert_or_match(
                conn,
                "approval_actions",
                "approval_action_id",
                approval.approval_action_id,
                values,
            )
            external = {
                "external_action_id": approval.approval_action_id,
                "kind": "APPROVAL",
                "economic_action_id": None,
                "approval_action_id": approval.approval_action_id,
            }
            self._insert_or_match(
                conn,
                "external_actions",
                "external_action_id",
                approval.approval_action_id,
                external,
            )
            return inserted

    def record_signed_transaction_metadata(
        self,
        record: SignedTransactionRecordV0,
        raw_signed_transaction: bytes,
        *,
        frozen_at_epoch_s: int,
    ) -> bool:
        if sha256_hex(raw_signed_transaction) != record.raw_signed_sha256:
            raise EnvelopeValidationError("signed metadata digest does not match supplied bytes")
        if len(raw_signed_transaction) != record.raw_signed_length:
            raise EnvelopeValidationError("signed metadata length does not match supplied bytes")
        if derive_transaction_hash(raw_signed_transaction) != record.transaction_hash:
            raise EnvelopeValidationError("signed metadata hash is not the locally derived Keccak hash")
        with self._transaction("signed_metadata") as conn:
            self._reject_if_killed("signed-transaction metadata")
            envelope = conn.execute(
                "SELECT * FROM execution_envelopes WHERE envelope_id = ?", (record.envelope_id,)
            ).fetchone()
            if envelope is None:
                raise LedgerError(f"unknown execution envelope {record.envelope_id}")
            if envelope["lifecycle"] != "AUTHORIZED":
                raise EnvelopeValidationError(
                    "signed metadata requires an AUTHORIZED execution envelope"
                )
            if (
                envelope["chain_id"] != record.chain_id
                or envelope["account_nonce"] != record.account_nonce
                or envelope["taker_address"] != record.taker_address
            ):
                raise EnvelopeValidationError("signed metadata disagrees with envelope identity")
            self._economic_external_action(conn, envelope["economic_action_id"])
            values = {
                "signed_transaction_id": record.signed_transaction_id,
                "external_action_id": envelope["economic_action_id"],
                "session_id": envelope["session_id"],
                "envelope_id": record.envelope_id,
                "approval_action_id": None,
                "chain_id": record.chain_id,
                "taker_address": record.taker_address,
                "account_nonce": record.account_nonce,
                "raw_signed_sha256": record.raw_signed_sha256,
                "raw_signed_length": record.raw_signed_length,
                "transaction_hash": record.transaction_hash,
                "signer_identity": record.signer_identity,
                "frozen_at_epoch_s": frozen_at_epoch_s,
            }
            inserted = self._insert_or_match(
                conn,
                "signed_transactions",
                "signed_transaction_id",
                record.signed_transaction_id,
                values,
            )
            state = self.ledger.intent_state(envelope["economic_action_id"])
            if inserted and state is IntentState.RESERVED:
                self.ledger.transition(
                    envelope["economic_action_id"], IntentState.SIGNED,
                    now_epoch_s=frozen_at_epoch_s,
                    payload={"execution": "signed_metadata_recorded"},
                )
            elif inserted and state not in EXTERNALLY_AMBIGUOUS_STATES:
                raise LedgerError(f"signed metadata requires RESERVED intent, got {state.value}")
            return inserted

    def record_submission_attempt(self, attempt: SubmissionAttemptV0) -> bool:
        with self._transaction("submission_attempt") as conn:
            self._reject_if_killed("submission attempts")
            signed = conn.execute(
                "SELECT * FROM signed_transactions WHERE signed_transaction_id = ?",
                (attempt.signed_transaction_id,),
            ).fetchone()
            if signed is None:
                raise LedgerError(f"unknown signed transaction {attempt.signed_transaction_id}")
            attempt.assert_hash_agreement(signed["transaction_hash"])
            if (
                attempt.acknowledgment is SubmissionAcknowledgment.ACCEPTED
                and attempt.provider_reported_hash != signed["transaction_hash"]
            ):
                raise ChainTruthError(
                    "an ACCEPTED submission must carry the locally derived transaction hash"
                )
            values = {
                "submission_attempt_id": attempt.submission_attempt_id,
                "signed_transaction_id": attempt.signed_transaction_id,
                "provider_id": attempt.provider_id,
                "attempt_ordinal": attempt.attempt_ordinal,
                "submitted_at_epoch_s": attempt.submitted_at_epoch_s,
                "acknowledgment": attempt.acknowledgment.value,
                "provider_reported_hash": attempt.provider_reported_hash,
                "error_class": attempt.error_class,
            }
            inserted = self._insert_or_match(
                conn,
                "submission_attempts",
                "submission_attempt_id",
                attempt.submission_attempt_id,
                values,
            )
            if inserted and attempt.acknowledgment in {
                SubmissionAcknowledgment.ACCEPTED,
                SubmissionAcknowledgment.UNKNOWN,
            }:
                action_id = signed["external_action_id"]
                state = self.ledger.intent_state(action_id)
                if state is IntentState.SIGNED:
                    self.ledger.transition(
                        action_id, IntentState.SUBMITTED,
                        now_epoch_s=attempt.submitted_at_epoch_s,
                        payload={"execution": "submission_metadata_recorded"},
                    )
                elif state not in EXTERNALLY_AMBIGUOUS_STATES:
                    raise LedgerError(f"submission metadata requires SIGNED intent, got {state.value}")
            return inserted

    @staticmethod
    def _observation_values(
        observation: ChainObservationV0, action_id: str, signed_id: str
    ) -> dict[str, Any]:
        return {
            "observation_id": observation.observation_id,
            "external_action_id": action_id,
            "signed_transaction_id": signed_id,
            "provider_id": observation.provider_id,
            "transaction_hash": observation.transaction_hash,
            "observed_at_epoch_s": observation.observed_at_epoch_s,
            "presence": observation.presence.value,
            "block_number": observation.block_number,
            "block_hash": observation.block_hash,
            "block_parent_hash": observation.block_parent_hash,
            "head_block_number": observation.head_block_number,
            "head_block_hash": observation.head_block_hash,
            "receipt_status": None
            if observation.receipt_status is None
            else observation.receipt_status.value,
            "effective_input_atomic": None
            if observation.effective_input_atomic is None
            else str(observation.effective_input_atomic),
            "effective_output_atomic": None
            if observation.effective_output_atomic is None
            else str(observation.effective_output_atomic),
            "raw_evidence_sha256": observation.raw_evidence_sha256,
        }

    @staticmethod
    def _observation_from_row(row: Mapping[str, Any]) -> ChainObservationV0:
        from ..execution_contract import ReceiptStatus

        return ChainObservationV0(
            provider_id=row["provider_id"],
            transaction_hash=row["transaction_hash"],
            observed_at_epoch_s=row["observed_at_epoch_s"],
            presence=ChainPresence(row["presence"]),
            raw_evidence_sha256=row["raw_evidence_sha256"],
            block_number=row["block_number"],
            block_hash=row["block_hash"],
            block_parent_hash=row["block_parent_hash"],
            head_block_number=row["head_block_number"],
            head_block_hash=row["head_block_hash"],
            receipt_status=None
            if row["receipt_status"] is None
            else ReceiptStatus(row["receipt_status"]),
            effective_input_atomic=None
            if row["effective_input_atomic"] is None
            else int(row["effective_input_atomic"]),
            effective_output_atomic=None
            if row["effective_output_atomic"] is None
            else int(row["effective_output_atomic"]),
        )

    def _truth_for_action(
        self,
        conn: sqlite3.Connection,
        action_id: str,
        signed_id: str,
        finality: FinalityPolicyV0,
    ) -> tuple[Any, Mapping[str, Any], Mapping[str, Any]]:
        signed = conn.execute(
            "SELECT * FROM signed_transactions WHERE signed_transaction_id = ?", (signed_id,)
        ).fetchone()
        if signed is None or signed["external_action_id"] != action_id:
            raise LedgerError("signed transaction is not bound to the external action")
        envelope = conn.execute(
            "SELECT * FROM execution_envelopes WHERE envelope_id = ?", (signed["envelope_id"],)
        ).fetchone()
        if envelope is None:
            raise LedgerError("economic signed transaction has no envelope")
        acknowledged = conn.execute(
            """SELECT 1 FROM submission_attempts
               WHERE signed_transaction_id = ? AND acknowledgment = 'ACCEPTED' LIMIT 1""",
            (signed_id,),
        ).fetchone() is not None
        expectation = __import__(
            "qntyspot.execution_contract", fromlist=["SettlementExpectationV0"]
        ).SettlementExpectationV0(
            economic_action_id=EconomicActionIDV0(action_id),
            transaction_hash=signed["transaction_hash"],
            chain_id=signed["chain_id"],
            taker_address=signed["taker_address"],
            submission_acknowledged=acknowledged,
        )
        rows = conn.execute(
            "SELECT * FROM chain_observations "
            "WHERE external_action_id = ? AND signed_transaction_id = ? "
            "ORDER BY observed_at_epoch_s ASC, observation_id ASC",
            (action_id, signed_id),
        ).fetchall()
        truth = evaluate_chain_truth(
            expectation,
            tuple(self._observation_from_row(row) for row in rows),
            finality,
        )
        return truth, signed, envelope

    def record_chain_observation(
        self,
        observation: ChainObservationV0,
        *,
        external_action_id: str,
        signed_transaction_id: str,
        finality: FinalityPolicyV0 = ROBINHOOD_V0_FINALITY,
    ) -> bool:
        with self._transaction("chain_observation") as conn:
            signed = conn.execute(
                "SELECT * FROM signed_transactions WHERE signed_transaction_id = ?",
                (signed_transaction_id,),
            ).fetchone()
            if signed is None:
                raise LedgerError(f"unknown signed transaction {signed_transaction_id}")
            if signed["external_action_id"] != external_action_id:
                raise ChainTruthError("observation external action disagrees with signed metadata")
            if observation.transaction_hash != signed["transaction_hash"]:
                raise ChainTruthError("observation hash disagrees with signed metadata")
            inserted = self._insert_or_match(
                conn,
                "chain_observations",
                "observation_id",
                observation.observation_id,
                self._observation_values(observation, external_action_id, signed_transaction_id),
            )
            if external_action_id == signed["external_action_id"] and conn.execute(
                "SELECT kind FROM external_actions WHERE external_action_id = ?",
                (external_action_id,),
            ).fetchone()[0] == "ECONOMIC":
                truth, _signed, _envelope = self._truth_for_action(
                    conn, external_action_id, signed_transaction_id, finality
                )
                state = self.ledger.intent_state(external_action_id)
                if truth.verdict is ChainTruthVerdict.AMBIGUOUS:
                    if state not in {IntentState.SAFE_HALT, IntentState.FILLED, IntentState.REJECTED}:
                        self.ledger.transition(
                            external_action_id,
                            IntentState.SAFE_HALT,
                            now_epoch_s=observation.observed_at_epoch_s,
                            payload={"execution": "ambiguous_chain_observation"},
                        )
                elif truth.verdict in {
                    ChainTruthVerdict.INCLUDED,
                    ChainTruthVerdict.CONFIRMED,
                }:
                    self._advance_to_chain_state(
                        external_action_id,
                        state,
                        IntentState.CONFIRMED
                        if truth.verdict is ChainTruthVerdict.CONFIRMED
                        else IntentState.INCLUDED,
                        now_epoch_s=observation.observed_at_epoch_s,
                    )
            return inserted

    def _advance_to_chain_state(
        self,
        action_id: str,
        state: IntentState,
        target: IntentState,
        *,
        now_epoch_s: int,
    ) -> None:
        path = {
            IntentState.SIGNED: (IntentState.SUBMITTED, IntentState.INCLUDED),
            IntentState.SUBMITTED: (IntentState.INCLUDED,),
            IntentState.INCLUDED: (),
            IntentState.CONFIRMED: (),
        }
        if target is IntentState.CONFIRMED:
            self._advance_to_chain_state(
                action_id, state, IntentState.INCLUDED, now_epoch_s=now_epoch_s
            )
            state = self.ledger.intent_state(action_id)
            if state is IntentState.INCLUDED:
                self.ledger.transition(
                    action_id, IntentState.CONFIRMED, now_epoch_s=now_epoch_s,
                    payload={"execution": "confirmed_chain_observation"},
                )
            return
        if target is not IntentState.INCLUDED or state is target:
            return
        if state is IntentState.SIGNED:
            self.ledger.transition(
                action_id, IntentState.SUBMITTED, now_epoch_s=now_epoch_s,
                payload={"execution": "included_chain_observation"},
            )
            state = IntentState.SUBMITTED
        if state is IntentState.SUBMITTED:
            self.ledger.transition(
                action_id, IntentState.INCLUDED, now_epoch_s=now_epoch_s,
                payload={"execution": "included_chain_observation"},
            )
        elif state not in {IntentState.INCLUDED, IntentState.CONFIRMED}:
            raise LedgerError(f"chain observation cannot advance intent from {state.value}")

    def _bounds_from_intent(self, row: Mapping[str, Any]) -> EconomicBounds:
        data = strict_json_loads(row["bounds_json"])
        return EconomicBounds(
            side=Side(data["side"]),
            input_instrument_id=data["input_instrument_id"],
            output_instrument_id=data["output_instrument_id"],
            max_input_atomic=int(data["max_input_atomic"]),
            min_output_atomic=int(data["min_output_atomic"]),
            limit_price=parse_canonical_decimal(data["limit_price"], field="limit_price"),
            max_price_impact_bps=int(data["max_price_impact_bps"]),
            max_slippage_bps=int(data["max_slippage_bps"]),
            deadline_epoch_s=int(data["deadline_epoch_s"]),
        )

    def reconcile_external_action(
        self,
        economic_action_id: str,
        *,
        now_epoch_s: int,
        finality: FinalityPolicyV0 = ROBINHOOD_V0_FINALITY,
        bounds: EconomicBounds | None = None,
        receipt_id: str | None = None,
        fee_atomic: int = 0,
        source: str = "external-chain-observation",
        observed_at_epoch_s: int | None = None,
    ) -> Any:
        with self._transaction("reconciliation") as conn:
            external = conn.execute(
                "SELECT kind FROM external_actions WHERE external_action_id = ?",
                (economic_action_id,),
            ).fetchone()
            if external is None or external["kind"] != "ECONOMIC":
                raise LedgerError("only an economic external action can reconcile to settlement")
            action_row = self._require_economic_intent(economic_action_id, conn)
            persisted_bounds = self._bounds_from_intent(action_row)
            if bounds is not None and bounds != persisted_bounds:
                raise EnvelopeValidationError(
                    "caller-supplied bounds differ from the persisted intent bounds"
                )
            bounds = persisted_bounds
            signed = conn.execute(
                "SELECT signed_transaction_id FROM signed_transactions "
                "WHERE external_action_id = ?", (economic_action_id,)
            ).fetchone()
            if signed is None:
                raise LedgerError("economic action has no signed transaction metadata")
            truth, signed_row, _envelope = self._truth_for_action(
                conn, economic_action_id, signed["signed_transaction_id"], finality
            )
            existing = conn.execute(
                "SELECT * FROM reconciliations WHERE external_action_id = ?",
                (economic_action_id,),
            ).fetchone()
            if existing is not None:
                if truth.verdict is ChainTruthVerdict.CONFIRMED and receipt_id is None:
                    raise LedgerError("a confirmed economic action requires a receipt id")
                expected = self._reconciliation_values(
                    economic_action_id,
                    truth,
                    now_epoch_s,
                    receipt_id=(receipt_id if truth.verdict is ChainTruthVerdict.CONFIRMED else None),
                )
                _record_values(
                    existing,
                    {
                        key: value
                        for key, value in expected.items()
                        if key != "reconciled_at_epoch_s"
                    },
                )
                return truth
            if truth.verdict in {ChainTruthVerdict.NO_EVIDENCE, ChainTruthVerdict.VISIBLE, ChainTruthVerdict.INCLUDED}:
                raise SafeHaltError(
                    f"chain truth is {truth.verdict.value}; reconciliation must wait for terminal evidence"
                )
            state = self.ledger.intent_state(economic_action_id)
            if truth.verdict is ChainTruthVerdict.AMBIGUOUS:
                self._insert_reconciliation(
                    conn, economic_action_id, truth, now_epoch_s, receipt_id=None,
                )
                if state not in {IntentState.SAFE_HALT, IntentState.REJECTED, IntentState.FILLED}:
                    self.ledger.transition(
                        economic_action_id, IntentState.SAFE_HALT,
                        now_epoch_s=now_epoch_s,
                        payload={"execution": "ambiguous_reconciliation"},
                    )
                return truth
            if truth.verdict is ChainTruthVerdict.REVERTED:
                self._insert_reconciliation(
                    conn, economic_action_id, truth, now_epoch_s, receipt_id=None,
                )
                if state in EXTERNALLY_AMBIGUOUS_STATES:
                    self.ledger.transition(
                        economic_action_id, IntentState.REJECTED,
                        now_epoch_s=now_epoch_s,
                        payload={"execution": "confirmed_revert"},
                    )
                return truth

            if receipt_id is None:
                raise LedgerError("a confirmed economic action requires a receipt id")
            validated_action = _validated_economic_action_from_database(
                EconomicActionIDV0(economic_action_id),
                signed_row["transaction_hash"],
                signed_row["chain_id"],
                signed_row["taker_address"],
            )
            receipt = reconcile_to_receipt(
                __import__(
                    "qntyspot.execution_contract", fromlist=["SettlementExpectationV0"]
                ).SettlementExpectationV0(
                    economic_action_id=EconomicActionIDV0(economic_action_id),
                    transaction_hash=signed_row["transaction_hash"],
                    chain_id=signed_row["chain_id"],
                    taker_address=signed_row["taker_address"],
                    submission_acknowledged=True,
                ),
                truth,
                bounds,
                validated_action=validated_action,
                receipt_id=receipt_id,
                fee_atomic=fee_atomic,
                observed_at_epoch_s=now_epoch_s if observed_at_epoch_s is None else observed_at_epoch_s,
                source=source,
            )
            if state not in {IntentState.CONFIRMED, IntentState.INCLUDED, IntentState.SUBMITTED, IntentState.SIGNED}:
                raise SafeHaltError(f"confirmed settlement cannot be accounted from {state.value}")
            self.ledger.append_execution_fill_receipt(
                receipt,
                validated_action=validated_action,
                now_epoch_s=now_epoch_s,
            )
            self._insert_reconciliation(
                conn, economic_action_id, truth, now_epoch_s, receipt_id=receipt.receipt_id,
            )
            self._advance_to_chain_state(
                economic_action_id, self.ledger.intent_state(economic_action_id),
                IntentState.CONFIRMED, now_epoch_s=now_epoch_s,
            )
            if self.ledger.intent_state(economic_action_id) is IntentState.CONFIRMED:
                self.ledger.transition(
                    economic_action_id, IntentState.RECONCILED,
                    now_epoch_s=now_epoch_s,
                    payload={"execution": "settlement_reconciled"},
                )
            return truth

    def _insert_reconciliation(
        self,
        conn: sqlite3.Connection,
        action_id: str,
        truth: Any,
        now_epoch_s: int,
        *,
        receipt_id: str | None,
    ) -> str:
        values = self._reconciliation_values(
            action_id, truth, now_epoch_s, receipt_id=receipt_id
        )
        self._insert_or_match(
            conn, "reconciliations", "reconciliation_id", values["reconciliation_id"], values
        )
        return values["reconciliation_id"]

    @staticmethod
    def _reconciliation_values(
        action_id: str,
        truth: Any,
        now_epoch_s: int,
        *,
        receipt_id: str | None,
    ) -> dict[str, Any]:
        verdict = {
            ChainTruthVerdict.CONFIRMED: "SETTLED",
            ChainTruthVerdict.REVERTED: "REVERTED",
            ChainTruthVerdict.AMBIGUOUS: "AMBIGUOUS",
        }[truth.verdict]
        reconciliation_id = digest_object(
            {
                "external_action_id": action_id,
                "receipt_id": receipt_id,
                "truth_evidence_digest": truth.evidence_digest,
                "verdict": verdict,
                "schema": "qntyspot.program_b1.v0.reconciliation",
            }
        )
        values = {
            "reconciliation_id": reconciliation_id,
            "external_action_id": action_id,
            "verdict": verdict,
            "receipt_id": receipt_id,
            "transaction_hash": truth.transaction_hash,
            "chain_id": truth.chain_id,
            "taker_address": truth.taker_address,
            "confirmation_depth": truth.confirmation_depth,
            "agreeing_provider_count": truth.agreeing_provider_count,
            "reconciled_at_epoch_s": now_epoch_s,
            "evidence_digest": truth.evidence_digest,
        }
        return values

    def complete_settlement(self, economic_action_id: str, *, now_epoch_s: int) -> bool:
        with self._transaction("fill_accounting"):
            if self.ledger.intent_state(economic_action_id) is not IntentState.RECONCILED:
                raise LedgerError("only a reconciled action can complete settlement bookkeeping")
            self.ledger.transition(
                economic_action_id, IntentState.FILLED, now_epoch_s=now_epoch_s,
                payload={"execution": "settlement_completed"},
            )
        return True

    def engage_kill_switch(
        self, *, now_epoch_s: int, reason: str, session_id: str | None = None
    ) -> bool:
        if not isinstance(reason, str) or not reason or reason.strip() != reason:
            raise LedgerError("kill-switch reason must be a non-empty label")
        with self._transaction("kill_switch") as conn:
            if self._kill_engaged():
                return False
            conn.execute(
                "INSERT INTO operator_control_events "
                "(session_id, control, engaged, occurred_epoch_s, reason) "
                "VALUES (?, 'KILL_SWITCH', 1, ?, ?)",
                (session_id, now_epoch_s, reason),
            )
        return True

    def read_execution_state(self) -> dict[str, Any]:
        tables: dict[str, list[dict[str, Any]]] = {}
        order_by = {
            "execution_sessions": "session_id",
            "authority_root_state": "trust_config_digest",
            "execution_envelopes": "envelope_id",
            "approval_actions": "approval_action_id",
            "external_actions": "external_action_id",
            "signed_transactions": "signed_transaction_id",
            "submission_attempts": "submission_attempt_id",
            "chain_observations": "observation_id",
            "reconciliations": "reconciliation_id",
            "operator_control_events": "seq",
        }
        for table, column in order_by.items():
            tables[table] = [
                dict(row) for row in self._conn.execute(
                    f"SELECT * FROM {table} ORDER BY {column} ASC"
                )
            ]
        return {
            "execution_schema_version": EXECUTION_SCHEMA_VERSION,
            "kill_switch_engaged": self._kill_engaged(),
            "tables": tables,
        }

    def execution_state_digest(self) -> str:
        return digest_object(self.read_execution_state())


ExecutionStore = ExecutionRuntime
