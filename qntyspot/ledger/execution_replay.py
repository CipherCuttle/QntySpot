"""Deterministic reconstruction of the Program B execution surface."""

from __future__ import annotations

from typing import Any, Mapping

from ..canon import digest_object
from ..errors import LedgerError, ReplayDivergenceError
from ..execution_contract import (
    ApprovalActionV0,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    SignedTransactionRecordV0,
    SubmissionAttemptV0,
)
from .execution import ExecutionRuntime
from .execution_schema import EXECUTION_TABLES, apply_execution_schema
from .replay import _EXECUTION_REPLAY_TOKEN, replay_into
from .store import SpotLedger, open_ledger

__all__ = [
    "execution_snapshot",
    "replay_execution_into",
    "reconstruct_execution",
    "assert_execution_replay_equivalence",
]

_COPY_ORDER = (
    "execution_sessions",
    "approval_actions",
    "execution_envelopes",
    "external_actions",
    "signed_transactions",
    "submission_attempts",
    "chain_observations",
    "reconciliations",
    "operator_control_events",
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayDivergenceError(message)


def execution_snapshot(source: SpotLedger) -> dict[str, Any]:
    """Return all execution facts in explicit, deterministic table order."""
    if not all(
        source.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (table,)
        ).fetchone()
        for table in EXECUTION_TABLES
    ):
        raise LedgerError("execution schema is not applied")
    tables: dict[str, list[dict[str, Any]]] = {}
    order_by = {
        "execution_sessions": "session_id",
        "execution_envelopes": "envelope_id",
        "approval_actions": "approval_action_id",
        "external_actions": "external_action_id",
        "signed_transactions": "signed_transaction_id",
        "submission_attempts": "submission_attempt_id",
        "chain_observations": "observation_id",
        "reconciliations": "reconciliation_id",
        "operator_control_events": "seq",
    }
    for table in EXECUTION_TABLES:
        tables[table] = [
            dict(row)
            for row in source.connection.execute(
                f"SELECT * FROM {table} ORDER BY {order_by[table]} ASC"
            )
        ]
    return {
        "execution_schema_version": 0,
        "kill_switch_engaged": any(
            row["engaged"] == 1 for row in tables["operator_control_events"]
        ),
        "tables": tables,
    }


def _validated_reverted_bindings(snapshot: Mapping[str, Any]) -> frozenset[str]:
    """Validate cross-table revert bindings before core replay consumes them."""
    signed_by_action = {
        row["external_action_id"]: row
        for row in snapshot["tables"]["signed_transactions"]
        if row["envelope_id"] is not None
    }
    observations = snapshot["tables"]["chain_observations"]
    bindings: set[str] = set()
    for row in snapshot["tables"]["reconciliations"]:
        expected_id = digest_object(
            {
                "external_action_id": row["external_action_id"],
                "receipt_id": row["receipt_id"],
                "truth_evidence_digest": row["evidence_digest"],
                "verdict": row["verdict"],
                "schema": "qntyspot.program_b1.v0.reconciliation",
            }
        )
        _require(
            expected_id == row["reconciliation_id"],
            "reconciliations: identity mismatch",
        )
        if row["verdict"] == "REVERTED":
            signed = signed_by_action.get(row["external_action_id"])
            _require(
                signed is not None
                and row["transaction_hash"] == signed["transaction_hash"]
                and row["chain_id"] == signed["chain_id"]
                and row["taker_address"] == signed["taker_address"],
                "reconciliations: reverted row is not bound to signed metadata",
            )
            _require(
                any(
                    observation["external_action_id"] == row["external_action_id"]
                    and observation["signed_transaction_id"] == signed["signed_transaction_id"]
                    and observation["presence"] == "INCLUDED"
                    and observation["receipt_status"] == "REVERTED"
                    for observation in observations
                ),
                "reconciliations: reverted row has no bound reverted observation",
            )
            bindings.add(row["external_action_id"])
    return frozenset(bindings)


def _validate_settlement_states(target: SpotLedger) -> None:
    """Reject execution replays that mark settlement without settlement facts."""
    for row in target.connection.execute(
        "SELECT economic_action_id, state FROM intents "
        "WHERE state IN ('RECONCILED','FILLED') ORDER BY economic_action_id"
    ):
        settled = target.connection.execute(
            """
            SELECT 1
              FROM reconciliations AS r
              JOIN fill_receipts AS f ON f.receipt_id = r.receipt_id
             WHERE r.external_action_id = ?
               AND r.verdict = 'SETTLED'
               AND f.economic_action_id = r.external_action_id
             LIMIT 1
            """,
            (row["economic_action_id"],),
        ).fetchone()
        _require(
            settled is not None,
            f"execution replay: {row['state']} action has no SETTLED reconciliation and fill receipt",
        )


def _validate_identity(table: str, row: Mapping[str, Any]) -> None:
    """Recompute every canonical contract identity before copying a row."""
    try:
        if table == "execution_sessions":
            record = ExecutionSessionV0(
                repository_commit=row["repository_commit"],
                implementation_digest=row["implementation_digest"],
                runtime_identity=row["runtime_identity"],
                db_schema_version=row["db_schema_version"],
                policy_id=row["policy_id"],
                authority_policy_digest=row["authority_policy_digest"],
                taker_address=row["taker_address"],
                network_id=row["network_id"],
                venue_id=row["venue_id"],
                venue_adapter_version=row["venue_adapter_version"],
                started_at_epoch_s=row["started_at_epoch_s"],
                session_ordinal=row["session_ordinal"],
            )
            _require(record.identity_digest == row["identity_digest"], f"{table}: identity digest mismatch")
            _require(record.session_id == row["session_id"], f"{table}: session id mismatch")
        elif table == "execution_envelopes":
            record = ExecutionEnvelopeV0(
                session_id=row["session_id"],
                session_identity_digest=row["session_identity_digest"],
                economic_action_id=row["economic_action_id"],
                chain_id=row["chain_id"],
                taker_address=row["taker_address"],
                input_instrument_id=row["input_instrument_id"],
                output_instrument_id=row["output_instrument_id"],
                max_input_atomic=int(row["max_input_atomic"]),
                min_output_atomic=int(row["min_output_atomic"]),
                transaction_to=row["transaction_to"],
                transaction_value_atomic=int(row["transaction_value_atomic"]),
                calldata_sha256=row["calldata_sha256"],
                calldata_length=row["calldata_length"],
                allowance_target=row["allowance_target"],
                account_nonce=row["account_nonce"],
                gas_limit_ceiling=row["gas_limit_ceiling"],
                max_fee_per_gas_ceiling_atomic=int(row["max_fee_per_gas_ceiling_atomic"]),
                max_priority_fee_per_gas_ceiling_atomic=int(row["max_priority_fee_per_gas_ceiling_atomic"]),
                deadline_epoch_s=row["deadline_epoch_s"],
                authority_policy_digest=row["authority_policy_digest"],
                plan_id=row["plan_id"],
                quote_id=row["quote_id"],
                quote_observation_digest=row["quote_observation_digest"],
                venue_block_number=row["venue_block_number"],
                constructed_at_epoch_s=row["constructed_at_epoch_s"],
            )
            _require(record.envelope_id == row["envelope_id"], f"{table}: envelope id mismatch")
            _require(record.evidence_digest == row["evidence_digest"], f"{table}: evidence digest mismatch")
        elif table == "approval_actions":
            record = ApprovalActionV0(
                session_id=row["session_id"],
                session_identity_digest=row["session_identity_digest"],
                taker_address=row["taker_address"],
                token_address=row["token_address"],
                spender_address=row["spender_address"],
                requested_allowance_atomic=int(row["requested_allowance_atomic"]),
                observed_prior_allowance_atomic=int(row["observed_prior_allowance_atomic"]),
                authority_policy_digest=row["authority_policy_digest"],
                deadline_epoch_s=row["deadline_epoch_s"],
                economic_action_id=row["economic_action_id"],
            )
            _require(record.approval_action_id == row["approval_action_id"], f"{table}: approval id mismatch")
        elif table == "signed_transactions" and row["envelope_id"] is not None:
            record = SignedTransactionRecordV0(
                envelope_id=row["envelope_id"],
                raw_signed_sha256=row["raw_signed_sha256"],
                raw_signed_length=row["raw_signed_length"],
                transaction_hash=row["transaction_hash"],
                chain_id=row["chain_id"],
                account_nonce=row["account_nonce"],
                taker_address=row["taker_address"],
                signer_identity=row["signer_identity"],
            )
            _require(
                record.signed_transaction_id == row["signed_transaction_id"],
                f"{table}: signed transaction id mismatch",
            )
        elif table == "submission_attempts":
            record = SubmissionAttemptV0(
                signed_transaction_id=row["signed_transaction_id"],
                provider_id=row["provider_id"],
                attempt_ordinal=row["attempt_ordinal"],
                submitted_at_epoch_s=row["submitted_at_epoch_s"],
                acknowledgment=__import__(
                    "qntyspot.execution_contract", fromlist=["SubmissionAcknowledgment"]
                ).SubmissionAcknowledgment(row["acknowledgment"]),
                provider_reported_hash=row["provider_reported_hash"],
                error_class=row["error_class"],
            )
            _require(
                record.submission_attempt_id == row["submission_attempt_id"],
                f"{table}: submission attempt id mismatch",
            )
        elif table == "chain_observations":
            observation = ExecutionRuntime._observation_from_row(row)
            _require(
                observation.observation_id == row["observation_id"],
                f"{table}: observation id mismatch",
            )
    except (KeyError, TypeError, ValueError, LedgerError) as exc:
        if isinstance(exc, ReplayDivergenceError):
            raise
        raise ReplayDivergenceError(f"{table}: malformed canonical fact: {exc}") from exc


def replay_execution_into(target: SpotLedger, source: SpotLedger) -> None:
    """Copy validated execution facts into a target with the core replayed."""
    if target.connection.execute(
        "SELECT COUNT(*) FROM execution_sessions"
    ).fetchone()[0] != 0:
        raise LedgerError("execution replay target must be empty")
    source_state = execution_snapshot(source)
    with target._write() as conn:  # noqa: SLF001 - replay is one authority surface
        for table in _COPY_ORDER:
            for raw in source_state["tables"][table]:
                row = dict(raw)
                _validate_identity(table, row)
                names = sorted(row)
                conn.execute(
                    f"INSERT INTO {table} ({','.join(names)}) "
                    f"VALUES ({','.join(':' + name for name in names)})",
                    row,
                )
    _validate_settlement_states(target)


def reconstruct_execution(source: SpotLedger, *, path: str = ":memory:") -> SpotLedger:
    """Rebuild core and execution projections from canonical committed facts."""
    target = open_ledger(path)
    apply_execution_schema(target.connection)
    source_state = execution_snapshot(source)
    reverted_bindings = _validated_reverted_bindings(source_state)
    replay_into(
        target,
        canonical_policies=source.canonical_policies(),
        events=source.events(),
        trusted_reverted_external_action_ids=reverted_bindings,
        _execution_replay_token=_EXECUTION_REPLAY_TOKEN,
    )
    replay_execution_into(target, source)
    target.integrity_check()
    return target


def assert_execution_replay_equivalence(source: SpotLedger) -> str:
    """Require two independent reconstructions to have identical state/digest."""
    original = execution_snapshot(source)
    digests: list[str] = []
    for _ in range(2):
        with reconstruct_execution(source) as replayed:
            actual = execution_snapshot(replayed)
            if actual != original:
                raise ReplayDivergenceError("execution replay differs from source facts")
            digests.append(digest_object(actual))
    if digests[0] != digests[1]:
        raise ReplayDivergenceError("two execution replays disagreed")
    return digests[0]
