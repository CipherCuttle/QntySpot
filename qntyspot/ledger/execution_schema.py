"""Program B execution authority surface: one transactional SQLite schema.

WHY ONE SURFACE
---------------
The lesson already paid for in Qnty is that a multi-file authority protocol --
a database here, a receipt file there, a marker file to tie them together --
has no atomic commit point, so a crash between two writes leaves an authority
state nobody can reconstruct. The future live execution authority is therefore
one transactional SQLite surface. There is no authoritative filesystem
artefact; raw provider payloads may be content-addressed on disk as evidence,
but the authority over what happened lives in these tables.

WHAT THE ENGINE ENFORCES, NOT THE APPLICATION
---------------------------------------------
* ``external_actions`` is the union of the two kinds of external effect a
  future runtime may cause: an economic action (a swap) and an approval. It is
  NOT a second identity system. A table CHECK requires
  ``external_action_id = COALESCE(economic_action_id, approval_action_id)``, so
  the identity of an economic external action IS its ``EconomicActionID``.
* ``signed_transactions.external_action_id`` is UNIQUE. One economic action can
  therefore never be associated with two economically distinct signed
  transactions. Retransmitting identical signed bytes reuses the same row,
  because ``signed_transaction_id`` is a digest of the envelope identity and
  the payload digest; a retransmission adds a ``submission_attempts`` row, not
  a signed transaction and not an economic action.
* ``signed_transactions`` also has UNIQUE ``(chain_id, taker_address,
  account_nonce)``, so two different signed transactions cannot collide on one
  nonce.
* ``execution_envelopes`` has a partial UNIQUE index allowing at most one
  AUTHORIZED envelope per economic action, and at most one AUTHORIZED envelope
  per ``(taker, chain, nonce)``.
* ``approval_actions`` has a partial UNIQUE index allowing at most one
  AUTHORIZED approval per ``(taker, token, spender)``.
* ``reconciliations.external_action_id`` is UNIQUE, and a SETTLED verdict is
  the only verdict that may carry a receipt.
* ``execution_sessions``, ``signed_transactions``, ``submission_attempts``, ``chain_observations``,
  ``external_actions``, ``reconciliations`` and ``operator_control_events``
  are append-only in the engine, via BEFORE UPDATE / BEFORE DELETE triggers
  that abort. Authorized envelope and approval identity-bearing facts are
  immutable after authorization, while their lifecycle may advance.
* Every table is STRICT, so a type confusion is a write error rather than a
  silently coerced value.

WHAT THIS MODULE IS NOT
-----------------------
It creates tables. It writes no rows, opens no connection of its own, signs
nothing, submits nothing, and stores no key material anywhere: a signed
transaction is represented by a digest of its payload, its length, and its
hash. ``EXECUTION_SCHEMA_VERSION`` is independently versioned from the core
``SCHEMA_VERSION``. Version 2 adds the append-only external transaction
reference and alternate chain-observation binding. Version 3 adds an
explicit external-signed origin for exact-byte admission while preserving
historical envelope and approval rows.
"""

from __future__ import annotations

import sqlite3

from ..errors import LedgerError, SchemaVersionError
from .atomics import non_negative_atomic_check, positive_atomic_check

__all__ = [
    "EXECUTION_SCHEMA_VERSION",
    "EXECUTION_SCHEMA_VERSION_V1",
    "EXECUTION_SCHEMA_VERSION_V2",
    "EXECUTION_SCHEMA_VERSION_V3",
    "EXECUTION_SCHEMA_SQL",
    "EXECUTION_TABLES",
    "EXECUTION_TABLES_V1",
    "apply_execution_schema",
    "migrate_execution_schema_v1_to_v2",
    "migrate_execution_schema_v2_to_v3",
    "migrate_execution_schema_v3_to_v4",
    "validate_execution_schema_shape",
    "read_execution_schema_version",
]

EXECUTION_SCHEMA_VERSION_V1 = 1
EXECUTION_SCHEMA_VERSION_V2 = 2
EXECUTION_SCHEMA_VERSION_V3 = 3
EXECUTION_SCHEMA_VERSION = 4

EXECUTION_TABLES_V1 = (
    "execution_sessions",
    "authority_root_state",
    "execution_envelopes",
    "approval_actions",
    "external_actions",
    "signed_transactions",
    "submission_attempts",
    "chain_observations",
    "reconciliations",
    "operator_control_events",
)

EXECUTION_TABLES = (
    *EXECUTION_TABLES_V1[:5],
    "external_transaction_refs",
    *EXECUTION_TABLES_V1[5:],
)

_APPEND_ONLY_TABLES = (
    "execution_sessions",
    "external_actions",
    "external_transaction_refs",
    "signed_transactions",
    "submission_attempts",
    "chain_observations",
    "reconciliations",
    "operator_control_events",
)

_CHECKS = {
    "pos_requested_allowance": positive_atomic_check("requested_allowance_atomic"),
    "nn_prior_allowance": non_negative_atomic_check("observed_prior_allowance_atomic"),
    "pos_max_input": positive_atomic_check("max_input_atomic"),
    "pos_min_output": positive_atomic_check("min_output_atomic"),
    "nn_tx_value": non_negative_atomic_check("transaction_value_atomic"),
    "pos_fee_ceiling": positive_atomic_check("max_fee_per_gas_ceiling_atomic"),
    "nn_priority_ceiling": non_negative_atomic_check("max_priority_fee_per_gas_ceiling_atomic"),
    "nn_effective_input": non_negative_atomic_check("effective_input_atomic"),
    "nn_effective_output": non_negative_atomic_check("effective_output_atomic"),
}

_SIGNED_TRANSACTIONS_TABLE_SQL = """
CREATE TABLE signed_transactions (
    signed_transaction_id TEXT PRIMARY KEY,
    external_action_id    TEXT NOT NULL UNIQUE
                          REFERENCES external_actions(external_action_id),
    session_id            TEXT NOT NULL REFERENCES execution_sessions(session_id),
    envelope_id           TEXT REFERENCES execution_envelopes(envelope_id),
    approval_action_id    TEXT REFERENCES approval_actions(approval_action_id),
    origin               TEXT NOT NULL DEFAULT 'ENVELOPE'
                          CHECK (origin IN ('ENVELOPE','APPROVAL','EXTERNAL_SIGNED_BYTES')),
    chain_id              INTEGER NOT NULL CHECK (chain_id > 0),
    taker_address         TEXT NOT NULL,
    account_nonce         INTEGER NOT NULL CHECK (account_nonce >= 0),
    raw_signed_sha256     TEXT NOT NULL UNIQUE,
    raw_signed_length     INTEGER NOT NULL CHECK (raw_signed_length > 0),
    transaction_hash      TEXT NOT NULL UNIQUE,
    scope_digest          TEXT NOT NULL DEFAULT '',
    signer_identity       TEXT NOT NULL,
    frozen_at_epoch_s     INTEGER NOT NULL CHECK (frozen_at_epoch_s >= 0),
    CHECK (
        origin IN ('ENVELOPE','APPROVAL')
        OR (origin = 'EXTERNAL_SIGNED_BYTES' AND envelope_id IS NULL AND approval_action_id IS NULL)
    ),
    UNIQUE (chain_id, taker_address, account_nonce)
) STRICT;
"""


_SCHEMA_TEMPLATE = """
CREATE TABLE execution_sessions (
    session_id            TEXT PRIMARY KEY,
    identity_digest       TEXT NOT NULL,
    repository_commit     TEXT NOT NULL,
    implementation_digest TEXT NOT NULL,
    runtime_identity      TEXT NOT NULL,
    db_schema_version     INTEGER NOT NULL CHECK (db_schema_version >= 0),
    policy_id             TEXT NOT NULL REFERENCES policies(policy_id),
    authority_root_id     TEXT NOT NULL,
    authority_policy_digest TEXT NOT NULL,
    authority_level       INTEGER NOT NULL CHECK (authority_level BETWEEN 0 AND 4),
    taker_address         TEXT NOT NULL,
    network_id            TEXT NOT NULL,
    venue_id              TEXT NOT NULL,
    venue_adapter_version TEXT NOT NULL,
    started_at_epoch_s    INTEGER NOT NULL CHECK (started_at_epoch_s >= 0),
    session_ordinal       INTEGER NOT NULL CHECK (session_ordinal >= 0),
    UNIQUE (identity_digest, started_at_epoch_s, session_ordinal)
) STRICT;

-- This is a local continuity projection, not the external trust anchor.
-- There is one high-water mark per digest-pinned operator configuration so a
-- new externally configured root cannot silently rewrite the old history.
CREATE TABLE authority_root_state (
    trust_config_digest          TEXT PRIMARY KEY,
    root_id                      TEXT NOT NULL,
    public_key_fingerprint       TEXT NOT NULL,
    minimum_authority_epoch      INTEGER NOT NULL CHECK (minimum_authority_epoch > 0),
    highest_accepted_epoch       INTEGER NOT NULL CHECK (highest_accepted_epoch >= minimum_authority_epoch),
    highest_accepted_receipt_id  TEXT NOT NULL,
    highest_accepted_at_epoch_s  INTEGER NOT NULL CHECK (highest_accepted_at_epoch_s >= 0)
) STRICT;

CREATE TABLE approval_actions (
    approval_action_id    TEXT PRIMARY KEY,
    session_id            TEXT NOT NULL REFERENCES execution_sessions(session_id),
    session_identity_digest TEXT NOT NULL,
    economic_action_id    TEXT REFERENCES intents(economic_action_id),
    taker_address         TEXT NOT NULL,
    token_address         TEXT NOT NULL,
    spender_address       TEXT NOT NULL,
    requested_allowance_atomic      TEXT NOT NULL CHECK {pos_requested_allowance},
    observed_prior_allowance_atomic TEXT NOT NULL CHECK {nn_prior_allowance},
    authority_policy_digest TEXT NOT NULL,
    lifecycle             TEXT NOT NULL
                          CHECK (lifecycle IN ('DRAFT','AUTHORIZED','SUPERSEDED','VOID','SETTLED')),
    deadline_epoch_s      INTEGER NOT NULL CHECK (deadline_epoch_s > 0),
    created_at_epoch_s    INTEGER NOT NULL CHECK (created_at_epoch_s >= 0)
) STRICT;

-- One live approval per (taker, token, spender). An approval is an external
-- effect: two concurrent live ones would make the on-chain allowance the
-- result of a race rather than of a decision.
CREATE UNIQUE INDEX uq_approval_authorized
    ON approval_actions(taker_address, token_address, spender_address)
    WHERE lifecycle = 'AUTHORIZED';

CREATE TABLE execution_envelopes (
    envelope_id           TEXT PRIMARY KEY,
    session_id            TEXT NOT NULL REFERENCES execution_sessions(session_id),
    session_identity_digest TEXT NOT NULL,
    economic_action_id    TEXT NOT NULL REFERENCES intents(economic_action_id),
    plan_id               TEXT NOT NULL,
    quote_id              TEXT NOT NULL,
    quote_observation_digest TEXT NOT NULL,
    venue_block_number    INTEGER NOT NULL CHECK (venue_block_number >= 0),
    chain_id              INTEGER NOT NULL CHECK (chain_id > 0),
    taker_address         TEXT NOT NULL,
    input_instrument_id   TEXT NOT NULL REFERENCES instruments(instrument_id),
    output_instrument_id  TEXT NOT NULL REFERENCES instruments(instrument_id),
    max_input_atomic      TEXT NOT NULL CHECK {pos_max_input},
    min_output_atomic     TEXT NOT NULL CHECK {pos_min_output},
    transaction_to        TEXT NOT NULL,
    transaction_value_atomic TEXT NOT NULL CHECK {nn_tx_value},
    calldata_sha256       TEXT NOT NULL,
    calldata_length       INTEGER NOT NULL CHECK (calldata_length > 0),
    allowance_target      TEXT,
    account_nonce         INTEGER NOT NULL CHECK (account_nonce >= 0),
    gas_limit_ceiling     INTEGER NOT NULL CHECK (gas_limit_ceiling > 0),
    max_fee_per_gas_ceiling_atomic TEXT NOT NULL CHECK {pos_fee_ceiling},
    max_priority_fee_per_gas_ceiling_atomic TEXT NOT NULL CHECK {nn_priority_ceiling},
    deadline_epoch_s      INTEGER NOT NULL CHECK (deadline_epoch_s > 0),
    authority_policy_digest TEXT NOT NULL,
    evidence_digest       TEXT NOT NULL,
    lifecycle             TEXT NOT NULL
                          CHECK (lifecycle IN ('DRAFT','AUTHORIZED','SUPERSEDED','VOID')),
    constructed_at_epoch_s INTEGER NOT NULL CHECK (constructed_at_epoch_s >= 0),
    CHECK (input_instrument_id <> output_instrument_id)
) STRICT;

CREATE INDEX idx_envelopes_action ON execution_envelopes(economic_action_id);

-- At most one authorized envelope per economic action. A re-quote may create a
-- new DRAFT envelope, but the previous one must be SUPERSEDED first, so there
-- is never a moment at which two distinct envelopes are both signable.
CREATE UNIQUE INDEX uq_envelope_authorized
    ON execution_envelopes(economic_action_id)
    WHERE lifecycle = 'AUTHORIZED';

-- Nonce collision is a database error, not a runtime race.
CREATE UNIQUE INDEX uq_envelope_nonce
    ON execution_envelopes(taker_address, chain_id, account_nonce)
    WHERE lifecycle = 'AUTHORIZED';

CREATE TABLE external_actions (
    external_action_id TEXT PRIMARY KEY,
    kind               TEXT NOT NULL CHECK (kind IN ('ECONOMIC','APPROVAL')),
    economic_action_id TEXT UNIQUE REFERENCES intents(economic_action_id),
    approval_action_id TEXT UNIQUE REFERENCES approval_actions(approval_action_id),
    session_id         TEXT REFERENCES execution_sessions(session_id),
    CHECK ((economic_action_id IS NULL) <> (approval_action_id IS NULL)),
    CHECK ((kind = 'ECONOMIC') = (economic_action_id IS NOT NULL)),
    -- The identity of an economic external action IS its EconomicActionID.
    CHECK (external_action_id = COALESCE(economic_action_id, approval_action_id))
) STRICT;

-- A transaction made outside QntySpot is represented by its stable public
-- identity only. It has no payload, signature, or construction material.
CREATE TABLE external_transaction_refs (
    external_transaction_ref_id TEXT PRIMARY KEY,
    external_action_id          TEXT NOT NULL UNIQUE
                                REFERENCES external_actions(external_action_id),
    session_id                  TEXT NOT NULL REFERENCES execution_sessions(session_id),
    session_identity_digest     TEXT NOT NULL,
    economic_action_id          TEXT NOT NULL UNIQUE REFERENCES intents(economic_action_id),
    transaction_hash            TEXT NOT NULL UNIQUE,
    chain_id                    INTEGER NOT NULL CHECK (chain_id > 0),
    taker_address               TEXT NOT NULL,
    authority_policy_digest     TEXT NOT NULL,
    origin                      TEXT NOT NULL CHECK (origin = 'EXTERNAL_TO_QNTYSPOT'),
    CHECK (external_action_id = economic_action_id)
) STRICT;

{signed_transactions_table}

CREATE TABLE submission_attempts (
    submission_attempt_id TEXT PRIMARY KEY,
    signed_transaction_id TEXT NOT NULL
                          REFERENCES signed_transactions(signed_transaction_id),
    provider_id           TEXT NOT NULL,
    attempt_ordinal       INTEGER NOT NULL CHECK (attempt_ordinal >= 0),
    submitted_at_epoch_s  INTEGER NOT NULL CHECK (submitted_at_epoch_s >= 0),
    acknowledgment        TEXT NOT NULL
                          CHECK (acknowledgment IN ('ACCEPTED','REJECTED','UNKNOWN')),
    provider_reported_hash TEXT,
    error_class           TEXT,
    UNIQUE (signed_transaction_id, provider_id, attempt_ordinal)
) STRICT;

CREATE INDEX idx_submissions_signed ON submission_attempts(signed_transaction_id);

CREATE TABLE chain_observations (
    observation_id        TEXT PRIMARY KEY,
    external_action_id    TEXT NOT NULL REFERENCES external_actions(external_action_id),
    signed_transaction_id TEXT REFERENCES signed_transactions(signed_transaction_id),
    external_transaction_ref_id TEXT REFERENCES external_transaction_refs(external_transaction_ref_id),
    provider_id           TEXT NOT NULL,
    transaction_hash      TEXT NOT NULL,
    observed_at_epoch_s   INTEGER NOT NULL CHECK (observed_at_epoch_s >= 0),
    presence              TEXT NOT NULL CHECK (presence IN ('ABSENT','PENDING','INCLUDED')),
    block_number          INTEGER,
    block_hash            TEXT,
    block_parent_hash     TEXT,
    head_block_number     INTEGER,
    head_block_hash       TEXT,
    receipt_status        TEXT CHECK (receipt_status IS NULL
                                      OR receipt_status IN ('SUCCESS','REVERTED')),
    effective_input_atomic  TEXT CHECK (effective_input_atomic IS NULL
                                        OR {nn_effective_input}),
    effective_output_atomic TEXT CHECK (effective_output_atomic IS NULL
                                        OR {nn_effective_output}),
    raw_evidence_sha256   TEXT NOT NULL,
    CHECK ((presence = 'INCLUDED') = (block_hash IS NOT NULL)),
    CHECK ((presence = 'INCLUDED') = (block_number IS NOT NULL)),
    CHECK ((presence = 'INCLUDED') = (block_parent_hash IS NOT NULL)),
    CHECK ((presence = 'INCLUDED') = (receipt_status IS NOT NULL)),
    CHECK (block_number IS NULL OR block_number >= 0),
    CHECK (head_block_number IS NULL OR head_block_number >= 0),
    CHECK (presence = 'INCLUDED' OR
           (block_number IS NULL AND block_hash IS NULL AND
            block_parent_hash IS NULL AND receipt_status IS NULL)),
    CHECK ((head_block_number IS NULL) = (head_block_hash IS NULL)),
    CHECK (presence <> 'INCLUDED' OR head_block_number IS NULL OR
           head_block_number >= block_number),
    CHECK ((effective_input_atomic IS NULL) = (effective_output_atomic IS NULL)),
    CHECK (effective_input_atomic IS NULL OR
           (presence = 'INCLUDED' AND receipt_status = 'SUCCESS')),
    CHECK ((signed_transaction_id IS NULL) <> (external_transaction_ref_id IS NULL))
) STRICT;

CREATE INDEX idx_observations_action ON chain_observations(external_action_id);

CREATE TABLE reconciliations (
    reconciliation_id      TEXT PRIMARY KEY,
    external_action_id     TEXT NOT NULL UNIQUE
                           REFERENCES external_actions(external_action_id),
    verdict                TEXT NOT NULL
                           CHECK (verdict IN ('SETTLED','REVERTED','AMBIGUOUS')),
    receipt_id             TEXT REFERENCES fill_receipts(receipt_id),
    -- Reverted release is valid only for this exact external expectation.
    -- These are nullable for the historical SETTLED/AMBIGUOUS shape, but a
    -- REVERTED row must carry all three and the trigger below binds them to
    -- the canonical signed transaction.
    transaction_hash      TEXT,
    chain_id              INTEGER,
    taker_address         TEXT,
    confirmation_depth     INTEGER NOT NULL CHECK (confirmation_depth >= 0),
    agreeing_provider_count INTEGER NOT NULL CHECK (agreeing_provider_count >= 0),
    reconciled_at_epoch_s  INTEGER NOT NULL CHECK (reconciled_at_epoch_s >= 0),
    evidence_digest        TEXT NOT NULL,
    -- Only a settled reconciliation may carry a receipt, and it must carry one.
    CHECK ((verdict = 'SETTLED') = (receipt_id IS NOT NULL)),
    CHECK (verdict <> 'REVERTED' OR
           (transaction_hash IS NOT NULL AND chain_id IS NOT NULL AND taker_address IS NOT NULL)),
    CHECK ((transaction_hash IS NULL) = (chain_id IS NULL)),
    CHECK ((transaction_hash IS NULL) = (taker_address IS NULL))
) STRICT;

CREATE TABLE operator_control_events (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       TEXT REFERENCES execution_sessions(session_id),
    control          TEXT NOT NULL CHECK (control IN ('KILL_SWITCH')),
    engaged          INTEGER NOT NULL CHECK (engaged IN (0,1)),
    occurred_epoch_s INTEGER NOT NULL CHECK (occurred_epoch_s >= 0),
    reason           TEXT NOT NULL
) STRICT;
"""

_APPEND_ONLY_TEMPLATE = """
CREATE TRIGGER {table}_no_update
BEFORE UPDATE ON {table}
BEGIN
    SELECT RAISE(ABORT, '{table} is append-only');
END;

CREATE TRIGGER {table}_no_delete
BEFORE DELETE ON {table}
BEGIN
    SELECT RAISE(ABORT, '{table} is append-only');
END;
"""

_CONFLICT_REPLACEMENT_SQL = """
CREATE TRIGGER authority_root_state_no_rollback
BEFORE UPDATE ON authority_root_state
WHEN NEW.trust_config_digest <> OLD.trust_config_digest
   OR NEW.root_id <> OLD.root_id
   OR NEW.public_key_fingerprint <> OLD.public_key_fingerprint
   OR NEW.minimum_authority_epoch <> OLD.minimum_authority_epoch
   OR NEW.highest_accepted_epoch < OLD.highest_accepted_epoch
   OR (NEW.highest_accepted_epoch = OLD.highest_accepted_epoch
       AND NEW.highest_accepted_receipt_id <> OLD.highest_accepted_receipt_id)
   OR NEW.highest_accepted_at_epoch_s < OLD.highest_accepted_at_epoch_s
BEGIN
    SELECT RAISE(ABORT, 'authority root state rollback or identity change');
END;

CREATE TRIGGER authority_root_state_no_delete
BEFORE DELETE ON authority_root_state
BEGIN
    SELECT RAISE(ABORT, 'authority root state is non-deletable');
END;

CREATE TRIGGER execution_sessions_no_conflict_replace
BEFORE INSERT ON execution_sessions
WHEN EXISTS (SELECT 1 FROM execution_sessions WHERE session_id = NEW.session_id)
   OR EXISTS (
       SELECT 1 FROM execution_sessions
        WHERE identity_digest = NEW.identity_digest
          AND started_at_epoch_s = NEW.started_at_epoch_s
          AND session_ordinal = NEW.session_ordinal
   )
BEGIN
    SELECT RAISE(ABORT, 'execution_sessions is append-only');
END;

CREATE TRIGGER approval_actions_no_conflict_replace
BEFORE INSERT ON approval_actions
WHEN EXISTS (SELECT 1 FROM approval_actions WHERE approval_action_id = NEW.approval_action_id)
   OR (
       NEW.lifecycle = 'AUTHORIZED'
       AND EXISTS (
           SELECT 1 FROM approval_actions
            WHERE lifecycle = 'AUTHORIZED'
              AND taker_address = NEW.taker_address
              AND token_address = NEW.token_address
              AND spender_address = NEW.spender_address
       )
   )
BEGIN
    SELECT RAISE(ABORT, 'approval action conflict replacement is forbidden');
END;

CREATE TRIGGER execution_envelopes_no_conflict_replace
BEFORE INSERT ON execution_envelopes
WHEN EXISTS (SELECT 1 FROM execution_envelopes WHERE envelope_id = NEW.envelope_id)
   OR (
       NEW.lifecycle = 'AUTHORIZED'
       AND EXISTS (
           SELECT 1 FROM execution_envelopes
            WHERE lifecycle = 'AUTHORIZED'
              AND (
                  economic_action_id = NEW.economic_action_id
                  OR (
                      taker_address = NEW.taker_address
                      AND chain_id = NEW.chain_id
                      AND account_nonce = NEW.account_nonce
                  )
              )
       )
   )
BEGIN
    SELECT RAISE(ABORT, 'execution envelope conflict replacement is forbidden');
END;

CREATE TRIGGER external_actions_no_conflict_replace
BEFORE INSERT ON external_actions
WHEN EXISTS (SELECT 1 FROM external_actions WHERE external_action_id = NEW.external_action_id)
   OR (NEW.economic_action_id IS NOT NULL AND EXISTS (
       SELECT 1 FROM external_actions WHERE economic_action_id = NEW.economic_action_id
   ))
   OR (NEW.approval_action_id IS NOT NULL AND EXISTS (
       SELECT 1 FROM external_actions WHERE approval_action_id = NEW.approval_action_id
   ))
BEGIN
    SELECT RAISE(ABORT, 'external_actions is append-only');
END;

CREATE TRIGGER signed_transactions_no_conflict_replace
BEFORE INSERT ON signed_transactions
WHEN EXISTS (SELECT 1 FROM signed_transactions WHERE signed_transaction_id = NEW.signed_transaction_id)
   OR EXISTS (SELECT 1 FROM signed_transactions WHERE external_action_id = NEW.external_action_id)
   OR EXISTS (SELECT 1 FROM signed_transactions WHERE raw_signed_sha256 = NEW.raw_signed_sha256)
   OR EXISTS (SELECT 1 FROM signed_transactions WHERE transaction_hash = NEW.transaction_hash)
   OR EXISTS (
       SELECT 1 FROM signed_transactions
        WHERE chain_id = NEW.chain_id
          AND taker_address = NEW.taker_address
          AND account_nonce = NEW.account_nonce
   )
BEGIN
    SELECT RAISE(ABORT, 'signed_transactions is append-only');
END;

CREATE TRIGGER submission_attempts_no_conflict_replace
BEFORE INSERT ON submission_attempts
WHEN EXISTS (SELECT 1 FROM submission_attempts WHERE submission_attempt_id = NEW.submission_attempt_id)
   OR EXISTS (
       SELECT 1 FROM submission_attempts
        WHERE signed_transaction_id = NEW.signed_transaction_id
          AND provider_id = NEW.provider_id
          AND attempt_ordinal = NEW.attempt_ordinal
   )
BEGIN
    SELECT RAISE(ABORT, 'submission_attempts is append-only');
END;

CREATE TRIGGER chain_observations_no_conflict_replace
BEFORE INSERT ON chain_observations
WHEN EXISTS (SELECT 1 FROM chain_observations WHERE observation_id = NEW.observation_id)
BEGIN
    SELECT RAISE(ABORT, 'chain_observations is append-only');
END;

CREATE TRIGGER external_transaction_refs_no_conflict_replace
BEFORE INSERT ON external_transaction_refs
WHEN EXISTS (SELECT 1 FROM external_transaction_refs
             WHERE external_transaction_ref_id = NEW.external_transaction_ref_id)
   OR EXISTS (SELECT 1 FROM external_transaction_refs
             WHERE external_action_id = NEW.external_action_id)
   OR EXISTS (SELECT 1 FROM external_transaction_refs
             WHERE transaction_hash = NEW.transaction_hash)
BEGIN
    SELECT RAISE(ABORT, 'external_transaction_refs is append-only');
END;

CREATE TRIGGER reconciliations_no_conflict_replace
BEFORE INSERT ON reconciliations
WHEN EXISTS (SELECT 1 FROM reconciliations WHERE reconciliation_id = NEW.reconciliation_id)
   OR EXISTS (SELECT 1 FROM reconciliations WHERE external_action_id = NEW.external_action_id)
BEGIN
    SELECT RAISE(ABORT, 'reconciliations is append-only');
END;

CREATE TRIGGER operator_control_events_no_conflict_replace
BEFORE INSERT ON operator_control_events
WHEN EXISTS (SELECT 1 FROM operator_control_events WHERE seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'operator_control_events is append-only');
END;
"""

_IDENTITY_COLUMNS = {
    "approval_actions": (
        "approval_action_id", "session_id", "session_identity_digest",
        "economic_action_id", "taker_address", "token_address", "spender_address",
        "requested_allowance_atomic", "observed_prior_allowance_atomic",
        "authority_policy_digest", "deadline_epoch_s", "created_at_epoch_s",
    ),
    "execution_envelopes": (
        "envelope_id", "session_id", "session_identity_digest", "economic_action_id",
        "plan_id", "quote_id", "quote_observation_digest", "venue_block_number",
        "chain_id", "taker_address", "input_instrument_id", "output_instrument_id",
        "max_input_atomic", "min_output_atomic", "transaction_to",
        "transaction_value_atomic", "calldata_sha256", "calldata_length",
        "allowance_target", "account_nonce", "gas_limit_ceiling",
        "max_fee_per_gas_ceiling_atomic", "max_priority_fee_per_gas_ceiling_atomic",
        "deadline_epoch_s", "authority_policy_digest", "evidence_digest",
        "constructed_at_epoch_s",
    ),
}

_AUTHORIZED_IMMUTABILITY_SQL = "".join(
    f"""
CREATE TRIGGER {table}_authorized_no_identity_update
BEFORE UPDATE ON {table}
WHEN OLD.lifecycle <> 'DRAFT'
 AND ({' OR '.join(f'NEW.{column} IS NOT OLD.{column}' for column in columns)})
BEGIN
    SELECT RAISE(ABORT, '{table} identity is immutable after authorization');
END;

CREATE TRIGGER {table}_authorized_no_delete
BEFORE DELETE ON {table}
WHEN OLD.lifecycle <> 'DRAFT'
BEGIN
    SELECT RAISE(ABORT, '{table} is immutable after authorization');
END;
"""
    for table, columns in _IDENTITY_COLUMNS.items()
)

_LIFECYCLE_GUARDS_SQL = """
CREATE TRIGGER execution_envelopes_lifecycle_guard
BEFORE UPDATE OF lifecycle ON execution_envelopes
WHEN NOT (
    NEW.lifecycle = OLD.lifecycle
    OR (OLD.lifecycle = 'DRAFT' AND NEW.lifecycle IN ('AUTHORIZED','SUPERSEDED','VOID'))
    OR (OLD.lifecycle = 'AUTHORIZED' AND NEW.lifecycle IN ('SUPERSEDED','VOID'))
)
BEGIN
    SELECT RAISE(ABORT, 'execution_envelopes lifecycle regression');
END;

CREATE TRIGGER approval_actions_lifecycle_guard
BEFORE UPDATE OF lifecycle ON approval_actions
WHEN NOT (
    NEW.lifecycle = OLD.lifecycle
    OR (OLD.lifecycle = 'DRAFT' AND NEW.lifecycle IN ('AUTHORIZED','SUPERSEDED','VOID'))
    OR (OLD.lifecycle = 'AUTHORIZED' AND NEW.lifecycle IN ('SUPERSEDED','VOID','SETTLED'))
)
BEGIN
    SELECT RAISE(ABORT, 'approval_actions lifecycle regression');
END;
"""

_CROSS_TABLE_GUARDS_SQL = """
CREATE TRIGGER execution_envelopes_session_identity_guard
BEFORE INSERT ON execution_envelopes
WHEN NOT EXISTS (
    SELECT 1 FROM execution_sessions
     WHERE session_id = NEW.session_id
       AND identity_digest = NEW.session_identity_digest
)
BEGIN
    SELECT RAISE(ABORT, 'execution envelope session identity does not match session');
END;

CREATE TRIGGER execution_envelopes_session_identity_update_guard
BEFORE UPDATE OF session_id, session_identity_digest ON execution_envelopes
WHEN NOT EXISTS (
    SELECT 1 FROM execution_sessions
     WHERE session_id = NEW.session_id
       AND identity_digest = NEW.session_identity_digest
)
BEGIN
    SELECT RAISE(ABORT, 'execution envelope session identity does not match session');
END;

CREATE TRIGGER approval_actions_session_identity_guard
BEFORE INSERT ON approval_actions
WHEN NOT EXISTS (
    SELECT 1 FROM execution_sessions
     WHERE session_id = NEW.session_id
       AND identity_digest = NEW.session_identity_digest
)
BEGIN
    SELECT RAISE(ABORT, 'approval session identity does not match session');
END;

CREATE TRIGGER approval_actions_session_identity_update_guard
BEFORE UPDATE OF session_id, session_identity_digest ON approval_actions
WHEN NOT EXISTS (
    SELECT 1 FROM execution_sessions
     WHERE session_id = NEW.session_id
       AND identity_digest = NEW.session_identity_digest
)
BEGIN
    SELECT RAISE(ABORT, 'approval session identity does not match session');
END;

CREATE TRIGGER signed_transactions_kind_guard
BEFORE INSERT ON signed_transactions
BEGIN
    SELECT CASE WHEN NEW.origin = 'EXTERNAL_SIGNED_BYTES' AND EXISTS (
        SELECT 1 FROM execution_envelopes WHERE envelope_id = NEW.envelope_id
    ) THEN RAISE(ABORT, 'external signed origin cannot name an envelope') END;
    SELECT CASE WHEN NEW.origin = 'ENVELOPE'
        AND NEW.envelope_id IS NULL AND NEW.approval_action_id IS NULL
        THEN RAISE(ABORT, 'signed transaction subtype is missing') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM external_transaction_refs
         WHERE external_action_id = NEW.external_action_id
    ) THEN RAISE(ABORT, 'economic action already has an external transaction reference') END;
    SELECT CASE WHEN NEW.origin = 'EXTERNAL_SIGNED_BYTES' AND NOT EXISTS (
        SELECT 1
          FROM external_actions AS ea
          JOIN execution_sessions AS es ON es.session_id = NEW.session_id
         WHERE ea.external_action_id = NEW.external_action_id
           AND ea.kind = 'ECONOMIC'
           AND ea.economic_action_id = NEW.external_action_id
           AND (ea.session_id IS NULL OR ea.session_id = NEW.session_id)
           AND es.taker_address = NEW.taker_address
           AND es.network_id = 'evm:' || NEW.chain_id
    ) THEN RAISE(ABORT, 'external signed transaction is not bound to its action/session') END;
    SELECT CASE WHEN NEW.envelope_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
          FROM external_actions AS ea
          JOIN execution_envelopes AS ee ON ee.envelope_id = NEW.envelope_id
         WHERE ea.external_action_id = NEW.external_action_id
           AND ea.kind = 'ECONOMIC'
           AND ea.economic_action_id = ee.economic_action_id
           AND ee.lifecycle = 'AUTHORIZED'
           AND NEW.session_id = ee.session_id
           AND NEW.chain_id = ee.chain_id
           AND NEW.taker_address = ee.taker_address
           AND NEW.account_nonce = ee.account_nonce
    ) THEN RAISE(ABORT, 'economic signed transaction subtype does not match external action') END;
    SELECT CASE WHEN NEW.approval_action_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
          FROM external_actions AS ea
          JOIN approval_actions AS aa ON aa.approval_action_id = NEW.approval_action_id
         WHERE ea.external_action_id = NEW.external_action_id
           AND ea.kind = 'APPROVAL'
           AND ea.approval_action_id = aa.approval_action_id
           AND NEW.session_id = aa.session_id
           AND NEW.taker_address = aa.taker_address
    ) THEN RAISE(ABORT, 'approval signed transaction subtype does not match external action') END;
END;

CREATE TRIGGER external_transaction_refs_no_signed_origin
BEFORE INSERT ON external_transaction_refs
WHEN EXISTS (
    SELECT 1 FROM signed_transactions
     WHERE external_action_id = NEW.external_action_id
)
BEGIN
    SELECT RAISE(ABORT, 'economic action already has a signed transaction origin');
END;

CREATE TRIGGER external_transaction_refs_binding_guard
BEFORE INSERT ON external_transaction_refs
WHEN NOT EXISTS (
    SELECT 1
      FROM external_actions AS ea
      JOIN execution_sessions AS es ON es.session_id = NEW.session_id
     WHERE ea.external_action_id = NEW.external_action_id
       AND ea.kind = 'ECONOMIC'
       AND ea.economic_action_id = NEW.economic_action_id
       AND (ea.session_id IS NULL OR ea.session_id = NEW.session_id)
       AND es.identity_digest = NEW.session_identity_digest
       AND es.authority_policy_digest = NEW.authority_policy_digest
       AND es.taker_address = NEW.taker_address
       AND es.network_id = 'evm:' || NEW.chain_id
)
BEGIN
    SELECT RAISE(ABORT, 'external transaction reference is not bound to its session/action');
END;

CREATE TRIGGER chain_observations_binding_guard
BEFORE INSERT ON chain_observations
WHEN NOT EXISTS (
    SELECT 1
      FROM signed_transactions AS st
     WHERE st.signed_transaction_id = NEW.signed_transaction_id
       AND st.external_action_id = NEW.external_action_id
)
AND NOT EXISTS (
    SELECT 1
      FROM external_transaction_refs AS etr
     WHERE etr.external_transaction_ref_id = NEW.external_transaction_ref_id
       AND etr.external_action_id = NEW.external_action_id
       AND etr.transaction_hash = NEW.transaction_hash
)
BEGIN
    SELECT RAISE(ABORT, 'chain observation is not bound to one transaction origin');
END;

CREATE TRIGGER reconciliations_receipt_kind_guard
BEFORE INSERT ON reconciliations
WHEN NEW.receipt_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM external_actions
         WHERE external_action_id = NEW.external_action_id
           AND kind = 'ECONOMIC'
    ) THEN RAISE(ABORT, 'only economic external actions may carry a fill receipt') END;
END;

CREATE TRIGGER reconciliations_receipt_binding_guard
BEFORE INSERT ON reconciliations
WHEN NEW.receipt_id IS NOT NULL
 AND EXISTS (
    SELECT 1 FROM external_actions
     WHERE external_action_id = NEW.external_action_id
       AND kind = 'ECONOMIC'
 )
 AND NOT EXISTS (
    SELECT 1
      FROM external_actions AS ea
      JOIN fill_receipts AS fr ON fr.receipt_id = NEW.receipt_id
     WHERE ea.external_action_id = NEW.external_action_id
       AND ea.kind = 'ECONOMIC'
       AND fr.economic_action_id = ea.economic_action_id
 )
BEGIN
    SELECT RAISE(ABORT, 'reconciliation receipt is not bound to the economic action');
END;

CREATE TRIGGER reconciliations_reverted_binding_guard
BEFORE INSERT ON reconciliations
WHEN NEW.verdict = 'REVERTED'
 AND NOT EXISTS (
    SELECT 1
      FROM signed_transactions AS st
      JOIN external_actions AS ea ON ea.external_action_id = st.external_action_id
      JOIN chain_observations AS co
        ON co.signed_transaction_id = st.signed_transaction_id
       AND co.external_action_id = st.external_action_id
     WHERE ea.external_action_id = NEW.external_action_id
       AND st.transaction_hash = NEW.transaction_hash
       AND st.chain_id = NEW.chain_id
       AND st.taker_address = NEW.taker_address
       AND co.presence = 'INCLUDED'
       AND co.receipt_status = 'REVERTED'
 )
 AND NOT EXISTS (
    SELECT 1
      FROM external_transaction_refs AS etr
      JOIN chain_observations AS co
        ON co.external_transaction_ref_id = etr.external_transaction_ref_id
       AND co.external_action_id = etr.external_action_id
     WHERE etr.external_action_id = NEW.external_action_id
       AND etr.transaction_hash = NEW.transaction_hash
       AND etr.chain_id = NEW.chain_id
       AND etr.taker_address = NEW.taker_address
       AND co.presence = 'INCLUDED'
       AND co.receipt_status = 'REVERTED'
 )
BEGIN
    SELECT RAISE(ABORT, 'reverted reconciliation is not bound to the transaction origin');
END;
"""

_EXECUTION_TRIGGER_SQL = "".join(
    _APPEND_ONLY_TEMPLATE.format(table=table) for table in _APPEND_ONLY_TABLES
) + _AUTHORIZED_IMMUTABILITY_SQL + _LIFECYCLE_GUARDS_SQL + _CROSS_TABLE_GUARDS_SQL + _CONFLICT_REPLACEMENT_SQL

EXECUTION_SCHEMA_SQL = _SCHEMA_TEMPLATE.format(
    **_CHECKS, signed_transactions_table=_SIGNED_TRANSACTIONS_TABLE_SQL
) + _EXECUTION_TRIGGER_SQL


_V2_EXTERNAL_TRANSACTION_REFS_SQL = """
CREATE TABLE external_transaction_refs (
    external_transaction_ref_id TEXT PRIMARY KEY,
    external_action_id          TEXT NOT NULL UNIQUE
                                REFERENCES external_actions(external_action_id),
    session_id                  TEXT NOT NULL REFERENCES execution_sessions(session_id),
    session_identity_digest     TEXT NOT NULL,
    economic_action_id          TEXT NOT NULL UNIQUE REFERENCES intents(economic_action_id),
    transaction_hash            TEXT NOT NULL UNIQUE,
    chain_id                    INTEGER NOT NULL CHECK (chain_id > 0),
    taker_address               TEXT NOT NULL,
    authority_policy_digest     TEXT NOT NULL,
    origin                      TEXT NOT NULL CHECK (origin = 'EXTERNAL_TO_QNTYSPOT'),
    CHECK (external_action_id = economic_action_id)
) STRICT
"""

_V2_CHAIN_OBSERVATIONS_SQL = """
CREATE TABLE chain_observations (
    observation_id        TEXT PRIMARY KEY,
    external_action_id    TEXT NOT NULL REFERENCES external_actions(external_action_id),
    signed_transaction_id TEXT REFERENCES signed_transactions(signed_transaction_id),
    external_transaction_ref_id TEXT REFERENCES external_transaction_refs(external_transaction_ref_id),
    provider_id           TEXT NOT NULL,
    transaction_hash      TEXT NOT NULL,
    observed_at_epoch_s   INTEGER NOT NULL CHECK (observed_at_epoch_s >= 0),
    presence              TEXT NOT NULL CHECK (presence IN ('ABSENT','PENDING','INCLUDED')),
    block_number          INTEGER,
    block_hash            TEXT,
    block_parent_hash     TEXT,
    head_block_number     INTEGER,
    head_block_hash       TEXT,
    receipt_status        TEXT CHECK (receipt_status IS NULL
                                      OR receipt_status IN ('SUCCESS','REVERTED')),
    effective_input_atomic  TEXT CHECK (effective_input_atomic IS NULL
                                        OR {nn_effective_input}),
    effective_output_atomic TEXT CHECK (effective_output_atomic IS NULL
                                        OR {nn_effective_output}),
    raw_evidence_sha256   TEXT NOT NULL,
    CHECK ((presence = 'INCLUDED') = (block_hash IS NOT NULL)),
    CHECK ((presence = 'INCLUDED') = (block_number IS NOT NULL)),
    CHECK ((presence = 'INCLUDED') = (block_parent_hash IS NOT NULL)),
    CHECK ((presence = 'INCLUDED') = (receipt_status IS NOT NULL)),
    CHECK (block_number IS NULL OR block_number >= 0),
    CHECK (head_block_number IS NULL OR head_block_number >= 0),
    CHECK (presence = 'INCLUDED' OR
           (block_number IS NULL AND block_hash IS NULL AND
            block_parent_hash IS NULL AND receipt_status IS NULL)),
    CHECK ((head_block_number IS NULL) = (head_block_hash IS NULL)),
    CHECK (presence <> 'INCLUDED' OR head_block_number IS NULL OR
           head_block_number >= block_number),
    CHECK ((effective_input_atomic IS NULL) = (effective_output_atomic IS NULL)),
    CHECK (effective_input_atomic IS NULL OR
           (presence = 'INCLUDED' AND receipt_status = 'SUCCESS')),
    CHECK ((signed_transaction_id IS NULL) <> (external_transaction_ref_id IS NULL))
) STRICT
""".format(**_CHECKS)


def _execute_trigger_script(conn: sqlite3.Connection, script: str) -> None:
    """Execute the internal trigger script without opening a second transaction."""
    statement = ""
    for line in script.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            conn.execute(statement)
            statement = ""
    if statement.strip():
        raise LedgerError("execution schema trigger migration ended with incomplete SQL")


_SIGNED_TRANSACTION_COLUMNS = (
    "signed_transaction_id",
    "external_action_id",
    "session_id",
    "envelope_id",
    "approval_action_id",
    "origin",
    "chain_id",
    "taker_address",
    "account_nonce",
    "raw_signed_sha256",
    "raw_signed_length",
    "transaction_hash",
    "scope_digest",
    "signer_identity",
    "frozen_at_epoch_s",
)
_SIGNED_TRANSACTION_LEGACY_COLUMNS = tuple(
    column for column in _SIGNED_TRANSACTION_COLUMNS if column not in {"origin", "scope_digest"}
)
_LEGACY_SIGNED_TRANSACTION_XOR = "CHECK ((ENVELOPE_ID IS NULL) <> (APPROVAL_ACTION_ID IS NULL))"


def _signed_transactions_create_sql(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'signed_transactions'"
    ).fetchone()
    if row is None or not isinstance(row[0], str):
        raise LedgerError("signed_transactions table definition is missing")
    return row[0]


def _signed_transactions_columns(conn: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[1] for row in conn.execute("PRAGMA table_info(signed_transactions)"))


def validate_execution_schema_shape(conn: sqlite3.Connection) -> None:
    """Fail closed unless the current version can admit every signed origin."""
    if _signed_transactions_columns(conn) != _SIGNED_TRANSACTION_COLUMNS:
        raise LedgerError("signed_transactions columns do not match execution schema v4")
    sql = " ".join(_signed_transactions_create_sql(conn).upper().split())
    if _LEGACY_SIGNED_TRANSACTION_XOR in sql:
        raise LedgerError("execution schema v4 retains the legacy signed-transaction XOR")
    required = (
        "ORIGIN IN ('ENVELOPE','APPROVAL','EXTERNAL_SIGNED_BYTES')",
        "ORIGIN = 'EXTERNAL_SIGNED_BYTES' AND ENVELOPE_ID IS NULL AND APPROVAL_ACTION_ID IS NULL",
        "UNIQUE (CHAIN_ID, TAKER_ADDRESS, ACCOUNT_NONCE)",
    )
    if any(fragment not in sql for fragment in required):
        raise LedgerError("signed_transactions constraints do not match execution schema v4")
    trigger_names = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'signed_transactions'"
        )
    }
    required_triggers = {
        "signed_transactions_no_update",
        "signed_transactions_no_delete",
        "signed_transactions_no_conflict_replace",
        "signed_transactions_kind_guard",
    }
    if not required_triggers <= trigger_names:
        raise LedgerError("signed_transactions append-only or binding guards are missing")


def _row_digest(conn: sqlite3.Connection, table: str, columns: tuple[str, ...]) -> str:
    import hashlib
    import json

    rows = [
        {column: row[index] for index, column in enumerate(columns)}
        for row in conn.execute(
            f"SELECT {','.join(columns)} FROM {table} ORDER BY {columns[0]}"
        )
    ]
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _rebuild_signed_transactions(conn: sqlite3.Connection) -> None:
    """Rebuild the table atomically while retaining all dependent tables."""
    columns = _signed_transactions_columns(conn)
    if set(columns) not in (
        set(_SIGNED_TRANSACTION_LEGACY_COLUMNS),
        set(_SIGNED_TRANSACTION_COLUMNS),
    ) or len(columns) not in {
        len(_SIGNED_TRANSACTION_LEGACY_COLUMNS),
        len(_SIGNED_TRANSACTION_COLUMNS),
    }:
        raise LedgerError("signed_transactions has an unsupported migration shape")
    before_count = conn.execute("SELECT COUNT(*) FROM signed_transactions").fetchone()[0]
    before_digest = _row_digest(conn, "signed_transactions", _SIGNED_TRANSACTION_LEGACY_COLUMNS)
    conn.execute(
        "CREATE TEMP TABLE signed_transactions_migration_backup AS "
        "SELECT * FROM signed_transactions"
    )
    triggers = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name IN ("
            + ",".join("?" for _ in EXECUTION_TABLES)
            + ")",
            EXECUTION_TABLES,
        )
    ]
    for trigger in triggers:
        conn.execute(f'DROP TRIGGER "{trigger.replace(chr(34), chr(34) * 2)}"')
    conn.execute("DROP TABLE signed_transactions")
    conn.execute(_SIGNED_TRANSACTIONS_TABLE_SQL)
    if set(columns) == set(_SIGNED_TRANSACTION_COLUMNS):
        conn.execute(
            "INSERT INTO signed_transactions (" + ",".join(_SIGNED_TRANSACTION_COLUMNS) + ") "
            "SELECT " + ",".join(_SIGNED_TRANSACTION_COLUMNS) + " "
            "FROM signed_transactions_migration_backup"
        )
    else:
        conn.execute(
            "INSERT INTO signed_transactions (" + ",".join(_SIGNED_TRANSACTION_COLUMNS) + ") "
            "SELECT signed_transaction_id, external_action_id, session_id, envelope_id, "
            "approval_action_id, CASE WHEN approval_action_id IS NULL THEN 'ENVELOPE' ELSE 'APPROVAL' END, "
            "chain_id, taker_address, account_nonce, raw_signed_sha256, raw_signed_length, "
            "transaction_hash, '', signer_identity, frozen_at_epoch_s "
            "FROM signed_transactions_migration_backup"
        )
    after_count = conn.execute("SELECT COUNT(*) FROM signed_transactions").fetchone()[0]
    after_digest = _row_digest(conn, "signed_transactions", _SIGNED_TRANSACTION_LEGACY_COLUMNS)
    if after_count != before_count or after_digest != before_digest:
        raise LedgerError("signed_transactions migration changed historical rows")
    conn.execute("DROP TABLE signed_transactions_migration_backup")
    _execute_trigger_script(conn, _EXECUTION_TRIGGER_SQL)
    validate_execution_schema_shape(conn)


def migrate_execution_schema_v3_to_v4(conn: sqlite3.Connection) -> None:
    """Repair v3 databases whose table shape cannot admit external bytes."""
    if read_execution_schema_version(conn) != EXECUTION_SCHEMA_VERSION_V3:
        raise SchemaVersionError("migration requires execution schema version 3")
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise LedgerError("execution schema migration requires foreign keys enabled")
    conn.execute("PRAGMA foreign_keys = OFF")
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 0:
        raise LedgerError("SQLite refused controlled migration foreign-key suspension")
    conn.execute("BEGIN IMMEDIATE")
    try:
        sql = " ".join(_signed_transactions_create_sql(conn).upper().split())
        if _LEGACY_SIGNED_TRANSACTION_XOR in sql:
            _rebuild_signed_transactions(conn)
        else:
            validate_execution_schema_shape(conn)
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'execution_schema_version'",
            (str(EXECUTION_SCHEMA_VERSION),),
        )
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'execution_authority'",
            ("B2_SUBMIT_EXACT_SIGNED_BYTES: external bytes only; no construction or signing",),
        )
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise LedgerError("execution schema migration introduced foreign-key violations")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise LedgerError("execution schema migration failed integrity_check")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")


def migrate_execution_schema_v1_to_v2(conn: sqlite3.Connection) -> None:
    """Migrate valid B1 v1 facts without discarding any execution history."""
    have = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    if set(EXECUTION_TABLES_V1) != have & set(EXECUTION_TABLES_V1):
        raise LedgerError("execution schema v1 is incomplete")
    if read_execution_schema_version(conn) != EXECUTION_SCHEMA_VERSION_V1:
        raise SchemaVersionError("migration requires execution schema version 1")
    conn.execute("BEGIN IMMEDIATE")
    try:
        trigger_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name IN ("
            + ",".join("?" for _ in EXECUTION_TABLES_V1)
            + ")",
            EXECUTION_TABLES_V1,
        ).fetchall()
        for row in trigger_rows:
            trigger_name = str(row[0]).replace('"', '""')
            conn.execute(f'DROP TRIGGER "{trigger_name}"')
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(external_actions)")
        }
        if "session_id" not in columns:
            conn.execute(
                "ALTER TABLE external_actions ADD COLUMN session_id TEXT "
                "REFERENCES execution_sessions(session_id)"
            )
        old_count = conn.execute("SELECT COUNT(*) FROM chain_observations").fetchone()[0]
        conn.execute("DROP INDEX IF EXISTS idx_observations_action")
        conn.execute("ALTER TABLE chain_observations RENAME TO chain_observations_v1")
        conn.execute(_V2_EXTERNAL_TRANSACTION_REFS_SQL)
        conn.execute(_V2_CHAIN_OBSERVATIONS_SQL)
        conn.execute(
            "CREATE INDEX idx_observations_action ON chain_observations(external_action_id)"
        )
        conn.execute(
            "INSERT INTO chain_observations ("
            "observation_id, external_action_id, signed_transaction_id, "
            "external_transaction_ref_id, provider_id, transaction_hash, "
            "observed_at_epoch_s, presence, block_number, block_hash, "
            "block_parent_hash, head_block_number, head_block_hash, receipt_status, "
            "effective_input_atomic, effective_output_atomic, raw_evidence_sha256) "
            "SELECT observation_id, external_action_id, signed_transaction_id, NULL, "
            "provider_id, transaction_hash, observed_at_epoch_s, presence, block_number, "
            "block_hash, block_parent_hash, head_block_number, head_block_hash, "
            "receipt_status, effective_input_atomic, effective_output_atomic, "
            "raw_evidence_sha256 FROM chain_observations_v1"
        )
        copied_count = conn.execute("SELECT COUNT(*) FROM chain_observations").fetchone()[0]
        if copied_count != old_count:
            raise LedgerError("execution schema migration did not preserve observations")
        conn.execute("DROP TABLE chain_observations_v1")
        _execute_trigger_script(conn, _EXECUTION_TRIGGER_SQL)
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'execution_schema_version'",
            (str(EXECUTION_SCHEMA_VERSION_V2),),
        )
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'execution_authority'",
            ("B1_RECONCILE_ONLY: no signer, no submission, no capital authority",),
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    migrate_execution_schema_v2_to_v3(conn)


def migrate_execution_schema_v2_to_v3(conn: sqlite3.Connection) -> None:
    """Add the origin discriminator, then complete the v4 shape repair."""
    if read_execution_schema_version(conn) != EXECUTION_SCHEMA_VERSION_V2:
        raise SchemaVersionError("migration requires execution schema version 2")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(signed_transactions)")}
    if ("origin" in columns) != ("scope_digest" in columns):
        raise LedgerError("v2 signed_transactions has a partial v3 column set")
    if "origin" in columns:
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'execution_schema_version'",
            (str(EXECUTION_SCHEMA_VERSION_V3),),
        )
        migrate_execution_schema_v3_to_v4(conn)
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        trigger_rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name IN ("
            + ",".join("?" for _ in EXECUTION_TABLES)
            + ")",
            EXECUTION_TABLES,
        ).fetchall()
        for row in trigger_rows:
            trigger_name = str(row[0]).replace('"', '""')
            conn.execute(f'DROP TRIGGER "{trigger_name}"')
        conn.execute(
            "ALTER TABLE signed_transactions ADD COLUMN origin TEXT NOT NULL DEFAULT 'ENVELOPE' "
            "CHECK (origin IN ('ENVELOPE','APPROVAL','EXTERNAL_SIGNED_BYTES'))"
        )
        conn.execute(
            "ALTER TABLE signed_transactions ADD COLUMN scope_digest TEXT NOT NULL DEFAULT ''"
        )
        conn.execute(
            "UPDATE signed_transactions SET origin = 'APPROVAL' "
            "WHERE envelope_id IS NULL AND approval_action_id IS NOT NULL"
        )
        _execute_trigger_script(conn, _EXECUTION_TRIGGER_SQL)
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'execution_schema_version'",
            (str(EXECUTION_SCHEMA_VERSION_V3),),
        )
        conn.execute(
            "UPDATE schema_meta SET value = ? WHERE key = 'execution_authority'",
            ("B2_SUBMIT_EXACT_SIGNED_BYTES: external bytes only; no construction or signing",),
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    migrate_execution_schema_v3_to_v4(conn)


def apply_execution_schema(conn: sqlite3.Connection) -> None:
    """Create the execution authority surface alongside an existing ledger.

    The core ledger must already exist: these tables reference ``policies``,
    ``instruments``, ``intents`` and ``fill_receipts``, because reusing the
    existing intent, reservation and receipt tables is the point. Applying the
    schema is a single transaction: either the whole surface lands or none of
    it does.
    """
    have = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    missing = sorted({"policies", "instruments", "intents", "fill_receipts"} - have)
    if missing:
        raise LedgerError(
            f"the execution surface requires the core ledger first; missing {missing}"
        )
    if collisions := sorted(have & set(EXECUTION_TABLES)):
        if set(collisions) == set(EXECUTION_TABLES_V1):
            migrate_execution_schema_v1_to_v2(conn)
            return
        if set(collisions) == set(EXECUTION_TABLES):
            version = read_execution_schema_version(conn)
            if version == EXECUTION_SCHEMA_VERSION_V2:
                migrate_execution_schema_v2_to_v3(conn)
                return
            if version == EXECUTION_SCHEMA_VERSION_V3:
                migrate_execution_schema_v3_to_v4(conn)
                return
        raise LedgerError(f"execution schema already applied: {collisions}")
    conn.execute("PRAGMA recursive_triggers = ON")
    if not conn.execute("PRAGMA recursive_triggers").fetchone()[0]:
        raise LedgerError(
            "SQLite refused to enable recursive_triggers; refusing to apply execution schema"
        )
    stamp = (
        "INSERT INTO schema_meta (key, value) VALUES\n"
        f"    ('execution_schema_version', '{EXECUTION_SCHEMA_VERSION}'),\n"
        "    ('execution_authority', 'B1_RECONCILE_ONLY: no signer, no submission, "
        "no capital authority');\n"
    )
    conn.executescript("BEGIN;\n" + EXECUTION_SCHEMA_SQL + "\n" + stamp + "COMMIT;\n")
    validate_execution_schema_shape(conn)


def read_execution_schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'execution_schema_version'"
    ).fetchone()
    if row is None:
        raise SchemaVersionError("database has no execution_schema_version")
    try:
        return int(row[0])
    except (TypeError, ValueError) as exc:
        raise SchemaVersionError(f"unreadable execution_schema_version {row[0]!r}") from exc
