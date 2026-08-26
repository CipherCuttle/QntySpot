"""QntySpot V0A error taxonomy.

Every error in this module means FAIL CLOSED. There is no error in V0A whose
correct handling is "continue anyway with a default".
"""

from __future__ import annotations


class QntySpotError(Exception):
    """Base class for every QntySpot failure."""


class CanonicalFormError(QntySpotError):
    """Input was not in the single canonical representation the contract requires."""


class PolicyError(QntySpotError):
    """Policy document could not be admitted."""


class PolicyMissingError(PolicyError):
    """No policy was supplied. Startup must refuse."""


class PolicyParseError(PolicyError):
    """Policy bytes were not admissible JSON under the strict reader."""


class PolicySchemaError(PolicyError):
    """Policy JSON was structurally valid but violated the V0 schema."""


class IdentityError(QntySpotError):
    """Instrument identity was absent, ambiguous, or not canonical."""


class StateTransitionError(QntySpotError):
    """An illegal lifecycle transition was attempted."""


class LedgerError(QntySpotError):
    """A ledger invariant was violated."""


class DuplicateEconomicActionError(LedgerError):
    """The same EconomicActionID was reserved or created twice."""


class BudgetExceededError(LedgerError):
    """A reservation would have exceeded a configured cap. No budget was taken."""


class ReplayDivergenceError(LedgerError):
    """Replaying the event stream did not reproduce the recorded state."""


class SchemaVersionError(LedgerError):
    """Database schema version is not the version this code understands."""


class OperationsError(QntySpotError):
    """An operational reliability check failed closed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class LockError(OperationsError):
    """The single-instance lock could not be inspected or acquired."""


class LockHeldError(LockError):
    """Another owner, including this process, already holds the lock."""


class LockPathError(LockError):
    """The lock path cannot be opened safely."""


class DatabaseOperationError(OperationsError):
    """A database could not be opened or verified read-only."""


class DatabaseMissingError(DatabaseOperationError):
    """The requested database file is absent."""


class DatabaseMalformedError(DatabaseOperationError):
    """The input is not an admissible SQLite database."""


class DatabaseIntegrityError(DatabaseOperationError):
    """SQLite integrity or foreign-key verification failed."""


class DatabaseSchemaError(DatabaseOperationError):
    """The SQLite file does not contain the supported ledger schema."""


class BackupError(OperationsError):
    """A native SQLite backup did not complete successfully."""


class BackupAliasError(BackupError):
    """The backup destination aliases the active database or its sidecars."""


class BackupDestinationError(BackupError):
    """The backup destination is not a safe new file."""


class BackupInterruptedError(BackupError):
    """A backup was interrupted and its partial output is not trusted."""


class BackupVerificationError(BackupError):
    """A backup completed but failed independent verification."""


class SafeHaltError(QntySpotError):
    """External truth is ambiguous. Operation must stop rather than speculate."""


class InkError(QntySpotError):
    """The bounded Ink shadow substrate rejected an operation."""


class RpcError(InkError):
    """The JSON-RPC exchange did not produce an admissible result."""


class RpcTransportError(RpcError):
    """A bounded transport attempt failed."""


class RpcTimeoutError(RpcTransportError):
    """A bounded RPC attempt exceeded its explicit timeout."""


class RpcResponseTooLargeError(RpcError):
    """An RPC response exceeded the configured byte bound."""


class RpcProtocolError(RpcError):
    """An RPC response violated the strict JSON-RPC contract."""


class LevelNotExecutableError(QntySpotError):
    """A ladder level cannot produce a well-formed economic action right now."""


class CycleLimitError(QntySpotError):
    """The policy's re-entry cycle limit has been reached."""


class SolanaError(QntySpotError):
    """The bounded Solana shadow substrate rejected an operation."""


class SolanaTransportError(SolanaError):
    """A bounded public-read transport attempt failed."""


class SolanaTimeoutError(SolanaTransportError):
    """A bounded public-read attempt exceeded its explicit timeout."""


class SolanaResponseTooLargeError(SolanaError):
    """A public-read response exceeded the configured byte bound."""


class SolanaProtocolError(SolanaError):
    """A Solana or Jupiter response violated the strict wire contract."""


class JupiterApiError(SolanaError):
    """The current official Jupiter read endpoint returned an API error."""


class RobinhoodError(QntySpotError):
    """The bounded Robinhood Chain shadow substrate rejected an operation."""


class RobinhoodTransportError(RobinhoodError):
    """A bounded public Robinhood read failed at the transport layer."""


class RobinhoodProtocolError(RobinhoodError):
    """A Robinhood, Chainlink, or EVM response violated the read contract."""


class ZeroXApiError(RobinhoodError):
    """The bounded 0x Swap API read returned an API error."""


class ZeroXApiKeyRequired(RobinhoodError):
    """A firm 0x quote cannot be requested without the local read credential."""
