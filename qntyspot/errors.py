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


class SafeHaltError(QntySpotError):
    """External truth is ambiguous. Operation must stop rather than speculate."""


class LevelNotExecutableError(QntySpotError):
    """A ladder level cannot produce a well-formed economic action right now."""


class CycleLimitError(QntySpotError):
    """The policy's re-entry cycle limit has been reached."""
