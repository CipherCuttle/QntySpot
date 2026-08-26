"""QntySpot -- deterministic policy-bound spot shadow runtime.

PHASE: PROGRAM B PRE-LIVE EXECUTION CONTRACT -- ROBINHOOD_SHADOW_READ_ONLY
--------------------------------------------------------------------------
This package contains the merged bounded Ink and Solana/Jupiter adapters and
one bounded public-read Robinhood/Chainlink/0x adapter. It has no signer, no key handling, no
transaction encoder, no transaction broadcast surface, and no live-capital
authority from any other repository.

``execution_contract`` and ``ledger.execution_schema`` are the frozen Program B
pre-live execution contract: immutable records, deterministic validators, and a
SQLite authority surface that describes a future runtime. They authorize
nothing. ``PHASE_GRANTED_AUTHORITY_LEVEL`` is ``AuthorityLevel.SHADOW`` and the
capability gate refuses everything above it.

What it does contain: an immutable domain model, a strict fail-closed policy
reader, a deterministic economic-limit contract, an append-only SQLite ledger
with database-enforced exactly-once economic identity and atomic budget
reservation, deterministic replay, and restart recovery that never retries an
action whose outcome is unknown.

See ``docs/AUTHORITY.md`` for the binding statement of what this phase
authorizes and forbids.
"""

from __future__ import annotations

__version__ = "0.0.1a0"

#: Machine-readable phase marker. Anything that reads this and proceeds to a
#: network or signing operation is violating the phase contract.
AUTHORITY = "ROBINHOOD_SHADOW_READ_ONLY"
NETWORK_AUTHORIZED = True
SIGNING_AUTHORIZED = False
LIVE_CAPITAL_AUTHORIZED = False

from .errors import (  # noqa: E402
    BudgetExceededError,
    BackupAliasError,
    BackupDestinationError,
    BackupError,
    BackupInterruptedError,
    BackupVerificationError,
    CanonicalFormError,
    DatabaseIntegrityError,
    DatabaseMalformedError,
    DatabaseMissingError,
    DatabaseOperationError,
    DatabaseSchemaError,
    DuplicateEconomicActionError,
    IdentityError,
    LedgerError,
    PolicyError,
    PolicyMissingError,
    QntySpotError,
    LockError,
    LockHeldError,
    LockPathError,
    OperationsError,
    ReplayDivergenceError,
    InkError,
    RpcError,
    RpcProtocolError,
    RpcResponseTooLargeError,
    RpcTimeoutError,
    RpcTransportError,
    SafeHaltError,
    StateTransitionError,
    SolanaError,
    SolanaTransportError,
    SolanaTimeoutError,
    SolanaResponseTooLargeError,
    SolanaProtocolError,
    JupiterApiError,
    RobinhoodError,
    RobinhoodTransportError,
    RobinhoodProtocolError,
    ZeroXApiError,
    ZeroXApiKeyRequired,
    ApprovalContractError,
    AuthorityCeilingError,
    ChainTruthError,
    EnvelopeValidationError,
    ExecutionContractError,
    SessionIdentityError,
)
from .domain import (  # noqa: E402
    CycleV0,
    EconomicBounds,
    ExecutionPlanV0,
    FillReceiptV0,
    IntentV0,
    LadderKind,
    LadderLevelV0,
    LadderV0,
    PolicyV0,
    PortfolioBudgetV0,
    QuoteV0,
    RuntimeStateV0,
    Side,
    economic_action_id,
)
from .identity import (  # noqa: E402
    AssetClass,
    EvmInstrumentRef,
    InstrumentV0,
    SolanaCluster,
    SolanaInstrumentRef,
    TokenProgram,
)
from .execution_contract import (  # noqa: E402
    CONTRACT_VERSION as PROGRAM_B_CONTRACT_VERSION,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    ApprovalActionV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    Capability,
    ChainObservationV0,
    ChainTruthV0,
    ChainTruthVerdict,
    EconomicActionIDV0,
    ExecutionEnvelopeV0,
    ExecutionReadiness,
    ExecutionSessionV0,
    FinalityPolicyV0,
    SignedTransactionRecordV0,
    SubmissionAttemptV0,
)
from .policy import load_policy_file, load_policy_text, parse_policy  # noqa: E402
from .states import IntentState  # noqa: E402
from .solana import (  # noqa: E402
    JupiterV2Client,
    SolanaMarketObservationV0,
    SolanaRpcClient,
    SolanaShadowAdapter,
)

__all__ = [
    "__version__",
    "AUTHORITY",
    "NETWORK_AUTHORIZED",
    "SIGNING_AUTHORIZED",
    "LIVE_CAPITAL_AUTHORIZED",
    "QntySpotError",
    "CanonicalFormError",
    "PolicyError",
    "PolicyMissingError",
    "IdentityError",
    "StateTransitionError",
    "LedgerError",
    "DuplicateEconomicActionError",
    "BudgetExceededError",
    "OperationsError",
    "LockError",
    "LockHeldError",
    "LockPathError",
    "DatabaseOperationError",
    "DatabaseMissingError",
    "DatabaseMalformedError",
    "DatabaseIntegrityError",
    "DatabaseSchemaError",
    "BackupError",
    "BackupAliasError",
    "BackupDestinationError",
    "BackupInterruptedError",
    "BackupVerificationError",
    "ReplayDivergenceError",
    "SafeHaltError",
    "InkError",
    "RpcError",
    "RpcProtocolError",
    "RpcResponseTooLargeError",
    "RpcTimeoutError",
    "RpcTransportError",
    "SolanaError",
    "SolanaTransportError",
    "SolanaTimeoutError",
    "SolanaResponseTooLargeError",
    "SolanaProtocolError",
    "JupiterApiError",
    "RobinhoodError",
    "RobinhoodTransportError",
    "RobinhoodProtocolError",
    "ZeroXApiError",
    "ZeroXApiKeyRequired",
    "ExecutionContractError",
    "AuthorityCeilingError",
    "SessionIdentityError",
    "EnvelopeValidationError",
    "ApprovalContractError",
    "ChainTruthError",
    "Side",
    "LadderKind",
    "LadderLevelV0",
    "LadderV0",
    "PolicyV0",
    "PortfolioBudgetV0",
    "CycleV0",
    "EconomicBounds",
    "IntentV0",
    "QuoteV0",
    "ExecutionPlanV0",
    "FillReceiptV0",
    "RuntimeStateV0",
    "economic_action_id",
    "AssetClass",
    "InstrumentV0",
    "EvmInstrumentRef",
    "SolanaInstrumentRef",
    "SolanaCluster",
    "TokenProgram",
    "IntentState",
    "PROGRAM_B_CONTRACT_VERSION",
    "PHASE_GRANTED_AUTHORITY_LEVEL",
    "AuthorityLevel",
    "Capability",
    "AuthorityPolicyRefV0",
    "ExecutionSessionV0",
    "ExecutionEnvelopeV0",
    "ApprovalActionV0",
    "SignedTransactionRecordV0",
    "SubmissionAttemptV0",
    "ChainObservationV0",
    "ChainTruthV0",
    "ChainTruthVerdict",
    "EconomicActionIDV0",
    "FinalityPolicyV0",
    "ExecutionReadiness",
    "SolanaRpcClient",
    "JupiterV2Client",
    "SolanaMarketObservationV0",
    "SolanaShadowAdapter",
    "parse_policy",
    "load_policy_text",
    "load_policy_file",
]
