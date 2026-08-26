"""Shared builders for the Program B pre-live execution contract tests.

Every address, digest and hash here is synthetic. Nothing in this module or in
the tests that use it signs, submits, approves, or reaches a network: the
contract under test is a set of pure dataclasses and deterministic validators.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

from qntyspot.canon import digest_object
from qntyspot.domain import EconomicBounds, Side
from qntyspot.execution_contract import (
    ApprovalActionV0,
    AuthorityLevel,
    AuthorityPolicyRefV0,
    ChainObservationV0,
    ChainPresence,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    EconomicActionIDV0,
    ReceiptStatus,
    SignedTransactionRecordV0,
    VenueQuoteResponseV0,
    ZeroXExecutionExpectationV0,
)

NOW = 1_700_000_100
CHAIN_ID = 4_663
NETWORK_ID = "evm:4663"
COMMIT = "a890de49e68486476b2385f70ef9c9558896f5b7"
IMPLEMENTATION_DIGEST = "11" * 32
POLICY_ID = "22" * 32
PLAN_ID = "33" * 32
QUOTE_OBSERVATION_DIGEST = "44" * 32
CALLDATA_SHA256 = "55" * 32
RAW_SIGNED_SHA256 = "66" * 32
RAW_EVIDENCE_SHA256 = "77" * 32

TAKER = "0x00000000000000000000000000000000000000aa"
SELL_TOKEN = "0x00000000000000000000000000000000000000bb"
BUY_TOKEN = "0x00000000000000000000000000000000000000cc"
ALLOWANCE_TARGET = "0x00000000000000000000000000000000000000dd"

SELL_INSTRUMENT = f"evm:{CHAIN_ID}:{SELL_TOKEN}"
BUY_INSTRUMENT = f"evm:{CHAIN_ID}:{BUY_TOKEN}"

TX_HASH = "0x" + "ab" * 32
BLOCK_HASH = "0x" + "cd" * 32
PARENT_HASH = "0x" + "ce" * 32
HEAD_HASH = "0x" + "ef" * 32

MAX_INPUT = 1_000_000
MIN_OUTPUT = 500_000


def authority(**overrides: Any) -> AuthorityPolicyRefV0:
    values: dict[str, Any] = {
        "authority_root_id": "qnty-authority-root-v0",
        "granted_level": AuthorityLevel.SHADOW,
        "permitted_repository_commit": COMMIT,
        "permitted_implementation_digest": IMPLEMENTATION_DIGEST,
        "permitted_network_id": NETWORK_ID,
        "permitted_taker_address": TAKER,
        "permitted_venue_id": "zero-x-allowance-holder",
        "max_reservation_atomic": MAX_INPUT,
        "max_cumulative_atomic": MAX_INPUT * 4,
        "not_before_epoch_s": NOW - 3_600,
        "not_after_epoch_s": NOW + 3_600,
    }
    values.update(overrides)
    return AuthorityPolicyRefV0(**values)


def session(grant: AuthorityPolicyRefV0 | None = None, **overrides: Any) -> ExecutionSessionV0:
    grant = grant or authority()
    values: dict[str, Any] = {
        "repository_commit": COMMIT,
        "implementation_digest": IMPLEMENTATION_DIGEST,
        "runtime_identity": "cpython-3.14",
        "db_schema_version": 1,
        "policy_id": POLICY_ID,
        "authority_policy_digest": grant.authority_policy_digest,
        "taker_address": TAKER,
        "network_id": NETWORK_ID,
        "venue_id": "zero-x-allowance-holder",
        "venue_adapter_version": "v0",
        "started_at_epoch_s": NOW - 60,
        "session_ordinal": 0,
    }
    values.update(overrides)
    return ExecutionSessionV0(**values)


def economic_action() -> EconomicActionIDV0:
    return EconomicActionIDV0(digest_object({"v": "test.economic_action", "level": "E1"}))


def bounds(**overrides: Any) -> EconomicBounds:
    values: dict[str, Any] = {
        "side": Side.BUY,
        "input_instrument_id": SELL_INSTRUMENT,
        "output_instrument_id": BUY_INSTRUMENT,
        "max_input_atomic": MAX_INPUT,
        "min_output_atomic": MIN_OUTPUT,
        "limit_price": Fraction(2, 1),
        "max_price_impact_bps": 100,
        "max_slippage_bps": 50,
        "deadline_epoch_s": NOW + 600,
    }
    values.update(overrides)
    return EconomicBounds(**values)


def envelope(
    active_session: ExecutionSessionV0 | None = None,
    grant: AuthorityPolicyRefV0 | None = None,
    **overrides: Any,
) -> ExecutionEnvelopeV0:
    grant = grant or authority()
    active_session = active_session or session(grant)
    values: dict[str, Any] = {
        "session_id": active_session.session_id,
        "session_identity_digest": active_session.identity_digest,
        "economic_action_id": economic_action(),
        "chain_id": CHAIN_ID,
        "taker_address": TAKER,
        "input_instrument_id": SELL_INSTRUMENT,
        "output_instrument_id": BUY_INSTRUMENT,
        "max_input_atomic": MAX_INPUT,
        "min_output_atomic": MIN_OUTPUT,
        "transaction_to": ALLOWANCE_TARGET,
        "transaction_value_atomic": 0,
        "calldata_sha256": CALLDATA_SHA256,
        "calldata_length": 324,
        "allowance_target": ALLOWANCE_TARGET,
        "account_nonce": 7,
        "gas_limit_ceiling": 400_000,
        "max_fee_per_gas_ceiling_atomic": 2_000_000_000,
        "max_priority_fee_per_gas_ceiling_atomic": 1_000_000,
        "deadline_epoch_s": NOW + 600,
        "authority_policy_digest": grant.authority_policy_digest,
        "plan_id": PLAN_ID,
        "quote_id": "quote-0001",
        "quote_observation_digest": QUOTE_OBSERVATION_DIGEST,
        "venue_block_number": 1_000_000,
        "constructed_at_epoch_s": NOW - 5,
    }
    values.update(overrides)
    return ExecutionEnvelopeV0(**values)


def expectation(**overrides: Any) -> ZeroXExecutionExpectationV0:
    values: dict[str, Any] = {
        "chain_id": CHAIN_ID,
        "taker_address": TAKER,
        "sell_token": SELL_TOKEN,
        "buy_token": BUY_TOKEN,
        "sell_amount_atomic": MAX_INPUT,
        "min_output_atomic": MIN_OUTPUT,
        "max_quote_age_s": 30,
    }
    values.update(overrides)
    return ZeroXExecutionExpectationV0(**values)


def venue_response(**overrides: Any) -> VenueQuoteResponseV0:
    values: dict[str, Any] = {
        "chain_id": CHAIN_ID,
        "taker_address": TAKER,
        "sell_token": SELL_TOKEN,
        "buy_token": BUY_TOKEN,
        "sell_amount_atomic": MAX_INPUT,
        "buy_amount_atomic": MIN_OUTPUT + 10_000,
        "min_buy_amount_atomic": MIN_OUTPUT,
        "allowance_target": ALLOWANCE_TARGET,
        "transaction_to": ALLOWANCE_TARGET,
        "transaction_value_atomic": 0,
        "calldata_sha256": CALLDATA_SHA256,
        "calldata_length": 324,
        "block_number": 1_000_000,
        "quote_mode": "exact_in",
        "quoted_at_epoch_s": NOW - 5,
        "liquidity_available": True,
        "simulation_incomplete": False,
    }
    values.update(overrides)
    return VenueQuoteResponseV0(**values)


def approval(
    active_session: ExecutionSessionV0 | None = None,
    grant: AuthorityPolicyRefV0 | None = None,
    **overrides: Any,
) -> ApprovalActionV0:
    grant = grant or authority()
    active_session = active_session or session(grant)
    values: dict[str, Any] = {
        "session_id": active_session.session_id,
        "session_identity_digest": active_session.identity_digest,
        "taker_address": TAKER,
        "token_address": SELL_TOKEN,
        "spender_address": ALLOWANCE_TARGET,
        "requested_allowance_atomic": MAX_INPUT,
        "observed_prior_allowance_atomic": 0,
        "authority_policy_digest": grant.authority_policy_digest,
        "deadline_epoch_s": NOW + 600,
        "economic_action_id": economic_action(),
    }
    values.update(overrides)
    return ApprovalActionV0(**values)


def signed_record(**overrides: Any) -> SignedTransactionRecordV0:
    values: dict[str, Any] = {
        "envelope_id": envelope().envelope_id,
        "raw_signed_sha256": RAW_SIGNED_SHA256,
        "raw_signed_length": 512,
        "transaction_hash": TX_HASH,
        "chain_id": CHAIN_ID,
        "account_nonce": 7,
        "taker_address": TAKER,
        "signer_identity": "external-human-controlled-account",
    }
    values.update(overrides)
    return SignedTransactionRecordV0(**values)


def included(
    provider: str,
    *,
    block_number: int = 1_000_000,
    head_block_number: int | None = 1_000_064,
    status: ReceiptStatus = ReceiptStatus.SUCCESS,
    block_hash: str = BLOCK_HASH,
    observed_at_epoch_s: int = NOW,
    effective_input: int | None = MAX_INPUT,
    effective_output: int | None = MIN_OUTPUT + 5_000,
) -> ChainObservationV0:
    settled = status is ReceiptStatus.SUCCESS
    return ChainObservationV0(
        provider_id=provider,
        transaction_hash=TX_HASH,
        observed_at_epoch_s=observed_at_epoch_s,
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=RAW_EVIDENCE_SHA256,
        block_number=block_number,
        block_hash=block_hash,
        block_parent_hash=PARENT_HASH,
        head_block_number=head_block_number,
        head_block_hash=None if head_block_number is None else HEAD_HASH,
        receipt_status=status,
        effective_input_atomic=effective_input if settled else None,
        effective_output_atomic=effective_output if settled else None,
    )


def absent(provider: str, *, observed_at_epoch_s: int = NOW) -> ChainObservationV0:
    return ChainObservationV0(
        provider_id=provider,
        transaction_hash=TX_HASH,
        observed_at_epoch_s=observed_at_epoch_s,
        presence=ChainPresence.ABSENT,
        raw_evidence_sha256=RAW_EVIDENCE_SHA256,
    )


def pending(provider: str, *, observed_at_epoch_s: int = NOW) -> ChainObservationV0:
    return ChainObservationV0(
        provider_id=provider,
        transaction_hash=TX_HASH,
        observed_at_epoch_s=observed_at_epoch_s,
        presence=ChainPresence.PENDING,
        raw_evidence_sha256=RAW_EVIDENCE_SHA256,
    )
