"""Ink V0F human-controlled signing, approval settlement, and pre-sign checks.

This module adds no execution authority.  It prepares the deterministic Level-3
mechanics while the binding source ceiling remains RECONCILE_ONLY:

* exact EIP-1559 approval and revoke-to-zero signing requests;
* byte-exact validation of externally signed approval/revoke transactions;
* two-provider approval transaction observations that do not pretend an ERC-20
  approval has swap input/output amounts;
* deterministic approval/revoke chain-truth evaluation;
* exact post-settlement allowance checks;
* same-amount swap revalidation against fresh pool/router/allowance/nonce/base-fee
  state without regenerating or resizing the preauthorized swap.

No signing key material is accepted or produced here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from .canon import canonical_json_bytes, digest_object, sha256_hex
from .domain import IntentV0, Side
from .errors import (
    AuthorityVerificationError,
    ChainTruthError,
    EnvelopeValidationError,
    RpcError,
    SafeHaltError,
)
from .exact_signed_bytes import (
    ExactSignedBytesScopeV0,
    ValidatedExactSignedBytesV0,
    validate_exact_signed_bytes,
)
from .execution_contract import (
    ApprovalActionV0,
    ChainPresence,
    ChainTruthVerdict,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    FinalityPolicyV0,
    ReceiptStatus,
)
from .ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    InkQuoteV0,
    InkShadowAdapter,
    JsonRpcClient,
)
from .ink_v0f_execution import (
    APPROVE_SELECTOR,
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    InkV0FRouterIdentityV0,
    amount_out_min_atomic,
    build_ink_v0f_human_signing_preview,
    encode_approve,
    encode_swap_exact_tokens_for_tokens,
)
from .ink_v0f_preauth import (
    InkV0FAllowanceObservationV0,
    InkV0FLiveVerifier,
)
from .ink_v0f_risk import InkV0FRiskPolicyV0
from .ledger.store import SpotLedger

APPROVAL_SIGNING_REQUEST_SCHEMA = "qntyspot.ink_v0f.approval_signing_request.v0"
APPROVAL_OBSERVATION_SCHEMA = "qntyspot.ink_v0f.approval_chain_observation.v0"
APPROVAL_TRUTH_SCHEMA = "qntyspot.ink_v0f.approval_chain_truth.v0"
APPROVAL_SETTLEMENT_SCHEMA = "qntyspot.ink_v0f.approval_settlement.v0"
SIGNER_STATE_SCHEMA = "qntyspot.ink_v0f.signer_state.v0"
SAME_AMOUNT_REVALIDATION_SCHEMA = "qntyspot.ink_v0f.same_amount_revalidation.v0"
SWAP_SIGNING_REQUEST_SCHEMA = "qntyspot.ink_v0f.swap_signing_request.v0"

_PROVIDER_IDS = ("ink-rpc-a", "ink-rpc-b")


def _uint(value: Any, *, field: str, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EnvelopeValidationError(f"{field} must be a non-negative integer")
    if positive and value == 0:
        raise EnvelopeValidationError(f"{field} must be positive")
    if value >= 2**256:
        raise EnvelopeValidationError(f"{field} exceeds uint256")
    return value


def _quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
        raise SafeHaltError(f"{field} is not a canonical RPC quantity")
    body = value[2:]
    if any(char not in "0123456789abcdef" for char in body):
        raise SafeHaltError(f"{field} is not lowercase hexadecimal")
    if len(body) > 1 and body[0] == "0":
        raise SafeHaltError(f"{field} has leading zeroes")
    return int(body, 16)


def _hash(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 66
        or not value.startswith("0x")
        or any(char not in "0123456789abcdef" for char in value[2:])
    ):
        raise SafeHaltError(f"{field} is not a canonical transaction/block hash")
    return value


def _digest(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise EnvelopeValidationError(f"{field} is not a canonical digest")
    return value


def _encode_revoke_to_zero(spender_address: str) -> bytes:
    if spender_address != INK_V0F_ROUTER_ADDRESS:
        raise EnvelopeValidationError("Ink V0F revoke must target the frozen router")
    return (
        APPROVE_SELECTOR
        + b"\x00" * 12
        + bytes.fromhex(spender_address[2:])
        + b"\x00" * 32
    )


class InkV0FApprovalKind(str, Enum):
    EXACT_APPROVAL = "EXACT_APPROVAL"
    REVOKE_TO_ZERO = "REVOKE_TO_ZERO"


@dataclass(frozen=True, slots=True)
class InkV0FApprovalSigningRequestV0:
    kind: InkV0FApprovalKind
    approval_action_id: str
    economic_action_id: str
    token_address: str
    spender_address: str
    allowance_atomic: int
    scope: ExactSignedBytesScopeV0
    constructed_at_epoch_s: int
    schema: str = APPROVAL_SIGNING_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != APPROVAL_SIGNING_REQUEST_SCHEMA:
            raise EnvelopeValidationError("unknown Ink V0F approval signing request schema")
        if not isinstance(self.kind, InkV0FApprovalKind):
            raise EnvelopeValidationError("Ink V0F approval signing request kind is invalid")
        _digest(self.approval_action_id, field="approval_action_id")
        _digest(self.economic_action_id, field="economic_action_id")
        if self.token_address not in {WETH9_ADDRESS, KRAKMASK_ADDRESS}:
            raise EnvelopeValidationError("Ink V0F approval token is outside the frozen pair")
        if self.spender_address != INK_V0F_ROUTER_ADDRESS:
            raise EnvelopeValidationError("Ink V0F approval spender is not the frozen router")
        _uint(self.allowance_atomic, field="allowance_atomic")
        _uint(self.constructed_at_epoch_s, field="constructed_at_epoch_s")
        if self.scope.chain_id != INK_CHAIN_ID:
            raise EnvelopeValidationError("Ink V0F approval scope is on the wrong chain")
        if self.scope.taker_address != INK_V0F_TAKER_ADDRESS:
            raise EnvelopeValidationError("Ink V0F approval scope has the wrong taker")
        if self.scope.target_address != self.token_address:
            raise EnvelopeValidationError("Ink V0F approval scope does not target the token")
        if self.scope.min_value_atomic != 0 or self.scope.max_value_atomic != 0:
            raise EnvelopeValidationError("Ink V0F approval must carry zero native value")
        expected_calldata = (
            encode_approve(self.spender_address, self.allowance_atomic)
            if self.kind is InkV0FApprovalKind.EXACT_APPROVAL
            else _encode_revoke_to_zero(self.spender_address)
        )
        if self.kind is InkV0FApprovalKind.EXACT_APPROVAL and self.allowance_atomic <= 0:
            raise EnvelopeValidationError("exact approval allowance must be positive")
        if self.kind is InkV0FApprovalKind.REVOKE_TO_ZERO and self.allowance_atomic != 0:
            raise EnvelopeValidationError("revoke allowance must be exactly zero")
        if (
            self.scope.calldata_sha256 != sha256_hex(expected_calldata)
            or self.scope.calldata_length != len(expected_calldata)
        ):
            raise EnvelopeValidationError(
                "Ink V0F approval scope calldata differs from the request"
            )

    @property
    def request_id(self) -> str:
        return digest_object(
            {
                "allowance_atomic": str(self.allowance_atomic),
                "approval_action_id": self.approval_action_id,
                "economic_action_id": self.economic_action_id,
                "kind": self.kind.value,
                "schema": self.schema,
                "scope_digest": self.scope.scope_digest,
                "spender_address": self.spender_address,
                "token_address": self.token_address,
            }
        )

    def eip1559_signing_fields(self) -> dict[str, Any]:
        calldata = (
            encode_approve(self.spender_address, self.allowance_atomic)
            if self.kind is InkV0FApprovalKind.EXACT_APPROVAL
            else _encode_revoke_to_zero(self.spender_address)
        )
        if sha256_hex(calldata) != self.scope.calldata_sha256:
            raise EnvelopeValidationError("approval signing request calldata digest drifted")
        return {
            "accessList": [],
            "chainId": self.scope.chain_id,
            "data": "0x" + calldata.hex(),
            "gas": self.scope.gas_limit_ceiling,
            "maxFeePerGas": self.scope.max_fee_per_gas_ceiling,
            "maxPriorityFeePerGas": self.scope.max_priority_fee_per_gas_ceiling,
            "nonce": self.scope.account_nonce,
            "to": self.token_address,
            "type": 2,
            "value": 0,
        }


@dataclass(frozen=True, slots=True)
class InkV0FSignedApprovalV0:
    request: InkV0FApprovalSigningRequestV0
    validated: ValidatedExactSignedBytesV0

    def __post_init__(self) -> None:
        if type(self.request) is not InkV0FApprovalSigningRequestV0:
            raise EnvelopeValidationError("signed approval request type is invalid")
        if type(self.validated) is not ValidatedExactSignedBytesV0:
            raise EnvelopeValidationError("signed approval validation type is invalid")
        if self.validated.scope != self.request.scope:
            raise EnvelopeValidationError("signed approval scope differs from its request")
        if self.validated.parsed.transaction_type != "eip-1559":
            raise EnvelopeValidationError("Ink V0F human signing accepts EIP-1559 only")
        parsed = self.validated.parsed
        scope = self.request.scope
        if parsed.chain_id != INK_CHAIN_ID:
            raise EnvelopeValidationError("signed approval is on the wrong chain")
        if parsed.sender_address != scope.taker_address:
            raise EnvelopeValidationError("signed approval sender differs from the request")
        if parsed.target_address != self.request.token_address:
            raise EnvelopeValidationError("signed approval target differs from the request")
        if parsed.value_atomic != 0:
            raise EnvelopeValidationError("signed approval carries unexpected native value")
        if len(parsed.calldata) != scope.calldata_length or sha256_hex(parsed.calldata) != scope.calldata_sha256:
            raise EnvelopeValidationError("signed approval calldata differs from the request")
        if scope.account_nonce is not None and parsed.account_nonce != scope.account_nonce:
            raise EnvelopeValidationError("signed approval nonce differs from the request")
        if scope.gas_limit_ceiling is not None and parsed.gas_limit > scope.gas_limit_ceiling:
            raise EnvelopeValidationError("signed approval gas exceeds the request ceiling")
        if scope.max_fee_per_gas_ceiling is not None and parsed.max_fee_per_gas > scope.max_fee_per_gas_ceiling:
            raise EnvelopeValidationError("signed approval fee exceeds the request ceiling")
        if (
            scope.max_priority_fee_per_gas_ceiling is not None
            and parsed.max_priority_fee_per_gas > scope.max_priority_fee_per_gas_ceiling
        ):
            raise EnvelopeValidationError("signed approval priority fee exceeds the request ceiling")

    @property
    def transaction_hash(self) -> str:
        return self.validated.parsed.transaction_hash

    @property
    def signed_bytes_sha256(self) -> str:
        return self.validated.signed_bytes_sha256

    @property
    def signed_bytes_length(self) -> int:
        return self.validated.signed_bytes_length

    @property
    def signed_transaction_id(self) -> str:
        return digest_object(
            {
                "request_id": self.request.request_id,
                "schema": "qntyspot.ink_v0f.signed_approval.v0",
                "signed_bytes_sha256": self.signed_bytes_sha256,
            }
        )


def _approval_scope(
    *,
    session: ExecutionSessionV0,
    action_id: str,
    token_address: str,
    calldata: bytes,
    account_nonce: int,
    gas_limit_ceiling: int,
    max_fee_per_gas_ceiling: int,
    max_priority_fee_per_gas_ceiling: int,
) -> ExactSignedBytesScopeV0:
    if type(session) is not ExecutionSessionV0:
        raise AuthorityVerificationError("Ink V0F signing request requires an execution session")
    if session.chain_id != INK_CHAIN_ID or session.taker_address != INK_V0F_TAKER_ADDRESS:
        raise AuthorityVerificationError("Ink V0F signing request session is outside frozen scope")
    return ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=INK_CHAIN_ID,
        taker_address=session.taker_address,
        target_address=token_address,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        account_nonce=_uint(account_nonce, field="account_nonce"),
        gas_limit_ceiling=_uint(gas_limit_ceiling, field="gas_limit_ceiling", positive=True),
        max_fee_per_gas_ceiling=_uint(
            max_fee_per_gas_ceiling, field="max_fee_per_gas_ceiling", positive=True
        ),
        max_priority_fee_per_gas_ceiling=_uint(
            max_priority_fee_per_gas_ceiling,
            field="max_priority_fee_per_gas_ceiling",
        ),
    )


def build_ink_v0f_approval_signing_request(
    *,
    approval: ApprovalActionV0,
    envelope: ExecutionEnvelopeV0,
    session: ExecutionSessionV0,
    approval_nonce: int,
    gas_limit_ceiling: int,
    max_fee_per_gas_ceiling: int,
    max_priority_fee_per_gas_ceiling: int,
    constructed_at_epoch_s: int,
) -> InkV0FApprovalSigningRequestV0:
    if type(approval) is not ApprovalActionV0 or type(envelope) is not ExecutionEnvelopeV0:
        raise AuthorityVerificationError("Ink V0F approval signing requires canonical preauth records")
    if approval.economic_action_id is None:
        raise EnvelopeValidationError("Ink V0F approval must be bound to an economic action")
    if approval.economic_action_id != envelope.economic_action_id:
        raise EnvelopeValidationError("Ink V0F approval and swap name different economic actions")
    if approval.session_identity_digest != envelope.session_identity_digest:
        raise EnvelopeValidationError("Ink V0F approval and swap session identities differ")
    if approval.authority_policy_digest != envelope.authority_policy_digest:
        raise EnvelopeValidationError("Ink V0F approval and swap authority digests differ")
    if approval.requested_allowance_atomic != envelope.max_input_atomic:
        raise EnvelopeValidationError("Ink V0F approval amount must equal frozen swap input")
    if approval.observed_prior_allowance_atomic != 0:
        raise EnvelopeValidationError("first-live Ink V0F approval requires zero prior allowance")
    constructed = _uint(constructed_at_epoch_s, field="constructed_at_epoch_s")
    if constructed >= approval.deadline_epoch_s:
        raise EnvelopeValidationError("Ink V0F approval signing request is past its deadline")
    nonce = _uint(approval_nonce, field="approval_nonce")
    if envelope.account_nonce != nonce + 1:
        raise EnvelopeValidationError(
            "frozen swap nonce must be exactly one after the approval nonce"
        )
    calldata = encode_approve(approval.spender_address, approval.requested_allowance_atomic)
    scope = _approval_scope(
        session=session,
        action_id=approval.approval_action_id,
        token_address=approval.token_address,
        calldata=calldata,
        account_nonce=nonce,
        gas_limit_ceiling=gas_limit_ceiling,
        max_fee_per_gas_ceiling=max_fee_per_gas_ceiling,
        max_priority_fee_per_gas_ceiling=max_priority_fee_per_gas_ceiling,
    )
    return InkV0FApprovalSigningRequestV0(
        kind=InkV0FApprovalKind.EXACT_APPROVAL,
        approval_action_id=approval.approval_action_id,
        economic_action_id=approval.economic_action_id,
        token_address=approval.token_address,
        spender_address=approval.spender_address,
        allowance_atomic=approval.requested_allowance_atomic,
        scope=scope,
        constructed_at_epoch_s=constructed,
    )


def build_ink_v0f_revoke_signing_request(
    *,
    approval: ApprovalActionV0,
    session: ExecutionSessionV0,
    revoke_nonce: int,
    gas_limit_ceiling: int,
    max_fee_per_gas_ceiling: int,
    max_priority_fee_per_gas_ceiling: int,
    constructed_at_epoch_s: int,
) -> InkV0FApprovalSigningRequestV0:
    if type(approval) is not ApprovalActionV0 or approval.economic_action_id is None:
        raise AuthorityVerificationError("Ink V0F revoke requires a bound approval action")
    revoke_action_id = digest_object(
        {
            "approval_action_id": approval.approval_action_id,
            "schema": "qntyspot.ink_v0f.revoke_action.v0",
        }
    )
    calldata = _encode_revoke_to_zero(approval.spender_address)
    scope = _approval_scope(
        session=session,
        action_id=revoke_action_id,
        token_address=approval.token_address,
        calldata=calldata,
        account_nonce=revoke_nonce,
        gas_limit_ceiling=gas_limit_ceiling,
        max_fee_per_gas_ceiling=max_fee_per_gas_ceiling,
        max_priority_fee_per_gas_ceiling=max_priority_fee_per_gas_ceiling,
    )
    return InkV0FApprovalSigningRequestV0(
        kind=InkV0FApprovalKind.REVOKE_TO_ZERO,
        approval_action_id=approval.approval_action_id,
        economic_action_id=approval.economic_action_id,
        token_address=approval.token_address,
        spender_address=approval.spender_address,
        allowance_atomic=0,
        scope=scope,
        constructed_at_epoch_s=_uint(
            constructed_at_epoch_s, field="constructed_at_epoch_s"
        ),
    )


def validate_ink_v0f_signed_approval(
    request: InkV0FApprovalSigningRequestV0,
    signed_bytes: bytes,
) -> InkV0FSignedApprovalV0:
    if type(request) is not InkV0FApprovalSigningRequestV0:
        raise AuthorityVerificationError("signed approval validation requires a signing request")
    request.eip1559_signing_fields()
    validated = validate_exact_signed_bytes(signed_bytes, request.scope)
    if validated.parsed.transaction_type != "eip-1559":
        raise EnvelopeValidationError("Ink V0F human signing accepts EIP-1559 transactions only")
    return InkV0FSignedApprovalV0(request=request, validated=validated)


@dataclass(frozen=True, slots=True)
class InkV0FApprovalChainObservationV0:
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
    schema: str = APPROVAL_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != APPROVAL_OBSERVATION_SCHEMA:
            raise ChainTruthError("unknown Ink V0F approval observation schema")
        if self.provider_id not in _PROVIDER_IDS:
            raise ChainTruthError("Ink V0F approval observation provider is not canonical")
        _hash(self.transaction_hash, field="transaction_hash")
        _digest(self.raw_evidence_sha256, field="raw_evidence_sha256")
        _uint(self.observed_at_epoch_s, field="observed_at_epoch_s")
        if not isinstance(self.presence, ChainPresence):
            raise ChainTruthError("Ink V0F approval observation presence is invalid")
        included = self.presence is ChainPresence.INCLUDED
        if included:
            if (
                self.block_number is None
                or self.block_hash is None
                or self.block_parent_hash is None
                or self.receipt_status is None
            ):
                raise ChainTruthError("included approval observation is incomplete")
            _uint(self.block_number, field="block_number")
            _hash(self.block_hash, field="block_hash")
            _hash(self.block_parent_hash, field="block_parent_hash")
            if not isinstance(self.receipt_status, ReceiptStatus):
                raise ChainTruthError("included approval receipt status is invalid")
        elif any(
            value is not None
            for value in (
                self.block_number,
                self.block_hash,
                self.block_parent_hash,
                self.receipt_status,
            )
        ):
            raise ChainTruthError("non-included approval observation carries block facts")
        if (self.head_block_number is None) != (self.head_block_hash is None):
            raise ChainTruthError("approval observation head identity is incomplete")
        if self.head_block_number is not None:
            _uint(self.head_block_number, field="head_block_number")
            _hash(self.head_block_hash, field="head_block_hash")
            if included and self.head_block_number < self.block_number:
                raise ChainTruthError("approval observation head precedes inclusion")

    @property
    def observation_id(self) -> str:
        return digest_object(self.canonical_object())

    @property
    def settlement_facts(self) -> tuple[Any, ...]:
        return (
            self.block_number,
            self.block_hash,
            self.block_parent_hash,
            None if self.receipt_status is None else self.receipt_status.value,
        )

    def canonical_object(self) -> dict[str, Any]:
        return {
            "block_hash": self.block_hash,
            "block_number": self.block_number,
            "block_parent_hash": self.block_parent_hash,
            "head_block_hash": self.head_block_hash,
            "head_block_number": self.head_block_number,
            "observed_at_epoch_s": self.observed_at_epoch_s,
            "presence": self.presence.value,
            "provider_id": self.provider_id,
            "raw_evidence_sha256": self.raw_evidence_sha256,
            "receipt_status": None
            if self.receipt_status is None
            else self.receipt_status.value,
            "schema": self.schema,
            "transaction_hash": self.transaction_hash,
        }


def _rpc_block(provider: JsonRpcClient, block_tag: str) -> Mapping[str, Any]:
    raw = provider.request("eth_getBlockByNumber", [block_tag, False])
    if not isinstance(raw, dict):
        raise SafeHaltError("Ink RPC block response is not an object")
    number = _quantity(raw.get("number"), field="block.number")
    if hex(number) != block_tag and block_tag != "latest":
        raise SafeHaltError("Ink RPC block number disagrees with requested block")
    _hash(raw.get("hash"), field="block.hash")
    _hash(raw.get("parentHash"), field="block.parentHash")
    return raw


def observe_ink_v0f_approval_transaction(
    providers: tuple[JsonRpcClient, JsonRpcClient],
    transaction_hash: str,
    *,
    observed_at_epoch_s: int,
) -> tuple[InkV0FApprovalChainObservationV0, InkV0FApprovalChainObservationV0]:
    if len(providers) != 2 or tuple(p.endpoint for p in providers) != INK_RPC_ENDPOINTS:
        raise SafeHaltError("Ink V0F approval observation requires canonical two-provider RPCs")
    _hash(transaction_hash, field="transaction_hash")
    observations: list[InkV0FApprovalChainObservationV0] = []
    for provider_id, provider in zip(_PROVIDER_IDS, providers):
        try:
            if provider.chain_id() != INK_CHAIN_ID:
                raise SafeHaltError("Ink V0F approval provider is on the wrong chain")
            head_number = provider.block_number()
            head = _rpc_block(provider, hex(head_number))
            receipt = provider.request("eth_getTransactionReceipt", [transaction_hash])
            transaction = provider.request("eth_getTransactionByHash", [transaction_hash])
        except RpcError as exc:
            raise SafeHaltError(f"Ink V0F approval RPC observation failed: {exc}") from exc
        evidence = {
            "head": dict(head),
            "receipt": receipt,
            "transaction": transaction,
        }
        evidence_digest = sha256_hex(canonical_json_bytes(evidence))
        if receipt is None:
            presence = ChainPresence.ABSENT if transaction is None else ChainPresence.PENDING
            observations.append(
                InkV0FApprovalChainObservationV0(
                    provider_id=provider_id,
                    transaction_hash=transaction_hash,
                    observed_at_epoch_s=observed_at_epoch_s,
                    presence=presence,
                    raw_evidence_sha256=evidence_digest,
                    head_block_number=head_number,
                    head_block_hash=_hash(head["hash"], field="head.hash"),
                )
            )
            continue
        if not isinstance(receipt, dict):
            raise SafeHaltError("Ink V0F approval receipt is not an object")
        if _hash(receipt.get("transactionHash"), field="receipt.transactionHash") != transaction_hash:
            raise SafeHaltError("Ink V0F approval receipt names another transaction")
        block_number = _quantity(receipt.get("blockNumber"), field="receipt.blockNumber")
        block = _rpc_block(provider, hex(block_number))
        block_hash = _hash(receipt.get("blockHash"), field="receipt.blockHash")
        if block_hash != _hash(block.get("hash"), field="block.hash"):
            raise SafeHaltError("Ink V0F approval receipt/block hash disagreement")
        status = _quantity(receipt.get("status"), field="receipt.status")
        if status not in (0, 1):
            raise SafeHaltError("Ink V0F approval receipt status is not 0 or 1")
        observations.append(
            InkV0FApprovalChainObservationV0(
                provider_id=provider_id,
                transaction_hash=transaction_hash,
                observed_at_epoch_s=observed_at_epoch_s,
                presence=ChainPresence.INCLUDED,
                raw_evidence_sha256=evidence_digest,
                block_number=block_number,
                block_hash=block_hash,
                block_parent_hash=_hash(block.get("parentHash"), field="block.parentHash"),
                head_block_number=head_number,
                head_block_hash=_hash(head.get("hash"), field="head.hash"),
                receipt_status=ReceiptStatus.SUCCESS if status == 1 else ReceiptStatus.REVERTED,
            )
        )
    return observations[0], observations[1]


@dataclass(frozen=True, slots=True)
class InkV0FApprovalTruthV0:
    external_action_id: str
    transaction_hash: str
    verdict: ChainTruthVerdict
    agreeing_provider_count: int
    confirmation_depth: int
    block_number: int | None
    block_hash: str | None
    receipt_status: ReceiptStatus | None
    evidence_digest: str
    schema: str = APPROVAL_TRUTH_SCHEMA


def evaluate_ink_v0f_approval_truth(
    signed: InkV0FSignedApprovalV0,
    observations: Sequence[InkV0FApprovalChainObservationV0],
    finality: FinalityPolicyV0,
    *,
    submission_acknowledged: bool,
) -> InkV0FApprovalTruthV0:
    if type(signed) is not InkV0FSignedApprovalV0:
        raise ChainTruthError("Ink V0F approval truth requires validated signed bytes")
    if type(finality) is not FinalityPolicyV0:
        raise ChainTruthError("Ink V0F approval truth requires a finality policy")
    if type(submission_acknowledged) is not bool:
        raise ChainTruthError("submission_acknowledged must be boolean")
    records = tuple(observations)
    for observation in records:
        if type(observation) is not InkV0FApprovalChainObservationV0:
            raise ChainTruthError("Ink V0F approval observations have the wrong type")
        if observation.transaction_hash != signed.transaction_hash:
            raise ChainTruthError("approval observation names another transaction")

    evidence_digest = digest_object(
        {
            "finality": finality.canonical_object(),
            "observations": sorted(
                (item.canonical_object() for item in records),
                key=digest_object,
            ),
            "request_id": signed.request.request_id,
            "schema": APPROVAL_TRUTH_SCHEMA + ".evidence",
            "signed_transaction_id": signed.signed_transaction_id,
            "submission_acknowledged": submission_acknowledged,
        }
    )

    def result(
        verdict: ChainTruthVerdict,
        *,
        agreeing: int = 0,
        depth: int = 0,
        included: InkV0FApprovalChainObservationV0 | None = None,
    ) -> InkV0FApprovalTruthV0:
        return InkV0FApprovalTruthV0(
            external_action_id=(
                signed.request.approval_action_id
                if signed.request.kind is InkV0FApprovalKind.EXACT_APPROVAL
                else signed.request.scope.economic_action_id
            ),
            transaction_hash=signed.transaction_hash,
            verdict=verdict,
            agreeing_provider_count=agreeing,
            confirmation_depth=depth,
            block_number=None if included is None else included.block_number,
            block_hash=None if included is None else included.block_hash,
            receipt_status=None if included is None else included.receipt_status,
            evidence_digest=evidence_digest,
        )

    latest: dict[str, InkV0FApprovalChainObservationV0] = {}
    for observation in sorted(
        records, key=lambda item: (item.observed_at_epoch_s, item.observation_id)
    ):
        latest[observation.provider_id] = observation
    latest_records = tuple(latest.values())
    included_records = [
        item for item in latest_records if item.presence is ChainPresence.INCLUDED
    ]
    historical_included = [
        item for item in records if item.presence is ChainPresence.INCLUDED
    ]
    if len({item.settlement_facts for item in historical_included}) > 1:
        return result(ChainTruthVerdict.AMBIGUOUS)
    for provider_id, observation in latest.items():
        if observation.presence is not ChainPresence.INCLUDED and any(
            prior.provider_id == provider_id
            and prior.presence is ChainPresence.INCLUDED
            for prior in records
        ):
            return result(ChainTruthVerdict.AMBIGUOUS)
    if included_records and any(
        item.presence is not ChainPresence.INCLUDED for item in latest_records
    ):
        return result(ChainTruthVerdict.AMBIGUOUS)
    if not included_records:
        if any(item.presence is ChainPresence.PENDING for item in records):
            return result(ChainTruthVerdict.VISIBLE)
        if submission_acknowledged:
            return result(ChainTruthVerdict.AMBIGUOUS)
        return result(ChainTruthVerdict.NO_EVIDENCE)

    exemplar = included_records[0]
    agreeing_providers = sorted({item.provider_id for item in included_records})
    agreeing = len(agreeing_providers)
    if agreeing < finality.min_agreeing_providers:
        return result(ChainTruthVerdict.VISIBLE, agreeing=agreeing, included=exemplar)
    depths = []
    for provider_id in agreeing_providers:
        head = latest[provider_id].head_block_number
        depths.append(
            0 if head is None else max(head - int(exemplar.block_number), 0)
        )
    depth = min(depths)
    if depth < finality.min_confirmation_depth:
        return result(
            ChainTruthVerdict.INCLUDED,
            agreeing=agreeing,
            depth=depth,
            included=exemplar,
        )
    return result(
        ChainTruthVerdict.CONFIRMED
        if exemplar.receipt_status is ReceiptStatus.SUCCESS
        else ChainTruthVerdict.REVERTED,
        agreeing=agreeing,
        depth=depth,
        included=exemplar,
    )


class InkV0FApprovalSettlementState(str, Enum):
    PENDING = "PENDING"
    SETTLED = "SETTLED"
    REVOKED = "REVOKED"
    SAFE_HALT = "SAFE_HALT"


@dataclass(frozen=True, slots=True)
class InkV0FApprovalSettlementV0:
    state: InkV0FApprovalSettlementState
    request_id: str
    approval_action_id: str
    economic_action_id: str
    transaction_hash: str
    expected_allowance_atomic: int
    observed_allowance_atomic: int
    allowance_observation_digest: str
    chain_truth_evidence_digest: str
    requires_revoke: bool
    schema: str = APPROVAL_SETTLEMENT_SCHEMA


def reconcile_ink_v0f_approval(
    request: InkV0FApprovalSigningRequestV0,
    signed: InkV0FSignedApprovalV0,
    truth: InkV0FApprovalTruthV0,
    allowance: InkV0FAllowanceObservationV0,
) -> InkV0FApprovalSettlementV0:
    if signed.request.request_id != request.request_id:
        raise ChainTruthError("signed approval does not belong to the signing request")
    if truth.transaction_hash != signed.transaction_hash:
        raise ChainTruthError("approval truth belongs to another signed transaction")
    expected_external_action_id = (
        request.approval_action_id
        if request.kind is InkV0FApprovalKind.EXACT_APPROVAL
        else request.scope.economic_action_id
    )
    if truth.external_action_id != expected_external_action_id:
        raise ChainTruthError("approval truth belongs to another external action")
    if (
        allowance.token_address != request.token_address
        or allowance.owner_address != INK_V0F_TAKER_ADDRESS
        or allowance.spender_address != INK_V0F_ROUTER_ADDRESS
    ):
        raise ChainTruthError("allowance observation is outside the signing request scope")
    expected = request.allowance_atomic
    observed = allowance.allowance_atomic
    if truth.block_number is not None and allowance.common_block < truth.block_number:
        raise SafeHaltError("allowance observation predates the approval inclusion block")

    state = InkV0FApprovalSettlementState.PENDING
    requires_revoke = False
    if truth.verdict is ChainTruthVerdict.CONFIRMED:
        if observed == expected:
            state = (
                InkV0FApprovalSettlementState.REVOKED
                if request.kind is InkV0FApprovalKind.REVOKE_TO_ZERO
                else InkV0FApprovalSettlementState.SETTLED
            )
        else:
            state = InkV0FApprovalSettlementState.SAFE_HALT
            requires_revoke = observed != 0
    elif truth.verdict in {
        ChainTruthVerdict.REVERTED,
        ChainTruthVerdict.AMBIGUOUS,
    }:
        state = InkV0FApprovalSettlementState.SAFE_HALT
        requires_revoke = observed != 0

    return InkV0FApprovalSettlementV0(
        state=state,
        request_id=request.request_id,
        approval_action_id=request.approval_action_id,
        economic_action_id=request.economic_action_id,
        transaction_hash=signed.transaction_hash,
        expected_allowance_atomic=expected,
        observed_allowance_atomic=observed,
        allowance_observation_digest=allowance.digest,
        chain_truth_evidence_digest=truth.evidence_digest,
        requires_revoke=requires_revoke,
    )


@dataclass(frozen=True, slots=True)
class InkV0FSignerStateObservationV0:
    common_block: int
    account_nonce: int
    base_fee_per_gas: int
    block_hash: str
    provider_evidence: tuple[Mapping[str, Any], Mapping[str, Any]]
    schema: str = SIGNER_STATE_SCHEMA

    @property
    def digest(self) -> str:
        return digest_object(
            {
                "account_nonce": self.account_nonce,
                "base_fee_per_gas": str(self.base_fee_per_gas),
                "block_hash": self.block_hash,
                "common_block": self.common_block,
                "provider_evidence": [dict(item) for item in self.provider_evidence],
                "schema": self.schema,
            }
        )


def observe_ink_v0f_signer_state_for_market(
    live_verifier: InkV0FLiveVerifier,
    market: InkMarketObservationV0,
) -> InkV0FSignerStateObservationV0:
    if type(live_verifier) is not InkV0FLiveVerifier or type(market) is not InkMarketObservationV0:
        raise AuthorityVerificationError("signer-state observation requires canonical Ink live objects")
    block_tag = hex(market.common_block)
    rows = []
    for provider in live_verifier.providers:
        try:
            nonce = _quantity(
                provider.request(
                    "eth_getTransactionCount",
                    [INK_V0F_TAKER_ADDRESS, block_tag],
                ),
                field="eth_getTransactionCount",
            )
            block = _rpc_block(provider, block_tag)
            base_fee = _quantity(block.get("baseFeePerGas"), field="block.baseFeePerGas")
        except RpcError as exc:
            raise SafeHaltError(f"Ink V0F signer-state RPC read failed: {exc}") from exc
        rows.append(
            {
                "account_nonce": nonce,
                "base_fee_per_gas": base_fee,
                "block_hash": _hash(block.get("hash"), field="block.hash"),
                "endpoint": provider.endpoint,
            }
        )
    if rows[0]["account_nonce"] != rows[1]["account_nonce"]:
        raise SafeHaltError("Ink V0F providers disagree on taker nonce")
    if rows[0]["base_fee_per_gas"] != rows[1]["base_fee_per_gas"]:
        raise SafeHaltError("Ink V0F providers disagree on base fee")
    if rows[0]["block_hash"] != rows[1]["block_hash"]:
        raise SafeHaltError("Ink V0F providers disagree on common-block hash")
    return InkV0FSignerStateObservationV0(
        common_block=market.common_block,
        account_nonce=rows[0]["account_nonce"],
        base_fee_per_gas=rows[0]["base_fee_per_gas"],
        block_hash=rows[0]["block_hash"],
        provider_evidence=(rows[0], rows[1]),
    )


@dataclass(frozen=True, slots=True)
class InkV0FSwapSigningRequestV0:
    scope: ExactSignedBytesScopeV0
    calldata: bytes
    schema: str = SWAP_SIGNING_REQUEST_SCHEMA

    def eip1559_signing_fields(self) -> dict[str, Any]:
        return {
            "accessList": [],
            "chainId": self.scope.chain_id,
            "data": "0x" + self.calldata.hex(),
            "gas": self.scope.gas_limit_ceiling,
            "maxFeePerGas": self.scope.max_fee_per_gas_ceiling,
            "maxPriorityFeePerGas": self.scope.max_priority_fee_per_gas_ceiling,
            "nonce": self.scope.account_nonce,
            "to": self.scope.target_address,
            "type": 2,
            "value": 0,
        }


def _frozen_swap_request(
    envelope: ExecutionEnvelopeV0,
    intent: IntentV0,
    session: ExecutionSessionV0,
) -> InkV0FSwapSigningRequestV0:
    if intent.economic_action_id != envelope.economic_action_id:
        raise EnvelopeValidationError("frozen swap envelope belongs to another intent")
    path = (
        (WETH9_ADDRESS, KRAKMASK_ADDRESS)
        if intent.side is Side.BUY
        else (KRAKMASK_ADDRESS, WETH9_ADDRESS)
    )
    calldata = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=envelope.max_input_atomic,
        amount_out_min_atomic=envelope.min_output_atomic,
        path=path,
        recipient=session.taker_address,
        deadline_epoch_s=envelope.deadline_epoch_s,
    )
    if sha256_hex(calldata) != envelope.calldata_sha256 or len(calldata) != envelope.calldata_length:
        raise SafeHaltError("frozen Ink V0F envelope calldata cannot be reconstructed exactly")
    scope = ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=envelope.economic_action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=envelope.chain_id,
        taker_address=envelope.taker_address,
        target_address=envelope.transaction_to,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=envelope.calldata_sha256,
        calldata_length=envelope.calldata_length,
        account_nonce=envelope.account_nonce,
        gas_limit_ceiling=envelope.gas_limit_ceiling,
        max_fee_per_gas_ceiling=envelope.max_fee_per_gas_ceiling_atomic,
        max_priority_fee_per_gas_ceiling=envelope.max_priority_fee_per_gas_ceiling_atomic,
    )
    return InkV0FSwapSigningRequestV0(scope=scope, calldata=calldata)


@dataclass(frozen=True, slots=True)
class InkV0FSameAmountRevalidationV0:
    swap_request: InkV0FSwapSigningRequestV0
    market_observation_digest: str
    router_observation_digest: str
    allowance_observation_digest: str
    signer_state_digest: str
    fresh_quote_output_atomic: int
    fresh_required_min_output_atomic: int
    schema: str = SAME_AMOUNT_REVALIDATION_SCHEMA


def revalidate_ink_v0f_same_amount(
    *,
    live_verifier: InkV0FLiveVerifier,
    risk_policy: InkV0FRiskPolicyV0,
    router_identity: InkV0FRouterIdentityV0,
    ledger: SpotLedger,
    intent: IntentV0,
    session: ExecutionSessionV0,
    approval: ApprovalActionV0,
    envelope: ExecutionEnvelopeV0,
    approval_settlement: InkV0FApprovalSettlementV0,
    now_epoch_s: int,
) -> InkV0FSameAmountRevalidationV0:
    if approval_settlement.state is not InkV0FApprovalSettlementState.SETTLED:
        raise SafeHaltError("swap signing requires a settled exact approval")
    if type(router_identity) is not InkV0FRouterIdentityV0:
        raise AuthorityVerificationError("same-amount revalidation requires verified router identity")
    if approval.economic_action_id is None:
        raise SafeHaltError("approval is not bound to an economic action")
    if (
        approval.economic_action_id != envelope.economic_action_id
        or intent.economic_action_id != envelope.economic_action_id
        or approval_settlement.economic_action_id != envelope.economic_action_id
        or approval_settlement.approval_action_id != approval.approval_action_id
    ):
        raise SafeHaltError("approval settlement, intent, and swap are not the same action")
    if (
        approval.session_identity_digest != session.identity_digest
        or envelope.session_identity_digest != session.identity_digest
        or approval.authority_policy_digest != session.authority_policy_digest
        or envelope.authority_policy_digest != session.authority_policy_digest
        or envelope.taker_address != session.taker_address
    ):
        raise SafeHaltError("approval or swap scope differs from the execution session")
    expected_token = WETH9_ADDRESS if intent.side is Side.BUY else KRAKMASK_ADDRESS
    if approval.token_address != expected_token or approval.spender_address != INK_V0F_ROUTER_ADDRESS:
        raise SafeHaltError("approval token/spender differs from the frozen swap direction")
    if approval.requested_allowance_atomic != envelope.max_input_atomic:
        raise SafeHaltError("approval amount and frozen swap input differ")
    if approval_settlement.observed_allowance_atomic != envelope.max_input_atomic:
        raise SafeHaltError("settled allowance is not exactly the frozen swap input")
    if now_epoch_s >= envelope.deadline_epoch_s:
        raise SafeHaltError("frozen Ink V0F swap deadline has expired")

    market = live_verifier.observe_market()
    router = live_verifier.observe_router_for_market(market)
    allowance = live_verifier.observe_allowance_for_market(
        market, token_address=approval.token_address
    )
    signer_state = observe_ink_v0f_signer_state_for_market(live_verifier, market)

    if router.router_address != router_identity.address:
        raise SafeHaltError("fresh router identity differs from frozen router")
    if allowance.allowance_atomic != envelope.max_input_atomic:
        raise SafeHaltError("fresh allowance differs from the frozen swap input")
    if signer_state.account_nonce != envelope.account_nonce:
        raise SafeHaltError("fresh taker nonce differs from the frozen swap nonce")
    if signer_state.base_fee_per_gas > envelope.max_fee_per_gas_ceiling_atomic:
        raise SafeHaltError("fresh base fee exceeds the frozen transaction fee ceiling")

    quote: InkQuoteV0 = InkShadowAdapter._quote(
        market, intent.side, envelope.max_input_atomic
    )
    fresh_preview = build_ink_v0f_human_signing_preview(
        policy=risk_policy,
        router=router_identity,
        observation=market,
        quote=quote,
        ledger=ledger,
        intent=intent,
        session=session,
        account_nonce=envelope.account_nonce,
        gas_limit_ceiling=envelope.gas_limit_ceiling,
        max_fee_per_gas_ceiling=envelope.max_fee_per_gas_ceiling_atomic,
        max_priority_fee_per_gas_ceiling=envelope.max_priority_fee_per_gas_ceiling_atomic,
        constructed_at_epoch_s=now_epoch_s,
    )
    if fresh_preview.swap.amount_in_atomic != envelope.max_input_atomic:
        raise SafeHaltError("fresh validation attempted to resize the frozen swap")
    required_min = amount_out_min_atomic(
        risk_policy, bounds=intent.bounds, quote=quote
    )
    if envelope.min_output_atomic < required_min:
        raise SafeHaltError(
            "frozen minimum output is now looser than the admissible fresh floor"
        )
    if envelope.min_output_atomic > quote.output_atomic:
        raise SafeHaltError(
            "fresh quote cannot satisfy the frozen minimum output; revoke instead of resizing"
        )

    swap_request = _frozen_swap_request(envelope, intent, session)
    return InkV0FSameAmountRevalidationV0(
        swap_request=swap_request,
        market_observation_digest=market.digest(),
        router_observation_digest=router.digest,
        allowance_observation_digest=allowance.digest,
        signer_state_digest=signer_state.digest,
        fresh_quote_output_atomic=quote.output_atomic,
        fresh_required_min_output_atomic=required_min,
    )
