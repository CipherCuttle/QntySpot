"""Native-ETH settlement wrapper for the Ink V0F SELL path.

Risk, inventory, approval, and same-amount revalidation reuse the canonical
KRAKMASK->WETH path. Only the final router call changes to
swapExactTokensForETH, causing the router to unwrap WETH and pay native ETH to
the frozen taker. No key material, signature production, or transport exists
here.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from .canon import digest_object, sha256_hex
from .domain import IntentV0, Side
from .errors import AuthorityVerificationError, EnvelopeValidationError, SafeHaltError
from .exact_signed_bytes import (
    ExactSignedBytesScopeV0,
    ValidatedExactSignedBytesV0,
    validate_exact_signed_bytes,
)
from .execution_contract import ApprovalActionV0, ExecutionEnvelopeV0, ExecutionSessionV0
from .ink import KRAKMASK_ADDRESS, WETH9_ADDRESS
from .ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    InkV0FHumanSigningPreviewV0,
    InkV0FRouterIdentityV0,
    build_ink_v0f_human_signing_preview,
)
from .ink_v0f_human_signing import (
    InkV0FApprovalSettlementV0,
    InkV0FApprovalSettlementState,
    InkV0FSameAmountRevalidationV0,
    revalidate_ink_v0f_same_amount,
)
from .ink_v0f_preauth import (
    InkV0FAllowanceObservationV0,
    InkV0FLiveVerifier,
    InkV0FRouterObservationV0,
    build_ink_v0f_approval_action,
    build_ink_v0f_execution_envelope,
)
from .ink_v0f_risk import InkV0FRiskPolicyV0
from .keccak import keccak256
from .ledger.store import SpotLedger

SWAP_EXACT_TOKENS_FOR_ETH_SELECTOR = keccak256(
    b"swapExactTokensForETH(uint256,uint256,address[],address,uint256)"
)[:4]
NATIVE_SELL_PREVIEW_SCHEMA = "qntyspot.ink_v0f.native_sell_preview.v0"
NATIVE_SELL_REVALIDATION_SCHEMA = "qntyspot.ink_v0f.native_sell_revalidation.v0"
MAX_REVALIDATION_TO_ADMISSION_S = 120
_NATIVE_SELL_PREVIEW_TOKEN = object()
_NATIVE_SELL_REVALIDATION_TOKEN = object()


def _uint(value: Any, *, field_name: str, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EnvelopeValidationError(f"{field_name} must be an integer")
    if value < 0 or (positive and value == 0) or value >= 2**256:
        relation = "> 0" if positive else ">= 0"
        raise EnvelopeValidationError(f"{field_name} must be {relation} and fit uint256")
    return value


def _address(value: Any, *, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 42
        or not value.startswith("0x")
        or value.lower() != value
    ):
        raise EnvelopeValidationError(f"{field_name} must be a lowercase 0x address")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise EnvelopeValidationError(f"{field_name} is not hexadecimal") from exc
    if len(raw) != 20 or int.from_bytes(raw, "big") == 0:
        raise EnvelopeValidationError(f"{field_name} is not a nonzero EVM address")
    return value


def _word(value: int) -> bytes:
    return _uint(value, field_name="ABI uint").to_bytes(32, "big")


def _address_word(value: str, *, field_name: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(_address(value, field_name=field_name)[2:])


def _decode_address_word(value: bytes, *, field_name: str) -> str:
    if len(value) != 32 or value[:12] != b"\x00" * 12:
        raise EnvelopeValidationError(f"{field_name} is not a canonical address word")
    return _address("0x" + value[12:].hex(), field_name=field_name)


def encode_swap_exact_tokens_for_eth(
    *,
    amount_in_atomic: int,
    amount_out_min_atomic: int,
    path: tuple[str, str],
    recipient: str,
    deadline_epoch_s: int,
) -> bytes:
    amount_in = _uint(amount_in_atomic, field_name="sell amount in", positive=True)
    amount_out_min = _uint(
        amount_out_min_atomic, field_name="sell amount out minimum", positive=True
    )
    if type(path) is not tuple or path != (KRAKMASK_ADDRESS, WETH9_ADDRESS):
        raise EnvelopeValidationError(
            "native Ink V0F SELL path must be pinned KRAKMASK -> WETH"
        )
    to = _address(recipient, field_name="sell recipient")
    deadline = _uint(deadline_epoch_s, field_name="sell deadline", positive=True)
    return b"".join(
        (
            SWAP_EXACT_TOKENS_FOR_ETH_SELECTOR,
            _word(amount_in),
            _word(amount_out_min),
            _word(32 * 5),
            _address_word(to, field_name="sell recipient"),
            _word(deadline),
            _word(2),
            _address_word(KRAKMASK_ADDRESS, field_name="sell input token"),
            _address_word(WETH9_ADDRESS, field_name="sell output token"),
        )
    )


def decode_swap_exact_tokens_for_eth(
    calldata: bytes,
) -> tuple[int, int, tuple[str, str], str, int]:
    if type(calldata) is not bytes or len(calldata) != 260:
        raise EnvelopeValidationError(
            "swapExactTokensForETH calldata must be exactly 260 bytes"
        )
    if calldata[:4] != SWAP_EXACT_TOKENS_FOR_ETH_SELECTOR:
        raise EnvelopeValidationError("native SELL calldata selector differs")
    args = calldata[4:]
    amount_in = int.from_bytes(args[0:32], "big")
    amount_out_min = int.from_bytes(args[32:64], "big")
    offset = int.from_bytes(args[64:96], "big")
    recipient = _decode_address_word(args[96:128], field_name="sell recipient")
    deadline = int.from_bytes(args[128:160], "big")
    if offset != 32 * 5:
        raise EnvelopeValidationError("native SELL path offset is not canonical")
    if int.from_bytes(args[160:192], "big") != 2:
        raise EnvelopeValidationError("native SELL path length is not exactly two")
    token_in = _decode_address_word(args[192:224], field_name="sell input token")
    token_out = _decode_address_word(args[224:256], field_name="sell output token")
    _uint(amount_in, field_name="sell amount in", positive=True)
    _uint(amount_out_min, field_name="sell amount out minimum", positive=True)
    _uint(deadline, field_name="sell deadline", positive=True)
    if (token_in, token_out) != (KRAKMASK_ADDRESS, WETH9_ADDRESS):
        raise EnvelopeValidationError("native SELL token path differs")
    return amount_in, amount_out_min, (token_in, token_out), recipient, deadline


@dataclass(frozen=True, slots=True)
class InkV0FNativeSellPreviewV0:
    token_preview: InkV0FHumanSigningPreviewV0
    token_envelope: ExecutionEnvelopeV0
    native_calldata: bytes
    native_scope: ExactSignedBytesScopeV0
    router_observation_digest: str
    schema: str = NATIVE_SELL_PREVIEW_SCHEMA
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _NATIVE_SELL_PREVIEW_TOKEN:
            raise SafeHaltError("native SELL preview must be produced by canonical builder")
        if self.schema != NATIVE_SELL_PREVIEW_SCHEMA:
            raise EnvelopeValidationError("unknown native SELL preview schema")
        if type(self.token_preview) is not InkV0FHumanSigningPreviewV0:
            raise EnvelopeValidationError("native SELL requires canonical token preview")
        if self.token_preview.side is not Side.SELL:
            raise EnvelopeValidationError("native SELL preview wraps a non-SELL preview")
        if type(self.token_envelope) is not ExecutionEnvelopeV0:
            raise EnvelopeValidationError("native SELL requires canonical token envelope")
        swap = self.token_preview.swap
        approval = self.token_preview.approval
        if swap.path != (KRAKMASK_ADDRESS, WETH9_ADDRESS):
            raise EnvelopeValidationError("native SELL token preview path differs")
        if approval.token_address != KRAKMASK_ADDRESS:
            raise EnvelopeValidationError("native SELL approval token differs")
        decoded = decode_swap_exact_tokens_for_eth(self.native_calldata)
        if decoded != (
            swap.amount_in_atomic,
            swap.amount_out_min_atomic,
            swap.path,
            swap.recipient,
            swap.deadline_epoch_s,
        ):
            raise EnvelopeValidationError("native SELL calldata differs from frozen token preview")
        if (
            self.native_scope.session_id != self.token_preview.signed_bytes_scope.session_id
            or self.native_scope.session_identity_digest
            != self.token_preview.signed_bytes_scope.session_identity_digest
            or self.native_scope.economic_action_id
            != self.token_preview.signed_bytes_scope.economic_action_id
            or self.native_scope.authority_policy_digest
            != self.token_preview.signed_bytes_scope.authority_policy_digest
            or self.native_scope.chain_id != self.token_preview.signed_bytes_scope.chain_id
            or self.native_scope.taker_address
            != self.token_preview.signed_bytes_scope.taker_address
            or self.native_scope.target_address != INK_V0F_ROUTER_ADDRESS
            or self.native_scope.min_value_atomic != 0
            or self.native_scope.max_value_atomic != 0
            or self.native_scope.account_nonce
            != self.token_preview.signed_bytes_scope.account_nonce
            or self.native_scope.gas_limit_ceiling
            != self.token_preview.signed_bytes_scope.gas_limit_ceiling
            or self.native_scope.max_fee_per_gas_ceiling
            != self.token_preview.signed_bytes_scope.max_fee_per_gas_ceiling
            or self.native_scope.max_priority_fee_per_gas_ceiling
            != self.token_preview.signed_bytes_scope.max_priority_fee_per_gas_ceiling
        ):
            raise EnvelopeValidationError("native SELL signed scope differs from token preview")
        if (
            self.native_scope.calldata_sha256 != sha256_hex(self.native_calldata)
            or self.native_scope.calldata_length != len(self.native_calldata)
        ):
            raise EnvelopeValidationError("native SELL scope calldata identity differs")
        if (
            type(self.router_observation_digest) is not str
            or len(self.router_observation_digest) != 64
        ):
            raise EnvelopeValidationError("native SELL router digest is not canonical")

    @property
    def preview_digest(self) -> str:
        return digest_object(
            {
                "native_calldata_sha256": sha256_hex(self.native_calldata),
                "native_scope_digest": self.native_scope.scope_digest,
                "router_observation_digest": self.router_observation_digest,
                "schema": self.schema,
                "token_envelope_id": self.token_envelope.envelope_id,
                "token_preview_digest": self.token_preview.preview_digest,
            }
        )

    def eip1559_signing_fields(self) -> dict[str, Any]:
        return {
            "accessList": [],
            "chainId": self.native_scope.chain_id,
            "data": "0x" + self.native_calldata.hex(),
            "gas": self.native_scope.gas_limit_ceiling,
            "maxFeePerGas": self.native_scope.max_fee_per_gas_ceiling,
            "maxPriorityFeePerGas": self.native_scope.max_priority_fee_per_gas_ceiling,
            "nonce": self.native_scope.account_nonce,
            "to": self.native_scope.target_address,
            "type": 2,
            "value": 0,
        }


def build_ink_v0f_native_sell_preview(
    token_preview: InkV0FHumanSigningPreviewV0,
    token_envelope: ExecutionEnvelopeV0,
    router_observation: InkV0FRouterObservationV0,
) -> InkV0FNativeSellPreviewV0:
    if type(token_preview) is not InkV0FHumanSigningPreviewV0:
        raise AuthorityVerificationError("native SELL requires canonical token preview")
    if token_preview.side is not Side.SELL:
        raise EnvelopeValidationError("native SELL requires SELL token preview")
    if type(token_envelope) is not ExecutionEnvelopeV0:
        raise AuthorityVerificationError("native SELL requires canonical token envelope")
    if type(router_observation) is not InkV0FRouterObservationV0:
        raise AuthorityVerificationError("native SELL requires live router observation")
    if router_observation.router_address != INK_V0F_ROUTER_ADDRESS:
        raise EnvelopeValidationError("native SELL router observation targets another router")
    if router_observation.common_block != token_preview.quote_common_block:
        raise EnvelopeValidationError("native SELL router observation differs from quote block")
    scope0 = token_preview.signed_bytes_scope
    if (
        token_envelope.economic_action_id != scope0.economic_action_id
        or token_envelope.session_identity_digest != scope0.session_identity_digest
        or token_envelope.authority_policy_digest != scope0.authority_policy_digest
        or token_envelope.max_input_atomic != token_preview.swap.amount_in_atomic
        or token_envelope.min_output_atomic != token_preview.swap.amount_out_min_atomic
        or token_envelope.transaction_to != INK_V0F_ROUTER_ADDRESS
        or token_envelope.transaction_value_atomic != 0
        or token_envelope.allowance_target != INK_V0F_ROUTER_ADDRESS
    ):
        raise EnvelopeValidationError("native SELL token envelope differs from token preview")

    calldata = encode_swap_exact_tokens_for_eth(
        amount_in_atomic=token_preview.swap.amount_in_atomic,
        amount_out_min_atomic=token_preview.swap.amount_out_min_atomic,
        path=token_preview.swap.path,
        recipient=token_preview.swap.recipient,
        deadline_epoch_s=token_preview.swap.deadline_epoch_s,
    )
    scope = ExactSignedBytesScopeV0(
        session_id=scope0.session_id,
        session_identity_digest=scope0.session_identity_digest,
        economic_action_id=scope0.economic_action_id,
        authority_policy_digest=scope0.authority_policy_digest,
        chain_id=scope0.chain_id,
        taker_address=scope0.taker_address,
        target_address=scope0.target_address,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        account_nonce=scope0.account_nonce,
        gas_limit_ceiling=scope0.gas_limit_ceiling,
        max_fee_per_gas_ceiling=scope0.max_fee_per_gas_ceiling,
        max_priority_fee_per_gas_ceiling=scope0.max_priority_fee_per_gas_ceiling,
    )
    return InkV0FNativeSellPreviewV0(
        token_preview=token_preview,
        token_envelope=token_envelope,
        native_calldata=calldata,
        native_scope=scope,
        router_observation_digest=router_observation.digest,
        _token=_NATIVE_SELL_PREVIEW_TOKEN,
    )


def build_ink_v0f_native_sell_envelope(
    preview: InkV0FNativeSellPreviewV0,
) -> ExecutionEnvelopeV0:
    if type(preview) is not InkV0FNativeSellPreviewV0 or preview._token is not _NATIVE_SELL_PREVIEW_TOKEN:
        raise AuthorityVerificationError("native SELL envelope requires canonical preview")
    plan_id = digest_object(
        {
            "native_sell_preview_digest": preview.preview_digest,
            "schema": "qntyspot.ink_v0f.native_sell_envelope_plan.v0",
        }
    )
    return replace(
        preview.token_envelope,
        plan_id=plan_id,
        calldata_sha256=sha256_hex(preview.native_calldata),
        calldata_length=len(preview.native_calldata),
    )


def assert_ink_v0f_native_sell_envelope_admissible(
    envelope: ExecutionEnvelopeV0,
    preview: InkV0FNativeSellPreviewV0,
    *,
    now_epoch_s: int,
) -> None:
    if envelope != build_ink_v0f_native_sell_envelope(preview):
        raise EnvelopeValidationError("native SELL envelope differs from canonical preview")
    now = _uint(now_epoch_s, field_name="now")
    if now >= envelope.deadline_epoch_s:
        raise EnvelopeValidationError("native SELL envelope deadline expired")
    if envelope.transaction_value_atomic != 0:
        raise EnvelopeValidationError("native SELL must carry zero native input value")
    if envelope.allowance_target != INK_V0F_ROUTER_ADDRESS:
        raise EnvelopeValidationError("native SELL requires exact router allowance")


@dataclass(frozen=True, slots=True)
class InkV0FNativeSellRevalidationV0:
    preview: InkV0FNativeSellPreviewV0
    token_revalidation: InkV0FSameAmountRevalidationV0
    native_scope: ExactSignedBytesScopeV0
    native_calldata: bytes
    schema: str = NATIVE_SELL_REVALIDATION_SCHEMA
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _NATIVE_SELL_REVALIDATION_TOKEN:
            raise SafeHaltError("native SELL revalidation must be produced by live revalidator")
        if type(self.preview) is not InkV0FNativeSellPreviewV0:
            raise EnvelopeValidationError("native SELL revalidation preview differs")
        if type(self.token_revalidation) is not InkV0FSameAmountRevalidationV0:
            raise EnvelopeValidationError("native SELL token revalidation differs")
        if self.native_scope != self.preview.native_scope:
            raise EnvelopeValidationError("native SELL revalidation scope drifted")
        if self.native_calldata != self.preview.native_calldata:
            raise EnvelopeValidationError("native SELL revalidation calldata drifted")

    @property
    def revalidated_at_epoch_s(self) -> int:
        return self.token_revalidation.revalidated_at_epoch_s

    @property
    def revalidation_id(self) -> str:
        return digest_object(
            {
                "native_scope_digest": self.native_scope.scope_digest,
                "preview_digest": self.preview.preview_digest,
                "schema": self.schema,
                "token_revalidation_id": self.token_revalidation.revalidation_id,
            }
        )

    def eip1559_signing_fields(self) -> dict[str, Any]:
        return {
            "accessList": [],
            "chainId": self.native_scope.chain_id,
            "data": "0x" + self.native_calldata.hex(),
            "gas": self.native_scope.gas_limit_ceiling,
            "maxFeePerGas": self.native_scope.max_fee_per_gas_ceiling,
            "maxPriorityFeePerGas": self.native_scope.max_priority_fee_per_gas_ceiling,
            "nonce": self.native_scope.account_nonce,
            "to": self.native_scope.target_address,
            "type": 2,
            "value": 0,
        }


def revalidate_ink_v0f_native_sell_same_amount(
    *,
    live_verifier: InkV0FLiveVerifier,
    risk_policy: InkV0FRiskPolicyV0,
    router_identity: InkV0FRouterIdentityV0,
    ledger: SpotLedger,
    intent: IntentV0,
    session: ExecutionSessionV0,
    approval: ApprovalActionV0,
    native_preview: InkV0FNativeSellPreviewV0,
    native_envelope: ExecutionEnvelopeV0,
    approval_settlement: InkV0FApprovalSettlementV0,
    now_epoch_s: int,
) -> InkV0FNativeSellRevalidationV0:
    if type(native_preview) is not InkV0FNativeSellPreviewV0 or native_preview._token is not _NATIVE_SELL_PREVIEW_TOKEN:
        raise AuthorityVerificationError("native SELL revalidation requires canonical preview")
    if native_envelope != build_ink_v0f_native_sell_envelope(native_preview):
        raise SafeHaltError("native SELL envelope differs from frozen preview")
    if approval_settlement.state is not InkV0FApprovalSettlementState.SETTLED:
        raise SafeHaltError("native SELL requires settled exact approval")
    if (
        approval.economic_action_id != native_envelope.economic_action_id
        or approval.approval_action_id != approval_settlement.approval_action_id
        or approval.requested_allowance_atomic != native_envelope.max_input_atomic
        or approval.token_address != KRAKMASK_ADDRESS
        or approval.spender_address != INK_V0F_ROUTER_ADDRESS
    ):
        raise SafeHaltError("native SELL approval differs from frozen envelope")
    if approval_settlement.observed_allowance_atomic != native_envelope.max_input_atomic:
        raise SafeHaltError("native SELL settled allowance differs from frozen input")

    token_revalidation = revalidate_ink_v0f_same_amount(
        live_verifier=live_verifier,
        risk_policy=risk_policy,
        router_identity=router_identity,
        ledger=ledger,
        intent=intent,
        session=session,
        approval=approval,
        envelope=native_preview.token_envelope,
        approval_settlement=approval_settlement,
        now_epoch_s=now_epoch_s,
    )
    if (
        token_revalidation.swap_request.scope.account_nonce
        != native_preview.native_scope.account_nonce
        or token_revalidation.swap_request.scope.gas_limit_ceiling
        != native_preview.native_scope.gas_limit_ceiling
        or token_revalidation.swap_request.scope.max_fee_per_gas_ceiling
        != native_preview.native_scope.max_fee_per_gas_ceiling
        or token_revalidation.swap_request.scope.max_priority_fee_per_gas_ceiling
        != native_preview.native_scope.max_priority_fee_per_gas_ceiling
    ):
        raise SafeHaltError("native SELL signer-state scope differs from frozen preview")

    return InkV0FNativeSellRevalidationV0(
        preview=native_preview,
        token_revalidation=token_revalidation,
        native_scope=native_preview.native_scope,
        native_calldata=native_preview.native_calldata,
        _token=_NATIVE_SELL_REVALIDATION_TOKEN,
    )


def validate_ink_v0f_native_signed_sell(
    revalidation: InkV0FNativeSellRevalidationV0,
    envelope: ExecutionEnvelopeV0,
    signed_bytes: bytes,
    *,
    admitted_at_epoch_s: int,
) -> ValidatedExactSignedBytesV0:
    if type(revalidation) is not InkV0FNativeSellRevalidationV0:
        raise AuthorityVerificationError("native signed SELL requires canonical revalidation")
    if revalidation._token is not _NATIVE_SELL_REVALIDATION_TOKEN:
        raise SafeHaltError("native signed SELL requires live-produced revalidation")
    if envelope != build_ink_v0f_native_sell_envelope(revalidation.preview):
        raise EnvelopeValidationError("native SELL envelope differs at admission")
    admitted = _uint(admitted_at_epoch_s, field_name="admitted time")
    if admitted < revalidation.revalidated_at_epoch_s:
        raise EnvelopeValidationError("native SELL admission predates revalidation")
    if admitted - revalidation.revalidated_at_epoch_s > MAX_REVALIDATION_TO_ADMISSION_S:
        raise SafeHaltError("native SELL revalidation is too old")
    if admitted >= envelope.deadline_epoch_s:
        raise SafeHaltError("native SELL admission is at or past deadline")
    validated = validate_exact_signed_bytes(signed_bytes, revalidation.native_scope)
    if validated.parsed.transaction_type != "eip-1559":
        raise EnvelopeValidationError("native SELL accepts EIP-1559 only")
    if validated.parsed.value_atomic != 0:
        raise EnvelopeValidationError("native SELL signed transaction carries native input")
    if validated.parsed.calldata != revalidation.native_calldata:
        raise EnvelopeValidationError("native SELL signed calldata differs")
    return validated
