"""Native-ETH first-live BUY path for Ink V0F.

The pool remains KRAKMASK/WETH. The wallet funds the BUY with native ETH as
transaction.value; the pinned UniswapV2Router02 wraps it to WETH internally.
WETH remains the pool quote unit. No WETH balance or approval is required.

This module never signs and never broadcasts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .canon import digest_object, sha256_hex
from .domain import IntentV0, Side
from .errors import (
    AuthorityVerificationError,
    EnvelopeValidationError,
    LevelNotExecutableError,
    SafeHaltError,
)
from .exact_signed_bytes import (
    ExactSignedBytesScopeV0,
    ValidatedExactSignedBytesV0,
    validate_exact_signed_bytes,
)
from .execution_contract import ExecutionEnvelopeV0, ExecutionSessionV0
from .ink import (
    INK_CHAIN_ID,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    InkQuoteV0,
    InkShadowAdapter,
)
from .ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    InkV0FRouterIdentityV0,
    _concurrency_snapshot_from_ledger,
    _durable_intent_row,
    amount_out_min_atomic,
)
from .ink_v0f_human_signing import observe_ink_v0f_signer_state_for_market
from .ink_v0f_preauth import INK_V0F_QUOTE_ID, InkV0FLiveVerifier
from .ink_v0f_risk import InkV0FRiskPolicyV0, assert_ink_v0f_entry_admissible
from .keccak import keccak256
from .ledger.store import SpotLedger

NATIVE_ETH_FUNDING_MODE = "NATIVE_ETH_ROUTER_WRAP"
SWAP_EXACT_ETH_FOR_TOKENS_SELECTOR = keccak256(
    b"swapExactETHForTokens(uint256,address[],address,uint256)"
)[:4]
NATIVE_BUY_PREVIEW_SCHEMA = "qntyspot.ink_v0f.native_buy_preview.v0"
NATIVE_REVALIDATION_SCHEMA = "qntyspot.ink_v0f.native_same_amount_revalidation.v0"
MAX_REVALIDATION_TO_ADMISSION_S = 120
_NATIVE_REVALIDATION_TOKEN = object()


def _rpc_quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
        raise SafeHaltError(f"{field} is not a canonical RPC quantity")
    body = value[2:]
    if any(char not in "0123456789abcdef" for char in body):
        raise SafeHaltError(f"{field} is not lowercase hexadecimal")
    if len(body) > 1 and body[0] == "0":
        raise SafeHaltError(f"{field} has leading zeroes")
    return int(body, 16)


@dataclass(frozen=True, slots=True)
class InkV0FNativeBalanceObservationV0:
    common_block: int
    balance_atomic: int
    provider_evidence: tuple[Mapping[str, Any], Mapping[str, Any]]
    schema: str = "qntyspot.ink_v0f.native_balance_observation.v0"

    def __post_init__(self) -> None:
        _uint(self.common_block, field="native balance common block")
        _uint(self.balance_atomic, field="native balance")
        if len(self.provider_evidence) != 2:
            raise SafeHaltError("native balance observation requires two providers")

    @property
    def digest(self) -> str:
        return digest_object(
            {
                "balance_atomic": str(self.balance_atomic),
                "common_block": self.common_block,
                "provider_evidence": [dict(item) for item in self.provider_evidence],
                "schema": self.schema,
            }
        )


def observe_ink_v0f_native_balance_for_market(
    live_verifier: InkV0FLiveVerifier,
    market: InkMarketObservationV0,
) -> InkV0FNativeBalanceObservationV0:
    if type(live_verifier) is not InkV0FLiveVerifier:
        raise AuthorityVerificationError("native balance requires canonical verifier")
    if type(market) is not InkMarketObservationV0:
        raise AuthorityVerificationError("native balance requires canonical market")
    # Reuse the verifier's provider/head binding before reading at the exact
    # market common block.
    live_verifier._heads_for_market(market)
    block_tag = hex(market.common_block)
    rows = []
    for provider in live_verifier.providers:
        try:
            raw = provider.request(
                "eth_getBalance",
                [INK_V0F_TAKER_ADDRESS, block_tag],
            )
        except Exception as exc:
            raise SafeHaltError(f"native balance RPC read failed: {exc}") from exc
        balance = _rpc_quantity(raw, field="eth_getBalance")
        rows.append(
            {
                "balance_atomic": balance,
                "endpoint": provider.endpoint,
            }
        )
    if rows[0]["balance_atomic"] != rows[1]["balance_atomic"]:
        raise SafeHaltError("Ink V0F providers disagree on native balance")
    return InkV0FNativeBalanceObservationV0(
        common_block=market.common_block,
        balance_atomic=int(rows[0]["balance_atomic"]),
        provider_evidence=(rows[0], rows[1]),
    )


def _uint(value: Any, *, field: str, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EnvelopeValidationError(f"{field} must be an integer")
    if value < 0 or (positive and value == 0) or value >= 2**256:
        relation = "> 0" if positive else ">= 0"
        raise EnvelopeValidationError(f"{field} must be {relation} and fit uint256")
    return value


def _address(value: Any, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 42
        or not value.startswith("0x")
        or value.lower() != value
    ):
        raise EnvelopeValidationError(f"{field} must be a lowercase 0x address")
    try:
        raw = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise EnvelopeValidationError(f"{field} is not hexadecimal") from exc
    if len(raw) != 20 or int.from_bytes(raw, "big") == 0:
        raise EnvelopeValidationError(f"{field} is not a nonzero EVM address")
    return value


def _word(value: int) -> bytes:
    return _uint(value, field="ABI uint").to_bytes(32, "big")


def _address_word(value: str, *, field: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(_address(value, field=field)[2:])


def _decode_address_word(value: bytes, *, field: str) -> str:
    if len(value) != 32 or value[:12] != b"\x00" * 12:
        raise EnvelopeValidationError(f"{field} is not a canonical address word")
    return _address("0x" + value[12:].hex(), field=field)


def encode_swap_exact_eth_for_tokens(
    *,
    amount_out_min_atomic: int,
    path: tuple[str, str],
    recipient: str,
    deadline_epoch_s: int,
) -> bytes:
    amount_out_min = _uint(
        amount_out_min_atomic,
        field="swap amount out minimum",
        positive=True,
    )
    if type(path) is not tuple or len(path) != 2:
        raise EnvelopeValidationError("native Ink V0F path must contain exactly two tokens")
    token_in = _address(path[0], field="swap input token")
    token_out = _address(path[1], field="swap output token")
    if token_in != WETH9_ADDRESS or token_out != KRAKMASK_ADDRESS:
        raise EnvelopeValidationError(
            "native Ink V0F BUY path must be pinned WETH -> KRAKMASK"
        )
    to = _address(recipient, field="swap recipient")
    deadline = _uint(deadline_epoch_s, field="swap deadline", positive=True)
    return b"".join(
        (
            SWAP_EXACT_ETH_FOR_TOKENS_SELECTOR,
            _word(amount_out_min),
            _word(32 * 4),
            _address_word(to, field="swap recipient"),
            _word(deadline),
            _word(2),
            _address_word(token_in, field="swap input token"),
            _address_word(token_out, field="swap output token"),
        )
    )


def decode_swap_exact_eth_for_tokens(
    calldata: bytes,
) -> tuple[int, tuple[str, str], str, int]:
    if type(calldata) is not bytes or len(calldata) != 228:
        raise EnvelopeValidationError(
            "swapExactETHForTokens calldata must be exactly 228 bytes"
        )
    if calldata[:4] != SWAP_EXACT_ETH_FOR_TOKENS_SELECTOR:
        raise EnvelopeValidationError("native swap calldata selector differs")
    args = calldata[4:]
    amount_out_min = int.from_bytes(args[0:32], "big")
    path_offset = int.from_bytes(args[32:64], "big")
    recipient = _decode_address_word(args[64:96], field="swap recipient")
    deadline = int.from_bytes(args[96:128], "big")
    if path_offset != 32 * 4:
        raise EnvelopeValidationError("native swap path offset is not canonical")
    if int.from_bytes(args[128:160], "big") != 2:
        raise EnvelopeValidationError("native swap path length is not exactly two")
    token_in = _decode_address_word(args[160:192], field="swap input token")
    token_out = _decode_address_word(args[192:224], field="swap output token")
    _uint(amount_out_min, field="swap amount out minimum", positive=True)
    _uint(deadline, field="swap deadline", positive=True)
    if token_in != WETH9_ADDRESS or token_out != KRAKMASK_ADDRESS:
        raise EnvelopeValidationError(
            "native Ink V0F BUY path must be pinned WETH -> KRAKMASK"
        )
    return amount_out_min, (token_in, token_out), recipient, deadline


@dataclass(frozen=True, slots=True)
class InkV0FNativeBuyPreviewV0:
    amount_in_native_atomic: int
    amount_out_min_atomic: int
    path: tuple[str, str]
    recipient: str
    deadline_epoch_s: int
    calldata: bytes
    router_address: str
    quote_observation_digest: str
    quote_common_block: int
    quoted_output_atomic: int
    scope: ExactSignedBytesScopeV0
    constructed_at_epoch_s: int
    schema: str = NATIVE_BUY_PREVIEW_SCHEMA
    funding_mode: str = NATIVE_ETH_FUNDING_MODE

    def __post_init__(self) -> None:
        if self.schema != NATIVE_BUY_PREVIEW_SCHEMA:
            raise EnvelopeValidationError("unknown native Ink V0F preview schema")
        if self.funding_mode != NATIVE_ETH_FUNDING_MODE:
            raise EnvelopeValidationError("native Ink V0F funding mode differs")
        amount_in = _uint(
            self.amount_in_native_atomic,
            field="native BUY amount",
            positive=True,
        )
        _uint(self.amount_out_min_atomic, field="minimum output", positive=True)
        if self.router_address != INK_V0F_ROUTER_ADDRESS:
            raise EnvelopeValidationError("native Ink V0F preview targets wrong router")
        if self.recipient != INK_V0F_TAKER_ADDRESS:
            raise EnvelopeValidationError("native Ink V0F preview has wrong recipient")
        decoded = decode_swap_exact_eth_for_tokens(self.calldata)
        if decoded != (
            self.amount_out_min_atomic,
            self.path,
            self.recipient,
            self.deadline_epoch_s,
        ):
            raise EnvelopeValidationError(
                "native Ink V0F calldata differs from declared preview"
            )
        if self.scope.chain_id != INK_CHAIN_ID:
            raise EnvelopeValidationError("native Ink V0F scope is on wrong chain")
        if self.scope.taker_address != INK_V0F_TAKER_ADDRESS:
            raise EnvelopeValidationError("native Ink V0F scope has wrong taker")
        if self.scope.target_address != self.router_address:
            raise EnvelopeValidationError("native Ink V0F scope targets wrong router")
        if (
            self.scope.min_value_atomic != amount_in
            or self.scope.max_value_atomic != amount_in
        ):
            raise EnvelopeValidationError(
                "native Ink V0F scope must carry exact selected input as value"
            )
        if (
            self.scope.calldata_sha256 != sha256_hex(self.calldata)
            or self.scope.calldata_length != len(self.calldata)
        ):
            raise EnvelopeValidationError(
                "native Ink V0F scope calldata identity differs"
            )
        _uint(self.quote_common_block, field="quote common block")
        _uint(self.quoted_output_atomic, field="quoted output", positive=True)
        _uint(self.constructed_at_epoch_s, field="constructed time")

    @property
    def preview_digest(self) -> str:
        return digest_object(
            {
                "amount_in_native_atomic": str(self.amount_in_native_atomic),
                "amount_out_min_atomic": str(self.amount_out_min_atomic),
                "calldata_sha256": sha256_hex(self.calldata),
                "constructed_at_epoch_s": self.constructed_at_epoch_s,
                "funding_mode": self.funding_mode,
                "quote_common_block": self.quote_common_block,
                "quote_observation_digest": self.quote_observation_digest,
                "quoted_output_atomic": str(self.quoted_output_atomic),
                "router_address": self.router_address,
                "schema": self.schema,
                "scope_digest": self.scope.scope_digest,
            }
        )

    def eip1559_signing_fields(self) -> dict[str, Any]:
        return {
            "accessList": [],
            "chainId": self.scope.chain_id,
            "data": "0x" + self.calldata.hex(),
            "gas": self.scope.gas_limit_ceiling,
            "maxFeePerGas": self.scope.max_fee_per_gas_ceiling,
            "maxPriorityFeePerGas": self.scope.max_priority_fee_per_gas_ceiling,
            "nonce": self.scope.account_nonce,
            "to": self.router_address,
            "type": 2,
            "value": self.amount_in_native_atomic,
        }


def build_ink_v0f_native_buy_preview(
    *,
    policy: InkV0FRiskPolicyV0,
    router: InkV0FRouterIdentityV0,
    observation: InkMarketObservationV0,
    quote: InkQuoteV0,
    ledger: SpotLedger,
    intent: IntentV0,
    session: ExecutionSessionV0,
    account_nonce: int,
    gas_limit_ceiling: int,
    max_fee_per_gas_ceiling: int,
    max_priority_fee_per_gas_ceiling: int,
    constructed_at_epoch_s: int,
) -> InkV0FNativeBuyPreviewV0:
    if type(policy) is not InkV0FRiskPolicyV0:
        raise AuthorityVerificationError("native Ink V0F preview requires verified risk")
    if type(router) is not InkV0FRouterIdentityV0:
        raise AuthorityVerificationError("native Ink V0F preview requires verified router")
    if type(session) is not ExecutionSessionV0:
        raise AuthorityVerificationError("native Ink V0F preview requires execution session")
    if intent.side is not Side.BUY or intent.bounds.side is not Side.BUY:
        raise LevelNotExecutableError("native Ink V0F path supports BUY only")
    if session.chain_id != INK_CHAIN_ID or session.taker_address != INK_V0F_TAKER_ADDRESS:
        raise AuthorityVerificationError("native Ink V0F session is outside frozen scope")
    if session.network_id != policy.network_id or session.venue_id != policy.venue_id:
        raise AuthorityVerificationError("native Ink V0F session differs from frozen risk")
    if session.policy_id != intent.policy_id:
        raise AuthorityVerificationError("native Ink V0F session policy differs from intent")

    row = _durable_intent_row(ledger, intent)
    if row["network_id"] != policy.network_id:
        raise AuthorityVerificationError("durable intent network differs from frozen risk")
    concurrency = _concurrency_snapshot_from_ledger(
        ledger,
        current_economic_action_id=intent.economic_action_id,
        instrument_id=intent.instrument_id,
        network_id=intent.network_id,
    )
    assert_ink_v0f_entry_admissible(
        policy,
        observation=observation,
        quote=quote,
        bounds=intent.bounds,
        cumulative_entry_atomic_after=ledger.held_atomic(),
        concurrency_snapshot=concurrency,
    )

    nonce = _uint(account_nonce, field="account nonce")
    gas = _uint(gas_limit_ceiling, field="gas limit ceiling", positive=True)
    max_fee = _uint(max_fee_per_gas_ceiling, field="fee ceiling", positive=True)
    priority = _uint(
        max_priority_fee_per_gas_ceiling,
        field="priority fee ceiling",
    )
    if priority > max_fee:
        raise EnvelopeValidationError("priority fee ceiling exceeds fee ceiling")
    constructed = _uint(constructed_at_epoch_s, field="constructed time")
    if constructed >= intent.bounds.deadline_epoch_s:
        raise LevelNotExecutableError("native Ink V0F preview deadline has expired")

    minimum = amount_out_min_atomic(policy, bounds=intent.bounds, quote=quote)
    path = (WETH9_ADDRESS, KRAKMASK_ADDRESS)
    calldata = encode_swap_exact_eth_for_tokens(
        amount_out_min_atomic=minimum,
        path=path,
        recipient=session.taker_address,
        deadline_epoch_s=intent.bounds.deadline_epoch_s,
    )
    scope = ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=intent.economic_action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=INK_CHAIN_ID,
        taker_address=session.taker_address,
        target_address=router.address,
        min_value_atomic=quote.input_atomic,
        max_value_atomic=quote.input_atomic,
        calldata_sha256=sha256_hex(calldata),
        calldata_length=len(calldata),
        account_nonce=nonce,
        gas_limit_ceiling=gas,
        max_fee_per_gas_ceiling=max_fee,
        max_priority_fee_per_gas_ceiling=priority,
    )
    return InkV0FNativeBuyPreviewV0(
        amount_in_native_atomic=quote.input_atomic,
        amount_out_min_atomic=minimum,
        path=path,
        recipient=session.taker_address,
        deadline_epoch_s=intent.bounds.deadline_epoch_s,
        calldata=calldata,
        router_address=router.address,
        quote_observation_digest=observation.digest(),
        quote_common_block=observation.common_block,
        quoted_output_atomic=quote.output_atomic,
        scope=scope,
        constructed_at_epoch_s=constructed,
    )


def build_ink_v0f_native_execution_envelope(
    preview: InkV0FNativeBuyPreviewV0,
    *,
    policy: InkV0FRiskPolicyV0,
    session: ExecutionSessionV0,
) -> ExecutionEnvelopeV0:
    if type(preview) is not InkV0FNativeBuyPreviewV0:
        raise AuthorityVerificationError("native envelope requires canonical preview")
    if type(policy) is not InkV0FRiskPolicyV0:
        raise AuthorityVerificationError("native envelope requires verified risk")
    if type(session) is not ExecutionSessionV0:
        raise AuthorityVerificationError("native envelope requires execution session")
    if preview.scope.session_id != session.session_id:
        raise EnvelopeValidationError("native preview belongs to another session")
    if preview.scope.session_identity_digest != session.identity_digest:
        raise EnvelopeValidationError("native preview session identity differs")
    if preview.scope.authority_policy_digest != session.authority_policy_digest:
        raise EnvelopeValidationError("native preview authority differs")

    plan_id = digest_object(
        {
            "funding_mode": NATIVE_ETH_FUNDING_MODE,
            "preview_digest": preview.preview_digest,
            "schema": "qntyspot.ink_v0f.native_envelope_plan.v0",
        }
    )
    return ExecutionEnvelopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=preview.scope.economic_action_id,
        chain_id=INK_CHAIN_ID,
        taker_address=session.taker_address,
        input_instrument_id=policy.quote_instrument_id,
        output_instrument_id=policy.base_instrument_id,
        max_input_atomic=preview.amount_in_native_atomic,
        min_output_atomic=preview.amount_out_min_atomic,
        transaction_to=preview.router_address,
        transaction_value_atomic=preview.amount_in_native_atomic,
        calldata_sha256=sha256_hex(preview.calldata),
        calldata_length=len(preview.calldata),
        allowance_target=None,
        account_nonce=int(preview.scope.account_nonce),
        gas_limit_ceiling=int(preview.scope.gas_limit_ceiling),
        max_fee_per_gas_ceiling_atomic=int(preview.scope.max_fee_per_gas_ceiling),
        max_priority_fee_per_gas_ceiling_atomic=int(
            preview.scope.max_priority_fee_per_gas_ceiling
        ),
        deadline_epoch_s=preview.deadline_epoch_s,
        authority_policy_digest=session.authority_policy_digest,
        plan_id=plan_id,
        quote_id=INK_V0F_QUOTE_ID,
        quote_observation_digest=preview.quote_observation_digest,
        venue_block_number=preview.quote_common_block,
        constructed_at_epoch_s=preview.constructed_at_epoch_s,
    )


def assert_ink_v0f_native_execution_envelope_admissible(
    envelope: ExecutionEnvelopeV0,
    preview: InkV0FNativeBuyPreviewV0,
    *,
    policy: InkV0FRiskPolicyV0,
    session: ExecutionSessionV0,
    now_epoch_s: int,
) -> None:
    expected = build_ink_v0f_native_execution_envelope(
        preview,
        policy=policy,
        session=session,
    )
    if envelope != expected:
        raise EnvelopeValidationError("native Ink V0F envelope differs from preview")
    now = _uint(now_epoch_s, field="now")
    if now >= envelope.deadline_epoch_s:
        raise EnvelopeValidationError("native Ink V0F envelope deadline expired")
    if envelope.allowance_target is not None:
        raise EnvelopeValidationError("native Ink V0F BUY must not have allowance target")
    if envelope.transaction_value_atomic != envelope.max_input_atomic:
        raise EnvelopeValidationError("native Ink V0F BUY value must equal frozen input")


@dataclass(frozen=True, slots=True)
class InkV0FNativeSameAmountRevalidationV0:
    preview: InkV0FNativeBuyPreviewV0
    market_observation_digest: str
    router_observation_digest: str
    signer_state_digest: str
    native_balance_observation_digest: str
    fresh_quote_output_atomic: int
    fresh_required_min_output_atomic: int
    common_block: int
    revalidated_at_epoch_s: int
    schema: str = NATIVE_REVALIDATION_SCHEMA
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _NATIVE_REVALIDATION_TOKEN:
            raise SafeHaltError("native revalidation must be produced by live revalidator")
        if self.schema != NATIVE_REVALIDATION_SCHEMA:
            raise EnvelopeValidationError("unknown native revalidation schema")
        if type(self.preview) is not InkV0FNativeBuyPreviewV0:
            raise EnvelopeValidationError("native revalidation requires canonical preview")
        for value, field in (
            (self.market_observation_digest, "market observation digest"),
            (self.router_observation_digest, "router observation digest"),
            (self.signer_state_digest, "signer state digest"),
            (self.native_balance_observation_digest, "native balance observation digest"),
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise EnvelopeValidationError(f"{field} is not canonical")
        _uint(self.fresh_quote_output_atomic, field="fresh quote output", positive=True)
        _uint(
            self.fresh_required_min_output_atomic,
            field="fresh required min output",
            positive=True,
        )
        _uint(self.common_block, field="common block")
        _uint(self.revalidated_at_epoch_s, field="revalidated time")

    @property
    def revalidation_id(self) -> str:
        return digest_object(
            {
                "common_block": self.common_block,
                "fresh_quote_output_atomic": str(self.fresh_quote_output_atomic),
                "fresh_required_min_output_atomic": str(
                    self.fresh_required_min_output_atomic
                ),
                "market_observation_digest": self.market_observation_digest,
                "native_balance_observation_digest": self.native_balance_observation_digest,
                "preview_digest": self.preview.preview_digest,
                "revalidated_at_epoch_s": self.revalidated_at_epoch_s,
                "router_observation_digest": self.router_observation_digest,
                "schema": self.schema,
                "signer_state_digest": self.signer_state_digest,
            }
        )

    def eip1559_signing_fields(self) -> dict[str, Any]:
        return self.preview.eip1559_signing_fields()


def revalidate_ink_v0f_native_same_amount(
    *,
    live_verifier: InkV0FLiveVerifier,
    risk_policy: InkV0FRiskPolicyV0,
    router_identity: InkV0FRouterIdentityV0,
    ledger: SpotLedger,
    intent: IntentV0,
    session: ExecutionSessionV0,
    envelope: ExecutionEnvelopeV0,
    now_epoch_s: int,
) -> InkV0FNativeSameAmountRevalidationV0:
    if type(live_verifier) is not InkV0FLiveVerifier:
        raise AuthorityVerificationError("native revalidation requires canonical verifier")
    if type(router_identity) is not InkV0FRouterIdentityV0:
        raise AuthorityVerificationError("native revalidation requires verified router")
    now = _uint(now_epoch_s, field="now")
    if intent.side is not Side.BUY:
        raise SafeHaltError("native revalidation only supports BUY")
    if envelope.allowance_target is not None:
        raise SafeHaltError("native BUY unexpectedly names an allowance target")
    if envelope.transaction_value_atomic != envelope.max_input_atomic:
        raise SafeHaltError("native BUY value differs from frozen input")
    if now >= envelope.deadline_epoch_s:
        raise SafeHaltError("native BUY deadline expired")

    market = live_verifier.observe_market()
    router = live_verifier.observe_router_for_market(market)
    signer_state = observe_ink_v0f_signer_state_for_market(live_verifier, market)
    native_balance = observe_ink_v0f_native_balance_for_market(live_verifier, market)
    if router.router_address != router_identity.address:
        raise SafeHaltError("fresh router differs from frozen router")
    if signer_state.account_nonce != envelope.account_nonce:
        raise SafeHaltError("fresh taker nonce differs from frozen native BUY nonce")
    if signer_state.base_fee_per_gas > envelope.max_fee_per_gas_ceiling_atomic:
        raise SafeHaltError("fresh base fee exceeds frozen fee ceiling")
    worst_case_gas_atomic = (
        envelope.gas_limit_ceiling * envelope.max_fee_per_gas_ceiling_atomic
    )
    required_native_atomic = envelope.transaction_value_atomic + worst_case_gas_atomic
    if native_balance.balance_atomic < required_native_atomic:
        raise SafeHaltError(
            "native balance cannot cover frozen input plus worst-case gas ceiling"
        )

    quote = InkShadowAdapter._quote(market, Side.BUY, envelope.max_input_atomic)
    concurrency = _concurrency_snapshot_from_ledger(
        ledger,
        current_economic_action_id=intent.economic_action_id,
        instrument_id=intent.instrument_id,
        network_id=intent.network_id,
    )
    assert_ink_v0f_entry_admissible(
        risk_policy,
        observation=market,
        quote=quote,
        bounds=intent.bounds,
        cumulative_entry_atomic_after=ledger.held_atomic(),
        concurrency_snapshot=concurrency,
    )
    required_min = amount_out_min_atomic(
        risk_policy,
        bounds=intent.bounds,
        quote=quote,
    )
    if envelope.min_output_atomic < required_min:
        raise SafeHaltError("frozen native minimum output is now too loose")
    if envelope.min_output_atomic > quote.output_atomic:
        raise SafeHaltError("fresh native quote cannot satisfy frozen minimum")

    frozen_calldata = encode_swap_exact_eth_for_tokens(
        amount_out_min_atomic=envelope.min_output_atomic,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=session.taker_address,
        deadline_epoch_s=envelope.deadline_epoch_s,
    )
    if sha256_hex(frozen_calldata) != envelope.calldata_sha256:
        raise SafeHaltError("frozen native calldata differs from envelope")
    if len(frozen_calldata) != envelope.calldata_length:
        raise SafeHaltError("frozen native calldata length differs from envelope")
    scope = ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=envelope.economic_action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=envelope.chain_id,
        taker_address=envelope.taker_address,
        target_address=envelope.transaction_to,
        min_value_atomic=envelope.transaction_value_atomic,
        max_value_atomic=envelope.transaction_value_atomic,
        calldata_sha256=envelope.calldata_sha256,
        calldata_length=envelope.calldata_length,
        account_nonce=envelope.account_nonce,
        gas_limit_ceiling=envelope.gas_limit_ceiling,
        max_fee_per_gas_ceiling=envelope.max_fee_per_gas_ceiling_atomic,
        max_priority_fee_per_gas_ceiling=envelope.max_priority_fee_per_gas_ceiling_atomic,
    )
    frozen_preview = InkV0FNativeBuyPreviewV0(
        amount_in_native_atomic=envelope.max_input_atomic,
        amount_out_min_atomic=envelope.min_output_atomic,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=session.taker_address,
        deadline_epoch_s=envelope.deadline_epoch_s,
        calldata=frozen_calldata,
        router_address=envelope.transaction_to,
        quote_observation_digest=market.digest(),
        quote_common_block=market.common_block,
        quoted_output_atomic=quote.output_atomic,
        scope=scope,
        constructed_at_epoch_s=now,
    )
    return InkV0FNativeSameAmountRevalidationV0(
        preview=frozen_preview,
        market_observation_digest=market.digest(),
        router_observation_digest=router.digest,
        signer_state_digest=signer_state.digest,
        native_balance_observation_digest=native_balance.digest,
        fresh_quote_output_atomic=quote.output_atomic,
        fresh_required_min_output_atomic=required_min,
        common_block=market.common_block,
        revalidated_at_epoch_s=now,
        _token=_NATIVE_REVALIDATION_TOKEN,
    )


def validate_ink_v0f_native_signed_buy(
    revalidation: InkV0FNativeSameAmountRevalidationV0,
    envelope: ExecutionEnvelopeV0,
    signed_bytes: bytes,
    *,
    admitted_at_epoch_s: int,
) -> ValidatedExactSignedBytesV0:
    if type(revalidation) is not InkV0FNativeSameAmountRevalidationV0:
        raise AuthorityVerificationError("native signed BUY requires canonical revalidation")
    admitted = _uint(admitted_at_epoch_s, field="admitted time")
    if admitted < revalidation.revalidated_at_epoch_s:
        raise EnvelopeValidationError("native admission predates revalidation")
    if admitted - revalidation.revalidated_at_epoch_s > MAX_REVALIDATION_TO_ADMISSION_S:
        raise SafeHaltError("native same-amount revalidation is too old")
    if admitted >= envelope.deadline_epoch_s:
        raise SafeHaltError("native signed BUY is at or past deadline")

    preview = revalidation.preview
    if (
        envelope.economic_action_id != preview.scope.economic_action_id
        or envelope.session_identity_digest != preview.scope.session_identity_digest
        or envelope.authority_policy_digest != preview.scope.authority_policy_digest
        or envelope.transaction_to != preview.scope.target_address
        or envelope.transaction_value_atomic != preview.amount_in_native_atomic
        or envelope.calldata_sha256 != preview.scope.calldata_sha256
        or envelope.calldata_length != preview.scope.calldata_length
        or envelope.account_nonce != preview.scope.account_nonce
    ):
        raise EnvelopeValidationError("native revalidation differs from frozen envelope")
    validated = validate_exact_signed_bytes(signed_bytes, preview.scope)
    if validated.parsed.transaction_type != "eip-1559":
        raise EnvelopeValidationError("native Ink V0F accepts EIP-1559 only")
    if validated.parsed.value_atomic != envelope.max_input_atomic:
        raise EnvelopeValidationError("native signed BUY value differs from frozen input")
    if validated.parsed.calldata != preview.calldata:
        raise EnvelopeValidationError("native signed BUY calldata differs")
    return validated
