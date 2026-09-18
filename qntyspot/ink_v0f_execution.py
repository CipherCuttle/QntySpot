"""Offline Ink V0F router codec and human-controlled signing preview.

This module is deliberately non-authorizing. It consumes already-verified
market/risk inputs and constructs deterministic transaction *previews* while
the binding QntySpot source ceiling remains RECONCILE_ONLY. It performs no
network I/O, persists nothing, produces no signature, and exposes no transport.

The preview is the exact material a later, separately authorized Level-3 phase
may turn into a durable execution envelope for a human-controlled taker.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canon import canonical_json_bytes, digest_object, sha256_hex, strict_json_loads
from .domain import BPS_DENOMINATOR, EconomicBounds, Side, ceil_div
from .errors import AuthorityVerificationError, EnvelopeValidationError, LevelNotExecutableError
from .exact_signed_bytes import ExactSignedBytesScopeV0
from .execution_contract import ExecutionSessionV0
from .ink import (
    INK_CHAIN_ID,
    INKYSWAP_V2_FACTORY,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    InkQuoteV0,
    InkShadowAdapter,
)
from .ink_v0f_risk import (
    INK_V0F_BASE_INSTRUMENT_ID,
    INK_V0F_QUOTE_INSTRUMENT_ID,
    INK_V0F_VENUE_ID,
    InkV0FRiskPolicyV0,
    assert_ink_v0f_entry_admissible,
)
from .keccak import keccak256
from .prelive_economics import (
    PositionConcurrencySnapshotV0,
    prorated_min_output_atomic,
)

INK_V0F_ROUTER_SCHEMA = "qntyspot.ink_v0f_router_identity.v0"
INK_V0F_ROUTER_ADDRESS = "0xa8c1c38ff57428e5c3a34e0899be5cb385476507"
INK_V0F_ROUTER_BYTECODE_SHA256 = (
    "64ec5d32d5ce6eb632cad54cb7de2653e7aec19fdad0b641b16c0b1a1f52ba7b"
)
INK_V0F_ROUTER_BYTECODE_LENGTH = 18_095
INK_V0F_ROUTER_ARTIFACT_DIGEST = (
    "985d10917c17058c1a564af9ce0f3c8118ce794d4dbdb12946b0390fad6bad0c"
)
INK_V0F_TAKER_ADDRESS = "0x3e604be3293d930069d0805e85379e0ca5fa01cb"

APPROVE_SELECTOR = keccak256(b"approve(address,uint256)")[:4]
SWAP_EXACT_TOKENS_SELECTOR = keccak256(
    b"swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"
)[:4]

_EXPECTED_ROUTER_FIELDS = {
    "address",
    "chain_id",
    "contract_name",
    "deployed_bytecode_length",
    "deployed_bytecode_sha256",
    "factory_address",
    "schema",
    "weth_address",
}


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


def _decode_address_word(word: bytes, *, field: str) -> str:
    if len(word) != 32 or word[:12] != b"\x00" * 12:
        raise EnvelopeValidationError(f"{field} is not a canonical address word")
    return _address("0x" + word[12:].hex(), field=field)


@dataclass(frozen=True, slots=True)
class InkV0FRouterIdentityV0:
    address: str
    chain_id: int
    contract_name: str
    deployed_bytecode_length: int
    deployed_bytecode_sha256: str
    factory_address: str
    weth_address: str
    artifact_digest: str = INK_V0F_ROUTER_ARTIFACT_DIGEST

    def __post_init__(self) -> None:
        if self.address != INK_V0F_ROUTER_ADDRESS:
            raise AuthorityVerificationError("Ink V0F router address differs from the pinned identity")
        if self.chain_id != INK_CHAIN_ID:
            raise AuthorityVerificationError("Ink V0F router chain differs from Ink mainnet")
        if self.contract_name != "UniswapV2Router02":
            raise AuthorityVerificationError("Ink V0F router contract name differs")
        if self.deployed_bytecode_length != INK_V0F_ROUTER_BYTECODE_LENGTH:
            raise AuthorityVerificationError("Ink V0F router bytecode length differs")
        if self.deployed_bytecode_sha256 != INK_V0F_ROUTER_BYTECODE_SHA256:
            raise AuthorityVerificationError("Ink V0F router bytecode digest differs")
        if self.factory_address != INKYSWAP_V2_FACTORY:
            raise AuthorityVerificationError("Ink V0F router factory differs")
        if self.weth_address != WETH9_ADDRESS:
            raise AuthorityVerificationError("Ink V0F router WETH differs")


def consume_ink_v0f_router_artifact(raw: bytes) -> InkV0FRouterIdentityV0:
    if type(raw) is not bytes:
        raise AuthorityVerificationError("Ink V0F router artifact must be explicit bytes")
    digest = sha256_hex(raw)
    if digest != INK_V0F_ROUTER_ARTIFACT_DIGEST:
        raise AuthorityVerificationError(
            f"Ink V0F router artifact digest mismatch: expected "
            f"{INK_V0F_ROUTER_ARTIFACT_DIGEST}, got {digest}"
        )
    try:
        document = strict_json_loads(raw)
    except Exception as exc:
        raise AuthorityVerificationError("Ink V0F router artifact is not strict JSON") from exc
    if type(document) is not dict or set(document) != _EXPECTED_ROUTER_FIELDS:
        raise AuthorityVerificationError("Ink V0F router artifact has unknown or missing fields")
    if canonical_json_bytes(document) != raw:
        raise AuthorityVerificationError("Ink V0F router artifact is not canonical JSON")
    if document["schema"] != INK_V0F_ROUTER_SCHEMA:
        raise AuthorityVerificationError("Ink V0F router artifact schema mismatch")
    return InkV0FRouterIdentityV0(
        address=document["address"],
        chain_id=document["chain_id"],
        contract_name=document["contract_name"],
        deployed_bytecode_length=document["deployed_bytecode_length"],
        deployed_bytecode_sha256=document["deployed_bytecode_sha256"],
        factory_address=document["factory_address"],
        weth_address=document["weth_address"],
    )


@dataclass(frozen=True, slots=True)
class InkV0FApprovalCallV0:
    token_address: str
    spender_address: str
    amount_atomic: int
    calldata: bytes

    def __post_init__(self) -> None:
        _address(self.token_address, field="approval token")
        _address(self.spender_address, field="approval spender")
        _uint(self.amount_atomic, field="approval amount", positive=True)
        if decode_approve(self.calldata) != (
            self.spender_address,
            self.amount_atomic,
        ):
            raise EnvelopeValidationError("approval calldata disagrees with the declared preview")

    @property
    def digest(self) -> str:
        return digest_object(
            {
                "amount_atomic": str(self.amount_atomic),
                "calldata_sha256": sha256_hex(self.calldata),
                "schema": "qntyspot.ink_v0f.approval_call.v0",
                "spender_address": self.spender_address,
                "token_address": self.token_address,
            }
        )


@dataclass(frozen=True, slots=True)
class InkV0FSwapCallV0:
    amount_in_atomic: int
    amount_out_min_atomic: int
    path: tuple[str, str]
    recipient: str
    deadline_epoch_s: int
    calldata: bytes

    def __post_init__(self) -> None:
        _uint(self.amount_in_atomic, field="swap amount in", positive=True)
        _uint(self.amount_out_min_atomic, field="swap amount out minimum", positive=True)
        if type(self.path) is not tuple or len(self.path) != 2:
            raise EnvelopeValidationError("Ink V0F swap path must contain exactly two tokens")
        _address(self.path[0], field="swap input token")
        _address(self.path[1], field="swap output token")
        if self.path[0] == self.path[1]:
            raise EnvelopeValidationError("Ink V0F swap path tokens must differ")
        _address(self.recipient, field="swap recipient")
        _uint(self.deadline_epoch_s, field="swap deadline", positive=True)
        decoded = decode_swap_exact_tokens_for_tokens(self.calldata)
        if decoded != (
            self.amount_in_atomic,
            self.amount_out_min_atomic,
            self.path,
            self.recipient,
            self.deadline_epoch_s,
        ):
            raise EnvelopeValidationError("swap calldata disagrees with the declared preview")

    @property
    def digest(self) -> str:
        return digest_object(
            {
                "amount_in_atomic": str(self.amount_in_atomic),
                "amount_out_min_atomic": str(self.amount_out_min_atomic),
                "calldata_sha256": sha256_hex(self.calldata),
                "deadline_epoch_s": self.deadline_epoch_s,
                "path": list(self.path),
                "recipient": self.recipient,
                "schema": "qntyspot.ink_v0f.swap_call.v0",
            }
        )


@dataclass(frozen=True, slots=True)
class InkV0FHumanSigningPreviewV0:
    side: Side
    router_address: str
    quote_observation_digest: str
    quote_common_block: int
    quoted_output_atomic: int
    approval: InkV0FApprovalCallV0
    swap: InkV0FSwapCallV0
    signed_bytes_scope: ExactSignedBytesScopeV0
    constructed_at_epoch_s: int

    def __post_init__(self) -> None:
        if self.side not in (Side.BUY, Side.SELL):
            raise EnvelopeValidationError("Ink V0F preview side is invalid")
        if self.router_address != INK_V0F_ROUTER_ADDRESS:
            raise EnvelopeValidationError("Ink V0F preview targets the wrong router")
        if self.approval.spender_address != self.router_address:
            raise EnvelopeValidationError("Ink V0F approval spender differs from the router")
        if self.approval.amount_atomic != self.swap.amount_in_atomic:
            raise EnvelopeValidationError("Ink V0F approval amount differs from swap input")
        if self.signed_bytes_scope.target_address != self.router_address:
            raise EnvelopeValidationError("Ink V0F signed-byte scope targets the wrong contract")
        if self.signed_bytes_scope.calldata_sha256 != sha256_hex(self.swap.calldata):
            raise EnvelopeValidationError("Ink V0F signed-byte scope calldata digest differs")
        if self.signed_bytes_scope.calldata_length != len(self.swap.calldata):
            raise EnvelopeValidationError("Ink V0F signed-byte scope calldata length differs")
        if self.signed_bytes_scope.min_value_atomic != 0 or self.signed_bytes_scope.max_value_atomic != 0:
            raise EnvelopeValidationError("Ink V0F token-to-token swap must carry zero native value")
        _uint(self.quote_common_block, field="quote common block")
        _uint(self.quoted_output_atomic, field="quoted output", positive=True)
        _uint(self.constructed_at_epoch_s, field="constructed time")

    @property
    def preview_digest(self) -> str:
        return digest_object(
            {
                "approval_digest": self.approval.digest,
                "constructed_at_epoch_s": self.constructed_at_epoch_s,
                "quote_common_block": self.quote_common_block,
                "quote_observation_digest": self.quote_observation_digest,
                "quoted_output_atomic": str(self.quoted_output_atomic),
                "router_address": self.router_address,
                "schema": "qntyspot.ink_v0f.human_signing_preview.v0",
                "side": self.side.value,
                "signed_bytes_scope_digest": self.signed_bytes_scope.scope_digest,
                "swap_digest": self.swap.digest,
            }
        )

    def eip1559_signing_fields(self) -> dict[str, Any]:
        """Return explicit unsigned fields for an external human-controlled signer."""

        return {
            "accessList": [],
            "chainId": self.signed_bytes_scope.chain_id,
            "data": "0x" + self.swap.calldata.hex(),
            "gas": self.signed_bytes_scope.gas_limit_ceiling,
            "maxFeePerGas": self.signed_bytes_scope.max_fee_per_gas_ceiling,
            "maxPriorityFeePerGas": self.signed_bytes_scope.max_priority_fee_per_gas_ceiling,
            "nonce": self.signed_bytes_scope.account_nonce,
            "to": self.router_address,
            "type": 2,
            "value": 0,
        }


def encode_approve(spender_address: str, amount_atomic: int) -> bytes:
    return (
        APPROVE_SELECTOR
        + _address_word(spender_address, field="approval spender")
        + _word(_uint(amount_atomic, field="approval amount", positive=True))
    )


def decode_approve(calldata: bytes) -> tuple[str, int]:
    if type(calldata) is not bytes or len(calldata) != 68:
        raise EnvelopeValidationError("approve calldata must be exactly 68 bytes")
    if calldata[:4] != APPROVE_SELECTOR:
        raise EnvelopeValidationError("approve calldata selector differs")
    spender = _decode_address_word(calldata[4:36], field="approval spender")
    amount = int.from_bytes(calldata[36:68], "big")
    _uint(amount, field="approval amount", positive=True)
    return spender, amount


def encode_swap_exact_tokens_for_tokens(
    *,
    amount_in_atomic: int,
    amount_out_min_atomic: int,
    path: tuple[str, str],
    recipient: str,
    deadline_epoch_s: int,
) -> bytes:
    amount_in = _uint(amount_in_atomic, field="swap amount in", positive=True)
    amount_out_min = _uint(
        amount_out_min_atomic, field="swap amount out minimum", positive=True
    )
    if type(path) is not tuple or len(path) != 2:
        raise EnvelopeValidationError("Ink V0F swap path must contain exactly two tokens")
    token_in = _address(path[0], field="swap input token")
    token_out = _address(path[1], field="swap output token")
    if token_in == token_out:
        raise EnvelopeValidationError("Ink V0F swap path tokens must differ")
    to = _address(recipient, field="swap recipient")
    deadline = _uint(deadline_epoch_s, field="swap deadline", positive=True)
    return b"".join(
        (
            SWAP_EXACT_TOKENS_SELECTOR,
            _word(amount_in),
            _word(amount_out_min),
            _word(32 * 5),
            _address_word(to, field="swap recipient"),
            _word(deadline),
            _word(2),
            _address_word(token_in, field="swap input token"),
            _address_word(token_out, field="swap output token"),
        )
    )


def decode_swap_exact_tokens_for_tokens(
    calldata: bytes,
) -> tuple[int, int, tuple[str, str], str, int]:
    if type(calldata) is not bytes or len(calldata) != 260:
        raise EnvelopeValidationError(
            "swapExactTokensForTokens calldata must be exactly 260 bytes"
        )
    if calldata[:4] != SWAP_EXACT_TOKENS_SELECTOR:
        raise EnvelopeValidationError("swap calldata selector differs")
    args = calldata[4:]
    amount_in = int.from_bytes(args[0:32], "big")
    amount_out_min = int.from_bytes(args[32:64], "big")
    path_offset = int.from_bytes(args[64:96], "big")
    recipient = _decode_address_word(args[96:128], field="swap recipient")
    deadline = int.from_bytes(args[128:160], "big")
    if path_offset != 32 * 5:
        raise EnvelopeValidationError("swap path offset is not canonical")
    path_length = int.from_bytes(args[160:192], "big")
    if path_length != 2:
        raise EnvelopeValidationError("swap path length is not exactly two")
    token_in = _decode_address_word(args[192:224], field="swap input token")
    token_out = _decode_address_word(args[224:256], field="swap output token")
    _uint(amount_in, field="swap amount in", positive=True)
    _uint(amount_out_min, field="swap amount out minimum", positive=True)
    _uint(deadline, field="swap deadline", positive=True)
    if token_in == token_out:
        raise EnvelopeValidationError("swap path tokens must differ")
    return amount_in, amount_out_min, (token_in, token_out), recipient, deadline


def assert_ink_v0f_exit_admissible(
    policy: InkV0FRiskPolicyV0,
    *,
    observation: InkMarketObservationV0,
    quote: InkQuoteV0,
    bounds: EconomicBounds,
    settled_inventory_base_atomic: int,
) -> None:
    """Bind a SELL exit to canonical pool evidence and settled base inventory."""

    if type(policy) is not InkV0FRiskPolicyV0:
        raise AuthorityVerificationError("Ink V0F policy object is not verified")
    if type(observation) is not InkMarketObservationV0 or type(quote) is not InkQuoteV0:
        raise AuthorityVerificationError("Ink V0F exit requires canonical Ink evidence")
    if type(bounds) is not EconomicBounds:
        raise AuthorityVerificationError("Ink V0F exit requires committed economic bounds")
    inventory = _uint(
        settled_inventory_base_atomic,
        field="settled base inventory",
        positive=True,
    )
    if observation.chain_id != INK_CHAIN_ID or observation.pool_address != policy.pool_address:
        raise LevelNotExecutableError("Ink V0F exit observation is outside the frozen scope")
    if observation.factory_address != INKYSWAP_V2_FACTORY:
        raise LevelNotExecutableError("Ink V0F exit factory is outside the frozen scope")
    if observation.token0 != KRAKMASK_ADDRESS or observation.token1 != WETH9_ADDRESS:
        raise LevelNotExecutableError("Ink V0F exit token pair is outside the frozen scope")
    if quote.observation_digest != observation.digest() or quote.common_block != observation.common_block:
        raise LevelNotExecutableError("Ink V0F exit quote is not bound to the supplied observation")
    if bounds.side is not Side.SELL or quote.side is not Side.SELL:
        raise LevelNotExecutableError("Ink V0F exit requires SELL evidence")
    canonical_quote = InkShadowAdapter._quote(observation, Side.SELL, quote.input_atomic)
    if quote != canonical_quote:
        raise LevelNotExecutableError(
            "Ink V0F exit quote does not match canonical reserve-derived quote"
        )
    if bounds.input_instrument_id != INK_V0F_BASE_INSTRUMENT_ID:
        raise LevelNotExecutableError("Ink V0F exit input instrument is outside the frozen scope")
    if bounds.output_instrument_id != INK_V0F_QUOTE_INSTRUMENT_ID:
        raise LevelNotExecutableError("Ink V0F exit output instrument is outside the frozen scope")
    if bounds.max_price_impact_bps > policy.max_price_impact_bps:
        raise LevelNotExecutableError("Ink V0F exit price-impact ceiling exceeds external risk")
    if bounds.max_slippage_bps > policy.max_slippage_bps:
        raise LevelNotExecutableError("Ink V0F exit slippage ceiling exceeds external risk")
    if bounds.max_input_atomic > inventory:
        raise LevelNotExecutableError("Ink V0F committed exit exceeds settled base inventory")
    if quote.input_atomic <= 0 or quote.input_atomic > bounds.max_input_atomic:
        raise LevelNotExecutableError("Ink V0F exit quote input exceeds committed bounds")
    if quote.input_atomic > inventory:
        raise LevelNotExecutableError("Ink V0F exit quote exceeds settled base inventory")
    if quote.price_impact_bps < 0 or quote.price_impact_bps > policy.max_price_impact_bps:
        raise LevelNotExecutableError("Ink V0F exit quoted price impact exceeds the frozen cap")


def amount_out_min_atomic(
    policy: InkV0FRiskPolicyV0,
    *,
    bounds: EconomicBounds,
    quote: InkQuoteV0,
) -> int:
    """Return the stricter of policy price floor and quote-relative slippage floor."""

    if type(policy) is not InkV0FRiskPolicyV0:
        raise AuthorityVerificationError("Ink V0F policy object is not verified")
    if type(bounds) is not EconomicBounds or type(quote) is not InkQuoteV0:
        raise AuthorityVerificationError("Ink V0F minimum output requires bounds and quote")
    economic_floor = prorated_min_output_atomic(bounds, quote.input_atomic)
    slippage_floor = ceil_div(
        quote.output_atomic * (BPS_DENOMINATOR - policy.max_slippage_bps),
        BPS_DENOMINATOR,
    )
    return max(economic_floor, slippage_floor)


def build_ink_v0f_human_signing_preview(
    *,
    policy: InkV0FRiskPolicyV0,
    router: InkV0FRouterIdentityV0,
    observation: InkMarketObservationV0,
    quote: InkQuoteV0,
    bounds: EconomicBounds,
    session: ExecutionSessionV0,
    economic_action_id: str,
    account_nonce: int,
    gas_limit_ceiling: int,
    max_fee_per_gas_ceiling: int,
    max_priority_fee_per_gas_ceiling: int,
    constructed_at_epoch_s: int,
    cumulative_entry_atomic_after: int | None = None,
    concurrency_snapshot: PositionConcurrencySnapshotV0 | None = None,
    settled_inventory_base_atomic: int | None = None,
) -> InkV0FHumanSigningPreviewV0:
    """Construct one deterministic preview without authorizing or submitting it."""

    if type(router) is not InkV0FRouterIdentityV0:
        raise AuthorityVerificationError("Ink V0F preview requires a verified router identity")
    if type(session) is not ExecutionSessionV0:
        raise AuthorityVerificationError("Ink V0F preview requires an execution session")
    if session.network_id != policy.network_id or session.venue_id != INK_V0F_VENUE_ID:
        raise AuthorityVerificationError("Ink V0F preview session scope differs from frozen risk")
    if session.chain_id != INK_CHAIN_ID:
        raise AuthorityVerificationError("Ink V0F preview session is on the wrong chain")
    if session.taker_address != INK_V0F_TAKER_ADDRESS:
        raise AuthorityVerificationError("Ink V0F preview session has the wrong taker")
    if type(economic_action_id) is not str or len(economic_action_id) != 64:
        raise EnvelopeValidationError("economic_action_id must be a canonical digest")
    try:
        int(economic_action_id, 16)
    except ValueError as exc:
        raise EnvelopeValidationError("economic_action_id must be hexadecimal") from exc
    nonce = _uint(account_nonce, field="account nonce")
    gas = _uint(gas_limit_ceiling, field="gas limit ceiling", positive=True)
    max_fee = _uint(max_fee_per_gas_ceiling, field="fee ceiling", positive=True)
    priority_fee = _uint(
        max_priority_fee_per_gas_ceiling,
        field="priority fee ceiling",
    )
    if priority_fee > max_fee:
        raise EnvelopeValidationError("priority fee ceiling exceeds fee ceiling")
    constructed = _uint(constructed_at_epoch_s, field="constructed time")
    if constructed >= bounds.deadline_epoch_s:
        raise LevelNotExecutableError("Ink V0F preview deadline has already expired")

    if bounds.side is Side.BUY:
        if cumulative_entry_atomic_after is None or concurrency_snapshot is None:
            raise AuthorityVerificationError(
                "Ink V0F entry preview requires cumulative capital and concurrency"
            )
        if settled_inventory_base_atomic is not None:
            raise AuthorityVerificationError(
                "Ink V0F entry preview must not accept caller-supplied inventory"
            )
        assert_ink_v0f_entry_admissible(
            policy,
            observation=observation,
            quote=quote,
            bounds=bounds,
            cumulative_entry_atomic_after=cumulative_entry_atomic_after,
            concurrency_snapshot=concurrency_snapshot,
        )
        path = (WETH9_ADDRESS, KRAKMASK_ADDRESS)
        approval_token = WETH9_ADDRESS
    else:
        if settled_inventory_base_atomic is None:
            raise AuthorityVerificationError(
                "Ink V0F exit preview requires settled base inventory"
            )
        if cumulative_entry_atomic_after is not None or concurrency_snapshot is not None:
            raise AuthorityVerificationError(
                "Ink V0F exit preview does not consume entry concurrency/capital inputs"
            )
        assert_ink_v0f_exit_admissible(
            policy,
            observation=observation,
            quote=quote,
            bounds=bounds,
            settled_inventory_base_atomic=settled_inventory_base_atomic,
        )
        path = (KRAKMASK_ADDRESS, WETH9_ADDRESS)
        approval_token = KRAKMASK_ADDRESS

    minimum = amount_out_min_atomic(policy, bounds=bounds, quote=quote)
    swap_calldata = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=quote.input_atomic,
        amount_out_min_atomic=minimum,
        path=path,
        recipient=session.taker_address,
        deadline_epoch_s=bounds.deadline_epoch_s,
    )
    approval = InkV0FApprovalCallV0(
        token_address=approval_token,
        spender_address=router.address,
        amount_atomic=quote.input_atomic,
        calldata=encode_approve(router.address, quote.input_atomic),
    )
    swap = InkV0FSwapCallV0(
        amount_in_atomic=quote.input_atomic,
        amount_out_min_atomic=minimum,
        path=path,
        recipient=session.taker_address,
        deadline_epoch_s=bounds.deadline_epoch_s,
        calldata=swap_calldata,
    )
    scope = ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=economic_action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=INK_CHAIN_ID,
        taker_address=session.taker_address,
        target_address=router.address,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=sha256_hex(swap_calldata),
        calldata_length=len(swap_calldata),
        account_nonce=nonce,
        gas_limit_ceiling=gas,
        max_fee_per_gas_ceiling=max_fee,
        max_priority_fee_per_gas_ceiling=priority_fee,
    )
    return InkV0FHumanSigningPreviewV0(
        side=bounds.side,
        router_address=router.address,
        quote_observation_digest=observation.digest(),
        quote_common_block=observation.common_block,
        quoted_output_atomic=quote.output_atomic,
        approval=approval,
        swap=swap,
        signed_bytes_scope=scope,
        constructed_at_epoch_s=constructed,
    )
