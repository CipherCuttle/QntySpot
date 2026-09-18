"""Ink V0F live-read preflight and grant-gated Level-3 admission helpers.

This module adds no authority by itself. Public RPC reads may verify the
already frozen router and ERC-20 allowance state at the exact pool-observation
block. Builders produce the existing generic execution-envelope / approval
records; persistence remains gated by the Level-3 source ceiling intersected
with a current exact external grant in :mod:`qntyspot.ledger.execution`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from .canon import digest_object, sha256_hex
from .domain import IntentV0, Side
from .errors import (
    AuthorityVerificationError,
    EnvelopeValidationError,
    RpcError,
    SafeHaltError,
)
from .execution_contract import ApprovalActionV0, ExecutionEnvelopeV0, ExecutionSessionV0
from .ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    INKYSWAP_V2_BYTECODE_SHA256,
    INKYSWAP_V2_FACTORY,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    InkQuoteV0,
    InkShadowAdapter,
    JsonRpcClient,
)
from .ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_ROUTER_BYTECODE_LENGTH,
    INK_V0F_ROUTER_BYTECODE_SHA256,
    INK_V0F_TAKER_ADDRESS,
    InkV0FHumanSigningPreviewV0,
    InkV0FRouterIdentityV0,
    build_ink_v0f_human_signing_preview,
)
from .ink_v0f_risk import InkV0FRiskPolicyV0
from .keccak import keccak256
from .ledger.store import SpotLedger

ROUTER_FACTORY_SELECTOR = keccak256(b"factory()")[:4]
ROUTER_WETH_SELECTOR = keccak256(b"WETH()")[:4]
ERC20_ALLOWANCE_SELECTOR = keccak256(b"allowance(address,address)")[:4]

ROUTER_OBSERVATION_SCHEMA = "qntyspot.ink_v0f.router_observation.v0"
ALLOWANCE_OBSERVATION_SCHEMA = "qntyspot.ink_v0f.allowance_observation.v0"
INK_V0F_QUOTE_ID = "ink-v0f-v2"


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


def _address_word(value: str, *, field: str) -> bytes:
    return b"\x00" * 12 + bytes.fromhex(_address(value, field=field)[2:])


def _decode_address_word(value: bytes, *, field: str) -> str:
    if type(value) is not bytes or len(value) != 32 or value[:12] != b"\x00" * 12:
        raise SafeHaltError(f"{field} did not return one canonical address word")
    address = "0x" + value[12:].hex()
    _address(address, field=field)
    return address


def _decode_uint_word(value: bytes, *, field: str) -> int:
    if type(value) is not bytes or len(value) != 32:
        raise SafeHaltError(f"{field} did not return one canonical uint256 word")
    return int.from_bytes(value, "big")


@dataclass(frozen=True, slots=True)
class InkV0FRouterObservationV0:
    chain_id: int
    router_address: str
    common_block: int
    provider_heads: Mapping[str, int]
    bytecode_sha256: str
    bytecode_length: int
    factory_address: str
    weth_address: str
    provider_evidence: tuple[Mapping[str, Any], ...]
    schema: str = ROUTER_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ROUTER_OBSERVATION_SCHEMA:
            raise SafeHaltError("Ink V0F router observation schema mismatch")
        if self.chain_id != INK_CHAIN_ID:
            raise SafeHaltError("Ink V0F router observation is on the wrong chain")
        if self.router_address != INK_V0F_ROUTER_ADDRESS:
            raise SafeHaltError("Ink V0F router observation targets the wrong router")
        if self.common_block < 0:
            raise SafeHaltError("Ink V0F router observation block is negative")
        if len(self.provider_heads) != 2 or len(self.provider_evidence) != 2:
            raise SafeHaltError("Ink V0F router observation requires exactly two providers")
        if self.bytecode_sha256 != INK_V0F_ROUTER_BYTECODE_SHA256:
            raise SafeHaltError("Ink V0F router observation bytecode digest differs")
        if self.bytecode_length != INK_V0F_ROUTER_BYTECODE_LENGTH:
            raise SafeHaltError("Ink V0F router observation bytecode length differs")
        if self.factory_address != INKYSWAP_V2_FACTORY:
            raise SafeHaltError("Ink V0F router observation factory differs")
        if self.weth_address != WETH9_ADDRESS:
            raise SafeHaltError("Ink V0F router observation WETH differs")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "bytecode_length": self.bytecode_length,
            "bytecode_sha256": self.bytecode_sha256,
            "chain_id": self.chain_id,
            "common_block": self.common_block,
            "factory_address": self.factory_address,
            "provider_evidence": [dict(item) for item in self.provider_evidence],
            "provider_heads": dict(sorted(self.provider_heads.items())),
            "router_address": self.router_address,
            "schema": self.schema,
            "weth_address": self.weth_address,
        }

    @property
    def digest(self) -> str:
        return digest_object(self.canonical_object())


@dataclass(frozen=True, slots=True)
class InkV0FAllowanceObservationV0:
    token_address: str
    owner_address: str
    spender_address: str
    allowance_atomic: int
    common_block: int
    provider_heads: Mapping[str, int]
    provider_evidence: tuple[Mapping[str, Any], ...]
    schema: str = ALLOWANCE_OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != ALLOWANCE_OBSERVATION_SCHEMA:
            raise SafeHaltError("Ink V0F allowance observation schema mismatch")
        if self.token_address not in {WETH9_ADDRESS, KRAKMASK_ADDRESS}:
            raise SafeHaltError("Ink V0F allowance token is outside the frozen pair")
        if self.owner_address != INK_V0F_TAKER_ADDRESS:
            raise SafeHaltError("Ink V0F allowance owner differs from the frozen taker")
        if self.spender_address != INK_V0F_ROUTER_ADDRESS:
            raise SafeHaltError("Ink V0F allowance spender differs from the frozen router")
        if (
            isinstance(self.allowance_atomic, bool)
            or not isinstance(self.allowance_atomic, int)
            or self.allowance_atomic < 0
        ):
            raise SafeHaltError("Ink V0F allowance is not a non-negative uint256")
        if self.common_block < 0:
            raise SafeHaltError("Ink V0F allowance observation block is negative")
        if len(self.provider_heads) != 2 or len(self.provider_evidence) != 2:
            raise SafeHaltError("Ink V0F allowance observation requires exactly two providers")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "allowance_atomic": str(self.allowance_atomic),
            "common_block": self.common_block,
            "owner_address": self.owner_address,
            "provider_evidence": [dict(item) for item in self.provider_evidence],
            "provider_heads": dict(sorted(self.provider_heads.items())),
            "schema": self.schema,
            "spender_address": self.spender_address,
            "token_address": self.token_address,
        }

    @property
    def digest(self) -> str:
        return digest_object(self.canonical_object())


class InkV0FLiveVerifier:
    """Two-provider same-block verifier for the frozen Ink V0F router state."""

    def __init__(
        self,
        providers: tuple[JsonRpcClient, JsonRpcClient],
        router_identity: InkV0FRouterIdentityV0,
        *,
        max_head_lag_blocks: int = 12,
        max_observation_age_blocks: int = 12,
    ) -> None:
        if len(providers) != 2:
            raise SafeHaltError("Ink V0F live verifier requires exactly two RPC providers")
        if tuple(provider.endpoint for provider in providers) != INK_RPC_ENDPOINTS:
            raise SafeHaltError(
                "Ink V0F live verifier requires the canonical Ink RPC endpoints"
            )
        if type(router_identity) is not InkV0FRouterIdentityV0:
            raise AuthorityVerificationError("Ink V0F live verifier requires a verified router identity")
        if (
            isinstance(max_head_lag_blocks, bool)
            or not isinstance(max_head_lag_blocks, int)
            or max_head_lag_blocks < 0
        ):
            raise SafeHaltError("max_head_lag_blocks must be a non-negative int")
        if (
            isinstance(max_observation_age_blocks, bool)
            or not isinstance(max_observation_age_blocks, int)
            or max_observation_age_blocks < 0
        ):
            raise SafeHaltError("max_observation_age_blocks must be a non-negative int")
        self.providers = providers
        self.router_identity = router_identity
        self.max_head_lag_blocks = max_head_lag_blocks
        self.max_observation_age_blocks = max_observation_age_blocks

    def observe_market(self) -> InkMarketObservationV0:
        """Read the frozen pool from the canonical two providers."""

        adapter = InkShadowAdapter(
            self.providers,
            expected_bytecode_sha256=INKYSWAP_V2_BYTECODE_SHA256,
            max_head_lag_blocks=self.max_head_lag_blocks,
            max_observation_age_blocks=self.max_observation_age_blocks,
        )
        return adapter.observe()

    def _heads_for_market(self, market: InkMarketObservationV0) -> list[int]:
        if type(market) is not InkMarketObservationV0:
            raise AuthorityVerificationError(
                "Ink V0F live verification requires an Ink market observation"
            )
        endpoints = tuple(provider.endpoint for provider in self.providers)
        if set(endpoints) != set(market.provider_heads):
            raise SafeHaltError(
                "router verification providers differ from market-observation providers"
            )

        # The pool observation already sampled both provider heads immediately
        # before selecting its common block. Re-polling eth_blockNumber here
        # would create a second, racing freshness snapshot on a fast chain.
        heads = [int(market.provider_heads[endpoint]) for endpoint in endpoints]
        chain_ids: list[int] = []
        for provider in self.providers:
            try:
                chain_ids.append(provider.chain_id())
            except RpcError as exc:
                raise SafeHaltError(
                    f"router provider chain verification failed: {exc}"
                ) from exc
        if chain_ids != [INK_CHAIN_ID, INK_CHAIN_ID]:
            raise SafeHaltError(f"router provider chain id mismatch: {chain_ids}")
        if abs(heads[0] - heads[1]) > self.max_head_lag_blocks:
            raise SafeHaltError(f"router provider head lag exceeds bound: {heads}")
        if any(head < market.common_block for head in heads):
            raise SafeHaltError("market provider head is behind its common block")
        if any(
            head - market.common_block > self.max_observation_age_blocks
            for head in heads
        ):
            raise SafeHaltError("market common block is too old for router preflight")
        return heads

    def observe_router_for_market(
        self,
        market: InkMarketObservationV0,
    ) -> InkV0FRouterObservationV0:
        heads = self._heads_for_market(market)
        block_tag = "0x" + format(market.common_block, "x")
        facts: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        factory_data = "0x" + ROUTER_FACTORY_SELECTOR.hex()
        weth_data = "0x" + ROUTER_WETH_SELECTOR.hex()
        for provider in self.providers:
            try:
                code, code_raw = provider.get_code(self.router_identity.address, block_tag)
                factory_raw_bytes, factory_raw = provider.call(
                    self.router_identity.address, factory_data, block_tag
                )
                weth_raw_bytes, weth_raw = provider.call(
                    self.router_identity.address, weth_data, block_tag
                )
            except RpcError as exc:
                raise SafeHaltError(
                    f"router provider observation failed at block {market.common_block}: {exc}"
                ) from exc
            code_hash = hashlib.sha256(code).hexdigest()
            factory = _decode_address_word(factory_raw_bytes, field="router.factory")
            weth = _decode_address_word(weth_raw_bytes, field="router.WETH")
            fact = {
                "bytecode_length": len(code),
                "bytecode_sha256": code_hash,
                "factory_address": factory,
                "weth_address": weth,
            }
            if code_hash != self.router_identity.deployed_bytecode_sha256:
                raise SafeHaltError("router bytecode digest differs from the pinned identity")
            if len(code) != self.router_identity.deployed_bytecode_length:
                raise SafeHaltError("router bytecode length differs from the pinned identity")
            if factory != self.router_identity.factory_address:
                raise SafeHaltError("router factory() differs from the pinned identity")
            if weth != self.router_identity.weth_address:
                raise SafeHaltError("router WETH() differs from the pinned identity")
            facts.append(fact)
            evidence.append(
                {
                    "endpoint": provider.endpoint,
                    "fact": fact,
                    "rpc_evidence": {
                        "eth_call.factory": factory_raw,
                        "eth_call.WETH": weth_raw,
                        "eth_getCode.raw_result_sha256": hashlib.sha256(
                            code_raw.encode("ascii")
                        ).hexdigest(),
                    },
                }
            )
        if facts[0] != facts[1]:
            raise SafeHaltError("router providers disagree on deterministic router facts")
        fact = facts[0]
        return InkV0FRouterObservationV0(
            chain_id=INK_CHAIN_ID,
            router_address=self.router_identity.address,
            common_block=market.common_block,
            provider_heads={
                self.providers[0].endpoint: heads[0],
                self.providers[1].endpoint: heads[1],
            },
            bytecode_sha256=fact["bytecode_sha256"],
            bytecode_length=fact["bytecode_length"],
            factory_address=fact["factory_address"],
            weth_address=fact["weth_address"],
            provider_evidence=tuple(evidence),
        )

    def observe_allowance_for_market(
        self,
        market: InkMarketObservationV0,
        *,
        token_address: str,
    ) -> InkV0FAllowanceObservationV0:
        token = _address(token_address, field="allowance token")
        if token not in {WETH9_ADDRESS, KRAKMASK_ADDRESS}:
            raise SafeHaltError("allowance token is outside the frozen Ink V0F pair")
        heads = self._heads_for_market(market)
        block_tag = "0x" + format(market.common_block, "x")
        calldata = (
            "0x"
            + ERC20_ALLOWANCE_SELECTOR.hex()
            + _address_word(INK_V0F_TAKER_ADDRESS, field="allowance owner").hex()
            + _address_word(INK_V0F_ROUTER_ADDRESS, field="allowance spender").hex()
        )
        values: list[int] = []
        evidence: list[dict[str, Any]] = []
        for provider in self.providers:
            try:
                raw_bytes, raw = provider.call(token, calldata, block_tag)
            except RpcError as exc:
                raise SafeHaltError(
                    f"allowance provider observation failed at block {market.common_block}: {exc}"
                ) from exc
            allowance = _decode_uint_word(raw_bytes, field="erc20.allowance")
            values.append(allowance)
            evidence.append(
                {
                    "endpoint": provider.endpoint,
                    "allowance_atomic": str(allowance),
                    "rpc_evidence": {"eth_call.allowance": raw},
                }
            )
        if values[0] != values[1]:
            raise SafeHaltError("allowance providers disagree")
        return InkV0FAllowanceObservationV0(
            token_address=token,
            owner_address=INK_V0F_TAKER_ADDRESS,
            spender_address=INK_V0F_ROUTER_ADDRESS,
            allowance_atomic=values[0],
            common_block=market.common_block,
            provider_heads={
                self.providers[0].endpoint: heads[0],
                self.providers[1].endpoint: heads[1],
            },
            provider_evidence=tuple(evidence),
        )


@dataclass(frozen=True, slots=True)
class InkV0FLivePreviewV0:
    market_observation: InkMarketObservationV0
    quote: InkQuoteV0
    router_observation: InkV0FRouterObservationV0
    preview: InkV0FHumanSigningPreviewV0

    def __post_init__(self) -> None:
        if self.quote.observation_digest != self.market_observation.digest():
            raise SafeHaltError("Ink V0F live quote is not bound to its market observation")
        if self.router_observation.common_block != self.market_observation.common_block:
            raise SafeHaltError("Ink V0F live router observation is not on the market block")
        if self.preview.quote_observation_digest != self.market_observation.digest():
            raise SafeHaltError("Ink V0F live preview is not bound to the market observation")
        if self.preview.quote_common_block != self.market_observation.common_block:
            raise SafeHaltError("Ink V0F live preview is not on the market block")


def derive_live_ink_v0f_preview(
    *,
    live_verifier: InkV0FLiveVerifier,
    policy: InkV0FRiskPolicyV0,
    router_identity: InkV0FRouterIdentityV0,
    ledger: SpotLedger,
    intent: IntentV0,
    session: ExecutionSessionV0,
    account_nonce: int,
    gas_limit_ceiling: int,
    max_fee_per_gas_ceiling: int,
    max_priority_fee_per_gas_ceiling: int,
    constructed_at_epoch_s: int,
) -> InkV0FLivePreviewV0:
    """Re-read market/router truth and deterministically rebuild the preview."""

    if type(live_verifier) is not InkV0FLiveVerifier:
        raise AuthorityVerificationError("Ink V0F live preview requires the canonical live verifier")
    if live_verifier.router_identity != router_identity:
        raise AuthorityVerificationError("Ink V0F live verifier/router identity mismatch")
    market = live_verifier.observe_market()
    effective_impact_bps = min(
        policy.max_price_impact_bps,
        intent.bounds.max_price_impact_bps,
    )
    selected_input = InkShadowAdapter.impact_capped_input_atomic(
        market,
        intent.bounds.side,
        desired_input_atomic=intent.bounds.max_input_atomic,
        max_price_impact_bps=effective_impact_bps,
    )
    quote = InkShadowAdapter._quote(market, intent.bounds.side, selected_input)
    router_observation = live_verifier.observe_router_for_market(market)
    preview = build_ink_v0f_human_signing_preview(
        policy=policy,
        router=router_identity,
        observation=market,
        quote=quote,
        ledger=ledger,
        intent=intent,
        session=session,
        account_nonce=account_nonce,
        gas_limit_ceiling=gas_limit_ceiling,
        max_fee_per_gas_ceiling=max_fee_per_gas_ceiling,
        max_priority_fee_per_gas_ceiling=max_priority_fee_per_gas_ceiling,
        constructed_at_epoch_s=constructed_at_epoch_s,
    )
    return InkV0FLivePreviewV0(
        market_observation=market,
        quote=quote,
        router_observation=router_observation,
        preview=preview,
    )


def build_ink_v0f_execution_envelope(
    preview: InkV0FHumanSigningPreviewV0,
    router_observation: InkV0FRouterObservationV0,
    session: ExecutionSessionV0,
) -> ExecutionEnvelopeV0:
    if type(preview) is not InkV0FHumanSigningPreviewV0:
        raise AuthorityVerificationError("Ink V0F envelope requires a verified preview")
    if type(router_observation) is not InkV0FRouterObservationV0:
        raise AuthorityVerificationError("Ink V0F envelope requires a live router observation")
    if type(session) is not ExecutionSessionV0:
        raise AuthorityVerificationError("Ink V0F envelope requires an execution session")
    if router_observation.common_block != preview.quote_common_block:
        raise EnvelopeValidationError("router observation block differs from the quote block")
    if session.taker_address != INK_V0F_TAKER_ADDRESS:
        raise EnvelopeValidationError("Ink V0F envelope session names the wrong taker")
    if preview.signed_bytes_scope.session_id != session.session_id:
        raise EnvelopeValidationError("Ink V0F preview names another session")
    if preview.signed_bytes_scope.session_identity_digest != session.identity_digest:
        raise EnvelopeValidationError("Ink V0F preview session identity differs")
    if preview.signed_bytes_scope.authority_policy_digest != session.authority_policy_digest:
        raise EnvelopeValidationError("Ink V0F preview authority policy differs")

    if preview.side is Side.BUY:
        input_id, output_id = (
            "evm:57073:" + WETH9_ADDRESS,
            "evm:57073:" + KRAKMASK_ADDRESS,
        )
    else:
        input_id, output_id = (
            "evm:57073:" + KRAKMASK_ADDRESS,
            "evm:57073:" + WETH9_ADDRESS,
        )
    plan_id = digest_object(
        {
            "preview_digest": preview.preview_digest,
            "router_observation_digest": router_observation.digest,
            "schema": "qntyspot.ink_v0f.envelope_plan.v0",
        }
    )
    scope = preview.signed_bytes_scope
    return ExecutionEnvelopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=scope.economic_action_id,
        chain_id=INK_CHAIN_ID,
        taker_address=session.taker_address,
        input_instrument_id=input_id,
        output_instrument_id=output_id,
        max_input_atomic=preview.swap.amount_in_atomic,
        min_output_atomic=preview.swap.amount_out_min_atomic,
        transaction_to=INK_V0F_ROUTER_ADDRESS,
        transaction_value_atomic=0,
        calldata_sha256=sha256_hex(preview.swap.calldata),
        calldata_length=len(preview.swap.calldata),
        allowance_target=INK_V0F_ROUTER_ADDRESS,
        account_nonce=scope.account_nonce,
        gas_limit_ceiling=scope.gas_limit_ceiling,
        max_fee_per_gas_ceiling_atomic=scope.max_fee_per_gas_ceiling,
        max_priority_fee_per_gas_ceiling_atomic=scope.max_priority_fee_per_gas_ceiling,
        deadline_epoch_s=preview.swap.deadline_epoch_s,
        authority_policy_digest=session.authority_policy_digest,
        plan_id=plan_id,
        quote_id=INK_V0F_QUOTE_ID,
        quote_observation_digest=preview.quote_observation_digest,
        venue_block_number=preview.quote_common_block,
        constructed_at_epoch_s=preview.constructed_at_epoch_s,
    )


def assert_ink_v0f_execution_envelope_admissible(
    envelope: ExecutionEnvelopeV0,
    preview: InkV0FHumanSigningPreviewV0,
    router_observation: InkV0FRouterObservationV0,
    session: ExecutionSessionV0,
    *,
    now_epoch_s: int,
) -> None:
    if type(envelope) is not ExecutionEnvelopeV0:
        raise EnvelopeValidationError("Ink V0F envelope has the wrong type")
    if not isinstance(now_epoch_s, int) or isinstance(now_epoch_s, bool) or now_epoch_s < 0:
        raise EnvelopeValidationError("now_epoch_s must be a non-negative integer")
    expected = build_ink_v0f_execution_envelope(preview, router_observation, session)
    if envelope != expected:
        raise EnvelopeValidationError("Ink V0F envelope differs from the verified preview")
    if envelope.deadline_epoch_s <= now_epoch_s:
        raise EnvelopeValidationError("Ink V0F envelope deadline has already passed")


def build_ink_v0f_approval_action(
    preview: InkV0FHumanSigningPreviewV0,
    allowance_observation: InkV0FAllowanceObservationV0,
    session: ExecutionSessionV0,
) -> ApprovalActionV0:
    if type(preview) is not InkV0FHumanSigningPreviewV0:
        raise AuthorityVerificationError("Ink V0F approval requires a verified preview")
    if type(allowance_observation) is not InkV0FAllowanceObservationV0:
        raise AuthorityVerificationError("Ink V0F approval requires a live allowance observation")
    if allowance_observation.common_block != preview.quote_common_block:
        raise EnvelopeValidationError("allowance observation block differs from the quote block")
    if allowance_observation.token_address != preview.approval.token_address:
        raise EnvelopeValidationError("allowance observation token differs from the approval token")
    if allowance_observation.owner_address != session.taker_address:
        raise EnvelopeValidationError("allowance observation owner differs from the session taker")
    if allowance_observation.spender_address != preview.approval.spender_address:
        raise EnvelopeValidationError("allowance observation spender differs from the preview")
    if allowance_observation.allowance_atomic != 0:
        raise EnvelopeValidationError(
            "first-live Ink V0F requires zero prior allowance before exact approval"
        )
    return ApprovalActionV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        taker_address=session.taker_address,
        token_address=preview.approval.token_address,
        spender_address=preview.approval.spender_address,
        requested_allowance_atomic=preview.approval.amount_atomic,
        observed_prior_allowance_atomic=allowance_observation.allowance_atomic,
        authority_policy_digest=session.authority_policy_digest,
        deadline_epoch_s=preview.swap.deadline_epoch_s,
        economic_action_id=preview.signed_bytes_scope.economic_action_id,
    )


def assert_ink_v0f_approval_admissible(
    approval: ApprovalActionV0,
    preview: InkV0FHumanSigningPreviewV0,
    allowance_observation: InkV0FAllowanceObservationV0,
    session: ExecutionSessionV0,
    *,
    now_epoch_s: int,
) -> None:
    if type(approval) is not ApprovalActionV0:
        raise EnvelopeValidationError("Ink V0F approval has the wrong type")
    if not isinstance(now_epoch_s, int) or isinstance(now_epoch_s, bool) or now_epoch_s < 0:
        raise EnvelopeValidationError("now_epoch_s must be a non-negative integer")
    expected = build_ink_v0f_approval_action(preview, allowance_observation, session)
    if approval != expected:
        raise EnvelopeValidationError("Ink V0F approval differs from the verified preview")
    if approval.deadline_epoch_s <= now_epoch_s:
        raise EnvelopeValidationError("Ink V0F approval deadline has already passed")
