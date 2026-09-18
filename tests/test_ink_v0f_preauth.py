from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from qntyspot.canon import canonical_json_bytes
from qntyspot.errors import EnvelopeValidationError, SafeHaltError
from qntyspot.exact_signed_bytes import ExactSignedBytesScopeV0
from qntyspot.execution_contract import (
    LADDER,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    AuthorityLevel,
    Capability,
    ExecutionSessionV0,
)
from qntyspot.ledger import ExecutionRuntime
from qntyspot.ink import (
    INK_CHAIN_ID,
    INKYSWAP_V2_FACTORY,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    V2_FEE_DENOMINATOR,
    V2_FEE_NUMERATOR,
    WETH9_ADDRESS,
    InkMarketObservationV0,
    JsonRpcClient,
)
from qntyspot.ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    InkV0FApprovalCallV0,
    InkV0FHumanSigningPreviewV0,
    InkV0FRouterIdentityV0,
    InkV0FSwapCallV0,
    encode_approve,
    encode_swap_exact_tokens_for_tokens,
)
from qntyspot.ink_v0f_preauth import (
    ERC20_ALLOWANCE_SELECTOR,
    ROUTER_FACTORY_SELECTOR,
    ROUTER_WETH_SELECTOR,
    InkV0FLiveVerifier,
    assert_ink_v0f_approval_admissible,
    assert_ink_v0f_execution_envelope_admissible,
    build_ink_v0f_approval_action,
    build_ink_v0f_execution_envelope,
)
from qntyspot.keccak import keccak256
from qntyspot.domain import Side


FAKE_CODE = bytes.fromhex("60016000556002600055")
FAKE_CODE_HASH = hashlib.sha256(FAKE_CODE).hexdigest()
FAKE_CODE_LENGTH = len(FAKE_CODE)


def word(value: int) -> str:
    return value.to_bytes(32, "big").hex()


def address_word(address: str) -> str:
    return "0" * 24 + address[2:]


def fake_router_identity() -> InkV0FRouterIdentityV0:
    identity = object.__new__(InkV0FRouterIdentityV0)
    object.__setattr__(identity, "address", INK_V0F_ROUTER_ADDRESS)
    object.__setattr__(identity, "chain_id", INK_CHAIN_ID)
    object.__setattr__(identity, "contract_name", "UniswapV2Router02")
    object.__setattr__(identity, "deployed_bytecode_length", FAKE_CODE_LENGTH)
    object.__setattr__(identity, "deployed_bytecode_sha256", FAKE_CODE_HASH)
    object.__setattr__(identity, "factory_address", INKYSWAP_V2_FACTORY)
    object.__setattr__(identity, "weth_address", WETH9_ADDRESS)
    object.__setattr__(identity, "artifact_digest", "00" * 32)
    return identity


class FakeRpc:
    def __init__(
        self,
        *,
        head: int = 105,
        factory: str = INKYSWAP_V2_FACTORY,
        weth: str = WETH9_ADDRESS,
        allowance: int = 0,
        code: bytes = FAKE_CODE,
    ) -> None:
        self.head = head
        self.factory = factory
        self.weth = weth
        self.allowance = allowance
        self.code = code
        self.block_tags: list[str] = []

    def __call__(self, payload: bytes) -> bytes:
        request = json.loads(payload)
        method = request["method"]
        params = request["params"]
        if method == "eth_chainId":
            result = hex(INK_CHAIN_ID)
        elif method == "eth_blockNumber":
            result = hex(self.head)
        elif method == "eth_getCode":
            self.block_tags.append(params[1])
            result = "0x" + self.code.hex()
        elif method == "eth_call":
            self.block_tags.append(params[1])
            data = params[0]["data"]
            if data == "0x" + ROUTER_FACTORY_SELECTOR.hex():
                result = "0x" + address_word(self.factory)
            elif data == "0x" + ROUTER_WETH_SELECTOR.hex():
                result = "0x" + address_word(self.weth)
            elif data.startswith("0x" + ERC20_ALLOWANCE_SELECTOR.hex()):
                result = "0x" + word(self.allowance)
            else:
                raise AssertionError(f"unexpected eth_call data {data}")
        else:
            raise AssertionError(f"unexpected method {method}")
        return canonical_json_bytes({"jsonrpc": "2.0", "id": 1, "result": result})


def market_observation() -> InkMarketObservationV0:
    return InkMarketObservationV0(
        schema="INK_MARKET_OBSERVATION_V0",
        chain_id=INK_CHAIN_ID,
        pool_address=INKYSWAP_V2_POOL,
        factory_address=INKYSWAP_V2_FACTORY,
        token0=KRAKMASK_ADDRESS,
        token1=WETH9_ADDRESS,
        common_block=100,
        provider_heads={"https://rpc-a.invalid": 105, "https://rpc-b.invalid": 104},
        bytecode_present=True,
        bytecode_sha256="11" * 32,
        bytecode_length=1,
        reserve0_atomic=10**21,
        reserve1_atomic=10**21,
        reserve_timestamp=1,
        provider_evidence=({}, {}),
        v2_fee_numerator=V2_FEE_NUMERATOR,
        v2_fee_denominator=V2_FEE_DENOMINATOR,
    )


def verifier(*, first: FakeRpc | None = None, second: FakeRpc | None = None):
    a = first or FakeRpc(head=105)
    b = second or FakeRpc(head=104)
    return InkV0FLiveVerifier(
        (
            JsonRpcClient("https://rpc-a.invalid", transport=a),
            JsonRpcClient("https://rpc-b.invalid", transport=b),
        ),
        fake_router_identity(),
    ), a, b


def session() -> ExecutionSessionV0:
    return ExecutionSessionV0(
        repository_commit="11" * 20,
        implementation_digest="22" * 32,
        runtime_identity="cpython-3.11",
        db_schema_version=1,
        policy_id="33" * 32,
        authority_policy_digest="44" * 32,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id="evm:57073",
        venue_id="inkyswap-v2-ink-mainnet",
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=1_800_000_000,
        session_ordinal=0,
    )


def preview() -> InkV0FHumanSigningPreviewV0:
    sess = session()
    approval = InkV0FApprovalCallV0(
        token_address=WETH9_ADDRESS,
        spender_address=INK_V0F_ROUTER_ADDRESS,
        amount_atomic=10**15,
        calldata=encode_approve(INK_V0F_ROUTER_ADDRESS, 10**15),
    )
    swap_data = encode_swap_exact_tokens_for_tokens(
        amount_in_atomic=10**15,
        amount_out_min_atomic=900_000_000_000_000,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=1_800_000_600,
    )
    swap = InkV0FSwapCallV0(
        amount_in_atomic=10**15,
        amount_out_min_atomic=900_000_000_000_000,
        path=(WETH9_ADDRESS, KRAKMASK_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=1_800_000_600,
        calldata=swap_data,
    )
    scope = ExactSignedBytesScopeV0(
        session_id=sess.session_id,
        session_identity_digest=sess.identity_digest,
        economic_action_id="55" * 32,
        authority_policy_digest=sess.authority_policy_digest,
        chain_id=INK_CHAIN_ID,
        taker_address=INK_V0F_TAKER_ADDRESS,
        target_address=INK_V0F_ROUTER_ADDRESS,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=hashlib.sha256(swap_data).hexdigest(),
        calldata_length=len(swap_data),
        account_nonce=7,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling=2_000_000_000,
        max_priority_fee_per_gas_ceiling=100_000_000,
    )
    return InkV0FHumanSigningPreviewV0(
        side=Side.BUY,
        router_address=INK_V0F_ROUTER_ADDRESS,
        quote_observation_digest="66" * 32,
        quote_common_block=100,
        quoted_output_atomic=10**15,
        approval=approval,
        swap=swap,
        signed_bytes_scope=scope,
        constructed_at_epoch_s=1_800_000_001,
    )


def test_selectors_are_exact() -> None:
    assert ROUTER_FACTORY_SELECTOR == keccak256(b"factory()")[:4]
    assert ROUTER_WETH_SELECTOR == keccak256(b"WETH()")[:4]
    assert ERC20_ALLOWANCE_SELECTOR == keccak256(b"allowance(address,address)")[:4]


def test_router_and_allowance_are_verified_at_market_common_block() -> None:
    live, left, right = verifier()
    market = market_observation()
    router_observation = live.observe_router_for_market(market)
    allowance = live.observe_allowance_for_market(market, token_address=WETH9_ADDRESS)
    assert router_observation.common_block == market.common_block == 100
    assert router_observation.factory_address == INKYSWAP_V2_FACTORY
    assert router_observation.weth_address == WETH9_ADDRESS
    assert allowance.allowance_atomic == 0
    assert all(tag == "0x64" for tag in left.block_tags + right.block_tags)


def test_router_bytecode_or_provider_disagreement_fails_closed() -> None:
    bad = FakeRpc(code=b"\x60\x00")
    live, _, _ = verifier(second=bad)
    with pytest.raises(SafeHaltError, match="bytecode"):
        live.observe_router_for_market(market_observation())

    live, _, _ = verifier(second=FakeRpc(allowance=1))
    with pytest.raises(SafeHaltError, match="disagree"):
        live.observe_allowance_for_market(market_observation(), token_address=WETH9_ADDRESS)


def test_stale_market_block_fails_closed() -> None:
    live, _, _ = verifier(first=FakeRpc(head=200), second=FakeRpc(head=199))
    market = replace(
        market_observation(),
        provider_heads={"https://rpc-a.invalid": 200, "https://rpc-b.invalid": 199},
    )
    with pytest.raises(SafeHaltError, match="too old"):
        live.observe_router_for_market(market)


def test_envelope_is_exactly_derived_from_preview_and_router_observation() -> None:
    live, _, _ = verifier()
    p = preview()
    ro = live.observe_router_for_market(market_observation())
    env = build_ink_v0f_execution_envelope(p, ro, session())
    assert env.economic_action_id == p.signed_bytes_scope.economic_action_id
    assert env.transaction_to == INK_V0F_ROUTER_ADDRESS
    assert env.calldata_sha256 == hashlib.sha256(p.swap.calldata).hexdigest()
    assert env.venue_block_number == 100
    assert env.max_input_atomic == p.swap.amount_in_atomic
    assert env.min_output_atomic == p.swap.amount_out_min_atomic
    assert_ink_v0f_execution_envelope_admissible(
        env, p, ro, session(), now_epoch_s=1_800_000_100
    )
    with pytest.raises(EnvelopeValidationError, match="differs"):
        assert_ink_v0f_execution_envelope_admissible(
            replace(env, transaction_value_atomic=1),
            p,
            ro,
            session(),
            now_epoch_s=1_800_000_100,
        )


def test_approval_requires_same_block_zero_prior_allowance_and_exact_amount() -> None:
    live, _, _ = verifier()
    p = preview()
    allowance = live.observe_allowance_for_market(
        market_observation(), token_address=WETH9_ADDRESS
    )
    approval = build_ink_v0f_approval_action(p, allowance, session())
    assert approval.requested_allowance_atomic == p.approval.amount_atomic
    assert approval.observed_prior_allowance_atomic == 0
    assert approval.spender_address == INK_V0F_ROUTER_ADDRESS
    assert_ink_v0f_approval_admissible(
        approval, p, allowance, session(), now_epoch_s=1_800_000_100
    )

    nonzero = replace(allowance, allowance_atomic=1)
    with pytest.raises(EnvelopeValidationError, match="zero prior allowance"):
        build_ink_v0f_approval_action(p, nonzero, session())


def test_preauth_runtime_methods_remain_dormant_at_level_one() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.RECONCILE_ONLY
    assert Capability.CONSTRUCT_ENVELOPE not in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.AUTHORIZE_APPROVAL not in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert hasattr(ExecutionRuntime, "record_ink_v0f_execution_envelope")
    assert hasattr(ExecutionRuntime, "record_ink_v0f_approval_action")
