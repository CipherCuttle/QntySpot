"""Offline tests for the bounded Ink V0B substrate."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from conftest import base_policy_doc
from qntyspot.canon import canonical_json_bytes
from qntyspot.errors import (
    LevelNotExecutableError,
    RpcProtocolError,
    RpcResponseTooLargeError,
    RpcTimeoutError,
    SafeHaltError,
)
from qntyspot.domain import Side
from qntyspot.economics import build_intent
from qntyspot.ink import (
    INK_CHAIN_ID,
    INKYSWAP_V2_FACTORY,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    InkShadowAdapter,
    JsonRpcClient,
    load_decision,
    load_observation,
    persist_decision,
    persist_observation,
    replay_shadow_decision,
)
from qntyspot.policy import parse_policy


POOL = "0xed11ed4b195e84ba9b74c4d6ce13b7a43b354264"
CODE = bytes.fromhex("60016001556002600255")
CODE_HASH = hashlib.sha256(CODE).hexdigest()


def word(value: int) -> str:
    return value.to_bytes(32, "big").hex()


def address_word(address: str) -> str:
    return "0" * 24 + address[2:]


class FakeRpc:
    def __init__(
        self,
        *,
        chain_id: int = INK_CHAIN_ID,
        head: int = 100,
        code: bytes = CODE,
        token0: str = KRAKMASK_ADDRESS,
        token1: str = WETH9_ADDRESS,
        factory: str = INKYSWAP_V2_FACTORY,
        pair: str = POOL,
        reserve0: int = 1_000,
        reserve1: int = 1_000,
        reserve_timestamp: int = 77,
        malformed: bytes | None = None,
        response_id: int = 1,
    ) -> None:
        self.chain_id = chain_id
        self.head = head
        self.code = code
        self.token0 = token0
        self.token1 = token1
        self.factory = factory
        self.pair = pair
        self.reserve0 = reserve0
        self.reserve1 = reserve1
        self.reserve_timestamp = reserve_timestamp
        self.malformed = malformed
        self.response_id = response_id
        self.calls = 0

    def __call__(self, payload: bytes) -> bytes:
        self.calls += 1
        if self.malformed is not None:
            return self.malformed
        request = json.loads(payload)
        method = request["method"]
        params = request["params"]
        if method == "eth_chainId":
            result = hex(self.chain_id)
        elif method == "eth_blockNumber":
            result = hex(self.head)
        elif method == "eth_getCode":
            result = "0x" + self.code.hex()
        elif method == "eth_call":
            data = params[0]["data"]
            if data == "0x0dfe1681":
                result = "0x" + address_word(self.token0)
            elif data == "0xd21220a7":
                result = "0x" + address_word(self.token1)
            elif data == "0xc45a0155":
                result = "0x" + address_word(self.factory)
            elif data.startswith("0xe6a43905"):
                result = "0x" + address_word(self.pair)
            elif data == "0x0902f1ac":
                result = "0x" + word(self.reserve0) + word(self.reserve1) + word(self.reserve_timestamp)
            else:  # pragma: no cover - protects the fake from accidental API drift
                raise AssertionError(f"unexpected eth_call data {data}")
        else:  # pragma: no cover
            raise AssertionError(f"unexpected RPC method {method}")
        return canonical_json_bytes({"jsonrpc": "2.0", "id": self.response_id, "result": result})


def adapter_pair(*, first: FakeRpc | None = None, second: FakeRpc | None = None, **kwargs: object):
    left = first or FakeRpc(**kwargs)
    right = second or FakeRpc(**kwargs)
    adapter = InkShadowAdapter(
        (
            JsonRpcClient("https://rpc-a.invalid", transport=left),
            JsonRpcClient("https://rpc-b.invalid", transport=right),
        ),
        expected_bytecode_sha256=CODE_HASH,
    )
    return adapter


def policy_for_fixture(*, max_impact: int = 10_000):
    doc = base_policy_doc()
    doc["base"]["ref"]["contract_address"] = KRAKMASK_ADDRESS
    doc["base"]["decimals"] = 18
    doc["quote"]["ref"]["contract_address"] = WETH9_ADDRESS
    doc["quote"]["decimals"] = 18
    doc["entry_ladder"]["levels"] = [
        {"level_id": "E1", "trigger_price": "2", "input_amount": "0.000000000000000002"}
    ]
    doc["exit_ladder"]["levels"] = [
        {"level_id": "X1", "trigger_price": "1", "input_ratio": "1"}
    ]
    doc["capital"].update(
        allocation_quote="100",
        per_order_cap_quote="100",
        per_instrument_cap_quote="100",
        per_network_cap_quote="100",
        global_portfolio_cap_quote="100",
    )
    doc["limits"].update(
        max_executable_price="2",
        min_executable_price="1",
        max_price_impact_bps=max_impact,
        max_slippage_bps=0,
    )
    return parse_policy(doc)


def observed_adapter(**kwargs: object):
    adapter = adapter_pair(**kwargs)
    return adapter, adapter.observe()


def test_wrong_chain_fails_closed() -> None:
    adapter = adapter_pair(first=FakeRpc(chain_id=1), second=FakeRpc(chain_id=1))
    with pytest.raises(SafeHaltError, match="chain id"):
        adapter.observe()


def test_malformed_json_rpc_is_rejected() -> None:
    client = JsonRpcClient("https://rpc.invalid", transport=lambda _payload: b"{")
    with pytest.raises(RpcProtocolError, match="strict JSON"):
        client.request("eth_chainId", [])


def test_json_rpc_unknown_fields_are_rejected() -> None:
    payload = canonical_json_bytes(
        {"jsonrpc": "2.0", "id": 1, "result": "0xdef1", "extra": True}
    )
    client = JsonRpcClient("https://rpc.invalid", transport=lambda _payload: payload)
    with pytest.raises(RpcProtocolError, match="unknown"):
        client.request("eth_chainId", [])


def test_mismatched_response_id_is_rejected() -> None:
    fake = FakeRpc(response_id=2)
    client = JsonRpcClient("https://rpc.invalid", transport=fake)
    with pytest.raises(RpcProtocolError, match="mismatch"):
        client.request("eth_chainId", [])


def test_timeout_has_a_finite_retry_bound() -> None:
    calls = 0

    def timeout(_payload: bytes) -> bytes:
        nonlocal calls
        calls += 1
        raise RpcTimeoutError("test timeout")

    client = JsonRpcClient("https://rpc.invalid", max_retries=2, transport=timeout)
    with pytest.raises(RpcTimeoutError):
        client.request("eth_chainId", [])
    assert calls == 3


def test_plain_timeout_from_transport_is_retried_and_bounded() -> None:
    calls = 0

    def timeout(_payload: bytes) -> bytes:
        nonlocal calls
        calls += 1
        raise TimeoutError("test timeout")

    client = JsonRpcClient("https://rpc.invalid", max_retries=1, transport=timeout)
    with pytest.raises(RpcTimeoutError):
        client.request("eth_chainId", [])
    assert calls == 2


def test_oversize_response_is_rejected() -> None:
    client = JsonRpcClient(
        "https://rpc.invalid",
        max_response_bytes=256,
        transport=lambda _payload: b"x" * 257,
    )
    with pytest.raises(RpcResponseTooLargeError):
        client.request("eth_chainId", [])


def test_provider_disagreement_is_safe_halt() -> None:
    adapter = adapter_pair(second=FakeRpc(reserve1=999))
    with pytest.raises(SafeHaltError, match="disagree"):
        adapter.observe()


def test_head_lag_is_safe_halt() -> None:
    adapter = adapter_pair(first=FakeRpc(head=200), second=FakeRpc(head=100))
    with pytest.raises(SafeHaltError, match="head lag"):
        adapter.observe()


def test_exact_common_block_is_used_for_all_facts() -> None:
    adapter, observation = observed_adapter(first=FakeRpc(head=105), second=FakeRpc(head=100))
    assert observation.common_block == 100
    assert all(item["facts"]["common_block"] == 100 for item in observation.provider_evidence)
    assert observation.digest() == observation.digest()
    assert adapter._observation is observation


def test_absent_pool_bytecode_is_rejected() -> None:
    empty_hash = hashlib.sha256(b"").hexdigest()
    adapter = InkShadowAdapter(
        (
            JsonRpcClient("https://rpc-a.invalid", transport=FakeRpc(code=b"")),
            JsonRpcClient("https://rpc-b.invalid", transport=FakeRpc(code=b"")),
        ),
        expected_bytecode_sha256=empty_hash,
    )
    with pytest.raises(SafeHaltError, match="absent"):
        adapter.observe()


def test_wrong_token_pair_is_rejected() -> None:
    adapter = adapter_pair(first=FakeRpc(token0=WETH9_ADDRESS), second=FakeRpc(token0=WETH9_ADDRESS))
    with pytest.raises(SafeHaltError, match="token pair"):
        adapter.observe()


def test_zero_reserves_are_rejected() -> None:
    adapter = adapter_pair(first=FakeRpc(reserve0=0), second=FakeRpc(reserve0=0))
    with pytest.raises(SafeHaltError, match="non-zero"):
        adapter.observe()


def test_v2_uint112_reserve_bound_is_rejected() -> None:
    too_large = 1 << 112
    adapter = adapter_pair(first=FakeRpc(reserve0=too_large), second=FakeRpc(reserve0=too_large))
    with pytest.raises(SafeHaltError, match="uint112"):
        adapter.observe()


def test_v2_quote_uses_integer_floor_and_fee() -> None:
    adapter, observation = observed_adapter()
    quote = adapter._quote(observation, side=Side.BUY, input_atomic=2)
    assert quote.output_atomic == 1
    assert quote.fee_atomic == Fraction(3, 500)
    assert quote.average_price == Fraction(2, 1)
    assert quote.spot_price == Fraction(1, 1)


def test_policy_limit_exactly_at_limit_would_execute() -> None:
    adapter, observation = observed_adapter()
    policy = policy_for_fixture(max_impact=10_000)
    decision = adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=1_700_000_100, observation=observation)
    assert decision.decision == "WOULD_EXECUTE"
    assert decision.reason_code == "PASS"


def test_one_unit_outside_impact_limit_abstains() -> None:
    adapter, observation = observed_adapter()
    policy = policy_for_fixture(max_impact=9_999)
    decision = adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=1_700_000_100, observation=observation)
    assert decision.decision == "ABSTAIN"
    assert "MAX_PRICE_IMPACT" in decision.reason_code


def test_policy_for_a_different_asset_is_not_admitted_to_the_adapter() -> None:
    adapter, observation = observed_adapter()
    policy = policy_for_fixture()
    doc = base_policy_doc()
    doc["base"]["ref"]["contract_address"] = "0xc0ffee0000000000000000000000000000000001"
    doc["base"]["decimals"] = 18
    doc["quote"]["ref"]["contract_address"] = WETH9_ADDRESS
    doc["quote"]["decimals"] = 18
    doc["entry_ladder"]["levels"] = [{"level_id": "E1", "trigger_price": "2", "input_amount": "0.000000000000000002"}]
    doc["exit_ladder"]["levels"] = [{"level_id": "X1", "trigger_price": "1", "input_ratio": "1"}]
    doc["limits"].update(max_executable_price="2", min_executable_price="1", max_price_impact_bps=10_000, max_slippage_bps=0)
    different = parse_policy(doc)
    with pytest.raises(SafeHaltError, match="pinned"):
        adapter.shadow_decision(different, "cycle-0", "E1", now_epoch_s=1_700_000_100, observation=observation)


def test_stale_observation_abstains_without_requoting() -> None:
    adapter, observation = observed_adapter()
    policy = policy_for_fixture()
    decision = adapter.shadow_decision(
        policy,
        "cycle-0",
        "E1",
        now_epoch_s=1_700_000_100,
        observation=observation,
        current_common_block=observation.common_block + 13,
    )
    assert decision.decision == "ABSTAIN"
    assert "STALE_OBSERVATION" in decision.reason_code


def test_digest_and_offline_replay_are_byte_deterministic(tmp_path: Path) -> None:
    adapter, observation = observed_adapter()
    policy = policy_for_fixture()
    decision = adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=1_700_000_100, observation=observation)
    replayed = replay_shadow_decision(policy, observation, "cycle-0", "E1", now_epoch_s=1_700_000_100)
    assert decision.canonical_object() == replayed.canonical_object()
    assert decision.digest() == replayed.digest()
    observation_path = tmp_path / "observation.json"
    decision_path = tmp_path / "decision.json"
    assert persist_observation(observation_path, observation) == observation.digest()
    assert persist_decision(decision_path, decision) == decision.digest()
    assert load_observation(observation_path).digest() == observation.digest()
    assert load_decision(decision_path).digest() == decision.digest()
    assert observation_path.read_bytes() == observation_path.read_bytes()


def test_immutable_persistence_refuses_replacement(tmp_path: Path) -> None:
    adapter, observation = observed_adapter()
    path = tmp_path / "observation.json"
    persist_observation(path, observation)
    path.write_bytes(b"tampered")
    with pytest.raises(SafeHaltError, match="different data"):
        persist_observation(path, observation)


def test_quote_source_rejects_output_outside_absolute_bound() -> None:
    adapter, observation = observed_adapter()
    adapter._observation = observation
    policy = policy_for_fixture()
    intent = build_intent(policy, "cycle-0", policy.level("E1"), now_epoch_s=1_700_000_100)
    too_strict = replace(intent.bounds, min_output_atomic=2)
    with pytest.raises(LevelNotExecutableError, match="output bound"):
        adapter.quote(too_strict, now_epoch_s=1_700_000_100)
