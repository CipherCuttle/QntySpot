"""Offline V0D qualification and hostile checks for the Robinhood adapter."""

from __future__ import annotations

import io
import json
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest

from qntyspot.canon import canonical_json_bytes
from qntyspot.errors import RobinhoodProtocolError, RobinhoodTransportError, SafeHaltError
from qntyspot.policy import parse_policy
from qntyspot.raw_evidence import RawEvidenceStore
from qntyspot.robinhood import (
    CHAINLINK_ROBINHOOD_FEED_DIRECTORY_ENDPOINT,
    QUALIFICATION_TAKER_ADDRESS,
    MAX_RPC_FUTURE_SKEW_S,
    ROBINHOOD_ASSETS_ENDPOINT,
    ROBINHOOD_PRICES_ENDPOINT,
    ROBINHOOD_RPC_ENDPOINT,
    SPY_SYMBOL,
    USDG_ADDRESS,
    ZEROX_SWAP_V2_QUOTE_ENDPOINT,
    ChainlinkRobinhoodDirectoryClient,
    RobinhoodRestClient,
    RobinhoodRpcClient,
    RobinhoodShadowAdapter,
    ZeroXV2Client,
    load_decision,
    load_observation,
    persist_decision,
    persist_identity,
    persist_observation,
    replay_shadow_decision,
)
from qntyspot.domain import Side

NOW = 1_800_000_000
TOKEN = "0x117cc2133c37b721f49de2a7a74833232b3b4c0c"
UID = "0x" + "12" * 32
FEED = "0x" + "34" * 20
ALLOWANCE = "0x0000000000001ff3684f28c67538d4d072c22734"
SETTLER = "0x" + "56" * 20


def word(value: int) -> str:
    return value.to_bytes(32, "big").hex()


def latest_round(answer: int, *, updated_at: int = NOW - 20) -> str:
    return "0x" + "".join((word(7), word(answer), word(0), word(updated_at), word(7)))


def robinhood_policy() -> Any:
    from conftest import base_policy_doc

    doc = base_policy_doc()
    doc["base"]["ref"] = {"namespace": "evm", "chain_id": 4663, "contract_address": TOKEN}
    doc["quote"]["ref"] = {"namespace": "evm", "chain_id": 4663, "contract_address": USDG_ADDRESS}
    doc["base"]["display_symbol"] = SPY_SYMBOL
    doc["base"]["decimals"] = 18
    doc["quote"]["decimals"] = 6
    doc["limits"].update({"max_executable_price": "200", "min_executable_price": "1"})
    doc["timing"]["expiry_epoch_s"] = 1_900_000_000
    doc["entry_ladder"]["levels"][0]["trigger_price"] = "200"
    doc["entry_ladder"]["levels"][1]["trigger_price"] = "100"
    return parse_policy(doc)


def asset_body(**changes: Any) -> bytes:
    item = {
        "id": UID,
        "tokenSymbol": SPY_SYMBOL,
        "tokenName": "SPDR S&P 500 ETF Trust • Robinhood Token",
        "deployments": [{"contractAddress": TOKEN, "chainId": 4663}],
        "currentMultiplier": "1.5",
        "pendingMultiplier": "",
        "tradingCapabilities": {
            "fractionalTradability": "tradable",
            "allDayTradability": "tradable",
            "extendedHoursFractionalTradability": True,
        },
        "status": "ASSET_STATUS_ACTIVE",
        "tokenDecimals": 18,
    }
    item.update(changes)
    return canonical_json_bytes({"assets": [item]})


def price_body(**changes: Any) -> bytes:
    item = {
        "tokenSymbol": SPY_SYMBOL,
        "deployments": [{"contractAddress": TOKEN, "chainId": 4663}],
        "bid": "100",
        "ask": "100",
        "currency": "USD",
        "isTradingHalt": False,
        "generatedAt": "2027-01-15T08:00:00Z",
    }
    item.update(changes)
    return canonical_json_bytes({"quotes": [item]})


def directory_body() -> bytes:
    return canonical_json_bytes(
        [
            {
                "contractAddress": FEED,
                "contractVersion": 6,
                "heartbeat": 3600,
                "name": "Robinhood SPY / USD",
                "path": "SPY / USD",
                "proxyAddress": FEED,
                "decimals": 8,
                "docs": {},
            }
        ]
    )


def zero_body(*, sell_token: str = USDG_ADDRESS, buy_token: str = TOKEN, sell_amount: int = 100_000_000, buy_amount: int = 666_666_666_666_666_666, min_buy: int = 660_000_000_000_000_000) -> bytes:
    body = {
        "allowanceTarget": ALLOWANCE,
        "blockNumber": "300",
        "buyAmount": str(buy_amount),
        "buyToken": buy_token,
        "fees": {"integratorFee": None, "zeroExFee": None, "gasFee": None},
        "issues": {"allowance": {"actual": "0", "spender": ALLOWANCE}, "balance": None, "simulationIncomplete": False, "invalidSourcesPassed": []},
        "liquidityAvailable": True,
        "minBuyAmount": str(min_buy),
        "route": {
            "fills": [{"from": sell_token, "to": buy_token, "source": "Robinhood_RFQ", "proportionBps": "10000"}],
            "tokens": [{"address": sell_token, "symbol": "USDG"}, {"address": buy_token, "symbol": "SPY"}],
        },
        "sellAmount": str(sell_amount),
        "sellToken": sell_token,
        "tokenMetadata": {"buyToken": {"buyTaxBps": "0", "sellTaxBps": "0"}, "sellToken": {"buyTaxBps": "0", "sellTaxBps": "0"}},
        "totalNetworkFee": "0",
        "transaction": {"to": SETTLER, "data": "0x1234", "gas": "100000", "gasPrice": "1", "value": "0"},
        "zid": "0x" + "ab" * 12,
    }
    return canonical_json_bytes(body)


class RpcFixture:
    def __init__(self, *, wrong_chain: bool = False, paused: bool = False, feed_answer: int = 15_000_000_000, block_timestamp: int | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.wrong_chain = wrong_chain
        self.paused = paused
        self.feed_answer = feed_answer
        self.block_timestamp = NOW - 1 if block_timestamp is None else block_timestamp

    def __call__(self, payload: bytes) -> bytes:
        request = json.loads(payload)
        self.calls.append(request)
        method = request["method"]
        if method == "eth_chainId":
            result: Any = "0x1238" if self.wrong_chain else "0x1237"
        elif method == "eth_getCode":
            result = "0x6001"
        elif method == "eth_getBlockByNumber":
            result = {"number": "0x100", "timestamp": hex(self.block_timestamp)}
        else:
            selector = request["params"][0]["data"]
            if selector == "0x313ce567":
                to = request["params"][0]["to"].lower()
                result = "0x" + word(6 if to == USDG_ADDRESS else 8 if to == FEED else 18)
            elif selector == "0xf514ce36":
                result = "0x" + UID[2:]
            elif selector in {"0xa60bf13d", "0xdc767007"}:
                result = "0x" + word(1_500_000_000_000_000_000)
            elif selector == "0x97a4064f":
                result = "0x" + word(0)
            elif selector == "0x7706ba52":
                result = "0x" + word(int(self.paused))
            elif selector == "0xfeaf968c":
                result = latest_round(self.feed_answer)
            else:  # pragma: no cover - defensive fixture failure
                raise AssertionError(selector)
        return canonical_json_bytes({"id": 1, "jsonrpc": "2.0", "result": result})


def http_transport_factory(zero_quote: bytes | None = None, *, asset: bytes | None = None, price: bytes | None = None):
    def transport(target: str, _query: bytes, _headers: dict[str, str]) -> bytes:
        if target.startswith(ROBINHOOD_ASSETS_ENDPOINT):
            return asset or asset_body()
        if target.startswith(ROBINHOOD_PRICES_ENDPOINT.replace("{symbol}", SPY_SYMBOL) + "?"):
            return price or price_body()
        if target.startswith(CHAINLINK_ROBINHOOD_FEED_DIRECTORY_ENDPOINT):
            return directory_body()
        if target.startswith(ZEROX_SWAP_V2_QUOTE_ENDPOINT):
            assert zero_quote is not None
            return zero_quote
        raise AssertionError(target)

    return transport


def make_adapter(tmp_path: Path, **kwargs: Any) -> tuple[RobinhoodShadowAdapter, Any, RpcFixture, RawEvidenceStore]:
    store = RawEvidenceStore(tmp_path / "raw", max_total_bytes=2_000_000, max_records=32)
    rpc_transport = RpcFixture(**kwargs.pop("rpc", {}))
    http_kwargs = kwargs.pop("http", {})
    http_kwargs.setdefault("zero_quote", zero_body())
    transport = http_transport_factory(**http_kwargs)
    rest = RobinhoodRestClient(evidence_store=store, transport=transport)
    rpc = RobinhoodRpcClient(evidence_store=store, transport=rpc_transport)
    directory = ChainlinkRobinhoodDirectoryClient(evidence_store=store, transport=transport)
    zero = ZeroXV2Client(api_key="fixture-key", evidence_store=store, transport=transport)
    adapter = RobinhoodShadowAdapter(rest, rpc, directory, zero, symbol=SPY_SYMBOL)
    return adapter, robinhood_policy(), rpc_transport, store


def test_offline_full_observation_and_two_replays_are_identical(tmp_path: Path) -> None:
    adapter, policy, _rpc, store = make_adapter(tmp_path)
    observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    decision = adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=NOW)
    assert observation.sequencer_status == "UNAVAILABLE_NOT_PUBLISHED"
    assert observation.rest_raw_bid == 100
    assert observation.token_reference_bid == 150
    assert observation.chainlink_price == 150
    assert observation.ui_multiplier == 1.5
    assert observation.rpc_block_timestamp_epoch_s == NOW - 1
    assert observation.rpc_future_skew_s == -1
    assert observation.max_rpc_future_skew_s == MAX_RPC_FUTURE_SKEW_S
    assert observation.share_equivalent_amount == observation.raw_token_amount * 3 // 2
    assert decision.decision == "WOULD_EXECUTE"
    assert decision.side is Side.BUY
    first = replay_shadow_decision(policy, observation, "cycle-0", "E1")
    second = replay_shadow_decision(policy, observation, "cycle-0", "E1", now_epoch_s=NOW)
    assert first.canonical_object() == second.canonical_object() == decision.canonical_object()
    assert first.digest() == second.digest() == decision.digest()
    assert len(adapter.rest.evidence_records) >= 1


@pytest.mark.parametrize("skew", [-1, 0, 1, 29, 30])
def test_rpc_future_skew_boundary_is_accepted(tmp_path: Path, skew: int) -> None:
    adapter, policy, _rpc, _store = make_adapter(tmp_path, rpc={"block_timestamp": NOW + skew})
    observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    assert observation.rpc_future_skew_s == skew
    assert observation.rpc_block_timestamp_epoch_s == NOW + skew


def test_rpc_future_skew_over_bound_safe_halts_before_0x(tmp_path: Path) -> None:
    adapter, policy, rpc, _store = make_adapter(tmp_path, rpc={"block_timestamp": NOW + MAX_RPC_FUTURE_SKEW_S + 1})
    with pytest.raises(SafeHaltError, match="bounded future skew"):
        adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    assert not any(request["method"] == "eth_call" and request["params"][0].get("data") == "0xfeaf968c" for request in rpc.calls)


def test_skew_fields_are_canonical_and_replay_uses_frozen_timestamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, policy, _rpc, _store = make_adapter(tmp_path, rpc={"block_timestamp": NOW + 30})
    observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    canonical = observation.canonical_object()
    assert canonical["observation_time_epoch_s"] == NOW
    assert canonical["rpc_block_timestamp_epoch_s"] == NOW + 30
    assert canonical["rpc_future_skew_s"] == 30
    assert canonical["max_rpc_future_skew_s"] == MAX_RPC_FUTURE_SKEW_S
    observation_path = tmp_path / "ROBINHOOD_MARKET_OBSERVATION_V0.json"
    persist_observation(observation_path, observation)
    assert canonical_json_bytes(canonical) == canonical_json_bytes(load_observation(observation_path).canonical_object())

    import time

    monkeypatch.setattr(time, "time", lambda: pytest.fail("replay read the wall clock"))
    monkeypatch.setattr(time, "time_ns", lambda: pytest.fail("replay read the wall clock"))
    replayed = replay_shadow_decision(policy, observation, "cycle-0", "E1")
    assert replayed.decision == "WOULD_EXECUTE"
    with pytest.raises(SafeHaltError, match="frozen observation timestamp"):
        replay_shadow_decision(policy, observation, "cycle-0", "E1", now_epoch_s=NOW + 1)


def test_persistence_is_immutable_and_reloads_byte_identically(tmp_path: Path) -> None:
    adapter, policy, _rpc, _store = make_adapter(tmp_path)
    observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    decision = adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=NOW)
    identity_path = tmp_path / "ROBINHOOD_ASSET_IDENTITY_V0.json"
    observation_path = tmp_path / "ROBINHOOD_MARKET_OBSERVATION_V0.json"
    decision_path = tmp_path / "SHADOW_DECISION_V0.json"
    persist_identity(identity_path, adapter.identity)
    persist_observation(observation_path, observation)
    persist_decision(decision_path, decision)
    assert load_observation(observation_path).canonical_object() == observation.canonical_object()
    assert load_decision(decision_path).canonical_object() == decision.canonical_object()
    with pytest.raises(SafeHaltError):
        persist_decision(decision_path, replace(decision, reason_code="tampered"))


@pytest.mark.parametrize("kind,mutator", [
    ("deployment", lambda doc: doc.update({"assets": [{**doc["assets"][0], "deployments": [{"contractAddress": TOKEN, "chainId": 1}]}]})),
    ("uid", lambda doc: doc.update({"assets": [{**doc["assets"][0], "id": "0x" + "99" * 32}]})),
    ("decimals", lambda doc: doc.update({"assets": [{**doc["assets"][0], "tokenDecimals": 6}]})),
])
def test_authoritative_identity_mismatches_fail_closed(tmp_path: Path, kind: str, mutator: Any) -> None:
    doc = json.loads(asset_body())
    mutator(doc)
    store = RawEvidenceStore(tmp_path / "raw")
    rest = RobinhoodRestClient(evidence_store=store, transport=http_transport_factory(asset=canonical_json_bytes(doc)))
    if kind == "deployment":
        with pytest.raises((SafeHaltError, RobinhoodProtocolError)):
            rest.asset(SPY_SYMBOL)
    else:
        rpc_transport = RpcFixture()
        adapter = RobinhoodShadowAdapter(
            rest,
            RobinhoodRpcClient(transport=rpc_transport),
            ChainlinkRobinhoodDirectoryClient(transport=http_transport_factory()),
            ZeroXV2Client(api_key="fixture-key", transport=http_transport_factory(zero_quote=zero_body())),
            symbol=SPY_SYMBOL,
        )
        with pytest.raises(SafeHaltError):
            adapter.observe(robinhood_policy(), "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)


def test_wrong_rpc_chain_and_oracle_pause_fail_closed(tmp_path: Path) -> None:
    adapter, policy, _rpc, _store = make_adapter(tmp_path, rpc={"wrong_chain": True})
    with pytest.raises(SafeHaltError):
        adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    adapter, policy, _rpc, _store = make_adapter(tmp_path / "paused", rpc={"paused": True})
    observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    assert adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=NOW, observation=observation).decision == "ABSTAIN"


def test_multiplier_is_applied_once_and_not_to_chainlink(tmp_path: Path) -> None:
    adapter, policy, _rpc, _store = make_adapter(tmp_path)
    observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    assert observation.token_reference_bid == observation.rest_raw_bid * observation.ui_multiplier
    assert observation.chainlink_price == 150
    assert observation.chainlink_price != observation.chainlink_price * observation.ui_multiplier


def test_pending_multiplier_transition_is_ambiguous(tmp_path: Path) -> None:
    pending_time = "2027-01-15T08:00:00Z"
    body = asset_body(pendingMultiplier="2", pendingMultiplierEffectiveTime=pending_time)
    adapter, policy, _rpc, _store = make_adapter(tmp_path, http={"asset": body})
    with pytest.raises(SafeHaltError):
        adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)


@pytest.mark.parametrize("price_changes, answer, expected", [
    ({"generatedAt": "2020-01-01T00:00:00Z"}, 15_000_000_000, "REST_STALE"),
    ({"isTradingHalt": True}, 15_000_000_000, "REST_TRADING_HALT"),
    ({}, 0, "Chainlink answer"),
])
def test_stale_halt_and_bad_oracle_are_not_eligible(tmp_path: Path, price_changes: dict[str, Any], answer: int, expected: str) -> None:
    adapter, policy, _rpc, _store = make_adapter(tmp_path, rpc={"feed_answer": answer}, http={"price": price_body(**price_changes)})
    if answer == 0:
        with pytest.raises(SafeHaltError, match=expected):
            adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    else:
        observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
        decision = adapter.shadow_decision(policy, "cycle-0", "E1", now_epoch_s=NOW, observation=observation)
        assert expected in decision.reason_code


@pytest.mark.parametrize("field", ["sellToken", "buyToken", "sellAmount"])
def test_zero_x_pair_and_amount_are_exact(tmp_path: Path, field: str) -> None:
    values = {"sell_token": USDG_ADDRESS, "buy_token": TOKEN, "sell_amount": 100_000_000}
    if field == "sellToken":
        values["sell_token"] = TOKEN
    elif field == "buyToken":
        values["buy_token"] = USDG_ADDRESS
    else:
        values["sell_amount"] = 100_000_001
    adapter, policy, _rpc, _store = make_adapter(tmp_path, http={"zero_quote": zero_body(**values)})
    with pytest.raises(SafeHaltError):
        adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)


def test_zero_x_unknown_wire_field_and_malformed_calldata_fail_closed(tmp_path: Path) -> None:
    raw = json.loads(zero_body())
    raw["unexpected"] = True
    adapter, policy, _rpc, _store = make_adapter(tmp_path, http={"zero_quote": canonical_json_bytes(raw)})
    with pytest.raises(RobinhoodProtocolError):
        adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    raw = json.loads(zero_body())
    raw["transaction"]["data"] = "0x0"
    adapter, policy, _rpc, _store = make_adapter(tmp_path / "calldata", http={"zero_quote": canonical_json_bytes(raw)})
    with pytest.raises(RobinhoodProtocolError):
        adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)


def test_api_key_is_never_captured_or_persisted(tmp_path: Path) -> None:
    key = "fixture-secret-key"
    store = RawEvidenceStore(tmp_path / "raw")
    client = ZeroXV2Client(api_key=key, evidence_store=store, transport=http_transport_factory(zero_quote=key.encode()))
    with pytest.raises(SafeHaltError):
        client.quote(sell_token=USDG_ADDRESS, buy_token=TOKEN, sell_amount_atomic=1, taker=QUALIFICATION_TAKER_ADDRESS, slippage_bps=0, policy_min_output_atomic=1)
    assert not list((tmp_path / "raw").rglob("*"))


def test_http_error_body_is_captured_without_the_api_key(tmp_path: Path) -> None:
    store = RawEvidenceStore(tmp_path / "raw")
    client = ZeroXV2Client(api_key="fixture-key", evidence_store=store)

    class ErrorOpener:
        def open(self, _request: Any, timeout: int) -> Any:
            del timeout
            raise HTTPError(
                ZEROX_SWAP_V2_QUOTE_ENDPOINT,
                400,
                "fixture validation error",
                {},
                io.BytesIO(b'{"validationErrors":[{"reason":"unsupported pair"}]}'),
            )

    client.http.opener = ErrorOpener()
    with pytest.raises(RobinhoodTransportError):
        client.quote(
            sell_token=USDG_ADDRESS,
            buy_token=TOKEN,
            sell_amount_atomic=1,
            taker=QUALIFICATION_TAKER_ADDRESS,
            slippage_bps=0,
            policy_min_output_atomic=1,
        )
    assert len(client.evidence_records) == 1
    assert b"fixture-key" not in store.read(client.evidence_records[0])


def test_venue_looser_bound_is_rejected_but_stricter_bound_is_acceptable(tmp_path: Path) -> None:
    raw = zero_body(min_buy=499_999_999)
    adapter, policy, _rpc, _store = make_adapter(tmp_path, http={"zero_quote": raw})
    with pytest.raises(SafeHaltError):
        adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    adapter, policy, _rpc, _store = make_adapter(tmp_path / "strict", http={"zero_quote": zero_body(min_buy=600_000_000_000_000_000)})
    observation = adapter.observe(policy, "cycle-0", "E1", now_epoch_s=NOW, taker=QUALIFICATION_TAKER_ADDRESS)
    assert observation.zero_x_min_buy_amount == 600_000_000_000_000_000


def test_raw_evidence_integrity_is_fail_closed(tmp_path: Path) -> None:
    store = RawEvidenceStore(tmp_path / "raw")
    record = store.capture(endpoint="https://example.invalid/read", method="GET", request_target="https://example.invalid/read", request_body=None, response_body=b'{"ok":true}')
    (tmp_path / "raw" / record.response_path).write_bytes(b"tampered")
    with pytest.raises(SafeHaltError):
        store.read(record)
