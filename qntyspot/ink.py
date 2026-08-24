"""Bounded, read-only Ink mainnet shadow observation.

This module is deliberately small and explicit.  It can read public JSON-RPC
data, but it has no transaction-producing surface.  The adapter only accepts
one caller-supplied pool identity and one pinned Uniswap V2 bytecode hash;
there is no venue or asset discovery.

All economic quantities are integers or exact ``Fraction`` values.  The
observation and decision records contain only canonical JSON values, so their
SHA-256 digests are stable across processes and Python versions.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler

from .boundary import QuoteSource
from .canon import (
    canonical_json_bytes,
    canonical_json_str,
    digest_object,
    strict_json_loads,
)
from .domain import EconomicBounds, IntentV0, PolicyV0, QuoteV0, Side
from .errors import (
    InkError,
    LevelNotExecutableError,
    RpcError,
    RpcProtocolError,
    RpcResponseTooLargeError,
    RpcTimeoutError,
    RpcTransportError,
    SafeHaltError,
)
from .economics import build_intent

__all__ = [
    "INK_CHAIN_ID",
    "INK_RPC_ENDPOINTS",
    "KRAKMASK_ADDRESS",
    "WETH9_ADDRESS",
    "INKYSWAP_V2_FACTORY",
    "INKYSWAP_V2_POOL",
    "INKYSWAP_V2_BYTECODE_SHA256",
    "JsonRpcClient",
    "InkMarketObservationV0",
    "InkQuoteV0",
    "ShadowDecisionV0",
    "InkShadowAdapter",
    "replay_shadow_decision",
    "persist_observation",
    "persist_decision",
    "load_observation",
    "load_decision",
]

INK_CHAIN_ID = 57_073
INK_RPC_ENDPOINTS = (
    "https://rpc-gel.inkonchain.com",
    "https://rpc-qnd.inkonchain.com",
)
KRAKMASK_ADDRESS = "0x32bcb803f696c99eb263d60a05cafd8689026575"
WETH9_ADDRESS = "0x4200000000000000000000000000000000000006"
KRAKMASK_DECIMALS = 18
WETH9_DECIMALS = 18
INKYSWAP_V2_FACTORY = "0x458c5d5b75ccba22651d2c5b61cb1ea1e0b0f95d"
INKYSWAP_V2_POOL = "0xed11ed4b195e84ba9b74c4d6ce13b7a43b354264"
# SHA-256 of the deployed runtime bytecode bytes, not of its hex spelling.
INKYSWAP_V2_BYTECODE_SHA256 = (
    "c5c2b764b882b8c18004fe5ce77d8649dd8c26cea265f663b16196708d22bf20"
)

V2_FEE_NUMERATOR = 997
V2_FEE_DENOMINATOR = 1000
V2_RESERVE_MAX = (1 << 112) - 1
V2_TIMESTAMP_MAX = (1 << 32) - 1
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_BYTES_RE = re.compile(r"^0x(?:[0-9a-f]{2})*$")


def _check_address(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise InkError(f"{field}: expected lowercase 0x address")
    return value


def _check_hash(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise InkError(f"{field}: expected lowercase SHA-256 hex")
    return value


def _quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not _QUANTITY_RE.fullmatch(value):
        raise RpcProtocolError(f"{field}: non-canonical JSON-RPC quantity {value!r}")
    return int(value[2:], 16)


def _hex_bytes(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or not _BYTES_RE.fullmatch(value):
        raise RpcProtocolError(f"{field}: expected lowercase 0x-prefixed bytes")
    return bytes.fromhex(value[2:])


def _word(data: bytes, index: int, *, field: str) -> int:
    start = index * 32
    end = start + 32
    if len(data) < end:
        raise RpcProtocolError(f"{field}: ABI response ended before word {index}")
    return int.from_bytes(data[start:end], "big")


def _address_word(data: bytes, *, field: str) -> str:
    if len(data) != 32 or data[:12] != b"\x00" * 12:
        raise RpcProtocolError(f"{field}: expected one canonical address word")
    return "0x" + data[12:].hex()


def _ratio(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _parse_ratio(value: Any, *, field: str) -> Fraction:
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise InkError(f"{field}: malformed exact ratio")
    numerator = value["numerator"]
    denominator = value["denominator"]
    if not isinstance(numerator, str) or not re.fullmatch(r"-?[0-9]+", numerator):
        raise InkError(f"{field}.numerator: expected integer string")
    if not isinstance(denominator, str) or not re.fullmatch(r"[1-9][0-9]*", denominator):
        raise InkError(f"{field}.denominator: expected positive integer string")
    return Fraction(int(numerator), int(denominator))


def _record_digest(obj: Mapping[str, Any]) -> str:
    return digest_object(dict(obj))


class JsonRpcClient:
    """A strict JSON-RPC client with explicit, finite resource bounds.

    ``transport`` is an offline test seam.  When omitted, the client uses an
    HTTPS opener with proxy discovery disabled.  The request id is always 1;
    a response with any other id is rejected.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        timeout_s: int = 10,
        max_retries: int = 2,
        max_response_bytes: int = 1_000_000,
        transport: Callable[[bytes], bytes] | None = None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise RpcError("endpoint must be an HTTPS URL without embedded credentials")
        if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or timeout_s < 1:
            raise RpcError("timeout_s must be a positive int")
        if not isinstance(max_retries, int) or isinstance(max_retries, bool) or not 0 <= max_retries <= 5:
            raise RpcError("max_retries must be an int in [0, 5]")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 256:
            raise RpcError("max_response_bytes must be an int >= 256")
        self.endpoint = endpoint
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.max_response_bytes = max_response_bytes
        self._transport = transport
        self._opener = build_opener(ProxyHandler({}))

    def _transport_once(self, payload: bytes) -> bytes:
        if self._transport is not None:
            return self._transport(payload)
        request = Request(
            self.endpoint,
            data=payload,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "qntyspot-v0b-read-only/1",
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout_s) as response:
                body = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            if exc.code in (408, 429) or 500 <= exc.code <= 599:
                raise RpcTransportError(f"HTTP {exc.code} from {self.endpoint}") from exc
            raise RpcError(f"HTTP {exc.code} from {self.endpoint}") from exc
        except (TimeoutError, URLError, OSError) as exc:
            if isinstance(exc, TimeoutError) or "timed out" in str(exc).lower():
                raise RpcTimeoutError(f"RPC timeout from {self.endpoint}") from exc
            raise RpcTransportError(f"RPC transport failed for {self.endpoint}") from exc
        return body

    def request(self, method: str, params: list[Any]) -> Any:
        if not isinstance(method, str) or not method:
            raise RpcProtocolError("method must be a non-empty string")
        if not isinstance(params, list):
            raise RpcProtocolError("params must be a list")
        payload = canonical_json_bytes(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        )
        last: RpcTransportError | None = None
        for _attempt in range(self.max_retries + 1):
            try:
                body = self._transport_once(payload)
                if len(body) > self.max_response_bytes:
                    raise RpcResponseTooLargeError(
                        f"response from {self.endpoint} exceeds {self.max_response_bytes} bytes"
                    )
                try:
                    raw = strict_json_loads(body)
                except Exception as exc:
                    raise RpcProtocolError("response was not strict JSON") from exc
                if not isinstance(raw, dict):
                    raise RpcProtocolError("JSON-RPC response must be an object")
                if raw.get("jsonrpc") != "2.0" or raw.get("id") != 1:
                    raise RpcProtocolError("JSON-RPC version or response id mismatch")
                has_result = "result" in raw
                has_error = "error" in raw
                expected_keys = {"jsonrpc", "id", "result"} if has_result else {"jsonrpc", "id", "error"}
                if set(raw) != expected_keys:
                    raise RpcProtocolError("JSON-RPC response contains unknown or missing fields")
                if has_result == has_error:
                    raise RpcProtocolError("JSON-RPC response must contain exactly one of result/error")
                if has_error:
                    error = raw["error"]
                    if not isinstance(error, dict) or not isinstance(error.get("code"), int) or not isinstance(error.get("message"), str):
                        raise RpcProtocolError("malformed JSON-RPC error object")
                    raise RpcError(f"JSON-RPC {error['code']}: {error['message']}")
                return raw["result"]
            except RpcTransportError as exc:
                last = exc
            except TimeoutError as exc:
                last = RpcTimeoutError(f"RPC timeout from {self.endpoint}")
                last.__cause__ = exc
            except OSError as exc:
                last = RpcTransportError(f"RPC transport failed for {self.endpoint}")
                last.__cause__ = exc
        if last is None:  # pragma: no cover - range always runs once
            raise RpcTransportError("RPC retry loop did not run")
        raise last

    def chain_id(self) -> int:
        return _quantity(self.request("eth_chainId", []), field="eth_chainId")

    def block_number(self) -> int:
        return _quantity(self.request("eth_blockNumber", []), field="eth_blockNumber")

    def get_code(self, address: str, block_tag: str) -> tuple[bytes, str]:
        raw = self.request("eth_getCode", [address, block_tag])
        code = _hex_bytes(raw, field="eth_getCode.result")
        return code, raw

    def call(self, address: str, data: str, block_tag: str) -> tuple[bytes, str]:
        raw = self.request("eth_call", [{"to": address, "data": data}, block_tag])
        return _hex_bytes(raw, field="eth_call.result"), raw


@dataclass(frozen=True, slots=True)
class InkMarketObservationV0:
    schema: str
    chain_id: int
    pool_address: str
    factory_address: str
    token0: str
    token1: str
    common_block: int
    provider_heads: Mapping[str, int]
    bytecode_present: bool
    bytecode_sha256: str
    bytecode_length: int
    reserve0_atomic: int
    reserve1_atomic: int
    reserve_timestamp: int
    provider_evidence: tuple[Mapping[str, Any], ...]
    v2_fee_numerator: int
    v2_fee_denominator: int

    def __post_init__(self) -> None:
        if self.schema != "INK_MARKET_OBSERVATION_V0":
            raise InkError("observation schema mismatch")
        if self.chain_id != INK_CHAIN_ID:
            raise SafeHaltError(f"unexpected Ink chain id {self.chain_id}")
        _check_address(self.pool_address, field="pool_address")
        _check_address(self.factory_address, field="factory_address")
        _check_address(self.token0, field="token0")
        _check_address(self.token1, field="token1")
        _check_hash(self.bytecode_sha256, field="bytecode_sha256")
        if not self.bytecode_present or self.bytecode_length <= 0:
            raise SafeHaltError("pool bytecode is absent")
        if self.common_block < 0 or self.reserve0_atomic <= 0 or self.reserve1_atomic <= 0:
            raise SafeHaltError("observation block/reserves are not executable")
        if self.v2_fee_numerator != V2_FEE_NUMERATOR or self.v2_fee_denominator != V2_FEE_DENOMINATOR:
            raise InkError("unsupported V2 fee semantics")
        if len(self.provider_evidence) != 2:
            raise InkError("exactly two provider evidence records are required")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "bytecode_length": self.bytecode_length,
            "bytecode_present": self.bytecode_present,
            "bytecode_sha256": self.bytecode_sha256,
            "chain_id": self.chain_id,
            "common_block": self.common_block,
            "factory_address": self.factory_address,
            "pool_address": self.pool_address,
            "provider_evidence": [dict(item) for item in self.provider_evidence],
            "provider_heads": dict(sorted(self.provider_heads.items())),
            "reserve0_atomic": str(self.reserve0_atomic),
            "reserve1_atomic": str(self.reserve1_atomic),
            "reserve_timestamp": self.reserve_timestamp,
            "schema": self.schema,
            "token0": self.token0,
            "token1": self.token1,
            "v2_fee_denominator": self.v2_fee_denominator,
            "v2_fee_numerator": self.v2_fee_numerator,
        }

    def digest(self) -> str:
        return _record_digest(self.canonical_object())

    @classmethod
    def from_canonical(cls, obj: Any) -> "InkMarketObservationV0":
        if not isinstance(obj, dict):
            raise InkError("observation must be an object")
        required = {
            "bytecode_length", "bytecode_present", "bytecode_sha256", "chain_id",
            "common_block", "factory_address", "pool_address", "provider_evidence",
            "provider_heads", "reserve0_atomic", "reserve1_atomic", "reserve_timestamp",
            "schema", "token0", "token1", "v2_fee_denominator", "v2_fee_numerator",
        }
        if set(obj) != required:
            raise InkError("observation fields are not exact")
        heads = obj["provider_heads"]
        if not isinstance(heads, dict) or any(not isinstance(k, str) or not isinstance(v, int) for k, v in heads.items()):
            raise InkError("provider_heads are malformed")
        evidence = obj["provider_evidence"]
        if not isinstance(evidence, list) or any(not isinstance(item, dict) for item in evidence):
            raise InkError("provider_evidence is malformed")
        ints = ("chain_id", "common_block", "bytecode_length", "reserve_timestamp", "v2_fee_denominator", "v2_fee_numerator")
        if any(not isinstance(obj[name], int) or isinstance(obj[name], bool) for name in ints):
            raise InkError("observation integer field is malformed")
        amounts = []
        for name in ("reserve0_atomic", "reserve1_atomic"):
            value = obj[name]
            if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
                raise InkError(f"{name} is not a positive atomic string")
            amounts.append(int(value))
        if not isinstance(obj["bytecode_present"], bool):
            raise InkError("bytecode_present must be boolean")
        return cls(
            schema=obj["schema"], chain_id=obj["chain_id"], pool_address=obj["pool_address"],
            factory_address=obj["factory_address"], token0=obj["token0"], token1=obj["token1"],
            common_block=obj["common_block"], provider_heads=heads,
            bytecode_present=obj["bytecode_present"], bytecode_sha256=obj["bytecode_sha256"],
            bytecode_length=obj["bytecode_length"], reserve0_atomic=amounts[0],
            reserve1_atomic=amounts[1], reserve_timestamp=obj["reserve_timestamp"],
            provider_evidence=tuple(evidence), v2_fee_numerator=obj["v2_fee_numerator"],
            v2_fee_denominator=obj["v2_fee_denominator"],
        )


@dataclass(frozen=True, slots=True)
class InkQuoteV0:
    side: Side
    input_atomic: int
    output_atomic: int
    reserve_in_atomic: int
    reserve_out_atomic: int
    average_price: Fraction
    spot_price: Fraction
    price_impact_bps: Fraction
    fee_atomic: Fraction
    observation_digest: str
    common_block: int

    def canonical_object(self) -> dict[str, Any]:
        return {
            "average_price": _ratio(self.average_price),
            "common_block": self.common_block,
            "fee_atomic": _ratio(self.fee_atomic),
            "input_atomic": str(self.input_atomic),
            "observation_digest": self.observation_digest,
            "output_atomic": str(self.output_atomic),
            "price_impact_bps": _ratio(self.price_impact_bps),
            "reserve_in_atomic": str(self.reserve_in_atomic),
            "reserve_out_atomic": str(self.reserve_out_atomic),
            "side": self.side.value,
            "spot_price": _ratio(self.spot_price),
        }


@dataclass(frozen=True, slots=True)
class ShadowDecisionV0:
    schema: str
    decision: str
    reason_code: str
    observation_digest: str
    policy_id: str
    cycle_id: str
    level_id: str
    side: Side
    economic_action_id: str
    common_block: int
    current_common_block: int
    expected_output_atomic: int
    average_price: Fraction
    spot_price: Fraction
    price_impact_bps: Fraction
    fee_atomic: Fraction
    bound_limit_price: Fraction
    bound_min_output_atomic: int
    bound_max_input_atomic: int

    def __post_init__(self) -> None:
        if self.schema != "SHADOW_DECISION_V0":
            raise InkError("decision schema mismatch")
        if self.decision not in {"WOULD_EXECUTE", "ABSTAIN"}:
            raise InkError("decision must be WOULD_EXECUTE or ABSTAIN")
        if self.side not in (Side.BUY, Side.SELL):
            raise InkError("decision side is invalid")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "average_price": _ratio(self.average_price),
            "bound_limit_price": _ratio(self.bound_limit_price),
            "bound_max_input_atomic": str(self.bound_max_input_atomic),
            "bound_min_output_atomic": str(self.bound_min_output_atomic),
            "common_block": self.common_block,
            "current_common_block": self.current_common_block,
            "cycle_id": self.cycle_id,
            "decision": self.decision,
            "economic_action_id": self.economic_action_id,
            "expected_output_atomic": str(self.expected_output_atomic),
            "fee_atomic": _ratio(self.fee_atomic),
            "level_id": self.level_id,
            "observation_digest": self.observation_digest,
            "policy_id": self.policy_id,
            "price_impact_bps": _ratio(self.price_impact_bps),
            "reason_code": self.reason_code,
            "schema": self.schema,
            "side": self.side.value,
            "spot_price": _ratio(self.spot_price),
        }

    def digest(self) -> str:
        return _record_digest(self.canonical_object())

    @classmethod
    def from_canonical(cls, obj: Any) -> "ShadowDecisionV0":
        if not isinstance(obj, dict):
            raise InkError("decision must be an object")
        required = {
            "average_price", "bound_limit_price", "bound_max_input_atomic", "bound_min_output_atomic",
            "common_block", "current_common_block", "cycle_id", "decision", "economic_action_id",
            "expected_output_atomic", "fee_atomic", "level_id", "observation_digest", "policy_id",
            "price_impact_bps", "reason_code", "schema", "side", "spot_price",
        }
        if set(obj) != required:
            raise InkError("decision fields are not exact")
        try:
            side = Side(obj["side"])
        except ValueError as exc:
            raise InkError("decision side is invalid") from exc
        ints = ("common_block", "current_common_block")
        if any(not isinstance(obj[name], int) or isinstance(obj[name], bool) for name in ints):
            raise InkError("decision block field is malformed")
        amounts: dict[str, int] = {}
        for name in ("bound_max_input_atomic", "bound_min_output_atomic", "expected_output_atomic"):
            value = obj[name]
            if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
                raise InkError(f"decision {name} is malformed")
            amounts[name] = int(value)
        return cls(
            schema=obj["schema"], decision=obj["decision"], reason_code=obj["reason_code"],
            observation_digest=obj["observation_digest"], policy_id=obj["policy_id"],
            cycle_id=obj["cycle_id"], level_id=obj["level_id"], side=side,
            economic_action_id=obj["economic_action_id"], common_block=obj["common_block"],
            current_common_block=obj["current_common_block"], expected_output_atomic=amounts["expected_output_atomic"],
            average_price=_parse_ratio(obj["average_price"], field="average_price"),
            spot_price=_parse_ratio(obj["spot_price"], field="spot_price"),
            price_impact_bps=_parse_ratio(obj["price_impact_bps"], field="price_impact_bps"),
            fee_atomic=_parse_ratio(obj["fee_atomic"], field="fee_atomic"),
            bound_limit_price=_parse_ratio(obj["bound_limit_price"], field="bound_limit_price"),
            bound_min_output_atomic=amounts["bound_min_output_atomic"],
            bound_max_input_atomic=amounts["bound_max_input_atomic"],
        )


class InkShadowAdapter(QuoteSource):
    """The one bounded KRAKMASK/WETH read-only Ink V2 adapter."""

    venue_id = "inkyswap-v2-ink-mainnet"

    def __init__(
        self,
        providers: tuple[JsonRpcClient, JsonRpcClient],
        *,
        expected_chain_id: int = INK_CHAIN_ID,
        expected_pool: str = INKYSWAP_V2_POOL,
        expected_factory: str = INKYSWAP_V2_FACTORY,
        expected_token0: str = KRAKMASK_ADDRESS,
        expected_token1: str = WETH9_ADDRESS,
        expected_bytecode_sha256: str = INKYSWAP_V2_BYTECODE_SHA256,
        max_head_lag_blocks: int = 12,
        max_observation_age_blocks: int = 12,
    ) -> None:
        if len(providers) != 2:
            raise InkError("exactly two RPC providers are required")
        self.providers = providers
        self.expected_chain_id = expected_chain_id
        self.expected_pool = _check_address(expected_pool, field="expected_pool")
        self.expected_factory = _check_address(expected_factory, field="expected_factory")
        self.expected_token0 = _check_address(expected_token0, field="expected_token0")
        self.expected_token1 = _check_address(expected_token1, field="expected_token1")
        self.expected_bytecode_sha256 = _check_hash(expected_bytecode_sha256, field="expected_bytecode_sha256")
        if not isinstance(max_head_lag_blocks, int) or max_head_lag_blocks < 0:
            raise InkError("max_head_lag_blocks must be a non-negative int")
        if not isinstance(max_observation_age_blocks, int) or max_observation_age_blocks < 0:
            raise InkError("max_observation_age_blocks must be a non-negative int")
        self.max_head_lag_blocks = max_head_lag_blocks
        self.max_observation_age_blocks = max_observation_age_blocks
        self._observation: InkMarketObservationV0 | None = None

    def _provider_observation(self, provider: JsonRpcClient, common_block: int) -> dict[str, Any]:
        block_tag = "0x" + format(common_block, "x")
        code, code_raw = provider.get_code(self.expected_pool, block_tag)
        code_hash = hashlib.sha256(code).hexdigest()
        token0_bytes, token0_raw = provider.call(self.expected_pool, "0x0dfe1681", block_tag)
        token1_bytes, token1_raw = provider.call(self.expected_pool, "0xd21220a7", block_tag)
        factory_bytes, factory_raw = provider.call(self.expected_pool, "0xc45a0155", block_tag)
        pair_a_bytes, pair_a_raw = provider.call(
            self.expected_factory,
            "0xe6a43905" + self.expected_token0[2:].rjust(64, "0") + self.expected_token1[2:].rjust(64, "0"),
            block_tag,
        )
        pair_b_bytes, pair_b_raw = provider.call(
            self.expected_factory,
            "0xe6a43905" + self.expected_token1[2:].rjust(64, "0") + self.expected_token0[2:].rjust(64, "0"),
            block_tag,
        )
        reserves_bytes, reserves_raw = provider.call(self.expected_pool, "0x0902f1ac", block_tag)
        token0 = _address_word(token0_bytes, field="token0")
        token1 = _address_word(token1_bytes, field="token1")
        factory = _address_word(factory_bytes, field="factory")
        pair_a = _address_word(pair_a_bytes, field="factory.getPair")
        pair_b = _address_word(pair_b_bytes, field="factory.getPair.reverse")
        if code_hash != self.expected_bytecode_sha256:
            raise SafeHaltError(
                f"pool bytecode hash mismatch: expected {self.expected_bytecode_sha256}, got {code_hash}"
            )
        if not code:
            raise SafeHaltError("pool bytecode is absent")
        if token0 != self.expected_token0 or token1 != self.expected_token1:
            raise SafeHaltError(f"pool token pair mismatch: {token0}/{token1}")
        if factory != self.expected_factory or pair_a != self.expected_pool or pair_b != self.expected_pool:
            raise SafeHaltError("pool factory identity mismatch")
        if len(reserves_bytes) != 96:
            raise SafeHaltError("getReserves did not return exactly three ABI words")
        reserve0 = _word(reserves_bytes, 0, field="reserve0")
        reserve1 = _word(reserves_bytes, 1, field="reserve1")
        timestamp = _word(reserves_bytes, 2, field="reserve_timestamp")
        if reserve0 > V2_RESERVE_MAX or reserve1 > V2_RESERVE_MAX:
            raise SafeHaltError("getReserves exceeded the Uniswap V2 uint112 reserve bound")
        if timestamp > V2_TIMESTAMP_MAX:
            raise SafeHaltError("getReserves timestamp exceeded its uint32 bound")
        if reserve0 <= 0 or reserve1 <= 0:
            raise SafeHaltError("pool reserves must both be non-zero")
        return {
            "bytecode_length": len(code),
            "bytecode_present": bool(code),
            "bytecode_sha256": code_hash,
            "chain_id": self.expected_chain_id,
            "common_block": common_block,
            "factory_address": factory,
            "pair_from_factory": pair_a,
            "pair_from_factory_reverse": pair_b,
            "pool_address": self.expected_pool,
            "reserve0_atomic": str(reserve0),
            "reserve1_atomic": str(reserve1),
            "reserve_timestamp": timestamp,
            "rpc_evidence": {
                "eth_call.factory": factory_raw,
                "eth_call.factory_getPair": pair_a_raw,
                "eth_call.factory_getPair_reverse": pair_b_raw,
                "eth_call.getReserves": reserves_raw,
                "eth_call.token0": token0_raw,
                "eth_call.token1": token1_raw,
                "eth_getCode.derivative": {
                    "byte_length": len(code),
                    "bytecode_sha256": code_hash,
                    "present": bool(code),
                    "raw_result_sha256": hashlib.sha256(code_raw.encode("ascii")).hexdigest(),
                },
            },
            "token0": token0,
            "token1": token1,
        }

    def observe(self) -> InkMarketObservationV0:
        heads: list[int] = []
        chain_ids: list[int] = []
        for provider in self.providers:
            try:
                chain_ids.append(provider.chain_id())
                heads.append(provider.block_number())
            except RpcError as exc:
                raise SafeHaltError(f"provider head/chain observation failed: {exc}") from exc
        if chain_ids[0] != self.expected_chain_id or chain_ids[1] != self.expected_chain_id:
            raise SafeHaltError(f"provider chain id mismatch: {chain_ids}")
        if abs(heads[0] - heads[1]) > self.max_head_lag_blocks:
            raise SafeHaltError(f"provider head lag exceeds bound: {heads}")
        common_block = min(heads)
        records: list[dict[str, Any]] = []
        for provider in self.providers:
            try:
                records.append(self._provider_observation(provider, common_block))
            except RpcError as exc:
                raise SafeHaltError(f"provider observation failed at block {common_block}: {exc}") from exc
        facts = [
            {
                key: record[key]
                for key in (
                    "bytecode_length", "bytecode_present", "bytecode_sha256", "chain_id",
                    "common_block", "factory_address", "pair_from_factory", "pair_from_factory_reverse", "pool_address",
                    "reserve0_atomic", "reserve1_atomic", "reserve_timestamp", "token0", "token1",
                )
            }
            for record in records
        ]
        if facts[0] != facts[1]:
            raise SafeHaltError("providers disagree on deterministic pool facts")
        fact = facts[0]
        observation = InkMarketObservationV0(
            schema="INK_MARKET_OBSERVATION_V0",
            chain_id=self.expected_chain_id,
            pool_address=self.expected_pool,
            factory_address=self.expected_factory,
            token0=self.expected_token0,
            token1=self.expected_token1,
            common_block=common_block,
            provider_heads={
                self.providers[0].endpoint: heads[0],
                self.providers[1].endpoint: heads[1],
            },
            bytecode_present=fact["bytecode_present"],
            bytecode_sha256=fact["bytecode_sha256"],
            bytecode_length=fact["bytecode_length"],
            reserve0_atomic=int(fact["reserve0_atomic"]),
            reserve1_atomic=int(fact["reserve1_atomic"]),
            reserve_timestamp=fact["reserve_timestamp"],
            provider_evidence=tuple(
                {
                    "endpoint": provider.endpoint,
                    "facts": facts[index],
                    "rpc_evidence": records[index]["rpc_evidence"],
                }
                for index, provider in enumerate(self.providers)
            ),
            v2_fee_numerator=V2_FEE_NUMERATOR,
            v2_fee_denominator=V2_FEE_DENOMINATOR,
        )
        self._observation = observation
        return observation

    @staticmethod
    def _quote(observation: InkMarketObservationV0, side: Side, input_atomic: int) -> InkQuoteV0:
        if not isinstance(input_atomic, int) or isinstance(input_atomic, bool) or input_atomic <= 0:
            raise LevelNotExecutableError("trade input must be a positive integer atomic amount")
        if side is Side.BUY:
            reserve_in, reserve_out = observation.reserve1_atomic, observation.reserve0_atomic
        else:
            reserve_in, reserve_out = observation.reserve0_atomic, observation.reserve1_atomic
        amount_in_with_fee = input_atomic * V2_FEE_NUMERATOR
        output_atomic = (amount_in_with_fee * reserve_out) // (
            reserve_in * V2_FEE_DENOMINATOR + amount_in_with_fee
        )
        if output_atomic <= 0:
            raise LevelNotExecutableError("trade input produces zero output")
        if side is Side.BUY:
            spot = Fraction(observation.reserve1_atomic, observation.reserve0_atomic)
            average = Fraction(input_atomic, output_atomic)
            impact = (average - spot) / spot * 10_000
        else:
            spot = Fraction(observation.reserve1_atomic, observation.reserve0_atomic)
            average = Fraction(output_atomic, input_atomic)
            impact = (spot - average) / spot * 10_000
        if impact < 0:
            impact = Fraction(0)
        return InkQuoteV0(
            side=side,
            input_atomic=input_atomic,
            output_atomic=output_atomic,
            reserve_in_atomic=reserve_in,
            reserve_out_atomic=reserve_out,
            average_price=average,
            spot_price=spot,
            price_impact_bps=impact,
            fee_atomic=Fraction(input_atomic * (V2_FEE_DENOMINATOR - V2_FEE_NUMERATOR), V2_FEE_DENOMINATOR),
            observation_digest=observation.digest(),
            common_block=observation.common_block,
        )

    def _require_observation(self, observation: InkMarketObservationV0 | None) -> InkMarketObservationV0:
        chosen = observation or self._observation
        if chosen is None:
            raise SafeHaltError("no pinned Ink observation is available")
        return chosen

    def _validate_market_policy(self, policy: PolicyV0) -> None:
        expected_base = f"evm:{INK_CHAIN_ID}:{self.expected_token0}"
        expected_quote = f"evm:{INK_CHAIN_ID}:{self.expected_token1}"
        if (
            policy.base.instrument_id != expected_base
            or policy.quote.instrument_id != expected_quote
            or policy.base.decimals != KRAKMASK_DECIMALS
            or policy.quote.decimals != WETH9_DECIMALS
        ):
            raise SafeHaltError("policy instruments do not match the pinned KRAKMASK/WETH market")

    def quote(self, bounds: EconomicBounds, *, now_epoch_s: int) -> QuoteV0:
        observation = self._require_observation(None)
        expected_input = f"evm:{INK_CHAIN_ID}:{self.expected_token1}"
        expected_output = f"evm:{INK_CHAIN_ID}:{self.expected_token0}"
        if bounds.side is Side.SELL:
            expected_input, expected_output = expected_output, expected_input
        if bounds.input_instrument_id != expected_input or bounds.output_instrument_id != expected_output:
            raise SafeHaltError("quote bounds do not match the pinned KRAKMASK/WETH market")
        quote = self._quote(observation, bounds.side, bounds.max_input_atomic)
        if quote.output_atomic < bounds.min_output_atomic:
            raise LevelNotExecutableError("shadow quote is below the absolute output bound")
        quote_id = digest_object(
            {
                "bounds": bounds.canonical_object(),
                "common_block": observation.common_block,
                "observation_digest": observation.digest(),
                "pinned_at_epoch_s": now_epoch_s,
            }
        )
        return QuoteV0(
            quote_id=quote_id,
            economic_action_id="shadow-quote",
            input_atomic=quote.input_atomic,
            output_atomic=quote.output_atomic,
            pinned_at_epoch_s=now_epoch_s,
            expires_at_epoch_s=now_epoch_s + 1,
            source=self.venue_id,
        )

    def shadow_decision(
        self,
        policy: PolicyV0,
        cycle_id: str,
        level_id: str,
        *,
        now_epoch_s: int,
        observation: InkMarketObservationV0 | None = None,
        inventory_atomic: int | None = None,
        current_common_block: int | None = None,
    ) -> ShadowDecisionV0:
        obs = self._require_observation(observation)
        self._validate_market_policy(policy)
        current = min(obs.provider_heads.values()) if current_common_block is None else current_common_block
        if current < obs.common_block:
            raise SafeHaltError("current block precedes frozen observation")
        age = current - obs.common_block
        intent = build_intent(
            policy,
            cycle_id,
            policy.level(level_id),
            now_epoch_s=now_epoch_s,
            inventory_atomic=inventory_atomic,
        )
        quote = self._quote(obs, intent.side, intent.bounds.max_input_atomic)
        reasons: list[str] = []
        if age > self.max_observation_age_blocks:
            reasons.append("STALE_OBSERVATION")
        if quote.output_atomic < intent.bounds.min_output_atomic:
            reasons.append("MIN_OUTPUT_BOUND")
        if intent.side is Side.BUY and quote.average_price > intent.bounds.limit_price:
            reasons.append("MAX_EXECUTABLE_PRICE")
        if intent.side is Side.SELL and quote.average_price < intent.bounds.limit_price:
            reasons.append("MIN_EXECUTABLE_PRICE")
        if quote.price_impact_bps > intent.bounds.max_price_impact_bps:
            reasons.append("MAX_PRICE_IMPACT")
        decision = "WOULD_EXECUTE" if not reasons else "ABSTAIN"
        reason = "PASS" if not reasons else "+".join(reasons)
        return ShadowDecisionV0(
            schema="SHADOW_DECISION_V0",
            decision=decision,
            reason_code=reason,
            observation_digest=obs.digest(),
            policy_id=policy.policy_id,
            cycle_id=cycle_id,
            level_id=level_id,
            side=intent.side,
            economic_action_id=intent.economic_action_id,
            common_block=obs.common_block,
            current_common_block=current,
            expected_output_atomic=quote.output_atomic,
            average_price=quote.average_price,
            spot_price=quote.spot_price,
            price_impact_bps=quote.price_impact_bps,
            fee_atomic=quote.fee_atomic,
            bound_limit_price=intent.bounds.limit_price,
            bound_min_output_atomic=intent.bounds.min_output_atomic,
            bound_max_input_atomic=intent.bounds.max_input_atomic,
        )


def replay_shadow_decision(
    policy: PolicyV0,
    observation: InkMarketObservationV0,
    cycle_id: str,
    level_id: str,
    *,
    now_epoch_s: int,
    current_common_block: int | None = None,
    inventory_atomic: int | None = None,
    max_observation_age_blocks: int = 12,
) -> ShadowDecisionV0:
    """Recompute a decision from frozen data without constructing a client."""
    adapter = object.__new__(InkShadowAdapter)
    adapter.max_observation_age_blocks = max_observation_age_blocks
    adapter.expected_token0 = observation.token0
    adapter.expected_token1 = observation.token1
    adapter._observation = observation
    return adapter.shadow_decision(
        policy,
        cycle_id,
        level_id,
        now_epoch_s=now_epoch_s,
        observation=observation,
        current_common_block=current_common_block,
        inventory_atomic=inventory_atomic,
    )


def _persist(path: str | Path, record: Any) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    canonical = record.canonical_object()
    digest = record.digest()
    payload = canonical_json_bytes({"digest": digest, "record": canonical})
    try:
        with target.open("xb") as handle:
            handle.write(payload)
    except FileExistsError:
        if target.read_bytes() != payload:
            raise SafeHaltError(f"immutable record path already contains different data: {target}")
    return digest


def persist_observation(path: str | Path, observation: InkMarketObservationV0) -> str:
    return _persist(path, observation)


def persist_decision(path: str | Path, decision: ShadowDecisionV0) -> str:
    return _persist(path, decision)


def _load(path: str | Path, factory: Callable[[Any], Any]) -> Any:
    raw = strict_json_loads(Path(path).read_bytes())
    if not isinstance(raw, dict) or set(raw) != {"digest", "record"} or not isinstance(raw["digest"], str):
        raise InkError("persisted record envelope is malformed")
    record = factory(raw["record"])
    if record.digest() != raw["digest"]:
        raise SafeHaltError("persisted record digest mismatch")
    return record


def load_observation(path: str | Path) -> InkMarketObservationV0:
    return _load(path, InkMarketObservationV0.from_canonical)


def load_decision(path: str | Path) -> ShadowDecisionV0:
    return _load(path, ShadowDecisionV0.from_canonical)
