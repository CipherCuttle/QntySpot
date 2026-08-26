"""Bounded Robinhood Chain Stock Token V0D shadow adapter.

This module has one deliberately narrow purpose: read the current SPY Stock
Token identity from Robinhood's public registry, verify the identity and
oracle facts on Robinhood Chain, obtain one firm 0x Swap API quote, and emit
canonical shadow evidence.  It has no signing, submission, approval, or
capital surface.

All amounts are integer atomic units.  Human prices and multipliers are exact
``Fraction`` values.  External responses are captured before interpretation so
that a representational parser repair can be performed offline.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from .boundary import QuoteSource
from .canon import canonical_json_bytes, digest_object, format_canonical_decimal
from .domain import EconomicBounds, PolicyV0, QuoteV0, Side
from .economics import build_intent
from .errors import (
    LevelNotExecutableError,
    RobinhoodError,
    RobinhoodProtocolError,
    RobinhoodTransportError,
    SafeHaltError,
    ZeroXApiError,
    ZeroXApiKeyRequired,
)
from .raw_evidence import RawEvidenceRecord, RawEvidenceStore

__all__ = [
    "ROBINHOOD_CHAIN_ID",
    "ROBINHOOD_RPC_ENDPOINT",
    "ROBINHOOD_ASSETS_ENDPOINT",
    "ROBINHOOD_PRICES_ENDPOINT",
    "CHAINLINK_ROBINHOOD_FEED_DIRECTORY_ENDPOINT",
    "ZEROX_SWAP_V2_QUOTE_ENDPOINT",
    "SPY_SYMBOL",
    "USDG_ADDRESS",
    "validate_qualification_taker",
    "SEQUENCER_GRACE_PERIOD_S",
    "MAX_RPC_FUTURE_SKEW_S",
    "ZEROX_MAX_BLOCK_LAG",
    "RobinhoodAssetIdentityV0",
    "RobinhoodMarketObservationV0",
    "RobinhoodShadowDecisionV0",
    "RobinhoodRestClient",
    "RobinhoodRpcClient",
    "ChainlinkRobinhoodDirectoryClient",
    "ZeroXV2Client",
    "RobinhoodShadowAdapter",
    "replay_shadow_decision",
    "persist_identity",
    "persist_observation",
    "persist_decision",
    "load_identity",
    "load_observation",
    "load_decision",
    "RawEvidenceRecord",
    "RawEvidenceStore",
]

ROBINHOOD_CHAIN_ID = 4_663
ROBINHOOD_RPC_ENDPOINT = "https://rpc.mainnet.chain.robinhood.com"
ROBINHOOD_ASSETS_ENDPOINT = "https://api.robinhood.com/rhj/assets"
ROBINHOOD_PRICES_ENDPOINT = "https://api.robinhood.com/rhj/prices/{symbol}"
CHAINLINK_ROBINHOOD_FEED_DIRECTORY_ENDPOINT = (
    "https://reference-data-directory.vercel.app/feeds-robinhood-mainnet.json"
)
ZEROX_SWAP_V2_QUOTE_ENDPOINT = "https://api.0x.org/swap/allowance-holder/quote"
SPY_SYMBOL = "SPY"
USDG_ADDRESS = "0x5fc5360d0400a0fd4f2af552add042d716f1d168"
_HISTORICAL_SYNTHETIC_TAKER = "0x0000000000000000000000000000000000000001"
SEQUENCER_GRACE_PERIOD_S = 3_600
MAX_RPC_FUTURE_SKEW_S = 30
MULTIPLIER_SCALE = 10**18
REFERENCE_TOLERANCE_BPS = 500
ZEROX_MAX_BLOCK_LAG = 64
_BPS = 10_000
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_UID_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")
_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")
_INTEGER_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_MAX_UINT256 = (1 << 256) - 1


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise RobinhoodProtocolError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(value: str) -> Any:
    raise RobinhoodProtocolError(f"JSON constant {value!r} is not admissible")


def _parse_json(body: bytes, *, field: str, decimal_numbers: bool = False) -> Any:
    try:
        return json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_duplicate_reject,
            parse_float=Decimal if decimal_numbers else None,
            parse_constant=_reject_constant,
        )
    except Exception as exc:
        raise RobinhoodProtocolError(f"{field}: response is not strict JSON") from exc


def _address(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise RobinhoodProtocolError(f"{field}: malformed EVM address")
    normalized = value.lower()
    if int(normalized, 16) == 0:
        raise RobinhoodProtocolError(f"{field}: zero address is not admissible")
    return normalized


def validate_qualification_taker(value: Any) -> str:
    """Validate and preserve the operator-configured public EVM taker."""
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RobinhoodProtocolError("qualification taker is required")
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise RobinhoodProtocolError("qualification taker is a malformed EVM address")
    normalized = value.lower()
    if int(normalized, 16) == 0:
        raise RobinhoodProtocolError("qualification taker cannot be the zero address")
    if normalized == _HISTORICAL_SYNTHETIC_TAKER:
        raise RobinhoodProtocolError("qualification taker cannot be the historical synthetic sentinel")
    return value


def _address_or_zero(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise RobinhoodProtocolError(f"{field}: malformed EVM address")
    return value.lower()


def _uid(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _UID_RE.fullmatch(value):
        raise RobinhoodProtocolError(f"{field}: malformed bytes32 UID")
    return value.lower()


def _integer(value: Any, *, field: str, positive: bool = False, maximum: int = _MAX_UINT256) -> int:
    if not isinstance(value, str) or not _INTEGER_RE.fullmatch(value):
        raise RobinhoodProtocolError(f"{field}: expected canonical integer string")
    parsed = int(value)
    if positive and parsed <= 0:
        raise RobinhoodProtocolError(f"{field}: must be positive")
    if parsed > maximum:
        raise RobinhoodProtocolError(f"{field}: exceeds configured integer bound")
    return parsed


def _quantity(value: Any, *, field: str, maximum: int = _MAX_UINT256) -> int:
    if not isinstance(value, str) or not _QUANTITY_RE.fullmatch(value):
        raise RobinhoodProtocolError(f"{field}: malformed JSON-RPC quantity")
    parsed = int(value[2:], 16)
    if parsed > maximum:
        raise RobinhoodProtocolError(f"{field}: quantity exceeds bound")
    return parsed


def _bytes(value: Any, *, field: str, exact_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value) or len(value[2:]) % 2:
        raise RobinhoodProtocolError(f"{field}: malformed hex bytes")
    data = bytes.fromhex(value[2:])
    if exact_bytes is not None and len(data) != exact_bytes:
        raise RobinhoodProtocolError(f"{field}: expected exactly {exact_bytes} bytes")
    return data


def _word(data: bytes, index: int, *, field: str) -> int:
    start = index * 32
    end = start + 32
    if len(data) < end:
        raise RobinhoodProtocolError(f"{field}: ABI result ended before word {index}")
    return int.from_bytes(data[start:end], "big")


def _signed_word(data: bytes, index: int, *, field: str) -> int:
    raw = _word(data, index, field=field)
    return raw - (1 << 256) if raw >= (1 << 255) else raw


def _external_fraction(value: Any, *, field: str, positive: bool = False) -> Fraction:
    if not isinstance(value, str):
        raise RobinhoodProtocolError(f"{field}: expected decimal text")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise RobinhoodProtocolError(f"{field}: malformed decimal") from exc
    if not parsed.is_finite():
        raise RobinhoodProtocolError(f"{field}: decimal is not finite")
    result = Fraction(parsed)
    if positive and result <= 0:
        raise RobinhoodProtocolError(f"{field}: decimal must be positive")
    return result


def _decimal(value: Fraction, *, field: str) -> str:
    return format_canonical_decimal(value, field=field)


def _ratio(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _parse_ratio(value: Any, *, field: str) -> Fraction:
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise RobinhoodError(f"{field}: malformed exact ratio")
    numerator = value["numerator"]
    denominator = value["denominator"]
    if not isinstance(numerator, str) or not re.fullmatch(r"-?[0-9]+", numerator):
        raise RobinhoodError(f"{field}: malformed ratio numerator")
    if not isinstance(denominator, str) or not re.fullmatch(r"[1-9][0-9]*", denominator):
        raise RobinhoodError(f"{field}: malformed ratio denominator")
    return Fraction(int(numerator), int(denominator))


def _parse_rfc3339(value: Any, *, field: str) -> tuple[str, int]:
    if not isinstance(value, str) or not value:
        raise RobinhoodProtocolError(f"{field}: missing RFC-3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RobinhoodProtocolError(f"{field}: malformed RFC-3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise RobinhoodProtocolError(f"{field}: timestamp must include a timezone")
    utc = parsed.astimezone(timezone.utc)
    epoch = calendar.timegm(utc.utctimetuple())
    return value, epoch


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record_refs(records: tuple[RawEvidenceRecord, ...]) -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "record_digest": record.digest(),
            "request_sha256": record.request_sha256,
            "response_sha256": record.response_sha256,
        }
        for record in records
    )


def _share_equivalent_amount(raw_token_amount: int, multiplier: Fraction) -> int:
    """Convert raw-token atomic units without silently rounding corporate actions."""
    converted = raw_token_amount * multiplier
    if converted.denominator != 1:
        raise SafeHaltError("raw token amount is not exactly representable after multiplier conversion")
    return converted.numerator


def _validate_exact_keys(obj: Any, required: set[str], allowed: set[str], *, field: str) -> None:
    if not isinstance(obj, dict):
        raise RobinhoodProtocolError(f"{field}: expected an object")
    missing = required - set(obj)
    unknown = set(obj) - allowed
    if missing:
        raise RobinhoodProtocolError(f"{field}: missing fields {sorted(missing)}")
    if unknown:
        raise RobinhoodProtocolError(f"{field}: unknown fields {sorted(unknown)}")


class _HttpsJson:
    def __init__(
        self,
        endpoint: str,
        *,
        evidence_store: RawEvidenceStore | None = None,
        timeout_s: int = 15,
        max_retries: int = 1,
        max_response_bytes: int = 2_000_000,
        transport: Callable[..., bytes] | None = None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise RobinhoodError("HTTPS endpoint must not contain credentials")
        if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or timeout_s < 1:
            raise RobinhoodError("timeout_s must be a positive integer")
        if not isinstance(max_retries, int) or isinstance(max_retries, bool) or not 0 <= max_retries <= 3:
            raise RobinhoodError("max_retries must be in [0, 3]")
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool) or max_response_bytes < 256:
            raise RobinhoodError("max_response_bytes must be at least 256")
        if evidence_store is not None and not isinstance(evidence_store, RawEvidenceStore):
            raise RobinhoodError("evidence_store must be a RawEvidenceStore")
        self.endpoint = endpoint
        self.evidence_store = evidence_store
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.max_response_bytes = max_response_bytes
        self.transport = transport
        self.records: list[RawEvidenceRecord] = []
        self.read_count = 0
        self.opener = build_opener(ProxyHandler({}))

    def _capture(self, *, target: str, body: bytes, request_body: bytes | None) -> None:
        if len(body) > self.max_response_bytes:
            raise RobinhoodTransportError(f"response from {self.endpoint} exceeds byte bound")
        if self.evidence_store is not None:
            self.records.append(
                self.evidence_store.capture(
                    endpoint=self.endpoint,
                    method="GET" if request_body is None else "POST",
                    request_target=target,
                    request_body=request_body,
                    response_body=body,
                )
            )

    def get(
        self,
        params: Mapping[str, str],
        *,
        headers: Mapping[str, str] | None = None,
        forbidden_response_substrings: tuple[bytes, ...] = (),
    ) -> bytes:
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in params.items()):
            raise RobinhoodError("query parameters must be strings")
        query = urlencode(sorted(params.items()))
        target = self.endpoint + ("&" if "?" in self.endpoint else "?") + query
        last: Exception | None = None
        for _ in range(self.max_retries + 1):
            try:
                self.read_count += 1
                if self.transport is not None:
                    try:
                        body = self.transport(target, query.encode("ascii"), headers or {})
                    except TypeError:
                        body = self.transport(target, query.encode("ascii"))
                else:
                    request_headers = {
                        "accept": "application/json",
                        "user-agent": "qntyspot-v0d-robinhood-shadow/1",
                    }
                    if headers:
                        request_headers.update(headers)
                    request = Request(target, headers=request_headers, method="GET")
                    with self.opener.open(request, timeout=self.timeout_s) as response:
                        body = response.read(self.max_response_bytes + 1)
                if not isinstance(body, bytes):
                    raise RobinhoodTransportError("transport returned non-bytes")
                if any(secret and secret in body for secret in forbidden_response_substrings):
                    raise SafeHaltError("forbidden request secret appeared in an external response")
                self._capture(target=target, body=body, request_body=None)
                return body
            except HTTPError as exc:
                try:
                    error_body = exc.read(self.max_response_bytes + 1)
                except OSError:
                    error_body = b""
                if not isinstance(error_body, bytes):
                    error_body = b""
                if any(secret and secret in error_body for secret in forbidden_response_substrings):
                    raise SafeHaltError("forbidden request secret appeared in an external error response")
                self._capture(target=target, body=error_body, request_body=None)
                last = exc
                if exc.code not in (408, 429) and not 500 <= exc.code <= 599:
                    break
            except (TimeoutError, URLError, OSError, RobinhoodTransportError) as exc:
                last = exc
        raise RobinhoodTransportError(f"bounded GET failed for {self.endpoint}") from last


class RobinhoodRestClient:
    """Strict public Robinhood REST reader."""

    def __init__(self, *, evidence_store: RawEvidenceStore | None = None, transport: Callable[..., bytes] | None = None) -> None:
        self.assets_http = _HttpsJson(ROBINHOOD_ASSETS_ENDPOINT, evidence_store=evidence_store, transport=transport)
        self.prices_http = _HttpsJson(ROBINHOOD_PRICES_ENDPOINT.format(symbol="SPY"), evidence_store=evidence_store, transport=transport)

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return tuple(self.assets_http.records + self.prices_http.records)

    def asset(self, symbol: str) -> dict[str, Any]:
        body = self.assets_http.get({})
        root = _parse_json(body, field="Robinhood /assets")
        _validate_exact_keys(root, {"assets"}, {"assets"}, field="Robinhood /assets")
        assets = root["assets"]
        if not isinstance(assets, list):
            raise RobinhoodProtocolError("Robinhood /assets: assets must be a list")
        candidates = [item for item in assets if isinstance(item, dict) and item.get("tokenSymbol") == symbol]
        if len(candidates) != 1:
            raise SafeHaltError(f"Robinhood asset {symbol!r} is absent or ambiguous")
        item = candidates[0]
        allowed = {
            "id", "tokenSymbol", "tokenName", "deployments", "currentMultiplier",
            "pendingMultiplier", "pendingMultiplierEffectiveTime", "logoUrl",
            "tradingCapabilities", "status", "tokenDecimals", "isin",
        }
        required = {
            "id", "tokenSymbol", "tokenName", "deployments", "currentMultiplier",
            "pendingMultiplier", "tradingCapabilities", "status", "tokenDecimals",
        }
        _validate_exact_keys(item, required, allowed, field="Robinhood /assets asset")
        if not isinstance(item["tokenSymbol"], str) or item["tokenSymbol"] != symbol:
            raise RobinhoodProtocolError("Robinhood /assets token symbol mismatch")
        if not isinstance(item["tokenName"], str) or not item["tokenName"]:
            raise RobinhoodProtocolError("Robinhood /assets token name is malformed")
        deployments = item["deployments"]
        if not isinstance(deployments, list):
            raise RobinhoodProtocolError("Robinhood /assets deployments must be a list")
        selected: list[dict[str, Any]] = []
        for index, deployment in enumerate(deployments):
            _validate_exact_keys(
                deployment,
                {"contractAddress", "chainId"},
                {"contractAddress", "chainId", "networkName"},
                field=f"Robinhood deployment {index}",
            )
            if not isinstance(deployment["chainId"], int) or isinstance(deployment["chainId"], bool):
                raise RobinhoodProtocolError("Robinhood deployment chainId is malformed")
            if deployment["chainId"] == ROBINHOOD_CHAIN_ID:
                selected.append(deployment)
        if len(selected) != 1:
            raise SafeHaltError(f"{symbol}: chain {ROBINHOOD_CHAIN_ID} deployment is absent or ambiguous")
        if not isinstance(item["status"], str) or not item["status"]:
            raise RobinhoodProtocolError("Robinhood asset status is malformed")
        if not isinstance(item["tradingCapabilities"], dict):
            raise RobinhoodProtocolError("Robinhood tradingCapabilities is malformed")
        if not isinstance(item["tokenDecimals"], int) or isinstance(item["tokenDecimals"], bool) or not 0 <= item["tokenDecimals"] <= 36:
            raise RobinhoodProtocolError("Robinhood tokenDecimals is malformed")
        current = _external_fraction(item["currentMultiplier"], field="currentMultiplier", positive=True)
        pending_raw = item["pendingMultiplier"]
        if not isinstance(pending_raw, str):
            raise RobinhoodProtocolError("pendingMultiplier must be text")
        pending = None if pending_raw == "" else _external_fraction(pending_raw, field="pendingMultiplier", positive=True)
        pending_time = None
        pending_time_raw = item.get("pendingMultiplierEffectiveTime")
        if pending_raw == "" and pending_time_raw is not None:
            raise RobinhoodProtocolError("pending effective time exists without pending multiplier")
        if pending_raw != "":
            if pending_time_raw is None:
                raise RobinhoodProtocolError("pending multiplier has no effective time")
            _, pending_time = _parse_rfc3339(pending_time_raw, field="pendingMultiplierEffectiveTime")
        return {
            "asset_uid": _uid(item["id"], field="asset id"),
            "token_symbol": symbol,
            "token_name": item["tokenName"],
            "token_address": _address(selected[0]["contractAddress"], field="asset deployment"),
            "token_decimals": item["tokenDecimals"],
            "current_multiplier": current,
            "pending_multiplier": pending,
            "pending_effective_at_epoch_s": pending_time,
            "status": item["status"],
            "trading_capabilities": item["tradingCapabilities"],
            "rest_asset_raw": item,
        }

    def price(self, symbol: str, token_address: str) -> dict[str, Any]:
        body = self.prices_http.get({}) if symbol == "SPY" else _HttpsJson(
            ROBINHOOD_PRICES_ENDPOINT.format(symbol=symbol), evidence_store=self.assets_http.evidence_store
        ).get({})
        root = _parse_json(body, field=f"Robinhood /prices/{symbol}")
        _validate_exact_keys(root, {"quotes"}, {"quotes"}, field="Robinhood prices")
        quotes = root["quotes"]
        if not isinstance(quotes, list):
            raise RobinhoodProtocolError("Robinhood prices quotes must be a list")
        candidates = [item for item in quotes if isinstance(item, dict) and item.get("tokenSymbol") == symbol]
        if len(candidates) != 1:
            raise SafeHaltError(f"Robinhood price {symbol!r} is absent or ambiguous")
        item = candidates[0]
        allowed = {
            "tokenSymbol", "deployments", "bid", "ask", "currency", "dailyTradingVolume",
            "isTradingHalt", "generatedAt", "dailyHigh", "dailyLow", "mintBurnTokenVolume",
            "mintBurnUsdVolume",
        }
        _validate_exact_keys(
            item,
            {"tokenSymbol", "deployments", "bid", "ask", "currency", "isTradingHalt", "generatedAt"},
            allowed,
            field="Robinhood price quote",
        )
        deployments = item["deployments"]
        if not isinstance(deployments, list):
            raise RobinhoodProtocolError("Robinhood price deployments must be a list")
        matching = [
            deployment
            for deployment in deployments
            if isinstance(deployment, dict)
            and deployment.get("chainId") == ROBINHOOD_CHAIN_ID
            and isinstance(deployment.get("contractAddress"), str)
            and deployment["contractAddress"].lower() == token_address.lower()
        ]
        if len(matching) != 1:
            raise SafeHaltError("Robinhood price deployment does not match the resolved asset")
        if item["currency"] != "USD" or not isinstance(item["isTradingHalt"], bool):
            raise RobinhoodProtocolError("Robinhood price currency or trading halt is malformed")
        bid = _external_fraction(item["bid"], field="REST bid", positive=True)
        ask = _external_fraction(item["ask"], field="REST ask", positive=True)
        if ask < bid:
            raise RobinhoodProtocolError("REST ask is below bid")
        generated_raw, generated_epoch = _parse_rfc3339(item["generatedAt"], field="REST generatedAt")
        return {
            "raw_bid": bid,
            "raw_ask": ask,
            "generated_at": generated_raw,
            "generated_at_epoch_s": generated_epoch,
            "is_trading_halt": item["isTradingHalt"],
            "price_raw": item,
        }


class RobinhoodRpcClient:
    """Bounded JSON-RPC reads for the Robinhood Chain."""

    _METHODS = frozenset({"eth_chainId", "eth_getCode", "eth_call", "eth_getBlockByNumber"})

    def __init__(self, endpoint: str = ROBINHOOD_RPC_ENDPOINT, *, evidence_store: RawEvidenceStore | None = None, transport: Callable[[bytes], bytes] | None = None) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise RobinhoodError("RPC endpoint must be HTTPS without credentials")
        self.endpoint = endpoint
        self.evidence_store = evidence_store
        self.transport = transport
        self.records: list[RawEvidenceRecord] = []
        self.read_count = 0
        self.opener = build_opener(ProxyHandler({}))

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return tuple(self.records)

    def request(self, method: str, params: list[Any]) -> Any:
        if method not in self._METHODS:
            raise RobinhoodError(f"RPC method is outside the read allowlist: {method}")
        payload = canonical_json_bytes({"id": 1, "jsonrpc": "2.0", "method": method, "params": params})
        try:
            self.read_count += 1
            if self.transport is not None:
                body = self.transport(payload)
            else:
                request = Request(
                    self.endpoint,
                    data=payload,
                    headers={"accept": "application/json", "content-type": "application/json", "user-agent": "qntyspot-v0d-robinhood-shadow/1"},
                    method="POST",
                )
                with self.opener.open(request, timeout=15) as response:
                    body = response.read(2_000_001)
        except (TimeoutError, URLError, OSError) as exc:
            raise RobinhoodTransportError(f"RPC transport failed for {method}") from exc
        if not isinstance(body, bytes):
            raise RobinhoodTransportError("RPC transport returned non-bytes")
        if len(body) > 2_000_000:
            raise RobinhoodTransportError("RPC response exceeds byte bound")
        if self.evidence_store is not None:
            self.records.append(
                self.evidence_store.capture(
                    endpoint=self.endpoint,
                    method="POST",
                    request_target=self.endpoint,
                    request_body=payload,
                    response_body=body,
                )
            )
        response = _parse_json(body, field=f"RPC {method}")
        _validate_exact_keys(response, {"id", "jsonrpc"}, {"id", "jsonrpc", "result", "error"}, field=f"RPC {method}")
        if response["id"] != 1 or response["jsonrpc"] != "2.0":
            raise RobinhoodProtocolError(f"RPC {method}: response envelope mismatch")
        if "error" in response:
            raise RobinhoodProtocolError(f"RPC {method}: returned an error")
        if "result" not in response:
            raise RobinhoodProtocolError(f"RPC {method}: missing result")
        return response["result"]

    def chain_id(self) -> int:
        return _quantity(self.request("eth_chainId", []), field="eth_chainId")

    def code(self, address: str) -> bytes:
        address = _address(address, field="eth_getCode.address")
        result = self.request("eth_getCode", [address, "latest"])
        code = _bytes(result, field="eth_getCode.result")
        if not code:
            raise SafeHaltError(f"no bytecode at {address}")
        return code

    def call(self, address: str, data: str) -> bytes:
        address = _address(address, field="eth_call.to")
        _bytes(data, field="eth_call.data")
        return _bytes(self.request("eth_call", [{"to": address, "data": data}, "latest"]), field="eth_call.result")

    def latest_block(self) -> tuple[int, int]:
        result = self.request("eth_getBlockByNumber", ["latest", False])
        if not isinstance(result, dict) or "number" not in result or "timestamp" not in result:
            raise RobinhoodProtocolError("latest block result lacks number or timestamp")
        return _quantity(result["number"], field="latest block number"), _quantity(result["timestamp"], field="latest block timestamp")


class ChainlinkRobinhoodDirectoryClient:
    """Resolves the current feed proxy and heartbeat from Chainlink's directory."""

    def __init__(self, *, evidence_store: RawEvidenceStore | None = None, transport: Callable[..., bytes] | None = None) -> None:
        self.http = _HttpsJson(CHAINLINK_ROBINHOOD_FEED_DIRECTORY_ENDPOINT, evidence_store=evidence_store, transport=transport)

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return tuple(self.http.records)

    def resolve(self, symbol: str) -> dict[str, Any]:
        body = self.http.get({})
        root = _parse_json(body, field="Chainlink Robinhood feed directory", decimal_numbers=True)
        if not isinstance(root, list):
            raise RobinhoodProtocolError("Chainlink feed directory must be a list")
        candidates = [item for item in root if isinstance(item, dict) and item.get("name") == f"Robinhood {symbol} / USD"]
        if len(candidates) != 1:
            raise SafeHaltError(f"Chainlink feed for {symbol} is absent or ambiguous")
        item = candidates[0]
        allowed = {
            "compareOffchain", "contractAddress", "contractType", "contractVersion", "decimalPlaces",
            "ens", "formatDecimalPlaces", "healthPrice", "heartbeat", "history", "maxSubmissionValue",
            "multiply", "name", "pair", "path", "proxyAddress", "secondaryProxyAddress", "threshold",
            "valuePrefix", "assetName", "feedCategory", "feedType", "docs",
        }
        required = {"contractAddress", "contractVersion", "heartbeat", "name", "path", "proxyAddress", "decimals", "docs"}
        allowed.add("decimals")
        _validate_exact_keys(item, required, allowed, field="Chainlink Robinhood feed entry")
        if item["name"] != f"Robinhood {symbol} / USD" or item["contractVersion"] != 6:
            raise RobinhoodProtocolError("Chainlink feed directory entry identity is malformed")
        if not isinstance(item["heartbeat"], int) or isinstance(item["heartbeat"], bool) or item["heartbeat"] <= 0:
            raise RobinhoodProtocolError("Chainlink feed heartbeat is malformed")
        if not isinstance(item["decimals"], int) or isinstance(item["decimals"], bool) or not 0 <= item["decimals"] <= 36:
            raise RobinhoodProtocolError("Chainlink feed decimals are malformed")
        docs = item["docs"]
        if not isinstance(docs, dict):
            raise RobinhoodProtocolError("Chainlink feed docs are malformed")
        if not isinstance(item["path"], str) or not item["path"]:
            raise RobinhoodProtocolError("Chainlink feed path is malformed")
        return {
            "feed_proxy": _address(item["proxyAddress"], field="Chainlink proxy"),
            "feed_contract": _address(item["contractAddress"], field="Chainlink aggregator"),
            "feed_heartbeat_s": item["heartbeat"],
            "feed_decimals": item["decimals"],
            "feed_directory_entry": item,
        }


class ZeroXV2Client:
    """Read-only firm quote client for 0x Swap API v2 AllowanceHolder."""

    def __init__(self, *, api_key: str | None, endpoint: str = ZEROX_SWAP_V2_QUOTE_ENDPOINT, evidence_store: RawEvidenceStore | None = None, transport: Callable[..., bytes] | None = None) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc:
            raise RobinhoodError("0x endpoint must be HTTPS")
        if api_key is not None and (not isinstance(api_key, str) or not api_key.strip()):
            raise ZeroXApiKeyRequired("0x read credential is empty")
        self.api_key = api_key
        self.http = _HttpsJson(endpoint, evidence_store=evidence_store, max_retries=0, transport=transport)

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return tuple(self.http.records)

    def quote(
        self,
        *,
        sell_token: str,
        buy_token: str,
        sell_amount_atomic: int,
        taker: str | None,
        slippage_bps: int,
        policy_min_output_atomic: int,
    ) -> dict[str, Any]:
        taker = validate_qualification_taker(taker)
        if self.api_key is None:
            raise ZeroXApiKeyRequired("0x read credential is required for a firm quote")
        sell_token = _address(sell_token, field="0x sellToken")
        buy_token = _address(buy_token, field="0x buyToken")
        if not isinstance(sell_amount_atomic, int) or isinstance(sell_amount_atomic, bool) or sell_amount_atomic <= 0:
            raise RobinhoodError("0x sell amount must be positive")
        if not isinstance(slippage_bps, int) or isinstance(slippage_bps, bool) or not 0 <= slippage_bps <= _BPS:
            raise RobinhoodError("0x slippage must be in [0, 10000]")
        if not isinstance(policy_min_output_atomic, int) or policy_min_output_atomic <= 0:
            raise RobinhoodError("policy output bound must be positive")
        params = {
            "buyToken": buy_token,
            "chainId": str(ROBINHOOD_CHAIN_ID),
            "sellAmount": str(sell_amount_atomic),
            "sellToken": sell_token,
            "slippageBps": str(slippage_bps),
            "taker": taker,
        }
        body = self.http.get(
            params,
            headers={"0x-api-key": self.api_key, "0x-version": "v2"},
            forbidden_response_substrings=(self.api_key.encode("utf-8"),),
        )
        raw = _parse_json(body, field="0x Swap API v2 quote")
        allowed = {
            "allowanceTarget", "blockNumber", "buyAmount", "buyToken", "fees", "issues",
            "liquidityAvailable", "minBuyAmount", "mode", "route", "sellAmount", "sellToken",
            "tokenMetadata", "totalNetworkFee", "zid", "transaction",
        }
        _validate_exact_keys(raw, allowed, allowed, field="0x quote")
        if raw["mode"] != "exact-in":
            raise SafeHaltError("0x quote is not an exact-in quote")
        if raw["liquidityAvailable"] is not True:
            raise SafeHaltError("0x quote is not an executable exact-in quote")
        if _address(raw["sellToken"], field="0x response sellToken") != sell_token:
            raise SafeHaltError("0x response sell token mismatch")
        if _address(raw["buyToken"], field="0x response buyToken") != buy_token:
            raise SafeHaltError("0x response buy token mismatch")
        returned_sell = _integer(raw["sellAmount"], field="0x response sellAmount", positive=True)
        returned_buy = _integer(raw["buyAmount"], field="0x response buyAmount", positive=True)
        if returned_sell != sell_amount_atomic:
            raise SafeHaltError("0x response sell amount mismatch")
        venue_min = None if raw["minBuyAmount"] is None else _integer(raw["minBuyAmount"], field="0x response minBuyAmount", positive=True)
        if venue_min is not None and venue_min < policy_min_output_atomic:
            raise SafeHaltError("0x venue minimum output is looser than PolicyV0")
        allowance_target = _address(raw["allowanceTarget"], field="0x allowanceTarget")
        spender = None
        issues = raw["issues"]
        if not isinstance(issues, dict):
            raise RobinhoodProtocolError("0x issues must be an object")
        _validate_exact_keys(issues, set(), {"allowance", "balance", "simulationIncomplete", "invalidSourcesPassed"}, field="0x issues")
        allowance = issues.get("allowance")
        if allowance is not None:
            _validate_exact_keys(allowance, {"actual", "spender"}, {"actual", "spender"}, field="0x issues.allowance")
            spender = _address(allowance["spender"], field="0x issues.allowance.spender")
            if spender != allowance_target:
                raise SafeHaltError("0x allowance spender disagrees with allowanceTarget")
        if issues.get("simulationIncomplete", False) is not False or issues.get("invalidSourcesPassed", []) != []:
            raise SafeHaltError("0x quote reports incomplete simulation or invalid sources")
        balance = issues.get("balance")
        if balance is not None:
            _validate_exact_keys(balance, {"token", "actual", "expected"}, {"token", "actual", "expected"}, field="0x issues.balance")
            _address(balance["token"], field="0x issues.balance.token")
            _integer(balance["actual"], field="0x issues.balance.actual")
            _integer(balance["expected"], field="0x issues.balance.expected", positive=True)
        route = raw["route"]
        if not isinstance(route, dict):
            raise RobinhoodProtocolError("0x route must be an object")
        _validate_exact_keys(route, {"fills", "tokens"}, {"fills", "tokens"}, field="0x route")
        fills = route["fills"]
        tokens = route["tokens"]
        if not isinstance(fills, list) or not fills:
            raise RobinhoodProtocolError("0x route fills are empty")
        if not isinstance(tokens, list) or not tokens:
            raise RobinhoodProtocolError("0x route tokens are empty")
        fill_records: list[dict[str, Any]] = []
        proportions: list[int] = []
        for index, fill in enumerate(fills):
            _validate_exact_keys(fill, {"from", "to", "source", "proportionBps"}, {"from", "to", "source", "proportionBps"}, field=f"0x route fill {index}")
            from_token = _address(fill["from"], field=f"0x route fill {index}.from")
            to_token = _address(fill["to"], field=f"0x route fill {index}.to")
            if not isinstance(fill["source"], str) or not fill["source"] or len(fill["source"]) > 128:
                raise RobinhoodProtocolError("0x route source is malformed")
            proportion = fill["proportionBps"]
            if proportion is not None:
                proportion = _integer(proportion, field="0x route proportionBps", maximum=_BPS)
                proportions.append(proportion)
            fill_records.append({"from": from_token, "to": to_token, "source": fill["source"], "proportion_bps": proportion})
        if proportions and sum(proportions) != _BPS:
            raise SafeHaltError("0x route proportions do not sum to 10000")
        token_records: list[dict[str, str]] = []
        for index, token in enumerate(tokens):
            _validate_exact_keys(token, {"address", "symbol"}, {"address", "symbol"}, field=f"0x route token {index}")
            token_records.append({"address": _address(token["address"], field=f"0x route token {index}.address"), "symbol": token["symbol"] if isinstance(token["symbol"], str) else ""})
            if not token_records[-1]["symbol"]:
                raise RobinhoodProtocolError("0x route token symbol is malformed")
        if fill_records[0]["from"] != sell_token or fill_records[-1]["to"] != buy_token:
            raise SafeHaltError("0x route endpoints do not match the quote pair")
        transaction = raw["transaction"]
        if not isinstance(transaction, dict):
            raise RobinhoodProtocolError("0x transaction must be an object")
        _validate_exact_keys(transaction, {"to", "data", "gas", "gasPrice", "value"}, {"to", "data", "gas", "gasPrice", "value"}, field="0x transaction")
        tx_to = _address(transaction["to"], field="0x transaction.to")
        tx_data = _bytes(transaction["data"], field="0x transaction.data")
        if not tx_data or len(tx_data) > 1_000_000:
            raise RobinhoodProtocolError("0x transaction calldata is empty or oversized")
        tx_value = _integer(transaction["value"], field="0x transaction.value")
        if tx_value != 0:
            raise SafeHaltError("0x quote unexpectedly requires native value")
        for name in ("gas", "gasPrice"):
            if transaction[name] is not None:
                _integer(transaction[name], field=f"0x transaction.{name}")
        block_number = None if raw["blockNumber"] is None else _integer(raw["blockNumber"], field="0x blockNumber", positive=True)
        zid = raw["zid"]
        if not isinstance(zid, str) or not zid or len(zid) > 128:
            raise RobinhoodProtocolError("0x zid is malformed")
        return {
            "sell_token": sell_token,
            "buy_token": buy_token,
            "sell_amount_atomic": returned_sell,
            "buy_amount_atomic": returned_buy,
            "venue_min_output_atomic": venue_min,
            "allowance_target": allowance_target,
            "allowance_spender": spender,
            "block_number": block_number,
            "route_fills": tuple(fill_records),
            "route_tokens": tuple(token_records),
            "route_sources": tuple(item["source"] for item in fill_records),
            "route_digest": digest_object({"fills": fill_records, "tokens": token_records}),
            "transaction_to": tx_to,
            "transaction_value_atomic": tx_value,
            "transaction_data_sha256": _sha256(tx_data),
            "zid": zid,
        }


@dataclass(frozen=True, slots=True)
class RobinhoodAssetIdentityV0:
    schema: str
    chain_id: int
    asset_uid: str
    token_symbol: str
    token_name: str
    stock_token_address: str
    token_decimals: int
    current_multiplier: Fraction
    pending_multiplier: Fraction | None
    pending_multiplier_effective_at_epoch_s: int | None
    status: str
    trading_capabilities: Mapping[str, Any]
    onchain_uid: str
    onchain_decimals: int
    onchain_ui_multiplier: Fraction
    onchain_new_ui_multiplier: Fraction
    onchain_effective_at_epoch_s: int
    oracle_paused: bool
    stock_token_bytecode_sha256: str
    stock_token_bytecode_length: int
    usdg_address: str
    usdg_decimals: int
    usdg_bytecode_sha256: str
    usdg_bytecode_length: int
    raw_evidence: tuple[Mapping[str, str], ...]

    def __post_init__(self) -> None:
        if self.schema != "ROBINHOOD_ASSET_IDENTITY_V0" or self.chain_id != ROBINHOOD_CHAIN_ID:
            raise RobinhoodError("asset identity schema or chain mismatch")
        _uid(self.asset_uid, field="asset_uid")
        _uid(self.onchain_uid, field="onchain_uid")
        _address(self.stock_token_address, field="stock_token_address")
        _address(self.usdg_address, field="usdg_address")
        if self.asset_uid != self.onchain_uid or self.token_decimals != self.onchain_decimals:
            raise SafeHaltError("Robinhood asset identity disagrees with onchain identity")
        if self.current_multiplier != self.onchain_ui_multiplier:
            raise SafeHaltError("Robinhood currentMultiplier disagrees with uiMultiplier")
        if self.onchain_ui_multiplier <= 0 or self.onchain_new_ui_multiplier <= 0:
            raise SafeHaltError("Stock Token multiplier must be positive")
        if not isinstance(self.oracle_paused, bool) or self.stock_token_bytecode_length <= 0 or self.usdg_bytecode_length <= 0:
            raise RobinhoodError("asset bytecode or pause state is malformed")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "asset_uid": self.asset_uid,
            "chain_id": self.chain_id,
            "current_multiplier": _decimal(self.current_multiplier, field="current_multiplier"),
            "onchain_decimals": self.onchain_decimals,
            "onchain_effective_at_epoch_s": self.onchain_effective_at_epoch_s,
            "onchain_new_ui_multiplier": _decimal(self.onchain_new_ui_multiplier, field="onchain_new_ui_multiplier"),
            "onchain_uid": self.onchain_uid,
            "onchain_ui_multiplier": _decimal(self.onchain_ui_multiplier, field="onchain_ui_multiplier"),
            "oracle_paused": self.oracle_paused,
            "pending_multiplier": None if self.pending_multiplier is None else _decimal(self.pending_multiplier, field="pending_multiplier"),
            "pending_multiplier_effective_at_epoch_s": self.pending_multiplier_effective_at_epoch_s,
            "raw_evidence": [dict(item) for item in self.raw_evidence],
            "schema": self.schema,
            "status": self.status,
            "stock_token_address": self.stock_token_address,
            "stock_token_bytecode_length": self.stock_token_bytecode_length,
            "stock_token_bytecode_sha256": self.stock_token_bytecode_sha256,
            "token_decimals": self.token_decimals,
            "token_name": self.token_name,
            "token_symbol": self.token_symbol,
            "trading_capabilities": dict(self.trading_capabilities),
            "usdg_address": self.usdg_address,
            "usdg_bytecode_length": self.usdg_bytecode_length,
            "usdg_bytecode_sha256": self.usdg_bytecode_sha256,
            "usdg_decimals": self.usdg_decimals,
        }

    def digest(self) -> str:
        return digest_object(self.canonical_object())

    @classmethod
    def from_canonical(cls, obj: Any) -> "RobinhoodAssetIdentityV0":
        required = {
            "asset_uid", "chain_id", "current_multiplier", "onchain_decimals", "onchain_effective_at_epoch_s",
            "onchain_new_ui_multiplier", "onchain_uid", "onchain_ui_multiplier", "oracle_paused", "pending_multiplier",
            "pending_multiplier_effective_at_epoch_s", "raw_evidence", "schema", "status", "stock_token_address",
            "stock_token_bytecode_length", "stock_token_bytecode_sha256", "token_decimals", "token_name", "token_symbol",
            "trading_capabilities", "usdg_address", "usdg_bytecode_length", "usdg_bytecode_sha256", "usdg_decimals",
        }
        _validate_exact_keys(obj, required, required, field="asset identity")
        pending = None if obj["pending_multiplier"] is None else _external_fraction(obj["pending_multiplier"], field="pending_multiplier", positive=True)
        evidence = obj["raw_evidence"]
        if not isinstance(evidence, list) or any(not isinstance(item, dict) for item in evidence):
            raise RobinhoodError("asset identity raw evidence is malformed")
        return cls(
            schema=obj["schema"], chain_id=obj["chain_id"], asset_uid=obj["asset_uid"], token_symbol=obj["token_symbol"],
            token_name=obj["token_name"], stock_token_address=obj["stock_token_address"], token_decimals=obj["token_decimals"],
            current_multiplier=_external_fraction(obj["current_multiplier"], field="current_multiplier", positive=True), pending_multiplier=pending,
            pending_multiplier_effective_at_epoch_s=obj["pending_multiplier_effective_at_epoch_s"], status=obj["status"],
            trading_capabilities=obj["trading_capabilities"], onchain_uid=obj["onchain_uid"], onchain_decimals=obj["onchain_decimals"],
            onchain_ui_multiplier=_external_fraction(obj["onchain_ui_multiplier"], field="onchain_ui_multiplier", positive=True),
            onchain_new_ui_multiplier=_external_fraction(obj["onchain_new_ui_multiplier"], field="onchain_new_ui_multiplier", positive=True),
            onchain_effective_at_epoch_s=obj["onchain_effective_at_epoch_s"], oracle_paused=obj["oracle_paused"],
            stock_token_bytecode_sha256=obj["stock_token_bytecode_sha256"], stock_token_bytecode_length=obj["stock_token_bytecode_length"],
            usdg_address=obj["usdg_address"], usdg_decimals=obj["usdg_decimals"], usdg_bytecode_sha256=obj["usdg_bytecode_sha256"],
            usdg_bytecode_length=obj["usdg_bytecode_length"], raw_evidence=tuple(evidence),
        )


@dataclass(frozen=True, slots=True)
class RobinhoodMarketObservationV0:
    schema: str
    observation_time_epoch_s: int
    chain_id: int
    chain_block_number: int
    rpc_block_timestamp_epoch_s: int
    rpc_future_skew_s: int
    max_rpc_future_skew_s: int
    identity_digest: str
    asset_uid: str
    stock_token_address: str
    token_decimals: int
    usdg_address: str
    usdg_decimals: int
    raw_token_amount: int
    ui_multiplier: Fraction
    share_equivalent_amount: int
    pending_multiplier: Fraction | None
    pending_multiplier_effective_at_epoch_s: int | None
    oracle_paused: bool
    status: str
    trading_capabilities: Mapping[str, Any]
    rest_generated_at: str
    rest_generated_at_epoch_s: int
    rest_raw_bid: Fraction
    rest_raw_ask: Fraction
    token_reference_bid: Fraction
    token_reference_ask: Fraction
    rest_is_trading_halt: bool
    chainlink_feed_proxy: str
    chainlink_feed_decimals: int
    chainlink_feed_heartbeat_s: int
    chainlink_feed_answer: int
    chainlink_feed_updated_at_epoch_s: int
    chainlink_feed_round_id: int
    chainlink_feed_answered_in_round: int
    sequencer_feed_proxy: str | None
    sequencer_answer: int | None
    sequencer_started_at_epoch_s: int | None
    sequencer_status: str
    sequencer_grace_period_s: int
    zero_x_sell_token: str
    zero_x_buy_token: str
    zero_x_sell_amount: int
    zero_x_buy_amount: int
    zero_x_min_buy_amount: int | None
    zero_x_allowance_target: str
    zero_x_allowance_spender: str | None
    zero_x_block_number: int | None
    zero_x_route_sources: tuple[str, ...]
    zero_x_route_digest: str
    zero_x_transaction_to: str
    zero_x_transaction_value_atomic: int
    zero_x_transaction_data_sha256: str
    reference_deviation_rest_chainlink_bps: Fraction
    reference_deviation_zero_x_chainlink_bps: Fraction
    reference_tolerance_bps: int
    raw_evidence: tuple[Mapping[str, str], ...]

    def __post_init__(self) -> None:
        if self.schema != "ROBINHOOD_MARKET_OBSERVATION_V0" or self.chain_id != ROBINHOOD_CHAIN_ID:
            raise RobinhoodError("market observation schema or chain mismatch")
        integer_fields = (
            self.observation_time_epoch_s,
            self.chain_block_number,
            self.rpc_block_timestamp_epoch_s,
            self.rpc_future_skew_s,
            self.max_rpc_future_skew_s,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in integer_fields):
            raise RobinhoodError("observation timestamps or skew are malformed")
        if self.rpc_future_skew_s != self.rpc_block_timestamp_epoch_s - self.observation_time_epoch_s:
            raise SafeHaltError("RPC future skew does not match the captured timestamps")
        if self.max_rpc_future_skew_s != MAX_RPC_FUTURE_SKEW_S:
            raise SafeHaltError("RPC future-skew bound is not the V0D shadow bound")
        if self.rpc_future_skew_s > self.max_rpc_future_skew_s:
            raise SafeHaltError("RPC block timestamp exceeds the bounded future skew")
        _address(self.stock_token_address, field="stock_token_address")
        _address(self.usdg_address, field="usdg_address")
        _address(self.chainlink_feed_proxy, field="chainlink_feed_proxy")
        if self.sequencer_feed_proxy is not None:
            _address(self.sequencer_feed_proxy, field="sequencer_feed_proxy")
        if not isinstance(self.token_decimals, int) or isinstance(self.token_decimals, bool) or not 0 <= self.token_decimals <= 36:
            raise RobinhoodError("Stock Token decimals are malformed")
        if not isinstance(self.usdg_decimals, int) or isinstance(self.usdg_decimals, bool) or not 0 <= self.usdg_decimals <= 36:
            raise RobinhoodError("USDG decimals are malformed")
        if self.raw_token_amount <= 0 or self.share_equivalent_amount <= 0:
            raise RobinhoodError("Stock Token amount semantics are not positive")
        if self.ui_multiplier <= 0 or self.chainlink_feed_answer <= 0:
            raise RobinhoodError("multiplier or Chainlink answer is not positive")
        if self.rest_raw_bid <= 0 or self.rest_raw_ask < self.rest_raw_bid:
            raise RobinhoodError("REST price range is malformed")
        if self.zero_x_sell_amount <= 0 or self.zero_x_buy_amount <= 0:
            raise RobinhoodError("0x amounts are not positive")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "asset_uid": self.asset_uid, "chain_block_number": self.chain_block_number,
            "chain_id": self.chain_id,
            "chainlink_feed_answer": str(self.chainlink_feed_answer), "chainlink_feed_answered_in_round": str(self.chainlink_feed_answered_in_round),
            "chainlink_feed_decimals": self.chainlink_feed_decimals, "chainlink_feed_heartbeat_s": self.chainlink_feed_heartbeat_s,
            "chainlink_feed_proxy": self.chainlink_feed_proxy, "chainlink_feed_round_id": str(self.chainlink_feed_round_id),
            "chainlink_feed_updated_at_epoch_s": self.chainlink_feed_updated_at_epoch_s, "identity_digest": self.identity_digest,
            "max_rpc_future_skew_s": self.max_rpc_future_skew_s, "observation_time_epoch_s": self.observation_time_epoch_s,
            "oracle_paused": self.oracle_paused,
            "pending_multiplier": None if self.pending_multiplier is None else _decimal(self.pending_multiplier, field="pending_multiplier"),
            "pending_multiplier_effective_at_epoch_s": self.pending_multiplier_effective_at_epoch_s,
            "raw_evidence": [dict(item) for item in self.raw_evidence], "raw_token_amount": str(self.raw_token_amount),
            "reference_deviation_rest_chainlink_bps": _ratio(self.reference_deviation_rest_chainlink_bps),
            "reference_deviation_zero_x_chainlink_bps": _ratio(self.reference_deviation_zero_x_chainlink_bps),
            "reference_tolerance_bps": self.reference_tolerance_bps, "rest_generated_at": self.rest_generated_at,
            "rest_generated_at_epoch_s": self.rest_generated_at_epoch_s, "rest_is_trading_halt": self.rest_is_trading_halt,
            "rest_raw_ask": _decimal(self.rest_raw_ask, field="rest_raw_ask"), "rest_raw_bid": _decimal(self.rest_raw_bid, field="rest_raw_bid"),
            "rpc_block_timestamp_epoch_s": self.rpc_block_timestamp_epoch_s, "rpc_future_skew_s": self.rpc_future_skew_s,
            "schema": self.schema, "sequencer_answer": self.sequencer_answer, "sequencer_feed_proxy": self.sequencer_feed_proxy,
            "sequencer_grace_period_s": self.sequencer_grace_period_s, "sequencer_started_at_epoch_s": self.sequencer_started_at_epoch_s,
            "sequencer_status": self.sequencer_status, "share_equivalent_amount": str(self.share_equivalent_amount),
            "status": self.status, "stock_token_address": self.stock_token_address, "trading_capabilities": dict(self.trading_capabilities),
            "token_decimals": self.token_decimals, "token_reference_ask": _decimal(self.token_reference_ask, field="token_reference_ask"),
            "token_reference_bid": _decimal(self.token_reference_bid, field="token_reference_bid"),
            "ui_multiplier": _decimal(self.ui_multiplier, field="ui_multiplier"), "usdg_address": self.usdg_address, "usdg_decimals": self.usdg_decimals,
            "zero_x_allowance_spender": self.zero_x_allowance_spender, "zero_x_allowance_target": self.zero_x_allowance_target,
            "zero_x_block_number": self.zero_x_block_number, "zero_x_buy_amount": str(self.zero_x_buy_amount),
            "zero_x_buy_token": self.zero_x_buy_token, "zero_x_min_buy_amount": None if self.zero_x_min_buy_amount is None else str(self.zero_x_min_buy_amount),
            "zero_x_route_digest": self.zero_x_route_digest, "zero_x_route_sources": list(self.zero_x_route_sources),
            "zero_x_sell_amount": str(self.zero_x_sell_amount), "zero_x_sell_token": self.zero_x_sell_token,
            "zero_x_transaction_data_sha256": self.zero_x_transaction_data_sha256, "zero_x_transaction_to": self.zero_x_transaction_to,
            "zero_x_transaction_value_atomic": str(self.zero_x_transaction_value_atomic),
        }

    def digest(self) -> str:
        return digest_object(self.canonical_object())

    @property
    def chainlink_price(self) -> Fraction:
        return Fraction(self.chainlink_feed_answer, 10**self.chainlink_feed_decimals)

    @property
    def zero_x_price(self) -> Fraction:
        if self.zero_x_sell_token == self.usdg_address:
            return Fraction(
                self.zero_x_sell_amount * 10**self.token_decimals,
                self.zero_x_buy_amount * 10**self.usdg_decimals,
            )
        return Fraction(
            self.zero_x_buy_amount * 10**self.usdg_decimals,
            self.zero_x_sell_amount * 10**self.token_decimals,
        )

    @classmethod
    def from_canonical(cls, obj: Any) -> "RobinhoodMarketObservationV0":
        required = {
            "asset_uid", "chain_block_number", "chain_id", "chainlink_feed_answer",
            "chainlink_feed_answered_in_round", "chainlink_feed_decimals", "chainlink_feed_heartbeat_s", "chainlink_feed_proxy",
            "chainlink_feed_round_id", "chainlink_feed_updated_at_epoch_s", "identity_digest", "max_rpc_future_skew_s", "observation_time_epoch_s", "oracle_paused",
            "pending_multiplier", "pending_multiplier_effective_at_epoch_s", "raw_evidence", "raw_token_amount",
            "reference_deviation_rest_chainlink_bps", "reference_deviation_zero_x_chainlink_bps", "reference_tolerance_bps",
            "rest_generated_at", "rest_generated_at_epoch_s", "rest_is_trading_halt", "rest_raw_ask", "rest_raw_bid", "schema",
            "sequencer_answer", "sequencer_feed_proxy", "sequencer_grace_period_s", "sequencer_started_at_epoch_s", "sequencer_status",
            "share_equivalent_amount", "status", "stock_token_address", "token_decimals", "trading_capabilities", "token_reference_ask", "token_reference_bid",
            "rpc_block_timestamp_epoch_s", "rpc_future_skew_s", "ui_multiplier", "usdg_address", "usdg_decimals", "zero_x_allowance_spender", "zero_x_allowance_target", "zero_x_block_number",
            "zero_x_buy_amount", "zero_x_buy_token", "zero_x_min_buy_amount", "zero_x_route_digest", "zero_x_route_sources",
            "zero_x_sell_amount", "zero_x_sell_token", "zero_x_transaction_data_sha256", "zero_x_transaction_to", "zero_x_transaction_value_atomic",
        }
        _validate_exact_keys(obj, required, required, field="market observation")
        evidence = obj["raw_evidence"]
        if not isinstance(evidence, list) or any(not isinstance(item, dict) for item in evidence):
            raise RobinhoodError("market raw evidence is malformed")
        pending = None if obj["pending_multiplier"] is None else _external_fraction(obj["pending_multiplier"], field="pending_multiplier", positive=True)
        return cls(
            schema=obj["schema"], observation_time_epoch_s=obj["observation_time_epoch_s"], chain_id=obj["chain_id"], chain_block_number=obj["chain_block_number"],
            rpc_block_timestamp_epoch_s=obj["rpc_block_timestamp_epoch_s"], rpc_future_skew_s=obj["rpc_future_skew_s"], max_rpc_future_skew_s=obj["max_rpc_future_skew_s"], identity_digest=obj["identity_digest"], asset_uid=obj["asset_uid"],
            stock_token_address=obj["stock_token_address"], token_decimals=obj["token_decimals"], usdg_address=obj["usdg_address"], usdg_decimals=obj["usdg_decimals"], raw_token_amount=int(obj["raw_token_amount"]),
            ui_multiplier=_external_fraction(obj["ui_multiplier"], field="ui_multiplier", positive=True), share_equivalent_amount=int(obj["share_equivalent_amount"]),
            pending_multiplier=pending, pending_multiplier_effective_at_epoch_s=obj["pending_multiplier_effective_at_epoch_s"], oracle_paused=obj["oracle_paused"],
            status=obj["status"], trading_capabilities=obj["trading_capabilities"], rest_generated_at=obj["rest_generated_at"], rest_generated_at_epoch_s=obj["rest_generated_at_epoch_s"],
            rest_raw_bid=_external_fraction(obj["rest_raw_bid"], field="rest_raw_bid", positive=True), rest_raw_ask=_external_fraction(obj["rest_raw_ask"], field="rest_raw_ask", positive=True),
            token_reference_bid=_external_fraction(obj["token_reference_bid"], field="token_reference_bid", positive=True), token_reference_ask=_external_fraction(obj["token_reference_ask"], field="token_reference_ask", positive=True),
            rest_is_trading_halt=obj["rest_is_trading_halt"], chainlink_feed_proxy=obj["chainlink_feed_proxy"], chainlink_feed_decimals=obj["chainlink_feed_decimals"],
            chainlink_feed_heartbeat_s=obj["chainlink_feed_heartbeat_s"], chainlink_feed_answer=int(obj["chainlink_feed_answer"]), chainlink_feed_updated_at_epoch_s=obj["chainlink_feed_updated_at_epoch_s"],
            chainlink_feed_round_id=int(obj["chainlink_feed_round_id"]), chainlink_feed_answered_in_round=int(obj["chainlink_feed_answered_in_round"]), sequencer_feed_proxy=obj["sequencer_feed_proxy"],
            sequencer_answer=obj["sequencer_answer"], sequencer_started_at_epoch_s=obj["sequencer_started_at_epoch_s"], sequencer_status=obj["sequencer_status"], sequencer_grace_period_s=obj["sequencer_grace_period_s"],
            zero_x_sell_token=obj["zero_x_sell_token"], zero_x_buy_token=obj["zero_x_buy_token"], zero_x_sell_amount=int(obj["zero_x_sell_amount"]), zero_x_buy_amount=int(obj["zero_x_buy_amount"]),
            zero_x_min_buy_amount=None if obj["zero_x_min_buy_amount"] is None else int(obj["zero_x_min_buy_amount"]), zero_x_allowance_target=obj["zero_x_allowance_target"], zero_x_allowance_spender=obj["zero_x_allowance_spender"],
            zero_x_block_number=obj["zero_x_block_number"], zero_x_route_sources=tuple(obj["zero_x_route_sources"]), zero_x_route_digest=obj["zero_x_route_digest"], zero_x_transaction_to=obj["zero_x_transaction_to"],
            zero_x_transaction_value_atomic=int(obj["zero_x_transaction_value_atomic"]), zero_x_transaction_data_sha256=obj["zero_x_transaction_data_sha256"],
            reference_deviation_rest_chainlink_bps=_parse_ratio(obj["reference_deviation_rest_chainlink_bps"], field="rest deviation"), reference_deviation_zero_x_chainlink_bps=_parse_ratio(obj["reference_deviation_zero_x_chainlink_bps"], field="0x deviation"),
            reference_tolerance_bps=obj["reference_tolerance_bps"], raw_evidence=tuple(evidence),
        )


@dataclass(frozen=True, slots=True)
class RobinhoodShadowDecisionV0:
    schema: str
    decision: str
    reason_code: str
    observation_digest: str
    identity_digest: str
    policy_id: str
    cycle_id: str
    level_id: str
    side: Side
    economic_action_id: str
    raw_token_amount: int
    share_equivalent_amount: int
    executable_input_atomic: int
    executable_output_atomic: int
    executable_price: Fraction
    policy_limit_price: Fraction
    policy_min_output_atomic: int
    venue_min_output_atomic: int | None
    reference_deviation_rest_chainlink_bps: Fraction
    reference_deviation_zero_x_chainlink_bps: Fraction

    def __post_init__(self) -> None:
        if self.schema != "SHADOW_DECISION_V0" or self.decision not in {"WOULD_EXECUTE", "ABSTAIN"}:
            raise RobinhoodError("shadow decision schema or decision is malformed")

    def canonical_object(self) -> dict[str, Any]:
        return {
            "decision": self.decision, "economic_action_id": self.economic_action_id, "executable_input_atomic": str(self.executable_input_atomic),
            "executable_output_atomic": str(self.executable_output_atomic), "executable_price": _ratio(self.executable_price), "identity_digest": self.identity_digest,
            "level_id": self.level_id, "policy_id": self.policy_id, "policy_limit_price": _ratio(self.policy_limit_price), "policy_min_output_atomic": str(self.policy_min_output_atomic),
            "observation_digest": self.observation_digest, "raw_token_amount": str(self.raw_token_amount), "reason_code": self.reason_code,
            "reference_deviation_rest_chainlink_bps": _ratio(self.reference_deviation_rest_chainlink_bps), "reference_deviation_zero_x_chainlink_bps": _ratio(self.reference_deviation_zero_x_chainlink_bps),
            "schema": self.schema, "share_equivalent_amount": str(self.share_equivalent_amount), "side": self.side.value,
            "venue_min_output_atomic": None if self.venue_min_output_atomic is None else str(self.venue_min_output_atomic), "cycle_id": self.cycle_id,
        }

    def digest(self) -> str:
        return digest_object(self.canonical_object())

    @classmethod
    def from_canonical(cls, obj: Any) -> "RobinhoodShadowDecisionV0":
        required = {
            "decision", "economic_action_id", "executable_input_atomic", "executable_output_atomic", "executable_price", "identity_digest", "level_id", "policy_id", "policy_limit_price", "policy_min_output_atomic", "observation_digest", "raw_token_amount", "reason_code", "reference_deviation_rest_chainlink_bps", "reference_deviation_zero_x_chainlink_bps", "schema", "share_equivalent_amount", "side", "venue_min_output_atomic", "cycle_id",
        }
        _validate_exact_keys(obj, required, required, field="shadow decision")
        try:
            side = Side(obj["side"])
        except ValueError as exc:
            raise RobinhoodError("shadow decision side is malformed") from exc
        return cls(
            schema=obj["schema"], decision=obj["decision"], reason_code=obj["reason_code"], observation_digest=obj["observation_digest"], identity_digest=obj["identity_digest"], policy_id=obj["policy_id"], cycle_id=obj["cycle_id"], level_id=obj["level_id"], side=side, economic_action_id=obj["economic_action_id"], raw_token_amount=int(obj["raw_token_amount"]), share_equivalent_amount=int(obj["share_equivalent_amount"]), executable_input_atomic=int(obj["executable_input_atomic"]), executable_output_atomic=int(obj["executable_output_atomic"]), executable_price=_parse_ratio(obj["executable_price"], field="executable_price"), policy_limit_price=_parse_ratio(obj["policy_limit_price"], field="policy_limit_price"), policy_min_output_atomic=int(obj["policy_min_output_atomic"]), venue_min_output_atomic=None if obj["venue_min_output_atomic"] is None else int(obj["venue_min_output_atomic"]), reference_deviation_rest_chainlink_bps=_parse_ratio(obj["reference_deviation_rest_chainlink_bps"], field="rest deviation"), reference_deviation_zero_x_chainlink_bps=_parse_ratio(obj["reference_deviation_zero_x_chainlink_bps"], field="0x deviation"),
        )


class RobinhoodShadowAdapter(QuoteSource):
    """The one bounded Robinhood Stock Token / USDG shadow adapter."""

    venue_id = "0x-swap-v2-robinhood-chain"

    def __init__(
        self,
        rest: RobinhoodRestClient,
        rpc: RobinhoodRpcClient,
        directory: ChainlinkRobinhoodDirectoryClient,
        zero_x: ZeroXV2Client,
        *,
        symbol: str,
        sequencer_feed_proxy: str | None = None,
        sequencer_grace_period_s: int = SEQUENCER_GRACE_PERIOD_S,
        reference_tolerance_bps: int = REFERENCE_TOLERANCE_BPS,
        rest_max_age_s: int = 120,
    ) -> None:
        if not isinstance(symbol, str) or not symbol:
            raise RobinhoodError("qualification symbol must be explicit")
        if sequencer_feed_proxy is not None:
            sequencer_feed_proxy = _address(sequencer_feed_proxy, field="sequencer_feed_proxy")
        if not isinstance(sequencer_grace_period_s, int) or sequencer_grace_period_s < 0:
            raise RobinhoodError("sequencer grace period is malformed")
        if not isinstance(reference_tolerance_bps, int) or not 0 <= reference_tolerance_bps <= _BPS:
            raise RobinhoodError("reference tolerance is malformed")
        if not isinstance(rest_max_age_s, int) or rest_max_age_s < 1:
            raise RobinhoodError("REST age bound is malformed")
        self.rest = rest
        self.rpc = rpc
        self.directory = directory
        self.zero_x = zero_x
        self.symbol = symbol
        self.sequencer_feed_proxy = sequencer_feed_proxy
        self.sequencer_grace_period_s = sequencer_grace_period_s
        self.reference_tolerance_bps = reference_tolerance_bps
        self.rest_max_age_s = rest_max_age_s
        self.identity: RobinhoodAssetIdentityV0 | None = None
        self.observation: RobinhoodMarketObservationV0 | None = None

    @staticmethod
    def _token_call(rpc: RobinhoodRpcClient, address: str, selector: str, *, field: str) -> int:
        data = rpc.call(address, selector)
        if len(data) != 32:
            raise RobinhoodProtocolError(f"{field}: expected one ABI word")
        return _word(data, 0, field=field)

    @staticmethod
    def _uid_call(rpc: RobinhoodRpcClient, address: str) -> str:
        data = rpc.call(address, "0xf514ce36")
        return "0x" + _bytes("0x" + data.hex(), field="uid", exact_bytes=32).hex()

    def _resolve_identity(self, asset: dict[str, Any], now_epoch_s: int) -> RobinhoodAssetIdentityV0:
        if self.rpc.chain_id() != ROBINHOOD_CHAIN_ID:
            raise SafeHaltError("Robinhood RPC chain id mismatch")
        token_address = asset["token_address"]
        token_code = self.rpc.code(token_address)
        usdg_code = self.rpc.code(USDG_ADDRESS)
        onchain_decimals = self._token_call(self.rpc, token_address, "0x313ce567", field="token decimals")
        onchain_uid = self._uid_call(self.rpc, token_address)
        onchain_ui = self._token_call(self.rpc, token_address, "0xa60bf13d", field="uiMultiplier")
        onchain_new = self._token_call(self.rpc, token_address, "0xdc767007", field="newUIMultiplier")
        onchain_effective = self._token_call(self.rpc, token_address, "0x97a4064f", field="effectiveAt")
        paused_word = self._token_call(self.rpc, token_address, "0x7706ba52", field="oraclePaused")
        usdg_decimals = self._token_call(self.rpc, USDG_ADDRESS, "0x313ce567", field="USDG decimals")
        if paused_word not in (0, 1) or onchain_ui == 0 or onchain_new == 0:
            raise RobinhoodProtocolError("Stock Token boolean or multiplier response is malformed")
        if onchain_decimals != asset["token_decimals"]:
            raise SafeHaltError("Stock Token decimals disagree with Robinhood metadata")
        if onchain_uid != asset["asset_uid"]:
            raise SafeHaltError("Stock Token uid disagrees with Robinhood metadata")
        onchain_ui_fraction = Fraction(onchain_ui, MULTIPLIER_SCALE)
        onchain_new_fraction = Fraction(onchain_new, MULTIPLIER_SCALE)
        if onchain_ui_fraction != asset["current_multiplier"]:
            raise SafeHaltError("uiMultiplier disagrees with currentMultiplier")
        if asset["pending_multiplier"] is not None and asset["pending_multiplier"] != onchain_new_fraction:
            raise SafeHaltError("pending multiplier disagrees across Robinhood surfaces")
        if asset["pending_multiplier"] is not None:
            if onchain_effective != asset["pending_effective_at_epoch_s"]:
                raise SafeHaltError("pending multiplier effective time disagrees across Robinhood surfaces")
            if onchain_effective <= now_epoch_s:
                raise SafeHaltError("pending multiplier transition is already effective but not reconciled")
        if asset["pending_multiplier"] is None and (onchain_effective != 0 or onchain_new_fraction != onchain_ui_fraction):
            raise SafeHaltError("onchain pending multiplier is absent from REST metadata")
        return RobinhoodAssetIdentityV0(
            schema="ROBINHOOD_ASSET_IDENTITY_V0", chain_id=ROBINHOOD_CHAIN_ID, asset_uid=asset["asset_uid"], token_symbol=self.symbol, token_name=asset["token_name"], stock_token_address=token_address, token_decimals=asset["token_decimals"], current_multiplier=asset["current_multiplier"], pending_multiplier=asset["pending_multiplier"], pending_multiplier_effective_at_epoch_s=asset["pending_effective_at_epoch_s"], status=asset["status"], trading_capabilities=asset["trading_capabilities"], onchain_uid=onchain_uid, onchain_decimals=onchain_decimals, onchain_ui_multiplier=onchain_ui_fraction, onchain_new_ui_multiplier=onchain_new_fraction, onchain_effective_at_epoch_s=onchain_effective, oracle_paused=bool(paused_word), stock_token_bytecode_sha256=_sha256(token_code), stock_token_bytecode_length=len(token_code), usdg_address=USDG_ADDRESS, usdg_decimals=usdg_decimals, usdg_bytecode_sha256=_sha256(usdg_code), usdg_bytecode_length=len(usdg_code), raw_evidence=(),
        )

    def _sequencer(self) -> tuple[str, int | None, int | None]:
        if self.sequencer_feed_proxy is None:
            return "UNAVAILABLE_NOT_PUBLISHED", None, None
        self.rpc.code(self.sequencer_feed_proxy)
        data = self.rpc.call(self.sequencer_feed_proxy, "0xfeaf968c")
        if len(data) != 160:
            raise RobinhoodProtocolError("sequencer latestRoundData has wrong length")
        answer = _signed_word(data, 1, field="sequencer answer")
        started = _word(data, 2, field="sequencer startedAt")
        if answer not in (0, 1) or started <= 0:
            raise RobinhoodProtocolError("sequencer uptime response is malformed")
        return ("UP" if answer == 0 else "DOWN"), answer, started

    def observe(self, policy: PolicyV0, cycle_id: str, level_id: str, *, now_epoch_s: int, taker: str | None) -> RobinhoodMarketObservationV0:
        taker = validate_qualification_taker(taker)
        if not isinstance(now_epoch_s, int) or isinstance(now_epoch_s, bool):
            raise RobinhoodError("now_epoch_s must be an explicit integer")
        asset = self.rest.asset(self.symbol)
        if policy.base.instrument_id != f"evm:{ROBINHOOD_CHAIN_ID}:{asset['token_address']}" or policy.quote.instrument_id != f"evm:{ROBINHOOD_CHAIN_ID}:{USDG_ADDRESS}":
            raise SafeHaltError("policy instruments do not match the resolved Robinhood pair")
        if policy.base.decimals != asset["token_decimals"]:
            raise SafeHaltError("policy Stock Token decimals do not match Robinhood metadata")
        if policy.quote.decimals != 6:
            raise SafeHaltError("policy USDG decimals must be 6")
        identity = self._resolve_identity(asset, now_epoch_s)
        identity_evidence_records = tuple(self.rest.evidence_records + self.rpc.evidence_records)
        block_number, block_timestamp = self.rpc.latest_block()
        rpc_future_skew_s = block_timestamp - now_epoch_s
        if rpc_future_skew_s > MAX_RPC_FUTURE_SKEW_S:
            raise SafeHaltError("latest RPC block exceeds the bounded future skew")
        price = self.rest.price(self.symbol, asset["token_address"])
        feed = self.directory.resolve(self.symbol)
        feed_code = self.rpc.code(feed["feed_proxy"])
        feed_decimals = self._token_call(self.rpc, feed["feed_proxy"], "0x313ce567", field="Chainlink feed decimals")
        if feed_decimals != feed["feed_decimals"]:
            raise SafeHaltError("Chainlink feed decimals disagree with directory")
        latest = self.rpc.call(feed["feed_proxy"], "0xfeaf968c")
        if len(latest) != 160:
            raise RobinhoodProtocolError("Chainlink latestRoundData has wrong length")
        round_id = _word(latest, 0, field="Chainlink roundId")
        answer = _signed_word(latest, 1, field="Chainlink answer")
        updated_at = _word(latest, 3, field="Chainlink updatedAt")
        answered_in_round = _word(latest, 4, field="Chainlink answeredInRound")
        if answer <= 0 or updated_at <= 0 or updated_at > now_epoch_s or round_id <= 0 or answered_in_round < round_id:
            raise SafeHaltError("Chainlink answer or timestamp is invalid")
        sequence_status, sequence_answer, sequence_started = self._sequencer()
        intent = build_intent(policy, cycle_id, policy.level(level_id), now_epoch_s=now_epoch_s)
        if intent.side is Side.BUY:
            sell_token, buy_token = USDG_ADDRESS, asset["token_address"]
        else:
            sell_token, buy_token = asset["token_address"], USDG_ADDRESS
        zero = self.zero_x.quote(sell_token=sell_token, buy_token=buy_token, sell_amount_atomic=intent.bounds.max_input_atomic, taker=taker, slippage_bps=policy.max_slippage_bps, policy_min_output_atomic=intent.bounds.min_output_atomic)
        if zero["block_number"] is not None and zero["block_number"] + ZEROX_MAX_BLOCK_LAG < block_number:
            raise SafeHaltError("0x quote block is stale relative to the pinned RPC block")
        token_reference_bid = price["raw_bid"] * identity.current_multiplier
        token_reference_ask = price["raw_ask"] * identity.current_multiplier
        chainlink_price = Fraction(answer, 10**feed_decimals)
        reference_mid = (token_reference_bid + token_reference_ask) / 2
        executable_price = Fraction(zero["sell_amount_atomic"] * 10**identity.token_decimals, zero["buy_amount_atomic"] * 10**identity.usdg_decimals) if sell_token == USDG_ADDRESS else Fraction(zero["buy_amount_atomic"] * 10**identity.usdg_decimals, zero["sell_amount_atomic"] * 10**identity.token_decimals)
        deviation_rest = max(
            abs(token_reference_bid - chainlink_price),
            abs(token_reference_ask - chainlink_price),
        ) / chainlink_price * _BPS
        deviation_zero = abs(executable_price - chainlink_price) / chainlink_price * _BPS
        raw_token_amount = zero["buy_amount_atomic"] if buy_token == asset["token_address"] else zero["sell_amount_atomic"]
        share_equivalent = _share_equivalent_amount(raw_token_amount, identity.onchain_ui_multiplier)
        evidence_records = tuple(self.rest.evidence_records + self.rpc.evidence_records + self.directory.evidence_records + self.zero_x.evidence_records)
        observation = RobinhoodMarketObservationV0(
            schema="ROBINHOOD_MARKET_OBSERVATION_V0", observation_time_epoch_s=now_epoch_s, chain_id=ROBINHOOD_CHAIN_ID, chain_block_number=block_number, rpc_block_timestamp_epoch_s=block_timestamp, rpc_future_skew_s=rpc_future_skew_s, max_rpc_future_skew_s=MAX_RPC_FUTURE_SKEW_S, identity_digest=identity.digest(), asset_uid=identity.asset_uid, stock_token_address=identity.stock_token_address, token_decimals=identity.token_decimals, usdg_address=identity.usdg_address, usdg_decimals=identity.usdg_decimals, raw_token_amount=raw_token_amount, ui_multiplier=identity.onchain_ui_multiplier, share_equivalent_amount=share_equivalent, pending_multiplier=identity.pending_multiplier, pending_multiplier_effective_at_epoch_s=identity.pending_multiplier_effective_at_epoch_s, oracle_paused=identity.oracle_paused, status=identity.status, trading_capabilities=identity.trading_capabilities, rest_generated_at=price["generated_at"], rest_generated_at_epoch_s=price["generated_at_epoch_s"], rest_raw_bid=price["raw_bid"], rest_raw_ask=price["raw_ask"], token_reference_bid=token_reference_bid, token_reference_ask=token_reference_ask, rest_is_trading_halt=price["is_trading_halt"], chainlink_feed_proxy=feed["feed_proxy"], chainlink_feed_decimals=feed_decimals, chainlink_feed_heartbeat_s=feed["feed_heartbeat_s"], chainlink_feed_answer=answer, chainlink_feed_updated_at_epoch_s=updated_at, chainlink_feed_round_id=round_id, chainlink_feed_answered_in_round=answered_in_round, sequencer_feed_proxy=self.sequencer_feed_proxy, sequencer_answer=sequence_answer, sequencer_started_at_epoch_s=sequence_started, sequencer_status=sequence_status, sequencer_grace_period_s=self.sequencer_grace_period_s, zero_x_sell_token=zero["sell_token"], zero_x_buy_token=zero["buy_token"], zero_x_sell_amount=zero["sell_amount_atomic"], zero_x_buy_amount=zero["buy_amount_atomic"], zero_x_min_buy_amount=zero["venue_min_output_atomic"], zero_x_allowance_target=zero["allowance_target"], zero_x_allowance_spender=zero["allowance_spender"], zero_x_block_number=zero["block_number"], zero_x_route_sources=zero["route_sources"], zero_x_route_digest=zero["route_digest"], zero_x_transaction_to=zero["transaction_to"], zero_x_transaction_value_atomic=zero["transaction_value_atomic"], zero_x_transaction_data_sha256=zero["transaction_data_sha256"], reference_deviation_rest_chainlink_bps=deviation_rest, reference_deviation_zero_x_chainlink_bps=deviation_zero, reference_tolerance_bps=self.reference_tolerance_bps, raw_evidence=(),
        )
        identity = replace(identity, raw_evidence=_record_refs(identity_evidence_records))
        observation = replace(observation, identity_digest=identity.digest(), raw_evidence=_record_refs(evidence_records))
        self.identity = identity
        self.observation = observation
        return observation

    def _require_observation(self, observation: RobinhoodMarketObservationV0 | None) -> RobinhoodMarketObservationV0:
        chosen = observation or self.observation
        if chosen is None:
            raise SafeHaltError("no pinned Robinhood observation is available")
        return chosen

    def _decision(self, policy: PolicyV0, cycle_id: str, level_id: str, *, now_epoch_s: int, observation: RobinhoodMarketObservationV0) -> RobinhoodShadowDecisionV0:
        if policy.base.instrument_id != f"evm:{ROBINHOOD_CHAIN_ID}:{observation.stock_token_address}" or policy.quote.instrument_id != f"evm:{ROBINHOOD_CHAIN_ID}:{observation.usdg_address}":
            raise SafeHaltError("policy instruments do not match pinned Robinhood observation")
        intent = build_intent(policy, cycle_id, policy.level(level_id), now_epoch_s=now_epoch_s)
        reasons: list[str] = []
        age_rest = now_epoch_s - observation.rest_generated_at_epoch_s
        age_feed = now_epoch_s - observation.chainlink_feed_updated_at_epoch_s
        if age_rest < 0 or age_rest > self.rest_max_age_s:
            reasons.append("REST_STALE")
        if age_feed < 0 or age_feed >= observation.chainlink_feed_heartbeat_s:
            reasons.append("CHAINLINK_STALE")
        if observation.oracle_paused:
            reasons.append("ORACLE_PAUSED")
        if observation.rest_is_trading_halt:
            reasons.append("REST_TRADING_HALT")
        if observation.sequencer_status == "DOWN":
            reasons.append("SEQUENCER_DOWN")
        elif observation.sequencer_status == "UP" and observation.sequencer_started_at_epoch_s is not None and now_epoch_s - observation.sequencer_started_at_epoch_s <= observation.sequencer_grace_period_s:
            reasons.append("SEQUENCER_GRACE_PERIOD")
        if observation.status != "ASSET_STATUS_ACTIVE":
            reasons.append("ASSET_NOT_ACTIVE")
        if observation.pending_multiplier_effective_at_epoch_s is not None:
            if observation.pending_multiplier_effective_at_epoch_s <= now_epoch_s:
                reasons.append("PENDING_MULTIPLIER_CROSSING")
            elif observation.pending_multiplier_effective_at_epoch_s <= intent.bounds.deadline_epoch_s:
                reasons.append("PENDING_MULTIPLIER_TRANSITION_WINDOW")
        if observation.reference_deviation_rest_chainlink_bps > observation.reference_tolerance_bps or observation.reference_deviation_zero_x_chainlink_bps > observation.reference_tolerance_bps:
            reasons.append("REFERENCE_DISAGREEMENT")
        if observation.zero_x_min_buy_amount is None:
            reasons.append("VENUE_MIN_OUTPUT_UNAVAILABLE")
        elif observation.zero_x_min_buy_amount < intent.bounds.min_output_atomic:
            raise SafeHaltError("pinned 0x minimum output is looser than PolicyV0")
        if observation.zero_x_buy_amount < intent.bounds.min_output_atomic:
            reasons.append("MIN_OUTPUT_BOUND")
        executable_price = observation.zero_x_price
        if intent.side is Side.BUY and executable_price > intent.bounds.limit_price:
            reasons.append("MAX_EXECUTABLE_PRICE")
        if intent.side is Side.SELL and executable_price < intent.bounds.limit_price:
            reasons.append("MIN_EXECUTABLE_PRICE")
        return RobinhoodShadowDecisionV0(schema="SHADOW_DECISION_V0", decision="WOULD_EXECUTE" if not reasons else "ABSTAIN", reason_code="PASS" if not reasons else "+".join(reasons), observation_digest=observation.digest(), identity_digest=observation.identity_digest, policy_id=policy.policy_id, cycle_id=cycle_id, level_id=level_id, side=intent.side, economic_action_id=intent.economic_action_id, raw_token_amount=observation.raw_token_amount, share_equivalent_amount=observation.share_equivalent_amount, executable_input_atomic=observation.zero_x_sell_amount, executable_output_atomic=observation.zero_x_buy_amount, executable_price=executable_price, policy_limit_price=intent.bounds.limit_price, policy_min_output_atomic=intent.bounds.min_output_atomic, venue_min_output_atomic=observation.zero_x_min_buy_amount, reference_deviation_rest_chainlink_bps=observation.reference_deviation_rest_chainlink_bps, reference_deviation_zero_x_chainlink_bps=observation.reference_deviation_zero_x_chainlink_bps)

    def shadow_decision(self, policy: PolicyV0, cycle_id: str, level_id: str, *, now_epoch_s: int, observation: RobinhoodMarketObservationV0 | None = None) -> RobinhoodShadowDecisionV0:
        return self._decision(policy, cycle_id, level_id, now_epoch_s=now_epoch_s, observation=self._require_observation(observation))

    def quote(self, bounds: EconomicBounds, *, now_epoch_s: int) -> QuoteV0:
        observation = self._require_observation(None)
        expected_sell = observation.usdg_address if bounds.side is Side.BUY else observation.stock_token_address
        expected_buy = observation.stock_token_address if bounds.side is Side.BUY else observation.usdg_address
        if bounds.input_instrument_id != f"evm:{ROBINHOOD_CHAIN_ID}:{expected_sell}" or bounds.output_instrument_id != f"evm:{ROBINHOOD_CHAIN_ID}:{expected_buy}":
            raise SafeHaltError("quote bounds do not match pinned Robinhood pair")
        if observation.zero_x_sell_amount != bounds.max_input_atomic or observation.zero_x_buy_amount < bounds.min_output_atomic:
            raise LevelNotExecutableError("pinned 0x quote does not satisfy absolute bounds")
        return QuoteV0(quote_id=digest_object({"bounds": bounds.canonical_object(), "observation_digest": observation.digest(), "pinned_at_epoch_s": now_epoch_s}), economic_action_id="shadow-quote", input_atomic=observation.zero_x_sell_amount, output_atomic=observation.zero_x_buy_amount, pinned_at_epoch_s=now_epoch_s, expires_at_epoch_s=now_epoch_s + 1, source=self.venue_id)


def replay_shadow_decision(policy: PolicyV0, observation: RobinhoodMarketObservationV0, cycle_id: str, level_id: str, *, now_epoch_s: int | None = None, reference_tolerance_bps: int = REFERENCE_TOLERANCE_BPS, rest_max_age_s: int = 120) -> RobinhoodShadowDecisionV0:
    frozen_now_epoch_s = observation.observation_time_epoch_s
    if now_epoch_s is not None and now_epoch_s != frozen_now_epoch_s:
        raise SafeHaltError("replay timestamp must match the frozen observation timestamp")
    adapter = object.__new__(RobinhoodShadowAdapter)
    adapter.observation = observation
    adapter.reference_tolerance_bps = reference_tolerance_bps
    adapter.rest_max_age_s = rest_max_age_s
    return adapter._decision(policy, cycle_id, level_id, now_epoch_s=frozen_now_epoch_s, observation=observation)


def _persist(path: str | Path, record: Any) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes({"digest": record.digest(), "record": record.canonical_object()})
    try:
        with target.open("xb") as handle:
            handle.write(payload)
    except FileExistsError:
        if target.read_bytes() != payload:
            raise SafeHaltError(f"immutable artifact path already contains different data: {target}")
    return record.digest()


def persist_identity(path: str | Path, identity: RobinhoodAssetIdentityV0) -> str:
    return _persist(path, identity)


def persist_observation(path: str | Path, observation: RobinhoodMarketObservationV0) -> str:
    return _persist(path, observation)


def persist_decision(path: str | Path, decision: RobinhoodShadowDecisionV0) -> str:
    return _persist(path, decision)


def _load(path: str | Path, factory: Callable[[Any], Any]) -> Any:
    try:
        obj = _parse_json(Path(path).read_bytes(), field=str(path))
    except OSError as exc:
        raise SafeHaltError(f"artifact is unavailable: {path}") from exc
    if not isinstance(obj, dict) or set(obj) != {"digest", "record"} or not isinstance(obj["digest"], str):
        raise RobinhoodError("artifact envelope is malformed")
    record = factory(obj["record"])
    if record.digest() != obj["digest"]:
        raise SafeHaltError("artifact digest mismatch")
    return record


def load_identity(path: str | Path) -> RobinhoodAssetIdentityV0:
    return _load(path, RobinhoodAssetIdentityV0.from_canonical)


def load_observation(path: str | Path) -> RobinhoodMarketObservationV0:
    return _load(path, RobinhoodMarketObservationV0.from_canonical)


def load_decision(path: str | Path) -> RobinhoodShadowDecisionV0:
    return _load(path, RobinhoodShadowDecisionV0.from_canonical)
