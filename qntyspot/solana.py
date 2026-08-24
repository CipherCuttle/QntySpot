"""Bounded Solana/Jupiter V0C shadow observation.

This module has one public-read path: finalized Solana RPC reads plus the
current Jupiter Swap V2 ``GET /build`` read.  It accepts the exact mint pair
and atomic input supplied by the policy-bound intent.  It does not discover
assets, choose a route, create a serialized payload, sign, or submit one.

Jupiter responses are untrusted external evidence.  The adapter validates the
wire shape, exact mint and amount identity, route split accounting, program
and account identities, instruction encodings, blockhash freshness, and
address-lookup-table semantics.  It records the validated facts in a
canonical SHA-256 observation that can be replayed without a network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, ProxyHandler, build_opener

from .canon import (
    canonical_json_bytes,
    digest_object,
    format_canonical_decimal,
    parse_canonical_decimal,
    strict_json_loads,
)
from .domain import EconomicBounds, PolicyV0, QuoteV0, Side
from .economics import build_intent
from .errors import (
    JupiterApiError,
    LevelNotExecutableError,
    SafeHaltError,
    SolanaError,
    SolanaProtocolError,
    SolanaResponseTooLargeError,
    SolanaTimeoutError,
    SolanaTransportError,
)
from .identity import SolanaCluster, SolanaInstrumentRef, TokenProgram
from .ink import ShadowDecisionV0
from .raw_evidence import RawEvidenceRecord, RawEvidenceStore

__all__ = [
    "SOLANA_MAINNET_RPC_ENDPOINT",
    "JUPITER_SWAP_V2_BUILD_ENDPOINT",
    "SPL_TOKEN_PROGRAM_ADDRESS",
    "TOKEN_2022_PROGRAM_ADDRESS",
    "QUALIFICATION_TAKER_ADDRESS",
    "policy_min_threshold_atomic",
    "SolanaRpcClient",
    "JupiterV2Client",
    "SolanaMarketObservationV0",
    "SolanaShadowAdapter",
    "replay_shadow_decision",
    "persist_observation",
    "persist_decision",
    "load_observation",
    "load_decision",
    "RawEvidenceRecord",
    "RawEvidenceStore",
]

SOLANA_MAINNET_RPC_ENDPOINT = "https://api.mainnet.solana.com"
JUPITER_SWAP_V2_BUILD_ENDPOINT = "https://api.jup.ag/swap/v2/build"
SPL_TOKEN_PROGRAM_ADDRESS = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM_ADDRESS = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
QUALIFICATION_TAKER_ADDRESS = "BQ72nSv9f3PRyRKCBnHLVrerrv37CYTHm5h3s9VSGQDV"

_SYSTEM_PROGRAM_ADDRESS = "11111111111111111111111111111111"
_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_ATOMIC_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_INTEGER_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_MAX_U64 = (1 << 64) - 1
_BPS_DENOMINATOR = 10_000
_MAX_INSTRUCTION_ACCOUNTS = 256
_MAX_LOOKUP_ADDRESSES = 256
_MAX_ROUTE_STEPS = 64


def policy_min_threshold_atomic(out_amount_atomic: int, max_slippage_bps: int) -> int:
    """Return the conservative ExactIn minimum output in atomic units.

    The policy owns this bound.  It is deliberately integer-only and rounds up
    whenever the exact percentage boundary is fractional, so the resulting
    transaction guard can never be looser than policy.
    """
    if (
        isinstance(out_amount_atomic, bool)
        or not isinstance(out_amount_atomic, int)
        or not 0 < out_amount_atomic <= _MAX_U64
    ):
        raise SolanaError("out_amount_atomic must be a positive uint64")
    if (
        isinstance(max_slippage_bps, bool)
        or not isinstance(max_slippage_bps, int)
        or not 0 <= max_slippage_bps <= _BPS_DENOMINATOR
    ):
        raise SolanaError("max_slippage_bps must be in [0, 10000]")
    numerator = out_amount_atomic * (_BPS_DENOMINATOR - max_slippage_bps)
    return (numerator + _BPS_DENOMINATOR - 1) // _BPS_DENOMINATOR


def _base58_decode(value: Any, *, field: str, allow_zero: bool = True) -> bytes:
    if not isinstance(value, str) or not _BASE58_RE.fullmatch(value):
        raise SolanaProtocolError(f"{field}: expected canonical base58 public key")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    index = {char: number for number, char in enumerate(alphabet)}
    number = 0
    for char in value:
        number = number * 58 + index[char]
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(value) - len(value.lstrip("1"))
    decoded = b"\x00" * leading + body
    if len(decoded) != 32 or (not allow_zero and decoded == b"\x00" * 32):
        raise SolanaProtocolError(f"{field}: public key must decode to 32 bytes")
    if _base58_encode(decoded) != value:
        raise SolanaProtocolError(f"{field}: non-canonical base58 spelling")
    return decoded


def _base58_encode(value: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not value:
        return ""
    number = int.from_bytes(value, "big")
    chars: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        chars.append(alphabet[remainder])
    leading = len(value) - len(value.lstrip(b"\x00"))
    return "1" * leading + "".join(reversed(chars))


def _pubkey(value: Any, *, field: str, allow_zero: bool = True) -> str:
    _base58_decode(value, field=field, allow_zero=allow_zero)
    return value


def _atomic(value: Any, *, field: str, positive: bool = False) -> int:
    if not isinstance(value, str) or not _ATOMIC_RE.fullmatch(value):
        raise SolanaProtocolError(f"{field}: expected canonical atomic integer string")
    parsed = int(value)
    if positive and parsed <= 0:
        raise SolanaProtocolError(f"{field}: must be positive")
    if parsed > _MAX_U64:
        raise SolanaProtocolError(f"{field}: exceeds uint64")
    return parsed


def _json_integer(value: Any, *, field: str, minimum: int = 0, maximum: int = _MAX_U64) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SolanaProtocolError(f"{field}: expected JSON integer")
    if not minimum <= value <= maximum:
        raise SolanaProtocolError(f"{field}: integer outside [{minimum}, {maximum}]")
    return value


def _text(value: Any, *, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise SolanaProtocolError(f"{field}: malformed text")
    return value


def _ratio(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _parse_ratio(value: Any, *, field: str) -> Fraction:
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise SolanaError(f"{field}: malformed exact ratio")
    numerator = value["numerator"]
    denominator = value["denominator"]
    if not isinstance(numerator, str) or not re.fullmatch(r"-?[0-9]+", numerator):
        raise SolanaError(f"{field}.numerator: malformed integer string")
    if not isinstance(denominator, str) or not re.fullmatch(r"[1-9][0-9]*", denominator):
        raise SolanaError(f"{field}.denominator: malformed positive integer string")
    return Fraction(int(numerator), int(denominator))


def _reject_api_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise SolanaProtocolError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def _parse_api_decimal(text: str) -> Decimal:
    try:
        value = Decimal(text)
    except InvalidOperation as exc:
        raise SolanaProtocolError("non-finite or malformed JSON decimal") from exc
    if not value.is_finite():
        raise SolanaProtocolError("non-finite JSON decimal")
    return value


def _reject_api_constant(text: str) -> Any:
    raise SolanaProtocolError(f"JSON constant {text!r} is not admissible")


def _non_economic_decimal(value: Any, *, field: str) -> str:
    """Canonicalize Jupiter's non-economic route USD metadata.

    Jupiter currently emits ``usdValue`` as a JSON decimal number.  It is
    retained as text-only metadata; every economic field remains restricted to
    atomic strings, integers, or canonical decimal strings by its own parser.
    """
    if isinstance(value, bool):
        raise SolanaProtocolError(f"{field}: malformed non-economic decimal")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise SolanaProtocolError(f"{field}: non-finite decimal")
        text = format(value, "f")
    elif isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        raise SolanaProtocolError(f"{field}: malformed non-economic decimal")
    try:
        parsed = parse_canonical_decimal(text, field=field)
    except Exception as exc:
        raise SolanaProtocolError(f"{field}: decimal metadata is not canonicalizable") from exc
    if parsed < 0:
        raise SolanaProtocolError(f"{field}: decimal metadata cannot be negative")
    return format_canonical_decimal(parsed, field=field)


def _strict_http_json(body: bytes, *, field: str) -> Any:
    try:
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        return json.loads(
            body,
            object_pairs_hook=_reject_api_duplicate_keys,
            parse_float=_parse_api_decimal,
            parse_constant=_reject_api_constant,
        )
    except Exception as exc:
        raise SolanaProtocolError(f"{field}: response was not strict JSON") from exc


class _HttpsGet:
    def __init__(
        self,
        endpoint: str,
        *,
        timeout_s: int = 15,
        max_retries: int = 1,
        max_response_bytes: int = 2_000_000,
        transport: Callable[[str, bytes], bytes] | None = None,
        evidence_store: RawEvidenceStore | None = None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise SolanaError("HTTPS endpoint must not contain credentials")
        if isinstance(timeout_s, bool) or not isinstance(timeout_s, int) or timeout_s < 1:
            raise SolanaError("timeout_s must be a positive integer")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 0 <= max_retries <= 3:
            raise SolanaError("max_retries must be in [0, 3]")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes < 256:
            raise SolanaError("max_response_bytes must be at least 256")
        self.endpoint = endpoint
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.max_response_bytes = max_response_bytes
        self._transport = transport
        if evidence_store is not None and not isinstance(evidence_store, RawEvidenceStore):
            raise SolanaError("evidence_store must be a RawEvidenceStore")
        self._evidence_store = evidence_store
        self._evidence_records: list[RawEvidenceRecord] = []
        self._opener = build_opener(ProxyHandler({}))
        self.read_count = 0

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return tuple(self._evidence_records)

    def get(self, params: Mapping[str, str]) -> Any:
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in params.items()):
            raise SolanaError("query parameters must be strings")
        query = urlencode(sorted(params.items()))
        url = self.endpoint + ("&" if "?" in self.endpoint else "?") + query
        last: SolanaTransportError | None = None
        for _attempt in range(self.max_retries + 1):
            try:
                self.read_count += 1
                if self._transport is not None:
                    body = self._transport(url, query.encode("ascii"))
                else:
                    request = Request(
                        url,
                        headers={
                            "accept": "application/json",
                            "user-agent": "qntyspot-v0c-solana-shadow/1",
                        },
                        method="GET",
                    )
                    with self._opener.open(request, timeout=self.timeout_s) as response:
                        body = response.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    raise SolanaResponseTooLargeError(
                        f"response from {self.endpoint} exceeds {self.max_response_bytes} bytes"
                    )
                if self._evidence_store is not None:
                    self._evidence_records.append(
                        self._evidence_store.capture(
                            endpoint=self.endpoint,
                            method="GET",
                            request_target=url,
                            request_body=None,
                            response_body=body,
                        )
                    )
                return _strict_http_json(body, field=self.endpoint)
            except HTTPError as exc:
                if exc.code in (408, 429) or 500 <= exc.code <= 599:
                    last = SolanaTransportError(f"HTTP {exc.code} from {self.endpoint}")
                    continue
                raise JupiterApiError(f"HTTP {exc.code} from {self.endpoint}") from exc
            except (TimeoutError, URLError, OSError) as exc:
                if isinstance(exc, TimeoutError) or "timed out" in str(exc).lower():
                    last = SolanaTimeoutError(f"timeout from {self.endpoint}")
                else:
                    last = SolanaTransportError(f"transport failure from {self.endpoint}")
        if last is None:  # pragma: no cover - the loop always runs
            raise SolanaTransportError("read retry loop did not run")
        raise last


class _JsonRpc:
    _READ_METHODS = frozenset({"getLatestBlockhash", "getBlockHeight", "getMultipleAccounts"})

    def __init__(
        self,
        endpoint: str,
        *,
        timeout_s: int = 15,
        max_retries: int = 1,
        max_response_bytes: int = 2_000_000,
        transport: Callable[[bytes], bytes] | None = None,
        evidence_store: RawEvidenceStore | None = None,
    ) -> None:
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise SolanaError("Solana RPC endpoint must be HTTPS without credentials")
        self.endpoint = endpoint
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.max_response_bytes = max_response_bytes
        self._transport = transport
        if evidence_store is not None and not isinstance(evidence_store, RawEvidenceStore):
            raise SolanaError("evidence_store must be a RawEvidenceStore")
        self._evidence_store = evidence_store
        self._evidence_records: list[RawEvidenceRecord] = []
        self._opener = build_opener(ProxyHandler({}))
        self.read_count = 0

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return tuple(self._evidence_records)

    def request(self, method: str, params: list[Any]) -> Any:
        if not isinstance(method, str) or method not in self._READ_METHODS or not isinstance(params, list):
            raise SolanaProtocolError("JSON-RPC method and params are malformed")
        payload = canonical_json_bytes({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        last: SolanaTransportError | None = None
        for _attempt in range(self.max_retries + 1):
            try:
                self.read_count += 1
                if self._transport is not None:
                    body = self._transport(payload)
                else:
                    request = Request(
                        self.endpoint,
                        data=payload,
                        headers={
                            "accept": "application/json",
                            "content-type": "application/json",
                            "user-agent": "qntyspot-v0c-solana-shadow/1",
                        },
                        method="POST",
                    )
                    with self._opener.open(request, timeout=self.timeout_s) as response:
                        body = response.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    raise SolanaResponseTooLargeError(
                        f"response from {self.endpoint} exceeds {self.max_response_bytes} bytes"
                    )
                if self._evidence_store is not None:
                    self._evidence_records.append(
                        self._evidence_store.capture(
                            endpoint=self.endpoint,
                            method="POST",
                            request_target=self.endpoint,
                            request_body=payload,
                            response_body=body,
                        )
                    )
                raw = _strict_http_json(body, field=self.endpoint)
                if not isinstance(raw, dict) or raw.get("jsonrpc") != "2.0" or raw.get("id") != 1:
                    raise SolanaProtocolError("JSON-RPC version or response id mismatch")
                if set(raw) not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"}):
                    raise SolanaProtocolError("JSON-RPC response has unknown or missing fields")
                if "error" in raw:
                    error = raw["error"]
                    if not isinstance(error, dict) or not isinstance(error.get("code"), int) or not isinstance(error.get("message"), str):
                        raise SolanaProtocolError("malformed JSON-RPC error")
                    raise JupiterApiError(f"JSON-RPC {error['code']}: {error['message']}")
                return raw["result"]
            except HTTPError as exc:
                if exc.code in (408, 429) or 500 <= exc.code <= 599:
                    last = SolanaTransportError(f"HTTP {exc.code} from {self.endpoint}")
                    continue
                raise SolanaError(f"HTTP {exc.code} from {self.endpoint}") from exc
            except (TimeoutError, URLError, OSError) as exc:
                if isinstance(exc, TimeoutError) or "timed out" in str(exc).lower():
                    last = SolanaTimeoutError(f"timeout from {self.endpoint}")
                else:
                    last = SolanaTransportError(f"transport failure from {self.endpoint}")
        if last is None:  # pragma: no cover
            raise SolanaTransportError("RPC retry loop did not run")
        raise last


class SolanaRpcClient:
    """Strict finalized-read Solana JSON-RPC client."""

    def __init__(self, endpoint: str = SOLANA_MAINNET_RPC_ENDPOINT, **kwargs: Any) -> None:
        self._rpc = _JsonRpc(endpoint, **kwargs)

    @property
    def endpoint(self) -> str:
        return self._rpc.endpoint

    @property
    def read_count(self) -> int:
        return self._rpc.read_count

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return self._rpc.evidence_records

    def get_multiple_accounts(self, addresses: list[str]) -> Any:
        if not 1 <= len(addresses) <= 100:
            raise SolanaError("getMultipleAccounts address count must be in [1, 100]")
        for index, address in enumerate(addresses):
            _pubkey(address, field=f"addresses[{index}]", allow_zero=False)
        return self._rpc.request(
            "getMultipleAccounts",
            [addresses, {"commitment": "finalized", "encoding": "base64"}],
        )

    def get_latest_blockhash(self) -> Any:
        return self._rpc.request("getLatestBlockhash", [{"commitment": "finalized"}])

    def get_block_height(self) -> Any:
        return self._rpc.request("getBlockHeight", [{"commitment": "finalized"}])


class JupiterV2Client:
    """Keyless, read-only Jupiter Swap V2 build client."""

    def __init__(self, endpoint: str = JUPITER_SWAP_V2_BUILD_ENDPOINT, **kwargs: Any) -> None:
        self._http = _HttpsGet(endpoint, **kwargs)

    @property
    def endpoint(self) -> str:
        return self._http.endpoint

    @property
    def read_count(self) -> int:
        return self._http.read_count

    @property
    def evidence_records(self) -> tuple[RawEvidenceRecord, ...]:
        return self._http.evidence_records

    def build(
        self,
        *,
        input_mint: str,
        output_mint: str,
        amount_atomic: int,
        taker: str,
        slippage_bps: int,
    ) -> dict[str, Any]:
        _pubkey(input_mint, field="inputMint", allow_zero=False)
        _pubkey(output_mint, field="outputMint", allow_zero=False)
        _pubkey(taker, field="taker", allow_zero=False)
        if input_mint == output_mint:
            raise SolanaError("inputMint and outputMint must differ")
        if isinstance(amount_atomic, bool) or not isinstance(amount_atomic, int) or amount_atomic <= 0 or amount_atomic > _MAX_U64:
            raise SolanaError("amount_atomic must be a positive uint64")
        if isinstance(slippage_bps, bool) or not isinstance(slippage_bps, int) or not 0 <= slippage_bps <= 10_000:
            raise SolanaError("slippage_bps must be in [0, 10000]")
        raw = self._http.get(
            {
                "amount": str(amount_atomic),
                "inputMint": input_mint,
                "outputMint": output_mint,
                "slippageBps": str(slippage_bps),
                "taker": taker,
            }
        )
        return _parse_build_response(
            raw,
            input_mint=input_mint,
            output_mint=output_mint,
            amount_atomic=amount_atomic,
            slippage_bps=slippage_bps,
        )


def _parse_build_response(
    raw: Any,
    *,
    input_mint: str,
    output_mint: str,
    amount_atomic: int,
    slippage_bps: int,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SolanaProtocolError("Jupiter build response must be an object")
    if "transaction" in raw or "swapTransaction" in raw:
        raise SafeHaltError("serialized third-party payload is outside the shadow boundary")
    required = {
        "inputMint", "outputMint", "inAmount", "outAmount", "otherAmountThreshold",
        "swapMode", "slippageBps", "priceImpactPct", "routePlan", "computeBudgetInstructions",
        "setupInstructions", "swapInstruction", "cleanupInstruction", "otherInstructions",
        "tipInstruction", "addressesByLookupTableAddress", "blockhashWithMetadata",
    }
    if set(raw) != required:
        raise SolanaProtocolError(f"Jupiter build response fields are not exact: {sorted(set(raw) ^ required)}")
    if raw["inputMint"] != input_mint or raw["outputMint"] != output_mint:
        raise SafeHaltError("Jupiter quote mint identity does not match the requested pair")
    in_amount = _atomic(raw["inAmount"], field="inAmount", positive=True)
    out_amount = _atomic(raw["outAmount"], field="outAmount", positive=True)
    threshold = _atomic(raw["otherAmountThreshold"], field="otherAmountThreshold")
    if in_amount != amount_atomic:
        raise SafeHaltError("Jupiter quote input amount does not match the exact requested size")
    if raw["swapMode"] != "ExactIn":
        raise SafeHaltError("only ExactIn Jupiter quotes are admitted")
    response_slippage = _json_integer(raw["slippageBps"], field="slippageBps", maximum=10_000)
    if response_slippage != slippage_bps:
        raise SafeHaltError("Jupiter response slippage does not match the request")
    policy_min_threshold = policy_min_threshold_atomic(out_amount, slippage_bps)
    if not 0 < threshold <= out_amount:
        raise SafeHaltError("Jupiter ExactIn threshold must be in (0, outAmount]")
    if threshold < policy_min_threshold:
        raise SafeHaltError("Jupiter ExactIn threshold is below the QntySpot policy minimum")
    impact = parse_canonical_decimal(raw["priceImpactPct"], field="priceImpactPct")
    if impact < 0 or impact >= 1:
        raise SafeHaltError("Jupiter price impact is outside [0, 1)")
    route_plan = _parse_route_plan(
        raw["routePlan"],
        input_mint,
        output_mint,
        expected_input_atomic=in_amount,
        expected_output_atomic=out_amount,
    )
    if not route_plan:
        raise SafeHaltError("Jupiter returned an empty route")
    instructions: list[dict[str, Any]] = []
    for name, group in (
        ("computeBudgetInstructions", raw["computeBudgetInstructions"]),
        ("setupInstructions", raw["setupInstructions"]),
        ("otherInstructions", raw["otherInstructions"]),
    ):
        if not isinstance(group, list):
            raise SolanaProtocolError(f"{name}: expected an array")
        for index, instruction in enumerate(group):
            instructions.append(_parse_instruction(instruction, field=f"{name}[{index}]", name=name))
    instructions.append(_parse_instruction(raw["swapInstruction"], field="swapInstruction", name="swapInstruction"))
    for name in ("cleanupInstruction", "tipInstruction"):
        value = raw[name]
        if value is not None:
            instructions.append(_parse_instruction(value, field=name, name=name))
    if not instructions:
        raise SafeHaltError("Jupiter returned no program instructions")
    lookup_evidence, transaction_semantics = _parse_lookup_mapping(raw["addressesByLookupTableAddress"])
    blockhash = _parse_blockhash_metadata(raw["blockhashWithMetadata"])
    return {
        "input_mint": input_mint,
        "output_mint": output_mint,
        "in_amount_atomic": in_amount,
        "out_amount_atomic": out_amount,
        "requested_slippage_bps": response_slippage,
        "policy_min_threshold_atomic": policy_min_threshold,
        "venue_threshold_atomic": threshold,
        # These aliases keep the internal build result compatible with the
        # existing adapter seam while the persisted contract uses explicit
        # policy/venue names.
        "threshold_atomic": threshold,
        "slippage_bps": response_slippage,
        "price_impact": impact,
        "route_plan": tuple(route_plan),
        "instruction_evidence": tuple(instructions),
        "lookup_evidence": tuple(lookup_evidence),
        "transaction_semantics": transaction_semantics,
        **blockhash,
    }


def _parse_route_plan(
    raw: Any,
    input_mint: str,
    output_mint: str,
    *,
    expected_input_atomic: int | None = None,
    expected_output_atomic: int | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= _MAX_ROUTE_STEPS:
        raise SolanaProtocolError("routePlan must contain between one and 64 steps")
    result: list[dict[str, Any]] = []
    edges: list[tuple[str, str, int, int, int, int]] = []
    for index, item in enumerate(raw):
        field = f"routePlan[{index}]"
        if not isinstance(item, dict) or set(item) not in (
            {"swapInfo", "percent", "bps"},
            {"swapInfo", "percent", "bps", "usdValue"},
        ):
            raise SolanaProtocolError(f"{field}: fields are not exact")
        swap = item["swapInfo"]
        allowed_swap = {"ammKey", "label", "inputMint", "outputMint", "inAmount", "outAmount"}
        if isinstance(swap, dict) and set(swap) in (allowed_swap, allowed_swap | {"feeAmount", "feeMint"}):
            amm_key = _pubkey(swap["ammKey"], field=f"{field}.swapInfo.ammKey", allow_zero=False)
            label = _text(swap["label"], field=f"{field}.swapInfo.label", maximum=128)
            route_input = _pubkey(swap["inputMint"], field=f"{field}.swapInfo.inputMint", allow_zero=False)
            route_output = _pubkey(swap["outputMint"], field=f"{field}.swapInfo.outputMint", allow_zero=False)
            route_in = _atomic(swap["inAmount"], field=f"{field}.swapInfo.inAmount", positive=True)
            route_out = _atomic(swap["outAmount"], field=f"{field}.swapInfo.outAmount", positive=True)
            normalized_swap: dict[str, Any] = {
                "ammKey": amm_key,
                "label": label,
                "inputMint": route_input,
                "outputMint": route_output,
                "inAmount": str(route_in),
                "outAmount": str(route_out),
            }
            if "feeAmount" in swap:
                normalized_swap["feeAmount"] = str(_atomic(swap["feeAmount"], field=f"{field}.swapInfo.feeAmount"))
                normalized_swap["feeMint"] = _pubkey(swap["feeMint"], field=f"{field}.swapInfo.feeMint", allow_zero=False)
        else:
            raise SolanaProtocolError(f"{field}.swapInfo: fields are not exact")
        percent = _json_integer(item["percent"], field=f"{field}.percent", maximum=100)
        bps = _json_integer(item["bps"], field=f"{field}.bps", minimum=1, maximum=10_000)
        edges.append((route_input, route_output, route_in, route_out, bps, percent))
        normalized: dict[str, Any] = {"bps": bps, "percent": percent, "swapInfo": normalized_swap}
        if "usdValue" in item:
            normalized["usdValue"] = _non_economic_decimal(item["usdValue"], field=f"{field}.usdValue")
        result.append(normalized)
    source_edges = [edge for edge in edges if edge[0] == input_mint]
    sink_edges = [edge for edge in edges if edge[1] == output_mint]
    if not source_edges or not sink_edges:
        raise SafeHaltError("Jupiter route does not connect the requested pair")
    if sum(edge[4] for edge in source_edges) != 10_000 or sum(edge[5] for edge in source_edges) != 100:
        raise SafeHaltError("Jupiter source route split does not total 10000 basis points and 100 percent")
    incoming: dict[str, int] = {}
    outgoing: dict[str, int] = {}
    for route_input, route_output, route_in, route_out, _bps, _percent in edges:
        outgoing[route_input] = outgoing.get(route_input, 0) + route_in
        incoming[route_output] = incoming.get(route_output, 0) + route_out
    for mint in set(incoming) | set(outgoing):
        if mint not in {input_mint, output_mint} and incoming.get(mint, 0) != outgoing.get(mint, 0):
            raise SafeHaltError("Jupiter route intermediate amounts do not reconcile")
    forward = {input_mint}
    reverse = {output_mint}
    changed = True
    while changed:
        changed = False
        for route_input, route_output, _route_in, _route_out, _bps, _percent in edges:
            if route_input in forward and route_output not in forward:
                forward.add(route_output)
                changed = True
            if route_output in reverse and route_input not in reverse:
                reverse.add(route_input)
                changed = True
    if any(route_input not in forward or route_output not in reverse for route_input, route_output, *_ in edges):
        raise SafeHaltError("Jupiter route contains a disconnected path")
    route_input_total = sum(edge[2] for edge in source_edges)
    route_output_total = sum(edge[3] for edge in sink_edges)
    if expected_input_atomic is not None and route_input_total != expected_input_atomic:
        raise SafeHaltError("Jupiter route input amounts do not reconcile with the quote")
    if expected_output_atomic is not None and route_output_total != expected_output_atomic:
        raise SafeHaltError("Jupiter route output amounts do not reconcile with the quote")
    return result


def _parse_instruction(raw: Any, *, field: str, name: str) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"programId", "accounts", "data"}:
        raise SolanaProtocolError(f"{field}: instruction fields are not exact")
    # System Program instructions are valid in Jupiter routes; preserve the
    # exact program identity without assuming every program address is nonzero.
    program_id = _pubkey(raw["programId"], field=f"{field}.programId", allow_zero=True)
    accounts = raw["accounts"]
    if not isinstance(accounts, list) or len(accounts) > _MAX_INSTRUCTION_ACCOUNTS:
        raise SolanaProtocolError(f"{field}.accounts: malformed or too large")
    account_evidence: list[dict[str, Any]] = []
    for index, account in enumerate(accounts):
        if not isinstance(account, dict) or set(account) != {"pubkey", "isWritable", "isSigner"}:
            raise SolanaProtocolError(f"{field}.accounts[{index}]: fields are not exact")
        if not isinstance(account["isWritable"], bool) or not isinstance(account["isSigner"], bool):
            raise SolanaProtocolError(f"{field}.accounts[{index}]: flags must be booleans")
        account_evidence.append(
            {
                "isSigner": account["isSigner"],
                "isWritable": account["isWritable"],
                "pubkey": _pubkey(account["pubkey"], field=f"{field}.accounts[{index}].pubkey"),
            }
        )
    data = raw["data"]
    if not isinstance(data, str) or not data or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", data):
        raise SolanaProtocolError(f"{field}.data: expected base64")
    try:
        decoded = base64.b64decode(data, validate=True)
    except Exception as exc:
        raise SolanaProtocolError(f"{field}.data: malformed base64") from exc
    if base64.b64encode(decoded).decode("ascii") != data:
        raise SolanaProtocolError(f"{field}.data: non-canonical base64")
    return {
        "accounts": account_evidence,
        "data_length": len(decoded),
        "data_sha256": hashlib.sha256(decoded).hexdigest(),
        "name": name,
        "program_id": program_id,
    }


def _parse_lookup_mapping(raw: Any) -> tuple[list[dict[str, Any]], str]:
    if raw is None:
        raise SafeHaltError("Jupiter omitted address-lookup-table semantics")
    if not isinstance(raw, dict):
        raise SolanaProtocolError("addressesByLookupTableAddress must be an object or null")
    if len(raw) > 16:
        raise SolanaProtocolError("too many address lookup tables")
    evidence: list[dict[str, Any]] = []
    for table, addresses in sorted(raw.items()):
        _pubkey(table, field="lookup table address", allow_zero=False)
        if not isinstance(addresses, list) or len(addresses) > _MAX_LOOKUP_ADDRESSES:
            raise SolanaProtocolError("lookup table address list is malformed or too large")
        normalized = [_pubkey(address, field="lookup address", allow_zero=False) for address in addresses]
        # Jupiter may list an address once per instruction reference. The
        # list is evidence of the venue's mapping, not a serialized ALT;
        # preserve its order and multiplicity without treating repeated
        # references as an economic or identity conflict.
        evidence.append({"addresses": normalized, "table_address": table})
    if evidence:
        return evidence, "VERSION_0_ADDRESS_LOOKUP_TABLES"
    return evidence, "INLINE_ADDRESSES_ONLY_NOT_A_LEGACY_ASSERTION"


def _parse_blockhash_metadata(raw: Any) -> dict[str, Any]:
    required = {"blockhash", "lastValidBlockHeight", "fetchedAt"}
    if not isinstance(raw, dict) or set(raw) != required:
        raise SolanaProtocolError("blockhashWithMetadata fields are not exact")
    blockhash_bytes = raw["blockhash"]
    if not isinstance(blockhash_bytes, list) or len(blockhash_bytes) != 32:
        raise SolanaProtocolError("Jupiter blockhash must be exactly 32 bytes")
    if any(isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255 for value in blockhash_bytes):
        raise SolanaProtocolError("Jupiter blockhash contains a non-byte")
    fetched = raw["fetchedAt"]
    if not isinstance(fetched, dict) or set(fetched) != {"secs_since_epoch", "nanos_since_epoch"}:
        raise SolanaProtocolError("Jupiter fetchedAt fields are not exact")
    secs = _json_integer(fetched["secs_since_epoch"], field="fetchedAt.secs_since_epoch")
    nanos = _json_integer(fetched["nanos_since_epoch"], field="fetchedAt.nanos_since_epoch", maximum=999_999_999)
    last_valid = _json_integer(raw["lastValidBlockHeight"], field="lastValidBlockHeight", minimum=1)
    return {
        "jupiter_blockhash": _base58_encode(bytes(blockhash_bytes)),
        "jupiter_blockhash_bytes": tuple(blockhash_bytes),
        "jupiter_fetched_at_epoch_s": secs,
        "jupiter_fetched_at_nanos": nanos,
        "jupiter_last_valid_block_height": last_valid,
    }


def _parse_rpc_context(raw: Any, *, field: str) -> int:
    if not isinstance(raw, dict) or set(raw) not in ({"slot"}, {"slot", "apiVersion"}):
        raise SolanaProtocolError(f"{field}: context fields are not exact")
    return _json_integer(raw["slot"], field=f"{field}.slot")


def _parse_latest_blockhash(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"context", "value"}:
        raise SolanaProtocolError("getLatestBlockhash result fields are not exact")
    slot = _parse_rpc_context(raw["context"], field="getLatestBlockhash.context")
    value = raw["value"]
    if not isinstance(value, dict) or set(value) != {"blockhash", "lastValidBlockHeight"}:
        raise SolanaProtocolError("getLatestBlockhash value fields are not exact")
    blockhash = _pubkey(value["blockhash"], field="getLatestBlockhash.blockhash", allow_zero=False)
    last_valid = _json_integer(value["lastValidBlockHeight"], field="getLatestBlockhash.lastValidBlockHeight", minimum=1)
    return {"slot": slot, "blockhash": blockhash, "last_valid_block_height": last_valid}


def _parse_mint_accounts(raw: Any, mint_addresses: tuple[str, str]) -> tuple[int, tuple[dict[str, Any], ...], int]:
    if not isinstance(raw, dict) or set(raw) != {"context", "value"}:
        raise SolanaProtocolError("getMultipleAccounts result fields are not exact")
    slot = _parse_rpc_context(raw["context"], field="getMultipleAccounts.context")
    values = raw["value"]
    if not isinstance(values, list) or len(values) != 2:
        raise SolanaProtocolError("getMultipleAccounts must return two accounts in order")
    evidence: list[dict[str, Any]] = []
    decimals: list[int] = []
    for index, account in enumerate(values):
        field = f"getMultipleAccounts.value[{index}]"
        if not isinstance(account, dict) or set(account) not in (
            {"data", "executable", "lamports", "owner", "rentEpoch"},
            {"data", "executable", "lamports", "owner", "rentEpoch", "space"},
        ):
            raise SolanaProtocolError(f"{field}: account fields are not exact")
        if account["executable"] is not False:
            raise SafeHaltError(f"{field}: mint account must not be executable")
        _json_integer(account["lamports"], field=f"{field}.lamports")
        _json_integer(account["rentEpoch"], field=f"{field}.rentEpoch")
        if "space" in account and account["space"] is not None:
            _json_integer(account["space"], field=f"{field}.space")
        owner = _pubkey(account["owner"], field=f"{field}.owner", allow_zero=False)
        owner_program = {
            SPL_TOKEN_PROGRAM_ADDRESS: TokenProgram.SPL_TOKEN,
            TOKEN_2022_PROGRAM_ADDRESS: TokenProgram.TOKEN_2022,
        }.get(owner)
        if owner_program is None:
            raise SafeHaltError(f"{field}: owner is neither the SPL Token nor Token-2022 program")
        data = account["data"]
        if not isinstance(data, list) or len(data) != 2 or data[1] != "base64" or not isinstance(data[0], str):
            raise SolanaProtocolError(f"{field}.data: expected [base64, base64]")
        try:
            decoded = base64.b64decode(data[0], validate=True)
        except Exception as exc:
            raise SolanaProtocolError(f"{field}.data: malformed base64") from exc
        if base64.b64encode(decoded).decode("ascii") != data[0] or len(decoded) < 82:
            raise SolanaProtocolError(f"{field}.data: malformed mint account bytes")
        mint_decimals = decoded[44]
        if mint_decimals > 36 or decoded[45] != 1:
            raise SafeHaltError(f"{field}: mint decimals or initialization flag is invalid")
        supply = int.from_bytes(decoded[36:44], "little")
        decimals.append(mint_decimals)
        evidence.append(
            {
                "account_data_length": len(decoded),
                "decimals": mint_decimals,
                "mint_address": mint_addresses[index],
                "owner": owner,
                "supply_atomic": str(supply),
                "token_program": owner_program.value,
            }
        )
    return slot, tuple(evidence), decimals[0] if decimals[0] >= 0 else 0


def _validate_instruction_evidence(items: tuple[dict[str, Any], ...]) -> None:
    digest_re = re.compile(r"^[0-9a-f]{64}$")
    for index, item in enumerate(items):
        field = f"instruction_evidence[{index}]"
        if not isinstance(item, dict) or set(item) != {"accounts", "data_length", "data_sha256", "name", "program_id"}:
            raise SolanaError(f"{field}: fields are not exact")
        _pubkey(item["program_id"], field=f"{field}.program_id", allow_zero=True)
        _text(item["name"], field=f"{field}.name", maximum=64)
        _json_integer(item["data_length"], field=f"{field}.data_length", maximum=2_000_000)
        if not isinstance(item["data_sha256"], str) or not digest_re.fullmatch(item["data_sha256"]):
            raise SolanaError(f"{field}.data_sha256: malformed SHA-256")
        accounts = item["accounts"]
        if not isinstance(accounts, list) or len(accounts) > _MAX_INSTRUCTION_ACCOUNTS:
            raise SolanaError(f"{field}.accounts: malformed")
        for account_index, account in enumerate(accounts):
            if not isinstance(account, dict) or set(account) != {"isSigner", "isWritable", "pubkey"}:
                raise SolanaError(f"{field}.accounts[{account_index}]: fields are not exact")
            if not isinstance(account["isSigner"], bool) or not isinstance(account["isWritable"], bool):
                raise SolanaError(f"{field}.accounts[{account_index}]: flags are not boolean")
            _pubkey(account["pubkey"], field=f"{field}.accounts[{account_index}].pubkey", allow_zero=True)


def _validate_mint_evidence(
    items: tuple[dict[str, Any], ...],
    *,
    input_mint: str,
    output_mint: str,
    input_program: TokenProgram,
    output_program: TokenProgram,
) -> None:
    if len(items) != 2:
        raise SolanaError("exactly two mint evidence records are required")
    expected = ((input_mint, input_program), (output_mint, output_program))
    for index, (item, (mint, program)) in enumerate(zip(items, expected)):
        field = f"mint_account_evidence[{index}]"
        if not isinstance(item, dict) or set(item) != {"account_data_length", "decimals", "mint_address", "owner", "supply_atomic", "token_program"}:
            raise SolanaError(f"{field}: fields are not exact")
        if item["mint_address"] != mint or item["token_program"] != program.value:
            raise SafeHaltError(f"{field}: mint or token-program identity changed")
        _pubkey(item["owner"], field=f"{field}.owner", allow_zero=False)
        expected_owner = SPL_TOKEN_PROGRAM_ADDRESS if program is TokenProgram.SPL_TOKEN else TOKEN_2022_PROGRAM_ADDRESS
        if item["owner"] != expected_owner:
            raise SafeHaltError(f"{field}: owner does not match token program")
        _json_integer(item["account_data_length"], field=f"{field}.account_data_length", minimum=82)
        _json_integer(item["decimals"], field=f"{field}.decimals", maximum=36)
        _atomic(item["supply_atomic"], field=f"{field}.supply_atomic")


def _validate_lookup_evidence(items: tuple[dict[str, Any], ...], semantics: str) -> None:
    mapping: dict[str, list[str]] = {}
    for index, item in enumerate(items):
        field = f"lookup_table_evidence[{index}]"
        if not isinstance(item, dict) or set(item) != {"addresses", "table_address"}:
            raise SolanaError(f"{field}: fields are not exact")
        table = _pubkey(item["table_address"], field=f"{field}.table_address", allow_zero=False)
        addresses = item["addresses"]
        if not isinstance(addresses, list) or len(addresses) > _MAX_LOOKUP_ADDRESSES:
            raise SolanaError(f"{field}.addresses: malformed")
        mapping[table] = [_pubkey(address, field=f"{field}.addresses", allow_zero=False) for address in addresses]
    normalized, expected_semantics = _parse_lookup_mapping(mapping)
    if tuple(normalized) != items or expected_semantics != semantics:
        raise SolanaError("lookup-table evidence is not canonical")


@dataclass(frozen=True, slots=True)
class SolanaMarketObservationV0:
    schema: str
    cluster: SolanaCluster
    side: Side
    input_mint: str
    output_mint: str
    input_token_program: TokenProgram
    output_token_program: TokenProgram
    input_decimals: int
    output_decimals: int
    requested_input_atomic: int
    quoted_output_atomic: int
    requested_slippage_bps: int
    policy_min_threshold_atomic: int
    venue_threshold_atomic: int
    price_impact_pct: Fraction
    slot_before: int
    mint_accounts_slot: int
    slot_after: int
    block_height_before: int
    block_height_after: int
    jupiter_blockhash: str
    jupiter_last_valid_block_height: int
    jupiter_fetched_at_epoch_s: int
    jupiter_fetched_at_nanos: int
    rpc_endpoint: str
    jupiter_endpoint: str
    transaction_semantics: str
    route_plan: tuple[dict[str, Any], ...]
    instruction_evidence: tuple[dict[str, Any], ...]
    lookup_table_evidence: tuple[dict[str, Any], ...]
    program_ids: tuple[str, ...]
    mint_account_evidence: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        if self.schema != "SOLANA_MARKET_OBSERVATION_V0":
            raise SolanaError("observation schema mismatch")
        if not isinstance(self.cluster, SolanaCluster):
            raise SolanaError("observation cluster is invalid")
        if not isinstance(self.side, Side):
            raise SolanaError("observation side is invalid")
        _pubkey(self.input_mint, field="input_mint", allow_zero=False)
        _pubkey(self.output_mint, field="output_mint", allow_zero=False)
        if self.input_mint == self.output_mint:
            raise SolanaError("observation mint pair must differ")
        if not isinstance(self.input_token_program, TokenProgram) or not isinstance(self.output_token_program, TokenProgram):
            raise SolanaError("observation token program identity is invalid")
        for name in ("input_decimals", "output_decimals"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 36:
                raise SolanaError(f"{name} is invalid")
        for name in (
            "requested_input_atomic",
            "quoted_output_atomic",
            "policy_min_threshold_atomic",
            "venue_threshold_atomic",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_U64:
                raise SolanaError(f"{name} must be a uint64")
        if self.requested_input_atomic <= 0 or self.quoted_output_atomic <= 0:
            raise SolanaError("requested and quoted atomic amounts must be positive")
        if (
            isinstance(self.requested_slippage_bps, bool)
            or not isinstance(self.requested_slippage_bps, int)
            or not 0 <= self.requested_slippage_bps <= _BPS_DENOMINATOR
        ):
            raise SolanaError("requested_slippage_bps is invalid")
        expected_policy_min = policy_min_threshold_atomic(
            self.quoted_output_atomic, self.requested_slippage_bps
        )
        if self.policy_min_threshold_atomic != expected_policy_min:
            raise SolanaError("policy_min_threshold_atomic is not canonical")
        if not 0 < self.venue_threshold_atomic <= self.quoted_output_atomic:
            raise SafeHaltError("venue threshold must be in (0, quoted output]")
        if self.venue_threshold_atomic < self.policy_min_threshold_atomic:
            raise SafeHaltError("venue threshold is below the QntySpot policy minimum")
        if not isinstance(self.price_impact_pct, Fraction) or not 0 <= self.price_impact_pct < 1:
            raise SolanaError("price_impact_pct is invalid")
        if self.slot_before < 0 or self.mint_accounts_slot < self.slot_before or self.slot_after < self.mint_accounts_slot:
            raise SolanaError("observation slots are not monotone")
        if self.block_height_before < 0 or self.block_height_after < self.block_height_before:
            raise SolanaError("observation block heights are not monotone")
        _pubkey(self.jupiter_blockhash, field="jupiter_blockhash", allow_zero=False)
        if self.jupiter_last_valid_block_height <= 0 or self.jupiter_fetched_at_epoch_s < 0 or not 0 <= self.jupiter_fetched_at_nanos < 1_000_000_000:
            raise SolanaError("Jupiter freshness metadata is invalid")
        if not isinstance(self.rpc_endpoint, str) or not isinstance(self.jupiter_endpoint, str):
            raise SolanaError("observation endpoints are invalid")
        if self.transaction_semantics not in {
            "VERSION_0_ADDRESS_LOOKUP_TABLES",
            "INLINE_ADDRESSES_ONLY_NOT_A_LEGACY_ASSERTION",
        }:
            raise SolanaError("transaction semantics are invalid")
        if not self.route_plan or not self.instruction_evidence:
            raise SolanaError("observation lacks route or program evidence")
        if not self.program_ids or any(not isinstance(value, str) for value in self.program_ids):
            raise SolanaError("program identity evidence is invalid")
        for index, program_id in enumerate(self.program_ids):
            _pubkey(program_id, field=f"program_ids[{index}]", allow_zero=True)
        _validate_mint_evidence(
            self.mint_account_evidence,
            input_mint=self.input_mint,
            output_mint=self.output_mint,
            input_program=self.input_token_program,
            output_program=self.output_token_program,
        )
        input_evidence = self.mint_account_evidence[0]
        output_evidence = self.mint_account_evidence[1]
        if self.input_decimals != input_evidence["decimals"] or self.output_decimals != output_evidence["decimals"]:
            raise SafeHaltError("observation decimals do not match mint-account evidence")
        normalized_route = _parse_route_plan(
            list(self.route_plan),
            self.input_mint,
            self.output_mint,
            expected_input_atomic=self.requested_input_atomic,
            expected_output_atomic=self.quoted_output_atomic,
        )
        if tuple(normalized_route) != self.route_plan:
            raise SolanaError("route evidence is not canonical")
        _validate_instruction_evidence(self.instruction_evidence)
        _validate_lookup_evidence(self.lookup_table_evidence, self.transaction_semantics)

    def canonical_object(self) -> dict[str, Any]:
        return {
            "block_height_after": self.block_height_after,
            "block_height_before": self.block_height_before,
            "cluster": self.cluster.value,
            "input_decimals": self.input_decimals,
            "input_mint": self.input_mint,
            "input_token_program": self.input_token_program.value,
            "instruction_evidence": [dict(item) for item in self.instruction_evidence],
            "jupiter_blockhash": self.jupiter_blockhash,
            "jupiter_endpoint": self.jupiter_endpoint,
            "jupiter_fetched_at_epoch_s": self.jupiter_fetched_at_epoch_s,
            "jupiter_fetched_at_nanos": self.jupiter_fetched_at_nanos,
            "jupiter_last_valid_block_height": self.jupiter_last_valid_block_height,
            "policy_min_threshold_atomic": str(self.policy_min_threshold_atomic),
            "lookup_table_evidence": [dict(item) for item in self.lookup_table_evidence],
            "mint_accounts_slot": self.mint_accounts_slot,
            "mint_account_evidence": [dict(item) for item in self.mint_account_evidence],
            "output_decimals": self.output_decimals,
            "output_mint": self.output_mint,
            "output_token_program": self.output_token_program.value,
            "price_impact_pct": _ratio(self.price_impact_pct),
            "program_ids": list(self.program_ids),
            "quoted_output_atomic": str(self.quoted_output_atomic),
            "requested_input_atomic": str(self.requested_input_atomic),
            "route_plan": [dict(item) for item in self.route_plan],
            "rpc_endpoint": self.rpc_endpoint,
            "schema": self.schema,
            "side": self.side.value,
            "slot_after": self.slot_after,
            "slot_before": self.slot_before,
            "requested_slippage_bps": self.requested_slippage_bps,
            "transaction_semantics": self.transaction_semantics,
            "venue_threshold_atomic": str(self.venue_threshold_atomic),
        }

    @property
    def jupiter_threshold_atomic(self) -> int:
        """Compatibility view of the venue-imposed ExactIn threshold."""
        return self.venue_threshold_atomic

    @property
    def slippage_bps(self) -> int:
        """Compatibility view of the requested policy slippage."""
        return self.requested_slippage_bps

    def digest(self) -> str:
        return digest_object(self.canonical_object())

    @classmethod
    def from_canonical(cls, obj: Any) -> "SolanaMarketObservationV0":
        if not isinstance(obj, dict):
            raise SolanaError("observation must be an object")
        required = {
            "block_height_after", "block_height_before", "cluster", "input_decimals", "input_mint",
            "input_token_program", "instruction_evidence", "jupiter_blockhash", "jupiter_endpoint",
            "jupiter_fetched_at_epoch_s", "jupiter_fetched_at_nanos", "jupiter_last_valid_block_height",
            "lookup_table_evidence", "mint_accounts_slot", "mint_account_evidence",
            "output_decimals", "output_mint", "output_token_program", "price_impact_pct", "program_ids",
            "quoted_output_atomic", "requested_input_atomic", "route_plan", "rpc_endpoint", "schema",
            "policy_min_threshold_atomic", "requested_slippage_bps", "side", "slot_after", "slot_before",
            "transaction_semantics", "venue_threshold_atomic",
        }
        if set(obj) != required:
            raise SolanaError("observation fields are not exact")
        try:
            cluster = SolanaCluster(obj["cluster"])
            side = Side(obj["side"])
            input_program = TokenProgram(obj["input_token_program"])
            output_program = TokenProgram(obj["output_token_program"])
        except ValueError as exc:
            raise SolanaError("observation enum field is invalid") from exc
        int_fields = (
            "block_height_after", "block_height_before", "input_decimals", "jupiter_fetched_at_epoch_s",
            "jupiter_fetched_at_nanos", "jupiter_last_valid_block_height", "mint_accounts_slot", "output_decimals",
            "requested_slippage_bps", "slot_after", "slot_before",
        )
        for field in int_fields:
            if field.endswith("decimals"):
                maximum = 36
            elif field == "requested_slippage_bps":
                maximum = _BPS_DENOMINATOR
            elif field == "jupiter_fetched_at_nanos":
                maximum = 999_999_999
            else:
                maximum = _MAX_U64
            _json_integer(obj[field], field=field, maximum=maximum)
        _atomic(obj["quoted_output_atomic"], field="quoted_output_atomic", positive=True)
        _atomic(obj["requested_input_atomic"], field="requested_input_atomic", positive=True)
        _atomic(obj["policy_min_threshold_atomic"], field="policy_min_threshold_atomic")
        _atomic(obj["venue_threshold_atomic"], field="venue_threshold_atomic")
        if not isinstance(obj["route_plan"], list) or not isinstance(obj["instruction_evidence"], list) or not isinstance(obj["lookup_table_evidence"], list) or not isinstance(obj["mint_account_evidence"], list) or not isinstance(obj["program_ids"], list):
            raise SolanaError("observation evidence arrays are malformed")
        if any(not isinstance(item, dict) for item in obj["route_plan"] + obj["instruction_evidence"] + obj["lookup_table_evidence"] + obj["mint_account_evidence"]):
            raise SolanaError("observation evidence item is malformed")
        if any(not isinstance(item, str) for item in obj["program_ids"]):
            raise SolanaError("program_ids are malformed")
        return cls(
            schema=obj["schema"], cluster=cluster, side=side, input_mint=obj["input_mint"], output_mint=obj["output_mint"],
            input_token_program=input_program, output_token_program=output_program,
            input_decimals=obj["input_decimals"], output_decimals=obj["output_decimals"],
            requested_input_atomic=int(obj["requested_input_atomic"]), quoted_output_atomic=int(obj["quoted_output_atomic"]),
            requested_slippage_bps=obj["requested_slippage_bps"],
            policy_min_threshold_atomic=int(obj["policy_min_threshold_atomic"]),
            venue_threshold_atomic=int(obj["venue_threshold_atomic"]),
            price_impact_pct=_parse_ratio(obj["price_impact_pct"], field="price_impact_pct"),
            slot_before=obj["slot_before"], mint_accounts_slot=obj["mint_accounts_slot"], slot_after=obj["slot_after"],
            block_height_before=obj["block_height_before"], block_height_after=obj["block_height_after"],
            jupiter_blockhash=obj["jupiter_blockhash"], jupiter_last_valid_block_height=obj["jupiter_last_valid_block_height"],
            jupiter_fetched_at_epoch_s=obj["jupiter_fetched_at_epoch_s"], jupiter_fetched_at_nanos=obj["jupiter_fetched_at_nanos"],
            rpc_endpoint=obj["rpc_endpoint"], jupiter_endpoint=obj["jupiter_endpoint"],
            transaction_semantics=obj["transaction_semantics"], route_plan=tuple(obj["route_plan"]),
            instruction_evidence=tuple(obj["instruction_evidence"]), lookup_table_evidence=tuple(obj["lookup_table_evidence"]),
            program_ids=tuple(obj["program_ids"]), mint_account_evidence=tuple(obj["mint_account_evidence"]),
        )


def _human_price(observation: SolanaMarketObservationV0, side: Side) -> tuple[Fraction, Fraction]:
    if side is Side.BUY:
        average = Fraction(
            observation.requested_input_atomic * (10 ** observation.output_decimals),
            observation.quoted_output_atomic * (10 ** observation.input_decimals),
        )
    else:
        average = Fraction(
            observation.quoted_output_atomic * (10 ** observation.input_decimals),
            observation.requested_input_atomic * (10 ** observation.output_decimals),
        )
    spot = average / (1 - observation.price_impact_pct)
    return average, spot


class SolanaShadowAdapter:
    """One exact-pair, public-read Jupiter Swap V2 shadow adapter."""

    venue_id = "jupiter-swap-v2-solana-mainnet-beta"

    def __init__(
        self,
        rpc: SolanaRpcClient,
        jupiter: JupiterV2Client,
        *,
        cluster: SolanaCluster = SolanaCluster.MAINNET_BETA,
        max_slot_age: int = 150,
        max_quote_age_s: int = 90,
    ) -> None:
        if not isinstance(cluster, SolanaCluster):
            raise SolanaError("cluster must be a SolanaCluster")
        if isinstance(max_slot_age, bool) or not isinstance(max_slot_age, int) or max_slot_age < 0:
            raise SolanaError("max_slot_age must be a non-negative integer")
        if isinstance(max_quote_age_s, bool) or not isinstance(max_quote_age_s, int) or max_quote_age_s < 1:
            raise SolanaError("max_quote_age_s must be positive")
        self.rpc = rpc
        self.jupiter = jupiter
        self.cluster = cluster
        self.max_slot_age = max_slot_age
        self.max_quote_age_s = max_quote_age_s
        self._observation: SolanaMarketObservationV0 | None = None

    @staticmethod
    def _refs(policy: PolicyV0, side: Side) -> tuple[SolanaInstrumentRef, SolanaInstrumentRef]:
        base = policy.base.ref
        quote = policy.quote.ref
        if not isinstance(base, SolanaInstrumentRef) or not isinstance(quote, SolanaInstrumentRef):
            raise SafeHaltError("Solana shadow policy must contain two Solana instruments")
        return (quote, base) if side is Side.BUY else (base, quote)

    def observe(
        self,
        policy: PolicyV0,
        cycle_id: str,
        level_id: str,
        *,
        now_epoch_s: int,
        taker: str,
        inventory_atomic: int | None = None,
    ) -> SolanaMarketObservationV0:
        intent = build_intent(policy, cycle_id, policy.level(level_id), now_epoch_s=now_epoch_s, inventory_atomic=inventory_atomic)
        input_ref, output_ref = self._refs(policy, intent.side)
        if input_ref.cluster is not self.cluster or output_ref.cluster is not self.cluster:
            raise SafeHaltError("policy cluster does not match the bounded Solana adapter")
        if intent.bounds.max_input_atomic <= 0:
            raise LevelNotExecutableError("intent input amount must be positive")
        _pubkey(taker, field="taker", allow_zero=False)
        before = _parse_latest_blockhash(self.rpc.get_latest_blockhash())
        before_height = _json_integer(self.rpc.get_block_height(), field="getBlockHeight.before")
        accounts_raw = self.rpc.get_multiple_accounts([input_ref.mint_address, output_ref.mint_address])
        account_slot, account_evidence, _ = _parse_mint_accounts(accounts_raw, (input_ref.mint_address, output_ref.mint_address))
        for index, ref in enumerate((input_ref, output_ref)):
            evidence_program = account_evidence[index]["token_program"]
            if evidence_program != ref.token_program.value:
                raise SafeHaltError("mint owner token-program identity does not match policy identity")
            if intent.side is Side.BUY:
                expected_decimals = policy.quote.decimals if index == 0 else policy.base.decimals
            else:
                expected_decimals = policy.base.decimals if index == 0 else policy.quote.decimals
            if int(account_evidence[index]["decimals"]) != expected_decimals:
                raise SafeHaltError("mint decimals do not match the exact policy instrument")
        build = self.jupiter.build(
            input_mint=input_ref.mint_address,
            output_mint=output_ref.mint_address,
            amount_atomic=intent.bounds.max_input_atomic,
            taker=taker,
            slippage_bps=policy.max_slippage_bps,
        )
        after = _parse_latest_blockhash(self.rpc.get_latest_blockhash())
        after_height = _json_integer(self.rpc.get_block_height(), field="getBlockHeight.after")
        if before["slot"] > account_slot or account_slot > after["slot"] or before["slot"] > after["slot"]:
            raise SafeHaltError("Solana RPC contexts are not monotone around the observation")
        if after["slot"] - before["slot"] > self.max_slot_age:
            raise SafeHaltError("Solana quote window exceeded the slot freshness bound")
        if before_height > after_height:
            raise SafeHaltError("Solana block heights are not monotone")
        if after_height >= build["jupiter_last_valid_block_height"]:
            raise SafeHaltError("Jupiter blockhash is stale or already expired")
        if now_epoch_s < build["jupiter_fetched_at_epoch_s"]:
            raise SafeHaltError("Jupiter fetchedAt is in the future relative to the supplied time")
        if now_epoch_s - build["jupiter_fetched_at_epoch_s"] > self.max_quote_age_s:
            raise SafeHaltError("Jupiter quote is stale by fetchedAt")
        program_ids = tuple(dict.fromkeys(item["program_id"] for item in build["instruction_evidence"]))
        observation = SolanaMarketObservationV0(
            schema="SOLANA_MARKET_OBSERVATION_V0",
            cluster=self.cluster,
            side=intent.side,
            input_mint=input_ref.mint_address,
            output_mint=output_ref.mint_address,
            input_token_program=input_ref.token_program,
            output_token_program=output_ref.token_program,
            input_decimals=int(account_evidence[0]["decimals"]),
            output_decimals=int(account_evidence[1]["decimals"]),
            requested_input_atomic=build["in_amount_atomic"],
            quoted_output_atomic=build["out_amount_atomic"],
            requested_slippage_bps=build["requested_slippage_bps"],
            policy_min_threshold_atomic=build["policy_min_threshold_atomic"],
            venue_threshold_atomic=build["venue_threshold_atomic"],
            price_impact_pct=build["price_impact"],
            slot_before=before["slot"],
            mint_accounts_slot=account_slot,
            slot_after=after["slot"],
            block_height_before=before_height,
            block_height_after=after_height,
            jupiter_blockhash=build["jupiter_blockhash"],
            jupiter_last_valid_block_height=build["jupiter_last_valid_block_height"],
            jupiter_fetched_at_epoch_s=build["jupiter_fetched_at_epoch_s"],
            jupiter_fetched_at_nanos=build["jupiter_fetched_at_nanos"],
            rpc_endpoint=self.rpc.endpoint,
            jupiter_endpoint=self.jupiter.endpoint,
            transaction_semantics=build["transaction_semantics"],
            route_plan=build["route_plan"],
            instruction_evidence=build["instruction_evidence"],
            lookup_table_evidence=build["lookup_evidence"],
            program_ids=program_ids,
            mint_account_evidence=account_evidence,
        )
        self._observation = observation
        return observation

    def _require_observation(self, observation: SolanaMarketObservationV0 | None) -> SolanaMarketObservationV0:
        chosen = observation or self._observation
        if chosen is None:
            raise SafeHaltError("no frozen Solana observation is available")
        return chosen

    def _validate_bounds(self, policy: PolicyV0, bounds: EconomicBounds, observation: SolanaMarketObservationV0) -> None:
        input_ref, output_ref = self._refs(policy, bounds.side)
        expected_input = f"solana:{input_ref.cluster.value}:{input_ref.mint_address}:{input_ref.token_program.value}"
        expected_output = f"solana:{output_ref.cluster.value}:{output_ref.mint_address}:{output_ref.token_program.value}"
        if bounds.input_instrument_id != expected_input or bounds.output_instrument_id != expected_output:
            raise SafeHaltError("quote bounds do not match the exact Solana mint pair")
        if observation.input_mint != input_ref.mint_address or observation.output_mint != output_ref.mint_address:
            raise SafeHaltError("frozen Solana observation mint identity does not match policy")
        if observation.input_token_program is not input_ref.token_program or observation.output_token_program is not output_ref.token_program:
            raise SafeHaltError("frozen Solana observation token-program identity does not match policy")
        if observation.side is not bounds.side:
            raise SafeHaltError("frozen Solana observation side does not match the economic bounds")
        expected_input_decimals = policy.quote.decimals if bounds.side is Side.BUY else policy.base.decimals
        expected_output_decimals = policy.base.decimals if bounds.side is Side.BUY else policy.quote.decimals
        if observation.input_decimals != expected_input_decimals or observation.output_decimals != expected_output_decimals:
            raise SafeHaltError("frozen Solana observation decimals do not match policy")
        if observation.requested_input_atomic != bounds.max_input_atomic:
            raise SafeHaltError("frozen Solana observation input size does not match the intent")
        if observation.requested_slippage_bps != bounds.max_slippage_bps:
            raise SafeHaltError("frozen Solana observation slippage does not match policy")
        expected_policy_min = policy_min_threshold_atomic(
            observation.quoted_output_atomic, bounds.max_slippage_bps
        )
        if observation.policy_min_threshold_atomic != expected_policy_min:
            raise SafeHaltError("frozen Solana policy threshold does not match policy")
        if observation.venue_threshold_atomic < expected_policy_min:
            raise SafeHaltError("frozen Solana venue threshold is looser than policy")

    def quote(self, bounds: EconomicBounds, *, now_epoch_s: int) -> QuoteV0:
        observation = self._require_observation(None)
        if not isinstance(now_epoch_s, int) or isinstance(now_epoch_s, bool):
            raise SolanaError("now_epoch_s must be an integer")
        expected_input = f"solana:{observation.cluster.value}:{observation.input_mint}:{observation.input_token_program.value}"
        expected_output = f"solana:{observation.cluster.value}:{observation.output_mint}:{observation.output_token_program.value}"
        if bounds.input_instrument_id != expected_input or bounds.output_instrument_id != expected_output:
            raise SafeHaltError("quote bounds do not match the frozen Solana mint pair")
        if bounds.side is not observation.side:
            raise SafeHaltError("quote side does not match the frozen Solana observation")
        if observation.requested_input_atomic != bounds.max_input_atomic:
            raise SafeHaltError("quote input size does not match the frozen Solana observation")
        if observation.requested_slippage_bps != bounds.max_slippage_bps:
            raise SafeHaltError("quote slippage does not match the frozen Solana policy")
        expected_policy_min = policy_min_threshold_atomic(
            observation.quoted_output_atomic, bounds.max_slippage_bps
        )
        if observation.policy_min_threshold_atomic != expected_policy_min:
            raise SafeHaltError("quote policy threshold does not match policy")
        if observation.venue_threshold_atomic < expected_policy_min:
            raise SafeHaltError("quote venue threshold is looser than policy")
        if now_epoch_s < observation.jupiter_fetched_at_epoch_s:
            raise SafeHaltError("Jupiter quote is from the future relative to the supplied time")
        if now_epoch_s - observation.jupiter_fetched_at_epoch_s > self.max_quote_age_s:
            raise SafeHaltError("Jupiter quote is stale by fetchedAt")
        if observation.quoted_output_atomic < bounds.min_output_atomic:
            raise LevelNotExecutableError("Jupiter quote is below the absolute output bound")
        return QuoteV0(
            quote_id=digest_object({"bounds": bounds.canonical_object(), "observation_digest": observation.digest()}),
            economic_action_id="shadow-quote",
            input_atomic=observation.requested_input_atomic,
            output_atomic=observation.quoted_output_atomic,
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
        observation: SolanaMarketObservationV0 | None = None,
        inventory_atomic: int | None = None,
        current_slot: int | None = None,
        current_block_height: int | None = None,
    ) -> ShadowDecisionV0:
        obs = self._require_observation(observation)
        level = policy.level(level_id)
        intent = build_intent(policy, cycle_id, level, now_epoch_s=now_epoch_s, inventory_atomic=inventory_atomic)
        self._validate_bounds(policy, intent.bounds, obs)
        current_slot = obs.slot_after if current_slot is None else current_slot
        current_block_height = obs.block_height_after if current_block_height is None else current_block_height
        if isinstance(current_slot, bool) or not isinstance(current_slot, int) or current_slot < obs.slot_after:
            raise SafeHaltError("current slot precedes the frozen observation")
        if isinstance(current_block_height, bool) or not isinstance(current_block_height, int) or current_block_height < obs.block_height_after:
            raise SafeHaltError("current block height precedes the frozen observation")
        average, spot = _human_price(obs, intent.side)
        reasons: list[str] = []
        if current_slot - obs.slot_after > self.max_slot_age:
            reasons.append("STALE_SLOT")
        if now_epoch_s < obs.jupiter_fetched_at_epoch_s:
            reasons.append("QUOTE_FROM_FUTURE")
        if now_epoch_s - obs.jupiter_fetched_at_epoch_s > self.max_quote_age_s:
            reasons.append("STALE_QUOTE")
        if current_block_height >= obs.jupiter_last_valid_block_height:
            reasons.append("STALE_JUPITER_BLOCKHASH")
        if obs.quoted_output_atomic < intent.bounds.min_output_atomic:
            reasons.append("MIN_OUTPUT_BOUND")
        if intent.side is Side.BUY and average > intent.bounds.limit_price:
            reasons.append("MAX_EXECUTABLE_PRICE")
        if intent.side is Side.SELL and average < intent.bounds.limit_price:
            reasons.append("MIN_EXECUTABLE_PRICE")
        impact_bps = obs.price_impact_pct * 10_000
        if impact_bps > intent.bounds.max_price_impact_bps:
            reasons.append("MAX_PRICE_IMPACT")
        return ShadowDecisionV0(
            schema="SHADOW_DECISION_V0",
            decision="WOULD_EXECUTE" if not reasons else "ABSTAIN",
            reason_code="PASS" if not reasons else "+".join(reasons),
            observation_digest=obs.digest(), policy_id=policy.policy_id, cycle_id=cycle_id, level_id=level_id,
            side=intent.side, economic_action_id=intent.economic_action_id,
            common_block=obs.slot_after, current_common_block=current_slot,
            expected_output_atomic=obs.quoted_output_atomic, average_price=average, spot_price=spot,
            price_impact_bps=impact_bps, fee_atomic=Fraction(0),
            bound_limit_price=intent.bounds.limit_price,
            bound_min_output_atomic=intent.bounds.min_output_atomic,
            bound_max_input_atomic=intent.bounds.max_input_atomic,
        )


def replay_shadow_decision(
    policy: PolicyV0,
    observation: SolanaMarketObservationV0,
    cycle_id: str,
    level_id: str,
    *,
    now_epoch_s: int,
    current_slot: int | None = None,
    current_block_height: int | None = None,
    max_slot_age: int = 150,
    max_quote_age_s: int = 90,
    inventory_atomic: int | None = None,
) -> ShadowDecisionV0:
    adapter = object.__new__(SolanaShadowAdapter)
    adapter.cluster = observation.cluster
    adapter.max_slot_age = max_slot_age
    adapter.max_quote_age_s = max_quote_age_s
    adapter._observation = observation
    return adapter.shadow_decision(
        policy, cycle_id, level_id, now_epoch_s=now_epoch_s, observation=observation,
        current_slot=current_slot, current_block_height=current_block_height, inventory_atomic=inventory_atomic,
    )


def _persist(path: str | Path, record: Any) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes({"digest": record.digest(), "record": record.canonical_object()})
    try:
        with target.open("xb") as handle:
            handle.write(payload)
    except FileExistsError:
        if target.read_bytes() != payload:
            raise SafeHaltError(f"immutable record path already contains different data: {target}")
    return record.digest()


def persist_observation(path: str | Path, observation: SolanaMarketObservationV0) -> str:
    return _persist(path, observation)


def persist_decision(path: str | Path, decision: ShadowDecisionV0) -> str:
    return _persist(path, decision)


def _load(path: str | Path, factory: Callable[[Any], Any]) -> Any:
    try:
        raw = strict_json_loads(Path(path).read_bytes())
    except Exception as exc:
        raise SolanaError("persisted record is not strict JSON") from exc
    if not isinstance(raw, dict) or set(raw) != {"digest", "record"} or not isinstance(raw["digest"], str):
        raise SolanaError("persisted record envelope is malformed")
    record = factory(raw["record"])
    if record.digest() != raw["digest"]:
        raise SafeHaltError("persisted record digest mismatch")
    return record


def load_observation(path: str | Path) -> SolanaMarketObservationV0:
    return _load(path, SolanaMarketObservationV0.from_canonical)


def load_decision(path: str | Path) -> ShadowDecisionV0:
    return _load(path, ShadowDecisionV0.from_canonical)
