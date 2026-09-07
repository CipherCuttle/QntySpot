"""Read-only validation and one-way transport for complete EVM byte strings.

The caller supplies the complete signed transaction.  This module never
creates an unsigned object, fills a field, or serializes a decoded object.
Only the byte string and immutable validation scope cross the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import rlp
from eth_keys import keys

from .canon import digest_object, sha256_hex
from .errors import EnvelopeValidationError
from .execution_contract import derive_transaction_hash
from .keccak import keccak256

__all__ = [
    "ExactSignedBytesScopeV0",
    "ParsedExactSignedBytesV0",
    "ValidatedExactSignedBytesV0",
    "ExactSignedTransactionRecordV0",
    "ExactSignedBytesAdmissionV0",
    "ExactSignedBytesTransport",
    "JsonRpcExactSignedBytesTransport",
    "validate_exact_signed_bytes",
]

_ADDRESS_RE = lambda value: isinstance(value, str) and len(value) == 42 and value.startswith("0x") and all(
    char in "0123456789abcdef" for char in value[2:]
)
_DIGEST_RE = lambda value: isinstance(value, str) and len(value) == 64 and all(
    char in "0123456789abcdef" for char in value
)
_MAX_UINT256 = 2**256 - 1


def _uint(value: bytes, *, field: str, allow_zero: bool = True) -> int:
    if not isinstance(value, bytes):
        raise EnvelopeValidationError(f"{field} is not an encoded integer")
    if len(value) > 32 or (len(value) > 1 and value[0] == 0):
        raise EnvelopeValidationError(f"{field} is not canonical")
    number = int.from_bytes(value, "big")
    if not allow_zero and number == 0:
        raise EnvelopeValidationError(f"{field} must be positive")
    return number


def _address(value: str, *, field: str) -> None:
    if not _ADDRESS_RE(value) or int(value, 16) == 0:
        raise EnvelopeValidationError(f"{field} is not a canonical non-zero address")


def _field_bytes(value: Any, *, field: str) -> bytes:
    if not isinstance(value, bytes):
        raise EnvelopeValidationError(f"{field} is not a byte string")
    return value


def _access_list(value: Any) -> None:
    if not isinstance(value, list):
        raise EnvelopeValidationError("access list is not an RLP list")
    for index, item in enumerate(value):
        if not isinstance(item, list) or len(item) != 2:
            raise EnvelopeValidationError(f"access list item {index} is malformed")
        address, slots = item
        if not isinstance(address, bytes) or len(address) != 20:
            raise EnvelopeValidationError(f"access list item {index} address is malformed")
        if not isinstance(slots, list):
            raise EnvelopeValidationError(f"access list item {index} slots are malformed")
        for slot in slots:
            if not isinstance(slot, bytes) or len(slot) != 32:
                raise EnvelopeValidationError(f"access list item {index} slot is malformed")


@dataclass(frozen=True, slots=True)
class ExactSignedBytesScopeV0:
    """Immutable scope supplied by the independently governed caller."""

    session_id: str
    session_identity_digest: str
    economic_action_id: str
    authority_policy_digest: str
    chain_id: int
    taker_address: str
    target_address: str
    min_value_atomic: int
    max_value_atomic: int
    calldata_sha256: str
    calldata_length: int
    account_nonce: int | None = None
    gas_limit_ceiling: int | None = None
    max_fee_per_gas_ceiling: int | None = None
    max_priority_fee_per_gas_ceiling: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "session_identity_digest",
            "economic_action_id",
            "authority_policy_digest",
            "calldata_sha256",
        ):
            value = getattr(self, name)
            if not _DIGEST_RE(value):
                raise EnvelopeValidationError(f"{name} is not a canonical digest")
        for name in ("taker_address", "target_address"):
            _address(getattr(self, name), field=name)
        if not isinstance(self.session_id, str) or not self.session_id:
            raise EnvelopeValidationError("session_id is required")
        if isinstance(self.chain_id, bool) or not isinstance(self.chain_id, int) or self.chain_id <= 0:
            raise EnvelopeValidationError("chain_id must be positive")
        if (
            isinstance(self.min_value_atomic, bool)
            or not isinstance(self.min_value_atomic, int)
            or self.min_value_atomic < 0
            or self.max_value_atomic < self.min_value_atomic
            or self.max_value_atomic > _MAX_UINT256
        ):
            raise EnvelopeValidationError("native value bounds are invalid")
        if isinstance(self.calldata_length, bool) or not isinstance(self.calldata_length, int) or self.calldata_length < 0:
            raise EnvelopeValidationError("calldata_length must be non-negative")
        for name in (
            "account_nonce",
            "gas_limit_ceiling",
            "max_fee_per_gas_ceiling",
            "max_priority_fee_per_gas_ceiling",
        ):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise EnvelopeValidationError(f"{name} must be a non-negative integer")
        if self.gas_limit_ceiling == 0:
            raise EnvelopeValidationError("gas_limit_ceiling must be positive")
        if self.max_fee_per_gas_ceiling is not None and self.max_priority_fee_per_gas_ceiling is not None:
            if self.max_priority_fee_per_gas_ceiling > self.max_fee_per_gas_ceiling:
                raise EnvelopeValidationError("priority fee ceiling exceeds fee ceiling")

    @property
    def scope_digest(self) -> str:
        document = {
            "account_nonce": self.account_nonce,
            "authority_policy_digest": self.authority_policy_digest,
            "calldata_length": self.calldata_length,
            "calldata_sha256": self.calldata_sha256,
            "chain_id": self.chain_id,
            "economic_action_id": self.economic_action_id,
            "gas_limit_ceiling": self.gas_limit_ceiling,
            "max_fee_per_gas_ceiling": self.max_fee_per_gas_ceiling,
            "max_priority_fee_per_gas_ceiling": self.max_priority_fee_per_gas_ceiling,
            "max_value_atomic": self.max_value_atomic,
            "min_value_atomic": self.min_value_atomic,
            "session_id": self.session_id,
            "session_identity_digest": self.session_identity_digest,
            "taker_address": self.taker_address,
            "target_address": self.target_address,
            "schema": "qntyspot.program_b.v0.exact_signed_bytes_scope",
        }
        return digest_object(document)


@dataclass(frozen=True, slots=True)
class ParsedExactSignedBytesV0:
    transaction_type: str
    chain_id: int
    account_nonce: int
    gas_limit: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    target_address: str
    value_atomic: int
    calldata: bytes
    sender_address: str
    transaction_hash: str


@dataclass(frozen=True, slots=True)
class ValidatedExactSignedBytesV0:
    scope: ExactSignedBytesScopeV0
    parsed: ParsedExactSignedBytesV0
    signed_bytes_sha256: str
    signed_bytes_length: int


@dataclass(frozen=True, slots=True)
class ExactSignedTransactionRecordV0:
    """Durable identity for one externally signed transaction."""

    economic_action_id: str
    scope_digest: str
    signed_bytes_sha256: str
    signed_bytes_length: int
    transaction_hash: str
    chain_id: int
    account_nonce: int
    taker_address: str
    signer_identity: str

    @property
    def signed_transaction_id(self) -> str:
        return digest_object(
            {
                "economic_action_id": self.economic_action_id,
                "schema": "qntyspot.program_b.v0.exact_signed_transaction",
                "signed_bytes_sha256": self.signed_bytes_sha256,
                "scope_digest": self.scope_digest,
            }
        )


@dataclass(frozen=True, slots=True)
class ExactSignedBytesAdmissionV0:
    """Ephemeral admission handle; only its hashes are persisted."""

    signed_bytes: bytes
    record: ExactSignedTransactionRecordV0
    validated: ValidatedExactSignedBytesV0


class ExactSignedBytesTransport(Protocol):
    """The only transport operation exposed by the Level-2 boundary."""

    def submit_exact_signed_bytes(self, signed_bytes: bytes) -> str:
        """Return the node's transaction hash for the unchanged byte string."""


class JsonRpcExactSignedBytesTransport:
    """Adapt the existing bounded JSON-RPC client to one fixed operation."""

    def __init__(self, rpc: Any) -> None:
        if not hasattr(rpc, "request"):
            raise TypeError("rpc must expose the existing request method")
        self._rpc = rpc

    def submit_exact_signed_bytes(self, signed_bytes: bytes) -> str:
        if type(signed_bytes) is not bytes or not signed_bytes:
            raise EnvelopeValidationError("signed bytes must be non-empty bytes")
        method = "eth_" + "sendRawTransaction"
        result = self._rpc.request(method, ["0x" + signed_bytes.hex()])
        if not isinstance(result, str) or len(result) != 66 or not result.startswith("0x"):
            raise EnvelopeValidationError("transport returned a malformed transaction hash")
        if any(char not in "0123456789abcdef" for char in result[2:]):
            raise EnvelopeValidationError("transport returned a non-canonical transaction hash")
        return result


def _recover_sender(message_hash: bytes, parity: int, r: int, s: int) -> str:
    try:
        signature = keys.Signature(vrs=(parity, r, s))
        public_key = signature.recover_public_key_from_msg_hash(message_hash)
        # eth-keys deliberately leaves address hashing to its optional utility
        # package; use QntySpot's already-pinned Keccak implementation here.
        return "0x" + keccak256(public_key.to_bytes())[-20:].hex()
    except Exception as exc:  # library exposes several signature-specific exception types
        raise EnvelopeValidationError("sender is not cryptographically recoverable") from exc


def _parse(raw: bytes) -> ParsedExactSignedBytesV0:
    if type(raw) is not bytes or not raw:
        raise EnvelopeValidationError("signed bytes must be non-empty bytes")
    tx_type: str
    if raw[0] in (1, 2):
        type_byte = raw[0]
        tx_type = "eip-2930" if type_byte == 1 else "eip-1559"
        try:
            fields = rlp.decode(raw[1:], strict=True)
        except Exception as exc:
            raise EnvelopeValidationError("typed transaction encoding is invalid") from exc
        if not isinstance(fields, list):
            raise EnvelopeValidationError("typed transaction must be an RLP list")
        expected = 11 if type_byte == 1 else 12
        if len(fields) != expected:
            raise EnvelopeValidationError("typed transaction is incomplete or has extra fields")
        chain_id = _uint(_field_bytes(fields[0], field="chain id"), field="chain id", allow_zero=False)
        nonce = _uint(_field_bytes(fields[1], field="nonce"), field="nonce")
        if type_byte == 1:
            gas_price = _uint(_field_bytes(fields[2], field="gas price"), field="gas price")
            gas_limit = _uint(_field_bytes(fields[3], field="gas limit"), field="gas limit", allow_zero=False)
            target = _field_bytes(fields[4], field="target")
            value = _uint(_field_bytes(fields[5], field="value"), field="value")
            calldata = _field_bytes(fields[6], field="calldata")
            access_list = fields[7]
            parity = _uint(_field_bytes(fields[8], field="y parity"), field="y parity")
            r = _uint(_field_bytes(fields[9], field="r"), field="r", allow_zero=False)
            s = _uint(_field_bytes(fields[10], field="s"), field="s", allow_zero=False)
            unsigned = fields[:8]
            max_fee = max_priority = gas_price
        else:
            max_priority = _uint(_field_bytes(fields[2], field="priority fee"), field="priority fee")
            max_fee = _uint(_field_bytes(fields[3], field="fee cap"), field="fee cap")
            gas_limit = _uint(_field_bytes(fields[4], field="gas limit"), field="gas limit", allow_zero=False)
            target = _field_bytes(fields[5], field="target")
            value = _uint(_field_bytes(fields[6], field="value"), field="value")
            calldata = _field_bytes(fields[7], field="calldata")
            access_list = fields[8]
            parity = _uint(_field_bytes(fields[9], field="y parity"), field="y parity")
            r = _uint(_field_bytes(fields[10], field="r"), field="r", allow_zero=False)
            s = _uint(_field_bytes(fields[11], field="s"), field="s", allow_zero=False)
            unsigned = fields[:9]
        if parity not in (0, 1):
            raise EnvelopeValidationError("typed transaction y parity is invalid")
        _access_list(access_list)
        if len(target) != 20:
            raise EnvelopeValidationError("contract creation target is outside governed scope")
        unsigned_bytes = bytes((type_byte,)) + rlp.encode(unsigned)
        sender = _recover_sender(keccak256(unsigned_bytes), parity, r, s)
    else:
        tx_type = "legacy-eip-155"
        try:
            fields = rlp.decode(raw, strict=True)
        except Exception as exc:
            raise EnvelopeValidationError("legacy transaction encoding is invalid") from exc
        if not isinstance(fields, list) or len(fields) != 9:
            raise EnvelopeValidationError("legacy transaction must contain nine fields")
        nonce = _uint(_field_bytes(fields[0], field="nonce"), field="nonce")
        gas_price = _uint(_field_bytes(fields[1], field="gas price"), field="gas price")
        gas_limit = _uint(_field_bytes(fields[2], field="gas limit"), field="gas limit", allow_zero=False)
        target = _field_bytes(fields[3], field="target")
        value = _uint(_field_bytes(fields[4], field="value"), field="value")
        calldata = _field_bytes(fields[5], field="calldata")
        v = _uint(_field_bytes(fields[6], field="v"), field="v", allow_zero=False)
        r = _uint(_field_bytes(fields[7], field="r"), field="r", allow_zero=False)
        s = _uint(_field_bytes(fields[8], field="s"), field="s", allow_zero=False)
        if v < 35:
            raise EnvelopeValidationError("legacy transaction has no explicit chain id")
        chain_id = (v - 35) // 2
        parity = (v - 35) % 2
        if chain_id <= 0:
            raise EnvelopeValidationError("legacy chain id is invalid")
        if len(target) != 20:
            raise EnvelopeValidationError("contract creation target is outside governed scope")
        unsigned_bytes = rlp.encode(fields[:6] + [chain_id.to_bytes((chain_id.bit_length() + 7) // 8, "big"), b"", b""])
        sender = _recover_sender(keccak256(unsigned_bytes), parity, r, s)
        max_fee = max_priority = gas_price
    if value > _MAX_UINT256:
        raise EnvelopeValidationError("native value exceeds uint256")
    target_address = "0x" + target.hex()
    return ParsedExactSignedBytesV0(
        transaction_type=tx_type,
        chain_id=chain_id,
        account_nonce=nonce,
        gas_limit=gas_limit,
        max_fee_per_gas=max_fee,
        max_priority_fee_per_gas=max_priority,
        target_address=target_address,
        value_atomic=value,
        calldata=calldata,
        sender_address=sender,
        transaction_hash=derive_transaction_hash(raw),
    )


def validate_exact_signed_bytes(
    signed_bytes: bytes,
    scope: ExactSignedBytesScopeV0,
) -> ValidatedExactSignedBytesV0:
    """Decode and validate without changing the admitted byte sequence."""
    parsed = _parse(signed_bytes)
    if parsed.chain_id != scope.chain_id:
        raise EnvelopeValidationError("signed transaction chain id disagrees with governed scope")
    if parsed.sender_address != scope.taker_address:
        raise EnvelopeValidationError("recovered sender disagrees with governed taker")
    if parsed.target_address != scope.target_address:
        raise EnvelopeValidationError("transaction target disagrees with governed scope")
    if not scope.min_value_atomic <= parsed.value_atomic <= scope.max_value_atomic:
        raise EnvelopeValidationError("transaction native value is outside governed bounds")
    if len(parsed.calldata) != scope.calldata_length:
        raise EnvelopeValidationError("calldata length disagrees with governed scope")
    if sha256_hex(parsed.calldata) != scope.calldata_sha256:
        raise EnvelopeValidationError("calldata digest disagrees with governed scope")
    if scope.account_nonce is not None and parsed.account_nonce != scope.account_nonce:
        raise EnvelopeValidationError("nonce disagrees with governed scope")
    if scope.gas_limit_ceiling is not None and parsed.gas_limit > scope.gas_limit_ceiling:
        raise EnvelopeValidationError("gas limit exceeds governed ceiling")
    if scope.max_fee_per_gas_ceiling is not None and parsed.max_fee_per_gas > scope.max_fee_per_gas_ceiling:
        raise EnvelopeValidationError("fee cap exceeds governed ceiling")
    if (
        scope.max_priority_fee_per_gas_ceiling is not None
        and parsed.max_priority_fee_per_gas > scope.max_priority_fee_per_gas_ceiling
    ):
        raise EnvelopeValidationError("priority fee exceeds governed ceiling")
    return ValidatedExactSignedBytesV0(
        scope=scope,
        parsed=parsed,
        signed_bytes_sha256=sha256_hex(signed_bytes),
        signed_bytes_length=len(signed_bytes),
    )
