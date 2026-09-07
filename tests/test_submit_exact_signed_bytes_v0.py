"""Focused Level-2 exact-byte admission tests with public fixture bytes."""

import pytest

from qntyspot.canon import sha256_hex
from qntyspot.errors import EnvelopeValidationError
from qntyspot.execution_contract import AuthorityLevel, Capability, LADDER, PHASE_GRANTED_AUTHORITY_LEVEL
from qntyspot.exact_signed_bytes import (
    ExactSignedBytesScopeV0,
    JsonRpcExactSignedBytesTransport,
    validate_exact_signed_bytes,
)


RAW = bytes.fromhex(
    "02f86482b6268001028252089411111111111111111111111111111111111111118080c080"
    "a0f7f948a59bff11e398786acf90c3e0d027ef41acbe8ca05c39e602704a58a769"
    "a05181aa1d7bdf96b7b926ac9b42d2a3f46d750dbc5c58144e925123a54aaabe28"
)
TAKER = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1"
TARGET = "0x1111111111111111111111111111111111111111"


def scope(**changes: object) -> ExactSignedBytesScopeV0:
    values: dict[str, object] = {
        "session_id": "session-v0",
        "session_identity_digest": "aa" * 32,
        "economic_action_id": "bb" * 32,
        "authority_policy_digest": "cc" * 32,
        "chain_id": 46630,
        "taker_address": TAKER,
        "target_address": TARGET,
        "min_value_atomic": 0,
        "max_value_atomic": 0,
        "calldata_sha256": sha256_hex(b""),
        "calldata_length": 0,
    }
    values.update(changes)
    return ExactSignedBytesScopeV0(**values)  # type: ignore[arg-type]


def test_source_ceiling_is_level_two_without_construct_or_sign() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.SUBMIT_EXACT_SIGNED_BYTES
    assert Capability.SUBMIT_EXACT_BYTES in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.CONSTRUCT_ENVELOPE not in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]
    assert Capability.PRODUCE_SIGNATURE not in LADDER[PHASE_GRANTED_AUTHORITY_LEVEL]


def test_complete_bytes_are_recovered_and_hashed_deterministically() -> None:
    first = validate_exact_signed_bytes(RAW, scope())
    second = validate_exact_signed_bytes(bytes(RAW), scope())
    assert first == second
    assert first.parsed.sender_address == TAKER
    assert first.parsed.transaction_hash == "0x7508482061b00d5775609a79956af4b58b07a969aa030ac99c3444c7573e129b"
    assert first.signed_bytes_length == len(RAW)


@pytest.mark.parametrize(
    "changes",
    [
        {"chain_id": 1},
        {"taker_address": "0x00000000000000000000000000000000000000aa"},
        {"target_address": "0x2222222222222222222222222222222222222222"},
        {"min_value_atomic": 1},
        {"calldata_sha256": "00" * 32},
        {"account_nonce": 1},
    ],
)
def test_scope_disagreements_fail_closed(changes: dict[str, object]) -> None:
    with pytest.raises(EnvelopeValidationError):
        validate_exact_signed_bytes(RAW, scope(**changes))


@pytest.mark.parametrize("raw", [b"", b"\x02\x01", RAW[:-1], b"\x01" + RAW[1:]])
def test_malformed_or_unsigned_bytes_fail_closed(raw: bytes) -> None:
    with pytest.raises(EnvelopeValidationError):
        validate_exact_signed_bytes(raw, scope())


def test_transport_receives_the_same_bytes_and_only_the_fixed_operation() -> None:
    class FakeRpc:
        def __init__(self) -> None:
            self.calls: list[tuple[str, list[str]]] = []

        def request(self, method: str, params: list[str]) -> str:
            self.calls.append((method, params))
            return "0x7508482061b00d5775609a79956af4b58b07a969aa030ac99c3444c7573e129b"

    rpc = FakeRpc()
    transport = JsonRpcExactSignedBytesTransport(rpc)
    assert transport.submit_exact_signed_bytes(RAW) == "0x7508482061b00d5775609a79956af4b58b07a969aa030ac99c3444c7573e129b"
    assert rpc.calls == [("eth_sendRawTransaction", ["0x" + RAW.hex()])]
