"""Small, dependency-free Keccak-256 implementation for EVM hash identity.

Ethereum uses Keccak-256 with the original ``0x01`` domain suffix.  That is
different from the standardized SHA3-256 function, whose domain suffix is
``0x06``.  This module is deliberately limited to the one digest primitive
needed by the offline execution metadata path.
"""

from __future__ import annotations

__all__ = ["keccak256", "keccak256_hex"]

_MASK64 = (1 << 64) - 1
_RATE = 136  # 1600-bit state - 2 * 256-bit capacity

_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

_ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl(value: int, offset: int) -> int:
    if offset == 0:
        return value
    return ((value << offset) | (value >> (64 - offset))) & _MASK64


def _permute(state: list[int]) -> None:
    for rc in _ROUND_CONSTANTS:
        column_parity = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        correction = [column_parity[(x - 1) % 5] ^ _rotl(column_parity[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= correction[x]

        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(
                    state[x + 5 * y], _ROTATION[x][y]
                )
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ (
                    (~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y]
                )
        state[0] ^= rc
        for index in range(25):
            state[index] &= _MASK64


def keccak256(data: bytes) -> bytes:
    """Return Ethereum's Keccak-256 digest for explicit bytes."""
    if not isinstance(data, bytes):
        raise TypeError("keccak256 requires bytes")
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((_RATE - len(padded) % _RATE) % _RATE))
    padded[-1] |= 0x80

    state = [0] * 25
    for offset in range(0, len(padded), _RATE):
        block = padded[offset : offset + _RATE]
        for lane in range(_RATE // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _permute(state)

    output = bytearray()
    for lane in range(_RATE // 8):
        output.extend(state[lane].to_bytes(8, "little"))
    return bytes(output[:32])


def keccak256_hex(data: bytes) -> str:
    """Return the lowercase hexadecimal Keccak-256 digest without a prefix."""
    return keccak256(data).hex()
