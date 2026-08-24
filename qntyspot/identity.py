"""Instrument identity for QntySpot V0A.

IDENTITY RULE
-------------
An instrument is identified by exact canonical on-chain identifiers only. A
ticker or symbol never establishes identity. Symbols are accepted as an
optional human label and are excluded from the identity string and from every
digest, so two instruments that share a symbol are still distinct and one
instrument whose symbol is edited keeps its identity.

NAMESPACES
----------
``evm``     -- ``chain_id`` + ``contract_address``. Covers Ink and Robinhood
               Chain (both EVM chains); they differ only by ``chain_id``.
``solana``  -- ``cluster`` + ``mint_address`` + ``token_program``. The token
               program is part of identity because SPL and Token-2022 mints are
               not interchangeable and a future adapter must not conflate them.

The two namespaces deliberately do not share an address type. An EVM hex
address is refused in the Solana namespace and a base58 mint is refused in the
EVM namespace, so a Solana instrument can never be silently handled with EVM
semantics.

CANONICAL ADDRESS FORM
----------------------
EVM addresses are canonically LOWERCASE ``0x``-prefixed hex. Mixed case is
refused rather than interpreted: validating an EIP-55 checksum requires
keccak256, which is not in the standard library and arrives with the chain
adapter in V0B. V0A refuses ambiguous input instead of guessing at it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

from .canon import digest_object
from .errors import IdentityError

__all__ = [
    "AssetClass",
    "SolanaCluster",
    "TokenProgram",
    "InstrumentRef",
    "EvmInstrumentRef",
    "SolanaInstrumentRef",
    "parse_instrument_ref",
    "InstrumentV0",
]

_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

#: Upper bound on EVM chain_id. EIP-2294 constrains chain ids to < 2**63 - 36.
_MAX_CHAIN_ID = 2**63 - 36


class AssetClass(str, Enum):
    """What kind of thing an instrument is.

    V0A admits ``FUNGIBLE`` only. The field exists so the core never assumes
    fungibility implicitly; a future non-fungible adapter adds a member here
    rather than reworking every call site. No non-fungible behaviour is
    implemented, modelled, or reserved beyond this one enum.
    """

    FUNGIBLE = "FUNGIBLE"


class SolanaCluster(str, Enum):
    MAINNET_BETA = "mainnet-beta"
    DEVNET = "devnet"
    TESTNET = "testnet"


class TokenProgram(str, Enum):
    """Solana token program identity. SPL and Token-2022 are not interchangeable."""

    SPL_TOKEN = "SPL_TOKEN"
    TOKEN_2022 = "TOKEN_2022"


def _decode_base58(text: str) -> bytes:
    num = 0
    for ch in text:
        idx = _B58_INDEX.get(ch)
        if idx is None:
            raise IdentityError(f"non-base58 character {ch!r} in {text!r}")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + body


@dataclass(frozen=True, slots=True)
class InstrumentRef:
    """Base class for instrument identity references."""

    namespace: ClassVar[str] = ""

    def identity_string(self) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def identity_fields(self) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def network_id(self) -> str:
        """The per-network budget scope this instrument belongs to."""
        raise NotImplementedError  # pragma: no cover - abstract


@dataclass(frozen=True, slots=True)
class EvmInstrumentRef(InstrumentRef):
    chain_id: int
    contract_address: str

    namespace: ClassVar[str] = "evm"

    def __post_init__(self) -> None:
        if isinstance(self.chain_id, bool) or not isinstance(self.chain_id, int):
            raise IdentityError("evm chain_id must be an integer")
        if not (1 <= self.chain_id <= _MAX_CHAIN_ID):
            raise IdentityError(f"evm chain_id out of range: {self.chain_id}")
        if not isinstance(self.contract_address, str):
            raise IdentityError("evm contract_address must be a string")
        if not _EVM_ADDRESS_RE.match(self.contract_address):
            raise IdentityError(
                f"evm contract_address {self.contract_address!r} is not canonical "
                "(expected lowercase 0x-prefixed 40 hex characters)"
            )
        if int(self.contract_address, 16) == 0:
            raise IdentityError("evm contract_address must not be the zero address")

    def identity_string(self) -> str:
        return f"evm:{self.chain_id}:{self.contract_address}"

    def identity_fields(self) -> dict[str, Any]:
        return {
            "namespace": "evm",
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
        }

    def network_id(self) -> str:
        return f"evm:{self.chain_id}"


@dataclass(frozen=True, slots=True)
class SolanaInstrumentRef(InstrumentRef):
    cluster: SolanaCluster
    mint_address: str
    token_program: TokenProgram

    namespace: ClassVar[str] = "solana"

    def __post_init__(self) -> None:
        if not isinstance(self.cluster, SolanaCluster):
            raise IdentityError(f"unknown solana cluster: {self.cluster!r}")
        if not isinstance(self.token_program, TokenProgram):
            raise IdentityError(f"unknown solana token_program: {self.token_program!r}")
        if not isinstance(self.mint_address, str):
            raise IdentityError("solana mint_address must be a string")
        if self.mint_address.startswith("0x"):
            raise IdentityError(
                "solana mint_address must be base58, not an EVM-style hex address"
            )
        if not _BASE58_RE.match(self.mint_address):
            raise IdentityError(
                f"solana mint_address {self.mint_address!r} is not base58"
            )
        raw = _decode_base58(self.mint_address)
        if len(raw) != 32:
            raise IdentityError(
                f"solana mint_address must decode to 32 bytes, got {len(raw)}"
            )
        if raw == b"\x00" * 32:
            raise IdentityError("solana mint_address must not be the system program id")

    def identity_string(self) -> str:
        return f"solana:{self.cluster.value}:{self.mint_address}:{self.token_program.value}"

    def identity_fields(self) -> dict[str, Any]:
        return {
            "namespace": "solana",
            "cluster": self.cluster.value,
            "mint_address": self.mint_address,
            "token_program": self.token_program.value,
        }

    def network_id(self) -> str:
        return f"solana:{self.cluster.value}"


_REQUIRED_KEYS: dict[str, frozenset[str]] = {
    "evm": frozenset({"namespace", "chain_id", "contract_address"}),
    "solana": frozenset({"namespace", "cluster", "mint_address", "token_program"}),
}


def parse_instrument_ref(obj: Any, *, field: str = "instrument") -> InstrumentRef:
    """Build an :class:`InstrumentRef` from a strict-parsed JSON object.

    Unknown keys are refused. A namespace's keys are refused in another
    namespace, so an EVM ``chain_id`` cannot appear on a Solana reference.
    """
    if not isinstance(obj, dict):
        raise IdentityError(f"{field}: expected an object")
    namespace = obj.get("namespace")
    if namespace not in _REQUIRED_KEYS:
        raise IdentityError(
            f"{field}: namespace must be one of {sorted(_REQUIRED_KEYS)}, got {namespace!r}"
        )
    required = _REQUIRED_KEYS[namespace]
    present = frozenset(obj)
    if missing := sorted(required - present):
        raise IdentityError(f"{field}: missing keys {missing}")
    if unknown := sorted(present - required):
        raise IdentityError(f"{field}: unknown keys {unknown} for namespace {namespace}")

    if namespace == "evm":
        return EvmInstrumentRef(
            chain_id=obj["chain_id"], contract_address=obj["contract_address"]
        )

    cluster_raw = obj["cluster"]
    program_raw = obj["token_program"]
    try:
        cluster = SolanaCluster(cluster_raw)
    except ValueError as exc:
        raise IdentityError(f"{field}: unknown solana cluster {cluster_raw!r}") from exc
    try:
        program = TokenProgram(program_raw)
    except ValueError as exc:
        raise IdentityError(
            f"{field}: unknown solana token_program {program_raw!r}"
        ) from exc
    return SolanaInstrumentRef(
        cluster=cluster, mint_address=obj["mint_address"], token_program=program
    )


@dataclass(frozen=True, slots=True)
class InstrumentV0:
    """An admitted instrument: identity, atomic scale, and a non-identifying label."""

    ref: InstrumentRef
    decimals: int
    asset_class: AssetClass = AssetClass.FUNGIBLE
    display_symbol: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.ref, InstrumentRef):
            raise IdentityError("instrument ref must be an InstrumentRef")
        if isinstance(self.decimals, bool) or not isinstance(self.decimals, int):
            raise IdentityError("instrument decimals must be an integer")
        if not (0 <= self.decimals <= 36):
            raise IdentityError(f"instrument decimals out of range: {self.decimals}")
        if not isinstance(self.asset_class, AssetClass):
            raise IdentityError(f"unknown asset_class: {self.asset_class!r}")
        if self.asset_class is not AssetClass.FUNGIBLE:
            raise IdentityError("V0A admits FUNGIBLE instruments only")
        if self.display_symbol is not None:
            if not isinstance(self.display_symbol, str) or not self.display_symbol.strip():
                raise IdentityError("display_symbol must be a non-empty string or absent")
            if len(self.display_symbol) > 64:
                raise IdentityError("display_symbol is too long")

    @property
    def instrument_id(self) -> str:
        return self.ref.identity_string()

    @property
    def network_id(self) -> str:
        return self.ref.network_id()

    def identity_object(self) -> dict[str, Any]:
        """The digest-bearing view. ``display_symbol`` is deliberately absent."""
        return {
            **self.ref.identity_fields(),
            "decimals": self.decimals,
            "asset_class": self.asset_class.value,
        }

    def identity_digest(self) -> str:
        return digest_object(self.identity_object())

    def policy_object(self) -> dict[str, Any]:
        """The instrument as it appears in a canonical policy document.

        This is the shape the policy reader accepts, so a canonical policy is
        itself an admissible policy document and re-admitting it reproduces
        the same ``policy_id``. ``display_symbol`` is omitted: it is a label,
        it does not participate in identity, and editing it must not change a
        policy's digest.
        """
        return {
            "ref": self.ref.identity_fields(),
            "decimals": self.decimals,
            "asset_class": self.asset_class.value,
        }
