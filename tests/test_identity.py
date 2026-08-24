"""Instrument identity: exact identifiers only, and no cross-namespace bleed."""

from __future__ import annotations

import pytest

from qntyspot.errors import IdentityError
from qntyspot.identity import (
    AssetClass,
    EvmInstrumentRef,
    InstrumentV0,
    SolanaCluster,
    SolanaInstrumentRef,
    TokenProgram,
    parse_instrument_ref,
)

GOOD_EVM = "0xc0ffee0000000000000000000000000000000001"
GOOD_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def test_evm_identity_string_and_network() -> None:
    ref = EvmInstrumentRef(chain_id=57073, contract_address=GOOD_EVM)
    assert ref.identity_string() == f"evm:57073:{GOOD_EVM}"
    assert ref.network_id() == "evm:57073"


def test_same_address_on_two_chains_is_two_instruments() -> None:
    a = EvmInstrumentRef(chain_id=57073, contract_address=GOOD_EVM)
    b = EvmInstrumentRef(chain_id=1, contract_address=GOOD_EVM)
    assert a.identity_string() != b.identity_string()
    assert a.network_id() != b.network_id()


@pytest.mark.parametrize(
    "address",
    [
        "0xC0FFEE0000000000000000000000000000000001",  # upper case
        "0xC0ffee0000000000000000000000000000000001",  # EIP-55 style mixed case
        "c0ffee0000000000000000000000000000000001",    # no 0x
        "0xc0ffee",                                     # too short
        "0xc0ffee00000000000000000000000000000000012",  # too long
        "0xzzffee0000000000000000000000000000000001",   # not hex
        GOOD_MINT,                                      # a Solana mint
    ],
)
def test_non_canonical_evm_addresses_are_refused(address: str) -> None:
    with pytest.raises(IdentityError):
        EvmInstrumentRef(chain_id=1, contract_address=address)


def test_zero_address_is_refused() -> None:
    with pytest.raises(IdentityError, match="zero address"):
        EvmInstrumentRef(chain_id=1, contract_address="0x" + "0" * 40)


@pytest.mark.parametrize("chain_id", [0, -1, "1", 1.0, True, None])
def test_invalid_chain_ids_are_refused(chain_id: object) -> None:
    with pytest.raises(IdentityError):
        EvmInstrumentRef(chain_id=chain_id, contract_address=GOOD_EVM)


def test_solana_identity_includes_token_program() -> None:
    spl = SolanaInstrumentRef(SolanaCluster.MAINNET_BETA, GOOD_MINT, TokenProgram.SPL_TOKEN)
    t22 = SolanaInstrumentRef(SolanaCluster.MAINNET_BETA, GOOD_MINT, TokenProgram.TOKEN_2022)
    # Same mint under a different token program is NOT the same instrument.
    assert spl.identity_string() != t22.identity_string()
    assert spl.network_id() == t22.network_id() == "solana:mainnet-beta"


@pytest.mark.parametrize(
    "mint",
    [
        GOOD_EVM,                       # an EVM address
        "0x" + "ab" * 20,               # hex, not base58
        "0OIl" + GOOD_MINT[4:],         # base58-excluded characters
        "abc",                          # decodes to fewer than 32 bytes
        "1" * 44,                       # decodes to all zero bytes
        "",                             # empty
    ],
)
def test_invalid_solana_mints_are_refused(mint: str) -> None:
    with pytest.raises(IdentityError):
        SolanaInstrumentRef(SolanaCluster.MAINNET_BETA, mint, TokenProgram.SPL_TOKEN)


def test_unknown_cluster_or_program_is_refused() -> None:
    with pytest.raises(IdentityError):
        SolanaInstrumentRef("mainnet", GOOD_MINT, TokenProgram.SPL_TOKEN)
    with pytest.raises(IdentityError):
        SolanaInstrumentRef(SolanaCluster.MAINNET_BETA, GOOD_MINT, "SPL")


# -- reference parsing -----------------------------------------------------


def test_parse_evm_reference() -> None:
    ref = parse_instrument_ref(
        {"namespace": "evm", "chain_id": 57073, "contract_address": GOOD_EVM}
    )
    assert isinstance(ref, EvmInstrumentRef)


def test_parse_solana_reference() -> None:
    ref = parse_instrument_ref(
        {
            "namespace": "solana",
            "cluster": "mainnet-beta",
            "mint_address": GOOD_MINT,
            "token_program": "TOKEN_2022",
        }
    )
    assert isinstance(ref, SolanaInstrumentRef)
    assert ref.token_program is TokenProgram.TOKEN_2022


def test_evm_keys_are_refused_on_a_solana_reference() -> None:
    with pytest.raises(IdentityError, match="unknown keys"):
        parse_instrument_ref(
            {
                "namespace": "solana",
                "cluster": "mainnet-beta",
                "mint_address": GOOD_MINT,
                "token_program": "SPL_TOKEN",
                "chain_id": 1,
            }
        )


def test_solana_keys_are_refused_on_an_evm_reference() -> None:
    with pytest.raises(IdentityError, match="unknown keys"):
        parse_instrument_ref(
            {
                "namespace": "evm",
                "chain_id": 1,
                "contract_address": GOOD_EVM,
                "mint_address": GOOD_MINT,
            }
        )


@pytest.mark.parametrize(
    "obj",
    [
        {},
        {"namespace": "bitcoin"},
        {"namespace": "evm"},
        {"namespace": "evm", "chain_id": 1},
        "not-an-object",
        None,
    ],
)
def test_malformed_references_are_refused(obj: object) -> None:
    with pytest.raises(IdentityError):
        parse_instrument_ref(obj)


# -- symbols are labels, not identity --------------------------------------


def test_symbol_does_not_participate_in_identity() -> None:
    ref = EvmInstrumentRef(chain_id=57073, contract_address=GOOD_EVM)
    a = InstrumentV0(ref=ref, decimals=18, display_symbol="KRAKMASK")
    b = InstrumentV0(ref=ref, decimals=18, display_symbol="TOTALLY-DIFFERENT")
    c = InstrumentV0(ref=ref, decimals=18)
    assert a.instrument_id == b.instrument_id == c.instrument_id
    assert a.identity_digest() == b.identity_digest() == c.identity_digest()
    assert a.policy_object() == b.policy_object() == c.policy_object()


def test_two_instruments_sharing_a_symbol_remain_distinct() -> None:
    a = InstrumentV0(
        ref=EvmInstrumentRef(chain_id=57073, contract_address=GOOD_EVM),
        decimals=18,
        display_symbol="USDC",
    )
    b = InstrumentV0(
        ref=EvmInstrumentRef(
            chain_id=57073, contract_address="0xc0ffee0000000000000000000000000000000002"
        ),
        decimals=6,
        display_symbol="USDC",
    )
    assert a.instrument_id != b.instrument_id


def test_decimals_participate_in_the_identity_digest() -> None:
    ref = EvmInstrumentRef(chain_id=57073, contract_address=GOOD_EVM)
    assert (
        InstrumentV0(ref=ref, decimals=18).identity_digest()
        != InstrumentV0(ref=ref, decimals=6).identity_digest()
    )


@pytest.mark.parametrize("decimals", [-1, 37, "18", 1.0, True, None])
def test_invalid_decimals_are_refused(decimals: object) -> None:
    with pytest.raises(IdentityError):
        InstrumentV0(
            ref=EvmInstrumentRef(chain_id=1, contract_address=GOOD_EVM), decimals=decimals
        )


def test_only_fungible_asset_class_is_admitted_in_v0a() -> None:
    # The enum exists so fungibility is stated rather than assumed. V0A admits
    # exactly one member; a future NFT adapter adds another.
    assert [member.value for member in AssetClass] == ["FUNGIBLE"]
    with pytest.raises(IdentityError):
        InstrumentV0(
            ref=EvmInstrumentRef(chain_id=1, contract_address=GOOD_EVM),
            decimals=18,
            asset_class="NON_FUNGIBLE",
        )
