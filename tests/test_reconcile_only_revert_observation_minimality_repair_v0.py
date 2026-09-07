"""Focused proof of the revert-observation selector-minimality repair."""

from __future__ import annotations

import hashlib
import inspect
import json
import subprocess
from pathlib import Path

import pytest

from qntyspot.canon import canonical_json_bytes, strict_json_loads
from qntyspot.errors import RobinhoodProtocolError
from qntyspot.execution_contract import ChainPresence, ReceiptStatus
from qntyspot.keccak import keccak256_hex
from qntyspot.robinhood_chain_truth import (
    READ_ONLY_RPC_METHODS,
    ROBINHOOD_MAINNET_CHAIN_ID,
    ROBINHOOD_TESTNET_CHAIN_ID,
    ROBINHOOD_TESTNET_NETWORK_ID,
    ROBINHOOD_TESTNET_VENUE_ID,
    RobinhoodTestnetChainTruthSource,
)
from scripts.derive_deployment_identity import build_identity


ROOT = Path(__file__).resolve().parents[1]
BASE = "be3cdfb908851d498d37f0639ef3b6894155119f"
INTENT_DESIGN_DIGEST = "36c2a6e29de02462d61a9b34da609d018a16621a602c39553fcf1a57839cbfd2"
AUTHORITY_ROOT = "618b05f1e780f7f20443f8c020bac0f676e66ff9"
OLD_IMPLEMENTATION_DIGEST = "7fdd08cbb60de858d4eab7031a8463f29b62648be4b88104f6bd031c23a32826"
NEW_IMPLEMENTATION_DIGEST = "bdb1f4025ee7c16130ea422bd21febd69de4759654da1710f1e41d6935f6bc81"
V0R2_DIGEST = "469a438528facd8fdacae1078a94c4cdb611dcb0f3c05de8b159ba0088745c20"
V0R3_DIGEST = "d4364133e8f62393f3cc3d083ff19828c7b939e6818f22fa9406a064c0e24a33"
REPAIR_DIGEST = "e345bf62aa3925687a58971d811ce9f67bf28b816cc85d04f991cafffbf99e0b"
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
INPUT_TOKEN = "0x00000000000000000000000000000000000000b1"
OUTPUT_TOKEN = "0x00000000000000000000000000000000000000b2"
TX_HASH = "0x" + "11" * 32
TX_BLOCK = "0x" + "22" * 32
PARENT_BLOCK = "0x" + "33" * 32
HEAD_BLOCK = "0x" + "44" * 32
NOW = 1_800_000_000
UNSET = object()

V0R2 = ROOT / "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R2.json"
V0R3 = ROOT / "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R3.json"
REPAIR = ROOT / "artifacts/RECONCILE_ONLY_REVERT_OBSERVATION_MINIMALITY_REPAIR_V0.json"
INTENT_DESIGN = ROOT / "artifacts/RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0.json"


def _topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


def _transfer_log(token: str, sender: str, recipient: str, amount: int) -> dict[str, object]:
    topic = "0x" + keccak256_hex(b"Transfer(address,address,uint256)")
    return {
        "address": token,
        "topics": [topic, _topic_address(sender), _topic_address(recipient)],
        "data": "0x" + amount.to_bytes(32, "big").hex(),
    }


def _responses(
    *,
    tx: object | None = None,
    receipt: object | None = None,
    inclusion: dict[str, object] | None = None,
    head_number: int = 9,
    chain_id: int = ROBINHOOD_TESTNET_CHAIN_ID,
) -> dict[str, object]:
    head = {
        "hash": HEAD_BLOCK,
        "number": hex(head_number),
        "parentHash": PARENT_BLOCK,
    }
    inclusion = inclusion or {
        "hash": TX_BLOCK,
        "number": "0x7",
        "parentHash": PARENT_BLOCK,
    }
    return {
        "eth_chainId": hex(chain_id),
        "eth_blockNumber": hex(head_number),
        "eth_getBlockByNumber": head,
        "eth_getBlockByHash": inclusion,
        "eth_getTransactionByHash": tx,
        "eth_getTransactionReceipt": receipt,
    }


def _included_fixture(*, status: int = 1, taker: str = TAKER) -> dict[str, object]:
    tx = {
        "hash": TX_HASH,
        "from": taker,
        "chainId": hex(ROBINHOOD_TESTNET_CHAIN_ID),
        "blockHash": TX_BLOCK,
        "blockNumber": "0x7",
    }
    logs = [] if status == 0 else [
        _transfer_log(INPUT_TOKEN, taker, "0x00000000000000000000000000000000000000c1", 1_000),
        _transfer_log(OUTPUT_TOKEN, "0x00000000000000000000000000000000000000c2", taker, 995),
    ]
    receipt = {
        "transactionHash": TX_HASH,
        "blockHash": TX_BLOCK,
        "blockNumber": "0x7",
        "status": hex(status),
        "logs": logs,
    }
    return _responses(tx=tx, receipt=receipt)


def _source(responses: dict[str, object]) -> RobinhoodTestnetChainTruthSource:
    return RobinhoodTestnetChainTruthSource(
        provider_id="fixture-provider",
        rpc_endpoint="https://fixture.invalid/rpc",
        transport=responses,
    )


def _observe(
    source: RobinhoodTestnetChainTruthSource,
    *,
    input_token: object = UNSET,
    output_token: object = UNSET,
):
    kwargs: dict[str, object] = {
        "expected_taker": TAKER,
        "observed_at_epoch_s": NOW,
    }
    if input_token is not UNSET:
        kwargs["input_token"] = input_token
    if output_token is not UNSET:
        kwargs["output_token"] = output_token
    return source.observe(TX_HASH, **kwargs)


def _artifact(path: Path) -> dict[str, object]:
    value = strict_json_loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.rstrip("\n")


@pytest.mark.parametrize(
    ("responses", "presence"),
    [
        (_responses(), ChainPresence.ABSENT),
        (
            _responses(
                tx={
                    "hash": TX_HASH,
                    "from": TAKER,
                    "chainId": hex(ROBINHOOD_TESTNET_CHAIN_ID),
                    "blockHash": None,
                    "blockNumber": None,
                }
            ),
            ChainPresence.PENDING,
        ),
        (_included_fixture(status=0), ChainPresence.INCLUDED),
    ],
)
def test_absent_pending_and_reverted_do_not_require_or_consume_selectors(
    responses: dict[str, object], presence: ChainPresence
) -> None:
    without_selectors = _observe(_source(responses))
    with_malformed_unrelated_selectors = _observe(
        _source(responses), input_token="malformed", output_token="also-malformed"
    )
    assert without_selectors.presence is presence
    assert with_malformed_unrelated_selectors.presence is presence
    assert without_selectors.raw_evidence_sha256 == with_malformed_unrelated_selectors.raw_evidence_sha256
    if presence is ChainPresence.INCLUDED:
        assert without_selectors.receipt_status is ReceiptStatus.REVERTED
        assert without_selectors.effective_input_atomic is None
        assert without_selectors.effective_output_atomic is None


def test_reverted_evidence_has_no_effective_amounts_or_selector_requirement() -> None:
    observation = _observe(_source(_included_fixture(status=0)))
    assert observation.receipt_status is ReceiptStatus.REVERTED
    assert observation.effective_input_atomic is None
    assert observation.effective_output_atomic is None


def test_selector_api_is_optional_but_asymmetric_presence_fails_before_rpc() -> None:
    signature = inspect.signature(RobinhoodTestnetChainTruthSource.observe)
    assert signature.parameters["input_token"].default is None
    assert signature.parameters["output_token"].default is None
    calls: list[tuple[str, tuple[object, ...]]] = []

    def transport(method: str, params: tuple[object, ...]) -> object:
        calls.append((method, params))
        return None

    source = RobinhoodTestnetChainTruthSource(
        provider_id="fixture-provider",
        rpc_endpoint="https://fixture.invalid/rpc",
        transport=transport,
    )
    with pytest.raises(RobinhoodProtocolError, match="supplied together"):
        _observe(source, input_token=INPUT_TOKEN)
    assert calls == []


def test_success_requires_both_selectors_and_preserves_exact_transfer_derivation() -> None:
    with pytest.raises(RobinhoodProtocolError, match="successful observation"):
        _observe(_source(_included_fixture()))
    observation = _observe(
        _source(_included_fixture()), input_token=INPUT_TOKEN, output_token=OUTPUT_TOKEN
    )
    assert observation.presence is ChainPresence.INCLUDED
    assert observation.receipt_status is ReceiptStatus.SUCCESS
    assert observation.effective_input_atomic == 1_000
    assert observation.effective_output_atomic == 995


@pytest.mark.parametrize(
    ("input_token", "output_token", "message"),
    [
        ("malformed", OUTPUT_TOKEN, "input_token"),
        (INPUT_TOKEN, "malformed", "output_token"),
        (INPUT_TOKEN, INPUT_TOKEN, "distinct"),
    ],
)
def test_success_selector_validation_remains_fail_closed(
    input_token: str, output_token: str, message: str
) -> None:
    with pytest.raises(RobinhoodProtocolError, match=message):
        _observe(
            _source(_included_fixture()),
            input_token=input_token,
            output_token=output_token,
        )


def test_chain_taker_receipt_block_and_mainnet_boundaries_remain_rejected() -> None:
    with pytest.raises(RobinhoodProtocolError, match="mainnet"):
        _observe(
            _source(_responses(chain_id=ROBINHOOD_MAINNET_CHAIN_ID)),
            input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN,
        )
    with pytest.raises(RobinhoodProtocolError, match="testnet"):
        _observe(
            _source(_responses(chain_id=1)),
            input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN,
        )
    with pytest.raises(RobinhoodProtocolError, match="sender"):
        _observe(
            _source(_included_fixture(taker="0x00000000000000000000000000000000000000bb")),
            input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN,
        )
    contradictory = _included_fixture()
    contradictory["eth_getTransactionReceipt"] = {
        **contradictory["eth_getTransactionReceipt"],
        "blockHash": "0x" + "ff" * 32,
    }
    with pytest.raises(RobinhoodProtocolError, match="block hash"):
        _observe(
            _source(contradictory), input_token=INPUT_TOKEN, output_token=OUTPUT_TOKEN
        )


def test_read_only_rpc_allowlist_and_no_transaction_authority_remain_frozen() -> None:
    assert ROBINHOOD_TESTNET_CHAIN_ID == 46630
    assert ROBINHOOD_TESTNET_NETWORK_ID == "evm:46630"
    assert ROBINHOOD_MAINNET_CHAIN_ID == 4663
    assert READ_ONLY_RPC_METHODS == frozenset(
        {
            "eth_chainId",
            "eth_blockNumber",
            "eth_getBlockByNumber",
            "eth_getBlockByHash",
            "eth_getTransactionByHash",
            "eth_getTransactionReceipt",
        }
    )
    source = _source(_responses())
    with pytest.raises(RobinhoodProtocolError):
        source._call("eth_sendRawTransaction", ())  # noqa: SLF001
    assert not any(
        hasattr(source, name)
        for name in ("sign", "submit", "approve", "build", "encode")
    )
    assert ROBINHOOD_TESTNET_VENUE_ID == "robinhood-chain-testnet-external-transaction"


def test_intent_design_and_v0r2_are_unchanged_and_accounting_pair_is_not_revert_input() -> None:
    for relative in (
        "artifacts/RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0.json",
        "artifacts/RECONCILE_ONLY_QUALIFICATION_INTENT_DESIGN_V0.sha256",
        "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R2.json",
        "artifacts/ROBINHOOD_TESTNET_TAKER_DECLARATION_V0R2.sha256",
    ):
        assert (ROOT / relative).read_bytes() == subprocess.check_output(
            ["git", "show", f"{BASE}:{relative}"], cwd=ROOT
        )
    design = _artifact(INTENT_DESIGN)
    assert hashlib.sha256(INTENT_DESIGN.read_bytes()).hexdigest() == INTENT_DESIGN_DIGEST
    assert design["qualification_intent"]["quote_exposure_atomic"] == 1
    assert design["qualification_intent"]["max_concurrent_reservations"] == 1
    assert design["future_authority_root_input_contract"]["max_reservation_atomic"] == 1
    assert design["future_authority_root_input_contract"]["max_cumulative_atomic"] == 1
    assert design["accounting_instruments"]["base_instrument_id"] == (
        "evm:46630:0x33e4191705c386532ba27cbf171db86919200b94"
    )
    assert design["accounting_instruments"]["quote_instrument_id"] == (
        "evm:46630:0xbf4479c07dc6fdc6daa764a0cca06969e894275f"
    )
    assert design["token_selector_semantics"]["selectors_semantically_required_for_revert"] == "NO"


def test_v0r3_declaration_is_canonical_and_supersedes_exact_v0r2() -> None:
    raw = V0R3.read_bytes()
    declaration = _artifact(V0R3)
    assert raw == canonical_json_bytes(declaration)
    assert hashlib.sha256(raw).hexdigest() == V0R3_DIGEST
    assert V0R3.with_suffix(".sha256").read_text(encoding="ascii") == (
        f"{V0R3_DIGEST}  {V0R3.name}\n"
    )
    assert declaration["schema"] == "qntyspot.robinhood_testnet_taker_declaration.v0r3"
    assert declaration["base_qntyspot_canonical"] == BASE
    assert declaration["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert declaration["implementation_digest"] == NEW_IMPLEMENTATION_DIGEST
    assert declaration["network_id"] == "evm:46630"
    assert declaration["taker_address"] == TAKER
    assert declaration["venue_id"] == ROBINHOOD_TESTNET_VENUE_ID
    assert declaration["source_phase_ceiling"] == "RECONCILE_ONLY"
    assert declaration["transaction_origin"] == "EXTERNAL_TO_QNTYSPOT"
    assert declaration["supersedes_schema"] == "qntyspot.robinhood_testnet_taker_declaration.v0r2"
    assert declaration["supersedes_artifact_digest"] == V0R2_DIGEST
    for field in (
        "account_control_proven",
        "private_key_control_proven",
        "signing_authorized",
        "transaction_construction_authorized",
        "approval_authorized",
        "submission_authorized",
        "capital_authorized",
        "live_capital_authorized",
    ):
        assert declaration[field] is False
    assert declaration["capital_authority"] == "NONE"


def test_repair_artifact_is_canonical_and_cross_binds_all_frozen_constraints() -> None:
    raw = REPAIR.read_bytes()
    evidence = _artifact(REPAIR)
    assert raw == canonical_json_bytes(evidence)
    assert hashlib.sha256(raw).hexdigest() == REPAIR_DIGEST
    assert REPAIR.with_suffix(".sha256").read_text(encoding="ascii") == (
        f"{REPAIR_DIGEST}  {REPAIR.name}\n"
    )
    assert evidence["phase"] == "QNTY_SPOT_RECONCILE_ONLY_REVERT_OBSERVATION_MINIMALITY_REPAIR_V0"
    assert evidence["base_canonical"] == BASE
    assert evidence["intent_design_artifact_digest"] == INTENT_DESIGN_DIGEST
    assert evidence["authority_root_canonical"] == AUTHORITY_ROOT
    assert evidence["old_implementation_digest"] == OLD_IMPLEMENTATION_DIGEST
    assert evidence["new_implementation_digest"] == NEW_IMPLEMENTATION_DIGEST
    assert evidence["network"] == "evm:46630"
    assert evidence["taker"] == TAKER
    assert evidence["venue"] == ROBINHOOD_TESTNET_VENUE_ID
    assert evidence["repair_reason"] == "REVERT_OBSERVATION_TOKEN_SELECTOR_COUPLING"
    assert evidence["selector_semantics"]["absent"].startswith("No input_token")
    assert evidence["selector_semantics"]["pending"].startswith("No input_token")
    assert evidence["selector_semantics"]["reverted"].endswith("derived.")
    assert "mandatory" in evidence["selector_semantics"]["success"]
    assert evidence["selector_semantics"]["asymmetric_selectors"].endswith("FAIL_CLOSED.")
    assert evidence["accounting_pair"]["ne_observation_selectors_for_revert"] == "YES"
    assert evidence["qualification_quote_exposure_atomic"] == 1
    assert evidence["qualification_max_concurrent_reservations"] == 1
    assert evidence["future_grant_max_reservation_atomic"] == 1
    assert evidence["future_grant_max_cumulative_atomic"] == 1
    assert evidence["grant_duration_max_seconds"] == 900
    assert evidence["min_agreeing_providers"] == 2
    assert evidence["min_confirmation_depth"] == 32
    assert evidence["current_level_1_external_grant"] == "NONE"
    assert evidence["current_effective_level_1_authority"] == "DENIED"
    assert evidence["exact_next_phase"] == "QNTY_AUTHORITY_ROOT_RECONCILE_ONLY_GRANT_GOVERNANCE_V0"
    assert evidence["network_activity"] == 0
    assert evidence["testnet_transactions"] == 0
    assert evidence["private_key_accessed"] == "NO"
    assert evidence["zero_blockchain_signatures"] == 0
    assert evidence["capital_deployed"] == 0
    assert evidence["no_key_access"] is True
    assert evidence["signing_authorized"] is False
    assert evidence["transaction_construction_authorized"] is False
    assert evidence["submission_authorized"] is False
    assert evidence["approval_authorized"] is False
    assert evidence["live_capital_authorized"] is False
    assert evidence["capital_authority"] == "NONE"
    assert evidence["v0r2_declaration_digest"] == V0R2_DIGEST
    assert evidence["v0r3_declaration_digest"] == V0R3_DIGEST


def test_post_repair_implementation_identity_is_new_and_boundary_is_untouched() -> None:
    identity = build_identity(ROOT, BASE)
    assert identity["implementation_identity_method"] == "sha256-canonical-source-manifest-v2"
    assert identity["implementation_digest"] != NEW_IMPLEMENTATION_DIGEST
    assert identity["implementation_digest"] != OLD_IMPLEMENTATION_DIGEST
    assert _git("diff", "--name-only", "--", "qntyspot/boundary.py") == ""
