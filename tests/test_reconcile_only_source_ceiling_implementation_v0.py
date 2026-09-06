"""Focused proof of the QntySpot reconcile-only implementation contract."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import NOW
from qntyspot.authority_root import (
    effective_capabilities,
    require_effective_capability,
    verify_authority_grant,
)
from qntyspot.boundary import ChainTruthSource
from qntyspot.canon import canonical_json_bytes
from qntyspot.errors import AuthorityCeilingError, AuthorityVerificationError, RobinhoodProtocolError
from qntyspot.execution_contract import (
    AuthorityLevel,
    Capability,
    KILL_SWITCH_PRESERVED_CAPABILITIES,
    LADDER,
    PHASE_GRANTED_AUTHORITY_LEVEL,
    granted_capabilities,
    require_capability,
)
from qntyspot.ledger.execution_schema import (
    EXECUTION_SCHEMA_VERSION,
    EXECUTION_SCHEMA_VERSION_V1,
    migrate_execution_schema_v1_to_v2,
    read_execution_schema_version,
)
from qntyspot.ledger import ExecutionRuntime, open_ledger
from qntyspot.robinhood_chain_truth import (
    READ_ONLY_RPC_METHODS,
    ROBINHOOD_MAINNET_CHAIN_ID,
    ROBINHOOD_TESTNET_CHAIN_ID,
    ROBINHOOD_TESTNET_NETWORK_ID,
    ROBINHOOD_TESTNET_VENUE_ID,
    RobinhoodTestnetChainTruthSource,
)
from qntyspot.execution_contract import ChainPresence, ReceiptStatus

from test_external_authority_root import _receipt, _root_for, _session


ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION_ARTIFACT = ROOT / "artifacts/RECONCILE_ONLY_SOURCE_CEILING_IMPLEMENTATION_V0.json"
IMPLEMENTATION_SIDECAR = IMPLEMENTATION_ARTIFACT.with_suffix(".sha256")
TAKER = "0x1324d87e24e1657f6fe6805de814bb6873052106"
INPUT_TOKEN = "0x00000000000000000000000000000000000000b1"
OUTPUT_TOKEN = "0x00000000000000000000000000000000000000b2"
TX_HASH = "0x" + "11" * 32
TX_BLOCK = "0x" + "22" * 32
PARENT_BLOCK = "0x" + "33" * 32
HEAD_BLOCK = "0x" + "44" * 32


def _topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


def _transfer_log(token: str, sender: str, recipient: str, amount: int) -> dict[str, object]:
    from qntyspot.keccak import keccak256_hex

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


def _verified(level: AuthorityLevel = AuthorityLevel.AUTONOMOUS_BOUNDED_SIGNER):
    receipt = _receipt(level)
    session = _session(receipt)
    grant = verify_authority_grant(
        receipt=receipt,
        trusted_root=_root_for(receipt.root_id),
        session=session,
        now_epoch_s=NOW,
    )
    return grant, session


def test_source_ceiling_and_effective_ladder_are_exact() -> None:
    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.RECONCILE_ONLY
    assert LADDER[AuthorityLevel.RECONCILE_ONLY] == frozenset(
        {
            Capability.OBSERVE_MARKET,
            Capability.DECIDE_OFFLINE,
            Capability.OBSERVE_CHAIN,
            Capability.RECONCILE,
            Capability.ACCOUNT_QUARANTINE,
            Capability.RESERVE_CAPITAL,
        }
    )
    assert Capability.SUBMIT_EXACT_BYTES not in LADDER[AuthorityLevel.RECONCILE_ONLY]
    assert Capability.CONSTRUCT_ENVELOPE not in LADDER[AuthorityLevel.RECONCILE_ONLY]
    assert Capability.AUTHORIZE_APPROVAL not in LADDER[AuthorityLevel.RECONCILE_ONLY]
    assert Capability.PRODUCE_SIGNATURE not in LADDER[AuthorityLevel.RECONCILE_ONLY]


def test_source_ceiling_alone_does_not_activate_level_one() -> None:
    with pytest.raises(AuthorityVerificationError, match="verified external grant"):
        granted_capabilities(AuthorityLevel.RECONCILE_ONLY)
    with pytest.raises(AuthorityVerificationError, match="verified external grant"):
        require_capability(Capability.RECONCILE, AuthorityLevel.RECONCILE_ONLY)
    with pytest.raises(AuthorityVerificationError, match="verified grant"):
        effective_capabilities(
            source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
            verified_grant=None,  # type: ignore[arg-type]
            now_epoch_s=NOW,
        )
    assert effective_capabilities(
        source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
        verified_grant=_verified()[0],
        now_epoch_s=NOW,
    ) == LADDER[AuthorityLevel.RECONCILE_ONLY]


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository_commit", "b" * 40),
        ("implementation_digest", "00" * 32),
        ("network_id", "evm:1"),
        ("taker_address", "0x00000000000000000000000000000000000000bb"),
        ("venue_id", "other-venue"),
    ],
)
def test_grant_scope_mismatch_denies_level_one(field: str, value: str) -> None:
    grant, session = _verified()
    with pytest.raises(AuthorityVerificationError):
        require_effective_capability(
            capability=Capability.OBSERVE_CHAIN,
            source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
            verified_grant=grant,
            session=replace(session, **{field: value}),
            now_epoch_s=NOW,
        )


def test_expired_and_shadow_grants_deny_level_one_and_expiry_is_rechecked() -> None:
    grant, session = _verified()
    with pytest.raises(AuthorityCeilingError):
        require_effective_capability(
            capability=Capability.OBSERVE_CHAIN,
            source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
            verified_grant=grant,
            session=session,
            now_epoch_s=NOW + 900,
        )
    shadow_receipt = _receipt(AuthorityLevel.SHADOW)
    shadow_session = _session(shadow_receipt)
    shadow = verify_authority_grant(
        receipt=shadow_receipt,
        trusted_root=_root_for(shadow_receipt.root_id),
        session=shadow_session,
        now_epoch_s=NOW,
    )
    with pytest.raises(AuthorityCeilingError):
        require_effective_capability(
            capability=Capability.OBSERVE_CHAIN,
            source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
            verified_grant=shadow,
            session=shadow_session,
            now_epoch_s=NOW,
        )


def test_kill_switch_masks_reserve_but_preserves_observation_reconciliation_quarantine() -> None:
    grant, session = _verified()
    permitted = effective_capabilities(
        source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
        verified_grant=grant,
        now_epoch_s=NOW,
        kill_switch=True,
    )
    assert permitted == KILL_SWITCH_PRESERVED_CAPABILITIES
    assert Capability.RESERVE_CAPITAL not in permitted
    assert {Capability.OBSERVE_CHAIN, Capability.RECONCILE, Capability.ACCOUNT_QUARANTINE} <= permitted
    with pytest.raises(AuthorityCeilingError):
        require_effective_capability(
            capability=Capability.RESERVE_CAPITAL,
            source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
            verified_grant=grant,
            session=session,
            now_epoch_s=NOW,
            kill_switch=True,
        )


def test_persisted_authority_evidence_is_not_activation(tmp_path: Path) -> None:
    ledger = open_ledger(str(tmp_path / "evidence.sqlite3"))
    runtime = ExecutionRuntime(ledger)
    grant, session = _verified()
    assert runtime.record_verified_authority(grant, accepted_at_epoch_s=NOW)
    with pytest.raises(AuthorityVerificationError):
        require_effective_capability(
            capability=Capability.OBSERVE_CHAIN,
            source_phase_ceiling=AuthorityLevel.RECONCILE_ONLY,
            verified_grant=None,  # type: ignore[arg-type]
            session=session,
            now_epoch_s=NOW,
        )


def test_adapter_emits_exact_read_only_chain_truth() -> None:
    source = _source(_included_fixture())
    assert isinstance(source, ChainTruthSource)
    observation = source.observe(
        TX_HASH,
        expected_taker=TAKER,
        input_token=INPUT_TOKEN,
        output_token=OUTPUT_TOKEN,
        observed_at_epoch_s=NOW,
    )
    assert observation.presence is ChainPresence.INCLUDED
    assert observation.receipt_status is ReceiptStatus.SUCCESS
    assert observation.effective_input_atomic == 1_000
    assert observation.effective_output_atomic == 995
    assert observation.head_block_number == 9
    assert observation.block_parent_hash == PARENT_BLOCK
    assert observation.raw_evidence_sha256 == observation.raw_evidence_sha256.lower()


def test_adapter_pending_and_absent_are_precise() -> None:
    pending = dict(_responses(tx={
        "hash": TX_HASH,
        "from": TAKER,
        "chainId": hex(ROBINHOOD_TESTNET_CHAIN_ID),
        "blockHash": None,
        "blockNumber": None,
    }))
    pending_observation = _source(pending).observe(
        TX_HASH,
        expected_taker=TAKER,
        input_token=INPUT_TOKEN,
        output_token=OUTPUT_TOKEN,
        observed_at_epoch_s=NOW,
    )
    assert pending_observation.presence is ChainPresence.PENDING
    absent_observation = _source(_responses()).observe(
        TX_HASH,
        expected_taker=TAKER,
        input_token=INPUT_TOKEN,
        output_token=OUTPUT_TOKEN,
        observed_at_epoch_s=NOW,
    )
    assert absent_observation.presence is ChainPresence.ABSENT


def test_adapter_rejects_mainnet_wrong_chain_taker_and_malformed_evidence() -> None:
    with pytest.raises(RobinhoodProtocolError):
        _source(_responses(chain_id=ROBINHOOD_MAINNET_CHAIN_ID)).observe(
            TX_HASH, expected_taker=TAKER, input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN, observed_at_epoch_s=NOW,
        )
    with pytest.raises(RobinhoodProtocolError):
        _source(_included_fixture(taker="0x00000000000000000000000000000000000000bb")).observe(
            TX_HASH, expected_taker=TAKER, input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN, observed_at_epoch_s=NOW,
        )
    malformed = _included_fixture()
    malformed["eth_getTransactionReceipt"] = {
        **malformed["eth_getTransactionReceipt"],
        "transactionHash": "0x" + "ff" * 32,
    }
    with pytest.raises(RobinhoodProtocolError):
        _source(malformed).observe(
            TX_HASH, expected_taker=TAKER, input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN, observed_at_epoch_s=NOW,
        )


def test_adapter_rejects_contradictory_blocks_and_bad_amount_evidence() -> None:
    bad_block = _included_fixture()
    bad_block["eth_getBlockByHash"] = {
        "hash": "0x" + "ee" * 32,
        "number": "0x7",
        "parentHash": PARENT_BLOCK,
    }
    with pytest.raises(RobinhoodProtocolError):
        _source(bad_block).observe(
            TX_HASH, expected_taker=TAKER, input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN, observed_at_epoch_s=NOW,
        )
    no_amounts = _included_fixture()
    no_amounts["eth_getTransactionReceipt"] = {
        **no_amounts["eth_getTransactionReceipt"], "logs": []
    }
    with pytest.raises(RobinhoodProtocolError):
        _source(no_amounts).observe(
            TX_HASH, expected_taker=TAKER, input_token=INPUT_TOKEN,
            output_token=OUTPUT_TOKEN, observed_at_epoch_s=NOW,
        )


def test_adapter_reverted_receipt_and_no_external_effect_surface() -> None:
    observation = _source(_included_fixture(status=0)).observe(
        TX_HASH,
        expected_taker=TAKER,
        input_token=INPUT_TOKEN,
        output_token=OUTPUT_TOKEN,
        observed_at_epoch_s=NOW,
    )
    assert observation.receipt_status is ReceiptStatus.REVERTED
    assert observation.effective_input_atomic is None
    assert observation.effective_output_atomic is None
    assert READ_ONLY_RPC_METHODS == frozenset(
        {
            "eth_chainId", "eth_blockNumber", "eth_getBlockByNumber",
            "eth_getBlockByHash", "eth_getTransactionByHash",
            "eth_getTransactionReceipt",
        }
    )
    assert not any(hasattr(_source(_responses()), name) for name in ("submit", "approve", "encode", "sign"))
    with pytest.raises(RobinhoodProtocolError):
        _source(_responses())._call("eth_sendRawTransaction", ())  # noqa: SLF001


def test_artifact_binds_implementation_scope_and_future_identity() -> None:
    document = __import__("json").loads(IMPLEMENTATION_ARTIFACT.read_bytes())
    assert document["design_artifact_digest"] == "f48dd09dc5cb1f122aa814f7b7eb53a89e422bcfe1431c867de60684d4e61b9c"
    assert document["implementation_scope_determination"] == "B"
    assert document["adapter_module"] == "qntyspot/robinhood_chain_truth.py"
    assert document["source_phase_ceiling"] == "RECONCILE_ONLY"
    assert document["current_level_1_external_grant"] == "NONE"
    assert document["current_effective_level_1_authority"] == "DENIED"
    assert document["qualification_network"] == ROBINHOOD_TESTNET_NETWORK_ID
    assert document["qualification_venue"] == "zero-x-swap-v2-robinhood-chain"
    assert ROBINHOOD_TESTNET_VENUE_ID == "robinhood-chain-testnet-external-transaction"
    assert document["qualification_taker"] == TAKER
    assert document["old_implementation_digest"] != document["new_implementation_digest"]
    raw = IMPLEMENTATION_ARTIFACT.read_bytes()
    assert raw == canonical_json_bytes(document)
    assert IMPLEMENTATION_SIDECAR.read_text(encoding="ascii") == (
        f"{hashlib.sha256(raw).hexdigest()}  {IMPLEMENTATION_ARTIFACT.name}\n"
    )


def test_schema_migration_preserves_prior_execution_rows(tmp_path: Path) -> None:
    ledger = open_ledger(str(tmp_path / "migration.sqlite3"))
    runtime = ExecutionRuntime(ledger)
    assert read_execution_schema_version(ledger.connection) == EXECUTION_SCHEMA_VERSION
    session_count = ledger.connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone()[0]
    for row in ledger.connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        ledger.connection.execute(f'DROP TRIGGER "{row[0]}"')
    ledger.connection.execute("DROP TABLE external_transaction_refs")
    ledger.connection.execute(
        "UPDATE schema_meta SET value = ? WHERE key = 'execution_schema_version'",
        (str(EXECUTION_SCHEMA_VERSION_V1),),
    )
    migrate_execution_schema_v1_to_v2(ledger.connection)
    assert read_execution_schema_version(ledger.connection) == EXECUTION_SCHEMA_VERSION
    assert ledger.connection.execute("SELECT COUNT(*) FROM execution_sessions").fetchone()[0] == session_count
