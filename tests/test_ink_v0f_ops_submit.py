from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from qntyspot.errors import ChainTruthError, SafeHaltError
from qntyspot.execution_contract import ExecutionEnvelopeV0, ReceiptStatus

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ops" / "ink_v0f_native_live_submit_v0.py"


def _helper():
    spec = importlib.util.spec_from_file_location("ink_v0f_native_live_submit_ops", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _envelope() -> ExecutionEnvelopeV0:
    return ExecutionEnvelopeV0(
        session_id="11" * 32,
        session_identity_digest="12" * 32,
        economic_action_id="13" * 32,
        chain_id=57_073,
        taker_address="0x3e604be3293d930069d0805e85379e0ca5fa01cb",
        input_instrument_id="evm:57073:0x4200000000000000000000000000000000000006",
        output_instrument_id="evm:57073:0x32bcb803f696c99eb263d60a05cafd8689026575",
        max_input_atomic=10**15,
        min_output_atomic=10**18,
        transaction_to="0x1111111111111111111111111111111111111111",
        transaction_value_atomic=10**15,
        calldata_sha256="14" * 32,
        calldata_length=4,
        allowance_target=None,
        account_nonce=0,
        gas_limit_ceiling=250_000,
        max_fee_per_gas_ceiling_atomic=1_000_000_000,
        max_priority_fee_per_gas_ceiling_atomic=1_000_000,
        deadline_epoch_s=2_000_000_000,
        authority_policy_digest="15" * 32,
        plan_id="16" * 32,
        quote_id="ink-v0f-test",
        quote_observation_digest="17" * 32,
        venue_block_number=1,
        constructed_at_epoch_s=1_999_999_000,
    )


def _word(value: int) -> str:
    return f"{value:064x}"


def test_submit_helper_is_bound_to_canonical_runtime_and_one_write_attempt() -> None:
    helper = _helper()
    assert helper.BOUND_REPOSITORY_COMMIT == (
        "928b110ee9e5202d411487ee1ede52a022e097c0"
    )
    assert helper.BOUND_IMPLEMENTATION_DIGEST == (
        "0eebedcd5028ada31899dde2794fc783970df13e461dfd85353ed61c22aa4e8d"
    )
    rpc = helper._submission_rpc()
    assert rpc.endpoint == helper.INK_RPC_ENDPOINTS[0]
    assert rpc.max_retries == 0


def test_submission_guard_is_exclusive_and_mode_restricted(
    tmp_path: Path, monkeypatch
) -> None:
    helper = _helper()
    fsync_calls: list[int] = []
    real_fsync = helper.os.fsync

    def tracked_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(helper.os, "fsync", tracked_fsync)
    path = tmp_path / "episode.submission.json"
    doc = {
        "schema": helper.SUBMISSION_GUARD_SCHEMA,
        "economic_action_id": "11" * 32,
    }
    helper._write_guard(path, doc)
    assert path.is_file()
    assert os.stat(path).st_mode & 0o077 == 0
    assert helper._read_guard(path) == doc
    assert len(fsync_calls) == 2
    with pytest.raises(FileExistsError):
        helper._write_guard(path, doc)


def test_signed_byte_file_requires_private_mode(tmp_path: Path) -> None:
    helper = _helper()
    path = tmp_path / "signed.hex"
    path.write_text("0x02abcd\n", encoding="ascii")
    path.chmod(0o644)
    with pytest.raises(RuntimeError, match="group/other"):
        helper._read_signed_bytes(path)

    path.chmod(0o600)
    assert helper._read_signed_bytes(path) == bytes.fromhex("02abcd")


def test_authority_window_is_strict_only_before_first_submission() -> None:
    helper = _helper()
    now = 2_000_000_000
    with pytest.raises(SafeHaltError, match="do not admit or submit"):
        helper._assert_authority_window(
            not_after_epoch_s=now + helper.MIN_REMAINING_AUTHORITY_S - 1,
            now_epoch_s=now,
            require_submission_window=True,
        )
    assert helper._assert_authority_window(
        not_after_epoch_s=now + 10,
        now_epoch_s=now,
        require_submission_window=False,
    ) == 10
    with pytest.raises(SafeHaltError, match="expired"):
        helper._assert_authority_window(
            not_after_epoch_s=now,
            now_epoch_s=now,
            require_submission_window=False,
        )


def test_success_receipt_requires_exact_pinned_buy_logs() -> None:
    helper = _helper()
    envelope = _envelope()
    output = 5 * 10**18
    receipt = {
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x3b9aca00",
        "l1Fee": "0x4d2",
        "logs": [
            {
                "address": helper.INKYSWAP_V2_POOL,
                "topics": [
                    helper._SWAP_TOPIC,
                    helper._topic_address(envelope.taker_address),
                    helper._topic_address(envelope.taker_address),
                ],
                "data": "0x"
                + _word(0)
                + _word(envelope.max_input_atomic)
                + _word(output)
                + _word(0),
            },
            {
                "address": helper.KRAKMASK_ADDRESS,
                "topics": [
                    helper._TRANSFER_TOPIC,
                    helper._topic_address(helper.INKYSWAP_V2_POOL),
                    helper._topic_address(envelope.taker_address),
                ],
                "data": "0x" + _word(output),
            },
        ],
    }
    status, input_atomic, output_atomic, fee_atomic = helper._settlement_from_receipt(
        receipt, envelope
    )
    assert status is ReceiptStatus.SUCCESS
    assert input_atomic == envelope.max_input_atomic
    assert output_atomic == output
    assert fee_atomic == 21_000 * 1_000_000_000 + 1_234


def test_success_receipt_refuses_wrong_swap_direction() -> None:
    helper = _helper()
    envelope = _envelope()
    output = 5 * 10**18
    receipt = {
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x3b9aca00",
        "l1Fee": "0x4d2",
        "logs": [
            {
                "address": helper.INKYSWAP_V2_POOL,
                "topics": [
                    helper._SWAP_TOPIC,
                    helper._topic_address(envelope.taker_address),
                    helper._topic_address(envelope.taker_address),
                ],
                "data": "0x"
                + _word(envelope.max_input_atomic)
                + _word(0)
                + _word(0)
                + _word(output),
            },
            {
                "address": helper.KRAKMASK_ADDRESS,
                "topics": [
                    helper._TRANSFER_TOPIC,
                    helper._topic_address(helper.INKYSWAP_V2_POOL),
                    helper._topic_address(envelope.taker_address),
                ],
                "data": "0x" + _word(output),
            },
        ],
    }
    with pytest.raises(ChainTruthError, match="WETH -> KRAKMASK"):
        helper._settlement_from_receipt(receipt, envelope)


def test_receipt_requires_explicit_ink_l1_fee() -> None:
    helper = _helper()
    envelope = _envelope()
    with pytest.raises(RuntimeError, match="receipt l1Fee"):
        helper._settlement_from_receipt(
            {
                "status": "0x0",
                "gasUsed": "0x5208",
                "effectiveGasPrice": "0x3b9aca00",
                "logs": [],
            },
            envelope,
        )


def test_reverted_receipt_records_gas_without_inventing_fill_amounts() -> None:
    helper = _helper()
    envelope = _envelope()
    status, input_atomic, output_atomic, fee_atomic = helper._settlement_from_receipt(
        {
            "status": "0x0",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3b9aca00",
            "logs": [],
        },
        envelope,
    )
    assert status is ReceiptStatus.REVERTED
    assert input_atomic is None
    assert output_atomic is None
    assert fee_atomic == 21_000 * 1_000_000_000 + 1_234
