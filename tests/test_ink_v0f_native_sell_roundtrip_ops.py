from __future__ import annotations

import importlib.util
import os
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest

from qntyspot.canon import decimal_to_fraction, format_canonical_decimal
from qntyspot.errors import CanonicalFormError

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "ops" / "ink_v0f_native_sell_roundtrip_prepare_v0.py"


EXECUTE_HELPER = ROOT / "ops" / "ink_v0f_native_sell_roundtrip_execute_v0.py"


def _helper():
    spec = importlib.util.spec_from_file_location("ink_v0f_native_sell_roundtrip_prepare_ops", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _execute_helper():
    spec = importlib.util.spec_from_file_location(
        "ink_v0f_native_sell_roundtrip_execute_ops", EXECUTE_HELPER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sell_prepare_is_bound_to_v9_runtime_and_exact_first_buy() -> None:
    helper = _helper()
    assert helper.BOUND_REPOSITORY_COMMIT == "91ec941d7e89fc44da0e4501b52f47fc65962020"
    assert helper.BOUND_IMPLEMENTATION_DIGEST == (
        "dbcbab558ad591d195fcee06951389d1eb566fed40d9b211b8e5578f61b14f81"
    )
    assert helper.EXPECTED_BUY_TX_HASH == (
        "0xa02d78dece891ba72dc1c8b4d363be7482e988d5487cb46567b52453db7e2ae7"
    )
    assert helper.EXPECTED_INVENTORY_ATOMIC == 4396392944674627615414
    assert helper.EXPECTED_APPROVAL_NONCE == 1


def test_successor_policy_refresh_changes_only_episode_identity_price_and_timing() -> None:
    helper = _helper()
    source = {
        "schema": "qntyspot.policy.v0",
        "policy_name": "old",
        "side": "BUY",
        "base": {"keep": "base"},
        "quote": {"keep": "quote"},
        "entry_ladder": {"levels": [{"level_id": "E1", "trigger_price": "1", "input_amount": "0.001"}]},
        "exit_ladder": {"levels": [{"level_id": "X1", "trigger_price": "1", "input_ratio": "1"}]},
        "capital": {"keep": "capital"},
        "limits": {
            "max_executable_price": "2",
            "min_executable_price": "0.5",
            "max_price_impact_bps": 100,
            "max_slippage_bps": 50,
        },
        "timing": {
            "valid_from_epoch_s": 1,
            "expiry_epoch_s": 2,
            "quote_ttl_s": 1,
        },
        "reentry": {
            "max_cycles": 4,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
        "recycling": {"profit_recycle_ratio": "0", "banked_profit_ratio": "1"},
    }
    result = helper._successor_policy_doc(
        source,
        spot=Decimal("0.00000025"),
        now=1_800_000_000,
        expiry=1_800_000_600,
    )
    assert source["policy_name"] == "old"
    assert result["policy_name"] == "ink-v0f-native-sell-successor-1800000000"
    assert result["side"] == "BUY"
    assert result["base"] == source["base"]
    assert result["quote"] == source["quote"]
    assert result["capital"] == source["capital"]
    assert result["entry_ladder"]["levels"][0]["trigger_price"] == "0.00000025"
    assert result["exit_ladder"]["levels"][0]["trigger_price"] == "0.00000025"
    assert result["limits"]["min_executable_price"] == "0.000000125"
    assert result["limits"]["max_executable_price"] == "0.0000005"
    assert result["limits"]["max_price_impact_bps"] == 100
    assert result["limits"]["max_slippage_bps"] == 50
    assert result["timing"] == {
        "valid_from_epoch_s": 1_799_999_995,
        "expiry_epoch_s": 1_800_000_600,
        "quote_ttl_s": 600,
    }
    assert result["reentry"]["max_cycles"] == 1


def test_successor_decimal_normalization_leaves_room_for_sell_slippage() -> None:
    helper = _helper()
    # This is the historical failure shape: a 29-place reserve price multiplied
    # by the SELL 0.995 slippage factor needs 31 canonical fractional places.
    old_trigger = decimal_to_fraction(
        Decimal("0.12345678901234567890123456788"), field="historical spot"
    )
    with pytest.raises(CanonicalFormError, match="needs 31 fractional digits"):
        format_canonical_decimal(old_trigger * Fraction(199, 200), field="limit_price")

    normalized = decimal_to_fraction(
        Decimal(helper._decimal_text(Decimal("0.12345678901234567890123456788"))),
        field="normalized spot",
    )
    assert format_canonical_decimal(normalized * Fraction(199, 200), field="limit_price")


def _recovery_ledger(
    helper,
    *,
    cycles,
    carries,
    intents,
    residue=None,
    sessions=None,
    inventories=None,
):
    residue = residue or {}
    sessions = sessions or {}
    inventories = inventories or {}

    class Result:
        def __init__(self, *, one=None, all_rows=None):
            self._one = one
            self._all = all_rows

        def fetchone(self):
            return self._one

        def fetchall(self):
            return self._all if self._all is not None else []

    class Connection:
        def execute(self, sql, params=()):
            normalized = " ".join(sql.split())
            if "FROM state_events" in normalized:
                rows = [
                    {
                        "cycle_id": child,
                        "payload_json": helper.canonical_json_str(
                            {
                                "inventory_carry": {
                                    "amount_atomic": str(amount),
                                    "source_cycle_id": source,
                                }
                            }
                        ),
                    }
                    for source, child, amount in carries
                ]
                return Result(all_rows=rows)
            if "FROM cycles AS c JOIN policies AS p" in normalized:
                cycle_id = params[0]
                row = cycles.get(cycle_id)
                return Result(one=row)
            if normalized.startswith(
                "SELECT COUNT(*) FROM execution_sessions WHERE policy_id"
            ):
                return Result(one=(sessions.get(params[0], 0),))
            if "FROM intents" in normalized and "WHERE cycle_id" in normalized:
                return Result(all_rows=intents.get(params[0], []))
            if normalized.startswith("SELECT COUNT(*) FROM"):
                table = normalized.split("FROM ", 1)[1].split(" ", 1)[0]
                action = params[0]
                return Result(one=(residue.get((table, action), 0),))
            raise AssertionError((normalized, params))

    class Ledger:
        def __init__(self):
            self.connection = Connection()

        def inventory_atomic(self, cycle_id):
            return inventories.get(cycle_id, helper.EXPECTED_INVENTORY_ATOMIC)

    return Ledger()



def _prepare_discovery_ledger(helper, *, prepare_sources, carries):
    class Result:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class Connection:
        def execute(self, sql, _params=()):
            normalized = " ".join(sql.split())
            if "FROM prepare_records" in normalized:
                return Result(
                    [{"source_cycle_id": source} for source in prepare_sources]
                )
            if "FROM state_events" in normalized:
                return Result(
                    [
                        {
                            "cycle_id": child,
                            "payload_json": helper.canonical_json_str(
                                {
                                    "inventory_carry": {
                                        "amount_atomic": str(amount),
                                        "source_cycle_id": source,
                                    }
                                }
                            ),
                        }
                        for source, child, amount in carries
                    ]
                )
            raise AssertionError(normalized)

    return SimpleNamespace(connection=Connection())


def test_durable_prepare_resume_finds_active_carried_successor_without_expiry_gate() -> None:
    helper = _helper()
    marker = object()

    class Runtime:
        def load_prepare_plan(self, *, operation_kind, source_cycle_id):
            assert operation_kind == "INK_V0F_NATIVE_SELL"
            assert source_cycle_id == "serial8-cycle"
            return marker

    ledger = _prepare_discovery_ledger(
        helper,
        prepare_sources=["serial8-cycle"],
        carries=[
            (
                "buy-cycle",
                "serial8-cycle",
                helper.EXPECTED_INVENTORY_ATOMIC,
            )
        ],
    )
    assert helper._load_existing_prepare(
        Runtime(),
        ledger,
        first_buy_cycle_id="buy-cycle",
    ) is marker


def test_durable_prepare_resume_rejects_disconnected_or_ambiguous_source() -> None:
    helper = _helper()

    class Runtime:
        def load_prepare_plan(self, **_kwargs):
            raise AssertionError("must stop before loading")

    disconnected = _prepare_discovery_ledger(
        helper,
        prepare_sources=["other-cycle"],
        carries=[],
    )
    with pytest.raises(RuntimeError, match="unique first-live inventory-carry chain"):
        helper._load_existing_prepare(
            Runtime(),
            disconnected,
            first_buy_cycle_id="buy-cycle",
        )

    ambiguous = _prepare_discovery_ledger(
        helper,
        prepare_sources=["serial8-cycle", "other-cycle"],
        carries=[],
    )
    with pytest.raises(RuntimeError, match="multiple durable"):
        helper._load_existing_prepare(
            Runtime(),
            ambiguous,
            first_buy_cycle_id="buy-cycle",
        )



def test_prepare_resume_rejects_existing_signed_transaction_residue() -> None:
    helper = _helper()
    plan = {
        "approval": {"approval_action_id": "aa" * 32},
        "envelope": {"economic_action_id": "bb" * 32},
    }

    class Result:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class Connection:
        def __init__(self, signed_rows):
            self.signed_rows = signed_rows

        def execute(self, sql, params=()):
            normalized = " ".join(sql.split())
            if "FROM signed_transactions" in normalized and "JOIN" not in normalized:
                assert params == ("aa" * 32, "bb" * 32)
                return Result(self.signed_rows)
            if "FROM submission_attempts AS st" in normalized:
                return Result([])
            raise AssertionError((normalized, params))

    clean = SimpleNamespace(connection=Connection([]))
    helper._assert_no_signed_prepare_residue(clean, plan)

    signed = SimpleNamespace(
        connection=Connection([{"external_action_id": "aa" * 32}])
    )
    with pytest.raises(RuntimeError, match="signed transaction exists"):
        helper._assert_no_signed_prepare_residue(signed, plan)


def test_partial_prepare_recovery_accepts_only_zero_effect_expired_simulated_sell() -> None:
    helper = _helper()
    action_id = "aa" * 32
    cycles = {
        "buy-cycle": {
            "status": "COMPLETED",
            "policy_id": "buy-policy",
            "canonical_json": "{}",
        },
        "partial-cycle": {
            "status": "OPEN",
            "policy_id": "partial-policy",
            "canonical_json": helper.canonical_json_str(
                {"timing": {"expiry_epoch_s": 100}}
            ),
        },
    }
    intents = {
        "partial-cycle": [
            {
                "economic_action_id": action_id,
                "state": helper.IntentState.SIMULATED.value,
                "side": "SELL",
                "quote_exposure_atomic": "0",
            }
        ]
    }
    ledger = _recovery_ledger(
        helper,
        cycles=cycles,
        carries=[
            (
                "buy-cycle",
                "partial-cycle",
                helper.EXPECTED_INVENTORY_ATOMIC,
            )
        ],
        intents=intents,
    )
    assert helper._recoverable_inventory_source(
        ledger,
        first_buy_cycle_id="buy-cycle",
        now=200,
    ) == ("partial-cycle", action_id)

    ledger = _recovery_ledger(
        helper,
        cycles=cycles,
        carries=[
            (
                "buy-cycle",
                "partial-cycle",
                helper.EXPECTED_INVENTORY_ATOMIC,
            )
        ],
        intents=intents,
        residue={("approval_actions", action_id): 1},
    )
    with pytest.raises(RuntimeError, match="approval_actions"):
        helper._recoverable_inventory_source(
            ledger,
            first_buy_cycle_id="buy-cycle",
            now=200,
        )


def test_partial_prepare_recovery_walks_repeated_zero_effect_carry_chain() -> None:
    helper = _helper()
    old_action = "bb" * 32
    cycles = {
        "buy-cycle": {
            "status": "COMPLETED",
            "policy_id": "buy-policy",
            "canonical_json": "{}",
        },
        "serial5-cycle": {
            "status": "COMPLETED",
            "policy_id": "serial5-policy",
            "canonical_json": helper.canonical_json_str(
                {"timing": {"expiry_epoch_s": 100}}
            ),
        },
        "serial6-cycle": {
            "status": "OPEN",
            "policy_id": "serial6-policy",
            "canonical_json": helper.canonical_json_str(
                {"timing": {"expiry_epoch_s": 150}}
            ),
        },
    }
    ledger = _recovery_ledger(
        helper,
        cycles=cycles,
        carries=[
            ("buy-cycle", "serial5-cycle", helper.EXPECTED_INVENTORY_ATOMIC),
            ("serial5-cycle", "serial6-cycle", helper.EXPECTED_INVENTORY_ATOMIC),
        ],
        intents={
            "serial5-cycle": [
                {
                    "economic_action_id": old_action,
                    "state": helper.IntentState.EXPIRED.value,
                    "side": "SELL",
                    "quote_exposure_atomic": "0",
                }
            ],
            "serial6-cycle": [],
        },
        inventories={
            "serial5-cycle": 0,
            "serial6-cycle": helper.EXPECTED_INVENTORY_ATOMIC,
        },
    )
    assert helper._recoverable_inventory_source(
        ledger,
        first_buy_cycle_id="buy-cycle",
        now=200,
    ) == ("serial6-cycle", None)


def test_partial_prepare_recovery_rejects_completed_hop_retaining_inventory() -> None:
    helper = _helper()
    old_action = "bc" * 32
    cycles = {
        "buy-cycle": {
            "status": "COMPLETED",
            "policy_id": "buy-policy",
            "canonical_json": "{}",
        },
        "serial5-cycle": {
            "status": "COMPLETED",
            "policy_id": "serial5-policy",
            "canonical_json": helper.canonical_json_str(
                {"timing": {"expiry_epoch_s": 100}}
            ),
        },
        "serial6-cycle": {
            "status": "OPEN",
            "policy_id": "serial6-policy",
            "canonical_json": helper.canonical_json_str(
                {"timing": {"expiry_epoch_s": 150}}
            ),
        },
    }
    ledger = _recovery_ledger(
        helper,
        cycles=cycles,
        carries=[
            ("buy-cycle", "serial5-cycle", helper.EXPECTED_INVENTORY_ATOMIC),
            ("serial5-cycle", "serial6-cycle", helper.EXPECTED_INVENTORY_ATOMIC),
        ],
        intents={
            "serial5-cycle": [
                {
                    "economic_action_id": old_action,
                    "state": helper.IntentState.EXPIRED.value,
                    "side": "SELL",
                    "quote_exposure_atomic": "0",
                }
            ],
            "serial6-cycle": [],
        },
        inventories={
            "serial5-cycle": helper.EXPECTED_INVENTORY_ATOMIC,
            "serial6-cycle": helper.EXPECTED_INVENTORY_ATOMIC,
        },
    )
    with pytest.raises(RuntimeError, match="retains inventory"):
        helper._recoverable_inventory_source(
            ledger,
            first_buy_cycle_id="buy-cycle",
            now=200,
        )


def test_partial_prepare_recovery_rejects_fill_receipt_residue() -> None:
    helper = _helper()
    action_id = "bd" * 32
    cycles = {
        "buy-cycle": {
            "status": "COMPLETED",
            "policy_id": "buy-policy",
            "canonical_json": "{}",
        },
        "partial-cycle": {
            "status": "OPEN",
            "policy_id": "partial-policy",
            "canonical_json": helper.canonical_json_str(
                {"timing": {"expiry_epoch_s": 100}}
            ),
        },
    }
    ledger = _recovery_ledger(
        helper,
        cycles=cycles,
        carries=[
            ("buy-cycle", "partial-cycle", helper.EXPECTED_INVENTORY_ATOMIC),
        ],
        intents={
            "partial-cycle": [
                {
                    "economic_action_id": action_id,
                    "state": helper.IntentState.EXPIRED.value,
                    "side": "SELL",
                    "quote_exposure_atomic": "0",
                }
            ]
        },
        residue={("fill_receipts", action_id): 1},
    )
    with pytest.raises(RuntimeError, match="fill_receipts"):
        helper._recoverable_inventory_source(
            ledger,
            first_buy_cycle_id="buy-cycle",
            now=200,
        )


def test_partial_prepare_recovery_rejects_session_on_empty_open_hop() -> None:
    helper = _helper()
    cycles = {
        "buy-cycle": {
            "status": "COMPLETED",
            "policy_id": "buy-policy",
            "canonical_json": "{}",
        },
        "partial-cycle": {
            "status": "OPEN",
            "policy_id": "partial-policy",
            "canonical_json": helper.canonical_json_str(
                {"timing": {"expiry_epoch_s": 100}}
            ),
        },
    }
    ledger = _recovery_ledger(
        helper,
        cycles=cycles,
        carries=[
            (
                "buy-cycle",
                "partial-cycle",
                helper.EXPECTED_INVENTORY_ATOMIC,
            )
        ],
        intents={"partial-cycle": []},
        sessions={"partial-policy": 1},
    )
    with pytest.raises(RuntimeError, match="execution session"):
        helper._recoverable_inventory_source(
            ledger,
            first_buy_cycle_id="buy-cycle",
            now=200,
        )


def test_partial_prepare_recovery_leaves_pristine_open_buy_untouched() -> None:
    helper = _helper()
    ledger = _recovery_ledger(
        helper,
        cycles={
            "buy-cycle": {
                "status": "OPEN",
                "policy_id": "buy-policy",
                "canonical_json": "{}",
            }
        },
        carries=[],
        intents={},
    )
    assert helper._recoverable_inventory_source(
        ledger,
        first_buy_cycle_id="buy-cycle",
        now=200,
    ) == ("buy-cycle", None)


def test_prepared_state_is_private_durable_and_exclusive(tmp_path: Path) -> None:
    helper = _helper()
    path = tmp_path / "episode.sqlite3.sell-prepared.json"
    helper._write_durable_state(path, {"schema": helper.PREPARED_SCHEMA, "x": 1})
    assert path.read_text(encoding="utf-8") == (
        '{"schema":"qntyspot.ops.ink_v0f_native_sell_roundtrip.prepared.v0","x":1}\n'
    )
    assert os.stat(path).st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        helper._write_durable_state(path, {"schema": helper.PREPARED_SCHEMA, "x": 1})


def test_rpc_uint_decoder_requires_one_word() -> None:
    helper = _helper()
    assert helper._data_uint("0x" + ("00" * 31) + "2a", field="x") == 42
    with pytest.raises(RuntimeError, match="uint256"):
        helper._data_uint("0x2a", field="x")



def test_execute_helper_imports_and_reconstructs_frozen_sell_fields() -> None:
    helper = _execute_helper()
    envelope = SimpleNamespace(
        max_input_atomic=123,
        min_output_atomic=77,
        deadline_epoch_s=1_900_000_000,
        calldata_sha256="",
        calldata_length=0,
        chain_id=57_073,
        gas_limit_ceiling=300_000,
        max_fee_per_gas_ceiling_atomic=2_000_000_000,
        max_priority_fee_per_gas_ceiling_atomic=100_000_000,
        account_nonce=2,
        transaction_to=helper.INK_V0F_ROUTER_ADDRESS,
    )
    calldata = helper.encode_swap_exact_tokens_for_eth(
        amount_in_atomic=envelope.max_input_atomic,
        amount_out_min_atomic=envelope.min_output_atomic,
        path=(helper.KRAKMASK_ADDRESS, helper.WETH9_ADDRESS),
        recipient=helper.INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=envelope.deadline_epoch_s,
    )
    envelope.calldata_sha256 = helper.sha256_hex(calldata)
    envelope.calldata_length = len(calldata)
    fields = helper._sell_signing_fields(envelope)
    assert fields["nonce"] == 2
    assert fields["to"] == helper.INK_V0F_ROUTER_ADDRESS
    assert fields["value"] == 0
    assert fields["data"].startswith("0x18cbafe5")


def test_sell_receipt_parser_requires_exact_native_sell_direction() -> None:
    helper = _execute_helper()
    amount_in = 123
    amount_out = 77
    envelope = SimpleNamespace(max_input_atomic=amount_in, min_output_atomic=70)

    swap_data = "0x" + "".join(
        f"{word:064x}" for word in (amount_in, 0, 0, amount_out)
    )
    transfer_in = "0x" + f"{amount_in:064x}"
    transfer_out = "0x" + f"{amount_out:064x}"
    receipt = {
        "status": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x3b9aca00",
        "l1Fee": "0x0",
        "logs": [
            {
                "address": helper.INKYSWAP_V2_POOL,
                "topics": [
                    helper._SWAP_TOPIC,
                    helper._topic_address(helper.INK_V0F_ROUTER_ADDRESS),
                    helper._topic_address(helper.INK_V0F_ROUTER_ADDRESS),
                ],
                "data": swap_data,
            },
            {
                "address": helper.KRAKMASK_ADDRESS,
                "topics": [
                    helper._TRANSFER_TOPIC,
                    helper._topic_address(helper.INK_V0F_TAKER_ADDRESS),
                    helper._topic_address(helper.INKYSWAP_V2_POOL),
                ],
                "data": transfer_in,
            },
            {
                "address": helper.WETH9_ADDRESS,
                "topics": [
                    helper._TRANSFER_TOPIC,
                    helper._topic_address(helper.INKYSWAP_V2_POOL),
                    helper._topic_address(helper.INK_V0F_ROUTER_ADDRESS),
                ],
                "data": transfer_out,
            },
        ],
    }
    status, actual_in, actual_out, fee = helper._receipt_settlement(receipt, envelope)
    assert status is helper.ReceiptStatus.SUCCESS
    assert actual_in == amount_in
    assert actual_out == amount_out
    assert fee == 21_000 * 1_000_000_000

    wrong = dict(receipt)
    wrong["logs"] = [dict(item) for item in receipt["logs"]]
    wrong["logs"][0] = dict(wrong["logs"][0])
    wrong["logs"][0]["data"] = "0x" + "".join(
        f"{word:064x}" for word in (0, amount_in, amount_out, 0)
    )
    with pytest.raises(helper.ChainTruthError, match="direction"):
        helper._receipt_settlement(wrong, envelope)


def test_revoke_sidecars_are_private_and_non_replaceable(tmp_path: Path) -> None:
    helper = _execute_helper()
    path = tmp_path / "episode.revoke-prepared.json"
    helper._write_private_once(
        path,
        {
            "schema": helper.REVOKE_PREPARED_SCHEMA,
            "request_id": "11" * 32,
        },
    )
    assert os.stat(path).st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        helper._write_private_once(
            path,
            {
                "schema": helper.REVOKE_PREPARED_SCHEMA,
                "request_id": "11" * 32,
            },
        )



def test_revoke_nonce_is_same_before_sell_and_next_after_terminal_revert(
    tmp_path: Path,
) -> None:
    helper = _execute_helper()
    ledger_path = tmp_path / "episode.sqlite3"
    envelope = SimpleNamespace(account_nonce=2)
    action_id = "aa" * 32

    class Result:
        def __init__(self, row):
            self._row = row

        def fetchone(self):
            return self._row

    class Connection:
        def __init__(self):
            self.signed = None
            self.reconciliation = None

        def execute(self, sql, _params):
            if "FROM signed_transactions" in sql:
                return Result(self.signed)
            if "FROM reconciliations" in sql:
                return Result(self.reconciliation)
            raise AssertionError(sql)

    class Ledger:
        def __init__(self):
            self.connection = Connection()
            self.state = helper.IntentState.RESERVED

        def intent_state(self, _action_id):
            return self.state

    ledger = Ledger()
    assert helper._expected_revoke_nonce(
        ledger,
        ledger_path=ledger_path,
        economic_action_id=action_id,
        envelope=envelope,
    ) == 2

    guard_path = helper._sell_guard_path(ledger_path)
    helper._write_guard(
        guard_path,
        {
            "schema": helper.SELL_GUARD_SCHEMA,
            "transaction_hash": "0x" + "11" * 32,
        },
    )
    ledger.connection.signed = {
        "transaction_hash": "0x" + "11" * 32,
        "account_nonce": 2,
    }
    ledger.connection.reconciliation = {
        "verdict": "REVERTED",
        "transaction_hash": "0x" + "11" * 32,
    }
    ledger.state = helper.IntentState.REJECTED
    assert helper._expected_revoke_nonce(
        ledger,
        ledger_path=ledger_path,
        economic_action_id=action_id,
        envelope=envelope,
    ) == 3

    ledger.state = helper.IntentState.SAFE_HALT
    with pytest.raises(helper.SafeHaltError, match="not terminal enough"):
        helper._expected_revoke_nonce(
            ledger,
            ledger_path=ledger_path,
            economic_action_id=action_id,
            envelope=envelope,
        )
