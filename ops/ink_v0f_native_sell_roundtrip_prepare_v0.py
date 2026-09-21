#!/usr/bin/env python3
"""Prepare the one-shot Ink V0F native-ETH SELL round trip.

Extraction/review helper only. It opens the already-filled first-live BUY ledger,
proves ledger inventory against two-provider chain state, carries that inventory
into a fresh successor policy, freezes one exact approval plus one exact native
SELL envelope, and prints signing fields.

It never reads key material, signs, or broadcasts.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import fields
from decimal import Decimal, ROUND_HALF_EVEN, getcontext
from pathlib import Path
from typing import Any

import qntyspot

from qntyspot.authority_root import (
    AuthorityGrantReceiptV0,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import canonical_json_str, strict_json_loads
from qntyspot.economics import build_intent
from qntyspot.execution_contract import ApprovalActionV0, ExecutionEnvelopeV0, ExecutionSessionV0
from qntyspot.ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    JsonRpcClient,
)
from qntyspot.ink_v0f_execution import INK_V0F_TAKER_ADDRESS, consume_ink_v0f_router_artifact
from qntyspot.ink_v0f_human_signing import (
    build_ink_v0f_approval_signing_request,
    observe_ink_v0f_signer_state_for_market,
)
from qntyspot.ink_v0f_native_sell import encode_swap_exact_tokens_for_eth
from qntyspot.ink_v0f_preauth import InkV0FLiveVerifier
from qntyspot.ink_v0f_risk import consume_ink_v0f_risk_artifact
from qntyspot.ledger import SCHEMA_VERSION, open_ledger
from qntyspot.ledger.execution import ExecutionRuntime
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

BOUND_REPOSITORY_COMMIT = "91ec941d7e89fc44da0e4501b52f47fc65962020"
BOUND_IMPLEMENTATION_DIGEST = (
    "dbcbab558ad591d195fcee06951389d1eb566fed40d9b211b8e5578f61b14f81"
)
EXPECTED_TRUST_CONFIG_DIGEST = (
    "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
)
EXPECTED_BUY_TX_HASH = "0xa02d78dece891ba72dc1c8b4d363be7482e988d5487cb46567b52453db7e2ae7"
EXPECTED_INVENTORY_ATOMIC = 4396392944674627615414
EXPECTED_APPROVAL_NONCE = 1
EXPECTED_MAX_AUTHORITY_ATOMIC = 10**15
VENUE_ID = "inkyswap-v2-ink-mainnet"
PREPARED_SCHEMA = "qntyspot.ops.ink_v0f_native_sell_roundtrip.prepared.v0"


def _assert_bound_qntyspot_root(root: Path) -> None:
    if not root.is_dir():
        raise RuntimeError("explicit QntySpot root is not a directory")
    try:
        head = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        raise RuntimeError("explicit QntySpot root is not a readable Git checkout") from exc
    if head != BOUND_REPOSITORY_COMMIT:
        raise RuntimeError(
            f"QntySpot worktree HEAD {head} is not bound commit {BOUND_REPOSITORY_COMMIT}"
        )
    if dirty.strip():
        raise RuntimeError("bound QntySpot worktree has tracked modifications")

    imported = Path(qntyspot.__file__).resolve()
    try:
        imported.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(
            f"qntyspot import {imported} is outside explicit bound worktree {root}"
        ) from exc

    identity_script = root / "scripts/derive_deployment_identity.py"
    with tempfile.TemporaryDirectory(prefix="qntyspot-sell-identity-") as tmp:
        output = Path(tmp) / "identity.json"
        subprocess.run(
            [
                sys.executable,
                str(identity_script),
                "--root",
                str(root),
                "--repository-commit",
                BOUND_REPOSITORY_COMMIT,
                "--output",
                str(output),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        identity = json.loads(output.read_text(encoding="utf-8"))
    if identity.get("implementation_digest") != BOUND_IMPLEMENTATION_DIGEST:
        raise RuntimeError("recomputed QntySpot implementation digest differs from current binding")


def _decimal_text(value: Decimal) -> str:
    quantum = Decimal(1).scaleb(-28)
    rounded = value.quantize(quantum, rounding=ROUND_HALF_EVEN)
    text = format(rounded, "f").rstrip("0").rstrip(".")
    return text if text else "0"


def _state_path(ledger_path: Path) -> Path:
    return ledger_path.with_suffix(ledger_path.suffix + ".sell-prepared.json")


def _write_durable_state(path: Path, document: dict[str, object]) -> None:
    data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _dataclass_object(value: Any) -> dict[str, object]:
    return {field.name: getattr(value, field.name) for field in fields(value)}


def _data_uint(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"{field} is not RPC hex data")
    body = value[2:]
    if len(body) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in body):
        raise RuntimeError(f"{field} is not one uint256 word")
    return int(body, 16)


def _observe_token_balance(
    live: InkV0FLiveVerifier,
    *,
    common_block: int,
) -> int:
    block_tag = hex(common_block)
    calldata = "0x70a08231" + ("0" * 24) + INK_V0F_TAKER_ADDRESS[2:]
    values: list[int] = []
    for provider in live.providers:
        raw = provider.request(
            "eth_call",
            [{"to": KRAKMASK_ADDRESS, "data": calldata}, block_tag],
        )
        values.append(_data_uint(raw, field="KRAKMASK balanceOf"))
    if len(values) != 2 or values[0] != values[1]:
        raise RuntimeError("Ink providers disagree on KRAKMASK wallet balance")
    return values[0]


def _source_buy(ledger) -> tuple[str, str]:
    rows = ledger.connection.execute(
        """
        SELECT DISTINCT i.cycle_id, i.policy_id, i.state, i.side
          FROM fill_receipts AS f
          JOIN intents AS i ON i.economic_action_id = f.economic_action_id
         WHERE lower(f.external_ref) = ?
        """,
        (EXPECTED_BUY_TX_HASH,),
    ).fetchall()
    if len(rows) != 1:
        raise RuntimeError("exact first-live BUY receipt is missing or ambiguous in ledger")
    row = rows[0]
    if row["state"] != IntentState.FILLED.value or row["side"] != "BUY":
        raise RuntimeError("exact first-live BUY is not a FILLED BUY in ledger")
    cycle = ledger.connection.execute(
        "SELECT status FROM cycles WHERE cycle_id = ?",
        (row["cycle_id"],),
    ).fetchone()
    if cycle is None or cycle["status"] not in {"OPEN", "COMPLETED"}:
        raise RuntimeError("first-live source cycle is neither OPEN nor safely continued")
    return str(row["cycle_id"]), str(row["policy_id"])


def _recoverable_inventory_source(
    ledger,
    *,
    first_buy_cycle_id: str,
    now: int,
) -> tuple[str, str | None]:
    """Find the unique inventory-bearing cycle after zero-effect prepare crashes.

    Recovery may walk multiple inventory-carry hops, but every post-BUY hop must
    remain provably pre-sign/pre-transport: exact inventory, expired policy,
    at most one zero-exposure SELL intent in SIMULATED/EXPIRED, no execution
    session, and no persisted reservation/approval/envelope/external/signed
    state. The first OPEN hop is the only admissible recovery source.
    """

    rows = ledger.connection.execute(
        """
        SELECT cycle_id, payload_json
          FROM state_events
         WHERE event_type = 'CYCLE_OPENED'
         ORDER BY seq
        """
    ).fetchall()
    successors: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        payload = strict_json_loads(row["payload_json"])
        carry = payload.get("inventory_carry") if isinstance(payload, dict) else None
        if not isinstance(carry, dict):
            continue
        source_cycle_id = carry.get("source_cycle_id")
        if not isinstance(source_cycle_id, str):
            raise RuntimeError("inventory-carry event has malformed source cycle id")
        successors.setdefault(source_cycle_id, []).append(
            {
                "cycle_id": str(row["cycle_id"]),
                "amount_atomic": carry.get("amount_atomic"),
            }
        )

    current_cycle_id = first_buy_cycle_id
    visited: set[str] = set()
    first = True

    while True:
        if current_cycle_id in visited:
            raise RuntimeError("inventory-carry history contains a cycle")
        visited.add(current_cycle_id)

        cycle = ledger.connection.execute(
            """
            SELECT c.status, c.policy_id, p.canonical_json
              FROM cycles AS c
              JOIN policies AS p ON p.policy_id = c.policy_id
             WHERE c.cycle_id = ?
            """,
            (current_cycle_id,),
        ).fetchone()
        if cycle is None:
            raise RuntimeError("inventory-carry history references a missing cycle")
        status = str(cycle["status"])
        if status not in {"OPEN", "COMPLETED"}:
            raise RuntimeError("inventory-carry cycle has an unrecoverable status")

        stale_action_id: str | None = None
        if not first:
            old_policy = strict_json_loads(cycle["canonical_json"])
            if not isinstance(old_policy, dict):
                raise RuntimeError("partial prepare successor policy is malformed")
            timing = old_policy.get("timing")
            if (
                not isinstance(timing, dict)
                or type(timing.get("expiry_epoch_s")) is not int
                or timing["expiry_epoch_s"] > now
            ):
                raise RuntimeError("partial prepare successor policy is not expired")

            session_count = ledger.connection.execute(
                "SELECT COUNT(*) FROM execution_sessions WHERE policy_id = ?",
                (cycle["policy_id"],),
            ).fetchone()[0]
            if session_count != 0:
                raise RuntimeError("partial prepare already has an execution session")

            intents = ledger.connection.execute(
                """
                SELECT economic_action_id, state, side, quote_exposure_atomic
                  FROM intents
                 WHERE cycle_id = ?
                """,
                (current_cycle_id,),
            ).fetchall()
            if len(intents) > 1:
                raise RuntimeError(
                    "partial prepare successor contains more than one intent"
                )
            if intents:
                intent = intents[0]
                if (
                    intent["side"] != "SELL"
                    or int(intent["quote_exposure_atomic"]) != 0
                    or intent["state"]
                    not in {
                        IntentState.SIMULATED.value,
                        IntentState.EXPIRED.value,
                    }
                ):
                    raise RuntimeError(
                        "partial prepare successor intent is not safely abandonable"
                    )
                action_id = str(intent["economic_action_id"])
                for table, column in (
                    ("fill_receipts", "economic_action_id"),
                    ("budget_reservations", "economic_action_id"),
                    ("approval_actions", "economic_action_id"),
                    ("execution_envelopes", "economic_action_id"),
                    ("external_actions", "economic_action_id"),
                    ("signed_transactions", "external_action_id"),
                ):
                    count = ledger.connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE {column} = ?",
                        (action_id,),
                    ).fetchone()[0]
                    if count != 0:
                        raise RuntimeError(
                            f"partial prepare has persisted {table}; "
                            "automatic recovery is forbidden"
                        )
                if intent["state"] == IntentState.SIMULATED.value:
                    stale_action_id = action_id
                    if status != "OPEN":
                        raise RuntimeError(
                            "SIMULATED partial prepare cannot already be completed"
                        )

        outgoing = successors.get(current_cycle_id, [])
        if status == "OPEN":
            if outgoing:
                raise RuntimeError("OPEN inventory source already has a carry successor")
            if ledger.inventory_atomic(current_cycle_id) != EXPECTED_INVENTORY_ATOMIC:
                raise RuntimeError(
                    "OPEN recovery source inventory differs from the first-live BUY"
                )
            return current_cycle_id, stale_action_id

        if len(outgoing) != 1:
            description = (
                "completed first-live BUY"
                if first
                else "completed partial prepare cycle"
            )
            raise RuntimeError(
                f"{description} must have exactly one inventory-carry successor"
            )
        if outgoing[0]["amount_atomic"] != str(EXPECTED_INVENTORY_ATOMIC):
            raise RuntimeError("partial prepare carried an unexpected inventory amount")
        if not first and ledger.inventory_atomic(current_cycle_id) != 0:
            raise RuntimeError(
                "completed recovery hop retains inventory after exact outgoing carry"
            )

        current_cycle_id = str(outgoing[0]["cycle_id"])
        first = False


def _successor_policy_doc(
    source_doc: dict[str, Any],
    *,
    spot: Decimal,
    now: int,
    expiry: int,
) -> dict[str, Any]:
    doc = json.loads(json.dumps(source_doc))
    doc["policy_name"] = f"ink-v0f-native-sell-successor-{now}"
    trigger = _decimal_text(spot)
    doc["entry_ladder"]["levels"][0]["trigger_price"] = trigger
    doc["exit_ladder"]["levels"][0]["trigger_price"] = trigger
    doc["limits"]["max_executable_price"] = _decimal_text(spot * Decimal("2"))
    doc["limits"]["min_executable_price"] = _decimal_text(spot * Decimal("0.5"))
    doc["timing"] = {
        "valid_from_epoch_s": now - 5,
        "expiry_epoch_s": expiry,
        "quote_ttl_s": expiry - now,
    }
    doc["reentry"]["max_cycles"] = 1
    return doc


def _verify_receipt_shape(receipt: AuthorityGrantReceiptV0, *, now: int) -> None:
    authority = receipt.authority_policy
    expected = {
        "permitted_repository_commit": BOUND_REPOSITORY_COMMIT,
        "permitted_implementation_digest": BOUND_IMPLEMENTATION_DIGEST,
        "permitted_network_id": f"evm:{INK_CHAIN_ID}",
        "permitted_taker_address": INK_V0F_TAKER_ADDRESS,
        "permitted_venue_id": VENUE_ID,
        "max_reservation_atomic": EXPECTED_MAX_AUTHORITY_ATOMIC,
        "max_cumulative_atomic": EXPECTED_MAX_AUTHORITY_ATOMIC,
    }
    for field, value in expected.items():
        if getattr(authority, field) != value:
            raise RuntimeError(f"AuthorityRoot receipt {field} differs from frozen V9 scope")
    if authority.not_after_epoch_s - now < 300:
        raise RuntimeError("fresh grant has less than 300s remaining; refuse rushed SELL prepare")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qntyspot-root", required=True)
    parser.add_argument("--authority-root")
    parser.add_argument("--receipt")
    parser.add_argument("--ledger", required=True)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="run all pre-grant read-only ledger/chain checks and exit",
    )
    args = parser.parse_args()

    now = int(time.time())
    qntyspot_root = Path(args.qntyspot_root).resolve()
    ledger_path = Path(args.ledger).resolve()
    state_path = _state_path(ledger_path)

    _assert_bound_qntyspot_root(qntyspot_root)
    if not ledger_path.is_file() or ledger_path.stat().st_size == 0:
        raise RuntimeError("SELL prepare requires the existing non-empty first-live BUY ledger")
    if state_path.exists():
        raise RuntimeError("SELL prepared state already exists; resume it instead of preparing again")

    if args.preflight_only:
        router_identity = consume_ink_v0f_router_artifact(
            (
                qntyspot_root
                / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json"
            ).read_bytes()
        )
        providers = tuple(JsonRpcClient(endpoint) for endpoint in INK_RPC_ENDPOINTS)
        if len(providers) != 2:
            raise RuntimeError("SELL preflight requires exactly two canonical Ink providers")
        live = InkV0FLiveVerifier((providers[0], providers[1]), router_identity)

        ledger = open_ledger(str(ledger_path))
        first_buy_cycle_id, source_policy_id = _source_buy(ledger)
        inventory_source_cycle_id, stale_partial_action_id = _recoverable_inventory_source(
            ledger,
            first_buy_cycle_id=first_buy_cycle_id,
            now=now,
        )
        inventory = ledger.inventory_atomic(inventory_source_cycle_id)
        if inventory != EXPECTED_INVENTORY_ATOMIC:
            raise RuntimeError(
                f"ledger inventory {inventory} differs from first-live BUY output "
                f"{EXPECTED_INVENTORY_ATOMIC}"
            )

        market = live.observe_market()
        live_balance = _observe_token_balance(live, common_block=market.common_block)
        if live_balance != inventory:
            raise RuntimeError(
                f"two-provider wallet balance {live_balance} differs from ledger inventory {inventory}"
            )
        allowance = live.observe_allowance_for_market(
            market,
            token_address=KRAKMASK_ADDRESS,
        )
        if allowance.allowance_atomic != 0:
            raise RuntimeError("KRAKMASK router allowance is not zero before SELL prepare")
        signer_state = observe_ink_v0f_signer_state_for_market(live, market)
        if signer_state.account_nonce != EXPECTED_APPROVAL_NONCE:
            raise RuntimeError(
                f"wallet nonce {signer_state.account_nonce} differs from expected first SELL nonce "
                f"{EXPECTED_APPROVAL_NONCE}"
            )

        source_policy_row = ledger.connection.execute(
            "SELECT canonical_json FROM policies WHERE policy_id = ?",
            (source_policy_id,),
        ).fetchone()
        if source_policy_row is None:
            raise RuntimeError("source BUY policy is missing from ledger")
        source_doc = strict_json_loads(source_policy_row["canonical_json"])
        if not isinstance(source_doc, dict):
            raise RuntimeError("source policy canonical JSON is not an object")

        priority_fee = max(
            1_000_000,
            min(100_000_000, signer_state.base_fee_per_gas // 10),
        )
        max_fee = max(
            1_000_000_000,
            signer_state.base_fee_per_gas * 3 + priority_fee,
        )
        approval_gas = 80_000
        sell_gas = 300_000
        native_balance = int(
            providers[0].request(
                "eth_getBalance",
                [INK_V0F_TAKER_ADDRESS, hex(market.common_block)],
            ),
            16,
        )
        native_balance_b = int(
            providers[1].request(
                "eth_getBalance",
                [INK_V0F_TAKER_ADDRESS, hex(market.common_block)],
            ),
            16,
        )
        if native_balance != native_balance_b:
            raise RuntimeError("Ink providers disagree on native wallet balance")
        fee_headroom = (approval_gas + sell_gas) * max_fee
        if native_balance < fee_headroom:
            raise RuntimeError("native balance cannot cover frozen approval + SELL fee ceilings")

        print(
            canonical_json_str(
                {
                    "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.pregrant_preflight.v0",
                    "status": "PRE_GRANT_PREFLIGHT_PASS",
                    "checked_at_epoch_s": now,
                    "first_buy_cycle_id": first_buy_cycle_id,
                    "inventory_source_cycle_id": inventory_source_cycle_id,
                    "stale_partial_action_id": stale_partial_action_id,
                    "inventory_atomic": str(inventory),
                    "common_block": market.common_block,
                    "wallet_nonce": signer_state.account_nonce,
                    "router_allowance_atomic": str(allowance.allowance_atomic),
                    "native_balance_wei": str(native_balance),
                    "fee_headroom_wei": str(fee_headroom),
                }
            )
        )
        return 0

    if args.authority_root is None or args.receipt is None:
        raise RuntimeError("--authority-root and --receipt are required outside --preflight-only")

    authority_root = Path(args.authority_root).resolve()
    receipt_path = Path(args.receipt).resolve()
    try:
        receipt_path.relative_to(authority_root)
    except ValueError as exc:
        raise RuntimeError("grant receipt must live inside the explicit AuthorityRoot") from exc

    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_path.read_bytes())
    _verify_receipt_shape(receipt, now=now)
    authority = receipt.authority_policy

    config_path = authority_root / "public/trusted-authority-root-v0.json"
    anchor_path = authority_root / "public/authority-root-ed25519-v0.pub"
    trusted = load_trusted_authority_root(
        config_path.read_bytes(),
        expected_config_digest=EXPECTED_TRUST_CONFIG_DIGEST,
        anchor_bytes=anchor_path.read_bytes(),
    )

    router_identity = consume_ink_v0f_router_artifact(
        (qntyspot_root / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json").read_bytes()
    )
    risk_policy = consume_ink_v0f_risk_artifact(
        (qntyspot_root / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json").read_bytes()
    )
    providers = tuple(JsonRpcClient(endpoint) for endpoint in INK_RPC_ENDPOINTS)
    if len(providers) != 2:
        raise RuntimeError("SELL prepare requires exactly two canonical Ink providers")
    live = InkV0FLiveVerifier((providers[0], providers[1]), router_identity)

    ledger = open_ledger(str(ledger_path))
    first_buy_cycle_id, source_policy_id = _source_buy(ledger)
    inventory_source_cycle_id, stale_partial_action_id = _recoverable_inventory_source(
        ledger,
        first_buy_cycle_id=first_buy_cycle_id,
        now=now,
    )
    inventory = ledger.inventory_atomic(inventory_source_cycle_id)
    if inventory != EXPECTED_INVENTORY_ATOMIC:
        raise RuntimeError(
            f"ledger inventory {inventory} differs from first-live BUY output "
            f"{EXPECTED_INVENTORY_ATOMIC}"
        )

    market = live.observe_market()
    live_balance = _observe_token_balance(live, common_block=market.common_block)
    if live_balance != inventory:
        raise RuntimeError(
            f"two-provider wallet balance {live_balance} differs from ledger inventory {inventory}"
        )
    allowance = live.observe_allowance_for_market(market, token_address=KRAKMASK_ADDRESS)
    if allowance.allowance_atomic != 0:
        raise RuntimeError("KRAKMASK router allowance is not zero before SELL prepare")
    signer_state = observe_ink_v0f_signer_state_for_market(live, market)
    if signer_state.account_nonce != EXPECTED_APPROVAL_NONCE:
        raise RuntimeError(
            f"wallet nonce {signer_state.account_nonce} differs from expected first SELL nonce "
            f"{EXPECTED_APPROVAL_NONCE}"
        )

    source_policy_row = ledger.connection.execute(
        "SELECT canonical_json FROM policies WHERE policy_id = ?",
        (source_policy_id,),
    ).fetchone()
    if source_policy_row is None:
        raise RuntimeError("source BUY policy is missing from ledger")
    source_doc = strict_json_loads(source_policy_row["canonical_json"])
    if not isinstance(source_doc, dict):
        raise RuntimeError("source policy canonical JSON is not an object")

    getcontext().prec = 80
    spot = Decimal(market.reserve1_atomic) / Decimal(market.reserve0_atomic)
    expiry = min(authority.not_after_epoch_s - 30, now + 600)
    if expiry - now < 240:
        raise RuntimeError("insufficient grant window after SELL policy/deadline margins")
    policy_doc = _successor_policy_doc(source_doc, spot=spot, now=now, expiry=expiry)
    policy = parse_policy(policy_doc)

    session_ordinal = int(
        ledger.connection.execute(
            "SELECT COALESCE(MAX(session_ordinal), -1) + 1 FROM execution_sessions"
        ).fetchone()[0]
    )
    session = ExecutionSessionV0(
        repository_commit=BOUND_REPOSITORY_COMMIT,
        implementation_digest=BOUND_IMPLEMENTATION_DIGEST,
        runtime_identity=f"cpython-{sys.version_info.major}.{sys.version_info.minor}",
        db_schema_version=SCHEMA_VERSION,
        policy_id=policy.policy_id,
        authority_policy_digest=authority.authority_policy_digest,
        taker_address=INK_V0F_TAKER_ADDRESS,
        network_id=f"evm:{INK_CHAIN_ID}",
        venue_id=VENUE_ID,
        venue_adapter_version="ink-v0f",
        started_at_epoch_s=now,
        session_ordinal=session_ordinal,
    )
    verified = verify_authority_grant(
        receipt=receipt,
        trusted_root=trusted,
        session=session,
        now_epoch_s=now,
    )

    priority_fee = max(1_000_000, min(100_000_000, signer_state.base_fee_per_gas // 10))
    max_fee = max(1_000_000_000, signer_state.base_fee_per_gas * 3 + priority_fee)
    approval_gas = 80_000
    sell_gas = 300_000
    native_balance = int(
        providers[0].request("eth_getBalance", [INK_V0F_TAKER_ADDRESS, hex(market.common_block)]),
        16,
    )
    native_balance_b = int(
        providers[1].request("eth_getBalance", [INK_V0F_TAKER_ADDRESS, hex(market.common_block)]),
        16,
    )
    if native_balance != native_balance_b:
        raise RuntimeError("Ink providers disagree on native wallet balance")
    if native_balance < (approval_gas + sell_gas) * max_fee:
        raise RuntimeError("native balance cannot cover frozen approval + SELL fee ceilings")

    # All external/read-only checks are complete before ledger continuity mutates.
    # A prior failed prepare may have left exactly one SIMULATED zero-effect
    # successor. Expire only that fully-proven pre-commitment action, then carry
    # its unchanged inventory forward. Any signable/external residue was
    # rejected above.
    if stale_partial_action_id is not None:
        ledger.transition(
            stale_partial_action_id,
            IntentState.EXPIRED,
            now_epoch_s=now,
            payload={"recovery": "abandon_failed_pre_sign_sell_prepare"},
        )
    ledger.admit_policy(policy)
    successor_cycle_id = ledger.continue_inventory_into_successor_cycle(
        inventory_source_cycle_id,
        policy,
        0,
        now_epoch_s=now,
    )
    carried = ledger.inventory_atomic(successor_cycle_id)
    if carried != inventory:
        raise RuntimeError("successor cycle did not receive exact source inventory")

    intent = build_intent(
        policy,
        successor_cycle_id,
        policy.level("X1"),
        now_epoch_s=now,
        inventory_atomic=carried,
    )
    if intent.quote_exposure_atomic != 0 or intent.bounds.max_input_atomic != inventory:
        raise RuntimeError("successor X1 is not the exact full-inventory zero-exposure SELL")
    ledger.create_intent(intent, now_epoch_s=now)
    for target in (IntentState.TRIGGERED, IntentState.QUOTE_PINNED, IntentState.SIMULATED):
        ledger.transition(intent.economic_action_id, target, now_epoch_s=now)

    runtime = ExecutionRuntime(ledger)
    runtime.record_verified_authority(verified, accepted_at_epoch_s=now)
    runtime.create_execution_session(session, verified, now_epoch_s=now)
    runtime.reserve_action(
        intent.economic_action_id,
        session=session,
        verified_grant=verified,
        now_epoch_s=now,
    )
    if ledger.connection.execute(
        "SELECT COUNT(*) FROM budget_reservations WHERE economic_action_id = ?",
        (intent.economic_action_id,),
    ).fetchone()[0] != 0:
        raise RuntimeError("zero-exposure SELL unexpectedly created a budget reservation")

    approval, envelope = runtime.record_ink_v0f_native_sell_preauth_bundle(
        live_verifier=live,
        risk_policy=risk_policy,
        router_identity=router_identity,
        intent=intent,
        session=session,
        verified_grant=verified,
        account_nonce=signer_state.account_nonce + 1,
        gas_limit_ceiling=sell_gas,
        max_fee_per_gas_ceiling=max_fee,
        max_priority_fee_per_gas_ceiling=priority_fee,
        constructed_at_epoch_s=now,
        now_epoch_s=now,
    )
    if envelope.account_nonce != signer_state.account_nonce + 1:
        raise RuntimeError("SELL nonce is not exactly one after approval nonce")
    if envelope.max_input_atomic != inventory:
        raise RuntimeError("frozen SELL does not consume exact carried inventory")

    approval_request = build_ink_v0f_approval_signing_request(
        approval=approval,
        envelope=envelope,
        session=session,
        approval_nonce=signer_state.account_nonce,
        gas_limit_ceiling=approval_gas,
        max_fee_per_gas_ceiling=max_fee,
        max_priority_fee_per_gas_ceiling=priority_fee,
        constructed_at_epoch_s=now,
    )
    sell_calldata = encode_swap_exact_tokens_for_eth(
        amount_in_atomic=envelope.max_input_atomic,
        amount_out_min_atomic=envelope.min_output_atomic,
        path=(KRAKMASK_ADDRESS, WETH9_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=envelope.deadline_epoch_s,
    )
    from qntyspot.canon import sha256_hex
    if sha256_hex(sell_calldata) != envelope.calldata_sha256:
        raise RuntimeError("reconstructed native SELL calldata differs from frozen envelope")
    sell_signing_fields = {
        "accessList": [],
        "chainId": envelope.chain_id,
        "data": "0x" + sell_calldata.hex(),
        "gas": envelope.gas_limit_ceiling,
        "maxFeePerGas": envelope.max_fee_per_gas_ceiling_atomic,
        "maxPriorityFeePerGas": envelope.max_priority_fee_per_gas_ceiling_atomic,
        "nonce": envelope.account_nonce,
        "to": envelope.transaction_to,
        "type": 2,
        "value": 0,
    }

    state = {
        "schema": PREPARED_SCHEMA,
        "qntyspot_root": str(qntyspot_root),
        "authority_root": str(authority_root),
        "receipt": str(receipt_path),
        "ledger": str(ledger_path),
        "prepared_at_epoch_s": now,
        "source_cycle_id": inventory_source_cycle_id,
        "cycle_id": successor_cycle_id,
        "policy_doc": policy_doc,
        "session": _dataclass_object(session),
        "approval": _dataclass_object(approval),
        "envelope": _dataclass_object(envelope),
        "approval_request": {
            "approval_nonce": signer_state.account_nonce,
            "gas_limit_ceiling": approval_gas,
            "max_fee_per_gas_ceiling": max_fee,
            "max_priority_fee_per_gas_ceiling": priority_fee,
            "constructed_at_epoch_s": now,
            "request_id": approval_request.request_id,
        },
        "expected_inventory_atomic": str(inventory),
        "buy_transaction_hash": EXPECTED_BUY_TX_HASH,
    }
    _write_durable_state(state_path, state)

    result = {
        "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.signing_requests.v0",
        "status": "PREPARED_NOT_SIGNED_NOT_BROADCAST",
        "ledger": str(ledger_path),
        "prepared_state": str(state_path),
        "economic_action_id": intent.economic_action_id,
        "approval_action_id": approval.approval_action_id,
        "approval_nonce": approval_request.scope.account_nonce,
        "sell_nonce": envelope.account_nonce,
        "inventory_atomic": str(inventory),
        "approval_signing_fields": approval_request.eip1559_signing_fields(),
        "sell_signing_fields_after_approval_revalidation": sell_signing_fields,
        "warning": (
            "Sign the approval externally first. Do not broadcast from the wallet. "
            "Only sign the frozen SELL after approval settlement and QntySpot revalidation."
        ),
    }
    print(canonical_json_str(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
