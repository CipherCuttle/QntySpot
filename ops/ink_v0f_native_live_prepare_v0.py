#!/usr/bin/env python3
"""Prepare one real Ink V0F native-ETH BUY without signing or broadcasting.

This ops helper is intentionally outside the QntySpot implementation manifest.
It must be executed while the imported qntyspot package is checked out at the
AuthorityRoot-bound canonical commit. It never reads wallet key material and
has no raw-transaction transport.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import sys
import time
from dataclasses import fields
from decimal import Decimal, ROUND_HALF_EVEN, getcontext
from pathlib import Path

import qntyspot

from qntyspot.authority_root import (
    AuthorityGrantReceiptV0,
    load_trusted_authority_root,
    verify_authority_grant,
)
from qntyspot.canon import canonical_json_str
from qntyspot.economics import build_intent
from qntyspot.execution_contract import ExecutionEnvelopeV0, ExecutionSessionV0
from qntyspot.ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    InkShadowAdapter,
    JsonRpcClient,
)
from qntyspot.ink_v0f_execution import (
    INK_V0F_TAKER_ADDRESS,
    consume_ink_v0f_router_artifact,
)
from qntyspot.ink_v0f_human_signing import observe_ink_v0f_signer_state_for_market
from qntyspot.ink_v0f_native import revalidate_ink_v0f_native_same_amount
from qntyspot.ink_v0f_preauth import InkV0FLiveVerifier
from qntyspot.ink_v0f_risk import consume_ink_v0f_risk_artifact
from qntyspot.ledger import SCHEMA_VERSION, open_ledger
from qntyspot.ledger.execution import ExecutionRuntime
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState

BOUND_REPOSITORY_COMMIT = "928b110ee9e5202d411487ee1ede52a022e097c0"
BOUND_IMPLEMENTATION_DIGEST = (
    "0eebedcd5028ada31899dde2794fc783970df13e461dfd85353ed61c22aa4e8d"
)
EXPECTED_TRUST_CONFIG_DIGEST = (
    "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
)
EXPECTED_MAX_INPUT_ATOMIC = 10**15
VENUE_ID = "inkyswap-v2-ink-mainnet"

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
    with tempfile.TemporaryDirectory(prefix="qntyspot-identity-") as tmp:
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
        raise RuntimeError(
            "recomputed QntySpot implementation digest differs from AuthorityRoot binding"
        )


def _decimal_text(value: Decimal) -> str:
    # Policy trigger prices are later widened by basis-point arithmetic.
    # Leave two decimal places of canonical headroom so a 50-bps (1/200)
    # multiplier still serializes within QntySpot's 30-fractional-digit limit.
    # Live reserve-derived quote math remains exact and the frozen 50-bps
    # output floor remains authoritative.
    quantum = Decimal(1).scaleb(-28)
    rounded = value.quantize(quantum, rounding=ROUND_HALF_EVEN)
    text = format(rounded, "f").rstrip("0").rstrip(".")
    return text if text else "0"


def _state_path(ledger_path: Path) -> Path:
    return ledger_path.with_suffix(ledger_path.suffix + ".prepared.json")


def _claim_fresh_episode_paths(ledger_path: Path, state_path: Path) -> None:
    """Atomically reserve both durable paths before any live observation."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    ledger_fd: int | None = None
    state_fd: int | None = None
    try:
        ledger_fd = os.open(ledger_path, flags, 0o600)
        os.close(ledger_fd)
        ledger_fd = None
        state_fd = os.open(state_path, flags, 0o600)
        os.close(state_fd)
        state_fd = None
    except FileExistsError as exc:
        if ledger_fd is not None:
            os.close(ledger_fd)
        if state_fd is not None:
            os.close(state_fd)
        # If this process created the ledger claim but could not claim the
        # state path, remove only our still-empty ledger placeholder.
        try:
            if ledger_path.is_file() and ledger_path.stat().st_size == 0:
                ledger_path.unlink()
        except FileNotFoundError:
            pass
        raise RuntimeError(
            "refusing to reuse or race an existing first-live ledger/state path; "
            "choose a fresh path"
        ) from exc


def _envelope_object(envelope: ExecutionEnvelopeV0) -> dict[str, object]:
    return {field.name: getattr(envelope, field.name) for field in fields(envelope)}


def _session_object(session: ExecutionSessionV0) -> dict[str, object]:
    return {field.name: getattr(session, field.name) for field in fields(session)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qntyspot-root", required=True)
    parser.add_argument("--authority-root", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--ledger", required=True)
    args = parser.parse_args()

    now = int(time.time())
    qntyspot_root = Path(args.qntyspot_root).resolve()
    _assert_bound_qntyspot_root(qntyspot_root)
    router_artifact = qntyspot_root / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json"
    risk_artifact = qntyspot_root / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json"
    authority_root = Path(args.authority_root).resolve()
    receipt_path = Path(args.receipt).resolve()
    ledger_path = Path(args.ledger).resolve()
    state_path = _state_path(ledger_path)

    _claim_fresh_episode_paths(ledger_path, state_path)
    if not receipt_path.is_file():
        raise RuntimeError("explicit AuthorityRoot receipt path is not a file")

    receipt_bytes = receipt_path.read_bytes()
    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_bytes)
    authority = receipt.authority_policy
    if authority.permitted_repository_commit != BOUND_REPOSITORY_COMMIT:
        raise RuntimeError("receipt does not authorize bound QntySpot commit")
    if authority.permitted_implementation_digest != BOUND_IMPLEMENTATION_DIGEST:
        raise RuntimeError("receipt does not authorize bound QntySpot implementation")
    if authority.permitted_network_id != f"evm:{INK_CHAIN_ID}":
        raise RuntimeError("receipt is not for Ink mainnet")
    if authority.permitted_taker_address != INK_V0F_TAKER_ADDRESS:
        raise RuntimeError("receipt is for another taker")
    if authority.permitted_venue_id != VENUE_ID:
        raise RuntimeError("receipt is for another venue")
    if authority.max_reservation_atomic != EXPECTED_MAX_INPUT_ATOMIC:
        raise RuntimeError("receipt reservation ceiling differs from frozen 0.001 ETH cap")
    if authority.max_cumulative_atomic != EXPECTED_MAX_INPUT_ATOMIC:
        raise RuntimeError("receipt cumulative ceiling differs from frozen 0.001 ETH cap")
    remaining = authority.not_after_epoch_s - now
    if remaining < 300:
        raise RuntimeError(
            f"grant has only {remaining}s remaining; refuse to prepare a rushed live action"
        )

    config_path = authority_root / "public/trusted-authority-root-v0.json"
    anchor_path = authority_root / "public/authority-root-ed25519-v0.pub"
    trusted = load_trusted_authority_root(
        config_path.read_bytes(),
        expected_config_digest=EXPECTED_TRUST_CONFIG_DIGEST,
        anchor_bytes=anchor_path.read_bytes(),
    )

    router_identity = consume_ink_v0f_router_artifact(router_artifact.read_bytes())
    risk_policy = consume_ink_v0f_risk_artifact(risk_artifact.read_bytes())
    providers = tuple(JsonRpcClient(endpoint) for endpoint in INK_RPC_ENDPOINTS)
    live = InkV0FLiveVerifier(providers, router_identity)

    # Read live pool truth first and derive a narrow policy around the current
    # reserve price. The transaction minimum later remains the stricter fresh
    # quote-relative 50-bps floor from the frozen risk consumer.
    market = live.observe_market()
    if market.reserve0_atomic <= 0 or market.reserve1_atomic <= 0:
        raise RuntimeError("live pool has non-positive reserves")
    getcontext().prec = 80
    spot = Decimal(market.reserve1_atomic) / Decimal(market.reserve0_atomic)
    trigger = spot
    max_price = spot * Decimal("1.02")
    min_price = spot * Decimal("0.50")

    expiry = min(authority.not_after_epoch_s - 30, now + 600)
    quote_ttl = expiry - now
    if quote_ttl < 240:
        raise RuntimeError("insufficient safe grant window after policy/deadline margins")

    policy_doc = {
        "schema": "qntyspot.policy.v0",
        "policy_name": "ink-v0f-native-first-live",
        "side": "BUY",
        "base": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": KRAKMASK_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "KRAKMASK",
        },
        "quote": {
            "ref": {
                "namespace": "evm",
                "chain_id": INK_CHAIN_ID,
                "contract_address": WETH9_ADDRESS,
            },
            "decimals": 18,
            "display_symbol": "WETH",
        },
        "entry_ladder": {
            "levels": [
                {
                    "level_id": "E1",
                    "trigger_price": _decimal_text(trigger),
                    "input_amount": "0.001",
                }
            ]
        },
        "exit_ladder": {
            "levels": [
                {
                    "level_id": "X1",
                    "trigger_price": _decimal_text(trigger),
                    "input_ratio": "1",
                }
            ]
        },
        "capital": {
            "allocation_quote": "0.001",
            "per_order_cap_quote": "0.001",
            "per_instrument_cap_quote": "0.001",
            "per_network_cap_quote": "0.001",
            "global_portfolio_cap_quote": "0.001",
            "reserved_cash_quote": "0",
        },
        "limits": {
            "max_executable_price": _decimal_text(max_price),
            "min_executable_price": _decimal_text(min_price),
            "max_price_impact_bps": 100,
            "max_slippage_bps": 50,
        },
        "timing": {
            "valid_from_epoch_s": now - 5,
            "expiry_epoch_s": expiry,
            "quote_ttl_s": quote_ttl,
        },
        "reentry": {
            "max_cycles": 1,
            "rearm_hysteresis_bps": 200,
            "rearm_cooldown_s": 600,
        },
        "recycling": {
            "profit_recycle_ratio": "0",
            "banked_profit_ratio": "1",
        },
    }

    policy = parse_policy(policy_doc)
    ledger = open_ledger(str(ledger_path))
    ledger.admit_policy(policy)
    cycle_id = ledger.open_cycle(policy, 0, now_epoch_s=now)
    intent = build_intent(policy, cycle_id, policy.level("E1"), now_epoch_s=now)
    if intent.bounds.max_input_atomic != EXPECTED_MAX_INPUT_ATOMIC:
        raise RuntimeError("constructed intent is not exactly 0.001 quote atomic")
    ledger.create_intent(intent, now_epoch_s=now)
    for state in (
        IntentState.TRIGGERED,
        IntentState.QUOTE_PINNED,
        IntentState.SIMULATED,
    ):
        ledger.transition(intent.economic_action_id, state, now_epoch_s=now)

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
        session_ordinal=0,
    )
    verified = verify_authority_grant(
        receipt=receipt,
        trusted_root=trusted,
        session=session,
        now_epoch_s=now,
    )
    runtime = ExecutionRuntime(ledger)
    runtime.record_verified_authority(verified, accepted_at_epoch_s=now)
    runtime.create_execution_session(session, verified, now_epoch_s=now)
    runtime.reserve_action(
        intent.economic_action_id,
        session=session,
        verified_grant=verified,
        now_epoch_s=now,
    )

    signer_market = live.observe_market()
    signer_state = observe_ink_v0f_signer_state_for_market(live, signer_market)
    priority_fee = max(1_000_000, min(100_000_000, signer_state.base_fee_per_gas // 10))
    max_fee = max(
        1_000_000_000,
        signer_state.base_fee_per_gas * 3 + priority_fee,
    )
    gas_limit = 250_000

    envelope = runtime.record_ink_v0f_native_buy_preauth(
        live_verifier=live,
        risk_policy=risk_policy,
        router_identity=router_identity,
        intent=intent,
        session=session,
        verified_grant=verified,
        account_nonce=signer_state.account_nonce,
        gas_limit_ceiling=gas_limit,
        max_fee_per_gas_ceiling=max_fee,
        max_priority_fee_per_gas_ceiling=priority_fee,
        constructed_at_epoch_s=now,
        now_epoch_s=now,
    )
    revalidation = revalidate_ink_v0f_native_same_amount(
        live_verifier=live,
        risk_policy=risk_policy,
        router_identity=router_identity,
        ledger=ledger,
        intent=intent,
        session=session,
        envelope=envelope,
        now_epoch_s=int(time.time()),
    )

    state = {
        "schema": "qntyspot.ops.ink_v0f_native_first_live.prepared.v0",
        "qntyspot_root": str(qntyspot_root),
        "authority_root": str(authority_root),
        "receipt": str(receipt_path),
        "ledger": str(ledger_path),
        "prepared_at_epoch_s": now,
        "cycle_id": cycle_id,
        "policy_doc": policy_doc,
        "session": _session_object(session),
        "envelope": _envelope_object(envelope),
    }
    state_path.write_text(
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    result = {
        "schema": "qntyspot.ops.ink_v0f_native_first_live.signing_request.v0",
        "status": "PREPARED_NOT_SIGNED_NOT_BROADCAST",
        "grant_receipt_id": receipt.receipt_id,
        "grant_not_after_epoch_s": authority.not_after_epoch_s,
        "economic_action_id": intent.economic_action_id,
        "envelope_id": envelope.envelope_id,
        "ledger": str(ledger_path),
        "prepared_state": str(state_path),
        "fresh_common_block": revalidation.common_block,
        "fresh_quote_output_atomic": str(revalidation.fresh_quote_output_atomic),
        "fresh_required_min_output_atomic": str(
            revalidation.fresh_required_min_output_atomic
        ),
        "signing_fields": revalidation.eip1559_signing_fields(),
        "warning": (
            "Sign these exact fields externally. Do not broadcast from the wallet. "
            "QntySpot must validate the complete signed bytes before submission."
        ),
    }
    print(canonical_json_str(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
