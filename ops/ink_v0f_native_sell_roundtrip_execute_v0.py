#!/usr/bin/env python3
"""Execute/observe the extraction-only Ink V0F native SELL round trip.

Modes are deliberately separate:
- approval: admit + transport the exact approval at most once, then observe it;
- sell: require confirmed exact approval, revalidate the frozen SELL, admit the
  externally signed SELL bytes, guard before transport, transport at most once,
  then observe/reconcile terminal chain truth.

No key material is accepted. Re-running after a durable transport guard is
observation-only.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

import qntyspot

from qntyspot.authority_root import (
    AuthorityGrantReceiptV0,
    load_trusted_authority_root,
    verify_authority_grant,
    verify_expired_authority_grant_for_recovery,
    require_effective_capability,
)
from qntyspot.canon import canonical_json_bytes, sha256_hex, strict_json_loads
from qntyspot.domain import Side
from qntyspot.economics import build_intent
from qntyspot.errors import ChainTruthError, SafeHaltError
from qntyspot.exact_signed_bytes import ExactSignedBytesScopeV0, JsonRpcExactSignedBytesTransport
from qntyspot.execution_contract import (
    ApprovalActionV0,
    AuthorityLevel,
    Capability,
    ChainObservationV0,
    ChainPresence,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    ReceiptStatus,
    ROBINHOOD_V0_FINALITY,
)
from qntyspot.ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    WETH9_ADDRESS,
    InkShadowAdapter,
    JsonRpcClient,
)
from qntyspot.ink_v0f_execution import (
    INK_V0F_ROUTER_ADDRESS,
    INK_V0F_TAKER_ADDRESS,
    amount_out_min_atomic,
    build_ink_v0f_human_signing_preview,
    consume_ink_v0f_router_artifact,
)
from qntyspot.ink_v0f_human_signing import (
    InkV0FApprovalSettlementState,
    build_ink_v0f_approval_signing_request,
    build_ink_v0f_revoke_signing_request,
    evaluate_ink_v0f_approval_truth,
    observe_ink_v0f_approval_transaction,
    observe_ink_v0f_signer_state_for_market,
    reconcile_ink_v0f_approval,
    validate_ink_v0f_signed_approval,
)
from qntyspot.ink_v0f_native_sell import (
    decode_swap_exact_tokens_for_eth,
    encode_swap_exact_tokens_for_eth,
)
from qntyspot.ink_v0f_preauth import InkV0FLiveVerifier
from qntyspot.ink_v0f_risk import consume_ink_v0f_risk_artifact
from qntyspot.keccak import keccak256
from qntyspot.ledger import open_ledger
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
PREPARED_SCHEMA = "qntyspot.ops.ink_v0f_native_sell_roundtrip.prepared.v0"
SELL_GUARD_SCHEMA = "qntyspot.ops.ink_v0f_native_sell_roundtrip.sell_guard.v0"
REVOKE_PREPARED_SCHEMA = "qntyspot.ops.ink_v0f_native_sell_roundtrip.revoke_prepared.v0"
REVOKE_GUARD_SCHEMA = "qntyspot.ops.ink_v0f_native_sell_roundtrip.revoke_guard.v0"
MIN_REMAINING_AUTHORITY_S = 120
PROVIDER_IDS = ("ink-provider-0", "ink-provider-1")

_SWAP_TOPIC = "0x" + keccak256(
    b"Swap(address,uint256,uint256,uint256,uint256,address)"
).hex()
_TRANSFER_TOPIC = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()


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
        raise RuntimeError("QntySpot worktree is not the V9-bound canonical commit")
    if dirty.strip():
        raise RuntimeError("bound QntySpot worktree has tracked modifications")
    imported = Path(qntyspot.__file__).resolve()
    try:
        imported.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("qntyspot import is outside the explicit bound worktree") from exc

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
        raise RuntimeError("recomputed implementation digest differs from V9 binding")


def _prepared_state(path: Path) -> Mapping[str, Any]:
    raw = strict_json_loads(path.read_bytes())
    expected = {
        "schema",
        "qntyspot_root",
        "authority_root",
        "receipt",
        "ledger",
        "prepared_at_epoch_s",
        "source_cycle_id",
        "cycle_id",
        "policy_doc",
        "session",
        "approval",
        "envelope",
        "approval_request",
        "expected_inventory_atomic",
        "buy_transaction_hash",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise RuntimeError("prepared state has unknown or missing fields")
    if raw["schema"] != PREPARED_SCHEMA:
        raise RuntimeError("prepared state schema differs")
    return raw


def _read_signed_bytes(path: Path) -> bytes:
    if not path.is_file():
        raise RuntimeError("signed-byte path is not a file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("signed-byte file must not permit group/other access")
    text = path.read_text(encoding="ascii").strip()
    if text.startswith("0x"):
        text = text[2:]
    if (
        not text
        or len(text) % 2
        or any(ch not in "0123456789abcdefABCDEF" for ch in text)
    ):
        raise RuntimeError("signed-byte file must contain one complete hex byte string")
    return bytes.fromhex(text)


def _write_guard(path: Path, document: Mapping[str, Any]) -> None:
    data = canonical_json_bytes(dict(document))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _read_guard(path: Path) -> Mapping[str, Any]:
    raw = strict_json_loads(path.read_bytes())
    if not isinstance(raw, dict) or raw.get("schema") != SELL_GUARD_SCHEMA:
        raise RuntimeError("SELL submission guard is malformed")
    return raw


def _sell_guard_path(ledger_path: Path) -> Path:
    return ledger_path.with_suffix(ledger_path.suffix + ".sell-submission.json")


def _revoke_prepared_path(ledger_path: Path) -> Path:
    return ledger_path.with_suffix(ledger_path.suffix + ".revoke-prepared.json")


def _revoke_guard_path(ledger_path: Path) -> Path:
    return ledger_path.with_suffix(ledger_path.suffix + ".revoke-submission.json")


def _write_private_once(path: Path, document: Mapping[str, Any]) -> None:
    data = canonical_json_bytes(dict(document))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _read_revoke_prepared(path: Path) -> Mapping[str, Any]:
    raw = strict_json_loads(path.read_bytes())
    expected = {
        "schema",
        "request_id",
        "approval_action_id",
        "economic_action_id",
        "revoke_nonce",
        "gas_limit_ceiling",
        "max_fee_per_gas_ceiling",
        "max_priority_fee_per_gas_ceiling",
        "constructed_at_epoch_s",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise RuntimeError("revoke prepared state has unknown or missing fields")
    if raw["schema"] != REVOKE_PREPARED_SCHEMA:
        raise RuntimeError("revoke prepared state schema differs")
    return raw


def _read_revoke_guard(path: Path) -> Mapping[str, Any]:
    raw = strict_json_loads(path.read_bytes())
    if not isinstance(raw, dict) or raw.get("schema") != REVOKE_GUARD_SCHEMA:
        raise RuntimeError("revoke submission guard is malformed")
    return raw


def _reconstruct(
    state: Mapping[str, Any],
) -> tuple[Any, Any, ExecutionSessionV0, ApprovalActionV0, ExecutionEnvelopeV0, Any]:
    policy = parse_policy(state["policy_doc"])
    session = ExecutionSessionV0(**state["session"])
    approval = ApprovalActionV0(**state["approval"])
    envelope = ExecutionEnvelopeV0(**state["envelope"])
    inventory = int(state["expected_inventory_atomic"])
    intent = build_intent(
        policy,
        state["cycle_id"],
        policy.level("X1"),
        now_epoch_s=state["prepared_at_epoch_s"],
        inventory_atomic=inventory,
    )
    if policy.policy_id != session.policy_id:
        raise RuntimeError("prepared policy differs from execution session")
    if intent.economic_action_id != envelope.economic_action_id:
        raise RuntimeError("reconstructed SELL intent differs from frozen envelope")
    if approval.economic_action_id != intent.economic_action_id:
        raise RuntimeError("prepared approval belongs to another economic action")
    if (
        envelope.session_id != session.session_id
        or envelope.session_identity_digest != session.identity_digest
        or envelope.authority_policy_digest != session.authority_policy_digest
        or approval.session_id != session.session_id
        or approval.session_identity_digest != session.identity_digest
    ):
        raise RuntimeError("prepared approval/envelope/session binding differs")

    request_args = state["approval_request"]
    request = build_ink_v0f_approval_signing_request(
        approval=approval,
        envelope=envelope,
        session=session,
        approval_nonce=request_args["approval_nonce"],
        gas_limit_ceiling=request_args["gas_limit_ceiling"],
        max_fee_per_gas_ceiling=request_args["max_fee_per_gas_ceiling"],
        max_priority_fee_per_gas_ceiling=request_args[
            "max_priority_fee_per_gas_ceiling"
        ],
        constructed_at_epoch_s=request_args["constructed_at_epoch_s"],
    )
    if request.request_id != request_args["request_id"]:
        raise RuntimeError("reconstructed approval request differs from prepared request")
    return policy, intent, session, approval, envelope, request


def _authority_proof(
    state: Mapping[str, Any],
    *,
    authority_root: Path,
    session: ExecutionSessionV0,
    now: int,
    external_effect_allowed: bool,
):
    if Path(state["authority_root"]).resolve() != authority_root:
        raise RuntimeError("prepared state names another AuthorityRoot")
    receipt_path = Path(state["receipt"]).resolve()
    try:
        receipt_path.relative_to(authority_root)
    except ValueError as exc:
        raise RuntimeError("prepared receipt is outside explicit AuthorityRoot") from exc
    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_path.read_bytes())
    authority = receipt.authority_policy
    if (
        authority.permitted_repository_commit != BOUND_REPOSITORY_COMMIT
        or authority.permitted_implementation_digest != BOUND_IMPLEMENTATION_DIGEST
    ):
        raise RuntimeError("receipt no longer authorizes the prepared V9 runtime")

    trusted = load_trusted_authority_root(
        (authority_root / "public/trusted-authority-root-v0.json").read_bytes(),
        expected_config_digest=EXPECTED_TRUST_CONFIG_DIGEST,
        anchor_bytes=(authority_root / "public/authority-root-ed25519-v0.pub").read_bytes(),
    )
    remaining = authority.not_after_epoch_s - now
    if external_effect_allowed:
        if remaining < MIN_REMAINING_AUTHORITY_S:
            raise SafeHaltError(
                f"grant has only {remaining}s remaining; refuse new approval/SELL transport"
            )
        return verify_authority_grant(
            receipt=receipt,
            trusted_root=trusted,
            session=session,
            now_epoch_s=now,
        ), False
    if remaining > 0:
        return verify_authority_grant(
            receipt=receipt,
            trusted_root=trusted,
            session=session,
            now_epoch_s=now,
        ), False
    return verify_expired_authority_grant_for_recovery(
        receipt=receipt,
        trusted_root=trusted,
        session=session,
        now_epoch_s=now,
    ), True


def _submission_rpc() -> JsonRpcClient:
    return JsonRpcClient(INK_RPC_ENDPOINTS[0], max_retries=0)


def _require_revoke_capabilities(
    proof,
    *,
    session: ExecutionSessionV0,
    now: int,
    include_submit: bool,
) -> None:
    require_effective_capability(
        capability=Capability.AUTHORIZE_APPROVAL,
        source_phase_ceiling=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
        verified_grant=proof,
        session=session,
        now_epoch_s=now,
    )
    if include_submit:
        require_effective_capability(
            capability=Capability.SUBMIT_EXACT_BYTES,
            source_phase_ceiling=AuthorityLevel.HUMAN_SIGNED_EXECUTION,
            verified_grant=proof,
            session=session,
            now_epoch_s=now,
        )


def _live(qntyspot_root: Path):
    router = consume_ink_v0f_router_artifact(
        (qntyspot_root / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json").read_bytes()
    )
    risk = consume_ink_v0f_risk_artifact(
        (qntyspot_root / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json").read_bytes()
    )
    providers = tuple(JsonRpcClient(endpoint) for endpoint in INK_RPC_ENDPOINTS)
    return router, risk, (providers[0], providers[1]), InkV0FLiveVerifier(
        (providers[0], providers[1]), router
    )


def _approval_settlement(
    *,
    signed,
    request,
    live: InkV0FLiveVerifier,
    providers: tuple[JsonRpcClient, JsonRpcClient],
    submission_acknowledged: bool,
):
    observations = observe_ink_v0f_approval_transaction(
        providers,
        signed.transaction_hash,
        observed_at_epoch_s=int(time.time()),
    )
    truth = evaluate_ink_v0f_approval_truth(
        signed,
        observations,
        ROBINHOOD_V0_FINALITY,
        submission_acknowledged=submission_acknowledged,
    )
    market = live.observe_market()
    allowance = live.observe_allowance_for_market(
        market,
        token_address=request.token_address,
    )
    return truth, reconcile_ink_v0f_approval(request, signed, truth, allowance)


def _uint_quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
        raise ChainTruthError(f"{field} is not a canonical RPC quantity")
    body = value[2:]
    if any(ch not in "0123456789abcdef" for ch in body):
        raise ChainTruthError(f"{field} is not lowercase hex")
    if len(body) > 1 and body[0] == "0":
        raise ChainTruthError(f"{field} has leading zeroes")
    return int(body, 16)


def _hash(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 66
        or not value.startswith("0x")
        or any(ch not in "0123456789abcdef" for ch in value[2:])
    ):
        raise ChainTruthError(f"{field} is not a canonical hash")
    return value


def _data_uint(value: Any, *, field: str) -> int:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or len(value) != 66
        or any(ch not in "0123456789abcdef" for ch in value[2:])
    ):
        raise ChainTruthError(f"{field} is not one canonical uint256 word")
    return int(value[2:], 16)


def _topic_address(address: str) -> str:
    return "0x" + ("0" * 24) + address[2:]


def _balances_at_block(
    providers: tuple[JsonRpcClient, JsonRpcClient],
    *,
    block_number: int,
) -> Mapping[str, int]:
    block_tag = hex(block_number)
    balance_call = "0x70a08231" + ("0" * 24) + INK_V0F_TAKER_ADDRESS[2:]
    rows: list[tuple[int, int]] = []
    for provider in providers:
        native = _uint_quantity(
            provider.request("eth_getBalance", [INK_V0F_TAKER_ADDRESS, block_tag]),
            field="eth_getBalance",
        )
        token = _data_uint(
            provider.request(
                "eth_call",
                [{"to": KRAKMASK_ADDRESS, "data": balance_call}, block_tag],
            ),
            field="KRAKMASK balanceOf",
        )
        rows.append((native, token))
    if len(rows) != 2 or rows[0] != rows[1]:
        raise SafeHaltError("Ink providers disagree on taker balances")
    return {
        "block_number": block_number,
        "native_balance_atomic": rows[0][0],
        "krakmask_balance_atomic": rows[0][1],
    }


def _receipt_settlement(
    receipt: Mapping[str, Any],
    envelope: ExecutionEnvelopeV0,
) -> tuple[ReceiptStatus, int | None, int | None, int]:
    status_raw = _uint_quantity(receipt.get("status"), field="receipt.status")
    gas_used = _uint_quantity(receipt.get("gasUsed"), field="receipt.gasUsed")
    effective_gas_price = _uint_quantity(
        receipt.get("effectiveGasPrice"), field="receipt.effectiveGasPrice"
    )
    l1_fee = _uint_quantity(receipt.get("l1Fee"), field="receipt.l1Fee")
    fee = gas_used * effective_gas_price + l1_fee
    if status_raw == 0:
        return ReceiptStatus.REVERTED, None, None, fee
    if status_raw != 1:
        raise ChainTruthError("SELL receipt status is neither success nor revert")

    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise ChainTruthError("successful SELL receipt has no logs")
    swap_data: list[str] = []
    token_transfers: list[str] = []
    weth_transfers: list[str] = []
    for log in logs:
        if not isinstance(log, dict):
            continue
        address = log.get("address")
        topics = log.get("topics")
        data = log.get("data")
        if not isinstance(address, str) or not isinstance(topics, list):
            continue
        address = address.lower()
        lowered = [topic.lower() if isinstance(topic, str) else topic for topic in topics]
        if (
            address == INKYSWAP_V2_POOL
            and len(lowered) == 3
            and lowered[0] == _SWAP_TOPIC
            and lowered[2] == _topic_address(INK_V0F_ROUTER_ADDRESS)
            and isinstance(data, str)
        ):
            swap_data.append(data)
        if (
            address == KRAKMASK_ADDRESS
            and len(lowered) == 3
            and lowered[0] == _TRANSFER_TOPIC
            and lowered[1] == _topic_address(INK_V0F_TAKER_ADDRESS)
            and lowered[2] == _topic_address(INKYSWAP_V2_POOL)
            and isinstance(data, str)
        ):
            token_transfers.append(data)
        if (
            address == WETH9_ADDRESS
            and len(lowered) == 3
            and lowered[0] == _TRANSFER_TOPIC
            and lowered[1] == _topic_address(INKYSWAP_V2_POOL)
            and lowered[2] == _topic_address(INK_V0F_ROUTER_ADDRESS)
            and isinstance(data, str)
        ):
            weth_transfers.append(data)

    if len(swap_data) != 1:
        raise ChainTruthError(
            "receipt does not contain exactly one pinned-pool KRAKMASK -> WETH SELL Swap"
        )
    data = swap_data[0]
    if (
        len(data) != 2 + 64 * 4
        or not data.startswith("0x")
        or any(ch not in "0123456789abcdef" for ch in data[2:])
    ):
        raise ChainTruthError("SELL Swap event data is malformed")
    amount0_in, amount1_in, amount0_out, amount1_out = [
        int(data[2 + i * 64 : 2 + (i + 1) * 64], 16) for i in range(4)
    ]
    if (
        amount0_in != envelope.max_input_atomic
        or amount1_in != 0
        or amount0_out != 0
        or amount1_out <= 0
    ):
        raise ChainTruthError("SELL Swap event differs from frozen KRAKMASK -> WETH direction")
    if amount1_out < envelope.min_output_atomic:
        raise SafeHaltError("settled native output is below frozen SELL minimum")

    if len(token_transfers) != 1 or _data_uint(token_transfers[0], field="KRAKMASK Transfer") != amount0_in:
        raise ChainTruthError("KRAKMASK taker-to-pair Transfer differs from SELL input")
    if len(weth_transfers) != 1 or _data_uint(weth_transfers[0], field="WETH Transfer") != amount1_out:
        raise ChainTruthError("WETH pair-to-router Transfer differs from SELL output")
    return ReceiptStatus.SUCCESS, amount0_in, amount1_out, fee


def _included_observation(
    provider: JsonRpcClient,
    provider_id: str,
    *,
    transaction_hash: str,
    envelope: ExecutionEnvelopeV0,
):
    if provider.chain_id() != INK_CHAIN_ID:
        raise ChainTruthError("SELL observation provider is on the wrong chain")
    receipt = provider.request("eth_getTransactionReceipt", [transaction_hash])
    if receipt is None:
        return None
    if not isinstance(receipt, dict):
        raise ChainTruthError("SELL receipt is not an object")
    if _hash(receipt.get("transactionHash"), field="receipt.transactionHash") != transaction_hash:
        raise ChainTruthError("SELL receipt names another transaction")
    block_number = _uint_quantity(receipt.get("blockNumber"), field="receipt.blockNumber")
    block_tag = hex(block_number)
    block = provider.request("eth_getBlockByNumber", [block_tag, False])
    latest = provider.request("eth_getBlockByNumber", ["latest", False])
    if not isinstance(block, dict) or not isinstance(latest, dict):
        raise ChainTruthError("SELL block observation is incomplete")
    block_hash = _hash(block.get("hash"), field="block.hash")
    if block_hash != _hash(receipt.get("blockHash"), field="receipt.blockHash"):
        raise ChainTruthError("SELL receipt/block hash disagreement")
    parent_hash = _hash(block.get("parentHash"), field="block.parentHash")
    head_number = _uint_quantity(latest.get("number"), field="head.number")
    head_hash = _hash(latest.get("hash"), field="head.hash")
    status, effective_input, effective_output, fee = _receipt_settlement(receipt, envelope)
    evidence = {"receipt": receipt, "inclusion": block, "head": latest}
    observation = ChainObservationV0(
        provider_id=provider_id,
        transaction_hash=transaction_hash,
        observed_at_epoch_s=int(time.time()),
        presence=ChainPresence.INCLUDED,
        raw_evidence_sha256=sha256_hex(canonical_json_bytes(evidence)),
        block_number=block_number,
        block_hash=block_hash,
        block_parent_hash=parent_hash,
        head_block_number=head_number,
        head_block_hash=head_hash,
        receipt_status=status,
        effective_input_atomic=effective_input,
        effective_output_atomic=effective_output,
    )
    return observation, fee


def _approval_mode(
    *,
    state,
    qntyspot_root: Path,
    authority_root: Path,
    approval_signed_path: Path,
) -> int:
    _policy, intent, session, approval, envelope, request = _reconstruct(state)
    ledger = open_ledger(str(Path(state["ledger"])))
    runtime = ExecutionRuntime(ledger)
    approval_bytes = _read_signed_bytes(approval_signed_path)
    signed = validate_ink_v0f_signed_approval(request, approval_bytes)

    existing = ledger.connection.execute(
        """
        SELECT st.submission_attempt_id
          FROM submission_attempts AS st
          JOIN signed_transactions AS sx
            ON sx.signed_transaction_id = st.signed_transaction_id
         WHERE sx.approval_action_id = ?
         LIMIT 1
        """,
        (approval.approval_action_id,),
    ).fetchone()
    if existing is None:
        proof, expired = _authority_proof(
            state,
            authority_root=authority_root,
            session=session,
            now=int(time.time()),
            external_effect_allowed=True,
        )
        if expired:
            raise RuntimeError("expired recovery proof cannot authorize approval transport")
        admitted = runtime.admit_ink_v0f_signed_approval(
            request,
            approval_bytes,
            session,
            proof,
            frozen_at_epoch_s=int(time.time()),
        )
        if admitted.transaction_hash != signed.transaction_hash:
            raise RuntimeError("runtime approval admission differs from exact-byte validation")
        runtime.submit_ink_v0f_signed_approval(
            admitted,
            approval_bytes,
            JsonRpcExactSignedBytesTransport(_submission_rpc()),
            session,
            proof,
            provider_id=PROVIDER_IDS[0],
            submitted_at_epoch_s=int(time.time()),
        )
        transport_status = "TRANSPORT_ATTEMPTED_ONCE"
    else:
        # Any prior DB guard makes every later invocation observation-only.
        row = ledger.connection.execute(
            "SELECT * FROM signed_transactions WHERE approval_action_id = ?",
            (approval.approval_action_id,),
        ).fetchone()
        if (
            row is None
            or row["transaction_hash"] != signed.transaction_hash
            or row["raw_signed_sha256"] != sha256_hex(approval_bytes)
        ):
            raise SafeHaltError("durable approval metadata differs from supplied bytes")
        _authority_proof(
            state,
            authority_root=authority_root,
            session=session,
            now=int(time.time()),
            external_effect_allowed=False,
        )
        transport_status = "OBSERVE_ONLY_PRIOR_GUARD"

    router, risk, providers, live = _live(qntyspot_root)
    durable_guard = ledger.connection.execute(
        """
        SELECT 1
          FROM submission_attempts AS st
          JOIN signed_transactions AS sx
            ON sx.signed_transaction_id = st.signed_transaction_id
         WHERE sx.approval_action_id = ?
         LIMIT 1
        """,
        (approval.approval_action_id,),
    ).fetchone()
    if durable_guard is None:
        raise SafeHaltError(
            "approval observation requires the durable pre-transport guard"
        )
    truth, settlement = _approval_settlement(
        signed=signed,
        request=request,
        live=live,
        providers=providers,
        submission_acknowledged=True,
    )
    result: dict[str, Any] = {
        "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.approval_result.v0",
        "status": settlement.state.value,
        "transport": transport_status,
        "transaction_hash": signed.transaction_hash,
        "chain_truth": truth.verdict.value,
        "confirmation_depth": truth.confirmation_depth,
        "agreeing_provider_count": truth.agreeing_provider_count,
        "observed_allowance_atomic": str(settlement.observed_allowance_atomic),
        "requires_revoke": settlement.requires_revoke,
    }
    if settlement.state is InkV0FApprovalSettlementState.SETTLED:
        fresh = _assert_sell_fresh(
            live=live,
            risk=risk,
            router=router,
            ledger=ledger,
            intent=intent,
            session=session,
            approval=approval,
            envelope=envelope,
            settlement=settlement,
        )
        result["status"] = "SELL_READY_TO_SIGN"
        result["sell_signing_fields"] = _sell_signing_fields(envelope)
        result["ops_freshness_digest"] = sha256_hex(
            canonical_json_bytes(dict(fresh))
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _sell_scope(
    envelope: ExecutionEnvelopeV0,
    session: ExecutionSessionV0,
) -> ExactSignedBytesScopeV0:
    return ExactSignedBytesScopeV0(
        session_id=session.session_id,
        session_identity_digest=session.identity_digest,
        economic_action_id=envelope.economic_action_id,
        authority_policy_digest=session.authority_policy_digest,
        chain_id=envelope.chain_id,
        taker_address=envelope.taker_address,
        target_address=envelope.transaction_to,
        min_value_atomic=0,
        max_value_atomic=0,
        calldata_sha256=envelope.calldata_sha256,
        calldata_length=envelope.calldata_length,
        account_nonce=envelope.account_nonce,
        gas_limit_ceiling=envelope.gas_limit_ceiling,
        max_fee_per_gas_ceiling=envelope.max_fee_per_gas_ceiling_atomic,
        max_priority_fee_per_gas_ceiling=envelope.max_priority_fee_per_gas_ceiling_atomic,
    )


def _sell_signing_fields(envelope: ExecutionEnvelopeV0) -> dict[str, Any]:
    calldata = encode_swap_exact_tokens_for_eth(
        amount_in_atomic=envelope.max_input_atomic,
        amount_out_min_atomic=envelope.min_output_atomic,
        path=(KRAKMASK_ADDRESS, WETH9_ADDRESS),
        recipient=INK_V0F_TAKER_ADDRESS,
        deadline_epoch_s=envelope.deadline_epoch_s,
    )
    if (
        sha256_hex(calldata) != envelope.calldata_sha256
        or len(calldata) != envelope.calldata_length
    ):
        raise SafeHaltError("native SELL calldata cannot be reconstructed from frozen envelope")
    return {
        "accessList": [],
        "chainId": envelope.chain_id,
        "data": "0x" + calldata.hex(),
        "gas": envelope.gas_limit_ceiling,
        "maxFeePerGas": envelope.max_fee_per_gas_ceiling_atomic,
        "maxPriorityFeePerGas": envelope.max_priority_fee_per_gas_ceiling_atomic,
        "nonce": envelope.account_nonce,
        "to": envelope.transaction_to,
        "type": 2,
        "value": 0,
    }


def _assert_sell_fresh(
    *,
    live: InkV0FLiveVerifier,
    risk,
    router,
    ledger,
    intent,
    session: ExecutionSessionV0,
    approval: ApprovalActionV0,
    envelope: ExecutionEnvelopeV0,
    settlement,
) -> Mapping[str, Any]:
    """Extraction-only mirror of the canonical same-amount freshness gates.

    We deliberately do not fabricate InkV0FNativeSellPreviewV0 after process
    restart. The durable native envelope is authoritative for exact bytes; this
    function re-runs the canonical live gates needed before those bytes may be
    signed/submitted.
    """
    if settlement.state is not InkV0FApprovalSettlementState.SETTLED:
        raise SafeHaltError("native SELL requires confirmed settled exact approval")
    if intent.side is not Side.SELL:
        raise SafeHaltError("prepared economic action is not SELL")
    if (
        approval.economic_action_id != envelope.economic_action_id
        or intent.economic_action_id != envelope.economic_action_id
        or settlement.economic_action_id != envelope.economic_action_id
        or settlement.approval_action_id != approval.approval_action_id
    ):
        raise SafeHaltError("approval settlement, intent, and SELL are not the same action")
    if (
        approval.session_identity_digest != session.identity_digest
        or envelope.session_identity_digest != session.identity_digest
        or approval.authority_policy_digest != session.authority_policy_digest
        or envelope.authority_policy_digest != session.authority_policy_digest
        or envelope.taker_address != session.taker_address
    ):
        raise SafeHaltError("approval or SELL scope differs from execution session")
    if (
        approval.token_address != KRAKMASK_ADDRESS
        or approval.spender_address != INK_V0F_ROUTER_ADDRESS
        or approval.requested_allowance_atomic != envelope.max_input_atomic
        or settlement.observed_allowance_atomic != envelope.max_input_atomic
    ):
        raise SafeHaltError("settled approval differs from frozen SELL input")
    now = int(time.time())
    if now >= envelope.deadline_epoch_s:
        raise SafeHaltError("frozen SELL deadline has expired; revoke instead of resizing")

    market = live.observe_market()
    router_observation = live.observe_router_for_market(market)
    allowance = live.observe_allowance_for_market(
        market, token_address=approval.token_address
    )
    signer_state = observe_ink_v0f_signer_state_for_market(live, market)
    if router_observation.router_address != router.address:
        raise SafeHaltError("fresh router identity differs from pinned router")
    if allowance.allowance_atomic != envelope.max_input_atomic:
        raise SafeHaltError("fresh allowance differs from frozen SELL input")
    if signer_state.account_nonce != envelope.account_nonce:
        raise SafeHaltError("fresh taker nonce differs from frozen SELL nonce")
    if signer_state.base_fee_per_gas > envelope.max_fee_per_gas_ceiling_atomic:
        raise SafeHaltError("fresh base fee exceeds frozen SELL fee ceiling")

    quote = InkShadowAdapter._quote(market, intent.side, envelope.max_input_atomic)
    fresh_preview = build_ink_v0f_human_signing_preview(
        policy=risk,
        router=router,
        observation=market,
        quote=quote,
        ledger=ledger,
        intent=intent,
        session=session,
        account_nonce=envelope.account_nonce,
        gas_limit_ceiling=envelope.gas_limit_ceiling,
        max_fee_per_gas_ceiling=envelope.max_fee_per_gas_ceiling_atomic,
        max_priority_fee_per_gas_ceiling=envelope.max_priority_fee_per_gas_ceiling_atomic,
        constructed_at_epoch_s=now,
    )
    if fresh_preview.swap.amount_in_atomic != envelope.max_input_atomic:
        raise SafeHaltError("fresh validation attempted to resize frozen SELL")
    required_min = amount_out_min_atomic(risk, bounds=intent.bounds, quote=quote)
    if envelope.min_output_atomic < required_min:
        raise SafeHaltError("frozen minimum output is now looser than fresh admissible floor")
    if envelope.min_output_atomic > quote.output_atomic:
        raise SafeHaltError("fresh quote cannot satisfy frozen minimum; revoke instead of resizing")
    return {
        "common_block": market.common_block,
        "market_observation_digest": market.digest(),
        "router_observation_digest": router_observation.digest,
        "allowance_observation_digest": allowance.digest,
        "signer_state_digest": signer_state.digest,
        "fresh_quote_output_atomic": str(quote.output_atomic),
        "fresh_required_min_output_atomic": str(required_min),
        "revalidated_at_epoch_s": now,
    }


def _safe_halt(ledger, action_id: str, *, reason: str) -> None:
    state = ledger.intent_state(action_id)
    if state in {IntentState.FILLED, IntentState.REJECTED, IntentState.SAFE_HALT}:
        return
    ledger.transition(
        action_id,
        IntentState.SAFE_HALT,
        now_epoch_s=int(time.time()),
        payload={"execution": "native_sell_operator", "reason": reason},
    )


def _sell_mode(
    *,
    state,
    qntyspot_root: Path,
    authority_root: Path,
    approval_signed_path: Path,
    sell_signed_path: Path,
) -> int:
    _policy, intent, session, approval, envelope, request = _reconstruct(state)
    ledger_path = Path(state["ledger"]).resolve()
    ledger = open_ledger(str(ledger_path))
    runtime = ExecutionRuntime(ledger)

    approval_bytes = _read_signed_bytes(approval_signed_path)
    approval_signed = validate_ink_v0f_signed_approval(request, approval_bytes)
    router, risk, providers, live = _live(qntyspot_root)
    approval_guard = ledger.connection.execute(
        """
        SELECT sx.transaction_hash, sx.raw_signed_sha256
          FROM submission_attempts AS st
          JOIN signed_transactions AS sx
            ON sx.signed_transaction_id = st.signed_transaction_id
         WHERE sx.approval_action_id = ?
         LIMIT 1
        """,
        (approval.approval_action_id,),
    ).fetchone()
    if (
        approval_guard is None
        or approval_guard["transaction_hash"] != approval_signed.transaction_hash
        or approval_guard["raw_signed_sha256"] != sha256_hex(approval_bytes)
    ):
        raise SafeHaltError(
            "SELL requires the matching durable approval pre-transport guard"
        )
    sell_bytes = _read_signed_bytes(sell_signed_path)
    guard_path = _sell_guard_path(ledger_path)
    guard = _read_guard(guard_path) if guard_path.exists() else None
    if guard is None:
        approval_truth, settlement = _approval_settlement(
            signed=approval_signed,
            request=request,
            live=live,
            providers=providers,
            submission_acknowledged=True,
        )
        if (
            approval_truth.verdict.value != "CONFIRMED"
            or settlement.state is not InkV0FApprovalSettlementState.SETTLED
        ):
            raise SafeHaltError(
                "SELL transport requires terminal confirmed exact approval and exact allowance"
            )
        proof, expired = _authority_proof(
            state,
            authority_root=authority_root,
            session=session,
            now=int(time.time()),
            external_effect_allowed=True,
        )
        if expired:
            raise RuntimeError("expired recovery proof cannot authorize SELL transport")
        fresh = _assert_sell_fresh(
            live=live,
            risk=risk,
            router=router,
            ledger=ledger,
            intent=intent,
            session=session,
            approval=approval,
            envelope=envelope,
            settlement=settlement,
        )
        scope = _sell_scope(envelope, session)
        admission = runtime.admit_exact_signed_bytes(
            scope,
            sell_bytes,
            session,
            proof,
            frozen_at_epoch_s=int(time.time()),
        )
        parsed = admission.validated.parsed
        decoded = decode_swap_exact_tokens_for_eth(parsed.calldata)
        if decoded != (
            envelope.max_input_atomic,
            envelope.min_output_atomic,
            (KRAKMASK_ADDRESS, WETH9_ADDRESS),
            INK_V0F_TAKER_ADDRESS,
            envelope.deadline_epoch_s,
        ):
            raise SafeHaltError("signed SELL calldata differs from frozen native route")
        pre_balances = _balances_at_block(
            providers,
            block_number=int(fresh["common_block"]),
        )
        guard_doc = {
            "schema": SELL_GUARD_SCHEMA,
            "economic_action_id": intent.economic_action_id,
            "envelope_id": envelope.envelope_id,
            "signed_transaction_id": admission.record.signed_transaction_id,
            "signed_bytes_sha256": admission.record.signed_bytes_sha256,
            "transaction_hash": admission.record.transaction_hash,
            "pre_balance_block": pre_balances["block_number"],
            "pre_native_balance_atomic": str(pre_balances["native_balance_atomic"]),
            "pre_krakmask_balance_atomic": str(pre_balances["krakmask_balance_atomic"]),
            "freshness_digest": sha256_hex(canonical_json_bytes(dict(fresh))),
            "approval_transaction_hash": approval_signed.transaction_hash,
            "approval_chain_truth_evidence_digest": approval_truth.evidence_digest,
            "approval_allowance_observation_digest": settlement.allowance_observation_digest,
            "approval_observed_allowance_atomic": str(
                settlement.observed_allowance_atomic
            ),
            "created_at_epoch_s": int(time.time()),
        }
        _write_guard(guard_path, guard_doc)
        guard = guard_doc
        attempt = runtime.submit_exact_signed_bytes(
            admission,
            JsonRpcExactSignedBytesTransport(_submission_rpc()),
            session,
            proof,
            provider_id=PROVIDER_IDS[0],
            submitted_at_epoch_s=int(time.time()),
        )
        transport_status = "TRANSPORT_" + attempt.acknowledgment.value
    else:
        digest = sha256_hex(sell_bytes)
        for field, expected in {
            "economic_action_id": intent.economic_action_id,
            "envelope_id": envelope.envelope_id,
            "signed_bytes_sha256": digest,
            "approval_transaction_hash": approval_signed.transaction_hash,
            "approval_observed_allowance_atomic": str(envelope.max_input_atomic),
        }.items():
            if guard.get(field) != expected:
                raise SafeHaltError(f"SELL guard {field} differs; retransmission forbidden")
        row = ledger.connection.execute(
            "SELECT * FROM signed_transactions WHERE external_action_id = ?",
            (intent.economic_action_id,),
        ).fetchone()
        if (
            row is None
            or row["signed_transaction_id"] != guard.get("signed_transaction_id")
            or row["transaction_hash"] != guard.get("transaction_hash")
            or row["raw_signed_sha256"] != digest
            or row["envelope_id"] != envelope.envelope_id
        ):
            raise SafeHaltError("durable SELL signed metadata differs from guard")
        _authority_proof(
            state,
            authority_root=authority_root,
            session=session,
            now=int(time.time()),
            external_effect_allowed=False,
        )
        transport_status = "OBSERVE_ONLY_PRIOR_GUARD"

    assert guard is not None
    tx_hash = str(guard["transaction_hash"])
    signed_id = str(guard["signed_transaction_id"])
    try:
        rows = tuple(
            _included_observation(
                provider,
                provider_id,
                transaction_hash=tx_hash,
                envelope=envelope,
            )
            for provider, provider_id in zip(providers, PROVIDER_IDS, strict=True)
        )
    except Exception:
        _safe_halt(ledger, intent.economic_action_id, reason="provider_observation_error")
        raise

    if any(row is None for row in rows):
        print(
            json.dumps(
                {
                    "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.sell_result.v0",
                    "status": "SELL_PENDING_OBSERVE_ONLY",
                    "transport": transport_status,
                    "transaction_hash": tx_hash,
                    "submission_guard": str(guard_path),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    first = rows[0]
    second = rows[1]
    assert first is not None and second is not None
    observations = (first[0], second[0])
    fees = (first[1], second[1])
    if observations[0].settlement_facts != observations[1].settlement_facts or fees[0] != fees[1]:
        _safe_halt(ledger, intent.economic_action_id, reason="provider_settlement_disagreement")
        raise SafeHaltError("providers disagree on terminal SELL settlement facts")
    fee = fees[0]
    depth = min(
        int(observation.head_block_number) - int(observation.block_number)
        for observation in observations
        if observation.head_block_number is not None and observation.block_number is not None
    )
    if depth < ROBINHOOD_V0_FINALITY.min_confirmation_depth:
        print(
            json.dumps(
                {
                    "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.sell_result.v0",
                    "status": "SELL_INCLUDED_NOT_FINAL",
                    "transport": transport_status,
                    "transaction_hash": tx_hash,
                    "confirmation_depth": depth,
                    "submission_guard": str(guard_path),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0

    inclusion_block = int(observations[0].block_number)
    post = _balances_at_block(providers, block_number=inclusion_block)
    pre_native = int(guard["pre_native_balance_atomic"])
    pre_token = int(guard["pre_krakmask_balance_atomic"])
    if observations[0].receipt_status is ReceiptStatus.SUCCESS:
        expected_token = pre_token - int(observations[0].effective_input_atomic)
        expected_native = pre_native + int(observations[0].effective_output_atomic) - fee
        if post["krakmask_balance_atomic"] != expected_token:
            _safe_halt(ledger, intent.economic_action_id, reason="token_balance_delta_mismatch")
            raise SafeHaltError("confirmed KRAKMASK balance delta differs from SELL receipt")
        if post["native_balance_atomic"] != expected_native:
            _safe_halt(ledger, intent.economic_action_id, reason="native_balance_delta_mismatch")
            raise SafeHaltError("confirmed native balance delta differs from SELL output minus fee")
    elif observations[0].receipt_status is ReceiptStatus.REVERTED:
        if post["krakmask_balance_atomic"] != pre_token:
            _safe_halt(ledger, intent.economic_action_id, reason="revert_changed_token_balance")
            raise SafeHaltError("reverted SELL unexpectedly changed KRAKMASK balance")
        if post["native_balance_atomic"] != pre_native - fee:
            _safe_halt(ledger, intent.economic_action_id, reason="revert_fee_delta_mismatch")
            raise SafeHaltError("reverted SELL native balance differs from gas-only loss")

    for observation in observations:
        proof, expired = _authority_proof(
            state,
            authority_root=authority_root,
            session=session,
            now=int(time.time()),
            external_effect_allowed=False,
        )
        runtime.record_chain_observation(
            observation,
            external_action_id=intent.economic_action_id,
            signed_transaction_id=signed_id,
            session=session,
            verified_grant=proof,
            now_epoch_s=int(time.time()),
            finality=ROBINHOOD_V0_FINALITY,
            expired_recovery=expired,
        )

    receipt_id = (
        "ink-v0f-native-sell-" + tx_hash[2:]
        if observations[0].receipt_status is ReceiptStatus.SUCCESS
        else None
    )
    proof, expired = _authority_proof(
        state,
        authority_root=authority_root,
        session=session,
        now=int(time.time()),
        external_effect_allowed=False,
    )
    truth = runtime.reconcile_external_action(
        intent.economic_action_id,
        session=session,
        verified_grant=proof,
        now_epoch_s=int(time.time()),
        finality=ROBINHOOD_V0_FINALITY,
        receipt_id=receipt_id,
        fee_atomic=fee if receipt_id is not None else 0,
        source="ink-v0f-native-sell-roundtrip-rpc",
        observed_at_epoch_s=max(o.observed_at_epoch_s for o in observations),
        expired_recovery=expired,
    )
    post_market = live.observe_market()
    post_allowance = live.observe_allowance_for_market(
        post_market, token_address=approval.token_address
    )
    if post_allowance.common_block < inclusion_block:
        raise SafeHaltError(
            "post-SELL allowance observation predates terminal inclusion block"
        )
    requires_revoke = post_allowance.allowance_atomic != 0
    if truth.verdict.value == "CONFIRMED" and not requires_revoke:
        runtime.complete_settlement(
            intent.economic_action_id,
            now_epoch_s=int(time.time()),
        )

    print(
        json.dumps(
            {
                "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.sell_result.v0",
                "status": ledger.intent_state(intent.economic_action_id).value,
                "transport": transport_status,
                "transaction_hash": tx_hash,
                "chain_truth": truth.verdict.value,
                "confirmation_depth": truth.confirmation_depth,
                "agreeing_provider_count": truth.agreeing_provider_count,
                "effective_input_atomic": truth.effective_input_atomic,
                "effective_output_atomic": truth.effective_output_atomic,
                "fee_atomic": fee,
                "post_sell_allowance_atomic": str(post_allowance.allowance_atomic),
                "requires_revoke": requires_revoke,
                "submission_guard": str(guard_path),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _expected_revoke_nonce(
    ledger,
    *,
    ledger_path: Path,
    economic_action_id: str,
    envelope: ExecutionEnvelopeV0,
) -> int:
    """Return the only safe nonce for a revoke in the current terminal state.

    Before SELL transport, revoke competes with the frozen SELL at nonce N.
    After a terminal SELL transaction, nonce N is consumed and revoke must use
    N+1. Ambiguous/in-flight SELL truth is never allowed to race a revoke.
    """
    sell_guard_path = _sell_guard_path(ledger_path)
    if not sell_guard_path.exists():
        return envelope.account_nonce

    sell_guard = _read_guard(sell_guard_path)
    signed = ledger.connection.execute(
        "SELECT transaction_hash, account_nonce FROM signed_transactions "
        "WHERE external_action_id = ?",
        (economic_action_id,),
    ).fetchone()
    reconciliation = ledger.connection.execute(
        "SELECT verdict, transaction_hash FROM reconciliations "
        "WHERE external_action_id = ?",
        (economic_action_id,),
    ).fetchone()
    state = ledger.intent_state(economic_action_id)
    if (
        signed is None
        or signed["transaction_hash"] != sell_guard.get("transaction_hash")
        or int(signed["account_nonce"]) != envelope.account_nonce
        or reconciliation is None
    ):
        raise SafeHaltError(
            "SELL guard exists without matching terminal durable chain truth"
        )

    if state is IntentState.REJECTED and reconciliation["verdict"] == "REVERTED":
        if reconciliation["transaction_hash"] != signed["transaction_hash"]:
            raise SafeHaltError("reverted SELL reconciliation hash differs from signed SELL")
        return envelope.account_nonce + 1

    if (
        state in {IntentState.RECONCILED, IntentState.FILLED}
        and reconciliation["verdict"] == "SETTLED"
    ):
        return envelope.account_nonce + 1

    raise SafeHaltError(
        "SELL outcome is not terminal enough for a non-competing revoke"
    )


def _require_settled_approval(
    *,
    ledger,
    approval: ApprovalActionV0,
    request,
    approval_signed_path: Path,
    live: InkV0FLiveVerifier,
    providers: tuple[JsonRpcClient, JsonRpcClient],
):
    approval_bytes = _read_signed_bytes(approval_signed_path)
    signed = validate_ink_v0f_signed_approval(request, approval_bytes)
    guard = ledger.connection.execute(
        """
        SELECT sx.transaction_hash, sx.raw_signed_sha256
          FROM submission_attempts AS st
          JOIN signed_transactions AS sx
            ON sx.signed_transaction_id = st.signed_transaction_id
         WHERE sx.approval_action_id = ?
         LIMIT 1
        """,
        (approval.approval_action_id,),
    ).fetchone()
    if (
        guard is None
        or guard["transaction_hash"] != signed.transaction_hash
        or guard["raw_signed_sha256"] != sha256_hex(approval_bytes)
    ):
        raise SafeHaltError("revoke requires the matching durable approval transport guard")
    truth, settlement = _approval_settlement(
        signed=signed,
        request=request,
        live=live,
        providers=providers,
        submission_acknowledged=True,
    )
    if truth.verdict.value != "CONFIRMED":
        raise SafeHaltError(
            "revoke preparation requires terminal confirmed approval chain truth"
        )
    return signed, truth, settlement


def _revoke_prepare_mode(
    *,
    state,
    qntyspot_root: Path,
    authority_root: Path,
    approval_signed_path: Path,
) -> int:
    _policy, intent, session, approval, envelope, request = _reconstruct(state)
    ledger_path = Path(state["ledger"]).resolve()
    ledger = open_ledger(str(ledger_path))
    router, _risk, providers, live = _live(qntyspot_root)
    _signed, _truth, settlement = _require_settled_approval(
        ledger=ledger,
        approval=approval,
        request=request,
        approval_signed_path=approval_signed_path,
        live=live,
        providers=providers,
    )
    if settlement.observed_allowance_atomic == 0:
        print(json.dumps({
            "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.revoke_prepare_result.v0",
            "status": "ALREADY_ZERO",
        }, sort_keys=True, separators=(",", ":")))
        return 0
    expected_revoke_nonce = _expected_revoke_nonce(
        ledger,
        ledger_path=ledger_path,
        economic_action_id=intent.economic_action_id,
        envelope=envelope,
    )

    # Revoke is a new external effect. Merely preparing it is kept under the
    # same current-grant boundary so signing cannot outlive the authority episode.
    authority_now = int(time.time())
    proof, expired = _authority_proof(
        state,
        authority_root=authority_root,
        session=session,
        now=authority_now,
        external_effect_allowed=True,
    )
    if expired:
        raise RuntimeError("expired recovery proof cannot prepare a new revoke effect")
    _require_revoke_capabilities(
        proof,
        session=session,
        now=authority_now,
        include_submit=False,
    )
    market = live.observe_market()
    signer = observe_ink_v0f_signer_state_for_market(live, market)
    if signer.account_nonce != expected_revoke_nonce:
        raise SafeHaltError(
            "fresh wallet nonce differs from the only terminal-safe revoke nonce"
        )
    allowance = live.observe_allowance_for_market(
        market, token_address=approval.token_address
    )
    if expected_revoke_nonce == envelope.account_nonce:
        if (
            settlement.state is not InkV0FApprovalSettlementState.SETTLED
            or allowance.allowance_atomic != approval.requested_allowance_atomic
        ):
            raise SafeHaltError(
                "pre-SELL revoke requires the exact confirmed approval allowance"
            )
    elif allowance.allowance_atomic <= 0:
        raise SafeHaltError(
            "terminal SELL revoke was requested but no positive allowance remains"
        )

    args = state["approval_request"]
    now = int(time.time())
    revoke = build_ink_v0f_revoke_signing_request(
        approval=approval,
        session=session,
        revoke_nonce=signer.account_nonce,
        gas_limit_ceiling=args["gas_limit_ceiling"],
        max_fee_per_gas_ceiling=args["max_fee_per_gas_ceiling"],
        max_priority_fee_per_gas_ceiling=args["max_priority_fee_per_gas_ceiling"],
        constructed_at_epoch_s=now,
    )
    prepared_path = _revoke_prepared_path(ledger_path)
    if prepared_path.exists():
        existing = _read_revoke_prepared(prepared_path)
        if existing["request_id"] != revoke.request_id:
            raise SafeHaltError("existing revoke preparation differs; do not replace it")
    else:
        _write_private_once(
            prepared_path,
            {
                "schema": REVOKE_PREPARED_SCHEMA,
                "request_id": revoke.request_id,
                "approval_action_id": approval.approval_action_id,
                "economic_action_id": intent.economic_action_id,
                "revoke_nonce": signer.account_nonce,
                "gas_limit_ceiling": args["gas_limit_ceiling"],
                "max_fee_per_gas_ceiling": args["max_fee_per_gas_ceiling"],
                "max_priority_fee_per_gas_ceiling": args[
                    "max_priority_fee_per_gas_ceiling"
                ],
                "constructed_at_epoch_s": now,
            },
        )
    print(json.dumps({
        "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.revoke_signing_request.v0",
        "status": "REVOKE_PREPARED_NOT_SIGNED_NOT_BROADCAST",
        "prepared_state": str(prepared_path),
        "request_id": revoke.request_id,
        "signing_fields": revoke.eip1559_signing_fields(),
        "warning": (
            "Sign exactly these revoke bytes externally. Do not broadcast from the wallet; "
            "the guarded revoke mode must validate and transport them once."
        ),
    }, sort_keys=True, separators=(",", ":")))
    return 0


def _revoke_mode(
    *,
    state,
    qntyspot_root: Path,
    authority_root: Path,
    approval_signed_path: Path,
    revoke_signed_path: Path,
) -> int:
    _policy, _intent, session, approval, envelope, request = _reconstruct(state)
    ledger_path = Path(state["ledger"]).resolve()
    ledger = open_ledger(str(ledger_path))
    router, _risk, providers, live = _live(qntyspot_root)
    _require_settled_approval(
        ledger=ledger,
        approval=approval,
        request=request,
        approval_signed_path=approval_signed_path,
        live=live,
        providers=providers,
    )
    expected_revoke_nonce = _expected_revoke_nonce(
        ledger,
        ledger_path=ledger_path,
        economic_action_id=approval.economic_action_id,
        envelope=envelope,
    )

    prepared_path = _revoke_prepared_path(ledger_path)
    if not prepared_path.is_file():
        raise RuntimeError("revoke must be prepared before signed bytes can be admitted")
    prepared = _read_revoke_prepared(prepared_path)
    revoke = build_ink_v0f_revoke_signing_request(
        approval=approval,
        session=session,
        revoke_nonce=prepared["revoke_nonce"],
        gas_limit_ceiling=prepared["gas_limit_ceiling"],
        max_fee_per_gas_ceiling=prepared["max_fee_per_gas_ceiling"],
        max_priority_fee_per_gas_ceiling=prepared[
            "max_priority_fee_per_gas_ceiling"
        ],
        constructed_at_epoch_s=prepared["constructed_at_epoch_s"],
    )
    if revoke.request_id != prepared["request_id"]:
        raise SafeHaltError("reconstructed revoke differs from durable preparation")
    if revoke.scope.account_nonce != expected_revoke_nonce:
        raise SafeHaltError(
            "durable revoke nonce no longer matches terminal SELL/approval state"
        )

    signed_bytes = _read_signed_bytes(revoke_signed_path)
    signed = validate_ink_v0f_signed_approval(revoke, signed_bytes)
    guard_path = _revoke_guard_path(ledger_path)
    guard = _read_revoke_guard(guard_path) if guard_path.exists() else None
    if guard is None:
        authority_now = int(time.time())
        proof, expired = _authority_proof(
            state,
            authority_root=authority_root,
            session=session,
            now=authority_now,
            external_effect_allowed=True,
        )
        if expired:
            raise RuntimeError("expired recovery proof cannot authorize revoke transport")
        _require_revoke_capabilities(
            proof,
            session=session,
            now=authority_now,
            include_submit=True,
        )
        market = live.observe_market()
        signer = observe_ink_v0f_signer_state_for_market(live, market)
        allowance = live.observe_allowance_for_market(
            market, token_address=approval.token_address
        )
        if signer.account_nonce != revoke.scope.account_nonce:
            raise SafeHaltError("fresh wallet nonce differs from prepared revoke nonce")
        if allowance.allowance_atomic == 0:
            print(json.dumps({
                "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.revoke_result.v0",
                "status": "ALREADY_ZERO",
            }, sort_keys=True, separators=(",", ":")))
            return 0
        if (
            expected_revoke_nonce == envelope.account_nonce
            and allowance.allowance_atomic != approval.requested_allowance_atomic
        ):
            raise SafeHaltError(
                "pre-SELL revoke fresh allowance differs from exact approval"
            )

        guard = {
            "schema": REVOKE_GUARD_SCHEMA,
            "request_id": revoke.request_id,
            "signed_bytes_sha256": signed.signed_bytes_sha256,
            "transaction_hash": signed.transaction_hash,
            "revoke_nonce": revoke.scope.account_nonce,
            "created_at_epoch_s": int(time.time()),
        }
        _write_private_once(guard_path, guard)
        # The durable file guard is the extraction-only transport boundary for
        # REVOKE_TO_ZERO because canonical approval rows intentionally cannot be
        # repurposed to bind a second signed transaction.
        try:
            provider_hash = JsonRpcExactSignedBytesTransport(
                _submission_rpc()
            ).submit_exact_signed_bytes(signed_bytes)
        except Exception:
            provider_hash = None
        if provider_hash is not None and provider_hash != signed.transaction_hash:
            transport_status = "TRANSPORT_UNKNOWN_PROVIDER_HASH_MISMATCH"
        else:
            transport_status = "TRANSPORT_ATTEMPTED_ONCE"
    else:
        if (
            guard.get("request_id") != revoke.request_id
            or guard.get("signed_bytes_sha256") != signed.signed_bytes_sha256
            or guard.get("transaction_hash") != signed.transaction_hash
        ):
            raise SafeHaltError("revoke guard differs from supplied exact signed bytes")
        _authority_proof(
            state,
            authority_root=authority_root,
            session=session,
            now=int(time.time()),
            external_effect_allowed=False,
        )
        transport_status = "OBSERVE_ONLY_PRIOR_GUARD"

    observations = observe_ink_v0f_approval_transaction(
        providers,
        signed.transaction_hash,
        observed_at_epoch_s=int(time.time()),
    )
    truth = evaluate_ink_v0f_approval_truth(
        signed,
        observations,
        ROBINHOOD_V0_FINALITY,
        submission_acknowledged=True,
    )
    market = live.observe_market()
    allowance = live.observe_allowance_for_market(
        market, token_address=approval.token_address
    )
    settlement = reconcile_ink_v0f_approval(revoke, signed, truth, allowance)
    completed_reconciled_sell = False
    if (
        settlement.state is InkV0FApprovalSettlementState.REVOKED
        and ledger.intent_state(approval.economic_action_id) is IntentState.RECONCILED
    ):
        sell_reconciliation = ledger.connection.execute(
            "SELECT verdict FROM reconciliations WHERE external_action_id = ?",
            (approval.economic_action_id,),
        ).fetchone()
        if sell_reconciliation is not None and sell_reconciliation["verdict"] == "SETTLED":
            ExecutionRuntime(ledger).complete_settlement(
                approval.economic_action_id,
                now_epoch_s=int(time.time()),
            )
            completed_reconciled_sell = True
    print(json.dumps({
        "schema": "qntyspot.ops.ink_v0f_native_sell_roundtrip.revoke_result.v0",
        "status": settlement.state.value,
        "transport": transport_status,
        "transaction_hash": signed.transaction_hash,
        "chain_truth": truth.verdict.value,
        "confirmation_depth": truth.confirmation_depth,
        "agreeing_provider_count": truth.agreeing_provider_count,
        "observed_allowance_atomic": str(settlement.observed_allowance_atomic),
        "submission_guard": str(guard_path),
        "completed_reconciled_sell": completed_reconciled_sell,
        "economic_state": ledger.intent_state(approval.economic_action_id).value,
        "note": (
            "Canonical approval lifecycle remains unchanged; zero allowance is proven "
            "externally and must not be faked into the approval row."
        ),
    }, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("approval", "sell", "revoke-prepare", "revoke"))
    parser.add_argument("--qntyspot-root", required=True)
    parser.add_argument("--authority-root", required=True)
    parser.add_argument("--prepared-state", required=True)
    parser.add_argument("--approval-signed-bytes", required=True)
    parser.add_argument("--sell-signed-bytes")
    parser.add_argument("--revoke-signed-bytes")
    args = parser.parse_args()

    qntyspot_root = Path(args.qntyspot_root).resolve()
    authority_root = Path(args.authority_root).resolve()
    prepared_path = Path(args.prepared_state).resolve()
    _assert_bound_qntyspot_root(qntyspot_root)
    state = _prepared_state(prepared_path)
    ledger_path = Path(state["ledger"]).resolve()
    if prepared_path != ledger_path.with_suffix(ledger_path.suffix + ".sell-prepared.json"):
        raise RuntimeError("prepared-state path does not match its ledger")
    if not ledger_path.is_file():
        raise RuntimeError("prepared ledger is missing")

    if args.mode == "approval":
        return _approval_mode(
            state=state,
            qntyspot_root=qntyspot_root,
            authority_root=authority_root,
            approval_signed_path=Path(args.approval_signed_bytes).resolve(),
        )
    if args.mode == "revoke-prepare":
        return _revoke_prepare_mode(
            state=state,
            qntyspot_root=qntyspot_root,
            authority_root=authority_root,
            approval_signed_path=Path(args.approval_signed_bytes).resolve(),
        )
    if args.mode == "revoke":
        if args.revoke_signed_bytes is None:
            raise RuntimeError("revoke mode requires --revoke-signed-bytes")
        return _revoke_mode(
            state=state,
            qntyspot_root=qntyspot_root,
            authority_root=authority_root,
            approval_signed_path=Path(args.approval_signed_bytes).resolve(),
            revoke_signed_path=Path(args.revoke_signed_bytes).resolve(),
        )
    if args.sell_signed_bytes is None:
        raise RuntimeError("sell mode requires --sell-signed-bytes")
    return _sell_mode(
        state=state,
        qntyspot_root=qntyspot_root,
        authority_root=authority_root,
        approval_signed_path=Path(args.approval_signed_bytes).resolve(),
        sell_signed_path=Path(args.sell_signed_bytes).resolve(),
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
