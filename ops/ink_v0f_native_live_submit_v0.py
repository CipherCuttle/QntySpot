#!/usr/bin/env python3
"""Admit, submit, observe, and reconcile one prepared Ink V0F native-ETH BUY.

This extraction-only operator helper never reads signing keys and never creates
or mutates a transaction. It accepts one complete externally signed EIP-1559
byte string from a mode-restricted file, revalidates the already-frozen native
BUY, durably admits those exact bytes, performs at most one transport call,
then observes the locally-derived transaction hash through both pinned Ink RPC
providers and reconciles only terminal two-provider chain truth.

A durable sidecar is written before the transport call. Once that sidecar
exists, subsequent invocations are observation-only and MUST NOT retransmit.
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
)
from qntyspot.canon import canonical_json_bytes, sha256_hex, strict_json_loads
from qntyspot.economics import build_intent
from qntyspot.errors import ChainTruthError, SafeHaltError
from qntyspot.exact_signed_bytes import JsonRpcExactSignedBytesTransport
from qntyspot.execution_contract import (
    ChainObservationV0,
    ChainPresence,
    ExecutionEnvelopeV0,
    ExecutionSessionV0,
    ReceiptStatus,
    ROBINHOOD_V0_FINALITY,
    SubmissionAcknowledgment,
)
from qntyspot.ink import (
    INK_CHAIN_ID,
    INK_RPC_ENDPOINTS,
    INKYSWAP_V2_POOL,
    KRAKMASK_ADDRESS,
    JsonRpcClient,
)
from qntyspot.ink_v0f_execution import (
    INK_V0F_TAKER_ADDRESS,
    consume_ink_v0f_router_artifact,
)
from qntyspot.ink_v0f_native import (
    revalidate_ink_v0f_native_same_amount,
    validate_ink_v0f_native_signed_buy,
)
from qntyspot.ink_v0f_preauth import InkV0FLiveVerifier
from qntyspot.ink_v0f_risk import consume_ink_v0f_risk_artifact
from qntyspot.keccak import keccak256
from qntyspot.ledger import open_ledger
from qntyspot.ledger.execution import ExecutionRuntime
from qntyspot.policy import parse_policy
from qntyspot.states import IntentState, TERMINAL_STATES

BOUND_REPOSITORY_COMMIT = "b25fa90a7fc0aa3304f17907b354cbab40c11ce3"
BOUND_IMPLEMENTATION_DIGEST = (
    "3412d290f5ff0a3b1ae1915f071a503fccd9c5e386e7d4ef0335c9079c4c0e21"
)
EXPECTED_TRUST_CONFIG_DIGEST = (
    "7da16f3c8df42db7c16eeae80136456518cf563e272f517219659b81c648b8a6"
)
PREPARED_SCHEMA = "qntyspot.ops.ink_v0f_native_first_live.prepared.v0"
SUBMISSION_GUARD_SCHEMA = "qntyspot.ops.ink_v0f_native_first_live.submission_guard.v0"
MIN_REMAINING_AUTHORITY_S = 180
POLL_INTERVAL_S = 2
MAX_OBSERVATION_WINDOW_S = 600
PROVIDER_IDS = ("ink-provider-0", "ink-provider-1")

_SWAP_TOPIC = "0x" + keccak256(
    b"Swap(address,uint256,uint256,uint256,uint256,address)"
).hex()
_TRANSFER_TOPIC = "0x" + keccak256(
    b"Transfer(address,address,uint256)"
).hex()


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


def _uint_quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 3:
        raise RuntimeError(f"{field} is not an RPC quantity")
    body = value[2:]
    if any(char not in "0123456789abcdef" for char in body):
        raise RuntimeError(f"{field} is not lowercase hexadecimal")
    if len(body) > 1 and body[0] == "0":
        raise RuntimeError(f"{field} has leading zeroes")
    return int(body, 16)


def _data_uint(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"{field} is not hex data")
    body = value[2:]
    if not body or len(body) % 2 or any(char not in "0123456789abcdef" for char in body):
        raise RuntimeError(f"{field} is malformed hex data")
    return int(body, 16)


def _hash(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 66
        or not value.startswith("0x")
        or any(char not in "0123456789abcdef" for char in value[2:])
    ):
        raise RuntimeError(f"{field} is not a canonical 32-byte hash")
    return value


def _topic_address(address: str) -> str:
    return "0x" + ("0" * 24) + address[2:]


def _prepared_state(path: Path) -> Mapping[str, Any]:
    if not path.is_file():
        raise RuntimeError("prepared state path is not a file")
    raw = strict_json_loads(path.read_bytes())
    expected = {
        "schema",
        "qntyspot_root",
        "authority_root",
        "receipt",
        "ledger",
        "prepared_at_epoch_s",
        "cycle_id",
        "policy_doc",
        "session",
        "envelope",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise RuntimeError("prepared state has unknown or missing fields")
    if raw["schema"] != PREPARED_SCHEMA:
        raise RuntimeError("prepared state schema differs")
    return raw


def _read_signed_bytes(path: Path) -> bytes:
    if not path.is_file():
        raise RuntimeError("signed-byte file is not a file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("signed-byte file must not permit group/other access")
    try:
        text = path.read_text(encoding="ascii").strip()
    except Exception as exc:
        raise RuntimeError("signed-byte file must contain ASCII hex text") from exc
    if text.startswith("0x"):
        text = text[2:]
    if not text or len(text) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in text):
        raise RuntimeError("signed-byte file does not contain one complete hex byte string")
    return bytes.fromhex(text)


def _guard_path(ledger_path: Path) -> Path:
    return ledger_path.with_suffix(ledger_path.suffix + ".submission.json")


def _write_guard(path: Path, document: Mapping[str, Any]) -> None:
    data = canonical_json_bytes(dict(document))
    path.parent.mkdir(parents=True, exist_ok=True)
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

    # The file fsync is not sufficient to make the new directory entry
    # durable across sudden power loss. The guard must survive any transport
    # attempt, so sync the parent directory before bytes can reach RPC.
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    dir_fd = os.open(path.parent, dir_flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _read_guard(path: Path) -> Mapping[str, Any]:
    raw = strict_json_loads(path.read_bytes())
    if not isinstance(raw, dict) or raw.get("schema") != SUBMISSION_GUARD_SCHEMA:
        raise RuntimeError("submission guard is malformed")
    return raw


def _submission_rpc() -> JsonRpcClient:
    """One write attempt only; the runtime owns ambiguity after any transport error."""
    return JsonRpcClient(INK_RPC_ENDPOINTS[0], max_retries=0)


def _balances_at_block(
    providers: tuple[JsonRpcClient, JsonRpcClient],
    *,
    block_number: int,
) -> Mapping[str, int]:
    block_tag = hex(block_number)
    balance_call = "0x70a08231" + ("0" * 24) + INK_V0F_TAKER_ADDRESS[2:]
    rows = []
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
    if rows[0] != rows[1]:
        raise SafeHaltError("Ink providers disagree on taker balances")
    return {
        "block_number": block_number,
        "native_balance_atomic": rows[0][0],
        "krakmask_balance_atomic": rows[0][1],
    }


def _settlement_from_receipt(
    receipt: Mapping[str, Any],
    envelope: ExecutionEnvelopeV0,
) -> tuple[ReceiptStatus, int | None, int | None, int]:
    status_raw = _uint_quantity(receipt.get("status"), field="receipt status")
    gas_used = _uint_quantity(receipt.get("gasUsed"), field="receipt gasUsed")
    effective_gas_price = _uint_quantity(
        receipt.get("effectiveGasPrice"), field="receipt effectiveGasPrice"
    )
    l1_fee = _uint_quantity(receipt.get("l1Fee"), field="receipt l1Fee")
    fee_atomic = gas_used * effective_gas_price + l1_fee
    if status_raw == 0:
        return ReceiptStatus.REVERTED, None, None, fee_atomic
    if status_raw != 1:
        raise ChainTruthError("receipt status is neither success nor revert")

    logs = receipt.get("logs")
    if not isinstance(logs, list):
        raise ChainTruthError("successful receipt logs are missing")

    swap_logs = []
    transfer_logs = []
    for log in logs:
        if not isinstance(log, dict):
            raise ChainTruthError("receipt log is not an object")
        address = log.get("address")
        topics = log.get("topics")
        data = log.get("data")
        if not isinstance(address, str) or not isinstance(topics, list):
            continue
        address = address.lower()
        lowered_topics = [topic.lower() if isinstance(topic, str) else topic for topic in topics]
        if (
            address == INKYSWAP_V2_POOL
            and len(lowered_topics) == 3
            and lowered_topics[0] == _SWAP_TOPIC
            and lowered_topics[2] == _topic_address(INK_V0F_TAKER_ADDRESS)
        ):
            swap_logs.append((lowered_topics, data))
        if (
            address == KRAKMASK_ADDRESS
            and len(lowered_topics) == 3
            and lowered_topics[0] == _TRANSFER_TOPIC
            and lowered_topics[1] == _topic_address(INKYSWAP_V2_POOL)
            and lowered_topics[2] == _topic_address(INK_V0F_TAKER_ADDRESS)
        ):
            transfer_logs.append(data)

    if len(swap_logs) != 1:
        raise ChainTruthError("receipt does not contain exactly one pinned-pool BUY Swap event")
    data = swap_logs[0][1]
    if (
        not isinstance(data, str)
        or not data.startswith("0x")
        or len(data) != 2 + (64 * 4)
        or any(ch not in "0123456789abcdef" for ch in data[2:])
    ):
        raise ChainTruthError("Swap event data is malformed")
    words = [int(data[2 + i * 64 : 2 + (i + 1) * 64], 16) for i in range(4)]
    amount0_in, amount1_in, amount0_out, amount1_out = words
    if (
        amount0_in != 0
        or amount1_in != envelope.max_input_atomic
        or amount0_out <= 0
        or amount1_out != 0
    ):
        raise ChainTruthError("Swap event differs from frozen WETH -> KRAKMASK BUY")
    if amount0_out < envelope.min_output_atomic:
        raise SafeHaltError("settled KRAKMASK output is below frozen minimum")

    if len(transfer_logs) != 1:
        raise ChainTruthError(
            "receipt does not contain exactly one KRAKMASK pair-to-taker Transfer"
        )
    transfer = transfer_logs[0]
    if (
        not isinstance(transfer, str)
        or not transfer.startswith("0x")
        or len(transfer) != 66
        or any(ch not in "0123456789abcdef" for ch in transfer[2:])
    ):
        raise ChainTruthError("KRAKMASK Transfer amount is malformed")
    if int(transfer[2:], 16) != amount0_out:
        raise ChainTruthError("KRAKMASK Transfer amount disagrees with Swap output")

    return ReceiptStatus.SUCCESS, amount1_in, amount0_out, fee_atomic


def _included_observation(
    provider: JsonRpcClient,
    provider_id: str,
    *,
    transaction_hash: str,
    envelope: ExecutionEnvelopeV0,
) -> tuple[ChainObservationV0, int] | None:
    receipt = provider.request("eth_getTransactionReceipt", [transaction_hash])
    if receipt is None:
        return None
    if not isinstance(receipt, dict):
        raise ChainTruthError("transaction receipt is not an object")
    if _hash(receipt.get("transactionHash"), field="receipt transactionHash") != transaction_hash:
        raise ChainTruthError("receipt transaction hash differs")
    block_number = _uint_quantity(receipt.get("blockNumber"), field="receipt blockNumber")
    block_hash = _hash(receipt.get("blockHash"), field="receipt blockHash")
    inclusion = provider.request("eth_getBlockByHash", [block_hash, False])
    head = provider.request("eth_getBlockByNumber", ["latest", False])
    if not isinstance(inclusion, dict) or not isinstance(head, dict):
        raise ChainTruthError("provider did not return inclusion/head blocks")
    if _hash(inclusion.get("hash"), field="inclusion block hash") != block_hash:
        raise ChainTruthError("inclusion block identity differs from receipt")
    if _uint_quantity(inclusion.get("number"), field="inclusion block number") != block_number:
        raise ChainTruthError("inclusion block number differs from receipt")
    parent_hash = _hash(inclusion.get("parentHash"), field="inclusion parent hash")
    head_number = _uint_quantity(head.get("number"), field="head block number")
    head_hash = _hash(head.get("hash"), field="head block hash")
    status, effective_input, effective_output, fee_atomic = _settlement_from_receipt(
        receipt, envelope
    )
    evidence = {
        "head": {
            "hash": head_hash,
            "number": hex(head_number),
        },
        "inclusion": {
            "hash": block_hash,
            "number": hex(block_number),
            "parentHash": parent_hash,
        },
        "receipt": receipt,
    }
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
    return observation, fee_atomic


def _terminal_observations(
    providers: tuple[JsonRpcClient, JsonRpcClient],
    *,
    transaction_hash: str,
    envelope: ExecutionEnvelopeV0,
    stop_epoch_s: int,
) -> tuple[tuple[ChainObservationV0, ChainObservationV0], int]:
    while int(time.time()) < stop_epoch_s:
        rows = tuple(
            _included_observation(
                provider,
                provider_id,
                transaction_hash=transaction_hash,
                envelope=envelope,
            )
            for provider, provider_id in zip(providers, PROVIDER_IDS, strict=True)
        )
        if all(row is not None for row in rows):
            first = rows[0]
            second = rows[1]
            assert first is not None and second is not None
            observations = (first[0], second[0])
            fees = (first[1], second[1])
            if observations[0].settlement_facts != observations[1].settlement_facts:
                return observations, max(fees)
            if fees[0] != fees[1]:
                raise ChainTruthError("providers disagree on transaction fee facts")
            depth = min(
                observation.head_block_number - observation.block_number
                for observation in observations
                if observation.head_block_number is not None
                and observation.block_number is not None
            )
            if depth >= ROBINHOOD_V0_FINALITY.min_confirmation_depth:
                return observations, fees[0]
        time.sleep(POLL_INTERVAL_S)
    raise SafeHaltError(
        "terminal two-provider chain evidence was not reached in the bounded window; "
        "do not retransmit the signed transaction"
    )


def _reconstruct_prepared(
    state: Mapping[str, Any],
) -> tuple[Any, Any, ExecutionSessionV0, ExecutionEnvelopeV0]:
    policy = parse_policy(state["policy_doc"])
    session = ExecutionSessionV0(**state["session"])
    envelope = ExecutionEnvelopeV0(**state["envelope"])
    intent = build_intent(
        policy,
        state["cycle_id"],
        policy.level("E1"),
        now_epoch_s=state["prepared_at_epoch_s"],
    )
    if policy.policy_id != session.policy_id:
        raise RuntimeError("prepared policy differs from frozen execution session")
    if intent.economic_action_id != envelope.economic_action_id:
        raise RuntimeError("reconstructed intent differs from prepared envelope")
    if (
        envelope.session_id != session.session_id
        or envelope.session_identity_digest != session.identity_digest
        or envelope.authority_policy_digest != session.authority_policy_digest
    ):
        raise RuntimeError("prepared envelope/session binding differs")
    return policy, intent, session, envelope


def _authority_mode(
    *,
    not_after_epoch_s: int,
    now_epoch_s: int,
    require_submission_window: bool,
    allow_expired_recovery: bool,
) -> str:
    remaining = not_after_epoch_s - now_epoch_s
    if remaining > 0:
        if require_submission_window and remaining < MIN_REMAINING_AUTHORITY_S:
            raise SafeHaltError(
                f"grant has only {remaining}s remaining; do not admit or submit signed bytes"
            )
        return "CURRENT"
    if not allow_expired_recovery:
        raise SafeHaltError("authority grant is expired; no new external effect is permitted")
    return "EXPIRED_RECOVERY"


def _verify_grant_for_phase(
    state: Mapping[str, Any],
    *,
    authority_root: Path,
    session: ExecutionSessionV0,
    now_epoch_s: int,
    require_submission_window: bool,
    allow_expired_recovery: bool,
):
    if Path(state["authority_root"]).resolve() != authority_root:
        raise RuntimeError("prepared state names another AuthorityRoot")
    receipt_path = Path(state["receipt"]).resolve()
    try:
        receipt_path.relative_to(authority_root)
    except ValueError as exc:
        raise RuntimeError("prepared receipt is outside the explicit AuthorityRoot") from exc
    receipt = AuthorityGrantReceiptV0.from_bytes(receipt_path.read_bytes())
    if receipt.authority_policy.permitted_repository_commit != BOUND_REPOSITORY_COMMIT:
        raise RuntimeError("receipt does not authorize current QntySpot commit")
    if (
        receipt.authority_policy.permitted_implementation_digest
        != BOUND_IMPLEMENTATION_DIGEST
    ):
        raise RuntimeError("receipt does not authorize current QntySpot implementation")
    mode = _authority_mode(
        not_after_epoch_s=receipt.authority_policy.not_after_epoch_s,
        now_epoch_s=now_epoch_s,
        require_submission_window=require_submission_window,
        allow_expired_recovery=allow_expired_recovery,
    )
    config_path = authority_root / "public/trusted-authority-root-v0.json"
    anchor_path = authority_root / "public/authority-root-ed25519-v0.pub"
    trusted = load_trusted_authority_root(
        config_path.read_bytes(),
        expected_config_digest=EXPECTED_TRUST_CONFIG_DIGEST,
        anchor_bytes=anchor_path.read_bytes(),
    )
    if mode == "CURRENT":
        proof = verify_authority_grant(
            receipt=receipt,
            trusted_root=trusted,
            session=session,
            now_epoch_s=now_epoch_s,
        )
        return receipt, proof, False
    proof = verify_expired_authority_grant_for_recovery(
        receipt=receipt,
        trusted_root=trusted,
        session=session,
        now_epoch_s=now_epoch_s,
    )
    return receipt, proof, True


def _quarantine_unknown_external_outcome(
    ledger,
    economic_action_id: str,
    *,
    cause: BaseException,
    now_epoch_s: int,
) -> None:
    """Durably sink unresolved post-guard outcomes before propagating failure."""
    state = ledger.intent_state(economic_action_id)
    if state in TERMINAL_STATES:
        return
    ledger.transition(
        economic_action_id,
        IntentState.SAFE_HALT,
        now_epoch_s=now_epoch_s,
        payload={
            "execution": "post_submission_truth_unresolved",
            "error_class": cause.__class__.__name__,
        },
    )


def _result(
    *,
    status: str,
    ledger_path: Path,
    action_id: str,
    transaction_hash: str,
    extra: Mapping[str, Any] | None = None,
) -> int:
    document: dict[str, Any] = {
        "schema": "qntyspot.ops.ink_v0f_native_first_live.submit_result.v0",
        "status": status,
        "ledger": str(ledger_path),
        "economic_action_id": action_id,
        "transaction_hash": transaction_hash,
    }
    if extra:
        document.update(extra)
    print(json.dumps(document, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qntyspot-root", required=True)
    parser.add_argument("--authority-root", required=True)
    parser.add_argument("--prepared-state", required=True)
    parser.add_argument("--signed-bytes", required=True)
    args = parser.parse_args()

    now = int(time.time())
    qntyspot_root = Path(args.qntyspot_root).resolve()
    authority_root = Path(args.authority_root).resolve()
    prepared_path = Path(args.prepared_state).resolve()
    signed_path = Path(args.signed_bytes).resolve()
    _assert_bound_qntyspot_root(qntyspot_root)

    state = _prepared_state(prepared_path)
    ledger_path = Path(state["ledger"]).resolve()
    if prepared_path != ledger_path.with_suffix(ledger_path.suffix + ".prepared.json"):
        raise RuntimeError("prepared-state path does not match its ledger")
    if not ledger_path.is_file():
        raise RuntimeError("prepared ledger is missing")

    _policy, intent, session, envelope = _reconstruct_prepared(state)
    guard_path = _guard_path(ledger_path)
    guard = _read_guard(guard_path) if guard_path.exists() else None
    receipt, authority_proof, expired_recovery = _verify_grant_for_phase(
        state,
        authority_root=authority_root,
        session=session,
        now_epoch_s=now,
        require_submission_window=guard is None,
        allow_expired_recovery=guard is not None,
    )
    signed_bytes = _read_signed_bytes(signed_path)

    ledger = open_ledger(str(ledger_path))
    runtime = ExecutionRuntime(ledger)
    durable_envelopes = ledger.connection.execute(
        "SELECT envelope_id FROM execution_envelopes "
        "WHERE economic_action_id = ? AND lifecycle = 'AUTHORIZED'",
        (intent.economic_action_id,),
    ).fetchall()
    if len(durable_envelopes) != 1 or durable_envelopes[0]["envelope_id"] != envelope.envelope_id:
        raise RuntimeError("prepared envelope is not the unique durable AUTHORIZED envelope")

    providers = tuple(JsonRpcClient(endpoint) for endpoint in INK_RPC_ENDPOINTS)
    if len(providers) != 2:
        raise RuntimeError("Ink live path requires exactly two read providers")
    read_providers = (providers[0], providers[1])

    if guard is None:
        router_identity = consume_ink_v0f_router_artifact(
            (qntyspot_root / "artifacts/ink_v0f/INK_V0F_ROUTER_IDENTITY_V0.json").read_bytes()
        )
        risk_policy = consume_ink_v0f_risk_artifact(
            (qntyspot_root / "artifacts/authority_root/INK_V0F_DUST_RISK_POLICY_V0.json").read_bytes()
        )
        live = InkV0FLiveVerifier(read_providers, router_identity)
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
        admitted_at = int(time.time())
        native_validated = validate_ink_v0f_native_signed_buy(
            revalidation,
            envelope,
            signed_bytes,
            admitted_at_epoch_s=admitted_at,
        )
        pre_balances = _balances_at_block(
            read_providers,
            block_number=revalidation.common_block,
        )

        existing_attempt = ledger.connection.execute(
            "SELECT 1 FROM submission_attempts st "
            "JOIN signed_transactions sx "
            "ON sx.signed_transaction_id = st.signed_transaction_id "
            "WHERE sx.external_action_id = ? LIMIT 1",
            (intent.economic_action_id,),
        ).fetchone()
        if existing_attempt is not None:
            raise SafeHaltError(
                "submission metadata exists without a submission guard; do not retransmit"
            )

        admission = runtime.admit_exact_signed_bytes(
            revalidation.preview.scope,
            signed_bytes,
            session,
            authority_proof,
            frozen_at_epoch_s=admitted_at,
        )
        if admission.validated != native_validated:
            raise RuntimeError("generic exact-byte admission differs from native validation")

        guard_doc = {
            "schema": SUBMISSION_GUARD_SCHEMA,
            "economic_action_id": intent.economic_action_id,
            "envelope_id": envelope.envelope_id,
            "signed_transaction_id": admission.record.signed_transaction_id,
            "signed_bytes_sha256": admission.record.signed_bytes_sha256,
            "transaction_hash": admission.record.transaction_hash,
            "pre_balance_block": pre_balances["block_number"],
            "pre_native_balance_atomic": str(pre_balances["native_balance_atomic"]),
            "pre_krakmask_balance_atomic": str(
                pre_balances["krakmask_balance_atomic"]
            ),
            "revalidation_id": revalidation.revalidation_id,
            "created_at_epoch_s": int(time.time()),
        }
        _write_guard(guard_path, guard_doc)
        guard = guard_doc

        submit_rpc = _submission_rpc()
        transport = JsonRpcExactSignedBytesTransport(submit_rpc)
        attempt = runtime.submit_exact_signed_bytes(
            admission,
            transport,
            session,
            authority_proof,
            provider_id=PROVIDER_IDS[0],
            submitted_at_epoch_s=int(time.time()),
        )
        submission_ack = attempt.acknowledgment.value
    else:
        signed_digest = sha256_hex(signed_bytes)
        required_guard = {
            "economic_action_id": intent.economic_action_id,
            "envelope_id": envelope.envelope_id,
            "signed_bytes_sha256": signed_digest,
        }
        for field, expected in required_guard.items():
            if guard.get(field) != expected:
                raise SafeHaltError(f"submission guard {field} differs; do not retransmit")
        row = ledger.connection.execute(
            "SELECT * FROM signed_transactions WHERE external_action_id = ?",
            (intent.economic_action_id,),
        ).fetchone()
        if row is None:
            raise SafeHaltError(
                "submission guard exists without durable signed metadata; observe only"
            )
        if (
            row["signed_transaction_id"] != guard.get("signed_transaction_id")
            or row["transaction_hash"] != guard.get("transaction_hash")
            or row["raw_signed_sha256"] != signed_digest
            or row["envelope_id"] != envelope.envelope_id
        ):
            raise SafeHaltError("durable signed metadata differs from submission guard")
        attempts = ledger.connection.execute(
            "SELECT acknowledgment FROM submission_attempts "
            "WHERE signed_transaction_id = ? ORDER BY submitted_at_epoch_s, attempt_ordinal",
            (row["signed_transaction_id"],),
        ).fetchall()
        submission_ack = (
            "OBSERVE_ONLY_NO_DURABLE_ATTEMPT"
            if not attempts
            else "OBSERVE_ONLY_" + attempts[-1]["acknowledgment"]
        )

    assert guard is not None
    transaction_hash = str(guard["transaction_hash"])
    signed_transaction_id = str(guard["signed_transaction_id"])
    # Once the durable submission guard exists, grant expiry must stop new
    # external effects but must not erase our ability to learn what already
    # happened. Observation may therefore continue beyond the grant window.
    stop_epoch_s = int(time.time()) + MAX_OBSERVATION_WINDOW_S
    try:
        observations, fee_atomic = _terminal_observations(
            read_providers,
            transaction_hash=transaction_hash,
            envelope=envelope,
            stop_epoch_s=stop_epoch_s,
        )
    except Exception as exc:
        _quarantine_unknown_external_outcome(
            ledger,
            intent.economic_action_id,
            cause=exc,
            now_epoch_s=int(time.time()),
        )
        raise

    # For a successful BUY, corroborate receipt logs against actual wallet
    # balance deltas before allowing reconciliation to mint a fill receipt.
    if observations[0].settlement_facts == observations[1].settlement_facts:
        inclusion_block = observations[0].block_number
        assert inclusion_block is not None
        post_balances = _balances_at_block(
            read_providers,
            block_number=inclusion_block,
        )
        pre_native = int(guard["pre_native_balance_atomic"])
        pre_token = int(guard["pre_krakmask_balance_atomic"])
        if observations[0].receipt_status is ReceiptStatus.SUCCESS:
            expected_token = pre_token + int(observations[0].effective_output_atomic)
            expected_native = (
                pre_native
                - int(observations[0].effective_input_atomic)
                - fee_atomic
            )
            if post_balances["krakmask_balance_atomic"] != expected_token:
                exc = SafeHaltError(
                    "confirmed KRAKMASK balance delta differs from receipt settlement"
                )
                _quarantine_unknown_external_outcome(
                    ledger,
                    intent.economic_action_id,
                    cause=exc,
                    now_epoch_s=int(time.time()),
                )
                raise exc
            if post_balances["native_balance_atomic"] != expected_native:
                exc = SafeHaltError(
                    "confirmed native balance delta differs from input plus gas"
                )
                _quarantine_unknown_external_outcome(
                    ledger,
                    intent.economic_action_id,
                    cause=exc,
                    now_epoch_s=int(time.time()),
                )
                raise exc
        elif observations[0].receipt_status is ReceiptStatus.REVERTED:
            if post_balances["krakmask_balance_atomic"] != pre_token:
                exc = SafeHaltError(
                    "reverted transaction unexpectedly changed KRAKMASK balance"
                )
                _quarantine_unknown_external_outcome(
                    ledger,
                    intent.economic_action_id,
                    cause=exc,
                    now_epoch_s=int(time.time()),
                )
                raise exc
            if post_balances["native_balance_atomic"] != pre_native - fee_atomic:
                exc = SafeHaltError(
                    "reverted native balance delta differs from gas-only loss"
                )
                _quarantine_unknown_external_outcome(
                    ledger,
                    intent.economic_action_id,
                    cause=exc,
                    now_epoch_s=int(time.time()),
                )
                raise exc

    try:
        for observation in observations:
            observation_now = int(time.time())
            _receipt, observation_proof, observation_expired_recovery = (
                _verify_grant_for_phase(
                    state,
                    authority_root=authority_root,
                    session=session,
                    now_epoch_s=observation_now,
                    require_submission_window=False,
                    allow_expired_recovery=True,
                )
            )
            runtime.record_chain_observation(
                observation,
                external_action_id=intent.economic_action_id,
                signed_transaction_id=signed_transaction_id,
                session=session,
                verified_grant=observation_proof,
                now_epoch_s=observation_now,
                finality=ROBINHOOD_V0_FINALITY,
                expired_recovery=observation_expired_recovery,
            )

        same_facts = observations[0].settlement_facts == observations[1].settlement_facts
        receipt_id = None
        if same_facts and observations[0].receipt_status is ReceiptStatus.SUCCESS:
            receipt_id = "ink-v0f-" + transaction_hash[2:]

        reconcile_now = int(time.time())
        _receipt, reconcile_proof, reconcile_expired_recovery = _verify_grant_for_phase(
            state,
            authority_root=authority_root,
            session=session,
            now_epoch_s=reconcile_now,
            require_submission_window=False,
            allow_expired_recovery=True,
        )
        truth = runtime.reconcile_external_action(
            intent.economic_action_id,
            session=session,
            verified_grant=reconcile_proof,
            now_epoch_s=reconcile_now,
            finality=ROBINHOOD_V0_FINALITY,
            receipt_id=receipt_id,
            fee_atomic=fee_atomic if receipt_id is not None else 0,
            source="ink-v0f-native-live-rpc",
            observed_at_epoch_s=max(o.observed_at_epoch_s for o in observations),
            expired_recovery=reconcile_expired_recovery,
        )
        if truth.verdict.value == "CONFIRMED":
            runtime.complete_settlement(
                intent.economic_action_id,
                now_epoch_s=int(time.time()),
            )

    except Exception as exc:
        _quarantine_unknown_external_outcome(
            ledger,
            intent.economic_action_id,
            cause=exc,
            now_epoch_s=int(time.time()),
        )
        raise

    return _result(
        status=(
            "FILLED"
            if ledger.intent_state(intent.economic_action_id) is IntentState.FILLED
            else ledger.intent_state(intent.economic_action_id).value
        ),
        ledger_path=ledger_path,
        action_id=intent.economic_action_id,
        transaction_hash=transaction_hash,
        extra={
            "submission_acknowledgment": submission_ack,
            "chain_truth": truth.verdict.value,
            "confirmation_depth": truth.confirmation_depth,
            "agreeing_provider_count": truth.agreeing_provider_count,
            "effective_input_atomic": truth.effective_input_atomic,
            "effective_output_atomic": truth.effective_output_atomic,
            "fee_atomic": fee_atomic,
            "submission_guard": str(guard_path),
        },
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        raise SystemExit(2)
