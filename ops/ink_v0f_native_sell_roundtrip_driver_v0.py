#!/usr/bin/env python3
"""Durable orchestration shell for a future authorized native-SELL episode.

This driver deliberately has NO grant-issuance capability.  Authority issuance
is an external, separately authorized operation.  The driver accepts only an
already-issued receipt, snapshots its exact bytes into a persistent RUN_DIR,
runs read-only preflight, and invokes the resumable prepare helper.

It never reads private keys, signs, broadcasts, approves, sells, revokes, or
increments an AuthorityRoot serial.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "qntyspot.ops.ink_v0f_native_sell_roundtrip.driver.v1"
PHASES = (
    "INIT",
    "PREFLIGHT_COMPLETE",
    "GRANT_COMMITTED",
    "PREPARED",
    "SAFE_STOP",
)


class DriverSafeStop(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _operator_prepare_path() -> Path:
    """Return the reviewed operator helper, not a copy from the frozen runtime."""

    return Path(__file__).resolve().with_name(
        "ink_v0f_native_sell_roundtrip_prepare_v0.py"
    )


def _runtime_env(qntyspot_root: Path) -> dict[str, str]:
    """Force subprocess imports to resolve from the frozen runtime checkout."""

    env = dict(os.environ)
    env["PYTHONPATH"] = str(qntyspot_root)
    return env


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_replace_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _atomic_write_once(path: Path, payload: bytes) -> None:
    """Publish exact bytes atomically without ever replacing a committed file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise
        _fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": SCHEMA, "phase": "INIT"}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise DriverSafeStop("driver state is unreadable") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema") != SCHEMA
        or value.get("phase") not in PHASES
    ):
        raise DriverSafeStop("driver state is malformed")
    return value


def _set_phase(
    state_path: Path,
    state: dict[str, Any],
    phase: str,
    **fields: Any,
) -> dict[str, Any]:
    if phase not in PHASES:
        raise ValueError("unknown driver phase")
    updated = dict(state)
    updated.update(fields)
    updated["schema"] = SCHEMA
    updated["phase"] = phase
    _atomic_replace_json(state_path, updated)
    return updated


def _commit_grant_snapshot(
    run_dir: Path,
    receipt_path: Path,
    state_path: Path,
    state: dict[str, Any],
) -> dict[str, Any]:
    if not receipt_path.is_file():
        raise DriverSafeStop("already-issued authority receipt is missing")
    raw = receipt_path.read_bytes()
    if not raw:
        raise DriverSafeStop("already-issued authority receipt is empty")
    digest = _sha256(raw)
    snapshot = run_dir / "grant.json"

    if snapshot.exists():
        existing = snapshot.read_bytes()
        if existing != raw:
            raise DriverSafeStop(
                "committed grant snapshot differs from supplied receipt"
            )
    else:
        try:
            _atomic_write_once(snapshot, raw)
        except FileExistsError:
            if snapshot.read_bytes() != raw:
                raise DriverSafeStop(
                    "concurrent committed grant snapshot differs"
                )

    recorded_digest = state.get("grant_sha256")
    if recorded_digest is not None and recorded_digest != digest:
        raise DriverSafeStop("driver state grant digest differs")
    return _set_phase(
        state_path,
        state,
        "GRANT_COMMITTED",
        grant_path=str(snapshot),
        grant_sha256=digest,
        receipt_path=str(receipt_path),
    )


def _run_phase(
    *,
    command: list[str],
    log_path: Path,
    label: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one unsigned/non-transport phase and append bounded textual output."""

    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(f"=== {label} rc={result.returncode} ===\n")
        if result.stdout:
            handle.write(result.stdout)
            if not result.stdout.endswith("\n"):
                handle.write("\n")
        if result.stderr:
            handle.write(result.stderr)
            if not result.stderr.endswith("\n"):
                handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--qntyspot-root", required=True)
    parser.add_argument("--authority-root", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--ledger", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    state_path = run_dir / "state.json"
    log_path = run_dir / "driver.log"
    qntyspot_root = Path(args.qntyspot_root).resolve()
    authority_root = Path(args.authority_root).resolve()
    receipt_path = Path(args.receipt).resolve()
    ledger_path = Path(args.ledger).resolve()
    prepare = _operator_prepare_path()
    if not prepare.is_file():
        raise DriverSafeStop("reviewed prepare helper is missing")
    prepare_sha256 = _sha256(prepare.read_bytes())
    runtime_env = _runtime_env(qntyspot_root)

    state = _load_state(state_path)
    fixed = {
        "qntyspot_root": str(qntyspot_root),
        "authority_root": str(authority_root),
        "receipt_path": str(receipt_path),
        "ledger": str(ledger_path),
        "operator_prepare_path": str(prepare),
        "operator_prepare_sha256": prepare_sha256,
    }
    for key, value in fixed.items():
        previous = state.get(key)
        if previous is not None and previous != value:
            raise DriverSafeStop(f"driver state {key} differs from this invocation")
    state = _set_phase(state_path, state, state["phase"], **fixed)

    # Dependency/import/setup and read-only preflight happen before the driver
    # commits any local grant snapshot.  Grant issuance itself is intentionally
    # outside this program.
    preflight = _run_phase(
        command=[
            sys.executable,
            str(prepare),
            "--qntyspot-root",
            str(qntyspot_root),
            "--ledger",
            str(ledger_path),
            "--preflight-only",
        ],
        log_path=log_path,
        label="PREFLIGHT",
        env=runtime_env,
    )
    if preflight.returncode != 0:
        _set_phase(
            state_path,
            state,
            "SAFE_STOP",
            safe_stop_reason="PREFLIGHT_FAILED",
        )
        print("SAFE_STOP: preflight failed; no grant was committed by driver")
        return 2

    state = _set_phase(state_path, state, "PREFLIGHT_COMPLETE")
    state = _commit_grant_snapshot(
        run_dir,
        receipt_path,
        state_path,
        state,
    )

    prepared = _run_phase(
        command=[
            sys.executable,
            str(prepare),
            "--qntyspot-root",
            str(qntyspot_root),
            "--authority-root",
            str(authority_root),
            "--receipt",
            str(receipt_path),
            "--ledger",
            str(ledger_path),
        ],
        log_path=log_path,
        label="PREPARE",
        env=runtime_env,
    )
    if prepared.returncode != 0:
        _set_phase(
            state_path,
            state,
            "SAFE_STOP",
            safe_stop_reason="PREPARE_FAILED",
        )
        print("SAFE_STOP: prepare did not complete; same committed grant remains")
        return 2

    _set_phase(state_path, state, "PREPARED", safe_stop_reason=None)
    print("PREPARED: unsigned prepare complete; no transaction was signed or broadcast")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DriverSafeStop as exc:
        print(f"SAFE_STOP: {exc}", file=sys.stderr)
        raise SystemExit(2)
