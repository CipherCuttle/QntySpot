"""Derive the reproducible QntySpot V0 deployment identity.

This is a non-execution build/evidence helper.  It reads only an explicitly
listed source manifest and emits canonical JSON.  The host path, file modes,
timestamps, environment, and Git object ids are not identity inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "qntyspot.deployment_identity.v0"
METHOD = "sha256-canonical-source-manifest-v1"
REPOSITORY_IDENTITY = "CipherCuttle/QntySpot"
CANONICAL_COMMIT = "982a0b38d9226523679c8e59c6abc22ccb5242fd"

# This list is intentionally explicit.  Enumerating a mutable working tree
# would allow an untracked file to become part of an authority identity.
SOURCE_PATHS = (
    "pyproject.toml",
    "qntyspot/__init__.py",
    "qntyspot/authority_root.py",
    "qntyspot/boundary.py",
    "qntyspot/canon.py",
    "qntyspot/domain.py",
    "qntyspot/economics.py",
    "qntyspot/errors.py",
    "qntyspot/execution_contract.py",
    "qntyspot/identity.py",
    "qntyspot/ink.py",
    "qntyspot/keccak.py",
    "qntyspot/ledger/__init__.py",
    "qntyspot/ledger/atomics.py",
    "qntyspot/ledger/execution.py",
    "qntyspot/ledger/execution_replay.py",
    "qntyspot/ledger/execution_schema.py",
    "qntyspot/ledger/recovery.py",
    "qntyspot/ledger/replay.py",
    "qntyspot/ledger/schema.py",
    "qntyspot/ledger/store.py",
    "qntyspot/operations.py",
    "qntyspot/policy.py",
    "qntyspot/raw_evidence.py",
    "qntyspot/redaction.py",
    "qntyspot/robinhood.py",
    "qntyspot/solana.py",
    "qntyspot/states.py",
    "qntyspot/status.py",
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class DeploymentIdentityError(ValueError):
    """The explicit deployment identity inputs are not admissible."""


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize the identity object with the QntySpot canonical JSON rules."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _validate_commit(repository_commit: str) -> None:
    if type(repository_commit) is not str or not _COMMIT_RE.fullmatch(repository_commit):
        raise DeploymentIdentityError("repository_commit must be lowercase 40-character Git commit text")


def _source_manifest(root: Path) -> list[dict[str, str]]:
    expected_package_paths = {path for path in SOURCE_PATHS if path.startswith("qntyspot/")}
    package_root = root / "qntyspot"
    discovered_package_paths = sorted(
        path.relative_to(root).as_posix() for path in package_root.rglob("*.py")
    )
    if set(discovered_package_paths) != expected_package_paths:
        raise DeploymentIdentityError(
            "qntyspot Python file set differs from the explicit canonical source manifest"
        )
    manifest: list[dict[str, str]] = []
    for relative_path in SOURCE_PATHS:
        path = root / relative_path
        if path.is_symlink() or not path.is_file():
            raise DeploymentIdentityError(f"identity input is not a regular file: {relative_path}")
        manifest.append(
            {
                "path": relative_path,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    return manifest


def build_identity(root: str | Path, repository_commit: str) -> dict[str, Any]:
    """Return the identity artifact for the explicit source inputs."""
    _validate_commit(repository_commit)
    root_path = Path(root).resolve()
    inputs: dict[str, Any] = {
        "canonicalization": "canonical_json(sort_keys=true,separators=(',', ':'),ensure_ascii=true)",
        "file_manifest": _source_manifest(root_path),
        "file_selection": "explicit SOURCE_PATHS: pyproject.toml and canonical qntyspot Python package",
        "repository_commit": repository_commit,
        "repository_identity": REPOSITORY_IDENTITY,
    }
    material = {
        "implementation_identity_inputs": inputs,
        "implementation_identity_method": METHOD,
        "schema": SCHEMA,
    }
    digest = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    return {
        **material,
        "implementation_digest": digest,
    }


def _write_once(path: Path, data: bytes) -> None:
    if path.exists():
        if path.read_bytes() != data:
            raise DeploymentIdentityError(f"refusing to overwrite different artifact: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="explicit source checkout root")
    parser.add_argument("--repository-commit", required=True, help="explicit canonical QntySpot commit")
    parser.add_argument("--output", type=Path, required=True, help="write-once canonical JSON artifact")
    args = parser.parse_args()
    artifact = build_identity(args.root, args.repository_commit)
    _write_once(args.output, canonical_json_bytes(artifact))
    print(json.dumps({"implementation_digest": artifact["implementation_digest"], "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
