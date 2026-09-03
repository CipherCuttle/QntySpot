from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from scripts.derive_deployment_identity import (
    CANONICAL_COMMIT,
    SOURCE_PATHS,
    DeploymentIdentityError,
    build_identity,
    canonical_json_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/DEPLOYMENT_IDENTITY_V0.json"


def test_canonical_artifact_reproduces_from_explicit_source_inputs() -> None:
    artifact = json.loads(ARTIFACT.read_bytes())
    assert artifact == build_identity(ROOT, CANONICAL_COMMIT)
    assert artifact["implementation_identity_inputs"]["file_manifest"]
    assert [item["path"] for item in artifact["implementation_identity_inputs"]["file_manifest"]] == list(SOURCE_PATHS)


def test_identity_is_independent_of_host_path_and_timestamps(tmp_path: Path) -> None:
    copied = tmp_path / "different-host-root"
    for relative_path in SOURCE_PATHS:
        destination = copied / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative_path, destination)
    first = build_identity(ROOT, CANONICAL_COMMIT)
    second = build_identity(copied, CANONICAL_COMMIT)
    assert second == first
    for relative_path in SOURCE_PATHS:
        (copied / relative_path).touch()
    assert build_identity(copied, CANONICAL_COMMIT) == first


def test_untracked_runtime_file_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "copy"
    shutil.copytree(ROOT / "qntyspot", copied / "qntyspot")
    shutil.copyfile(ROOT / "pyproject.toml", copied / "pyproject.toml")
    (copied / "qntyspot" / "untracked.py").write_text("UNTRACKED = True\n", encoding="utf-8")
    with pytest.raises(DeploymentIdentityError, match="file set differs"):
        build_identity(copied, CANONICAL_COMMIT)


def test_material_source_change_changes_digest(tmp_path: Path) -> None:
    copied = tmp_path / "copy"
    for relative_path in SOURCE_PATHS:
        destination = copied / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative_path, destination)
    target = copied / "qntyspot/execution_contract.py"
    target.write_bytes(target.read_bytes() + b"\n# identity test mutation\n")
    assert build_identity(copied, CANONICAL_COMMIT)["implementation_digest"] != build_identity(ROOT, CANONICAL_COMMIT)["implementation_digest"]


def test_artifact_bytes_are_canonical_and_sidecar_digestable() -> None:
    raw = ARTIFACT.read_bytes()
    artifact = json.loads(raw)
    assert raw == canonical_json_bytes(artifact)
    artifact_digest = hashlib.sha256(raw).hexdigest()
    assert (ARTIFACT.with_suffix(".sha256")).read_text(encoding="ascii") == (
        f"{artifact_digest}  {ARTIFACT.name}\n"
    )


def test_wrong_commit_shape_is_rejected() -> None:
    with pytest.raises(DeploymentIdentityError, match="40-character"):
        build_identity(ROOT, "not-a-commit")
