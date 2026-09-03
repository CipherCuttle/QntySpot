from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from scripts.derive_deployment_identity import (
    CANONICAL_COMMIT,
    METHOD,
    SOURCE_PATHS,
    DeploymentIdentityError,
    build_identity,
    canonical_json_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts/DEPLOYMENT_IDENTITY_V0R1.json"
HISTORICAL_ARTIFACT = ROOT / "artifacts/DEPLOYMENT_IDENTITY_V0.json"


def test_canonical_artifact_reproduces_from_explicit_source_inputs() -> None:
    artifact = json.loads(ARTIFACT.read_bytes())
    assert artifact == build_identity(ROOT, CANONICAL_COMMIT)
    assert artifact["implementation_digest"] == "2da5b936e8cb657d5204a161c27cc94862a18099db838a1c97e77deccb6b9f9d"
    assert artifact["implementation_identity_method"] == METHOD
    assert artifact["implementation_identity"]["file_manifest"]
    assert [item["path"] for item in artifact["implementation_identity"]["file_manifest"]] == list(SOURCE_PATHS)


def test_v1_historical_artifact_is_preserved() -> None:
    artifact = json.loads(HISTORICAL_ARTIFACT.read_bytes())
    assert artifact["implementation_identity_method"] == "sha256-canonical-source-manifest-v1"
    assert artifact["implementation_digest"] == "a1803ecbb16b91cb66cacd811f997b170b4e8c2cebf43c05830d1d314825f96c"
    assert artifact["implementation_identity_inputs"]["repository_commit"] == "982a0b38d9226523679c8e59c6abc22ccb5242fd"


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


def test_repository_commit_is_provenance_only() -> None:
    first = build_identity(ROOT, "a" * 40)
    second = build_identity(ROOT, "b" * 40)
    assert first["implementation_digest"] == second["implementation_digest"]
    assert first["provenance"]["repository_commit"] != second["provenance"]["repository_commit"]
    assert "repository_commit" not in first["implementation_identity"]


def test_merge_commit_provenance_does_not_change_implementation_digest() -> None:
    pre_merge = build_identity(ROOT, "982a0b38d9226523679c8e59c6abc22ccb5242fd")
    post_merge = build_identity(ROOT, CANONICAL_COMMIT)
    assert pre_merge["implementation_digest"] == post_merge["implementation_digest"]
    assert pre_merge["provenance"] != post_merge["provenance"]


def test_untracked_runtime_file_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "copy"
    shutil.copytree(ROOT / "qntyspot", copied / "qntyspot")
    shutil.copyfile(ROOT / "pyproject.toml", copied / "pyproject.toml")
    (copied / "qntyspot" / "untracked.py").write_text("UNTRACKED = True\n", encoding="utf-8")
    with pytest.raises(DeploymentIdentityError, match="file set differs"):
        build_identity(copied, CANONICAL_COMMIT)


def test_untracked_native_runtime_file_fails_closed(tmp_path: Path) -> None:
    copied = tmp_path / "copy"
    shutil.copytree(ROOT / "qntyspot", copied / "qntyspot")
    shutil.copyfile(ROOT / "pyproject.toml", copied / "pyproject.toml")
    (copied / "qntyspot" / "canon.so").write_bytes(b"untracked native payload")
    with pytest.raises(DeploymentIdentityError, match="runtime file set"):
        build_identity(copied, CANONICAL_COMMIT)


def test_identity_artifact_is_not_a_source_input(tmp_path: Path) -> None:
    copied = tmp_path / "copy"
    for relative_path in SOURCE_PATHS:
        destination = copied / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative_path, destination)
    evidence = copied / "artifacts/DEPLOYMENT_IDENTITY_V0R1.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_bytes(b"provenance evidence can vary")
    assert build_identity(copied, CANONICAL_COMMIT)["implementation_digest"] == build_identity(ROOT, CANONICAL_COMMIT)["implementation_digest"]


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


def test_candidate_digest_is_independently_recomputed_from_artifact_material() -> None:
    artifact = json.loads(ARTIFACT.read_bytes())
    material = {
        "implementation_identity": artifact["implementation_identity"],
        "implementation_identity_method": artifact["implementation_identity_method"],
        "schema": artifact["schema"],
    }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    assert hashlib.sha256(encoded).hexdigest() == artifact["implementation_digest"]


def test_artifact_provenance_digest_is_separate_from_implementation_digest() -> None:
    first = build_identity(ROOT, "a" * 40)
    second = build_identity(ROOT, "b" * 40)
    first_artifact_digest = hashlib.sha256(canonical_json_bytes(first)).hexdigest()
    second_artifact_digest = hashlib.sha256(canonical_json_bytes(second)).hexdigest()
    assert first["implementation_digest"] == second["implementation_digest"]
    assert first_artifact_digest != second_artifact_digest


def test_wrong_commit_shape_is_rejected() -> None:
    with pytest.raises(DeploymentIdentityError, match="40-character"):
        build_identity(ROOT, "not-a-commit")


def test_identity_repair_keeps_source_phase_ceiling_at_shadow() -> None:
    from qntyspot.execution_contract import AuthorityLevel, PHASE_GRANTED_AUTHORITY_LEVEL

    assert PHASE_GRANTED_AUTHORITY_LEVEL is AuthorityLevel.SHADOW
