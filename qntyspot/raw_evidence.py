"""Bounded, immutable raw HTTP evidence for public-read qualification.

The transport clients call this store immediately after receiving a response
and before interpreting its JSON.  Response bytes are content-addressed by
their SHA-256 digest.  The manifest contains only replay metadata: endpoint,
method, request target, and (for JSON-RPC) the public request body.  Request
headers are intentionally not part of this interface.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canon import canonical_json_bytes, digest_object, strict_json_loads
from .errors import SafeHaltError, SolanaError

__all__ = ["RawEvidenceRecord", "RawEvidenceStore"]

_HASH_RE = r"^[0-9a-f]{64}$"


def _safe_evidence_relative_path(value: object, *, directory: str, suffix: str) -> Path:
    if not isinstance(value, str):
        raise SafeHaltError("raw evidence path is malformed")
    path = Path(value)
    if path.is_absolute() or path.parts[:1] != (directory,) or len(path.parts) != 2:
        raise SafeHaltError("raw evidence path escapes its content-addressed directory")
    if ".." in path.parts or not path.name.endswith(suffix):
        raise SafeHaltError("raw evidence path is not content-addressed")
    return path


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_immutable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except FileExistsError:
        if path.read_bytes() != payload:
            raise SafeHaltError(f"immutable evidence path already contains different data: {path}")


def _validate_endpoint(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise SolanaError(f"{field} is malformed")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
        raise SolanaError(f"{field} must be an HTTPS URL without credentials")
    return value


@dataclass(frozen=True)
class RawEvidenceRecord:
    schema: str
    response_sha256: str
    response_bytes: int
    response_path: str
    request_sha256: str
    request: dict[str, Any]
    manifest_path: str

    def canonical_object(self) -> dict[str, Any]:
        return {
            "manifest_path": self.manifest_path,
            "request": dict(self.request),
            "request_sha256": self.request_sha256,
            "response_bytes": self.response_bytes,
            "response_path": self.response_path,
            "response_sha256": self.response_sha256,
            "schema": self.schema,
        }

    def digest(self) -> str:
        return digest_object(self.canonical_object())


class RawEvidenceStore:
    """A finite content-addressed store for raw public-read responses."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_response_bytes: int = 2_000_000,
        max_total_bytes: int = 12_000_000,
        max_records: int = 16,
    ) -> None:
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes < 256:
            raise SolanaError("max_response_bytes must be at least 256")
        if isinstance(max_total_bytes, bool) or not isinstance(max_total_bytes, int) or max_total_bytes < max_response_bytes:
            raise SolanaError("max_total_bytes must be at least max_response_bytes")
        if isinstance(max_records, bool) or not isinstance(max_records, int) or not 1 <= max_records <= 1024:
            raise SolanaError("max_records must be in [1, 1024]")
        self.root = Path(root)
        self.max_response_bytes = max_response_bytes
        self.max_total_bytes = max_total_bytes
        self.max_records = max_records

    def capture(
        self,
        *,
        endpoint: str,
        method: str,
        request_target: str,
        request_body: bytes | None,
        response_body: bytes,
    ) -> RawEvidenceRecord:
        endpoint = _validate_endpoint(endpoint, field="endpoint")
        if method not in {"GET", "POST"}:
            raise SolanaError("evidence request method must be GET or POST")
        if not isinstance(request_target, str) or not request_target or len(request_target) > 4096:
            raise SolanaError("evidence request target is malformed")
        if request_body is not None and not isinstance(request_body, bytes):
            raise SolanaError("evidence request body must be bytes or None")
        if request_body is not None and len(request_body) > self.max_response_bytes:
            raise SolanaError("evidence request body exceeds the configured bound")
        if not isinstance(response_body, bytes):
            raise SolanaError("evidence response body must be bytes")
        if len(response_body) > self.max_response_bytes:
            raise SolanaError("evidence response body exceeds the configured bound")

        request = {
            "body_base64": None
            if request_body is None
            else base64.b64encode(request_body).decode("ascii"),
            "body_bytes": 0 if request_body is None else len(request_body),
            "body_sha256": None if request_body is None else _sha256_hex(request_body),
            "endpoint": endpoint,
            "method": method,
            "target": request_target,
        }
        request_sha256 = digest_object(request)
        response_sha256 = _sha256_hex(response_body)
        response_path = Path("responses") / f"{response_sha256}.bin"
        manifest_path = Path("manifests") / f"{response_sha256}-{request_sha256}.json"
        response_target = self.root / response_path
        manifest_target = self.root / manifest_path

        response_exists = response_target.exists()
        manifest_exists = manifest_target.exists()
        if not response_exists:
            response_files = list((self.root / "responses").glob("*.bin")) if (self.root / "responses").exists() else []
            total_bytes = sum(path.stat().st_size for path in response_files)
            if len(response_files) >= self.max_records:
                raise SolanaError("raw evidence record count exceeds the configured bound")
            if total_bytes + len(response_body) > self.max_total_bytes:
                raise SolanaError("raw evidence total size exceeds the configured bound")
        if not manifest_exists:
            manifest_files = list((self.root / "manifests").glob("*.json")) if (self.root / "manifests").exists() else []
            if len(manifest_files) >= self.max_records:
                raise SolanaError("raw evidence manifest count exceeds the configured bound")

        record = RawEvidenceRecord(
            schema="RAW_HTTP_EVIDENCE_V0",
            response_sha256=response_sha256,
            response_bytes=len(response_body),
            response_path=response_path.as_posix(),
            request_sha256=request_sha256,
            request=request,
            manifest_path=manifest_path.as_posix(),
        )
        if not response_exists:
            _write_immutable(response_target, response_body)
        elif response_target.read_bytes() != response_body:
            raise SafeHaltError(f"raw response bytes changed for content address: {response_target}")
        _write_immutable(manifest_target, canonical_json_bytes(record.canonical_object()))
        return record

    def read(self, record: RawEvidenceRecord) -> bytes:
        if not isinstance(record, RawEvidenceRecord):
            raise SolanaError("raw evidence record is malformed")
        if (
            not isinstance(record.response_sha256, str)
            or re.fullmatch(_HASH_RE, record.response_sha256) is None
            or not isinstance(record.request_sha256, str)
            or re.fullmatch(_HASH_RE, record.request_sha256) is None
            or isinstance(record.response_bytes, bool)
            or not isinstance(record.response_bytes, int)
            or record.response_bytes < 0
            or not isinstance(record.request, dict)
        ):
            raise SafeHaltError("raw evidence record fields are malformed")
        response_path = _safe_evidence_relative_path(
            record.response_path, directory="responses", suffix=".bin"
        )
        manifest_path = _safe_evidence_relative_path(
            record.manifest_path, directory="manifests", suffix=".json"
        )
        path = self.root / response_path
        manifest = self.root / manifest_path
        try:
            body = path.read_bytes()
        except OSError as exc:
            raise SafeHaltError(f"raw response evidence is unavailable: {path}") from exc
        if len(body) != record.response_bytes or _sha256_hex(body) != record.response_sha256:
            raise SafeHaltError(f"raw response evidence digest mismatch: {path}")
        try:
            manifest_object = strict_json_loads(manifest.read_bytes())
        except OSError as exc:
            raise SafeHaltError(f"raw evidence manifest is unavailable: {manifest}") from exc
        except Exception as exc:
            raise SafeHaltError(f"raw evidence manifest is malformed: {manifest}") from exc
        if manifest_object != record.canonical_object():
            raise SafeHaltError(f"raw evidence manifest does not match the response record: {manifest}")
        return body

    def persist_index(self, path: str | Path, records: list[RawEvidenceRecord]) -> str:
        if not isinstance(records, list) or len(records) > self.max_records:
            raise SolanaError("raw evidence index exceeds the configured record bound")
        unique: dict[str, RawEvidenceRecord] = {}
        for record in records:
            if not isinstance(record, RawEvidenceRecord):
                raise SolanaError("raw evidence index contains a malformed record")
            self.read(record)
            if record.digest() in unique:
                raise SolanaError("raw evidence index contains a duplicate record")
            unique[record.digest()] = record
        payload_object = {
            "records": [record.canonical_object() for _, record in sorted(unique.items())],
            "schema": "RAW_EVIDENCE_INDEX_V0",
        }
        payload = canonical_json_bytes(payload_object)
        target = Path(path)
        _write_immutable(target, payload)
        return _sha256_hex(payload)

    @staticmethod
    def load_index(path: str | Path) -> list[RawEvidenceRecord]:
        try:
            raw = strict_json_loads(Path(path).read_bytes())
        except Exception as exc:
            raise SolanaError("raw evidence index is not strict JSON") from exc
        if not isinstance(raw, dict) or set(raw) != {"records", "schema"} or raw["schema"] != "RAW_EVIDENCE_INDEX_V0":
            raise SolanaError("raw evidence index is malformed")
        records = raw["records"]
        if not isinstance(records, list):
            raise SolanaError("raw evidence index records are malformed")
        loaded: list[RawEvidenceRecord] = []
        for item in records:
            if not isinstance(item, dict) or set(item) != {
                "manifest_path", "request", "request_sha256", "response_bytes", "response_path",
                "response_sha256", "schema",
            }:
                raise SolanaError("raw evidence index record is malformed")
            if item["schema"] != "RAW_HTTP_EVIDENCE_V0" or not isinstance(item["request"], dict):
                raise SolanaError("raw evidence index record schema is malformed")
            loaded.append(
                RawEvidenceRecord(
                    schema=item["schema"],
                    response_sha256=item["response_sha256"],
                    response_bytes=item["response_bytes"],
                    response_path=item["response_path"],
                    request_sha256=item["request_sha256"],
                    request=item["request"],
                    manifest_path=item["manifest_path"],
                )
            )
        return loaded
