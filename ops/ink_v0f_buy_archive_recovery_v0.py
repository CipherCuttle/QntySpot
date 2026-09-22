#!/usr/bin/env python3
"""Read-only archived-ledger discovery for the original QntySpot Ink first-live BUY.

Never accesses wallet keys, signs, sends RPC requests or changes source archives.
Matching archive members are copied into a PRIVATE, QUARANTINED evidence case;
this tool does not reconstruct missing policy/history or authorize execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import stat
import sys
import tarfile
import time
import uuid
import zipfile
from urllib.parse import quote

EXPECTED_HASH = "0xa02d78dece891ba72dc1c8b4d363be7482e988d5487cb46567b52453db7e2ae7"
EXPECTED_INPUT = "1000000000000000"
EXPECTED_OUTPUT = "4396392944674627615414"
SQLITE_SUFFIXES = (".sqlite3", ".sqlite", ".db")
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2")
UNSUPPORTED = (".tar.zst", ".tzst", ".zst", ".7z", ".rar")
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_ARCHIVES = 1500
MAX_MEMBERS_PER_ARCHIVE = 40000
MAX_CANDIDATES_PER_ARCHIVE = 150
MAX_EXTRACTED_BYTES_PER_ARCHIVE = 2 * 1024 * 1024 * 1024
MAX_VISITED_DIRECTORIES = 60000
CREDENTIAL_PATH_PARTS = {".ssh", ".gnupg", "keystore", "keystores", "wallet", "wallets", "private"}
SKIP_DIR_NAMES = {".git", ".cache", "node_modules", ".venv", "venv", "__pycache__", "site-packages"}


def safe_name(name: str) -> bool:
    parts = PurePosixPath(name).parts
    return bool(parts) and not name.startswith("/") and "\\" not in name and "\x00" not in name and all(
        p not in {".", ".."} for p in parts
    )


def source_fingerprint(path: Path) -> dict:
    st = path.stat()
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "inode": st.st_ino}


def snapshot_member(open_stream, dest: Path) -> dict:
    """Stream at most 512 MiB into a private path; never create source-side files."""
    digest = hashlib.sha256()
    total = 0
    with open_stream() as src, dest.open("xb") as dst:
        os.chmod(dest, 0o600)
        while chunk := src.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_MEMBER_BYTES:
                raise ValueError("archive member exceeds the 512 MiB hard limit")
            digest.update(chunk)
            dst.write(chunk)
    return {"sha256": digest.hexdigest(), "bytes": total}


def inspect_snapshot(db_path: Path) -> dict:
    outcome: dict = {"integrity": None, "foreign_key_violations": None, "buy_matches": []}
    conn = sqlite3.connect("file:" + quote(str(db_path)) + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON")
        outcome["integrity"] = [r[0] for r in conn.execute("PRAGMA integrity_check").fetchall()]
        outcome["foreign_key_violations"] = len(conn.execute("PRAGMA foreign_key_check").fetchall())
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        outcome["qntyspot_schema"] = {"fill_receipts", "intents", "cycles", "policies"}.issubset(tables)
        if outcome["qntyspot_schema"]:
            matches = conn.execute(
                """SELECT f.external_ref, f.input_atomic_filled, f.output_atomic_filled,
                          i.side, i.state, i.policy_id, i.cycle_id, c.status AS cycle_status
                     FROM fill_receipts f
                     JOIN intents i ON i.economic_action_id = f.economic_action_id
                     JOIN cycles c ON c.cycle_id = i.cycle_id
                    WHERE lower(f.external_ref) = ?""",
                (EXPECTED_HASH,),
            ).fetchall()
            outcome["buy_matches"] = [dict(row) for row in matches]
            outcome["state_event_count"] = (
                conn.execute("SELECT COUNT(*) FROM state_events").fetchone()[0]
                if "state_events" in tables else None
            )
            outcome["historical_table_counts"] = {
                t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                for t in ("prepare_records", "execution_sessions", "signed_transactions",
                          "external_actions", "submission_attempts", "approval_actions",
                          "execution_envelopes") if t in tables
            }
            outcome["last_state_event_epoch_s"] = (
                conn.execute("SELECT MAX(occurred_epoch_s) FROM state_events").fetchone()[0]
                if "state_events" in tables else None
            )
    finally:
        conn.close()
    matches = outcome["buy_matches"]
    outcome["matching_expected_buy"] = bool(
        outcome["integrity"] == ["ok"]
        and outcome["foreign_key_violations"] == 0
        and len(matches) == 1
        and matches[0]["side"] == "BUY"
        and matches[0]["state"] == "FILLED"
        and matches[0]["input_atomic_filled"] == EXPECTED_INPUT
        and matches[0]["output_atomic_filled"] == EXPECTED_OUTPUT
        and matches[0]["cycle_status"] in {"OPEN", "COMPLETED"}
    )
    # Receipt row is intentionally small, with no policy JSON or signed bytes.
    return outcome


def _archive_members(archive, is_zip: bool) -> tuple[dict, set]:
    """Index only regular, safe, non-duplicate entries; duplicates fail closed."""
    members: dict = {}
    ambiguous: set = set()
    infos = archive.infolist() if is_zip else archive.getmembers()
    if len(infos) > MAX_MEMBERS_PER_ARCHIVE:
        raise ValueError("too many archive members")
    for m in infos:
        name = m.filename if is_zip else m.name
        if not safe_name(name):
            continue
        if is_zip:
            if m.is_dir() or stat.S_ISLNK(m.external_attr >> 16):
                continue
        elif not m.isfile():
            continue
        if name in members:
            ambiguous.add(name)
            continue
        members[name] = m
    return members, ambiguous


def inspect_archive(path: Path, case: Path, report: dict) -> None:
    before = source_fingerprint(path)
    is_zip = path.name.lower().endswith(".zip")
    archive = zipfile.ZipFile(path) if is_zip else tarfile.open(path, mode="r:*")
    try:
        members, ambiguous = _archive_members(archive, is_zip)
        source_mentions_qntyspot = "qntyspot" in path.name.lower() or "ink-v0f" in path.name.lower()
        sqlite_names = [name for name in sorted(members)
                        if name.lower().endswith(SQLITE_SUFFIXES)
                        and name not in ambiguous
                        and not CREDENTIAL_PATH_PARTS.intersection(
                            part.lower() for part in PurePosixPath(name).parts
                        )
                        and (source_mentions_qntyspot
                             or "qntyspot" in name.lower() or "ink-v0f" in name.lower())]
        if len(sqlite_names) > MAX_CANDIDATES_PER_ARCHIVE:
            raise ValueError("too many SQLite archive candidates")
        extracted_bytes = 0
        for name in sqlite_names:
            item = members[name]
            source_member_size = item.file_size if is_zip else item.size
            if extracted_bytes + source_member_size > MAX_EXTRACTED_BYTES_PER_ARCHIVE:
                report["archive_errors"].append({"archive_path": str(path),
                                                 "error_type": "TotalExtractionBudget"})
                break
            if source_member_size > MAX_MEMBER_BYTES:
                report["candidate_errors"].append({"archive_path": str(path), "member": name,
                                                  "error_type": "MemberSizeLimit"})
                continue
            reported: dict = {"archive_path": str(path), "member": name}
            candidate_dir = case / ("candidate-" + uuid.uuid4().hex[:12])
            candidate_dir.mkdir(mode=0o700)
            db_path = candidate_dir / "candidate.sqlite3"
            try:
                def opener(member):
                    stream = archive.open(member) if is_zip else archive.extractfile(member)
                    if stream is None:
                        raise ValueError("archive member cannot be read")
                    return stream
                main_hash = snapshot_member(lambda: opener(item), db_path)
                extracted_bytes += main_hash["bytes"]
                if extracted_bytes > MAX_EXTRACTED_BYTES_PER_ARCHIVE:
                    raise ValueError("archive extraction budget exceeded")
                reported["snapshot_main"] = main_hash
                with db_path.open("rb") as check:
                    if check.read(16) != b"SQLite format 3\x00":
                        raise ValueError("member has no SQLite header")
                for suffix in ("-wal", "-shm"):
                    sidecar_name = name + suffix
                    if sidecar_name in ambiguous:
                        raise ValueError("duplicate sidecar member")
                    if sidecar_name in members:
                        m = members[sidecar_name]
                        companion_bytes = m.file_size if is_zip else m.size
                        if companion_bytes > MAX_MEMBER_BYTES:
                            raise ValueError("sidecar exceeds the hard size limit")
                        if extracted_bytes + companion_bytes > MAX_EXTRACTED_BYTES_PER_ARCHIVE:
                            raise ValueError("archive extraction budget exceeded")
                        reported[suffix[1:] + "_snapshot"] = snapshot_member(
                            lambda m=m: opener(m), candidate_dir / ("candidate.sqlite3" + suffix),
                        )
                        extracted_bytes += reported[suffix[1:] + "_snapshot"]["bytes"]
                        if extracted_bytes > MAX_EXTRACTED_BYTES_PER_ARCHIVE:
                            raise ValueError("archive extraction budget exceeded")
                    else:
                        reported[suffix[1:] + "_in_archive"] = False
                reported.update(inspect_snapshot(db_path))
                if not reported["buy_matches"] and not (
                    reported["qntyspot_schema"] and ("qntyspot" in name.lower() or "ink-v0f" in name.lower())
                ):
                    shutil.rmtree(candidate_dir)
                    continue
                reported["quarantined_snapshot"] = str(db_path)
                reported["status"] = (
                    "ORIGINAL_BUY_CANDIDATE_REVIEW_REQUIRED"
                    if reported["matching_expected_buy"] else "PARTIAL_OR_CONTRADICTORY_CANDIDATE"
                )
                report["candidates"].append(reported)
            except (OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
                shutil.rmtree(candidate_dir, ignore_errors=True)
                # Avoid printing member content or raw SQLite diagnostics.
                report["candidate_errors"].append({"archive_path": str(path), "member": name,
                                                   "error_type": type(exc).__name__})
        if ambiguous:
            report["ambiguous_archives"].append({"archive_path": str(path), "duplicate_names": len(ambiguous)})
    finally:
        archive.close()
    stable = source_fingerprint(path) == before
    for candidate in report["candidates"]:
        if candidate["archive_path"] == str(path):
            candidate["source_stable"] = stable
    if not stable:
        report["unstable_source_archives"].append(str(path))


def find_archives(roots: list[Path], case: Path, report: dict):
    visited: set[tuple[int, int]] = set()
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            try:
                if current_path == case or case in current_path.parents:
                    dirs[:] = []
                    continue
                st = current_path.stat()
                identity = (st.st_dev, st.st_ino)
                if identity in visited:
                    dirs[:] = []
                    continue
                visited.add(identity)
                if len(visited) > MAX_VISITED_DIRECTORIES:
                    report["scan_limit_hit"] = True
                    report["directories_visited"] = len(visited)
                    return
            except OSError:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES
                       and d.lower() not in CREDENTIAL_PATH_PARTS
                       and not (current_path / d).is_symlink()]
            for name in files:
                lower = name.lower()
                if not lower.endswith(ARCHIVE_SUFFIXES):
                    if lower.endswith(UNSUPPORTED):
                        report["unsupported_archives"].append(str(current_path / name))
                    continue
                path = current_path / name
                if path.is_symlink():
                    continue
                if report["archives_checked"] >= MAX_ARCHIVES:
                    report["scan_limit_hit"] = True
                    report["directories_visited"] = len(visited)
                    return
                report["archives_checked"] += 1
                try:
                    inspect_archive(path, case, report)
                except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
                    report["archive_errors"].append({"archive_path": str(path),
                                                     "error_type": type(exc).__name__})
    report["directories_visited"] = len(visited)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--search-root", action="append", type=Path, default=[])
    p.add_argument("--case-root", type=Path,
                   default=Path.home() / ".local/share/qntyspot/serial9-forensic-cases")
    args = p.parse_args(argv)
    base = args.case_root.expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(base, 0o700)
    case = base / ("archive-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8])
    case.mkdir(mode=0o700)
    roots = [Path.home(), Path("/mnt"), Path("/media"), Path("/tmp"), *args.search_root]
    report: dict = {"schema": "qntyspot.ink_v0f.archived_buy_discovery.v0", "case": str(case),
                    "read_only_source": True, "external_effects_authorized": False,
                    "archives_checked": 0, "scan_limit_hit": False, "candidates": [],
                    "candidate_errors": [], "archive_errors": [], "ambiguous_archives": [],
                    "unsupported_archives": [], "unstable_source_archives": []}
    find_archives([x.expanduser().resolve() for x in roots], case, report)
    matches = [c["quarantined_snapshot"] for c in report["candidates"]
               if c["matching_expected_buy"] and c.get("source_stable") is True]
    report["matched_snapshots"] = matches
    report["verdict"] = ("CANDIDATE_FOUND_REQUIRES_INDEPENDENT_REVIEW" if matches else "SAFE_STOP_NO_MATCH_FOUND")
    output = case / "archive-recovery-report.json"
    with output.open("x", encoding="utf-8") as f:
        os.chmod(output, 0o600)
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({"verdict": report["verdict"], "report": str(output),
                      "archives_checked": report["archives_checked"],
                      "matching_buy_candidates": matches,
                      "unsupported_archives": len(report["unsupported_archives"]),
                      "archive_errors": len(report["archive_errors"]),
                      "scan_limit_hit": report["scan_limit_hit"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
