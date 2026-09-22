"""Offline regression tests for archive-only discovery (no keys, RPC or source writes)."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import sqlite3
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

MODULE = Path(__file__).resolve().parent.parent / "ops" / "ink_v0f_buy_archive_recovery_v0.py"
spec = importlib.util.spec_from_file_location("archive_recovery", MODULE)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def sample_db(path: Path, *, hash_: str, output: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript("""
            CREATE TABLE policies(policy_id TEXT PRIMARY KEY, canonical_json TEXT);
            CREATE TABLE cycles(cycle_id TEXT PRIMARY KEY, status TEXT);
            CREATE TABLE intents(economic_action_id TEXT PRIMARY KEY, cycle_id TEXT, policy_id TEXT,
                                 side TEXT, state TEXT);
            CREATE TABLE fill_receipts(external_ref TEXT, economic_action_id TEXT,
                                       input_atomic_filled TEXT, output_atomic_filled TEXT);
            CREATE TABLE state_events(seq INTEGER PRIMARY KEY, occurred_epoch_s INTEGER);
            INSERT INTO policies VALUES ('p1','{}');
            INSERT INTO cycles VALUES ('c1','COMPLETED');
            INSERT INTO intents VALUES ('e1','c1','p1','BUY','FILLED');
            INSERT INTO state_events VALUES (1, 1790025410);
        """)
        conn.execute("INSERT INTO fill_receipts VALUES (?,?,?,?)",
                     (hash_, "e1", recovery.EXPECTED_INPUT, output))
        conn.commit()
    finally:
        conn.close()


class ArchiveRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.scan = self.root / "scan"
        self.scan.mkdir()
        self.case = self.root / "evidence"
        self.case.mkdir()
        self.report = {"archives_checked": 0, "scan_limit_hit": False,
                       "candidates": [], "candidate_errors": [], "archive_errors": [],
                       "ambiguous_archives": [], "unsupported_archives": [],
                       "unstable_source_archives": []}

    def test_zip_exact_buy_retains_private_snapshot_without_source_changes(self):
        db = self.root / "first.sqlite3"
        sample_db(db, hash_=recovery.EXPECTED_HASH, output=recovery.EXPECTED_OUTPUT)
        archive = self.scan / "backup.zip"
        with zipfile.ZipFile(archive, "w") as out:
            out.write(db, "tmp/qntyspot-ink-v0f-ink-v0f-1789941991-900.sqlite3")
        before = hashlib.sha256(archive.read_bytes()).hexdigest()
        recovery.find_archives([self.scan], self.case, self.report)
        self.assertEqual(before, hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(self.report["archives_checked"], 1)
        self.assertEqual(len(self.report["candidates"]), 1)
        candidate = self.report["candidates"][0]
        self.assertTrue(candidate["matching_expected_buy"])
        self.assertEqual(candidate["integrity"], ["ok"])
        self.assertTrue(Path(candidate["quarantined_snapshot"]).is_file())
        self.assertEqual(Path(candidate["quarantined_snapshot"]).stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.report["unstable_source_archives"])

    def test_tar_wrong_fill_does_not_accept_as_original(self):
        db = self.root / "other.sqlite3"
        sample_db(db, hash_=recovery.EXPECTED_HASH, output="1")
        archive = self.scan / "backup.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            out.add(db, "qntyspot/ink-v0f/other.sqlite3")
        recovery.find_archives([self.scan], self.case, self.report)
        self.assertEqual(len(self.report["candidates"]), 1)
        self.assertFalse(self.report["candidates"][0]["matching_expected_buy"])
        self.assertEqual(self.report["candidates"][0]["status"], "PARTIAL_OR_CONTRADICTORY_CANDIDATE")

    def test_zip_traversal_and_symlinks_not_extracted(self):
        db = self.root / "malicious.sqlite3"
        sample_db(db, hash_=recovery.EXPECTED_HASH, output=recovery.EXPECTED_OUTPUT)
        archive = self.scan / "backup.zip"
        with zipfile.ZipFile(archive, "w") as out:
            out.write(db, "../../outside.sqlite3")
            info = zipfile.ZipInfo("symlink.sqlite3")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            out.writestr(info, db.read_bytes())
        recovery.find_archives([self.scan], self.case, self.report)
        self.assertEqual(self.report["candidates"], [])
        self.assertFalse((self.root / "outside.sqlite3").exists())

    def test_unrelated_archive_wallet_file_is_not_opened(self):
        db = self.root / "wallet.db"
        sample_db(db, hash_=recovery.EXPECTED_HASH, output=recovery.EXPECTED_OUTPUT)
        archive = self.scan / "generic_backup.zip"
        with zipfile.ZipFile(archive, "w") as out:
            out.write(db, "wallets/vault.db")
        recovery.find_archives([self.scan], self.case, self.report)
        self.assertEqual(self.report["candidates"], [])
        self.assertEqual(self.report["candidate_errors"], [])

    def test_unstable_archive_is_not_eligible_for_recovery(self):
        db = self.root / "first.sqlite3"
        sample_db(db, hash_=recovery.EXPECTED_HASH, output=recovery.EXPECTED_OUTPUT)
        archive = self.scan / "qntyspot-backup.zip"
        with zipfile.ZipFile(archive, "w") as out:
            out.write(db, "first.sqlite3")
        good = recovery.source_fingerprint(archive)
        changed = dict(good, mtime_ns=good["mtime_ns"] + 1)
        with mock.patch.object(recovery, "source_fingerprint", side_effect=[good, changed]):
            recovery.find_archives([self.scan], self.case, self.report)
        self.assertEqual(len(self.report["candidates"]), 1)
        self.assertFalse(self.report["candidates"][0]["source_stable"])
        self.assertEqual(self.report["unstable_source_archives"], [str(archive)])

    def test_zip_wal_companion_contains_committed_buy(self):
        db = self.root / "wal.sqlite3"
        conn = sqlite3.connect(db)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE policies(policy_id TEXT PRIMARY KEY, canonical_json TEXT);
                CREATE TABLE cycles(cycle_id TEXT PRIMARY KEY, status TEXT);
                CREATE TABLE intents(economic_action_id TEXT PRIMARY KEY, cycle_id TEXT, policy_id TEXT,
                                     side TEXT, state TEXT);
                CREATE TABLE fill_receipts(external_ref TEXT, economic_action_id TEXT,
                                           input_atomic_filled TEXT, output_atomic_filled TEXT);
                INSERT INTO policies VALUES ('p','{}');
                INSERT INTO cycles VALUES ('c','COMPLETED');
                INSERT INTO intents VALUES ('e','c','p','BUY','FILLED');
            """)
            conn.execute("INSERT INTO fill_receipts VALUES(?,?,?,?)",
                         (recovery.EXPECTED_HASH, "e", recovery.EXPECTED_INPUT, recovery.EXPECTED_OUTPUT))
            conn.commit()
            archive = self.scan / "wal.zip"
            with zipfile.ZipFile(archive, "w") as out:
                out.write(db, "data/qntyspot-ink.sqlite3")
                out.write(Path(str(db) + "-wal"), "data/qntyspot-ink.sqlite3-wal")
                out.write(Path(str(db) + "-shm"), "data/qntyspot-ink.sqlite3-shm")
            recovery.find_archives([self.scan], self.case, self.report)
        finally:
            conn.close()
        self.assertEqual(len(self.report["candidates"]), 1)
        self.assertTrue(self.report["candidates"][0]["matching_expected_buy"])
        self.assertIn("wal_snapshot", self.report["candidates"][0])


if __name__ == "__main__":
    unittest.main()
