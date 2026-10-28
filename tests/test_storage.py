from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from wechat_group_audit.engine import calculate
from wechat_group_audit.model import AuditError
from wechat_group_audit.paths import local_path
from wechat_group_audit.readers import read_database, read_json
from wechat_group_audit.reports import write_bundle
from support import PROJECT, database


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wga-storage-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "input/contact.db"
        database(self.db)

    def report(self):
        directory = read_database(self.db, "demo-owner")
        return calculate(directory, ["活动通知群", "日常交流群"])

    def mutate(self, sql):
        con = sqlite3.connect(self.db)
        try:
            con.execute(sql)
            con.commit()
        finally:
            con.close()

    def test_sqlite_classification_matches_json_and_preserves_source(self):
        before = hashlib.sha256(self.db.read_bytes()).digest()
        actual = self.report()
        expected = calculate(read_json(PROJECT / "examples/directory.json"), ["活动通知群", "日常交流群"])
        self.assertEqual(actual["statistics"], expected["statistics"])
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).digest(), before)
        self.assertEqual(list(self.db.parent.iterdir()), [self.db])

    def test_missing_fields_tables_and_orphans_fail(self):
        for sql in ("ALTER TABLE contact DROP COLUMN flag", "DROP TABLE chatroom_member",
                    "INSERT INTO chatroom_member VALUES(100,99999)", "DELETE FROM chat_room WHERE id=100"):
            path = self.root / (hashlib.md5(sql.encode()).hexdigest() + ".db")
            database(path)
            con = sqlite3.connect(path)
            con.execute(sql); con.commit(); con.close()
            with self.assertRaises(AuditError):
                calculate(read_database(path, "demo-owner"), ["活动通知群"])

    def test_sqlite_requires_explicit_valid_owner(self):
        with self.assertRaises(AuditError): read_database(self.db, None)
        with self.assertRaises(AuditError): read_database(self.db, "unknown-account")

    def test_sidecars_are_not_deleted_or_ignored(self):
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.db) + suffix)
            sidecar.write_bytes(b"synthetic-uncheckpointed-state")
            try:
                with self.assertRaises(AuditError): self.report()
                self.assertTrue(sidecar.exists())
            finally:
                sidecar.unlink()

    def test_paths_reject_network_parent_traversal_and_links(self):
        for path in ("//server/share/file.json", "a/../b"):
            with self.assertRaises(AuditError): local_path(path)
        link = self.root / "alias.db"
        try:
            link.symlink_to(self.db)
        except OSError:
            self.skipTest("this runner does not allow creating a synthetic symlink")
        with self.assertRaises(AuditError): read_database(link, "demo-owner")

    def test_export_bundle_readback_and_separate_runs(self):
        report = self.report()
        one = write_bundle(report, self.root / "output")
        two = write_bundle(report, self.root / "output")
        self.assertNotEqual(one, two)
        self.assertEqual(json.loads(Path(one["json"]).read_bytes()), report)
        self.assertTrue(Path(one["text"]).read_bytes().startswith(b"\xef\xbb\xbf"))
        rows = list(csv.reader(io.StringIO(Path(one["csv"]).read_text(encoding="utf-8-sig"))))
        self.assertEqual(len(rows), 3)
        markdown = Path(one["markdown"]).read_text(encoding="utf-8")
        self.assertEqual(sum(line.startswith("| ") and line.split("|")[1].strip().isdigit() for line in markdown.splitlines()), 2)

    def test_markdown_and_spreadsheet_payloads_are_text(self):
        report = self.report()
        row = report["people"][0]
        row["name"] = '=HYPERLINK("https://example.invalid")'
        row["nickname"] = "<script>alert(1)</script>|[link](https://example.invalid)"
        output = write_bundle(report, self.root / "escaped")
        markdown = Path(output["markdown"]).read_text(encoding="utf-8")
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("[link](", markdown)
        csv_rows = list(csv.reader(io.StringIO(Path(output["csv"]).read_text(encoding="utf-8-sig"))))
        self.assertTrue(csv_rows[1][2].startswith("'="))
        self.assertEqual(json.loads(Path(output["json"]).read_bytes())["people"][0]["name"], row["name"])

    def test_failure_cleans_new_files_but_keeps_existing_outputs(self):
        target = self.root / "existing"
        target.mkdir()
        keep = target / "keep.txt"; keep.write_text("keep", encoding="utf-8")
        with patch("wechat_group_audit.reports.MAX_REPORT", 1), self.assertRaises(AuditError):
            write_bundle(self.report(), target)
        self.assertEqual(list(target.iterdir()), [keep])
        with self.assertRaises(AuditError): write_bundle(self.report(), PROJECT / "private-results")

    def test_cli_reports_counts_without_printing_names(self):
        command = [sys.executable, "-m", "wechat_group_audit", "audit", "--input", str(PROJECT / "examples/directory.json"),
                   "--group", "活动通知群", "--group", "日常交流群", "--output", str(self.root / "cli")]
        process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(process.returncode, 0, process.stderr)
        receipt = json.loads(process.stdout)
        self.assertEqual(receipt["statistics"]["selected"], 2)
        self.assertNotIn("咨询助手", process.stdout)
        again = subprocess.run(command + ["--previous", receipt["files"]["json"]], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(json.loads(again.stdout)["changes"], {"added": 0, "removed": 0, "unchanged": 2})

    def test_demo_can_run_without_site_packages_or_crypto(self):
        env = dict(os.environ, PYTHONPATH=str(PROJECT / "src"))
        process = subprocess.run([sys.executable, "-S", "-m", "wechat_group_audit", "rooms", "--input", str(PROJECT / "examples/directory.json")],
                                 env=env, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(len(json.loads(process.stdout)["rooms"]), 2)

    def test_cli_failure_publishes_nothing(self):
        target = self.root / "must-not-exist"
        process = subprocess.run([sys.executable, "-m", "wechat_group_audit", "audit", "--database", str(self.db),
                                  "--me", "demo-owner", "--group", "活动通知群", "--expect", "999", "--output", str(target)],
                                 capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(process.returncode, 2)
        self.assertFalse(target.exists())
