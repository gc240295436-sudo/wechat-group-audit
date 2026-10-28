from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from wechat_group_audit.engine import calculate, difference
from wechat_group_audit.model import AuditError, Person, Room, identity
from wechat_group_audit.readers import read_json
from support import sample


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wga-analysis-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "directory.json"
        self.data = sample()

    def directory(self):
        self.path.write_text(json.dumps(self.data), encoding="utf-8")
        return read_json(self.path)

    def report(self, **options):
        return calculate(self.directory(), ["活动通知群", "日常交流群"], **options)

    def test_coverage_deduplicates_and_excludes_nonfriends_and_self(self):
        report = self.report(expected=[4, 3])
        self.assertEqual(report["statistics"], {"friends": 5, "covered": 3, "missing": 2,
            "in_every_group": 1, "in_single_group": 2, "in_multiple_groups": 1,
            "selected": 2, "personal": 1, "enterprise": 1})
        self.assertEqual(report["overlap"][0]["members"], 2)
        self.assertEqual(report["overlap"][0]["friends"], 1)
        self.assertEqual([r["coverage"] for r in report["groups"]], [40.0, 40.0])

    def test_every_selection_mode_and_enterprise_filter(self):
        for mode, expected in (("missing", 2), ("any", 3), ("all", 1), ("single", 2), ("repeated", 1), ("roster", 5)):
            with self.subTest(mode=mode):
                self.assertEqual(self.report(mode=mode)["statistics"]["selected"], expected)
        self.assertEqual(self.report(kind="enterprise")["statistics"]["selected"], 1)
        self.assertEqual(self.report(kind="personal")["statistics"]["selected"], 1)

    def test_search_remark_alias_and_stable_key(self):
        self.data["contacts"][4]["alias"] = "demo-dan-alias"
        report = self.report(query="dan-alias")
        self.assertEqual(report["statistics"]["selected"], 1)
        self.assertNotIn("demo-dan-alias", json.dumps(report))
        key = report["people"][0]["key"]
        self.assertEqual(self.report(query=key)["statistics"]["selected"], 1)
        self.assertEqual(self.report(query="林同学", mode="any")["statistics"]["selected"], 1)

    def test_silent_member_is_covered_without_any_message_data(self):
        self.data["groups"][0]["members"].append("demo-dan")
        self.data["groups"][0]["member_count"] += 1
        self.assertEqual(self.report()["statistics"]["missing"], 1)

    def test_same_names_and_blank_names_remain_distinct(self):
        self.data["contacts"][3]["remark"] = "林同学"
        self.data["contacts"][4]["nickname"] = "\u00a0"
        rows = self.report(mode="roster")["people"]
        same = [r for r in rows if r["name"] == "林同学"]
        self.assertEqual(len(same), 2)
        self.assertEqual(len({r["key"] for r in same}), 2)
        self.assertTrue(all(r["ambiguous_name"] for r in same))
        self.assertTrue(any(r["name"] == "（空白昵称）" and r["ambiguous_name"] for r in rows))

    def test_identifiers_opt_in_only(self):
        self.assertNotIn("username", json.dumps(self.report()))
        self.assertIn("demo-dan", json.dumps(self.report(identifiers=True)))

    def test_group_duplicates_and_ambiguity_require_exact_id(self):
        self.data["groups"][1]["name"] = "活动通知群"
        directory = self.directory()
        with self.assertRaisesRegex(AuditError, "同名"):
            calculate(directory, ["活动通知群"])
        ids = [r.key for r in directory.rooms]
        self.assertEqual(calculate(directory, ids)["statistics"]["selected"], 2)
        with self.assertRaisesRegex(AuditError, "重复选择"):
            calculate(directory, [ids[0], ids[0]])

    def test_bad_membership_never_becomes_a_missing_list(self):
        for variant in ("orphan", "duplicate", "empty", "incomplete", "wrong-size"):
            with self.subTest(variant=variant):
                self.data = sample()
                room = self.data["groups"][0]
                if variant == "orphan": room["members"][0] = "unknown-person"
                if variant == "duplicate": room["members"].append(room["members"][0])
                if variant == "empty": room["members"] = []
                if variant == "incomplete": room["complete"] = False
                if variant == "wrong-size": room["member_count"] += 1
                with self.assertRaises(AuditError): self.report()

    def test_expectation_alignment_and_no_fuzzy_group_selection(self):
        for expected in ([3, 4], [4], [0, 3]):
            with self.assertRaises(AuditError): self.report(expected=expected)
        with self.assertRaises(AuditError): calculate(self.directory(), ["活动"])
        with self.assertRaises(AuditError): calculate(self.directory(), [""])

    def test_history_uses_identity_not_names_or_group_order(self):
        old = self.report()
        self.data["groups"][0]["members"].append("demo-dan")
        self.data["groups"][0]["member_count"] += 1
        self.data["contacts"][5]["nickname"] = "新的显示名"
        self.data["contacts"].append({"id": "demo-new", "nickname": "新增演示好友", "kind": "personal"})
        current = calculate(self.directory(), ["日常交流群", "活动通知群"])
        changes = difference(current, old)
        self.assertEqual(len(changes["added"]), 1)
        self.assertEqual(len(changes["removed"]), 1)
        self.assertEqual(changes["unchanged"], 1)

    def test_cross_account_or_changed_scope_is_not_compared(self):
        current = self.report()
        for field, value in (("account", "another"), ("mode", "any"), ("groups", [])):
            previous = copy.deepcopy(current)
            previous["scope"][field] = value
            with self.assertRaises(AuditError): difference(current, previous)
        previous = copy.deepcopy(current)
        previous["people"].append(previous["people"][0])
        with self.assertRaises(AuditError): difference(current, previous)

    def test_input_identity_validation_and_owner_alias(self):
        self.data["contacts"][0]["alias"] = "demo-my-alias"
        self.path.write_text(json.dumps(self.data), encoding="utf-8")
        self.assertEqual(read_json(self.path, "demo-my-alias").owner, "demo-owner")
        with self.assertRaises(AuditError): read_json(self.path, "demo-amy")
        self.data["contacts"].append(self.data["contacts"][0])
        with self.assertRaises(AuditError): self.directory()

    def test_unknown_report_format_and_invalid_json_fail_cleanly(self):
        with self.assertRaises(AuditError): difference(self.report(), {"schema": "other"})
        self.path.write_text("{", encoding="utf-8")
        with self.assertRaises(AuditError): read_json(self.path)
