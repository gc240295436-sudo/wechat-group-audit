from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from wechat_group_audit import windows
from wechat_group_audit.model import AuditError
from support import KEY, database, encrypt


class WindowsBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wga-native-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_budget_failure_happens_before_native_read(self):
        memory = windows.ProcessMemory.__new__(windows.ProcessMemory)
        memory.handle = 123
        memory.api = MagicMock()
        memory.limit, memory.read_bytes = 4, 0
        memory.deadline = time.monotonic() + 10
        with self.assertRaises(AuditError): memory.read(0x10000, 5)
        memory.deadline = time.monotonic() - 1
        with self.assertRaises(AuditError): memory.read(0x10000, 1)
        memory.api.ReadProcessMemory.assert_not_called()
        memory.close(); memory.close()
        memory.api.CloseHandle.assert_called_once_with(123)

    def test_wrong_account_and_non_weixin_pid_stop_before_memory_access(self):
        source = windows.Source(self.root / "wxid_demo_abcd/db_storage", "demo-source")
        with patch.object(windows, "discover", return_value=[source]), patch.object(windows, "ProcessMemory") as memory:
            with self.assertRaises(AuditError): windows.read_live("demo-source", None, "wxid_wrong", 123)
            memory.assert_not_called()
        path = self.root / "db_storage/contact/contact.db"
        path.parent.mkdir(parents=True); path.write_bytes(b"x" * 4096)
        source = windows.Source(path.parent.parent, "demo-source")
        with patch.object(windows, "discover", return_value=[source]), patch.object(windows, "weixin_pids", return_value={123}), patch.object(windows, "ProcessMemory") as memory:
            with self.assertRaises(AuditError): windows.read_live("demo-source", None, "demo-owner", 999)
            memory.assert_not_called()

    def test_contact_only_pipeline_creates_no_plaintext_files(self):
        plain = self.root / "synthetic-input.db"
        database(plain, reserve=True)
        path = self.root / "db_storage/contact/contact.db"
        path.parent.mkdir(parents=True); path.write_bytes(encrypt(plain.read_bytes()))
        source = windows.Source(path.parent.parent, "demo-source")
        references = []
        def verified(*args):
            salt = args[4][0][3]
            args[6][salt] = KEY.hex()
            args[7].clear()
            references.append(args[6])
        memory = MagicMock()
        memory.__enter__.return_value = memory
        memory.regions.return_value = []
        before = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file())
        with patch.object(windows, "discover", return_value=[source]), patch.object(windows, "weixin_pids", return_value={123}), patch.object(windows, "ProcessMemory", return_value=memory), patch("wechat_group_audit._wcdb_scan._scan_windows_v411_config_cipher", side_effect=verified):
            directory = windows.read_live("demo-source", None, "demo-owner", 123)
        after = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file())
        self.assertEqual(before, after)
        self.assertEqual(len(directory.rooms), 2)
        self.assertTrue(directory.evidence["authenticated_pages"])
        self.assertFalse(directory.evidence["plaintext_saved"])
        self.assertEqual(references, [{}])

    def test_plaintext_source_does_not_trigger_a_key_scan(self):
        path = self.root / "db_storage/contact/contact.db"
        database(path)
        source = windows.Source(path.parent.parent, "demo-source")
        with patch.object(windows, "discover", return_value=[source]), patch.object(windows, "ProcessMemory") as memory:
            with self.assertRaises(AuditError): windows.read_live("demo-source", None, "demo-owner", 123)
            memory.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "native Windows process identity check")
    def test_python_process_is_rejected_as_not_weixin(self):
        import os
        with self.assertRaisesRegex(AuditError, "Weixin.exe"):
            windows.ProcessMemory(os.getpid())

    @unittest.skipUnless(sys.platform == "win32", "native Windows private output ACL")
    def test_output_directory_has_only_current_user_and_system_entries(self):
        import ctypes as ct
        from ctypes import wintypes as wt
        folder = self.root / "private"; folder.mkdir()
        windows.protect_new_directory(folder)
        api = windows._library("advapi32", {
            "GetNamedSecurityInfoW": ([wt.LPWSTR, wt.DWORD, wt.DWORD, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.POINTER(ct.c_void_p)], wt.DWORD),
            "ConvertSecurityDescriptorToStringSecurityDescriptorW": ([ct.c_void_p, wt.DWORD, wt.DWORD, ct.POINTER(wt.LPWSTR), ct.c_void_p], wt.BOOL),
        })
        descriptor, text = ct.c_void_p(), wt.LPWSTR()
        self.assertEqual(api.GetNamedSecurityInfoW(str(folder), 1, 4, None, None, None, None, ct.byref(descriptor)), 0)
        try:
            self.assertTrue(api.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, ct.byref(text), None))
            self.assertEqual(text.value.count("(A;"), 2)
            self.assertIn(";;;SY)", text.value)
            self.assertTrue(text.value.startswith("D:P"))
        finally:
            windows._kernel().LocalFree(text)
            windows._kernel().LocalFree(descriptor)
