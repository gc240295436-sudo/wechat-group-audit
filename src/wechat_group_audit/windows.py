"""Read-only Windows APIs and an in-memory, contact-only acquisition path.

Win32 structure layouts follow Microsoft documentation. The optional key object
traversal is the separately attributed MIT selection in _wcdb_scan.py.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
import csv
import ctypes as ct
from ctypes import wintypes as wt
from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from .model import AuditError, Directory
from .paths import local_path


def _windows_only():
    if sys.platform != "win32" or ct.sizeof(ct.c_void_p) != 8:
        raise AuditError("此操作需要 64 位 Windows Python；其他平台可分析 JSON 或静态明文数据库。")


def _library(name, definitions):
    _windows_only()
    dll = ct.WinDLL(name, use_last_error=True)
    for function, (arguments, result) in definitions.items():
        api = getattr(dll, function)
        api.argtypes, api.restype = arguments, result
    return dll


def _kernel():
    return _library("kernel32", {
        "GetCurrentProcess": ([], wt.HANDLE),
        "OpenProcess": ([wt.DWORD, wt.BOOL, wt.DWORD], wt.HANDLE),
        "CloseHandle": ([wt.HANDLE], wt.BOOL),
        "LocalFree": ([ct.c_void_p], ct.c_void_p),
        "QueryFullProcessImageNameW": ([wt.HANDLE, wt.DWORD, wt.LPWSTR, ct.POINTER(wt.DWORD)], wt.BOOL),
        "ReadProcessMemory": ([wt.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_size_t)], wt.BOOL),
        "VirtualQueryEx": ([wt.HANDLE, ct.c_void_p, ct.c_void_p, ct.c_size_t], ct.c_size_t),
    })


def process_user(handle) -> str:
    api = _library("advapi32", {
        "OpenProcessToken": ([wt.HANDLE, wt.DWORD, ct.POINTER(wt.HANDLE)], wt.BOOL),
        "GetTokenInformation": ([wt.HANDLE, ct.c_int, ct.c_void_p, wt.DWORD, ct.POINTER(wt.DWORD)], wt.BOOL),
        "ConvertSidToStringSidW": ([ct.c_void_p, ct.POINTER(wt.LPWSTR)], wt.BOOL),
    })
    token, needed = wt.HANDLE(), wt.DWORD()
    kernel = _kernel()
    if not api.OpenProcessToken(handle, 0x0008, ct.byref(token)):
        raise AuditError("无法核验进程所属用户。")
    try:
        api.GetTokenInformation(token, 1, None, 0, ct.byref(needed))
        buffer = ct.create_string_buffer(needed.value)
        if not api.GetTokenInformation(token, 1, buffer, needed, ct.byref(needed)):
            raise AuditError("无法读取进程用户身份。")
        sid_pointer = ct.cast(buffer, ct.POINTER(ct.c_void_p))[0]
        text = wt.LPWSTR()
        if not api.ConvertSidToStringSidW(sid_pointer, ct.byref(text)):
            raise AuditError("无法解析进程用户身份。")
        try:
            return text.value
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def trusted_signature(executable: str) -> bool:
    class Guid(ct.Structure):
        _fields_ = [("a", wt.DWORD), ("b", wt.WORD), ("c", wt.WORD), ("d", ct.c_ubyte * 8)]
    class File(ct.Structure):
        _fields_ = [("size", wt.DWORD), ("path", wt.LPCWSTR), ("handle", wt.HANDLE), ("subject", ct.c_void_p)]
    class Trust(ct.Structure):
        _fields_ = [("size", wt.DWORD), ("policy", ct.c_void_p), ("sip", ct.c_void_p),
                    ("ui", wt.DWORD), ("revocation", wt.DWORD), ("choice", wt.DWORD),
                    ("file", ct.POINTER(File)), ("action", wt.DWORD), ("state", wt.HANDLE),
                    ("url", wt.LPCWSTR), ("flags", wt.DWORD), ("context", wt.DWORD), ("settings", ct.c_void_p)]
    api = _library("wintrust", {"WinVerifyTrust": ([wt.HWND, ct.POINTER(Guid), ct.POINTER(Trust)], wt.LONG)})
    action = Guid.from_buffer_copy(uuid.UUID("00aac56b-cd44-11d0-8cc2-00c04fc295ee").bytes_le)
    file = File(ct.sizeof(File), executable, None, None)
    request = Trust()
    request.size = ct.sizeof(Trust)
    request.ui, request.choice, request.action = 2, 1, 1
    request.flags = 0x1000  # cache-only verification; acquisition does not access the network
    request.file = ct.pointer(file)
    try:
        return api.WinVerifyTrust(wt.HWND(-1), ct.byref(action), ct.byref(request)) == 0
    finally:
        request.action = 2
        api.WinVerifyTrust(wt.HWND(-1), ct.byref(action), ct.byref(request))


class ProcessMemory(AbstractContextManager):
    """Same-user, signed Weixin process with hard time/byte/chunk limits."""
    def __init__(self, pid: int, seconds=45, max_bytes=2 * 1024**3):
        self.api = _kernel()
        self.handle = self.api.OpenProcess(0x0410, False, pid)
        self.deadline = time.monotonic() + seconds
        self.limit, self.read_bytes = max_bytes, 0
        if not self.handle:
            raise AuditError("无法只读打开所选微信进程，请检查权限和登录状态。")
        try:
            length, path = wt.DWORD(32768), ct.create_unicode_buffer(32768)
            if not self.api.QueryFullProcessImageNameW(self.handle, 0, path, ct.byref(length)):
                raise AuditError("无法核验所选进程路径。")
            if Path(path.value).name.casefold() != "weixin.exe" or not trusted_signature(path.value):
                raise AuditError("所选进程不是签名校验通过的 Weixin.exe。")
            if process_user(self.handle) != process_user(self.api.GetCurrentProcess()):
                raise AuditError("只允许读取与当前 Windows 用户相同的微信进程。")
        except BaseException:
            self.close()
            raise

    def regions(self):
        class Region(ct.Structure):
            _fields_ = [("start", ct.c_void_p), ("allocation", ct.c_void_p), ("allocation_protection", wt.DWORD),
                        ("partition", wt.WORD), ("length", ct.c_size_t), ("state", wt.DWORD),
                        ("protection", wt.DWORD), ("kind", wt.DWORD)]
        output, address = [], 0
        while address < (1 << 47):
            record = Region()
            if not self.api.VirtualQueryEx(self.handle, address, ct.byref(record), ct.sizeof(record)):
                break
            if record.state == 0x1000 and record.protection & 0xFF in (2, 4, 8, 0x20, 0x40, 0x80) and not record.protection & 0x100:
                output.append((record.start, record.length))
            end = (record.start or 0) + record.length
            if end <= address:
                break
            address = end
        return output

    def read(self, address, size):
        if time.monotonic() > self.deadline or self.read_bytes + size > self.limit:
            raise AuditError("只读内存扫描达到时间或字节预算，未获取可验证密钥。")
        if not 0 < size <= 2 * 1024**2 or not 0 < address < (1 << 47):
            return b""
        self.read_bytes += size
        target, received = ct.create_string_buffer(size), ct.c_size_t()
        self.api.ReadProcessMemory(self.handle, address, target, size, ct.byref(received))
        return target.raw[:received.value]

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def __exit__(self, *exception):
        self.close()


def weixin_pids() -> set[int]:
    _windows_only()
    result = subprocess.run(["tasklist.exe", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                            capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    rows = csv.reader(io.StringIO(result.stdout.decode("utf-8", errors="replace")))
    return {int(row[1]) for row in rows if len(row) > 1 and row[0].casefold() == "weixin.exe" and row[1].isdigit()}


def file_holders(path: Path) -> set[int] | None:
    class Unique(ct.Structure):
        _fields_ = [("pid", wt.DWORD), ("started", wt.FILETIME)]
    class Info(ct.Structure):
        _fields_ = [("process", Unique), ("app", wt.WCHAR * 256), ("service", wt.WCHAR * 64),
                    ("type", ct.c_int), ("status", wt.ULONG), ("session", wt.DWORD), ("restart", wt.BOOL)]
    api = _library("rstrtmgr", {
        "RmStartSession": ([ct.POINTER(wt.DWORD), wt.DWORD, wt.LPWSTR], wt.DWORD),
        "RmRegisterResources": ([wt.DWORD, wt.UINT, ct.POINTER(wt.LPCWSTR), wt.UINT, ct.c_void_p, wt.UINT, ct.c_void_p], wt.DWORD),
        "RmGetList": ([wt.DWORD, ct.POINTER(wt.UINT), ct.POINTER(wt.UINT), ct.POINTER(Info), ct.POINTER(wt.DWORD)], wt.DWORD),
        "RmEndSession": ([wt.DWORD], wt.DWORD),
    })
    session, key = wt.DWORD(), ct.create_unicode_buffer(33)
    if api.RmStartSession(ct.byref(session), 0, key):
        return None
    try:
        files = (wt.LPCWSTR * 1)(str(path))
        if api.RmRegisterResources(session, 1, files, 0, None, 0, None):
            return None
        needed, count, reboot = wt.UINT(), wt.UINT(), wt.DWORD()
        error = api.RmGetList(session, ct.byref(needed), ct.byref(count), None, ct.byref(reboot))
        if error not in (0, 234) or needed.value > 1024:
            return None
        buffer = (Info * max(1, needed.value))()
        count.value = needed.value
        if api.RmGetList(session, ct.byref(needed), ct.byref(count), buffer, ct.byref(reboot)):
            return None
        return {item.process.pid for item in buffer[:count.value]}
    finally:
        api.RmEndSession(session)


@dataclass(frozen=True)
class Source:
    root: Path
    key: str

    @property
    def database(self):
        return self.root / "contact/contact.db"


def discover(data_dir=None) -> list[Source]:
    _windows_only()
    if data_dir:
        roots = [local_path(data_dir, exists=True, directory=True)]
        if roots[0].name.casefold() != "db_storage":
            raise AuditError("--data-dir 应明确指向所选账号的 db_storage。")
    else:
        roots = []
        profile = Path(os.environ["USERPROFILE"])
        for base in (profile / "Documents/xwechat_files", profile / "Documents/WeChat Files/xwechat_files"):
            if base.is_dir():
                local_path(base, exists=True, directory=True)
                roots.extend(item / "db_storage" for item in base.iterdir() if item.is_dir())
    found = {}
    for root in roots:
        if not (root / "contact/contact.db").is_file():
            continue
        database = local_path(root / "contact/contact.db", exists=True)
        root = database.parent.parent
        key = hashlib.sha256(os.fsencode(str(root).casefold())).hexdigest()[:16]
        found[key] = Source(root, key)
    return list(found.values())


def source_list(data_dir=None, identifiers=False):
    running, result = weixin_pids(), []
    for item in discover(data_dir):
        owners = file_holders(item.database)
        row = {"source": item.key, "active_pids": None if owners is None else sorted(owners & running)}
        if identifiers:
            row["account_directory"] = item.root.parent.name
        result.append(row)
    return {"sources": result, "process_memory_read": False}


def read_live(source_key, data_dir, me, pid=None, seconds=45) -> Directory:
    from . import _wcdb_scan as scan
    from .cipher import decode_database, verify_key
    from .readers import now, read_memory
    from .wal import MAX_DATABASE, capture_pair
    if not me or not 5 <= seconds <= 180:
        raise AuditError("实时读取需要 --me，扫描时间范围为 5–180 秒。")
    options = [s for s in discover(data_dir) if not source_key or s.key == source_key]
    if len(options) != 1:
        raise AuditError("请用 sources 选择一个明确的账号来源。")
    selected = options[0]
    binding = re.fullmatch(r"(wxid_[A-Za-z0-9]+)_[0-9a-fA-F]{4}", selected.root.parent.name)
    if binding and me.startswith("wxid_") and binding[1] != me:
        raise AuditError("--me 与所选来源的账号不符。")
    database = local_path(selected.database, exists=True)
    if not 4096 <= database.stat().st_size <= MAX_DATABASE:
        raise AuditError("通讯录数据库大小不支持。")
    with database.open("rb") as stream:
        first_page = stream.read(4096)
    if first_page.startswith(b"SQLite format 3\0"):
        raise AuditError("来源已是明文，请改用 --database 静态输入。")
    running = weixin_pids()
    if pid is None:
        owners = file_holders(database)
        candidates = (owners & running) if owners is not None else running
        if len(candidates) != 1:
            raise AuditError("无法唯一绑定微信进程，请从 sources 获取 PID 后使用 --pid。")
        pid = candidates.pop()
    if pid not in running:
        raise AuditError("--pid 不是运行中的微信进程。")
    salt = first_page[:16].hex()
    records = [("contact.db", None, database.stat().st_size, salt, first_page)]
    keys, outstanding = {}, {salt}
    try:
        with ProcessMemory(pid, seconds) as memory:
            regions = memory.regions()
            scan._scan_windows_v411_config_cipher(pid, regions, memory.read, memory.read, records,
                                                 {salt: ["contact.db"]}, keys, outstanding, lambda *args: None)
            if salt not in keys:
                for _, block in scan._iter_windows_region_chunks(regions, memory.read, overlap=200):
                    for match in re.finditer(rb"[xX]'([0-9a-fA-F]{96,192})'", block):
                        literal = match[1].decode("ascii")
                        if literal[64:96].casefold() == salt:
                            candidate = bytes.fromhex(literal[:64])
                            if verify_key(candidate, first_page):
                                keys[salt] = literal[:64]
                                break
                    if salt in keys:
                        break
        if salt not in keys:
            raise AuditError("未找到通过数据库页认证的密钥；当前客户端版本可能不兼容。")
        encrypted = capture_pair(database)
        if encrypted[:16].hex() != salt:
            raise AuditError("读取期间数据库身份发生变化，请重新采集。")
        decoded = decode_database(encrypted, bytes.fromhex(keys[salt]))
        directory = read_memory(decoded, me, {"type": "windows-live", "source": selected.key,
                                "captured_at": now(), "authenticated_pages": True,
                                "pages": len(encrypted) // 4096, "plaintext_saved": False, "key_saved": False})
        if binding and binding[1] != directory.owner:
            raise AuditError("本人身份与所选数据目录不匹配。")
        return directory
    finally:
        keys.clear()


def protect_new_directory(path: Path):
    """Apply a private ACL to a newly created output directory only."""
    path = local_path(path, exists=True, directory=True)
    kernel = _kernel()
    owner = process_user(kernel.GetCurrentProcess())
    api = _library("advapi32", {
        "ConvertStringSecurityDescriptorToSecurityDescriptorW": ([wt.LPCWSTR, wt.DWORD, ct.POINTER(ct.c_void_p), ct.POINTER(wt.ULONG)], wt.BOOL),
        "GetSecurityDescriptorDacl": ([ct.c_void_p, ct.POINTER(wt.BOOL), ct.POINTER(ct.c_void_p), ct.POINTER(wt.BOOL)], wt.BOOL),
        "SetNamedSecurityInfoW": ([wt.LPWSTR, wt.DWORD, wt.DWORD, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p], wt.DWORD),
    })
    descriptor, acl, present, inherited = ct.c_void_p(), ct.c_void_p(), wt.BOOL(), wt.BOOL()
    text = f"D:P(A;OICI;FA;;;{owner})(A;OICI;FA;;;SY)"
    if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(text, 1, ct.byref(descriptor), None):
        raise AuditError("无法建立报告目录的私密权限。")
    try:
        if not api.GetSecurityDescriptorDacl(descriptor, ct.byref(present), ct.byref(acl), ct.byref(inherited)) or not present:
            raise AuditError("无法读取新目录权限。")
        if api.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, acl, None):
            raise AuditError("无法保护新建报告目录。")
    finally:
        kernel.LocalFree(descriptor)
