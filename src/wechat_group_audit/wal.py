"""Committed WAL replay, independently implemented from SQLite's file specification."""
from __future__ import annotations

from pathlib import Path
import os
import struct

from .model import AuditError
from .paths import bounded_read, local_path

MAX_DATABASE = 128 * 1024 * 1024
PAGE = 4096


def checksum(data: bytes, order: str, running=(0, 0)):
    if len(data) % 8:
        raise AuditError("WAL 校验输入未对齐。")
    a, b = running
    for x, y in struct.iter_unpack(order + "II", data):
        a = (a + x + b) & 0xFFFFFFFF
        b = (b + y + a) & 0xFFFFFFFF
    return a, b


def replay(main: bytes, log: bytes) -> bytes:
    if len(main) < PAGE or len(main) % PAGE or len(main) > MAX_DATABASE:
        raise AuditError("主数据库大小或页面不合法。")
    if not log:
        return main
    if len(log) < 32:
        raise AuditError("WAL 头不完整。")
    magic, version, size = struct.unpack_from(">III", log)
    if magic not in (0x377F0682, 0x377F0683) or version != 3007000 or size != PAGE:
        raise AuditError("WAL 格式不支持。")
    order = "<" if magic == 0x377F0682 else ">"
    running = checksum(log[:24], order)
    if running != struct.unpack_from(">II", log, 24):
        raise AuditError("WAL 头校验失败。")
    generation = log[16:24]
    pages = [main[i:i + PAGE] for i in range(0, len(main), PAGE)]
    pending = {}
    saw_commit = False
    stride = PAGE + 24
    for offset in range(32, len(log) - stride + 1, stride):
        header = log[offset:offset + 24]
        if header[8:16] != generation:
            break  # preallocated bytes from an older WAL generation
        number, length = struct.unpack_from(">II", header)
        if not 1 <= number <= MAX_DATABASE // PAGE or length > MAX_DATABASE // PAGE:
            raise AuditError("WAL 页号超出数据库限额。")
        data = log[offset + 24:offset + stride]
        running = checksum(header[:8] + data, order, running)
        if running != struct.unpack_from(">II", header, 16):
            raise AuditError("WAL 事务帧校验失败。")
        pending[number] = data
        if length:
            # Apply each committed transaction in sequence. A truncation cannot
            # resurrect an old base-file page when a later transaction grows.
            next_pages = pages[:length] + [None] * max(0, length - len(pages))
            for page_number, payload in pending.items():
                if page_number <= length:
                    next_pages[page_number - 1] = payload
            if any(page is None for page in next_pages):
                raise AuditError("WAL 增长事务缺少必要页面。")
            pages = next_pages
            pending.clear()
            saw_commit = True
    return b"".join(pages) if saw_commit else main


def stamp(path: Path):
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return info.st_size, info.st_mtime_ns, info.st_ino


def capture_pair(database: Path, retries=3) -> bytes:
    database = local_path(database, exists=True)
    wal = Path(str(database) + "-wal")
    journal = Path(str(database) + "-journal")
    for _ in range(retries):
        if os.path.lexists(journal):
            raise AuditError("来源仍有 rollback journal，请等待客户端事务完成。")
        if os.path.lexists(wal):
            local_path(wal, exists=True)
        before = stamp(database), stamp(wal)
        base = bounded_read(database, MAX_DATABASE)
        try:
            log = bounded_read(wal, MAX_DATABASE)
        except FileNotFoundError:
            log = b""
        except AuditError:
            if not wal.exists():
                log = b""
            else:
                raise
        if os.path.lexists(journal):
            raise AuditError("读取期间出现 rollback journal，请稍后重试。")
        if before == (stamp(database), stamp(wal)):
            return replay(base, log)
    raise AuditError("数据库或 WAL 持续变化，未生成分析结果，请稍后重试。")
