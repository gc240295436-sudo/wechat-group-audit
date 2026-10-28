"""Local paths only; reject aliases before reading data or writing a report."""
from __future__ import annotations

import os
from pathlib import Path
import stat

from .model import AuditError


def local_path(value, *, exists=False, directory=False) -> Path:
    path = Path(value).expanduser()
    raw = os.fspath(path)
    if raw.startswith(("\\\\", "//")) or ".." in path.parts:
        raise AuditError("仅接受无父目录跳转的本机路径。")
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise AuditError("数据与报告路径不能经过软链接、junction 或 reparse point。")
    if exists:
        if directory and not absolute.is_dir():
            raise AuditError("指定目录不可用。")
        if not directory and not absolute.is_file():
            raise AuditError("指定输入文件不可用。")
    return absolute


def bounded_read(path, limit: int) -> bytes:
    path = local_path(path, exists=True)
    if path.stat().st_size > limit:
        raise AuditError("输入超出大小限制。")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise AuditError("输入在读取期间增长到限额之外。")
    return data
