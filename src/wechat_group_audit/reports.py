"""Private report bundles, readable tables, and spreadsheet-safe CSV."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import html
import io
import json
import os
from pathlib import Path
import sys
import uuid

from .model import AuditError, compact
from .paths import local_path

MAX_REPORT = 32 * 1024 * 1024


def table_text(value):
    text = html.escape(compact(str(value)), quote=False)
    for symbol in ("\\", "[", "]", "`", "*", "_"):
        text = text.replace(symbol, "\\" + symbol)
    return text.replace("|", "&#124;")


def discriminator(row):
    if not row["ambiguous_name"]:
        return ""
    return row.get("wechat_id") or row.get("username") or row["key"][-8:]


def markdown(report):
    stats = report["statistics"]
    names = {room["key"]: room["name"] for room in report["groups"]}
    lines = [f"# {report['title']}", "", f"生成时间：{report['created_at']}", "",
             f"好友范围 {stats['friends']} 位；已覆盖 {stats['covered']} 位；未覆盖 {stats['missing']} 位。",
             f"本次筛选 {stats['selected']} 位：普通好友 {stats['personal']} 位，企业微信联系人 {stats['enterprise']} 位。", "",
             "仅依据本机已同步关系。昵称相同的账号分别保留，核对号用于区分。", "",
             "| 群 | 成员数 | 本范围好友 | 覆盖率 |", "| --- | ---: | ---: | ---: |"]
    for room in report["groups"]:
        lines.append(f"| {table_text(room['name'])} | {room['members']} | {room['friends']} | {room['coverage']}% |")
    if report["overlap"]:
        lines += ["", "## 群之间的重叠", "", "| 群一 | 群二 | 共同成员 | 其中好友 |", "| --- | --- | ---: | ---: |"]
        for pair in report["overlap"]:
            lines.append(f"| {table_text(names[pair['a']])} | {table_text(names[pair['b']])} | {pair['members']} | {pair['friends']} |")
    for kind, heading in (("personal", "普通微信好友"), ("enterprise", "企业微信联系人")):
        rows = [row for row in report["people"] if row["kind"] == kind]
        lines += ["", f"## {heading}（{len(rows)} 位）", "", "| 序号 | 显示名 | 备注 | 昵称 | 所在目标群 | 区分信息 |", "| ---: | --- | --- | --- | --- | --- |"]
        for index, row in enumerate(rows, 1):
            columns = (index, row["name"], row["remark"], row["nickname"], "、".join(names[k] for k in row["rooms"]) or "无", discriminator(row))
            lines.append("| " + " | ".join(table_text(v) for v in columns) + " |")
    if "changes" in report:
        changes = report["changes"]
        lines += ["", "## 与上次结果的变化", "", f"新增 {len(changes['added'])} 位，移出 {len(changes['removed'])} 位，仍在结果中 {changes['unchanged']} 位。",
                  changes["note"]]
        for key, heading in (("added", "新增"), ("removed", "移出")):
            lines += ["", f"### {heading}", ""]
            lines += [f"- {table_text(row['name'])}（{row['key'][-8:]}）" for row in changes[key]] or ["无"]
    return "\n".join(lines) + "\n"


def plain_text(report):
    names = {room["key"]: room["name"] for room in report["groups"]}
    lines = [report["title"], f"生成时间：{report['created_at']}", ""]
    for kind, heading in (("personal", "普通微信好友"), ("enterprise", "企业微信联系人")):
        rows = [row for row in report["people"] if row["kind"] == kind]
        lines += [f"{heading}（{len(rows)} 位）", ""]
        for number, row in enumerate(rows, 1):
            details = []
            if row["remark"] and row["nickname"] != row["remark"]:
                details.append("昵称：" + row["nickname"])
            if row["rooms"]:
                details.append("所在群：" + "、".join(names[k] for k in row["rooms"]))
            if discriminator(row):
                details.append("区分：" + discriminator(row))
            tail = "（" + "；".join(details) + "）" if details else ""
            lines.append(f"{number}. {row['name']}{tail}")
        lines.append("")
    if "changes" in report:
        for key, heading in (("added", "新增"), ("removed", "移出")):
            lines.append(f"{heading}（{len(report['changes'][key])} 位）")
            lines += [f"- {r['name']}〔{r['key'][-8:]}〕" for r in report["changes"][key]]
            lines.append("")
        lines.append(report["changes"]["note"])
    return "\n".join(lines) + "\n"


def _csv_text(value):
    value = str(value)
    # CSV has no cell type: explicitly text-escape potentially executable cells.
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value


def csv_text(report):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["核对号", "类型", "显示名", "备注", "昵称", "目标群数量", "所在目标群", "区分信息"])
    names = {room["key"]: room["name"] for room in report["groups"]}
    for row in report["people"]:
        fields = (row["key"], "普通微信好友" if row["kind"] == "personal" else "企业微信联系人",
                  row["name"], row["remark"], row["nickname"], len(row["rooms"]),
                  "、".join(names[k] for k in row["rooms"]), discriminator(row))
        writer.writerow([_csv_text(value) for value in fields])
    return buffer.getvalue()


def default_output():
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return base / "WeChatGroupAudit/results"


def write_bundle(report, output=None):
    parent = local_path(output or default_output())
    package = Path(__file__).resolve().parent
    forbidden = [package]
    checkout = package.parent.parent
    if (checkout / "pyproject.toml").is_file() and (checkout / "src/wechat_group_audit").is_dir():
        forbidden.append(checkout)
    if any(parent == root or root in parent.parents for root in forbidden):
        raise AuditError("个人报告不能写入本项目源码或安装包目录。")
    parent.mkdir(parents=True, exist_ok=True)
    local_path(parent, exists=True, directory=True)
    tag = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    folder = parent / tag
    folder.mkdir(mode=0o700)
    filenames = ("members.md", "members.txt", "members.csv", "members.json")
    paths = [folder / name for name in filenames]
    try:
        if sys.platform == "win32":
            from .windows import protect_new_directory
            protect_new_directory(folder)
        payloads = [markdown(report).encode("utf-8"), plain_text(report).encode("utf-8-sig"),
                    csv_text(report).encode("utf-8-sig"), (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")]
        for path, content in zip(paths, payloads):
            if len(content) > MAX_REPORT:
                raise AuditError("报告超出限额，请缩小好友筛选范围。")
            descriptor = os.open(path, os.O_EXCL | os.O_CREAT | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if path.read_bytes() != content:
                raise AuditError("报告回读校验失败。")
        saved = json.loads(paths[-1].read_bytes())
        if saved["statistics"]["selected"] != len(saved["people"]):
            raise AuditError("报告人数回读不一致。")
        if len(list(csv.reader(io.StringIO(paths[2].read_text(encoding="utf-8-sig"))))) != len(saved["people"]) + 1:
            raise AuditError("CSV 人数回读不一致。")
    except BaseException:
        for path in paths:
            path.unlink(missing_ok=True)
        folder.rmdir()
        raise
    return dict(zip(("markdown", "text", "csv", "json"), map(str, paths)))
