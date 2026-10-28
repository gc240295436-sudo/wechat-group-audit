"""Explicit JSON and SQLite adapters for the normalized relationship model."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3

from .model import AuditError, Directory, Person, Room
from .paths import bounded_read, local_path
from .wal import MAX_DATABASE, stamp

MAX_CONTACTS = 200_000
MAX_RELATIONS = 2_000_000
JSON_LIMIT = 32 * 1024 * 1024
SYSTEM_ACCOUNTS = frozenset("filehelper fmessage qmessage qqmail qqsync medianote floatbottle tmessage newsapp weixin notification_messages notifymessage weixingame weixinreminder feedsapp weibo masssendapp facebookapp blogapp linkedinplugin voiceinputapp voicevoipapp helper_entry brandsessionholder message_fold officialaccounts appbrandcustomerservicemsg".split())


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path, me: str | None = None) -> Directory:
    try:
        data = json.loads(bounded_read(path, JSON_LIMIT))
        if data["schema"] != "wga-directory/1" or not isinstance(data["account"], str):
            raise AuditError("输入不是支持的关系数据格式。")
        if not isinstance(data["contacts"], list) or len(data["contacts"]) > MAX_CONTACTS or not isinstance(data["groups"], list):
            raise AuditError("联系人或群列表无效或超限。")
        people = {}
        for row in data["contacts"]:
            user = row["id"]
            fields = [row.get(key, "") for key in ("nickname", "remark", "alias")]
            if not isinstance(user, str) or not user or user in people or not all(isinstance(v, str) for v in fields):
                raise AuditError("联系人身份或名称字段无效。")
            kind = row.get("kind", "other")
            if kind not in ("personal", "enterprise", "other"):
                raise AuditError("联系人类别无效。")
            people[user] = Person(user, *fields, kind)
        rooms, keys, relations = [], set(), 0
        for row in data["groups"]:
            user, title, members = row["id"], row["name"], row["members"]
            if not isinstance(user, str) or not user or user in keys or not isinstance(title, str) or not isinstance(members, list):
                raise AuditError("群身份、名称或成员列表无效。")
            if not all(isinstance(item, str) for item in members) or type(row.get("complete", True)) is not bool:
                raise AuditError("群成员身份或完整性标记无效。")
            count = row.get("member_count")
            if count is not None and (type(count) is not int or count < 0):
                raise AuditError("群声明人数无效。")
            relations += len(members)
            if relations > MAX_RELATIONS:
                raise AuditError("成员关系数量超限。")
            keys.add(user)
            rooms.append(Room(user, title, tuple(members), row.get("complete", True), count))
        result = Directory(data["account"], people, rooms, {"type": "json", "checked_at": now(), "authenticated_pages": False})
        result.resolve_owner(me)
        return result
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError("关系 JSON 结构不完整或无法解析。") from exc


def _columns(con, table):
    row = con.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=? COLLATE NOCASE", (table,)).fetchone()
    if not row or "CREATE VIRTUAL" in str(row[0]).upper():
        raise AuditError("需要完整的联系人、群身份和群成员普通数据表。")
    return {str(item[1]).casefold(): str(item[1]) for item in con.execute(f'PRAGMA table_info("{table}")')}


def from_sqlite(con: sqlite3.Connection, me: str, evidence=None) -> Directory:
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA trusted_schema=OFF")
    con.execute("PRAGMA temp_store=MEMORY")
    con.execute("PRAGMA query_only=ON")
    if [r[0] for r in con.execute("PRAGMA integrity_check")] != ["ok"]:
        raise AuditError("SQLite 完整性校验失败。")
    columns = _columns(con, "contact")
    required = {"id", "username", "local_type", "flag", "delete_flag", "verify_flag"}
    if not required <= columns.keys():
        raise AuditError("缺少好友分类字段，不能将所有联系人视为好友。")
    if con.execute("SELECT count(*) FROM contact").fetchone()[0] > MAX_CONTACTS:
        raise AuditError("联系人数量超限。")
    selected = sorted(required | (columns.keys() & {"nick_name", "remark", "alias"}))
    people, row_ids, raw = {}, {}, []
    for item in con.execute("SELECT " + ",".join(f'"{columns[name]}" AS "{name}"' for name in selected) + " FROM contact"):
        record = dict(item)
        user, number = record["username"], record["id"]
        if type(number) is not int or number in row_ids or not isinstance(user, str) or not user or user in people:
            raise AuditError("联系人身份重复或无法解析。")
        if any(type(record[name]) is not int for name in ("local_type", "flag", "delete_flag", "verify_flag")):
            raise AuditError("好友分类字段损坏。")
        normal = (record["local_type"] in (1, 5) and bool(record["flag"] & 1) and record["delete_flag"] == 0
                  and record["verify_flag"] == 0 and user not in SYSTEM_ACCOUNTS
                  and not user.startswith("gh_") and not user.endswith("@chatroom"))
        kind = ("enterprise" if record["local_type"] == 5 else "personal") if normal else "other"
        labels = [record.get(name) or "" for name in ("nick_name", "remark", "alias")]
        if any(not isinstance(value, str) for value in labels):
            raise AuditError("联系人名称字段损坏。")
        people[user] = Person(user, *labels, kind)
        row_ids[number] = user
        raw.append((number, user))
    if not {"id", "username"} <= _columns(con, "chat_room").keys() or not {"room_id", "member_id"} <= _columns(con, "chatroom_member").keys():
        raise AuditError("缺少完整群成员关系，不能以聊天发言者代替。")
    identities = {}
    for number, user in con.execute("SELECT id,username FROM chat_room"):
        if number in identities:
            raise AuditError("群身份映射重复。")
        identities[number] = user
    if con.execute("SELECT count(*) FROM chatroom_member").fetchone()[0] > MAX_RELATIONS:
        raise AuditError("群成员关系数量超限。")
    member_map = {}
    for number, member in con.execute("SELECT room_id,member_id FROM chatroom_member"):
        member_map.setdefault(number, []).append(row_ids.get(member, f"unresolved:{member}"))
    rooms = [Room(user, people[user].label, tuple(member_map.get(number, ())), identities.get(number) == user)
             for number, user in raw if user.endswith("@chatroom")]
    result = Directory("", people, rooms, {"type": "sqlite", "checked_at": now(), "sqlite_integrity": True, **(evidence or {})})
    result.resolve_owner(me)
    return result


@contextmanager
def immutable_database(path):
    path = local_path(path, exists=True)
    if not 0 < path.stat().st_size <= MAX_DATABASE:
        raise AuditError("通讯录数据库为空或大于 128 MiB。")
    sidecars = [Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")]
    if any(os.path.lexists(p) for p in sidecars):
        raise AuditError("明文输入仍有 WAL/SHM/journal，请提供静止且已 checkpoint 的快照。")
    before = stamp(path)
    con = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        yield con
    finally:
        con.close()
    if stamp(path) != before or any(os.path.lexists(p) for p in sidecars):
        raise AuditError("查询期间输入发生变化，未发布报告。")


def read_database(path, me) -> Directory:
    if not me:
        raise AuditError("SQLite 输入需要通过 --me 指定本人身份。")
    with immutable_database(path) as con:
        return from_sqlite(con, me, {"authenticated_pages": False})


def read_memory(image: bytes, me, evidence) -> Directory:
    if not hasattr(sqlite3.Connection, "deserialize"):
        raise AuditError("此 Python 的 SQLite 不支持内存数据库加载。")
    # The WAL is already replayed. Only the private RAM image switches to the
    # rollback header expected by SQLite's deserialize API.
    image = bytearray(image)
    image[18:20] = b"\x01\x01"
    con = sqlite3.connect(":memory:")
    try:
        con.deserialize(image)
        return from_sqlite(con, me, evidence)
    finally:
        con.close()
