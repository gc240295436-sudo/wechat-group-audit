"""Synthetic fixtures written independently for this repository."""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import struct
import sys

PROJECT = Path(__file__).resolve().parents[1]


def sample():
    return json.loads((PROJECT / "examples/directory.json").read_text(encoding="utf-8"))


def database(path, reserve=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if reserve:
        reserve_pages(path)
    con = sqlite3.connect(path)
    try:
        con.executescript("""
            CREATE TABLE contact(id INTEGER PRIMARY KEY, username TEXT, local_type INTEGER,
                flag INTEGER, delete_flag INTEGER, verify_flag INTEGER,
                nick_name TEXT, remark TEXT, alias TEXT);
            CREATE TABLE chat_room(id INTEGER PRIMARY KEY, username TEXT);
            CREATE TABLE chatroom_member(room_id INTEGER, member_id INTEGER);
        """)
        data = sample()
        ids = {person["id"]: index for index, person in enumerate(data["contacts"], 1)}
        for row in data["contacts"]:
            kind = row.get("kind")
            values = (ids[row["id"]], row["id"], 5 if kind == "enterprise" else 1 if kind == "personal" else 3,
                      1 if kind in ("personal", "enterprise") else 4, 0, 0,
                      row.get("nickname", ""), row.get("remark", ""), row.get("alias", ""))
            con.execute("INSERT INTO contact VALUES(?,?,?,?,?,?,?,?,?)", values)
        for index, room in enumerate(data["groups"], 100):
            user = room["id"] + "@chatroom"
            con.execute("INSERT INTO contact VALUES(?,?,2,2,0,0,?,'','')", (index, user, room["name"]))
            con.execute("INSERT INTO chat_room VALUES(?,?)", (index, user))
            con.executemany("INSERT INTO chatroom_member VALUES(?,?)", [(index, ids[user]) for user in room["members"]])
        for row in ((200, "filehelper", 1, 1, 0, 0, "文件助手", "", ""),
                    (201, "gh_demo", 1, 515, 0, 24, "演示公众号", "", ""),
                    (202, "demo-deleted", 1, 3, 1, 0, "已删除演示好友", "", "")):
            con.execute("INSERT INTO contact VALUES(?,?,?,?,?,?,?,?,?)", row)
        con.commit()
    finally:
        con.close()


def reserve_pages(path):
    """Set SQLite's public RESERVE_BYTES file-control before building a fixture."""
    if sys.platform == "win32":
        choices = [Path(sys.base_prefix) / "DLLs/sqlite3.dll", Path(sys.base_prefix) / "sqlite3.dll"]
        library = str(next(p for p in choices if p.is_file()))
    else:
        library = ctypes.util.find_library("sqlite3")
    api = ctypes.CDLL(library)
    api.sqlite3_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    api.sqlite3_exec.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    api.sqlite3_file_control.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    api.sqlite3_close.argtypes = [ctypes.c_void_p]
    handle = ctypes.c_void_p()
    if api.sqlite3_open(str(path).encode(), ctypes.byref(handle)):
        raise RuntimeError("synthetic SQLite open failed")
    try:
        if api.sqlite3_exec(handle, b"PRAGMA page_size=4096; PRAGMA schema_version;", None, None, None):
            raise RuntimeError("synthetic SQLite setup failed")
        reserve = ctypes.c_int(80)
        if api.sqlite3_file_control(handle, b"main", 38, ctypes.byref(reserve)):
            raise RuntimeError("synthetic SQLite reserve failed")
        if api.sqlite3_exec(handle, b"VACUUM;", None, None, None):
            raise RuntimeError("synthetic SQLite VACUUM failed")
    finally:
        api.sqlite3_close(handle)


KEY = hashlib.sha256(b"wga synthetic key, never a user key").digest()
SALT = hashlib.md5(b"wga synthetic salt").digest()


def encrypt(data):
    from Crypto.Cipher import AES
    mac_key = hashlib.pbkdf2_hmac("sha512", KEY, bytes(n ^ 0x3A for n in SALT), 2, 32)
    output = bytearray()
    for index in range(len(data) // 4096):
        page = data[index * 4096:(index + 1) * 4096]
        iv = hashlib.md5(str(index).encode()).digest()
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        block = cipher.encrypt(page[16 if index == 0 else 0:4016]) + iv
        digest = hmac.new(mac_key, block + struct.pack("<I", index + 1), hashlib.sha512).digest()
        output.extend((SALT if index == 0 else b"") + block + digest)
    return bytes(output)


def wal(frames, order="<"):
    # Independent expression of SQLite's two-register checksum, not production code.
    state = [0, 0]
    def signature(raw):
        words = struct.unpack(order + "I" * (len(raw) // 4), raw)
        for pos in range(0, len(words), 2):
            state[0] = (state[0] + words[pos] + state[1]) % (2**32)
            state[1] = (state[1] + words[pos + 1] + state[0]) % (2**32)
        return struct.pack(">II", *state)
    generation = b"WGA-demo"
    head = struct.pack(">IIII", 0x377F0682 if order == "<" else 0x377F0683, 3007000, 4096, 0) + generation
    output = bytearray(head + signature(head))
    for number, commit, page in frames:
        prefix = struct.pack(">II", number, commit)
        output.extend(prefix + generation + signature(prefix + page) + page)
    return bytes(output)
