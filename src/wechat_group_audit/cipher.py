"""SQLCipher v4 raw-key page verification, based on the published file design."""
from __future__ import annotations

import hashlib
import hmac
import struct

from .model import AuditError

PAGE_BYTES = 4096
TRAILER_BYTES = 80


def authentication_key(encryption_key: bytes, salt: bytes) -> bytes:
    if len(encryption_key) != 32 or len(salt) != 16:
        raise AuditError("数据库密钥或盐长度不支持。")
    return hashlib.pbkdf2_hmac("sha512", encryption_key, bytes(b ^ 0x3A for b in salt), 2, dklen=32)


def page_matches(page: bytes, number: int, mac_key: bytes) -> bool:
    if len(page) != PAGE_BYTES:
        return False
    offset = 16 if number == 1 else 0
    mac = hmac.new(mac_key, digestmod="sha512")
    mac.update(page[offset:PAGE_BYTES - 64])
    mac.update(struct.pack("<I", number))
    return hmac.compare_digest(mac.digest(), page[-64:])


def verify_key(encryption_key: bytes, page_one: bytes) -> bool:
    return len(page_one) == PAGE_BYTES and page_matches(page_one, 1, authentication_key(encryption_key, page_one[:16]))


def decode_database(encrypted: bytes, encryption_key: bytes) -> bytes:
    if not encrypted or len(encrypted) % PAGE_BYTES:
        raise AuditError("数据库页不完整。")
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise AuditError("Windows 采集需要 live 依赖：pip install '.[live]'。") from exc
    signing_key = authentication_key(encryption_key, encrypted[:16])
    output = bytearray()
    for number, start in enumerate(range(0, len(encrypted), PAGE_BYTES), 1):
        page = encrypted[start:start + PAGE_BYTES]
        if not page_matches(page, number, signing_key):
            raise AuditError("数据库页认证失败，已停止处理。")
        first = 16 if number == 1 else 0
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv=page[-80:-64])
        payload = cipher.decrypt(page[first:-80])
        if number == 1:
            if payload[:2] != b"\x10\x00" or payload[4:8] != b"\x50\x40\x20\x20":
                raise AuditError("解密后的数据库格式不兼容。")
            output.extend(b"SQLite format 3\0")
        output.extend(payload)
        output.extend(bytes(TRAILER_BYTES))
    return bytes(output)
