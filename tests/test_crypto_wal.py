from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from wechat_group_audit import _wcdb_scan as vendor
from wechat_group_audit.cipher import decode_database, verify_key
from wechat_group_audit.model import AuditError
from wechat_group_audit.readers import read_memory
from wechat_group_audit.wal import capture_pair, replay
from support import KEY, SALT, database, encrypt, wal


class CryptoAndWALTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wga-crypto-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_authenticated_pages_roundtrip_into_real_sqlite(self):
        path = self.root / "fixture.db"
        database(path, reserve=True)
        data = path.read_bytes()
        self.assertEqual(data[20], 80)
        encrypted = encrypt(data)
        self.assertTrue(verify_key(KEY, encrypted[:4096]))
        decoded = decode_database(encrypted, KEY)
        directory = read_memory(decoded, "demo-owner", {"test": True})
        self.assertEqual(len(directory.rooms), 2)
        for offset in (40, 4096 + 40, len(encrypted) - 1):
            corrupted = bytearray(encrypted); corrupted[offset] ^= 1
            with self.assertRaises(AuditError): decode_database(bytes(corrupted), KEY)
        with self.assertRaises(AuditError): decode_database(encrypted, bytes(32))
        with self.assertRaises(AuditError): decode_database(encrypted[:-1], KEY)

    def test_known_aes256_cbc_vector(self):
        from Crypto.Cipher import AES
        key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(cipher.decrypt(bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")), bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"))

    def test_wal_commits_only_and_both_checksum_orders(self):
        a, b, c = (letter * 4096 for letter in (b"a", b"b", b"c"))
        for order in ("<", ">"):
            log = wal([(1, 1, b), (1, 0, c)], order)
            self.assertEqual(replay(a, log), b)
            damaged = bytearray(log); damaged[100] ^= 1
            with self.assertRaises(AuditError): replay(a, bytes(damaged))
        self.assertEqual(replay(a, wal([(1, 0, b)])), a)

    def test_wal_shrink_then_growth_does_not_resurrect_removed_pages(self):
        a, b, c = (letter * 4096 for letter in (b"a", b"b", b"c"))
        self.assertEqual(replay(a + b, wal([(1, 1, c), (2, 2, a)])), c + a)
        with self.assertRaises(AuditError): replay(a + b, wal([(1, 1, c), (3, 3, a)]))

    def test_old_generation_and_partial_trailing_frame(self):
        a, b = b"a" * 4096, b"b" * 4096
        log = wal([(1, 1, b)])
        stale = bytearray(log[32:]); stale[8:16] = b"old-demo"
        self.assertEqual(replay(a, log + stale), b)
        self.assertEqual(replay(a, log + b"incomplete"), b)
        for malformed in (log[:10], bytes(32)):
            with self.assertRaises(AuditError): replay(a, malformed)

    def test_capture_refuses_journal_and_replays_stable_files(self):
        db = self.root / "encrypted.db"; db.write_bytes(b"a" * 4096)
        Path(str(db) + "-wal").write_bytes(wal([(1, 1, b"b" * 4096)]))
        self.assertEqual(capture_pair(db), b"b" * 4096)
        Path(str(db) + "-journal").write_bytes(b"pending")
        with self.assertRaises(AuditError): capture_pair(db)

    def test_mit_object_traversal_matches_only_authenticated_candidates(self):
        page_path = self.root / "fixture.db"; database(page_path, reserve=True)
        first = encrypt(page_path.read_bytes())[:4096]
        base, name, node, config, blob = 0x10000, 0x11000, 0x12000, 0x13000, 0x14000
        image = bytearray(0x5000)
        def put(address, value): image[address-base:address-base+len(value)] = value
        put(name, vendor.WINDOWS_CONFIG_CIPHER_NAME)
        for offset, value in ((0x10, name), (0x18, len(vendor.WINDOWS_CONFIG_CIPHER_NAME)), (0x28, config)):
            put(node + offset, struct.pack("<Q", value))
        literal = ("x'" + KEY.hex() + SALT.hex() + "'").encode()
        encoded = bytes(v ^ vendor.WINDOWS_CONFIG_XOR_MASK[i % 32] for i, v in enumerate(literal))
        put(blob, encoded); put(config + 0x90, struct.pack("<Q", blob)); put(config + 0x98, struct.pack("<Q", len(encoded)))
        def read(address, size): return bytes(image[address-base:address-base+size])
        salt = SALT.hex()
        for corrupted in (False, True):
            keys, missing = {}, {salt}
            page = bytearray(first)
            if corrupted: page[200] ^= 1
            vendor._scan_windows_v411_config_cipher(123, [(base, len(image))], read, read,
                [("synthetic.db", None, 4096, salt, bytes(page))], {salt: ["synthetic.db"]}, keys, missing, lambda *args: None)
            self.assertEqual(bool(keys), not corrupted)
            if not corrupted: self.assertEqual(keys[salt], KEY.hex())
