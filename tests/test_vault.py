import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vault
from strength import check_strength


class VaultTests(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.mkdtemp()
        os.chdir(self._tmp)

    def tearDown(self):
        os.chdir(self._cwd)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_register_then_login_succeeds(self):
        vault.register("alice", "correct-horse-battery")
        ok, key = vault.login("alice", "correct-horse-battery")
        self.assertTrue(ok)
        self.assertIsNotNone(key)

    def test_login_wrong_password_fails(self):
        vault.register("alice", "correct-horse-battery")
        ok, key = vault.login("alice", "wrong-password")
        self.assertFalse(ok)
        self.assertIsNone(key)

    def test_duplicate_registration_rejected(self):
        vault.register("alice", "correct-horse-battery")
        with self.assertRaises(ValueError):
            vault.register("alice", "another-password")

    def test_same_password_different_users_get_different_hashes(self):
        vault.register("alice", "shared-password")
        vault.register("bob", "shared-password")
        alice = vault.get_user_record("alice")
        bob = vault.get_user_record("bob")
        self.assertNotEqual(alice["salt"], bob["salt"])
        self.assertNotEqual(alice["hash"], bob["hash"])

    def test_file_roundtrip_encrypt_decrypt(self):
        key = vault.register("alice", "correct-horse-battery")
        token = vault.encrypt(b"hello vault", key)
        vault.save_encrypted_file("alice", "note.txt", token)
        loaded = vault.load_encrypted_file("alice", "note.txt")
        self.assertEqual(vault.decrypt(loaded, key), b"hello vault")

    def test_other_users_key_cannot_decrypt(self):
        alice_key = vault.register("alice", "alice-password")
        bob_key = vault.register("bob", "bob-password")
        token = vault.encrypt(b"secret", alice_key)
        vault.save_encrypted_file("alice", "note.txt", token)
        loaded = vault.load_encrypted_file("alice", "note.txt")
        with self.assertRaises(Exception):
            vault.decrypt(loaded, bob_key)

    def test_list_and_delete_file(self):
        key = vault.register("alice", "correct-horse-battery")
        token = vault.encrypt(b"data", key)
        vault.save_encrypted_file("alice", "a.txt", token)
        self.assertIn("a.txt", vault.list_files("alice"))
        self.assertTrue(vault.delete_file("alice", "a.txt"))
        self.assertNotIn("a.txt", vault.list_files("alice"))
        self.assertFalse(vault.delete_file("alice", "a.txt"))


class StrengthTests(unittest.TestCase):
    def test_weak_password_scores_low(self):
        self.assertLess(check_strength("password"), 6)

    def test_strong_password_scores_high(self):
        self.assertGreaterEqual(check_strength("Tr0ub4dor&3xyz"), 6)


if __name__ == "__main__":
    unittest.main()
