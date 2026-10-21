import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import auth
import auth_helpers
import crypto
import generator
import manager
from cryptography.fernet import Fernet


class PasswordManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = os.path.join(self.temp.name, "data")
        os.makedirs(self.data)
        self.auth_file = os.path.join(self.data, ".auth")
        self.key_file = os.path.join(self.data, ".key")
        self.vault_file = os.path.join(self.data, ".vault.json")
        self.patches = [
            patch.object(auth, "DATA_DIR", self.data),
            patch.object(auth, "AUTH_FILE", self.auth_file),
            patch.object(auth, "VAULT_FILE", self.vault_file),
            patch.object(auth, "PENDING_CHANGE_FILE", os.path.join(self.data, ".password-change.pending")),
            patch.object(auth, "KEY_FILE", self.key_file),
            patch.object(crypto, "DATA_DIR", self.data),
            patch.object(crypto, "KEY_FILE", self.key_file),
            patch.object(manager, "DATA_DIR", self.data),
            patch.object(manager, "VAULT_FILE", self.vault_file),
            patch.object(auth_helpers, "DATA_DIR", self.data),
        ]
        for item in self.patches:
            item.start()
        crypto.clear_active_key()

    def tearDown(self):
        crypto.clear_active_key()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def create_v2_user(self, password="correct horse battery staple 2026"):
        record, key = auth._make_auth(password)
        auth_helpers.atomic_write_json(self.auth_file, record)
        auth_helpers.atomic_write_json(self.vault_file, {"version": 2, "entries": {}})
        return password, key

    def test_first_time_setup_creates_auth_and_empty_vault(self):
        password = "a sufficiently long master passphrase"
        with patch.object(auth.getpass, "getpass", side_effect=[password, password]):
            auth.setup_password()
        self.assertTrue(os.path.isfile(self.auth_file))
        self.assertTrue(os.path.isfile(self.vault_file))
        with open(self.vault_file, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"version": 2, "entries": {}})
        crypto.clear_active_key()
        self.assertTrue(auth.authenticate_password(password))

    def test_password_generator_uses_allowed_length_and_charset(self):
        value = generator.generate_password(32)
        self.assertEqual(len(value), 32)
        allowed = set(__import__("string").ascii_letters + __import__("string").digits + generator.SPECIALS)
        self.assertTrue(set(value) <= allowed)

    def test_password_generator_rejects_unsafe_lengths_and_types(self):
        for value in (0, 4, 11, 129, True, "16"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                generator.generate_password(value)

    def test_v2_authentication_and_vault_crud(self):
        password, _ = self.create_v2_user()
        self.assertTrue(auth.authenticate_password(password))
        manager.save_password("Example", "alice", "S3cure-value!")
        self.assertEqual(manager._decrypt("Example", "alice"), "S3cure-value!")
        self.assertFalse(manager.update_password("Missing", "alice", "not-added"))
        self.assertNotIn("Missing", manager.load_data())

    def test_wrong_master_password_does_not_migrate_or_change_auth(self):
        legacy_password = "legacy-pass"
        old_key = Fernet.generate_key()
        with open(self.auth_file, "w", encoding="utf-8") as f:
            f.write(hashlib.sha256(legacy_password.encode()).hexdigest())
        with open(self.key_file, "wb") as f:
            f.write(old_key)
        with open(self.vault_file, "w", encoding="utf-8") as f:
            json.dump({"Example": {"alice": Fernet(old_key).encrypt(b"secret").decode()}}, f)
        with open(self.auth_file, "rb") as f:
            before = f.read()
        self.assertFalse(auth.authenticate_password("wrong password"))
        with open(self.auth_file, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertTrue(os.path.exists(self.key_file))

    def test_missing_legacy_key_does_not_modify_auth_or_vault(self):
        password = "legacy-pass"
        with open(self.auth_file, "w", encoding="utf-8") as f:
            f.write(hashlib.sha256(password.encode()).hexdigest())
        with open(self.vault_file, "w", encoding="utf-8") as f:
            json.dump({"Example": {"alice": "encrypted-token"}}, f)
        with open(self.auth_file, "rb") as f:
            old_auth = f.read()
        with open(self.vault_file, "rb") as f:
            old_vault = f.read()
        with self.assertRaises(FileNotFoundError):
            auth.authenticate_password(password)
        with open(self.auth_file, "rb") as f:
            self.assertEqual(f.read(), old_auth)
        with open(self.vault_file, "rb") as f:
            self.assertEqual(f.read(), old_vault)
        self.assertFalse(os.path.exists(self.key_file))

    def test_legacy_vault_migrates_and_preserves_plaintext(self):
        password = "legacy-pass"
        old_key = Fernet.generate_key()
        old_fernet = Fernet(old_key)
        with open(self.auth_file, "w", encoding="utf-8") as f:
            f.write(hashlib.sha256(password.encode()).hexdigest())
        with open(self.key_file, "wb") as f:
            f.write(old_key)
        old_entries = {"Example": {"alice": old_fernet.encrypt(b"old-secret").decode()}}
        with open(self.vault_file, "w", encoding="utf-8") as f:
            json.dump(old_entries, f)
        self.assertTrue(auth.authenticate_password(password))
        with open(self.vault_file, encoding="utf-8") as f:
            migrated = json.load(f)
        self.assertEqual(migrated["version"], 2)
        self.assertEqual(manager._decrypt("Example", "alice"), "old-secret")
        self.assertFalse(os.path.exists(self.key_file))
        self.assertTrue(any(name.startswith("legacy-backup-") for name in os.listdir(self.data)))

    def test_corrupt_vault_is_not_silently_reset(self):
        self.create_v2_user()
        with open(self.vault_file, "w", encoding="utf-8") as f:
            f.write("{ definitely not json")
        with self.assertRaises(RuntimeError):
            manager.load_data()
        with open(self.vault_file, encoding="utf-8") as f:
            self.assertEqual(f.read(), "{ definitely not json")

    def test_missing_v2_vault_fails_closed(self):
        password, _ = self.create_v2_user()
        os.remove(self.vault_file)
        with self.assertRaisesRegex(RuntimeError, "Vault file is missing"):
            auth.authenticate_password(password)
        self.assertFalse(os.path.exists(self.vault_file))

    def test_first_time_setup_refuses_orphaned_vault_data(self):
        with open(self.vault_file, "w", encoding="utf-8") as f:
            json.dump({"Example": {"alice": "encrypted-token"}}, f)
        with patch.object(auth.getpass, "getpass", side_effect=AssertionError("must not prompt")):
            with self.assertRaisesRegex(RuntimeError, "Existing vault/key/recovery data"):
                auth.setup_password()
        self.assertFalse(os.path.exists(self.auth_file))
        with open(self.vault_file, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"Example": {"alice": "encrypted-token"}})

    def test_vault_operations_require_unlock(self):
        self.create_v2_user()
        crypto.clear_active_key()
        with self.assertRaises(RuntimeError):
            manager.save_password("Example", "alice", "secret")

    def test_missing_vault_fails_closed_during_operations(self):
        self.create_v2_user()
        password = "correct horse battery staple 2026"
        self.assertTrue(auth.authenticate_password(password))
        os.remove(self.vault_file)
        with self.assertRaisesRegex(RuntimeError, "Vault file is missing"):
            manager.load_data()
        self.assertFalse(os.path.exists(self.vault_file))

    def test_update_rejects_empty_password(self):
        self.create_v2_user()
        auth.authenticate_password("correct horse battery staple 2026")
        manager.save_password("Example", "alice", "existing-secret")
        with self.assertRaisesRegex(ValueError, "Password cannot be empty"):
            manager.update_password("Example", "alice", "")
        self.assertEqual(manager._decrypt("Example", "alice"), "existing-secret")


    def test_master_password_change_reencrypts_vault(self):
        old_password, _ = self.create_v2_user()
        self.assertTrue(auth.authenticate_password(old_password))
        manager.save_password("Example", "alice", "preserve-me")
        new_password = "a new much longer master passphrase 2026"
        with patch.object(auth.getpass, "getpass", side_effect=[old_password, new_password, new_password]):
            auth.change_master_password()
        self.assertFalse(auth.authenticate_password(old_password))
        self.assertTrue(auth.authenticate_password(new_password))
        self.assertEqual(manager._decrypt("Example", "alice"), "preserve-me")

    def test_interrupted_password_change_can_be_recovered_with_new_password(self):
        old_password, _ = self.create_v2_user()
        self.assertTrue(auth.authenticate_password(old_password))
        manager.save_password("Example", "alice", "recover-me")
        with open(self.auth_file, encoding="utf-8") as f:
            old_auth = json.load(f)
        with open(self.vault_file, encoding="utf-8") as f:
            old_vault = json.load(f)
        new_password = "brand new master password phrase 2026"
        new_auth, new_key = auth._make_auth(new_password)
        new_entries = auth._encrypt_entries({"Example": {"alice": "recover-me"}}, new_key)
        new_vault = {"version": 2, "entries": new_entries}
        auth_helpers.atomic_write_json(auth.PENDING_CHANGE_FILE, {
            "version": 1, "old_auth": old_auth, "new_auth": new_auth,
            "old_vault": old_vault, "new_vault": new_vault,
        })
        self.assertTrue(auth.authenticate_password(new_password))
        self.assertFalse(os.path.exists(auth.PENDING_CHANGE_FILE))
        self.assertEqual(manager._decrypt("Example", "alice"), "recover-me")

    def test_auth_file_permissions_are_restricted_on_posix(self):
        password, _ = self.create_v2_user()
        auth.authenticate_password(password)
        auth_helpers.atomic_write_json(self.auth_file, auth._make_auth(password)[0])
        if os.name == "posix":
            self.assertEqual(os.stat(self.auth_file).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
