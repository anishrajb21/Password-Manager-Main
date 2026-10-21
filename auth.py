"""Master-password authentication and safe migration from the legacy format."""
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import sys
import secrets
import shutil
import time
from typing import Any

from cryptography.fernet import InvalidToken
from auth_helpers import atomic_write_bytes, atomic_write_json, ensure_data_dir, secure_file
from crypto import (
    DATA_DIR,
    KEY_FILE,
    derive_key,
    legacy_fernet,
    set_active_key,
)

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
AUTH_FILE = os.path.join(DATA_DIR, ".auth")
VAULT_FILE = os.path.join(DATA_DIR, ".vault.json")
PENDING_CHANGE_FILE = os.path.join(DATA_DIR, ".password-change.pending")
RESTORE_PENDING_FILE = os.path.join(DATA_DIR, ".restore.pending")
AUTH_VERSION = 2
VERIFIER_CONTEXT = b"password-manager-master-password-verifier-v2"
MIN_MASTER_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    """Legacy SHA-256 verifier, retained only to identify old installations."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _verifier(key: bytes) -> str:
    import base64
    raw_key = base64.urlsafe_b64decode(key)
    return hmac.new(raw_key, VERIFIER_CONTEXT, hashlib.sha256).hexdigest()


def _make_auth(password: str, salt: bytes | None = None) -> tuple[dict[str, Any], bytes]:
    import base64

    salt = salt or secrets.token_bytes(16)
    key = derive_key(password, salt)
    record = {
        "version": AUTH_VERSION,
        "kdf": "argon2id",
        "salt": base64.b64encode(salt).decode("ascii"),
        "time_cost": 3,
        "memory_cost_kib": 65536,
        "parallelism": 2,
        "verifier": _verifier(key),
    }
    return record, key


def _read_auth() -> dict[str, Any] | None:
    if not os.path.exists(AUTH_FILE):
        return None
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            value = json.load(f)
        if isinstance(value, dict) and value.get("version") == AUTH_VERSION and value.get("kdf") == "argon2id":
            return value
        return None
    except (OSError, json.JSONDecodeError):
        return None


def _is_legacy_auth() -> bool:
    if not os.path.isfile(AUTH_FILE):
        return False
    try:
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
        return len(content) == 64 and all(c in "0123456789abcdefABCDEF" for c in content)
    except OSError:
        return False


def _backup_legacy_files() -> str:
    """Create a private, timestamped rollback copy before migration."""
    ensure_data_dir()
    backup_dir = os.path.join(DATA_DIR, f"legacy-backup-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}")
    os.makedirs(backup_dir, mode=0o700, exist_ok=False)
    for path in (AUTH_FILE, KEY_FILE, VAULT_FILE):
        if os.path.isfile(path):
            destination = os.path.join(backup_dir, os.path.basename(path))
            shutil.copy2(path, destination)
            secure_file(destination)
    try:
        os.chmod(backup_dir, 0o700)
    except OSError:
        pass
    return backup_dir


def _read_legacy_entries() -> dict[str, dict[str, str]]:
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            old = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Legacy vault is unreadable. No migration was performed.") from exc
    if not isinstance(old, dict):
        raise RuntimeError("Legacy vault structure is invalid. No migration was performed.")
    # Already migrated format.
    if old.get("version") == 2 and isinstance(old.get("entries"), dict):
        return old["entries"]
    for platform, users in old.items():
        if not isinstance(platform, str) or not isinstance(users, dict):
            raise RuntimeError("Legacy vault structure is invalid. No migration was performed.")
        if any(not isinstance(user, str) or not isinstance(token, str) for user, token in users.items()):
            raise RuntimeError("Legacy vault structure is invalid. No migration was performed.")
    return old


def _decrypt_legacy_entries(entries: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    if not entries:
        return {}
    old_fernet = legacy_fernet()
    plaintext: dict[str, dict[str, str]] = {}
    try:
        for platform, users in entries.items():
            plaintext[platform] = {}
            for username, token in users.items():
                plaintext[platform][username] = old_fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise RuntimeError(
            "A legacy vault entry could not be decrypted. No migration was performed; restore the original key/vault pair."
        ) from exc
    return plaintext


def _encrypt_entries(entries: dict[str, dict[str, str]], key: bytes) -> dict[str, dict[str, str]]:
    from cryptography.fernet import Fernet

    fernet = Fernet(key)
    return {
        platform: {
            username: fernet.encrypt(password.encode("utf-8")).decode("ascii")
            for username, password in users.items()
        }
        for platform, users in entries.items()
    }


def _write_vault_v2(entries: dict[str, dict[str, str]]) -> None:
    atomic_write_json(VAULT_FILE, {"version": 2, "entries": entries})


def _ensure_vault_v2(password: str, key: bytes) -> None:
    """Finish a migration interrupted after the new auth record was written."""
    if not os.path.exists(VAULT_FILE):
        # A missing vault is ambiguous: it may be an interrupted first-time
        # setup, but it may also be accidental deletion of real credentials.
        # Never silently replace it with an empty vault. Restore the matching
        # backup set or recover the interrupted operation explicitly.
        raise RuntimeError(
            "Vault file is missing. Refusing to create an empty vault; "
            "restore data/.vault.json from a matching backup before continuing."
        )
    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as f:
            vault = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Vault is unreadable. It has not been overwritten.") from exc
    if isinstance(vault, dict) and vault.get("version") == 2 and isinstance(vault.get("entries"), dict):
        # A leftover legacy key is no longer needed after the v2 vault is durable.
        if os.path.isfile(KEY_FILE):
            try:
                os.remove(KEY_FILE)
            except OSError:
                pass
        return
    # If this is a legacy vault, preserve a rollback copy before touching it.
    if os.path.isfile(KEY_FILE):
        _backup_legacy_files()
        legacy_entries = _read_legacy_entries()
        plaintext = _decrypt_legacy_entries(legacy_entries)
        _write_vault_v2(_encrypt_entries(plaintext, key))
        try:
            os.remove(KEY_FILE)
        except OSError:
            pass
        return
    raise RuntimeError(
        "Vault format is not recognized and the legacy key is missing. No data was overwritten."
    )


def setup_password() -> None:
    ensure_data_dir()
    if os.path.exists(AUTH_FILE):
        raise RuntimeError("Authentication file already exists; refusing to overwrite it.")
    if os.path.exists(VAULT_FILE) or os.path.exists(KEY_FILE) or os.path.exists(PENDING_CHANGE_FILE) or os.path.exists(RESTORE_PENDING_FILE):
        raise RuntimeError(
            "Existing vault/key/recovery data was found without an authentication file. "
            "Refusing first-time setup to prevent data loss; restore the matching data files or move them aside only after making a backup."
        )
    while True:
        pwd1 = getpass.getpass("Set Master Password (12+ characters recommended): ")
        pwd2 = getpass.getpass("Confirm Master Password: ")
        if pwd1 != pwd2:
            print("Passwords do not match.\n")
        elif len(pwd1) < MIN_MASTER_PASSWORD_LENGTH:
            print(f"Use at least {MIN_MASTER_PASSWORD_LENGTH} characters.\n")
        else:
            auth_record, key = _make_auth(pwd1)
            atomic_write_json(AUTH_FILE, auth_record)
            if not os.path.exists(VAULT_FILE):
                _write_vault_v2({})
            set_active_key(key)
            print("Master password set.\n")
            return


def _verify_v2(password: str, record: dict[str, Any]) -> bytes | None:
    import base64
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        if len(salt) < 16:
            return None
        key = derive_key(password, salt)
        if hmac.compare_digest(_verifier(key), str(record["verifier"])):
            return key
    except (KeyError, TypeError, ValueError):
        return None
    return None


def _migrate_legacy(password: str) -> bytes:
    # Parse/decrypt everything before writing any new-format files.
    old_entries = _read_legacy_entries()
    plaintext = _decrypt_legacy_entries(old_entries) if old_entries else {}
    backup_dir = _backup_legacy_files()
    auth_record, new_key = _make_auth(password)
    new_vault = {"version": 2, "entries": _encrypt_entries(plaintext, new_key)}
    # The old key is retained until the new vault is durably written. If the
    # process stops between these writes, _ensure_vault_v2() completes it later.
    atomic_write_json(AUTH_FILE, auth_record)
    atomic_write_json(VAULT_FILE, new_vault)
    try:
        os.remove(KEY_FILE)
    except OSError:
        pass
    print(f"Legacy vault migrated. Recovery copy: {backup_dir}")
    print("Keep that backup offline and protected until you verify your entries; then remove it securely.")
    if len(password) < MIN_MASTER_PASSWORD_LENGTH:
        print("Your legacy master password is shorter than the recommended minimum; change it using menu option 6.")
    return new_key


def _recover_pending_password_change(password: str) -> bool | None:
    """Complete or roll back an interrupted master-password rotation.

    The journal contains only encrypted vault snapshots and verifier records,
    never the master password. Either the old or new password can resolve it.
    """
    if not os.path.isfile(PENDING_CHANGE_FILE):
        return None
    try:
        with open(PENDING_CHANGE_FILE, "r", encoding="utf-8") as f:
            journal = json.load(f)
        if not isinstance(journal, dict) or journal.get("version") != 1:
            raise ValueError("Unsupported password-change journal version")
        old_auth = journal["old_auth"]
        new_auth = journal["new_auth"]
        old_vault = journal["old_vault"]
        new_vault = journal["new_vault"]
        for candidate in (old_vault, new_vault):
            if not isinstance(candidate, dict) or candidate.get("version") != 2 or not isinstance(candidate.get("entries"), dict):
                raise ValueError("Invalid vault snapshot in password-change journal")
        old_key = _verify_v2(password, old_auth)
        new_key = _verify_v2(password, new_auth)
        if new_key is not None:
            atomic_write_json(VAULT_FILE, new_vault)
            atomic_write_json(AUTH_FILE, new_auth)
            set_active_key(new_key)
            outcome = "completed"
        elif old_key is not None:
            atomic_write_json(VAULT_FILE, old_vault)
            atomic_write_json(AUTH_FILE, old_auth)
            set_active_key(old_key)
            outcome = "rolled back"
        else:
            return False
        os.remove(PENDING_CHANGE_FILE)
        print(f"Recovered an interrupted master-password change ({outcome}).")
        return True
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "Pending password-change recovery data is invalid. Do not delete it; restore from backup."
        ) from exc


def _recover_pending_restore(password: str) -> bool | None:
    """Resolve an interrupted encrypted-backup restore using either vault's master password."""
    if not os.path.isfile(RESTORE_PENDING_FILE): return None
    try:
        with open(RESTORE_PENDING_FILE, "r", encoding="utf-8") as f: journal = json.load(f)
        if not isinstance(journal, dict) or journal.get("version") != 1: raise ValueError("Unsupported restore journal")
        old_auth, old_vault = journal.get("old_auth"), journal.get("old_vault")
        new_auth, new_vault = journal.get("new_auth"), journal.get("new_vault")
        if not isinstance(new_auth, dict) or not isinstance(new_vault, dict) or new_vault.get("version") != 2 or not isinstance(new_vault.get("entries"), dict): raise ValueError("Invalid new restore snapshot")
        new_key = _verify_v2(password, new_auth)
        old_key = _verify_v2(password, old_auth) if isinstance(old_auth, dict) else None
        if new_key is not None:
            selected_auth, selected_vault, key = new_auth, new_vault, new_key
            outcome = "completed"
        elif old_key is not None and isinstance(old_vault, dict) and old_vault.get("version") == 2:
            selected_auth, selected_vault, key = old_auth, old_vault, old_key
            outcome = "rolled back"
        else:
            return False
        # Validate every encrypted credential before committing a recovery snapshot.
        from cryptography.fernet import Fernet, InvalidToken
        fernet = Fernet(key)
        for platform, users in selected_vault["entries"].items():
            if not isinstance(platform, str) or not platform.strip() or not isinstance(users, dict): raise ValueError("Invalid vault entries")
            for username, token in users.items():
                if not isinstance(username, str) or not username.strip() or not isinstance(token, str) or not token: raise ValueError("Invalid vault credential")
                fernet.decrypt(token.encode("ascii"))
        atomic_write_json(VAULT_FILE, selected_vault)
        atomic_write_json(AUTH_FILE, selected_auth)
        os.remove(RESTORE_PENDING_FILE)
        set_active_key(key)
        print(f"Recovered an interrupted backup restore ({outcome}).")
        return True
    except (OSError, KeyError, TypeError, ValueError, AttributeError, InvalidToken, json.JSONDecodeError) as exc:
        raise RuntimeError("Pending restore recovery data is invalid. Do not delete it; restore the matching encrypted files from backup.") from exc


def _harden_storage_permissions() -> None:
    """Best-effort private permissions for existing sensitive files."""
    ensure_data_dir()
    for path in (AUTH_FILE, VAULT_FILE, KEY_FILE, PENDING_CHANGE_FILE, RESTORE_PENDING_FILE):
        if os.path.isfile(path):
            secure_file(path)


def authenticate_password(password: str) -> bool:
    """Test a password without prompting; useful for automated tests."""
    _harden_storage_permissions()
    restored = _recover_pending_restore(password)
    if restored is not None: return restored
    recovered = _recover_pending_password_change(password)
    if recovered is not None:
        return recovered
    if not os.path.exists(AUTH_FILE):
        return False
    record = _read_auth()
    if record is not None:
        key = _verify_v2(password, record)
        if key is None:
            return False
        _ensure_vault_v2(password, key)
        set_active_key(key)
        return True
    if _is_legacy_auth():
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                stored = f.read().strip().lower()
        except OSError:
            return False
        if not hmac.compare_digest(hash_password(password), stored):
            return False
        key = _migrate_legacy(password)
        set_active_key(key)
        return True
    return False


def verify_password() -> bool:
    if not os.path.exists(AUTH_FILE):
        setup_password()
        return True
    for attempt in range(3):
        pwd = getpass.getpass("Enter Master Password: ")
        try:
            if authenticate_password(pwd):
                return True
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"Unable to unlock safely: {exc}")
            return False
        print(f"Wrong password or invalid authentication data. Attempts left: {2 - attempt}")
    return False


def change_master_password_values(current: str, new_password: str) -> None:
    """Rotate the master password without prompting (for trusted local clients)."""
    if not isinstance(new_password, str) or len(new_password) < MIN_MASTER_PASSWORD_LENGTH:
        raise ValueError(f"New master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters.")
    if not authenticate_password(current):
        raise ValueError("Current master password is incorrect.")
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        old_vault = json.load(f)
    with open(AUTH_FILE, "r", encoding="utf-8") as f:
        old_auth = json.load(f)
    if not isinstance(old_vault, dict) or old_vault.get("version") != 2 or not isinstance(old_vault.get("entries"), dict):
        raise RuntimeError("Vault format is invalid; password was not changed.")
    plaintext = _decrypt_entries_with_key(old_vault["entries"], current)
    new_auth, new_key = _make_auth(new_password)
    new_vault = {"version": 2, "entries": _encrypt_entries(plaintext, new_key)}
    _backup_legacy_files()
    journal = {"version": 1, "old_auth": old_auth, "new_auth": new_auth, "old_vault": old_vault, "new_vault": new_vault}
    atomic_write_json(PENDING_CHANGE_FILE, journal)
    try:
        atomic_write_json(VAULT_FILE, new_vault)
        atomic_write_json(AUTH_FILE, new_auth)
        os.remove(PENDING_CHANGE_FILE)
        set_active_key(new_key)
    except Exception:
        atomic_write_json(VAULT_FILE, old_vault)
        atomic_write_json(AUTH_FILE, old_auth)
        try: os.remove(PENDING_CHANGE_FILE)
        except OSError: pass
        raise


def change_master_password() -> None:
    current = getpass.getpass("Enter current master password: ")
    if not authenticate_password(current):
        print("Current password is incorrect.")
        return
    new1 = getpass.getpass("Enter new master password (12+ characters): ")
    new2 = getpass.getpass("Confirm new master password: ")
    if new1 != new2:
        print("Passwords do not match.")
        return
    if len(new1) < MIN_MASTER_PASSWORD_LENGTH:
        print(f"Use at least {MIN_MASTER_PASSWORD_LENGTH} characters.")
        return

    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        old_vault = json.load(f)
    with open(AUTH_FILE, "r", encoding="utf-8") as f:
        old_auth = json.load(f)
    if not isinstance(old_vault, dict) or old_vault.get("version") != 2 or not isinstance(old_vault.get("entries"), dict):
        raise RuntimeError("Vault format is invalid; password was not changed.")

    plaintext = _decrypt_entries_with_key(old_vault["entries"], current)
    new_auth, new_key = _make_auth(new1)
    new_vault = {"version": 2, "entries": _encrypt_entries(plaintext, new_key)}
    _backup_legacy_files()
    journal = {
        "version": 1,
        "old_auth": old_auth,
        "new_auth": new_auth,
        "old_vault": old_vault,
        "new_vault": new_vault,
    }
    # Persist recovery information before replacing either half of the state.
    # If power is lost, either password can resolve the journal at next startup.
    atomic_write_json(PENDING_CHANGE_FILE, journal)
    try:
        atomic_write_json(VAULT_FILE, new_vault)
        atomic_write_json(AUTH_FILE, new_auth)
        os.remove(PENDING_CHANGE_FILE)
        set_active_key(new_key)
        print("Master password changed and vault entries re-encrypted.")
    except Exception:
        # For ordinary exceptions, restore the original pair. If the process is
        # terminated before this handler runs, the pending journal enables recovery.
        atomic_write_json(VAULT_FILE, old_vault)
        atomic_write_json(AUTH_FILE, old_auth)
        try:
            os.remove(PENDING_CHANGE_FILE)
        except OSError:
            pass
        raise


def _decrypt_entries_with_key(entries: dict[str, dict[str, str]], password: str) -> dict[str, dict[str, str]]:
    import base64
    from cryptography.fernet import Fernet, InvalidToken

    record = _read_auth()
    if record is None:
        raise RuntimeError("Authentication record is invalid.")
    key = _verify_v2(password, record)
    if key is None:
        raise RuntimeError("Current master password verification failed.")
    fernet = Fernet(key)
    output: dict[str, dict[str, str]] = {}
    try:
        for platform, users in entries.items():
            output[platform] = {
                username: fernet.decrypt(token.encode("ascii")).decode("utf-8")
                for username, token in users.items()
            }
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise RuntimeError("Vault authentication failed; no password change was committed.") from exc
    return output
