"""Password-protected encrypted backup and validated restore for the local vault."""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import time

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken

import auth
import crypto
import manager
from auth_helpers import atomic_write_json, ensure_data_dir, secure_file

BACKUP_VERSION = 1
BACKUP_TIME_COST = 3
BACKUP_MEMORY_KIB = 65536
BACKUP_PARALLELISM = 2
RESTORE_PENDING_FILE = os.path.join(auth.DATA_DIR, ".restore.pending")


def _derive_backup_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or len(password) < 12: raise ValueError("Backup passphrase must be at least 12 characters.")
    raw = hash_secret_raw(password.encode(), salt, time_cost=BACKUP_TIME_COST, memory_cost=BACKUP_MEMORY_KIB, parallelism=BACKUP_PARALLELISM, hash_len=32, type=Type.ID)
    return base64.urlsafe_b64encode(raw)


def create_backup(path: str, backup_passphrase: str) -> str:
    if not crypto.get_fernet(): raise RuntimeError("Unlock the vault before creating a backup.")
    ensure_data_dir()
    if os.path.exists(path): raise FileExistsError("Backup path already exists; choose a new filename to avoid overwriting a recovery point.")
    with open(auth.AUTH_FILE, encoding="utf-8") as f: auth_record = json.load(f)
    with open(manager.VAULT_FILE, encoding="utf-8") as f: vault = json.load(f)
    salt = secrets.token_bytes(16)
    key = _derive_backup_key(backup_passphrase, salt)
    payload = json.dumps({"version": BACKUP_VERSION, "created_at": int(time.time()), "auth": auth_record, "vault": vault}, separators=(",", ":")).encode()
    envelope = {"format": "password-manager-encrypted-backup", "version": BACKUP_VERSION, "kdf": "argon2id", "salt": base64.b64encode(salt).decode(), "time_cost": BACKUP_TIME_COST, "memory_cost_kib": BACKUP_MEMORY_KIB, "parallelism": BACKUP_PARALLELISM, "ciphertext": Fernet(key).encrypt(payload).decode()}
    parent = os.path.dirname(os.path.abspath(path)); os.makedirs(parent, exist_ok=True)
    from auth_helpers import atomic_write_json as write_json
    write_json(path, envelope); return os.path.abspath(path)


def _decode_backup(path: str, backup_passphrase: str) -> tuple[dict, dict]:
    try:
        with open(path, encoding="utf-8") as f: env = json.load(f)
        if not isinstance(env, dict) or env.get("format") != "password-manager-encrypted-backup" or env.get("version") != BACKUP_VERSION or env.get("kdf") != "argon2id": raise ValueError
        salt = base64.b64decode(env["salt"], validate=True)
        if len(salt) != 16: raise ValueError
        key = _derive_backup_key(backup_passphrase, salt)
        payload = json.loads(Fernet(key).decrypt(env["ciphertext"].encode()).decode())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, InvalidToken) as exc:
        raise RuntimeError("Backup could not be authenticated or parsed. No files were changed; check the passphrase and backup integrity.") from exc
    if not isinstance(payload, dict) or payload.get("version") != BACKUP_VERSION: raise RuntimeError("Unsupported backup payload; no files were changed.")
    record, vault = payload.get("auth"), payload.get("vault")
    if not isinstance(record, dict) or not isinstance(vault, dict) or vault.get("version") != 2 or not isinstance(vault.get("entries"), dict): raise RuntimeError("Backup contents are invalid; no files were changed.")
    # The encrypted vault is validated against the embedded auth record when the user supplies the master password.
    try:
        salt_auth = base64.b64decode(record["salt"], validate=True)
        if len(salt_auth) < 16 or record.get("kdf") != "argon2id": raise ValueError
        # Auth record alone cannot recover the derived key; decryptability is validated after the user supplies the master password on restore.
    except (KeyError, ValueError, TypeError) as exc: raise RuntimeError("Backup authentication metadata is invalid; no files were changed.") from exc
    return record, vault


def _validate_with_master(record: dict, vault: dict, master_password: str) -> None:
    key = auth._verify_v2(master_password, record)
    if key is None: raise RuntimeError("Master password does not match this backup. No files were changed.")
    fernet = Fernet(key)
    try:
        for platform, users in vault["entries"].items():
            if not isinstance(platform, str) or not platform.strip() or not isinstance(users, dict): raise ValueError
            for username, token in users.items():
                if not isinstance(username, str) or not username.strip() or not isinstance(token, str) or not token: raise ValueError
                plain = fernet.decrypt(token.encode()).decode("utf-8")
                try: decoded = json.loads(plain)
                except json.JSONDecodeError: decoded = plain
                if not isinstance(decoded, str) and (not isinstance(decoded, dict) or not isinstance(decoded.get("password"), str)): raise TypeError
    except (InvalidToken, UnicodeError, ValueError, AttributeError) as exc: raise RuntimeError("Backup vault integrity validation failed. No files were changed.") from exc


def restore_backup(path: str, backup_passphrase: str, master_password: str) -> str:
    record, vault = _decode_backup(path, backup_passphrase)
    _validate_with_master(record, vault, master_password)
    ensure_data_dir()
    # Capture current encrypted files; journal allows startup recovery if power is lost mid-restore.
    old_auth = old_vault = None
    if os.path.isfile(auth.AUTH_FILE):
        with open(auth.AUTH_FILE, encoding="utf-8") as f: old_auth = json.load(f)
    if os.path.isfile(manager.VAULT_FILE):
        with open(manager.VAULT_FILE, encoding="utf-8") as f: old_vault = json.load(f)
    rollback = os.path.join(auth.DATA_DIR, f"pre-restore-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}")
    os.makedirs(rollback, mode=0o700, exist_ok=False)
    for source in (auth.AUTH_FILE, manager.VAULT_FILE):
        if os.path.isfile(source):
            target = os.path.join(rollback, os.path.basename(source)); shutil.copy2(source, target); secure_file(target)
    journal = {"version": 1, "old_auth": old_auth, "old_vault": old_vault, "new_auth": record, "new_vault": vault}
    atomic_write_json(RESTORE_PENDING_FILE, journal)
    try:
        atomic_write_json(manager.VAULT_FILE, vault)
        atomic_write_json(auth.AUTH_FILE, record)
        os.remove(RESTORE_PENDING_FILE)
    except Exception:
        # Roll back best-effort for ordinary exceptions. The journal handles process/power interruption.
        if old_vault is not None: atomic_write_json(manager.VAULT_FILE, old_vault)
        if old_auth is not None: atomic_write_json(auth.AUTH_FILE, old_auth)
        try: os.remove(RESTORE_PENDING_FILE)
        except OSError: pass
        raise
    crypto.clear_active_key()
    return rollback
