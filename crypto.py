"""Cryptographic primitives for the local password manager.

Vault encryption uses Fernet (AES-128-CBC + HMAC-SHA256) with a 32-byte
key derived from the master password using Argon2id. The derived key is held
in process memory only while the vault is unlocked.
"""
from __future__ import annotations

import base64
import os
import sys
from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEY_FILE = os.path.join(DATA_DIR, ".key")  # legacy only; never create a new key file
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 64 * 1024
ARGON2_PARALLELISM = 2
KEY_LENGTH = 32
_active_key: bytes | None = None


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a master password and salt."""
    if not isinstance(password, str) or not password:
        raise ValueError("Master password cannot be empty.")
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw)


def set_active_key(key: bytes | None) -> None:
    """Unlock or lock the vault for this process."""
    global _active_key
    _active_key = key


def clear_active_key() -> None:
    set_active_key(None)


def get_fernet() -> Fernet:
    if _active_key is None:
        raise RuntimeError("Vault is locked. Authenticate first.")
    return Fernet(_active_key)


def legacy_fernet() -> Fernet:
    """Load the old standalone key only for one-time migration."""
    if not os.path.isfile(KEY_FILE):
        raise FileNotFoundError(
            "Legacy encryption key is missing. Do not reset it; restore data/.key from backup."
        )
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read().strip()
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise ValueError("Legacy encryption key is invalid; vault was not changed.") from exc
