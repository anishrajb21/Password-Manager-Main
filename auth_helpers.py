"""Small, shared filesystem helpers for private atomic writes."""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")


def ensure_data_dir() -> None:
    os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass


def secure_file(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def atomic_write_bytes(path: str, content: bytes) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".tmp-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        secure_file(temp_path)
        os.replace(temp_path, path)
        secure_file(path)
        # Persist the rename itself across a sudden power loss where supported.
        if os.name == "posix":
            try:
                dir_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def atomic_write_json(path: str, value: Any) -> None:
    payload = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_bytes(path, payload)
