#!/usr/bin/env python3
"""Native Messaging bridge for the trusted browser extension.

Never prints secrets or diagnostics to stdout; stdout is reserved for framed JSON.
The host is installed with an exact extension origin in its native-host manifest.
"""
from __future__ import annotations

import contextlib
import json
import os
import struct
import sys
import time
from urllib.parse import urlparse

import auth
import backup
import crypto
import e2e_sync
import generator
import manager

HOST_IDLE_TIMEOUT = 300
MAX_MESSAGE = 1024 * 1024
_last_activity = time.monotonic()


def _read_message():
    header = sys.stdin.buffer.read(4)
    if not header: return None
    if len(header) != 4: raise ValueError("Invalid native messaging frame")
    size = struct.unpack("=I", header)[0]
    if size > MAX_MESSAGE: raise ValueError("Native messaging request too large")
    raw = sys.stdin.buffer.read(size)
    if len(raw) != size: raise ValueError("Truncated native messaging frame")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict): raise TypeError("Request must be a JSON object")
    return value


def _write_message(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(raw)) + raw); sys.stdout.buffer.flush()


def _origin_tuple(value):
    parsed = urlparse(value if isinstance(value, str) else "")
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password: return None
    try: port = parsed.port
    except ValueError: return None
    return parsed.scheme.casefold(), parsed.hostname.casefold().rstrip("."), port or (443 if parsed.scheme == "https" else 80)


def _require_unlocked(request_id):
    global _last_activity
    if crypto._active_key is None: return {"id": request_id, "ok": False, "error": "Vault is locked. Unlock again."}
    if time.monotonic() - _last_activity >= HOST_IDLE_TIMEOUT:
        crypto.clear_active_key(); return {"id": request_id, "ok": False, "error": "Native vault session expired. Unlock again."}
    _last_activity = time.monotonic()
    return None


def _records_public(records):
    return [{k: r.get(k) for k in ("platform", "username", "category", "tags", "url")} for r in records]


def handle(request):
    global _last_activity
    request_id, action = request.get("id"), request.get("action")
    if not isinstance(request_id, (int, str)) or action not in {
        "unlock", "lock", "list", "search", "site_search", "get", "add", "generate",
        "update_password", "delete", "update_metadata", "reveal", "health", "change_master",
        "backup", "restore", "sync_push", "sync_pull", "sync_status", "devices", "revoke_device"
    }: raise ValueError("Invalid request")
    if action == "unlock":
        password = request.get("master_password")
        if not isinstance(password, str) or not password: return {"id": request_id, "ok": False, "error": "Master password is required."}
        crypto.clear_active_key()
        try:
            with contextlib.redirect_stdout(sys.stderr): ok = auth.authenticate_password(password)
        except Exception as exc:  # noqa: BLE001
            crypto.clear_active_key(); return {"id": request_id, "ok": False, "error": f"Vault unlock failed safely: {type(exc).__name__}."}
        _last_activity = time.monotonic()
        return {"id": request_id, "ok": bool(ok), "error": None if ok else "Incorrect master password or invalid vault."}
    if action == "lock":
        crypto.clear_active_key(); return {"id": request_id, "ok": True}
    # A fresh device must be able to bootstrap by decrypting a remote snapshot
    # with the supplied master password before a local auth file exists.
    if action != "sync_pull" or crypto._active_key is not None:
        locked = _require_unlocked(request_id)
        if locked: return locked
    try:
        if action == "list": return {"id": request_id, "ok": True, "records": _records_public(manager.list_records())}
        if action == "search":
            if request.get("origin"):
                if _origin_tuple(request.get("origin")) is None: return {"id": request_id, "ok": False, "error": "Invalid page origin."}
                candidates = manager.records_for_origin(request["origin"])
                return {"id": request_id, "ok": True, "credentials": [{"platform": r["platform"], "username": r["username"], "category": r["category"]} for r in candidates]}
            records = manager.search_records(str(request.get("query", ""))[:256], category=str(request.get("category", ""))[:256], tag=str(request.get("tag", ""))[:64])
            return {"id": request_id, "ok": True, "records": _records_public(records)}
        if action == "site_search":
            origin = request.get("origin", "")
            if _origin_tuple(origin) is None: return {"id": request_id, "ok": False, "error": "Invalid page origin."}
            candidates = manager.records_for_origin(origin)
            return {"id": request_id, "ok": True, "credentials": [{"platform": r["platform"], "username": r["username"], "category": r["category"]} for r in candidates]}
        if action == "reveal":
            platform, username = request.get("platform"), request.get("username")
            if not any(r["platform"] == platform and r["username"] == username for r in manager.list_records()):
                return {"id": request_id, "ok": False, "error": "Credential not found."}
            return {"id": request_id, "ok": True, "password": manager._decrypt(platform, username)}
        if action == "get":
            origin = request.get("origin", "")
            if _origin_tuple(origin) is None: return {"id": request_id, "ok": False, "error": "Invalid page origin."}
            platform, username = request.get("platform"), request.get("username")
            match = next((r for r in manager.records_for_origin(origin) if r["platform"] == platform and r["username"] == username), None)
            if match is None: return {"id": request_id, "ok": False, "error": "No credential is saved for this exact website origin."}
            return {"id": request_id, "ok": True, "credential": {"platform": platform, "username": username, "password": manager._decrypt(platform, username)}}
        if action == "generate": return {"id": request_id, "ok": True, "password": generator.generate_password(int(request.get("length", 20)))}
        if action == "add":
            manager.save_password(request.get("platform", ""), request.get("username", ""), request.get("password", ""), category=request.get("category", "Other"), tags=request.get("tags", []), url=request.get("url", ""))
            return {"id": request_id, "ok": True}
        if action == "update_password":
            ok = manager.update_password(request.get("platform", ""), request.get("username", ""), request.get("password", ""))
            return {"id": request_id, "ok": bool(ok), "error": None if ok else "Credential not found."}
        if action == "delete":
            platform, username = request.get("platform", ""), request.get("username", "")
            if not any(r["platform"] == platform and r["username"] == username for r in manager.list_records()): return {"id": request_id, "ok": False, "error": "Credential not found."}
            with contextlib.redirect_stdout(sys.stderr): manager.delete_user(platform, username)
            return {"id": request_id, "ok": True}
        if action == "update_metadata":
            ok = manager.update_metadata(request.get("platform", ""), request.get("username", ""), category=request.get("category"), tags=request.get("tags"), url=request.get("url"))
            return {"id": request_id, "ok": bool(ok), "error": None if ok else "Credential not found."}
        if action == "health": return {"id": request_id, "ok": True, "report": manager.password_health_report()}
        if action == "change_master":
            current, new = request.get("current_password"), request.get("new_password")
            auth.change_master_password_values(current, new)
            return {"id": request_id, "ok": True, "message": "Master password changed locally. Sync the new encrypted snapshot to update other devices."}
        if action == "backup":
            path = request.get("path") or os.path.join(auth.DATA_DIR, "password-manager-backup.pmbak")
            result = backup.create_backup(path, request.get("backup_passphrase", ""))
            return {"id": request_id, "ok": True, "path": result}
        if action == "restore":
            result = backup.restore_backup(request.get("path", ""), request.get("backup_passphrase", ""), request.get("master_password", ""))
            return {"id": request_id, "ok": True, "rollback_path": result, "message": "Backup restored. Restart/unlock with the restored master password."}
        if action == "sync_status":
            client = e2e_sync.SupabaseSyncClient.from_env(); row = client.pull()
            return {"id": request_id, "ok": True, "configured": True, "remote_revision": row.get("revision") if row else None, "has_remote_vault": bool(row)}
        if action == "devices":
            devices = e2e_sync.SupabaseSyncClient.from_env().list_devices()
            return {"id": request_id, "ok": True, "devices": devices}
        if action == "revoke_device":
            result = e2e_sync.SupabaseSyncClient.from_env().revoke_device(request.get("device_id", ""))
            return {"id": request_id, "ok": True, "devices": result, "message": "Device session revoked for future sync requests. Sign out/revoke its Supabase session too if lost or compromised."}
        if action == "sync_push":
            vault_id = os.environ.get("PM_SYNC_VAULT_ID", "")
            client = e2e_sync.SupabaseSyncClient.from_env()
            remote = client.pull()
            revision = (remote["revision"] + 1) if remote else 1
            envelope = e2e_sync.current_envelope(vault_id, revision)
            try: row = client.push(envelope)
            except e2e_sync.SyncConflict:
                path = e2e_sync.save_conflict_copy(envelope, "local")
                raise e2e_sync.SyncConflict(f"Sync conflict. Local encrypted snapshot saved to {path}; pull and reconcile before retrying.")
            return {"id": request_id, "ok": True, "revision": row.get("revision"), "message": "Encrypted vault snapshot synchronized."}
        if action == "sync_pull":
            client = e2e_sync.SupabaseSyncClient.from_env(); row = client.pull()
            if not row: return {"id": request_id, "ok": False, "error": "No remote vault exists yet. Push from the device that has the correct vault."}
            master = request.get("master_password", "")
            local_snapshot = None
            if crypto._active_key is not None and os.path.isfile(auth.AUTH_FILE) and os.path.isfile(auth.VAULT_FILE):
                local_snapshot = e2e_sync.save_conflict_copy(e2e_sync.current_envelope(os.environ.get("PM_SYNC_VAULT_ID", "")), "pre-pull-local")
            rollback = e2e_sync.apply_remote_envelope(row["encrypted_payload"], master, os.environ.get("PM_SYNC_VAULT_ID", ""), row.get("revision"))
            return {"id": request_id, "ok": True, "revision": row.get("revision"), "rollback_path": rollback, "local_snapshot": local_snapshot, "message": "Remote snapshot verified and applied. Previous local files preserved where present."}
    except Exception as exc:  # noqa: BLE001
        return {"id": request_id, "ok": False, "error": str(exc)[:500] if isinstance(exc, (ValueError, RuntimeError, OSError)) else f"Request failed safely: {type(exc).__name__}."}
    return {"id": request_id, "ok": False, "error": "Unsupported action."}


def main():
    while True:
        try:
            request = _read_message()
            if request is None: break
            try: response = handle(request)
            except Exception as exc: response = {"id": request.get("id"), "ok": False, "error": f"Request failed safely: {type(exc).__name__}."}  # noqa: BLE001
            _write_message(response)
        except Exception as exc:  # noqa: BLE001
            print(f"native host protocol error: {type(exc).__name__}", file=sys.stderr); break
    crypto.clear_active_key()

if __name__ == "__main__": main()
