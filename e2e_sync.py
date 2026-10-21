"""End-to-end encrypted vault snapshots and optimistic-concurrency sync client.

The remote service receives only an authenticated ciphertext envelope. It never
receives the master password or an unwrapped vault key. This module intentionally
uses a small HTTPS/PostgREST adapter so deployments can be tested independently.
"""
from __future__ import annotations
import base64, hmac, json, os, secrets, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import auth, crypto

FORMAT = "password-manager-e2e-vault"
VERSION = 1
MAX_ENVELOPE_BYTES = 20 * 1024 * 1024


def _derive_aead_key(fernet_key: bytes, vault_id: str) -> bytes:
    raw = base64.urlsafe_b64decode(fernet_key)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=vault_id.encode(),
                info=b"password-manager/e2e-sync/v1").derive(raw)


def encrypt_snapshot(auth_record: dict, vault: dict, vault_id: str, active_key: bytes, revision: int = 1) -> dict:
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("Revision must be a positive integer.")
    if not isinstance(vault_id, str) or not vault_id or len(vault_id) > 128:
        raise ValueError("A valid vault ID is required.")
    try:
        salt = base64.b64decode(auth_record["salt"], validate=True)
    except Exception as exc:
        raise ValueError("Authentication salt is invalid.") from exc
    if len(salt) < 16 or not isinstance(vault, dict) or vault.get("version") != 2 or not isinstance(vault.get("entries"), dict):
        raise ValueError("Authentication or vault structure is invalid.")
    try:
        if not hmac.compare_digest(auth._verifier(active_key), str(auth_record.get("verifier", ""))):
            raise ValueError("Active encryption key does not match the authentication record.")
    except (TypeError, ValueError) as exc:
        raise ValueError("Active encryption key does not match the authentication record.") from exc
    nonce = secrets.token_bytes(12)
    header = {"format": FORMAT, "version": VERSION, "vault_id": vault_id, "revision": revision,
              "kdf": "argon2id", "salt": base64.b64encode(salt).decode("ascii")}
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    payload = json.dumps({"auth": auth_record, "vault": vault}, separators=(",", ":"), ensure_ascii=False).encode()
    key = _derive_aead_key(active_key, vault_id)
    ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
    return {**header, "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}


def decrypt_snapshot(envelope: dict, master_password: str, expected_vault_id: str | None = None, expected_revision: int | None = None) -> tuple[dict, dict, bytes]:
    try:
        if not isinstance(envelope, dict) or envelope.get("format") != FORMAT or envelope.get("version") != VERSION or envelope.get("kdf") != "argon2id":
            raise ValueError("Unsupported encrypted vault envelope.")
        vault_id = envelope["vault_id"]
        revision = envelope.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise ValueError("Invalid encrypted vault revision.")
        if expected_revision is not None and revision != expected_revision:
            raise ValueError("Encrypted snapshot revision does not match cloud revision.")
        if not isinstance(vault_id, str) or not vault_id or (expected_vault_id and vault_id != expected_vault_id):
            raise ValueError("Vault ID mismatch.")
        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        if len(salt) < 16 or len(nonce) != 12 or len(ciphertext) > MAX_ENVELOPE_BYTES:
            raise ValueError("Invalid encrypted vault envelope lengths.")
        # Same Argon2id-derived Fernet key as local authentication; only the salt
        # and public vault ID are needed to derive the envelope key on a new device.
        key = crypto.derive_key(master_password, salt)
        header = {"format": FORMAT, "version": VERSION, "vault_id": vault_id, "revision": revision, "kdf": "argon2id", "salt": base64.b64encode(salt).decode("ascii")}
        aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        raw = AESGCM(_derive_aead_key(key, vault_id)).decrypt(nonce, ciphertext, aad)
        payload = json.loads(raw.decode("utf-8"))
        auth_record, vault = payload["auth"], payload["vault"]
        verified_key = auth._verify_v2(master_password, auth_record)
        if verified_key is None or verified_key != key:
            raise ValueError("Master password does not match this vault.")
        if not isinstance(vault, dict) or vault.get("version") != 2 or not isinstance(vault.get("entries"), dict):
            raise ValueError("Vault structure is invalid.")
        fernet = Fernet(key)
        for platform, users in vault["entries"].items():
            if not isinstance(platform, str) or not isinstance(users, dict): raise ValueError("Invalid credential map.")
            for username, token in users.items():
                if not isinstance(username, str) or not username or not isinstance(token, str): raise ValueError("Invalid credential entry.")
                # Validate all ciphertexts before any local files are changed.
                fernet.decrypt(token.encode("ascii"))
        return auth_record, vault, key
    except Exception as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(("Unsupported", "Vault ID", "Invalid encrypted", "Encrypted snapshot revision", "Master password", "Vault structure", "Invalid credential")):
            raise
        raise ValueError("Encrypted vault could not be authenticated; no local files were changed.") from exc


def _sync_state_path() -> str:
    return os.path.join(auth.DATA_DIR, ".sync-state.json")


def known_revision(vault_id: str) -> int | None:
    path = _sync_state_path()
    if not os.path.isfile(path): return None
    try:
        with open(path, encoding="utf-8") as f: state = json.load(f)
        if not isinstance(state, dict): raise ValueError
        if state.get("vault_id") != vault_id: return None
        revision = state.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1: raise ValueError
        return revision
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SyncError("Local sync state is invalid. Preserve it and restore from a trusted backup; sync was stopped.") from exc


def remember_revision(vault_id: str, revision: int) -> None:
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1: raise ValueError("Invalid sync revision.")
    previous = known_revision(vault_id)
    if previous is not None and revision < previous:
        raise SyncError("Refusing to lower the remembered sync revision.")
    from auth_helpers import atomic_write_json, secure_file
    atomic_write_json(_sync_state_path(), {"version": 1, "vault_id": vault_id, "revision": revision, "updated_at": int(time.time())})
    secure_file(_sync_state_path())


def assert_not_rollback(vault_id: str, remote_revision: int) -> None:
    if isinstance(remote_revision, bool) or not isinstance(remote_revision, int) or remote_revision < 1:
        raise SyncError("Remote sync revision is invalid; no files were changed.")
    previous = known_revision(vault_id)
    if previous is not None and remote_revision < previous:
        raise SyncError(f"Remote revision {remote_revision} is older than this device's remembered revision {previous}; possible rollback detected. No files were changed.")


class SyncError(RuntimeError): pass
class SyncConflict(SyncError): pass

class SupabaseSyncClient:
    """Small HTTPS adapter for a row in public.password_manager_vaults.

    Configuration is passed by the caller; no tokens are written to source or
    logs. Use a short-lived user JWT, never a service-role key in a client.
    """
    def __init__(self, url: str, anon_key: str, access_token: str, user_id: str, vault_id: str, device_id: str, timeout: int = 15):
        if not url.startswith("https://"):
            raise ValueError("Sync endpoint must use HTTPS.")
        if not all(isinstance(x, str) and x.strip() for x in (anon_key, access_token, user_id, vault_id, device_id)):
            raise ValueError("Incomplete sync configuration.")
        self.root = url.rstrip("/") + "/rest/v1"
        self.base = self.root + "/password_manager_vaults"
        self.devices_base = self.root + "/password_manager_devices"
        self.anon_key, self.token, self.user_id, self.vault_id, self.device_id, self.timeout = anon_key, access_token, user_id, vault_id, device_id, timeout

    @classmethod
    def from_env(cls):
        return cls(*(os.environ.get(k, "") for k in ("PM_SYNC_SUPABASE_URL", "PM_SYNC_SUPABASE_ANON_KEY", "PM_SYNC_ACCESS_TOKEN", "PM_SYNC_USER_ID", "PM_SYNC_VAULT_ID", "PM_SYNC_DEVICE_ID")))

    def _request(self, method: str, url: str, body: dict | None = None, prefer: str | None = None):
        headers = {"apikey": self.anon_key, "Authorization": "Bearer " + self.token, "Accept": "application/json", "x-pm-device-id": self.device_id}
        if body is not None: headers["Content-Type"] = "application/json"
        if prefer: headers["Prefer"] = prefer
        data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read(MAX_ENVELOPE_BYTES + 1)
                if len(raw) > MAX_ENVELOPE_BYTES: raise SyncError("Sync response is too large.")
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code in (409, 412): raise SyncConflict("Remote vault changed; local changes were not overwritten.") from exc
            if exc.code in (401, 403): raise SyncError("Cloud authentication or access policy rejected the request.") from exc
            raise SyncError(f"Cloud sync request failed (HTTP {exc.code}).") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise SyncError("Cloud sync unavailable or returned invalid data.") from exc

    def _jwt_session_id(self):
        try:
            part = self.token.split(".")[1]
            payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            session_id = payload.get("session_id")
            if not isinstance(session_id, str) or not session_id: raise ValueError
            return session_id
        except Exception as exc:
            raise SyncError("Access token does not contain a valid session_id; sign in again.") from exc

    def register_device(self):
        """Register this authenticated Supabase session as an allowed device."""
        params = urllib.parse.urlencode({"on_conflict": "user_id,device_id"})
        body = {"user_id": self.user_id, "device_id": self.device_id, "auth_session_id": self._jwt_session_id(), "label": os.environ.get("PM_SYNC_DEVICE_LABEL", "Unnamed device")[:80]}
        _, result = self._request("POST", self.devices_base + "?" + params, body, "resolution=ignore-duplicates,return=representation")
        return result

    def list_devices(self):
        self.register_device()
        params = urllib.parse.urlencode({"select": "device_id,label,created_at,revoked_at", "user_id": "eq." + self.user_id, "order": "created_at.desc"})
        _, result = self._request("GET", self.devices_base + "?" + params)
        if not isinstance(result, list): raise SyncError("Unexpected device-list response.")
        return [{**item, "is_current": item.get("device_id") == self.device_id} for item in result]

    def revoke_device(self, device_id: str):
        if not isinstance(device_id, str) or not device_id or len(device_id) > 128: raise ValueError("Invalid device ID.")
        params = urllib.parse.urlencode({"user_id": "eq." + self.user_id, "device_id": "eq." + device_id, "revoked_at": "is.null", "select": "device_id,revoked_at"})
        _, result = self._request("PATCH", self.devices_base + "?" + params, {"revoked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, "return=representation")
        if not result: raise SyncError("Device was not found or was already revoked.")
        return result

    def _query(self, select="vault_id,revision,encrypted_payload,updated_at"):
        params = urllib.parse.urlencode({"select": select, "user_id": "eq." + self.user_id, "vault_id": "eq." + self.vault_id, "limit": "1"})
        _, rows = self._request("GET", self.base + "?" + params)
        if not isinstance(rows, list): raise SyncError("Unexpected cloud response.")
        return rows[0] if rows else None

    def pull(self):
        self.register_device()
        row = self._query()
        if row is None:
            if known_revision(self.vault_id) is not None:
                raise SyncError("Remote vault is missing but this device has synced before; refusing to initialize a replacement silently.")
            return None
        assert_not_rollback(self.vault_id, row.get("revision"))
        if not isinstance(row.get("encrypted_payload"), dict) or row["encrypted_payload"].get("revision") != row.get("revision"):
            raise SyncError("Cloud revision does not match the authenticated envelope; possible replay or corruption. No files were changed.")
        return row

    def push(self, envelope: dict):
        if not isinstance(envelope, dict) or envelope.get("format") != FORMAT or envelope.get("vault_id") != self.vault_id:
            raise ValueError("Encrypted snapshot does not match the configured vault ID.")
        self.register_device()
        row = self._query()
        if row is None:
            if known_revision(self.vault_id) is not None: raise SyncConflict("Remote vault is missing but local sync history exists; refusing to recreate it silently.")
            if envelope.get("revision") != 1: raise SyncConflict("Initial sync revision must be 1; pull the remote vault before retrying.")
            params = urllib.parse.urlencode({"on_conflict": "user_id,vault_id"})
            body = {"user_id": self.user_id, "vault_id": self.vault_id, "revision": 1, "encrypted_payload": envelope, "last_device_id": self.device_id}
            try:
                _, result = self._request("POST", self.base + "?" + params, body, "resolution=ignore-duplicates,return=representation")
            except SyncConflict:
                raise
            if result:
                saved = result[0] if isinstance(result, list) else result
                remember_revision(self.vault_id, saved.get("revision", 1))
                return saved
            # A concurrent initial insert won. Never overwrite it without comparing.
            raise SyncConflict("Another device initialized this vault. Pull it before pushing.")
        revision = row.get("revision")
        if not isinstance(revision, int): raise SyncError("Remote revision is invalid.")
        if not isinstance(row.get("encrypted_payload"), dict) or row["encrypted_payload"].get("revision") != revision:
            raise SyncError("Cloud revision does not match the authenticated envelope; possible replay or corruption.")
        assert_not_rollback(self.vault_id, revision)
        known = known_revision(self.vault_id)
        if known is None or known != revision:
            raise SyncConflict("This device has not pulled the current remote revision. Pull and reconcile before pushing to avoid overwriting another device's changes.")
        if envelope.get("revision") != revision + 1:
            raise SyncConflict("Local snapshot was built against a stale remote revision; pull and reconcile before retrying.")
        params = urllib.parse.urlencode({"user_id": "eq." + self.user_id, "vault_id": "eq." + self.vault_id, "revision": "eq." + str(revision), "select": "vault_id,revision,encrypted_payload,updated_at"})
        body = {"revision": revision + 1, "encrypted_payload": envelope, "last_device_id": self.device_id, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _, result = self._request("PATCH", self.base + "?" + params, body, "return=representation")
        if not result: raise SyncConflict("Remote vault changed concurrently; local changes were not overwritten.")
        saved = result[0] if isinstance(result, list) else result
        if saved.get("revision") != envelope.get("revision"):
            raise SyncError("Server revision did not match the authenticated snapshot revision.")
        remember_revision(self.vault_id, saved["revision"])
        return saved


def save_conflict_copy(envelope: dict, label: str = "local") -> str:
    base = Path(auth.DATA_DIR) / "sync-conflicts"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    try: os.chmod(base, 0o700)
    except OSError: pass
    path = base / f"{int(time.time())}-{label}-{secrets.token_hex(4)}.json"
    from auth_helpers import atomic_write_json, secure_file
    atomic_write_json(str(path), envelope); secure_file(str(path))
    return str(path)


def current_envelope(vault_id: str, revision: int = 1) -> dict:
    with open(auth.AUTH_FILE, encoding="utf-8") as f: record = json.load(f)
    with open(auth.VAULT_FILE, encoding="utf-8") as f: vault = json.load(f)
    return encrypt_snapshot(record, vault, vault_id, crypto._active_key, revision)


def apply_remote_envelope(envelope: dict, master_password: str, vault_id: str, expected_revision: int | None = None) -> str:
    record, vault, key = decrypt_snapshot(envelope, master_password, vault_id, expected_revision)
    if expected_revision is not None: remember_revision(vault_id, expected_revision)
    from auth_helpers import atomic_write_json, ensure_data_dir, secure_file
    ensure_data_dir()
    # Keep encrypted rollback copies and a journal so existing startup recovery
    # can resolve interrupted writes with either the previous or incoming password.
    old_auth = old_vault = None
    if os.path.isfile(auth.AUTH_FILE):
        with open(auth.AUTH_FILE, encoding="utf-8") as f: old_auth = json.load(f)
    if os.path.isfile(auth.VAULT_FILE):
        with open(auth.VAULT_FILE, encoding="utf-8") as f: old_vault = json.load(f)
    backup = Path(auth.DATA_DIR) / f"pre-sync-{int(time.time())}-{secrets.token_hex(3)}"
    backup.mkdir(mode=0o700)
    for src in (auth.AUTH_FILE, auth.VAULT_FILE):
        if os.path.isfile(src):
            import shutil
            dst = backup / os.path.basename(src); shutil.copy2(src, dst); secure_file(str(dst))
    journal = {"version": 1, "old_auth": old_auth, "old_vault": old_vault, "new_auth": record, "new_vault": vault}
    atomic_write_json(auth.RESTORE_PENDING_FILE, journal)
    try:
        atomic_write_json(auth.VAULT_FILE, vault); atomic_write_json(auth.AUTH_FILE, record)
        os.remove(auth.RESTORE_PENDING_FILE); crypto.set_active_key(key)
    except Exception:
        raise RuntimeError("Sync snapshot application interrupted. Keep the recovery journal and restart authentication to recover safely.")
    return str(backup)
