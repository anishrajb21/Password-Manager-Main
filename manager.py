"""Encrypted vault CRUD, metadata, search, and local password-health analysis."""
from __future__ import annotations
import json, os, re, sys
from urllib.parse import urlparse
from cryptography.fernet import InvalidToken
from auth_helpers import atomic_write_json, ensure_data_dir
from crypto import get_fernet

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
VAULT_FILE = os.path.join(DATA_DIR, ".vault.json")
RECORD_MARKER = "__password_manager_record_v1__"


def _validate_name(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip(): raise ValueError(f"{label} cannot be empty.")
    if len(value) > 256: raise ValueError(f"{label} is too long (maximum 256 characters).")
    return value.strip()


def _normalize_record(value: str | dict) -> dict:
    if isinstance(value, str): return {"password": value, "category": "Other", "tags": [], "url": ""}
    if not isinstance(value, dict) or value.get(RECORD_MARKER) != 1 or not isinstance(value.get("password"), str):
        raise RuntimeError("Credential record is invalid; vault was not changed.")
    tags = value.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(x, str) for x in tags): raise RuntimeError("Credential metadata is invalid.")
    return {"password": value["password"], "category": value.get("category", "Other"), "tags": tags, "url": value.get("url", "")}


def _encrypt_record(record: dict) -> str:
    payload = {RECORD_MARKER: 1, **record}
    return get_fernet().encrypt(json.dumps(payload, ensure_ascii=False).encode()).decode("ascii")


def _decrypt_record(platform: str, username: str, entries: dict | None = None) -> dict:
    data = entries if entries is not None else load_data()
    try: token = data[platform][username]
    except KeyError as exc: raise KeyError("User or platform not found.") from exc
    try:
        raw = get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
        try: value = json.loads(raw)
        except json.JSONDecodeError: value = raw
        # Only payloads carrying our explicit marker are metadata records. Every other
        # decrypted string remains a password, even if it happens to look like JSON.
        if isinstance(value, dict) and value.get(RECORD_MARKER) == 1:
            return _normalize_record(value)
        return {"password": raw, "category": "Other", "tags": [], "url": ""}
    except (InvalidToken, UnicodeError, ValueError, TypeError) as exc:
        raise RuntimeError("Credential could not be decrypted; vault was not changed.") from exc


def load_data() -> dict[str, dict[str, str]]:
    if not os.path.exists(VAULT_FILE): raise RuntimeError("Vault file is missing; refusing to treat it as an empty vault.")
    try:
        with open(VAULT_FILE, encoding="utf-8") as f: content = json.load(f)
    except (OSError, json.JSONDecodeError) as exc: raise RuntimeError("Vault is unreadable; it was not reset or overwritten.") from exc
    if not isinstance(content, dict) or content.get("version") != 2 or not isinstance(content.get("entries"), dict):
        raise RuntimeError("Vault format is invalid; it was not reset or overwritten.")
    for platform, users in content["entries"].items():
        if not isinstance(platform, str) or not platform.strip() or not isinstance(users, dict): raise RuntimeError("Vault structure is invalid; no changes were made.")
        if any(not isinstance(u, str) or not u.strip() or not isinstance(t, str) or not t for u,t in users.items()): raise RuntimeError("Vault structure is invalid; no changes were made.")
    return content["entries"]


def save_data(data: dict[str, dict[str, str]]) -> None:
    ensure_data_dir()
    if not isinstance(data, dict): raise ValueError("Vault data must be a dictionary.")
    for platform, users in data.items():
        if not isinstance(platform, str) or not platform.strip() or not isinstance(users, dict): raise ValueError("Vault entries have an invalid structure.")
        if any(not isinstance(u, str) or not u.strip() or not isinstance(t, str) or not t for u,t in users.items()): raise ValueError("Vault entries have an invalid structure.")
    atomic_write_json(VAULT_FILE, {"version": 2, "entries": data})


def save_password(platform: str, username: str, password: str, *, category: str = "Other", tags: list[str] | None = None, url: str = "") -> None:
    platform, username = _validate_name(platform, "Platform"), _validate_name(username, "Username")
    if not isinstance(password, str) or not password: raise ValueError("Password cannot be empty.")
    category = _validate_name(category, "Category")
    if tags is None: tags = []
    if not isinstance(tags, list) or any(not isinstance(t, str) or not t.strip() or len(t) > 64 for t in tags): raise ValueError("Tags must be non-empty strings of at most 64 characters.")
    if not isinstance(url, str) or len(url) > 2048: raise ValueError("URL is invalid or too long.")
    if url and (urlparse(url).scheme not in {"https", "http"} or not urlparse(url).hostname or urlparse(url).username or urlparse(url).password): raise ValueError("URL must be a valid http:// or https:// URL without embedded credentials.")
    data = load_data(); data.setdefault(platform, {})[username] = _encrypt_record({"password": password, "category": category, "tags": sorted(set(t.strip() for t in tags)), "url": url.strip()})
    save_data(data)


def list_records() -> list[dict]:
    data = load_data(); output = []
    for platform, users in data.items():
        for username in users:
            rec = _decrypt_record(platform, username, data)
            output.append({"platform": platform, "username": username, "category": rec["category"], "tags": rec["tags"], "url": rec["url"]})
    return sorted(output, key=lambda r: (r["platform"].casefold(), r["username"].casefold()))


def search_records(query: str = "", *, category: str = "", tag: str = "") -> list[dict]:
    q, cat, tg = query.casefold().strip(), category.casefold().strip(), tag.casefold().strip()
    return [r for r in list_records() if (not q or q in r["platform"].casefold() or q in r["username"].casefold() or q in r["category"].casefold() or q in r["url"].casefold() or any(q in t.casefold() for t in r["tags"])) and (not cat or r["category"].casefold() == cat) and (not tg or any(tg == t.casefold() for t in r["tags"]))]


def _origin_tuple(value: str) -> tuple[str, str, int | None] | None:
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password: return None
    scheme = parsed.scheme.casefold()
    host = parsed.hostname.casefold().rstrip(".")
    try: port = parsed.port
    except ValueError: return None
    if port is None: port = 443 if scheme == "https" else 80
    return scheme, host, port


def records_for_origin(origin: str) -> list[dict]:
    target = _origin_tuple(origin)
    if target is None: return []
    return [r for r in list_records() if r["url"] and _origin_tuple(r["url"]) == target]


def _decrypt(platform: str, username: str) -> str: return _decrypt_record(platform, username)["password"]


def list_all() -> None:
    records = list_records()
    if not records: print("No data found."); return
    for r in records: print(f"{r['platform']} | {r['username']} | {r['category']} | tags: {', '.join(r['tags']) or '-'}")


def list_platform(platform: str) -> None:
    users = load_data().get(platform)
    if users is None: print("Platform not found."); return
    for username in sorted(users, key=str.casefold): print(username)


def decrypt_all() -> None:
    for r in list_records(): print(f"{r['platform']} | {r['username']} -> {_decrypt(r['platform'], r['username'])}")


def decrypt_platform(platform: str) -> None:
    data = load_data()
    if platform not in data: print("Platform not found."); return
    for username in data[platform]: print(f"{username} -> {_decrypt(platform, username)}")


def decrypt_single(platform: str, user: str) -> None:
    try: print("Password:", _decrypt(platform, user))
    except KeyError as exc: print(str(exc).strip("'"))


def update_password(platform: str, username: str, new_password: str) -> bool:
    platform, username = _validate_name(platform, "Platform"), _validate_name(username, "Username")
    if not isinstance(new_password, str) or not new_password: raise ValueError("Password cannot be empty.")
    data = load_data()
    if platform not in data or username not in data[platform]: print("User or platform not found; no new entry was created."); return False
    rec = _decrypt_record(platform, username, data); rec["password"] = new_password
    data[platform][username] = _encrypt_record(rec); save_data(data); return True


def update_metadata(platform: str, username: str, *, category: str | None = None, tags: list[str] | None = None, url: str | None = None) -> bool:
    data = load_data()
    if platform not in data or username not in data[platform]: return False
    rec = _decrypt_record(platform, username, data)
    if category is not None: rec["category"] = _validate_name(category, "Category")
    if tags is not None:
        if not isinstance(tags, list) or any(not isinstance(t, str) or not t.strip() for t in tags): raise ValueError("Tags must be non-empty strings.")
        rec["tags"] = sorted(set(t.strip() for t in tags))
    if url is not None:
        if url and (urlparse(url).scheme not in {"https", "http"} or not urlparse(url).hostname or urlparse(url).username or urlparse(url).password): raise ValueError("URL must be a valid http:// or https:// URL without embedded credentials.")
        rec["url"] = url
    data[platform][username] = _encrypt_record(rec); save_data(data); return True


def delete_user(platform: str, username: str) -> None:
    data = load_data()
    if platform not in data or username not in data[platform]: print("User not found."); return
    del data[platform][username]
    if not data[platform]: del data[platform]
    save_data(data); print("User deleted.")


def delete_platform(platform: str) -> None:
    data = load_data()
    if platform not in data: print("Platform not found."); return
    del data[platform]; save_data(data); print("Platform deleted.")


def password_health_report() -> dict:
    """Local-only heuristic checks. Does not claim formal entropy or breach status."""
    data = load_data(); seen: dict[str, list[tuple[str,str]]] = {}; findings = []
    common = {"password", "qwerty", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon", "sunshine", "princess"}
    for platform, users in data.items():
        for username in users:
            password = _decrypt_record(platform, username, data)["password"]
            reasons = []
            if len(password) < 12: reasons.append("shorter than 12 characters")
            if password.casefold() in common or re.sub(r"[^a-z]", "", password.casefold()) in common: reasons.append("matches a common weak password or predictable variant")
            if len(set(password)) <= 3 and len(password) >= 8: reasons.append("uses very few distinct characters")
            if reasons: findings.append({"platform": platform, "username": username, "issues": reasons})
            seen.setdefault(password, []).append((platform, username))
    for accounts in seen.values():
        if len(accounts) > 1:
            for platform, username in accounts: findings.append({"platform": platform, "username": username, "issues": ["password reused across multiple accounts"]})
    return {"total_accounts": sum(len(x) for x in data.values()), "findings": findings, "weak_or_reused_accounts": len({(f['platform'], f['username']) for f in findings}), "scope": "local heuristic checks only; no online breach lookup"}
