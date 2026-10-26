"""Interactive CLI for the local password manager."""
import builtins
import os
from getpass import getpass

from auth import change_master_password, verify_password
from backup import create_backup, restore_backup
from crypto import clear_active_key
from generator import MAX_LENGTH, MIN_LENGTH, generate_password
from manager import (
    _decrypt,
    decrypt_all,
    decrypt_platform,
    decrypt_single,
    delete_platform,
    delete_user,
    list_all,
    list_platform,
    password_health_report,
    save_password,
    search_records,
    update_metadata,
    update_password,
)
from session_security import SessionTimer, copy_secret

SESSION_TIMEOUT_SECONDS = 300

_SESSION_TIMER = None

def ensure_session_current() -> None:
    """Lock and reauthenticate after inactivity before any sensitive operation."""
    if _SESSION_TIMER is not None and _SESSION_TIMER.expired():
        clear_active_key()
        print("Session timed out. Reauthenticate to continue.")
        if not verify_password(): raise RuntimeError("Reauthentication failed; session remains locked.")
        _SESSION_TIMER.touch()

def read_input(prompt: str = "") -> str:
    """Read a CLI response, then enforce inactivity expiry before using it."""
    value = builtins.input(prompt)
    ensure_session_current()
    if _SESSION_TIMER is not None: _SESSION_TIMER.touch()
    return value


def menu():
    print("\n=== Password Manager ===")
    print("1. Generate / save password")
    print("2. List saved accounts")
    print("3. Modify password")
    print("4. Delete")
    print("5. Reveal / copy password (reauthentication required)")
    print("6. Change Master Password")
    print("7. Lock and Exit")
    print("8. Search / filter vault")
    print("9. Password health report")
    print("10. Create encrypted backup")
    print("11. Restore encrypted backup")
    print("12. Edit category, tags or website URL")

def confirmed(prompt: str) -> bool:
    return read_input(f"{prompt} Type 'yes' to confirm: ").strip().lower() == "yes"

def parse_tags(raw: str) -> list[str]: return [tag.strip() for tag in raw.split(",") if tag.strip()]

def list_menu():
    while True:
        print("\n1. List all accounts\n2. List a platform\n3. Back")
        choice = read_input("Choice: ").strip()
        try:
            if choice == "1": list_all()
            elif choice == "2": list_platform(read_input("Platform: ").strip())
            elif choice == "3": return
            else: print("Invalid choice.")
        except (RuntimeError, ValueError) as exc: print(f"Operation failed: {exc}")

def delete_menu():
    while True:
        print("\n1. Delete user\n2. Delete platform\n3. Back")
        choice = read_input("Choice: ").strip()
        if choice == "1":
            platform, username = read_input("Platform: ").strip(), read_input("Username: ").strip()
            if confirmed(f"Delete account {username!r} on {platform!r}?"):
                try: delete_user(platform, username)
                except (RuntimeError, ValueError) as exc: print(f"Operation failed: {exc}")
        elif choice == "2":
            platform = read_input("Platform: ").strip()
            if confirmed(f"Delete ALL accounts under {platform!r}?"):
                try: delete_platform(platform)
                except (RuntimeError, ValueError) as exc: print(f"Operation failed: {exc}")
        elif choice == "3": return
        else: print("Invalid choice.")

def reveal_menu():
    while True:
        print("\n1. Reveal one password\n2. Reveal platform passwords\n3. Reveal all passwords\n4. Copy one password to clipboard\n5. Back")
        choice = read_input("Choice: ").strip()
        if choice == "5": return
        if choice not in {"1", "2", "3", "4"}: print("Invalid choice."); continue
        if not verify_password(): print("Reauthentication failed."); continue
        try:
            if choice == "1": decrypt_single(read_input("Platform: ").strip(), read_input("Username: ").strip())
            elif choice == "2": decrypt_platform(read_input("Platform: ").strip())
            elif choice == "3":
                if confirmed("Reveal every stored password on screen?"): decrypt_all()
            else:
                platform, username = read_input("Platform: ").strip(), read_input("Username: ").strip()
                secret = _decrypt(platform, username); copy_secret(secret, 30); print("Copied. Clipboard will be cleared after 30 seconds if unchanged.")
        except (RuntimeError, ValueError, KeyError) as exc: print(f"Operation failed: {exc}")

def generate_menu():
    while True:
        print("\n1. Generate / save password\n2. Back")
        choice = read_input("Choice: ").strip()
        if choice == "2": return
        if choice != "1": print("Invalid choice."); continue
        platform, username = read_input("Platform / website: ").strip(), read_input("Username: ").strip()
        try:
            length = int(read_input(f"Password length ({MIN_LENGTH}-{MAX_LENGTH}): "))
            password = generate_password(length)
            print("Generated password (shown once):", password)
            if read_input("Save to vault? yes/no: ").strip().lower() == "yes":
                category = read_input("Category [Other]: ").strip() or "Other"
                tags = parse_tags(read_input("Tags, comma-separated [optional]: "))
                url = read_input("Website URL for autofill [optional]: ").strip()
                save_password(platform, username, password, category=category, tags=tags, url=url)
                print("Saved successfully.")
        except (ValueError, RuntimeError) as exc: print(f"Could not generate/save password: {exc}")

def search_menu():
    query = read_input("Search text [optional]: ").strip()
    category = read_input("Exact category [optional]: ").strip()
    tag = read_input("Exact tag [optional]: ").strip()
    try:
        results = search_records(query, category=category, tag=tag)
        if not results: print("No matches.")
        for r in results: print(f"{r['platform']} | {r['username']} | {r['category']} | {', '.join(r['tags']) or '-'} | {r['url'] or '-'}")
    except (RuntimeError, ValueError) as exc: print(f"Search failed: {exc}")

def health_menu():
    report = password_health_report()
    print(f"Accounts analyzed: {report['total_accounts']}")
    print(f"Accounts with findings: {report['weak_or_reused_accounts']}")
    print("Checks are local heuristics; no online breach lookup is performed.")
    for item in report["findings"]: print(f"- {item['platform']} / {item['username']}: {', '.join(item['issues'])}")
    if not report["findings"]: print("No weak/reused passwords detected by the included heuristic checks.")

def backup_menu():
    path = read_input("Backup file path [password-manager-backup.pmbak]: ").strip() or "password-manager-backup.pmbak"
    p1, p2 = getpass("Set backup passphrase (12+ characters): "), getpass("Confirm backup passphrase: ")
    if p1 != p2: print("Passphrases do not match."); return
    try:
        ensure_session_current()
        print(f"Encrypted backup created: {create_backup(path, p1)}")
    except (RuntimeError, ValueError, OSError) as exc: print(f"Backup failed: {exc}")

def restore_menu():
    path = read_input("Encrypted backup path: ").strip()
    backup_passphrase = getpass("Backup passphrase: ")
    master_password = getpass("Master password used when this backup was created: ")
    if not confirmed("Restore this backup? Current encrypted files will be preserved first."): return
    try:
        rollback = restore_backup(path, backup_passphrase, master_password)
        print(f"Backup restored. Previous encrypted files preserved at: {rollback}")
        print("Vault is locked; restart authentication with the restored master password.")
    except (RuntimeError, ValueError, OSError) as exc: print(f"Restore failed safely: {exc}")

def metadata_menu():
    platform, username = read_input("Platform: ").strip(), read_input("Username: ").strip()
    category = read_input("New category [blank keeps current]: ").strip()
    tags_raw = read_input("Replace tags (comma-separated; blank keeps current): ").strip()
    url = read_input("New website URL [blank keeps current]: ").strip()
    try:
        kwargs = {}
        if category: kwargs["category"] = category
        if tags_raw: kwargs["tags"] = parse_tags(tags_raw)
        if url: kwargs["url"] = url
        if not kwargs: print("No changes requested."); return
        if update_metadata(platform, username, **kwargs): print("Metadata updated.")
        else: print("Account not found.")
    except (RuntimeError, ValueError) as exc: print(f"Update failed: {exc}")

def main():
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"), exist_ok=True)
    try:
        if not verify_password(): return
        global _SESSION_TIMER
        timer = SessionTimer(SESSION_TIMEOUT_SECONDS)
        _SESSION_TIMER = timer
        while True:
            menu(); choice = read_input("Choice: ").strip()
            try:
                if choice == "1": generate_menu()
                elif choice == "2": list_menu()
                elif choice == "3":
                    platform, username = read_input("Platform: ").strip(), read_input("Username: ").strip()
                    password = generate_password()
                    if update_password(platform, username, password):
                        try: copy_secret(password, 30); print("Password updated and copied to clipboard (clears after 30s if unchanged).")
                        except RuntimeError: print("Password updated. Clipboard support unavailable; use reveal to access it.")
                elif choice == "4": delete_menu()
                elif choice == "5": reveal_menu()
                elif choice == "6": change_master_password()
                elif choice == "7": break
                elif choice == "8": search_menu()
                elif choice == "9": health_menu()
                elif choice == "10": backup_menu()
                elif choice == "11": restore_menu()
                elif choice == "12": metadata_menu()
                else: print("Invalid choice.")
                timer.touch()
            except (RuntimeError, ValueError, OSError) as exc: print(f"Operation failed: {exc}")
    except (OSError, RuntimeError, ValueError) as exc: print(f"Unable to continue safely: {exc}")
    finally:
        _SESSION_TIMER = None
        clear_active_key(); print("Vault locked.")

if __name__ == "__main__": main()
