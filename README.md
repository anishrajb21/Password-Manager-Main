# Password Manager — CLI + Browser Vault + E2E Sync

A local Python CLI password manager. Vault entries use Fernet authenticated encryption with a key derived from the master password through Argon2id. The derived key is held in process memory while unlocked; new installations do not create a standalone `.key` file.

## Requirements and launch

- Python 3.10+
- Dependencies listed in `requirements.txt`

```bash
python -m pip install -r requirements.txt
python main.py
```

On Windows, `anish.bat` launches the CLI from the project folder.

## Features

- Secure password generation (`secrets`), categories, tags, website URLs, search and filters.
- Local password health checks for short/common passwords, low character diversity, and reused passwords. This is a heuristic, not a formal entropy calculation and not an online breach check.
- Password reveal with reauthentication, clipboard copy with best-effort delayed clearing, and an inactivity timeout checked at CLI interaction boundaries.
- Password-protected encrypted backups and restore validation. Backups use an independent Argon2id-derived key and Fernet authentication; restoring requires both the backup passphrase and the master password associated with that snapshot.
- Chromium browser extension with a full vault dashboard and quick autofill popup: CRUD, generation, search, metadata, health, backup/restore, master-password rotation, encrypted sync and device management. See [`BROWSER_EXTENSION.md`](BROWSER_EXTENSION.md).
- End-to-end encrypted cloud snapshot sync with AES-256-GCM, Argon2id-derived key, HKDF domain separation, authenticated revisions, local rollback detection, conflict protection, encrypted conflict snapshots, and a Supabase RLS/device-session schema. See [`SYNC_AND_MOBILE.md`](SYNC_AND_MOBILE.md).
- Mobile architecture plan for Android/iOS; native mobile apps are not included in this ZIP.
- Expanded automated tests for migration, corruption, metadata confidentiality, health checks, backups, session timeout, clipboard clearing, and native-host origin restrictions.

## Local data

`data/.auth` contains the KDF salt and verifier; `data/.vault.json` contains encrypted credentials. Credential metadata (category, tags, website URL) is encrypted inside each credential token. Do not commit `data/`, put it in an unencrypted sync folder, or distribute it with the source. The `.gitignore` excludes local vault material.

## Safe migration from the original project

1. Close the old application. Make an offline encrypted copy of the complete old `data/` folder before doing anything else.
2. Extract this version into a new folder and install dependencies.
3. Copy the old `data/` directory into the new project. Keep `.auth`, `.key`, and `.vault.json` together; do not overwrite them with sample files.
4. Run `python main.py` and authenticate using the existing master password. The legacy SHA-256 auth + standalone Fernet key format is migrated on first successful authentication. The program makes a timestamped rollback copy before migrating.
5. Verify multiple known credentials and test adding/updating/deleting a dummy credential. Create a new encrypted backup and verify that a restore test works in a separate test copy before relying on it.
6. Keep the original backup and migration rollback copy protected until verification is complete. The legacy rollback folder contains the old key and encrypted vault together; anyone who gets both can decrypt the legacy vault.

If migration reports a missing key, missing vault, malformed file, or decryption error, stop. Do not reset authentication or regenerate a key. Restore the matching original file set from backup. A missing vault is not treated as an empty vault.

## Encrypted backups

Choose a backup passphrase distinct from the master password and store it safely. The application cannot recover a forgotten backup passphrase. Restore validates the backup passphrase, the supplied master password, and the encrypted entries before replacing the current files. The current encrypted auth/vault files are preserved in a `pre-restore-*` folder. A recovery journal lets the next unlock finish or roll back an interrupted two-file restore using the corresponding master password. After a successful restore, the vault is locked and must be authenticated again. Keep the rollback folder until you confirm the restored vault works.

## Security notes and limitations

- Use a long, unique master passphrase. Argon2id raises the cost of offline guessing but does not make weak passwords safe.
- Session timeout is checked at CLI interaction boundaries; it does not forcibly interrupt an OS-level blocking terminal prompt. Do not leave an unlocked terminal unattended.
- Clipboard clearing is best-effort. Clipboard managers, remote desktop software, or OS history may retain copied secrets. The app clears only if the clipboard still contains the same secret at timeout.
- Python cannot guarantee zeroization of all immutable strings or library copies in memory. Malware running as your user, a compromised OS, screenshots, filesystem snapshots, and swap remain outside this tool's protection.
- Browser autofill is optional and requires native host installation. Exact-origin checks and explicit user action reduce accidental credential leakage but cannot make a phishing site or compromised browser safe.
- Password health checks are local heuristics. They do not query breach databases and can miss weak patterns.
- No software-only password manager should be considered independently audited because unit tests pass. Review cryptographic design and platform-specific behavior before storing critical credentials.

## Tests

Run the complete standard-library unittest suite (includes offline sync-envelope crypto tests; no live cloud project is needed):

```bash
python -m unittest discover -s tests -v
```

Tests use temporary directories and synthetic credentials. Optional dependency audit:

```bash
python -m pip install pip-audit
python -m pip_audit -r requirements.txt
```
