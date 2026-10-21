# Safe migration from the original password manager

This guide applies to the original CLI format that used `data/.auth` (a SHA-256 hash), `data/.key` (a standalone Fernet key), and `data/.vault.json` (encrypted credentials).

## Before you start

1. Close the old password manager.
2. Make a copy of the **entire existing `data/` directory**. Store the copy offline in an encrypted location. It contains a standalone key and a vault that can be decrypted together.
3. Do not delete, rename, regenerate, or replace `.auth`, `.key`, or `.vault.json` individually. They must remain a matching set until migration succeeds.
4. Keep the original application folder until you have verified the migrated vault.

## Install and migrate

1. Extract the updated ZIP to a new folder.
2. Install the dependencies from that folder:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Copy your original `data/` directory into the new project folder. Do not overwrite it with the ZIP's `data/` directory; the ZIP contains only a `.gitkeep` placeholder.
4. Run the CLI:

   ```bash
   python main.py
   ```

   On Windows, you can also run `anish.bat`.

5. Enter your existing master password. On successful legacy authentication, the application derives a new Argon2id key, decrypts the old entries, writes the version-2 encrypted vault, and removes the active legacy `.key` file after the new vault is written.
6. The app creates a `data/legacy-backup-*` directory before changing legacy files. Keep it and your separate pre-migration backup offline and protected until verification is complete.
7. Verify several known credentials by revealing them individually, then test adding, updating, and deleting a dummy credential.
8. After successful verification, remove old recovery copies only if you no longer need them. Securely dispose of any copy that contains both the old key and old vault.

## If migration fails

**Stop. Do not reset the master password, generate a new key, delete files, or keep retrying after changing the data.** The program is designed to refuse migration when the key is missing/invalid, the vault is missing/unreadable, or an entry cannot be decrypted.

Restore the original `.auth`, `.key`, and `.vault.json` from the same backup set (restore only the files that existed in that set), then retry. If the original key is lost and the vault contains encrypted entries, those entries generally cannot be recovered without another matching copy of the key.

If the app reports that the vault is missing, it deliberately will not create an empty replacement. Restore the vault from a matching backup first. If you have no backup and are certain this was a brand-new, empty installation, create a new installation in a separate folder rather than overwriting the damaged data directory.

## After migration

- Use menu option **6** to change a legacy master password shorter than 12 characters.
- The active new format uses Argon2id-derived key material and Fernet authenticated encryption; new installations do not create a standalone `.key` file.
- Keep `data/` out of Git and avoid unencrypted cloud sync or backups.
- Do not share the legacy recovery backup: it contains the old standalone key and encrypted vault together.

## Features added after migration

The expanded version keeps the existing outer version-2 vault format so password-only entries from the previous secure CLI remain readable. New category, tag, and website metadata is stored inside each encrypted credential token; do not hand-edit `.vault.json`.

- **Encrypted backup:** choose a distinct backup passphrase. Restore requires both that passphrase and the master password for the snapshot. A restore writes a protected `pre-restore-*` copy and a journal so the next unlock can complete or roll back an interrupted restore. Keep the rollback copy until you have verified the restored vault.
- **Session and clipboard:** inactivity is enforced after terminal input returns; it cannot interrupt a terminal prompt at the operating-system level. Clipboard clearing is best-effort and may be defeated by clipboard history tools.
- **Browser extension:** optional, Chromium-based Native Messaging setup is documented in `BROWSER_EXTENSION.md`. Build/register the host only after reviewing the source. Autofill is user-triggered and uses exact scheme/hostname/port matching.
- **Tests:** run `python -m unittest discover -s tests -v`. Tests use temporary data and synthetic passwords, not your real vault.
