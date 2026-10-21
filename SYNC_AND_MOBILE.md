# Encrypted sync, device revocation, and mobile architecture

## What is implemented in this release

- `e2e_sync.py` creates an AES-256-GCM envelope for the *entire* vault snapshot, including usernames, platform names, URLs, categories, tags, and the authentication record. The cloud receives only the envelope, public format/version, vault ID, KDF salt, nonce, and ciphertext.
- The envelope key is derived from the same master password and Argon2id salt used by the local vault, then domain-separated with HKDF and the vault ID. The server never receives the master password or unwrapped key.
- The cloud revision is authenticated as AES-GCM associated data and must match the database row revision. Each client remembers its highest successful revision and refuses lower remote revisions to detect rollback/replay against that device.
- The Supabase REST adapter uses HTTPS, user JWTs, per-device headers, a revision field, and conditional updates. A stale concurrent update returns a conflict rather than silently overwriting remote data.
- Pull validates the GCM tag, master-password verifier, vault structure, and every credential ciphertext before replacing local files. It keeps an encrypted pre-sync snapshot and uses the existing restore-recovery journal.
- Supabase schema includes per-user RLS and a device/session registry. A device registration is bound to the `session_id` in the verified Supabase JWT. Revoking a device is one-way from authenticated clients; its sync requests fail the RLS check.
- The extension dashboard exposes vault CRUD, search, generation, metadata editing, reveal, health checks, encrypted backup/restore, master-password change, sync, and device revocation. The popup remains a quick autofill UI.

## What is not yet production-verified

No live Supabase project, browser profile, signed extension, Android device, or iOS device was available in this environment. The SQL migration and client adapter are included but must be deployed and tested against a real project before relying on cloud sync. The mobile client is an architecture plan, not a shipped native app. No end-to-end browser autofill test has been performed against real login pages.

## Supabase setup

1. Create a Supabase project and apply `supabase/migrations/0001_encrypted_vault_sync.sql` in a test project first.
2. Create a normal Supabase Auth user. Do **not** use a service-role key in the extension, native host environment, or mobile client.
3. For each device/session, generate a unique random device ID (UUID format is suitable). Sign in on that device and configure the environment variables below. The native host registers the device against the session ID from the user JWT on the first sync request.
4. Configure environment variables for the native host process (not JavaScript in the extension):
   - `PM_SYNC_SUPABASE_URL=https://YOUR_PROJECT.supabase.co`
   - `PM_SYNC_SUPABASE_ANON_KEY=YOUR_PUBLISHABLE_OR_ANON_KEY`
   - `PM_SYNC_ACCESS_TOKEN=SHORT_LIVED_USER_ACCESS_TOKEN`
   - `PM_SYNC_USER_ID=AUTH_USER_UUID`
   - `PM_SYNC_VAULT_ID=YOUR_STABLE_VAULT_ID`
   - `PM_SYNC_DEVICE_ID=UNIQUE_DEVICE_ID`
   - Optional `PM_SYNC_DEVICE_LABEL=Anish laptop`
5. Configure a separate device ID and current user session token on each device. Keep tokens in the OS credential store or another protected runtime secret mechanism; environment variables are a bootstrap option, not the ideal long-term credential store.
6. Unlock the vault and push from the device containing the authoritative data. On a new device, sign in, use the same master password, and pull the remote vault. Do not create an unrelated vault first and assume it will merge.
7. Test `Check sync status`, `Push encrypted vault`, and `Pull and restore remote vault` with dummy credentials first. Verify the database `encrypted_payload` contains no website names, usernames, or passwords.

### Master-password changes

The encrypted envelope uses the current Argon2id salt and is re-encrypted on the next push after a master-password change. Push immediately from the device where the password changed. Other devices must pull the latest envelope and unlock with the new password. An offline device may contain a stale snapshot; do not push from it until it has pulled and reconciled. Existing copies previously downloaded by an attacker cannot be retroactively erased.

### Conflict behavior

Sync is whole-vault snapshot sync, not per-record CRDT merging. If two devices edit offline and push concurrently, the revision check rejects the stale update. Keep both devices' encrypted conflict snapshots, pull the current remote vault, then manually reconcile the conflicting changes through the CLI/dashboard before pushing again. The code deliberately does not guess which vault is authoritative. A new device with no previously remembered revision cannot independently know whether a malicious server has replayed an older complete database snapshot; protect the server account and verify backups. Existing devices use their local remembered revision to detect a lower revision.

### Device revocation

Use the dashboard's device list and revoke action, then also revoke/sign out the corresponding Supabase Auth session in Supabase's session controls when a device is lost or compromised. RLS binds sync access to both `x-pm-device-id` and the JWT `session_id`, so a revoked row cannot sync even if its JWT has not yet expired. Revocation does not erase data already downloaded to that device. Rotate the master password and review recovery copies if a device may have been compromised.


### Token expiry and local configuration

The current adapter reads the Supabase URL, publishable/anon key, user access JWT, user ID, vault ID, and device ID from the native host process environment. The access JWT expires; this release does not refresh Supabase sessions automatically. Refresh/sign in again and update the native host environment, then restart the browser so its native host inherits the new environment. Do not commit tokens or place service-role keys in environment variables. For routine production use, replace this bootstrap configuration with an OS credential-store integration and an audited session-refresh flow.

## Mobile app plan (Android/iOS)

Recommended client architecture:

- A native UI (Android Kotlin/Jetpack Compose; iOS Swift/SwiftUI) with a shared, audited crypto protocol and JSON test vectors. Do not port crypto by hand independently without interoperability tests.
- Derive 32 bytes with Argon2id using the envelope salt, time cost 3, memory cost 65,536 KiB, parallelism 2, and output length 32 bytes. The local key API represents those bytes as URL-safe Base64; decode it back to the raw 32 bytes for HKDF-SHA256. HKDF salt is the UTF-8 vault ID and info is the exact bytes `password-manager/e2e-sync/v1`. AES-256-GCM uses a fresh 12-byte nonce. Associated data is UTF-8 JSON of `{format, version, vault_id, revision, kdf, salt}` with keys sorted lexicographically and compact separators `(',', ':')`; ciphertext is Base64 of ciphertext plus GCM tag.
- Store only device/session tokens and convenience-unlock material in Android Keystore / iOS Keychain. Never store the plaintext master password. Use platform autofill APIs (`AutofillService` on Android and AutoFill Credential Provider extension on iOS) instead of DOM injection.
- Register a unique device ID bound to each authenticated session; provide device revocation, sync conflict UI, encrypted local cache, screen-lock policy, biometric convenience unlock, and recovery export.
- Add shared cross-language vectors and tests for wrong password, tampered nonce/ciphertext/header, old KDF parameters, stale revisions, concurrent updates, revocation, interrupted restore, and offline edits before shipping.

## Important security notes

- E2E encryption protects the vault contents from the sync database, but cloud account metadata (account identity, timestamps, revisions, approximate payload sizes) is still visible.
- The Argon2id salt is public; the encrypted verifier is inside the ciphertext. A copied envelope can still be subjected to offline password guessing, so use a strong master passphrase.
- The sync server is a transport/store, not a password recovery service. If the master password and all recovery copies are lost, the vault cannot be decrypted.
- Supabase policies must be verified against your project's actual Postgres/Supabase versions and settings. Never deploy this schema to a production project without testing RLS and device revocation with two real sessions first.
