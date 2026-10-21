# Changelog

## Version 3 feature set

- Added encrypted per-credential metadata for categories, tags, and website URLs while preserving the existing vault container and password-only entry compatibility.
- Added local heuristic password-health checks for weak/common patterns and password reuse.
- Added password-protected encrypted backups, master-password verification during restore, current-file rollback copies, and a crash-recovery journal.
- Added inactivity expiry checks at CLI input boundaries and best-effort clipboard clearing that avoids clearing a clipboard value that changed after copying.
- Added exact-origin Chromium autofill through Native Messaging, with explicit user-triggered fill and no local HTTP server.
- Added regression tests for backup tampering, wrong passwords, interrupted restore, migration, vault corruption, metadata encryption, and native-host origin matching.


## v4 architecture update

- Added `e2e_sync.py`: AES-GCM authenticated encrypted whole-vault snapshots, Argon2id-derived key material, HKDF domain separation, HTTPS Supabase REST client, revision CAS, conflict detection, encrypted local conflict copies, and validated snapshot apply/recovery.
- Added Supabase RLS schema for vault snapshots and per-session device registration/revocation.
- Expanded native host API for full vault CRUD, health, generation, backup/restore, master-password change, sync, and device management.
- Added full browser vault dashboard while retaining the quick autofill popup.
- Added mobile client protocol and implementation plan. Android/iOS clients and live Supabase/browser integration remain unimplemented/unverified.
