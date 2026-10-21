"""Offline tests for E2E envelope crypto and safe remote snapshot application."""
import json, os, sys, tempfile, unittest
from unittest.mock import patch
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
import auth, auth_helpers, crypto, e2e_sync, manager

class E2ESyncTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.data=os.path.join(self.temp.name,'data'); os.makedirs(self.data)
        self.auth_file=os.path.join(self.data,'.auth'); self.vault_file=os.path.join(self.data,'.vault.json')
        self.patches=[patch.object(auth,'DATA_DIR',self.data),patch.object(auth,'AUTH_FILE',self.auth_file),patch.object(auth,'VAULT_FILE',self.vault_file),patch.object(auth,'PENDING_CHANGE_FILE',os.path.join(self.data,'.password-change.pending')),patch.object(auth,'RESTORE_PENDING_FILE',os.path.join(self.data,'.restore.pending')),patch.object(crypto,'DATA_DIR',self.data),patch.object(crypto,'KEY_FILE',os.path.join(self.data,'.key')),patch.object(manager,'DATA_DIR',self.data),patch.object(manager,'VAULT_FILE',self.vault_file),patch.object(auth_helpers,'DATA_DIR',self.data)]
        for p in self.patches:p.start()
        self.password='correct horse battery staple for sync tests'
        self.record,self.key=auth._make_auth(self.password)
        auth_helpers.atomic_write_json(self.auth_file,self.record); auth_helpers.atomic_write_json(self.vault_file,{'version':2,'entries':{}})
        self.assertTrue(auth.authenticate_password(self.password))
    def tearDown(self):
        crypto.clear_active_key()
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def test_envelope_does_not_expose_credentials_or_metadata(self):
        manager.save_password('Private Example','alice@example.test','super-secret-password',category='Banking',tags=['private'],url='https://secret.example.test/login')
        with open(self.auth_file,encoding='utf-8') as f: record=json.load(f)
        with open(self.vault_file,encoding='utf-8') as f: vault=json.load(f)
        env=e2e_sync.encrypt_snapshot(record,vault,'vault-test-001',crypto._active_key)
        encoded=json.dumps(env)
        for secret in ('alice@example.test','super-secret-password','Banking','secret.example.test','Private Example'):
            self.assertNotIn(secret,encoded)
        out_record,out_vault,key=e2e_sync.decrypt_snapshot(env,self.password,'vault-test-001')
        self.assertEqual(out_record,record); self.assertEqual(out_vault,vault); self.assertEqual(key,crypto._active_key)
    def test_wrong_password_and_tamper_are_rejected(self):
        env=e2e_sync.encrypt_snapshot(self.record,{'version':2,'entries':{}},'vault-test-001',crypto._active_key)
        with self.assertRaises(ValueError): e2e_sync.decrypt_snapshot(env,'a completely wrong master password','vault-test-001')
        altered=dict(env); altered['vault_id']='different-vault'
        with self.assertRaises(ValueError): e2e_sync.decrypt_snapshot(altered,self.password,'vault-test-001')
        altered=dict(env); altered['ciphertext']=altered['ciphertext'][:-3]+'AAA'
        with self.assertRaises(ValueError): e2e_sync.decrypt_snapshot(altered,self.password,'vault-test-001')
    def test_remote_snapshot_is_validated_then_applied_with_rollback(self):
        manager.save_password('Old','alice','old-password')
        env=e2e_sync.current_envelope('vault-test-001')
        manager.save_password('Local newer','bob','local-password')
        rollback=e2e_sync.apply_remote_envelope(env,self.password,'vault-test-001')
        self.assertTrue(os.path.isdir(rollback))
        self.assertEqual(manager._decrypt('Old','alice'),'old-password')
        self.assertNotIn('Local newer',manager.load_data())
        self.assertTrue(os.path.exists(os.path.join(rollback,'.vault.json')))
    def test_bad_remote_envelope_never_changes_local_files(self):
        manager.save_password('Keep','alice','keep-this-password')
        with open(self.vault_file,'rb') as f: before=f.read()
        env=e2e_sync.current_envelope('vault-test-001'); env['ciphertext']='invalid'
        with self.assertRaises(ValueError): e2e_sync.apply_remote_envelope(env,self.password,'vault-test-001')
        with open(self.vault_file,'rb') as f: self.assertEqual(f.read(),before)
    def test_stale_revision_is_a_conflict_not_an_overwrite(self):
        client=e2e_sync.SupabaseSyncClient('https://example.supabase.co','anon','token','user','vault','device')
        client.register_device=lambda: None
        client._query=lambda: {'revision': 7, 'encrypted_payload': {'revision': 7}}
        client._request=lambda *args, **kwargs: (200, [])
        envelope=e2e_sync.encrypt_snapshot(self.record,{'version':2,'entries':{}},'vault',crypto._active_key)
        with self.assertRaises(e2e_sync.SyncConflict): client.push(envelope)

    def test_revision_is_authenticated_and_lower_remote_revision_is_rejected(self):
        env=e2e_sync.encrypt_snapshot(self.record,{'version':2,'entries':{}},'vault-test-001',crypto._active_key,revision=4)
        with self.assertRaisesRegex(ValueError,'revision'):
            e2e_sync.decrypt_snapshot(env,self.password,'vault-test-001',expected_revision=3)
        e2e_sync.remember_revision('vault-test-001',4)
        with self.assertRaises(e2e_sync.SyncError):
            e2e_sync.assert_not_rollback('vault-test-001',3)

    def test_master_password_rotation_reencrypts_sync_envelope(self):
        manager.save_password('Rotation','alice','keep-credential')
        old_envelope=e2e_sync.current_envelope('vault-test-001',revision=1)
        new_password='a different strong master password for sync'
        auth.change_master_password_values(self.password,new_password)
        new_envelope=e2e_sync.current_envelope('vault-test-001',revision=2)
        record,vault,key=e2e_sync.decrypt_snapshot(new_envelope,new_password,'vault-test-001',expected_revision=2)
        self.assertEqual(vault['version'],2)
        with self.assertRaises(ValueError): e2e_sync.decrypt_snapshot(old_envelope,new_password,'vault-test-001')
        self.assertEqual(manager._decrypt('Rotation','alice'),'keep-credential')

    def test_sync_client_requires_https_and_all_identity_fields(self):
        with self.assertRaises(ValueError): e2e_sync.SupabaseSyncClient('http://localhost','anon','token','user','vault','device')
        with self.assertRaises(ValueError): e2e_sync.SupabaseSyncClient('https://example.supabase.co','','token','user','vault','device')

if __name__=='__main__': unittest.main(verbosity=2)
