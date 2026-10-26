"""Regression tests for metadata, health checks, backups, session and native messaging."""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import auth
import auth_helpers
import backup
import browser_native_host
import crypto
import e2e_sync
import manager
import session_security


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.data = os.path.join(self.temp.name, 'data'); os.makedirs(self.data)
        self.auth_file = os.path.join(self.data, '.auth'); self.vault_file = os.path.join(self.data, '.vault.json')
        self.patches = [patch.object(auth, 'DATA_DIR', self.data), patch.object(auth, 'AUTH_FILE', self.auth_file),
            patch.object(auth, 'VAULT_FILE', self.vault_file), patch.object(auth, 'PENDING_CHANGE_FILE', os.path.join(self.data,'.pending')), patch.object(auth, 'RESTORE_PENDING_FILE', os.path.join(self.data,'.restore.pending')), patch.object(backup, 'RESTORE_PENDING_FILE', os.path.join(self.data,'.restore.pending')),
            patch.object(crypto, 'DATA_DIR', self.data), patch.object(crypto, 'KEY_FILE', os.path.join(self.data,'.key')),
            patch.object(manager, 'DATA_DIR', self.data), patch.object(manager, 'VAULT_FILE', self.vault_file),
            patch.object(auth_helpers, 'DATA_DIR', self.data)]
        for p in self.patches: p.start()
        crypto.clear_active_key()
        self.master = 'a long master password for tests 2026'
        record, _ = auth._make_auth(self.master)
        auth_helpers.atomic_write_json(self.auth_file, record); auth_helpers.atomic_write_json(self.vault_file, {'version':2,'entries':{}})
        self.assertTrue(auth.authenticate_password(self.master))
    def tearDown(self):
        crypto.clear_active_key()
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def test_metadata_is_encrypted_and_searchable(self):
        manager.save_password('Example', 'alice', 'a-long-password-1!', category='Work', tags=['dev','git'], url='https://example.com/login')
        with open(self.vault_file, encoding='utf-8') as f: raw=f.read()
        self.assertNotIn('example.com', raw); self.assertNotIn('Work', raw); self.assertNotIn('dev', raw)
        self.assertEqual(manager.search_records('git')[0]['username'], 'alice')
        self.assertEqual(manager.search_records(category='work')[0]['tags'], ['dev','git'])
        self.assertEqual(manager._decrypt('Example','alice'), 'a-long-password-1!')

    def test_exact_origin_matching(self):
        manager.save_password('Example','alice','safe-password',url='https://example.com/login')
        self.assertEqual(len(manager.records_for_origin('https://example.com')), 1)
        self.assertEqual(manager.records_for_origin('http://example.com'), [])
        self.assertEqual(manager.records_for_origin('https://evil-example.com'), [])
        self.assertEqual(manager.records_for_origin('https://example.com:444'), [])

    def test_health_report_detects_weak_and_reused(self):
        manager.save_password('One','alice','password')
        manager.save_password('Two','bob','password')
        manager.save_password('Three','eve','a much stronger unique phrase! 2026')
        report=manager.password_health_report()
        self.assertEqual(report['total_accounts'],3)
        self.assertEqual(report['weak_or_reused_accounts'],2)
        self.assertTrue(any('password reused across multiple accounts' in i for f in report['findings'] for i in f['issues']))

    def test_backup_restore_round_trip_and_wrong_passphrase_is_safe(self):
        manager.save_password('Example','alice','restore-me',category='Work',tags=['important'],url='https://example.com')
        backup_path=os.path.join(self.temp.name,'vault.pmbak')
        backup.create_backup(backup_path,'a strong backup passphrase')
        with open(backup_path,encoding='utf-8') as f: envelope=json.load(f)
        self.assertNotIn('restore-me',json.dumps(envelope))
        with open(self.vault_file,'rb') as f: before=f.read()
        with self.assertRaises(RuntimeError): backup.restore_backup(backup_path,'wrong backup passphrase','a long master password for tests 2026')
        with open(self.vault_file,'rb') as f: self.assertEqual(f.read(),before)
        manager.save_password('Other','bob','later-change')
        rollback=backup.restore_backup(backup_path,'a strong backup passphrase',self.master)
        self.assertTrue(os.path.isdir(rollback))
        self.assertIsNone(crypto._active_key)
        self.assertTrue(auth.authenticate_password(self.master))
        self.assertEqual(manager._decrypt('Example','alice'),'restore-me')
        self.assertNotIn('Other',manager.load_data())

    def test_backup_restore_rejects_wrong_master_without_modifying_files(self):
        manager.save_password('Example','alice','restore-me')
        path=os.path.join(self.temp.name,'vault.pmbak'); backup.create_backup(path,'another backup passphrase')
        with open(self.vault_file,'rb') as f: before=f.read()
        with self.assertRaisesRegex(RuntimeError,'Master password does not match'):
            backup.restore_backup(path,'another backup passphrase','incorrect but sufficiently long password')
        with open(self.vault_file,'rb') as f: self.assertEqual(f.read(),before)


    def test_interrupted_restore_journal_recovers_new_snapshot(self):
        manager.save_password('Old','alice','old-secret')
        with open(self.auth_file, encoding='utf-8') as f: old_auth=json.load(f)
        with open(self.vault_file, encoding='utf-8') as f: old_vault=json.load(f)
        new_password='new restored master password 2026'
        new_auth,new_key=auth._make_auth(new_password)
        new_vault={'version':2,'entries':auth._encrypt_entries({'New':{'bob':'new-secret'}},new_key)}
        auth_helpers.atomic_write_json(auth.RESTORE_PENDING_FILE, {'version':1,'old_auth':old_auth,'old_vault':old_vault,'new_auth':new_auth,'new_vault':new_vault})
        # Simulate a process stopping after the new vault was written but before auth was replaced.
        auth_helpers.atomic_write_json(self.vault_file,new_vault)
        crypto.clear_active_key()
        self.assertTrue(auth.authenticate_password(new_password))
        self.assertFalse(os.path.exists(auth.RESTORE_PENDING_FILE))
        self.assertEqual(manager._decrypt('New','bob'),'new-secret')
        self.assertNotIn('Old',manager.load_data())

    def test_tampered_backup_is_rejected_without_changes(self):
        manager.save_password('Example','alice','restore-me')
        path=os.path.join(self.temp.name,'tampered.pmbak')
        backup.create_backup(path,'a tamper test backup passphrase')
        with open(path,encoding='utf-8') as f: envelope=json.load(f)
        envelope['ciphertext']=envelope['ciphertext'][:-1] + ('A' if envelope['ciphertext'][-1] != 'A' else 'B')
        with open(path,'w',encoding='utf-8') as f: json.dump(envelope,f)
        with open(self.vault_file,'rb') as f: before=f.read()
        with self.assertRaises(RuntimeError): backup.restore_backup(path,'a tamper test backup passphrase',self.master)
        with open(self.vault_file,'rb') as f: self.assertEqual(f.read(),before)

    def test_session_timer_expires(self):
        with patch.object(session_security.time,'monotonic',side_effect=[100,131,132,132]):
            timer=session_security.SessionTimer(30)
            self.assertTrue(timer.expired())
            timer.touch(); self.assertFalse(timer.expired())

    def test_native_host_requires_unlock_and_exact_site(self):
        crypto.clear_active_key()
        response=browser_native_host.handle({'id':1,'action':'search','origin':'https://example.com'})
        self.assertFalse(response['ok'])
        self.assertTrue(auth.authenticate_password(self.master))
        manager.save_password('Example','alice','browser-secret',url='https://example.com/login')
        response=browser_native_host.handle({'id':2,'action':'search','origin':'https://example.com'})
        self.assertTrue(response['ok']); self.assertEqual(response['credentials'][0]['username'],'alice')
        denied=browser_native_host.handle({'id':3,'action':'get','origin':'https://evil-example.com','platform':'Example','username':'alice'})
        self.assertFalse(denied['ok'])
        allowed=browser_native_host.handle({'id':4,'action':'get','origin':'https://example.com','platform':'Example','username':'alice'})
        self.assertEqual(allowed['credential']['password'],'browser-secret')

    def test_native_host_full_vault_crud_actions(self):
        added=browser_native_host.handle({'id':31,'action':'add','platform':'DashboardTest','username':'alice','password':'initial-password','category':'Work','tags':['cli','browser'],'url':'https://dashboard.example.test'})
        self.assertTrue(added['ok'])
        listed=browser_native_host.handle({'id':32,'action':'list'})
        self.assertTrue(listed['ok']); self.assertEqual(listed['records'][0]['platform'],'DashboardTest')
        changed=browser_native_host.handle({'id':33,'action':'update_metadata','platform':'DashboardTest','username':'alice','category':'Development','tags':['browser'],'url':'https://dashboard.example.test'})
        self.assertTrue(changed['ok'])
        revealed=browser_native_host.handle({'id':34,'action':'reveal','platform':'DashboardTest','username':'alice'})
        self.assertEqual(revealed['password'],'initial-password')
        updated=browser_native_host.handle({'id':35,'action':'update_password','platform':'DashboardTest','username':'alice','password':'rotated-password'})
        self.assertTrue(updated['ok']); self.assertEqual(manager._decrypt('DashboardTest','alice'),'rotated-password')
        deleted=browser_native_host.handle({'id':36,'action':'delete','platform':'DashboardTest','username':'alice'})
        self.assertTrue(deleted['ok']); self.assertFalse(manager.load_data().get('DashboardTest'))

    def test_locked_new_device_can_bootstrap_from_encrypted_sync_snapshot(self):
        manager.save_password('RemoteSite','alice','remote-only-secret',url='https://remote.example.test')
        envelope=e2e_sync.current_envelope('shared-vault-id')
        crypto.clear_active_key()
        os.remove(self.auth_file); os.remove(self.vault_file)
        class FakeClient:
            def pull(self): return {'revision': 1, 'encrypted_payload': envelope}
        with patch.dict(os.environ, {'PM_SYNC_VAULT_ID':'shared-vault-id'}), patch.object(e2e_sync.SupabaseSyncClient,'from_env',return_value=FakeClient()):
            result=browser_native_host.handle({'id':90,'action':'sync_pull','master_password':self.master})
        self.assertTrue(result['ok'], result.get('error'))
        self.assertTrue(os.path.isfile(self.auth_file)); self.assertTrue(os.path.isfile(self.vault_file))
        self.assertEqual(manager._decrypt('RemoteSite','alice'),'remote-only-secret')

    def test_clipboard_clears_only_if_secret_unchanged(self):
        state={'text':''}
        fake=type('FakeClipboard',(),{'copy':staticmethod(lambda s: state.update(text=s)),'paste':staticmethod(lambda: state['text'])})
        with patch.dict(sys.modules, {'pyperclip':fake}), patch.object(session_security.threading,'Timer') as timer:
            session_security.copy_secret('secret-value',30)
            self.assertEqual(state['text'],'secret-value')
            clear=timer.call_args.args[1]; clear(); self.assertEqual(state['text'],'')
            session_security.copy_secret('secret-value',30); state['text']='user-copied-something-else'
            clear=timer.call_args.args[1]; clear(); self.assertEqual(state['text'],'user-copied-something-else')

if __name__ == '__main__': unittest.main(verbosity=2)
