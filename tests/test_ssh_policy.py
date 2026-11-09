import argparse
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import stat
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ssh_policy', ROOT / 'ssh/disable_root_ssh_password.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.config = self.base / 'sshd_config'
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Simulate root-owned fixture metadata; tests never require root.
        original_stat = Path.stat

        def root_stat(path, *args, **kwargs):
            values = list(original_stat(path, *args, **kwargs))
            values[4] = 0
            return os.stat_result(values)

        self.stack.enter_context(patch.object(Path, 'stat', root_stat))
        self.stack.enter_context(patch.object(policy, 'CONFIG', self.config))
        self.stack.enter_context(patch.object(policy, 'INCLUDE_BASE', self.base))
        self.stack.enter_context(patch.object(policy, 'BACKUP_BASE', self.base / 'backups'))
        self.stack.enter_context(patch.object(policy, 'say'))

    def write(self, name, text):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o600)
        return path

    def scan(self):
        return policy.scan_configs(self.config)

    def test_includes_match_comments_and_stricter_values(self):
        self.write('sshd_config', 'Include conf.d/*.conf\nMatch User root\n  PermitRootLogin yes # keep\n')
        child = self.write('conf.d/root.conf', 'PermitRootLogin=no\nMatch Address 203.0.113.0/24\nPermitRootLogin="yes"\n')
        originals, changes, locations = self.scan()
        self.assertEqual(len(originals), 2)
        self.assertEqual(len(locations), 2)
        self.assertIn(b'  PermitRootLogin prohibit-password  # keep', changes[self.config])
        self.assertIn(b'PermitRootLogin=no', changes[child])
        self.assertIn(b'PermitRootLogin prohibit-password', changes[child])
        # Scanning never modifies files.
        self.assertIn('PermitRootLogin yes', self.config.read_text())

    def test_idempotency_and_line_endings(self):
        self.config.write_bytes(b'PermitRootLogin yes\r\nPermitRootLogin no\r\n')
        self.config.chmod(0o600)
        _, changes, _ = self.scan()
        self.assertEqual(changes[self.config], b'PermitRootLogin prohibit-password\r\nPermitRootLogin no\r\n')
        self.config.write_bytes(changes[self.config])
        self.assertFalse(self.scan()[1])

    def test_all_safe_values_are_preserved(self):
        for value in sorted(policy.SAFE_ROOT_VALUES):
            with self.subTest(value=value):
                self.write('sshd_config', f'PermitRootLogin {value}\n')
                self.assertFalse(self.scan()[1])

    def test_cycle_is_rejected(self):
        self.write('sshd_config', 'Include child.conf\n')
        self.write('child.conf', 'Include sshd_config\n')
        with self.assertRaisesRegex(policy.Failure, 'Include'):
            self.scan()

    def test_group_writable_config_is_rejected(self):
        self.write('sshd_config', 'PermitRootLogin yes\n').chmod(0o660)
        with self.assertRaisesRegex(policy.Failure, 'root'):
            self.scan()

    def test_hard_linked_config_is_rejected(self):
        self.write('sshd_config', 'PermitRootLogin yes\n')
        os.link(self.config, self.base / 'hardlink')
        with self.assertRaisesRegex(policy.Failure, 'ссылок'):
            self.scan()

    def test_unrecognized_include_and_escaping_are_rejected(self):
        for text in ('Include conf[12]/*.conf\n', 'PermitRootLogin "y\\es"\n'):
            with self.subTest(text=text):
                self.write('sshd_config', text)
                with self.assertRaises(policy.Failure):
                    self.scan()

    def test_mfa_in_unsampled_match_is_rejected_before_changes(self):
        self.write('sshd_config', 'PermitRootLogin yes\nMatch Address 203.0.113.0/24\n'
                   'AuthenticationMethods publickey,keyboard-interactive:pam\n')
        originals, _, _ = self.scan()
        with patch.object(policy, 'effective') as effective:
            with self.assertRaisesRegex(policy.Failure, 'MFA'):
                policy.check_mfa('/fixture/sshd', originals)
            effective.assert_not_called()

    def test_mfa_with_key_only_alternative_is_accepted(self):
        self.write('sshd_config', 'PermitRootLogin yes\n'
                   'AuthenticationMethods publickey,password publickey\n')
        originals, _, _ = self.scan()
        with patch.object(policy, 'effective', return_value={
                'permitrootlogin': 'yes', 'authenticationmethods': 'publickey,password publickey'}):
            policy.check_mfa('/fixture/sshd', originals)

    def prepare_perform(self):
        info = {'Id': 'ssh.service', 'CanReload': 'yes', 'KillMode': 'process'}
        self.stack.enter_context(patch.object(policy, 'select_service', return_value=info))
        self.stack.enter_context(patch.object(policy, 'verify_runtime', return_value='/fixture/sshd'))
        run = self.stack.enter_context(patch.object(policy, 'run'))
        self.stack.enter_context(patch.object(policy, 'effective', return_value={'permitrootlogin': 'yes'}))
        self.stack.enter_context(patch.object(policy, 'check_mfa'))
        verify = self.stack.enter_context(patch.object(policy, 'verify_policy'))
        apply = self.stack.enter_context(patch.object(policy, 'apply_service', return_value='/fixture/sshd'))
        self.stack.enter_context(patch.object(policy, 'service_info', return_value={
            'ActiveState': 'active', 'CanReload': 'yes'}))
        self.stack.enter_context(patch.object(policy.os, 'chown'))
        self.stack.enter_context(patch.object(policy.signal, 'signal'))
        return run, verify, apply

    def test_check_is_read_only_and_returns_two(self):
        self.write('sshd_config', 'PermitRootLogin yes\n')
        _, _, apply = self.prepare_perform()
        self.assertEqual(policy.perform(argparse.Namespace(check=True, restart=False)), 2)
        self.assertEqual(self.config.read_text(), 'PermitRootLogin yes\n')
        self.assertFalse((self.base / 'backups').exists())
        apply.assert_not_called()

    def test_safe_noop_never_reloads_even_if_reload_unavailable(self):
        self.write('sshd_config', 'PermitRootLogin no\n')
        _, _, apply = self.prepare_perform()
        self.stack.enter_context(patch.object(policy, 'effective', return_value={'permitrootlogin': 'no'}))
        self.stack.enter_context(patch.object(policy, 'select_service', return_value={
            'Id': 'ssh.service', 'CanReload': 'no', 'KillMode': 'control-group'}))
        self.assertEqual(policy.perform(argparse.Namespace(check=False, restart=False)), 0)
        apply.assert_not_called()
        self.assertFalse((self.base / 'backups').exists())

    def test_successful_apply_and_backup(self):
        self.write('sshd_config', 'PermitRootLogin yes\n')
        _, _, apply = self.prepare_perform()
        self.assertEqual(policy.perform(argparse.Namespace(check=False, restart=False)), 0)
        apply.assert_called_once_with('ssh.service', 'reload')
        self.assertEqual(self.config.read_text(), 'PermitRootLogin prohibit-password\n')
        backup = list((self.base / 'backups').rglob('sshd_config'))
        self.assertEqual(len(backup), 1)
        self.assertEqual(backup[0].read_text(), 'PermitRootLogin yes\n')
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)

    def test_validation_failure_restores_without_reloading(self):
        self.write('sshd_config', 'PermitRootLogin yes\n')
        run, _, apply = self.prepare_perform()
        run.side_effect = [None, policy.Failure('invalid configuration'), None]
        self.assertEqual(policy.perform(argparse.Namespace(check=False, restart=False)), 1)
        self.assertEqual(self.config.read_text(), 'PermitRootLogin yes\n')
        apply.assert_not_called()

    def test_reload_failure_restores_and_recovers_service(self):
        self.write('sshd_config', 'PermitRootLogin yes\n')
        _, _, apply = self.prepare_perform()
        apply.side_effect = [policy.Failure('reload failed'), '/fixture/sshd']
        self.assertEqual(policy.perform(argparse.Namespace(check=False, restart=False)), 1)
        self.assertEqual(self.config.read_text(), 'PermitRootLogin yes\n')
        self.assertEqual(apply.call_count, 2)

    def test_unsafe_restart_is_rejected_before_backup(self):
        self.write('sshd_config', 'PermitRootLogin yes\n')
        self.prepare_perform()
        self.stack.enter_context(patch.object(policy, 'select_service', return_value={
            'Id': 'ssh.service', 'CanReload': 'yes', 'KillMode': 'control-group'}))
        with self.assertRaisesRegex(policy.Failure, 'KillMode'):
            policy.perform(argparse.Namespace(check=False, restart=True))
        self.assertFalse((self.base / 'backups').exists())

    def test_concurrent_change_is_not_overwritten_by_rollback(self):
        self.write('sshd_config', 'PermitRootLogin yes\n')
        _, verify, _ = self.prepare_perform()

        def external_change(_binary):
            self.config.write_text('# concurrent operator change\nPermitRootLogin no\n')
            raise policy.Failure('external change')

        verify.side_effect = external_change
        self.assertEqual(policy.perform(argparse.Namespace(check=False, restart=False)), 1)
        self.assertIn('# concurrent operator change', self.config.read_text())
        self.assertTrue(any('[CRITICAL]' in str(call) for call in policy.say.call_args_list))

    @unittest.skipUnless(Path('/usr/sbin/sshd').is_file() and shutil.which('ssh-keygen'),
                         'OpenSSH server and ssh-keygen are required for offline parser checks')
    def test_real_openssh_parser_before_and_after_rewrite(self):
        # Generate a disposable host key. Never start a daemon or open a port.
        hostkey = self.base / 'hostkey'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(hostkey)],
                       check=True, capture_output=True, timeout=15)
        self.write('sshd_config', f'HostKey "{hostkey}"\nInclude child.conf\n'
                   'PermitRootLogin yes\nMatch User root Address 203.0.113.0/24\n'
                   'PermitRootLogin yes\n')
        self.write('child.conf', '# empty fixture\n')

        def effective_for(address):
            result = subprocess.run([
                '/usr/sbin/sshd', '-T', '-f', str(self.config), '-C',
                f'user=root,host=example.test,addr={address},laddr=127.0.0.1,lport=22'],
                cwd=self.base, check=True, text=True, capture_output=True, timeout=15)
            return dict(line.split(None, 1) for line in result.stdout.splitlines() if ' ' in line)

        # Relative Includes are relative to /etc/ssh, so use an explicit temp path.
        self.config.write_text(self.config.read_text().replace(
            'Include child.conf', f'Include "{self.base / "child.conf"}"'))
        self.assertEqual(effective_for('203.0.113.8')['permitrootlogin'], 'yes')
        for path, content in self.scan()[1].items():
            path.write_bytes(content)
        subprocess.run(['/usr/sbin/sshd', '-t', '-f', str(self.config)],
                       check=True, capture_output=True, timeout=15)
        for address in ('203.0.113.8', '198.51.100.8'):
            self.assertEqual(effective_for(address)['permitrootlogin'], 'prohibit-password')


class RuntimeTests(unittest.TestCase):
    def test_timeout_is_reported_as_failure(self):
        with patch.object(policy.subprocess, 'run', side_effect=subprocess.TimeoutExpired('sshd', 45)):
            with self.assertRaises(policy.Failure):
                policy.run(['/fixture/sshd', '-t'])

    def test_subprocess_receives_argv_and_deadline(self):
        with patch.object(policy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            policy.run(['/fixture/sshd', '-t'])
            self.assertEqual(run.call_args.kwargs['timeout'], 45)
            self.assertNotIn('shell', run.call_args.kwargs)

    def test_non_root_invocation_does_not_open_lock(self):
        with patch.object(policy.os, 'geteuid', return_value=1000), patch.object(policy.os, 'open') as opened:
            with patch.object(policy, 'say'):
                self.assertEqual(policy.main(['--check']), 1)
            opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
