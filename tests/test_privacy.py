import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        shutil.copyfile(ROOT / 'server.py', self.directory / 'server.py')
        self.data = {
            'root_key': 'ROOT-TEST',
            'verify_keys': {'KEY-TEST': {
                'label': 'Test device', 'device': 'iphone',
                'mode': 'ios_shadowrocket', 'activated': True,
                'profile_token': 'secret-profile-token',
                'dashboard_token': 'secret-dashboard-token',
                'activated_ip': '10.20.30.40', 'last_ip': '10.20.30.41',
                'ip_history': ['10.20.30.40'], 'ss_port': 8400,
            }},
            'requests': {'request-test': {
                'status': 'pending', 'client_ip': '10.20.30.42',
            }},
        }
        (self.directory / 'keys.json').write_text(json.dumps(self.data))
        with mock.patch.object(threading.Thread, 'start'):
            self.server = load_module('privacy_test_server', self.directory / 'server.py')
        self.client = self.server.app.test_client()

    def test_existing_ip_history_is_removed_without_losing_credentials(self):
        saved = json.loads((self.directory / 'keys.json').read_text())
        self.assertNotIn('10.20.30.', json.dumps(saved))
        entry = saved['verify_keys']['KEY-TEST']
        self.assertEqual(entry['profile_token'], 'secret-profile-token')
        self.assertEqual(entry['ss_port'], 8400)

    def test_request_recovery_and_status_do_not_save_or_return_addresses(self):
        self.client.post('/api/request-key', json={'name': 'Alias', 'device': 'mac'},
                         environ_overrides={'REMOTE_ADDR': '10.50.60.70'})
        self.client.post('/api/session/recover', json={'token': 'secret-profile-token'},
                         environ_overrides={'REMOTE_ADDR': '10.50.60.70'})
        with mock.patch.object(self.server, '_shadowsocks_service_up', return_value=True):
            response = self.client.get('/api/user/status',
                                       environ_overrides={'REMOTE_ADDR': '10.50.60.70'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('10.50.60.70', response.get_data(as_text=True))
        self.assertNotIn('10.50.60.70', (self.directory / 'keys.json').read_text())
        self.assertIn('traffic_7d', response.get_json())

    def test_private_proxy_emits_only_byte_counts(self):
        proxy = load_module('privacy_test_proxy',
                            ROOT / 'Plugins/private-mac-vpn/scripts/private_socks.py')
        proxy.LOG_DIR = str(self.directory / 'counts')
        proxy.log_conn(8601, 120, 340)
        logs = list(Path(proxy.LOG_DIR).glob('*'))
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].name, 'user-8601.log')
        self.assertEqual(logs[0].read_text(), '120 340\n')

    def test_shadowsocks_filter_discards_addresses_errors_and_credentials(self):
        sample = (
            'tcp tunnel 10.20.30.40:51234 <-> sensitive.example:443 closed, '
            'L2R 120 bytes, R2L 340 bytes\n'
            'udp relay 10.20.30.40:51234 -> dns.example:53 with 45 bytes\n'
            'udp relay 10.20.30.40:51234 <- dns.example:53 with 65 bytes\n'
            'ERROR secret-password unable to connect sensitive.example\n'
            'tcp tunnel truncated confidential payload\n'
        )
        result = subprocess.run(
            [sys.executable, str(ROOT / 'Plugins/shadowsocks-ios-mode/scripts/traffic_filter.py')],
            input=sample, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True)
        self.assertEqual(result.stdout, '120 340\n45 0\n0 65\n')
        self.assertEqual(result.stderr, '')

    def test_sanitized_counts_reach_sqlite_and_legacy_lines_are_ignored(self):
        logs = self.directory / 'counts'
        logs.mkdir()
        (logs / 'user-8400.log').write_text(
            '120 340\n45 0\n0 65\n'
            'tcp tunnel 10.20.30.40:42 <-> secret.example:443 closed, L2R 99 bytes, R2L 99 bytes\n'
            'invalid\n-1 3\n')
        self.server.SS_LOG_DIR = str(logs)
        self.server.PRIVATE_VPN_LOG_DIR = str(self.directory / 'absent')
        self.server._process_proxy_logs()
        self.server._flush_pending_traffic()
        totals = self.server._traffic_7d('KEY-TEST')
        self.assertEqual(sum(row['up'] for row in totals), 165)
        self.assertEqual(sum(row['down'] for row in totals), 405)

    def test_http_logger_never_emits_raw_request_or_token(self):
        output = io.StringIO()
        with mock.patch('sys.stderr', output):
            handler = object.__new__(self.server.PrivacyRequestHandler)
            handler.log('info', 'GET /api/profile/clash/secret-profile-token 10.20.30.40')
        self.assertEqual(output.getvalue(), '')

    def test_unhandled_http_exception_does_not_log_or_return_private_details(self):
        @self.server.app.route('/test-private-error')
        def fail():
            raise RuntimeError('secret-profile-token at sensitive.example')
        output = io.StringIO()
        with mock.patch('sys.stderr', output):
            response = self.client.get('/test-private-error')
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()['error'], 'Internal server error')
        self.assertNotIn('secret-profile-token', output.getvalue())
        self.assertNotIn('sensitive.example', output.getvalue())

    def test_new_shadowsocks_users_launch_through_the_filter_wrapper(self):
        for code in (0, 1):
            with mock.patch.object(self.server, '_shadowsocks_service_up', return_value=True), \
                    mock.patch.object(self.server, '_write_ssserver_config'), \
                    mock.patch.object(self.server.subprocess, 'run', side_effect=[
                        subprocess.CompletedProcess([], 1),
                        subprocess.CompletedProcess([], code),
                    ]) as run:
                started = self.server._ensure_ss_process(
                    'KEY-TEST', {'ss_port': 8400, 'ss_password': 'private-password'})
            self.assertEqual(started, code == 0)
            command = run.call_args_list[1][0][0]
            self.assertEqual(command[4], '/app/scripts/run-user.sh')
            self.assertEqual(command[6], '/app/state/traffic/user-8400.log')
            self.assertNotIn('private-password', ' '.join(command))

    def test_cleanup_is_limited_to_project_history_and_preserves_totals(self):
        migration = load_module('privacy_cleanup', ROOT / 'ops/privacy_cleanup.py')
        old = self.directory / migration.LOG_DIRECTORIES[0]
        old.mkdir(parents=True)
        (old / 'user-8400-KEY-TEST.log').write_text('sensitive.example')
        (old / 'user-8400-KEY-TEST.log.1.gz').write_bytes(b'old archive')
        (old / 'keep.txt').write_text('unrelated')
        (self.directory / 'server.log').write_text('secret-token')
        database = (self.directory / 'traffic.sqlite3').read_bytes()
        self.assertEqual(migration.cleanup(self.directory), 2)
        self.assertEqual((old / 'keep.txt').read_text(), 'unrelated')
        self.assertEqual((self.directory / 'server.log').read_text(), '')
        self.assertEqual((self.directory / 'traffic.sqlite3').read_bytes(), database)

    def test_admin_payload_has_totals_but_no_destination_audit(self):
        with mock.patch.object(self.server, '_admin_diagnostics', return_value={}):
            result = self.server._admin_analytics()
        self.assertEqual(set(result), {'traffic', 'diagnostics'})
        self.assertIn('days', result['traffic'])

    def test_cleanup_rejects_redirected_log_directory(self):
        migration = load_module('privacy_cleanup', ROOT / 'ops/privacy_cleanup.py')
        outside = self.directory / 'outside'
        outside.mkdir()
        secret = outside / 'user-8400.log'
        secret.write_text('must remain')
        old = self.directory / migration.LOG_DIRECTORIES[0]
        old.parent.mkdir(parents=True)
        old.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            migration.cleanup(self.directory)
        self.assertEqual(secret.read_text(), 'must remain')

    def test_only_ssh_fallback_keeps_short_lived_ip_attribution(self):
        with self.server.app.test_request_context():
            self.server._entry_for('KEY-TEST', '10.50.60.70')
            self.assertEqual(self.server._ssh_clients, {})
            self.server.DATA['verify_keys']['KEY-TEST']['mode'] = 'ssh_runner'
            self.server._entry_for('KEY-TEST', '10.50.60.70')
        self.assertEqual(self.server._best_key_for_ip('10.50.60.70', ('ssh_runner',))[0],
                         'KEY-TEST')
        with mock.patch.object(self.server.time, 'monotonic', return_value=float('inf')):
            self.assertEqual(self.server._best_key_for_ip('10.50.60.70', ('ssh_runner',)),
                             (None, None))


if __name__ == '__main__':
    unittest.main()
