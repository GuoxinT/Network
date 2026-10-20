import importlib.util
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

try:
    import flask  # noqa: F401
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


@unittest.skipUnless(FLASK_AVAILABLE, 'Flask is required for endpoint tests')
class DashboardRecoveryEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        source = Path(__file__).resolve().parents[1] / 'server.py'
        module_path = Path(cls.temp_dir.name) / 'server.py'
        shutil.copyfile(source, module_path)
        spec = importlib.util.spec_from_file_location('mynetwork_recovery_server', module_path)
        cls.server = importlib.util.module_from_spec(spec)
        with mock.patch.object(threading.Thread, 'start', return_value=None):
            spec.loader.exec_module(cls.server)
        cls.server._save = lambda _data: None

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        self.entry = {
            'label': 'Recovery Test',
            'mode': 'ios_shadowrocket',
            'device': 'iphone',
            'profile_token': 'profile-token',
            'dashboard_token': 'dashboard-token',
            'activated': True,
            'ip_history': [],
        }
        self.server.DATA = {
            'root_key': 'ROOT-TEST',
            'requests': {},
            'verify_keys': {'TEST-KEY': self.entry},
        }
        self.client = self.server.app.test_client()

    def test_profile_token_migrates_to_rotating_dashboard_session(self):
        response = self.client.post('/api/session/recover', json={'token': 'profile-token'})

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload['ok'])
        self.assertNotEqual(payload['recovery_token'], 'dashboard-token')
        cookie = response.headers.get('Set-Cookie', '')
        self.assertIn('labvpn_key=TEST-KEY', cookie)
        self.assertIn('Max-Age=34560000', cookie)
        self.assertIn('HttpOnly', cookie)

        stale = self.client.post('/api/session/recover', json={'token': 'dashboard-token'})
        self.assertEqual(stale.status_code, 401)
        rotated = self.client.post(
            '/api/session/recover', json={'token': payload['recovery_token']})
        self.assertEqual(rotated.status_code, 200)

    def test_admin_link_uses_fragment_and_revocation_blocks_recovery(self):
        response = self.client.post(
            '/api/admin/keys/TEST-KEY/recovery-link',
            headers={'X-Root-Key': 'ROOT-TEST'},
        )
        self.assertEqual(response.status_code, 200)
        link = response.get_json()['recovery_link']
        self.assertIn('/#recover=', link)
        token = link.split('/#recover=', 1)[1]

        self.server.DATA['verify_keys'].clear()
        revoked = self.client.post('/api/session/recover', json={'token': token})
        self.assertEqual(revoked.status_code, 401)

    def test_private_profiles_route_gpu1_through_the_campus_outlet(self):
        self.entry.update({
            'private_vpn': True,
            'private_vpn_port': 8601,
            'private_vpn_password': 'private-password',
            'ss_port': 8401,
            'ss_method': 'chacha20-ietf-poly1305',
            'ss_password': 'direct-password',
        })
        ss_config = Path(self.temp_dir.name) / 'ss-config.json'
        ss_config.write_text(json.dumps({
            'server_host': 'proxy.example.test',
            'server_port': 8388,
            'method': 'chacha20-ietf-poly1305',
            'password': 'fallback-password',
        }), encoding='utf-8')

        with mock.patch.object(self.server, 'SS_CONFIG', str(ss_config)), \
                mock.patch.object(self.server, '_private_vpn_enabled_for', return_value=True), \
                mock.patch.object(self.server, '_private_vpn_cfg', return_value={
                    'enabled': True,
                    'server_host': 'proxy.example.test',
                    'server_port': 8600,
                }), \
                mock.patch.object(self.server, '_ensure_private_vpn_user', return_value=False), \
                mock.patch.object(self.server, '_ensure_ss_user', return_value=False):
            shadowrocket = self.server._shadowrocket_conf(
                'TEST-KEY', 'proxy.example.test')
            clash = self.server._clash_yaml('TEST-KEY', 'proxy.example.test')

        shadowrocket_rule = 'DOMAIN,gpu1.bucea.edu.cn,MyNetwork Direct'
        clash_rule = '  - DOMAIN,gpu1.bucea.edu.cn,MyNetwork Direct'
        self.assertIn(shadowrocket_rule, shadowrocket)
        self.assertLess(shadowrocket.index(shadowrocket_rule),
                        shadowrocket.index('FINAL,MyNetwork'))
        self.assertIn(clash_rule, clash)
        self.assertLess(clash.index(clash_rule), clash.index('  - MATCH,PROXY'))

    def test_private_gateway_routes_gpu1_before_per_node_selection(self):
        template = (Path(__file__).resolve().parents[1]
                    / 'Plugins/private-mac-vpn/mihomo.template.yaml').read_text(
                        encoding='utf-8')
        rule = '  - DOMAIN,gpu1.bucea.edu.cn,DIRECT'
        self.assertIn(rule, template)
        self.assertLess(template.index(rule),
                        template.index('  - IN-USER,us01,ROUTE-us01'))

    def test_campus_only_hostname_uses_campus_dns_on_every_backend(self):
        project = Path(__file__).resolve().parents[1]
        template = (project / 'Plugins/private-mac-vpn/mihomo.template.yaml').read_text(
            encoding='utf-8')
        direct_compose = (project / 'Plugins/shadowsocks-ios-mode/docker-compose.yml').read_text(
            encoding='utf-8')

        self.assertIn('nameserver-policy:', template)
        self.assertIn("'gpu1.bucea.edu.cn': 10.1.4.10", template)
        self.assertIn('    dns:\n      - 10.1.4.10', direct_compose)


if __name__ == '__main__':
    unittest.main()
