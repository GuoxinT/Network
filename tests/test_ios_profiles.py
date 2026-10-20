import base64
import ast
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from urllib.parse import quote, unquote


class IosProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        source = Path(__file__).resolve().parents[1] / 'server.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        assignments = {'PRIVATE_VPN_ROUTES', '_SR_LAN_DIRECT'}
        functions = {
            '_shadowrocket_url',
            '_shadowrocket_profile_url',
            '_shadowrocket_import_link',
            '_shadowrocket_subscription',
            '_shadowrocket_conf',
        }
        selected = []
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id in assignments
                       for target in targets):
                    selected.append(node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in functions:
                selected.append(node)
        cls.ns = {
            'base64': base64,
            'json': json,
            'os': os,
            'quote': quote,
            'secrets': __import__('secrets'),
            'SERVER_HOST': 'proxy.example.test',
            'PRIVATE_VPN_PORT_START': 8600,
        }
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), 'exec'), cls.ns)
        proxy_source = source.parent / 'Plugins/private-mac-vpn/scripts/private_socks.py'
        proxy_tree = ast.parse(proxy_source.read_text(encoding='utf-8'))
        route_function = next(
            node for node in proxy_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == 'route_from_username'
        )
        exec(compile(ast.Module(body=[route_function], type_ignores=[]),
                     str(proxy_source), 'exec'), cls.ns)

        cls.kid = 'TEST-KEY'
        cls.entry = {
            'mode': 'ios_shadowrocket',
            'device': 'iphone',
            'profile_token': 'profile-token',
            'private_vpn': True,
            'private_vpn_port': 8601,
            'private_vpn_password': 'private-password',
            'ss_port': 8401,
            'ss_method': 'chacha20-ietf-poly1305',
            'ss_password': 'direct-password',
        }
        cls.ns['DATA'] = {
            'root_key': 'root',
            'requests': {},
            'verify_keys': {cls.kid: cls.entry},
        }
        cls.ns['SS_CONFIG'] = str(Path(cls.temp_dir.name) / 'ss-config.json')
        Path(cls.ns['SS_CONFIG']).write_text(json.dumps({
            'server_host': 'proxy.example.test',
            'server_port': 8388,
            'method': 'chacha20-ietf-poly1305',
            'password': 'fallback-password',
        }), encoding='utf-8')
        cls.ns['_private_vpn_enabled_for'] = lambda kid, entry: True
        cls.ns['_private_vpn_cfg'] = lambda: {
            'enabled': True,
            'server_host': 'proxy.example.test',
            'server_port': 8600,
        }
        cls.ns['_ensure_private_vpn_user'] = lambda *args, **kwargs: False
        cls.ns['_ensure_ss_user'] = lambda *args, **kwargs: False
        cls.ns['_save'] = lambda *args, **kwargs: None
        cls.ns['request'] = types.SimpleNamespace(url_root='http://labvpn:5000/')

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_private_config_contains_every_route_and_direct_fallback(self):
        config = self.ns['_shadowrocket_conf'](self.kid, 'proxy.example.test')

        for route_id, route_name in self.ns['PRIVATE_VPN_ROUTES']:
            self.assertIn(
                f'{route_name} = socks5, proxy.example.test, 8601, '
                f'{self.kid}__{route_id}, private-password, udp-relay=true',
                config,
            )
        self.assertIn('MyNetwork Direct = ss, proxy.example.test, 8401,', config)
        self.assertIn('[Proxy Group]\nMyNetwork = select, ', config)
        self.assertIn('FINAL,MyNetwork', config)
        self.assertNotIn('username=', config)

    def test_legacy_subscription_refresh_returns_all_private_nodes(self):
        encoded = self.ns['_shadowrocket_subscription'](
            self.kid, 'proxy.example.test')
        nodes = base64.b64decode(encoded).decode().strip().splitlines()

        self.assertEqual(len(nodes), len(self.ns['PRIVATE_VPN_ROUTES']) + 1)
        self.assertEqual(sum(node.startswith('socks5://') for node in nodes), 11)
        self.assertTrue(nodes[-1].startswith('ss://'))
        for route_id, _route_name in self.ns['PRIVATE_VPN_ROUTES']:
            self.assertTrue(any(f'{self.kid}__{route_id}' in node for node in nodes))

    def test_private_users_receive_the_documented_config_import_link(self):
        link = self.ns['_shadowrocket_import_link'](self.kid)
        self.assertEqual(self.ns['_shadowrocket_url'](kid=self.kid), link)

        prefix = 'shadowrocket://config/add/'
        self.assertTrue(link.startswith(prefix))
        self.assertEqual(
            unquote(link[len(prefix):]),
            'http://labvpn:5000/api/profile/shadowrocket-conf/profile-token',
        )

    def test_legacy_subscription_link_uses_supported_add_scheme(self):
        link = self.ns['_shadowrocket_profile_url'](self.kid)

        prefix = 'shadowrocket://add/'
        self.assertTrue(link.startswith(prefix))
        self.assertEqual(
            unquote(link[len(prefix):]),
            'http://labvpn:5000/api/profile/shadowrocket/profile-token',
        )

    def test_generated_usernames_select_the_matching_backend_route(self):
        expected = {'username': self.kid}
        for route_id, _route_name in self.ns['PRIVATE_VPN_ROUTES']:
            self.assertEqual(
                self.ns['route_from_username'](f'{self.kid}__{route_id}', expected),
                route_id,
            )


if __name__ == '__main__':
    unittest.main()
