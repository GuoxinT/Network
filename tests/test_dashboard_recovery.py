import ast
import secrets
import unittest
from pathlib import Path


class FakeResponse:
    def __init__(self):
        self.cookie = None

    def set_cookie(self, *args, **kwargs):
        self.cookie = (args, kwargs)


class DashboardRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / 'server.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        assignments = {'COOKIE_NAME', 'USER_COOKIE_MAX_AGE'}
        functions = {
            '_ensure_dashboard_token',
            '_entry_for_recovery_token',
            '_set_user_cookie',
        }
        selected = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                if any(isinstance(target, ast.Name) and target.id in assignments
                       for target in node.targets):
                    selected.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in functions:
                selected.append(node)
        found_functions = {
            node.name for node in selected if isinstance(node, ast.FunctionDef)
        }
        if found_functions != functions:
            raise AssertionError('dashboard recovery helpers are incomplete')
        cls.ns = {'secrets': secrets}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), 'exec'), cls.ns)

    def setUp(self):
        self.entry = {'profile_token': 'profile-token'}
        self.ns['DATA'] = {'verify_keys': {'KEY-1': self.entry}}

    def test_dashboard_token_is_stable_until_rotated(self):
        first = self.ns['_ensure_dashboard_token'](self.entry)
        self.assertEqual(self.ns['_ensure_dashboard_token'](self.entry), first)
        rotated = self.ns['_ensure_dashboard_token'](self.entry, rotate=True)
        self.assertNotEqual(rotated, first)
        self.assertGreaterEqual(len(rotated), 32)

    def test_recovery_accepts_dashboard_and_legacy_profile_tokens(self):
        dashboard_token = self.ns['_ensure_dashboard_token'](self.entry)
        self.assertEqual(
            self.ns['_entry_for_recovery_token'](dashboard_token)[:2],
            ('KEY-1', self.entry),
        )
        self.assertEqual(
            self.ns['_entry_for_recovery_token']('profile-token')[:2],
            ('KEY-1', self.entry),
        )

    def test_revoked_key_cannot_be_recovered(self):
        token = self.ns['_ensure_dashboard_token'](self.entry)
        self.ns['DATA']['verify_keys'].clear()
        self.assertEqual(self.ns['_entry_for_recovery_token'](token), (None, None, None))

    def test_authenticated_requests_receive_a_rolling_cookie(self):
        response = FakeResponse()
        self.ns['_set_user_cookie'](response, 'KEY-1')
        args, kwargs = response.cookie
        self.assertEqual(args, ('labvpn_key', 'KEY-1'))
        self.assertEqual(kwargs['max_age'], 60 * 60 * 24 * 400)
        self.assertTrue(kwargs['httponly'])
        self.assertEqual(kwargs['samesite'], 'Lax')


if __name__ == '__main__':
    unittest.main()
