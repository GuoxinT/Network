#!/usr/bin/env python3
"""Remove only legacy MyNetwork application logs after stopping its writers.

Does not access system/SSH/security-agent logs, Docker logs or SQLite totals.
Run from the deployed project: python3 ops/privacy_cleanup.py
"""
import json
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOG_DIRECTORIES = (
    'Plugins/shadowsocks-ios-mode/state/logs',
    'Plugins/private-mac-vpn/state/logs',
)
LEGACY_LOG = re.compile(r'(?:user|shared)-[A-Za-z0-9-]+\.log(?:\.\d+(?:\.gz)?)?$')


def cleanup(root):
    root = root.resolve()
    removed = 0
    for relative in LOG_DIRECTORIES:
        directory = root / relative
        if not directory.exists():
            continue
        if directory.is_symlink() or directory.resolve() != directory:
            raise RuntimeError('Refusing a redirected log directory')
        for path in directory.iterdir():
            if LEGACY_LOG.fullmatch(path.name) and not path.is_symlink() and path.is_file():
                path.unlink()
                removed += 1
    # The old Flask access log contains client IPs and subscription tokens.
    access_log = root / 'server.log'
    if access_log.is_file() and not access_log.is_symlink():
        with access_log.open('w'):
            pass
    key_file = root / 'keys.json'
    if key_file.is_file() and not key_file.is_symlink():
        data = json.loads(key_file.read_text(encoding='utf-8'))
        for entry in list(data.get('verify_keys', {}).values()) + list(data.get('requests', {}).values()):
            for field in ('activated_ip', 'last_ip', 'ip_history', 'client_ip'):
                entry.pop(field, None)
        temp = root / 'keys.privacy-tmp'
        with temp.open('x', encoding='utf-8') as stream:
            os.chmod(str(temp), 0o600)
            json.dump(data, stream, indent=2)
        os.replace(str(temp), str(key_file))
    return removed


if __name__ == '__main__':
    print('Removed %d legacy project logs; cleared project HTTP log and IP history. '
          'Traffic totals and credentials retained.' % cleanup(ROOT))
