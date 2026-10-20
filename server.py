#!/usr/bin/env python3
"""ServerFetch MyNetwork — server.py

Runs on the lab machine. Generates a per-user SSH key, serves a tiny runner
that opens an SSH SOCKS5 tunnel, and — because every tunnel terminates here —
measures each user's live throughput / data-flow / connect history server-side.
That means the runner needs nothing but a built-in `ssh` (no Python on the
client), and the dashboard still shows real stats for every user.
"""
import os, re, json, time, shutil, secrets, threading, subprocess, base64, pwd, sqlite3
from collections import deque
from datetime import datetime, timedelta
from urllib.parse import quote
from flask import Flask, request, jsonify, Response, send_file, abort
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
_HTTP_EVENTS = deque(maxlen=120)

@app.after_request
def _remember_http_event(resp):
    try:
        path = request.path or ''
        if not path.startswith('/api/admin'):
            _HTTP_EVENTS.appendleft({
                'time': _now_iso(),
                'ip': request.remote_addr,
                'path': path,
                'status': resp.status_code,
            })
    except Exception:
        pass
    return resp

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE   = os.path.join(BASE_DIR, 'keys.json')
KEYS_DIR    = os.path.join(BASE_DIR, 'keys')
SS_CONFIG   = os.path.join(BASE_DIR, 'Plugins', 'shadowsocks-ios-mode', 'config.json')
SS_USERS    = os.path.join(BASE_DIR, 'Plugins', 'shadowsocks-ios-mode', 'state', 'users.json')
SS_CONFIG_DIR = os.path.join(BASE_DIR, 'Plugins', 'shadowsocks-ios-mode', 'state', 'ssserver.d')
SS_LOG_DIR = os.path.join(BASE_DIR, 'Plugins', 'shadowsocks-ios-mode', 'state', 'logs')
PRIVATE_VPN_CONFIG = os.path.join(BASE_DIR, 'Plugins', 'private-mac-vpn', 'config.json')
PRIVATE_VPN_USERS = os.path.join(BASE_DIR, 'Plugins', 'private-mac-vpn', 'state', 'users.json')
PRIVATE_VPN_CONFIG_DIR = os.path.join(BASE_DIR, 'Plugins', 'private-mac-vpn', 'state', 'ssserver.d')
PRIVATE_VPN_LOG_DIR = os.path.join(BASE_DIR, 'Plugins', 'private-mac-vpn', 'state', 'logs')
TRAFFIC_DB  = os.path.join(BASE_DIR, 'traffic.sqlite3')
SSH_USER    = os.environ.get('SSH_USER',    'user1')
SERVER_HOST = os.environ.get('SERVER_HOST', '10.1.4.43')
DISPLAY_HOST = os.environ.get('DISPLAY_HOST', 'labvpn')
SSH_PORT    = str(os.environ.get('SSH_PORT', '22'))
AUTH_KEYS   = os.environ.get('AUTH_KEYS',   '')
LOCK_TO_FIRST_IP = False
KICK_SSH_ON_REVOKE = False
COOKIE_NAME = 'labvpn_key'
USER_COOKIE_MAX_AGE = 60 * 60 * 24 * 400
MOBILE_PROXY_CONTAINER = 'Network'
PRIVATE_VPN_PROXY_CONTAINER = 'PrivateVPNProxy'
VALID_DEVICES = ('iphone', 'android', 'mac', 'windows')
SS_USER_PORT_START = 8400
SS_USER_PORT_END = 8599
PRIVATE_VPN_PORT_START = 8600
PRIVATE_VPN_PORT_END = 8699
PRIVATE_VPN_ROUTES = (
    ('us01', 'MyNetwork US01'),
    ('us02', 'MyNetwork US02'),
    ('us03', 'MyNetwork US03'),
    ('us04', 'MyNetwork US04'),
    ('us05', 'MyNetwork US05'),
    ('us06', 'MyNetwork US06'),
    ('us07', 'MyNetwork US07'),
    ('us08', 'MyNetwork US08'),
    ('ashburn01', 'MyNetwork Ashburn01'),
    ('ashburn02', 'MyNetwork Ashburn02'),
    ('ashburn03', 'MyNetwork Ashburn03'),
)
# Local timezone offset (hours) used only for bucketing traffic into days/hours
# so the dashboard's "today" matches the operator's wall clock. Default +8
# (China). Stored timestamps elsewhere stay UTC; only bucket labels shift.
TRAFFIC_TZ_OFFSET_HOURS = int(os.environ.get('TRAFFIC_TZ_OFFSET_HOURS', '8'))
# Key id used to bucket traffic on the shared Shadowsocks port, which cannot be
# attributed to a single user (one port, one shared password).
SHARED_TRAFFIC_KEY = '__shared__'
_IOS_NET = {
    'rx': None, 'tx': None, 't': None,
    'base_rx': None, 'base_tx': None,
    'rx_bps': 0, 'tx_bps': 0,
}

os.makedirs(KEYS_DIR, mode=0o700, exist_ok=True)
try:
    os.chmod(KEYS_DIR, 0o700)
except OSError:
    pass

# ── Key store ────────────────────────────────────────────────────────────────

def _load():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE) as f:
            return json.load(f)
    return None

def _save(data):
    with open(KEYS_FILE, 'w') as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(KEYS_FILE, 0o600)
    except OSError:
        pass

def _now_iso():
    return datetime.utcnow().isoformat()

def _iso_age_seconds(iso):
    if not iso:
        return None
    try:
        raw = iso.replace('Z', '').split('.', 1)[0]
        return (datetime.utcnow() - datetime.strptime(raw, '%Y-%m-%dT%H:%M:%S')).total_seconds()
    except Exception:
        return None

def _init():
    data = _load()
    if not data:
        root_key = 'ROOT-' + secrets.token_hex(12).upper()
        data = {'root_key': root_key, 'verify_keys': {}, 'requests': {}}
        _save(data)
        print('\n' + '=' * 60)
        print('  ROOT KEY (save this — it cannot be recovered!)')
        print(f'  {root_key}')
        print('=' * 60 + '\n')
    elif os.path.exists(KEYS_FILE):
        data.setdefault('verify_keys', {})
        data.setdefault('requests', {})
        try:
            os.chmod(KEYS_FILE, 0o600)
        except OSError:
            pass
    return data

DATA = _init()

def _ensure_dashboard_token(entry, rotate=False):
    if rotate or not entry.get('dashboard_token'):
        entry['dashboard_token'] = secrets.token_urlsafe(32)
    return entry['dashboard_token']

def _entry_for_recovery_token(token):
    token = (token or '').strip()
    if not token:
        return None, None, None
    for kid, entry in DATA.get('verify_keys', {}).items():
        dashboard_token = entry.get('dashboard_token') or ''
        if dashboard_token and secrets.compare_digest(dashboard_token, token):
            return kid, entry, 'dashboard'
        profile_token = entry.get('profile_token') or ''
        if profile_token and secrets.compare_digest(profile_token, token):
            return kid, entry, 'profile'
    return None, None, None

def _set_user_cookie(resp, kid):
    resp.set_cookie(COOKIE_NAME, kid, max_age=USER_COOKIE_MAX_AGE,
                    httponly=True, samesite='Lax')
    return resp

def _ok_root(key):
    return secrets.compare_digest(key or '', DATA['root_key'])

def _request_host(default=SERVER_HOST):
    host = (request.host or '').split(':', 1)[0].strip()
    if not host or host in ('127.0.0.1', 'localhost'):
        return default
    return host

def _is_loopback_ip(ip):
    return ip in ('127.0.0.1', '::1', 'localhost')

def _norm_device(device):
    d = (device or '').strip().lower()
    aliases = {
        'ios': 'iphone',
        'iphone': 'iphone',
        'ipad': 'iphone',
        'android': 'android',
        'clash': 'android',
        'clash meta': 'android',
        'mac': 'mac',
        'macos': 'mac',
        'macbook': 'mac',
        'windows': 'windows',
        'win': 'windows',
        'pc': 'windows',
    }
    return aliases.get(d, d if d in VALID_DEVICES else 'windows')

def _device_kind(device):
    device = _norm_device(device)
    if device == 'iphone':
        return 'ios_shadowrocket'
    if device == 'android':
        return 'android_clash'
    if device in ('mac', 'windows'):
        return 'desktop_clash'
    return 'verify_key'

_traffic_write_lock = threading.Lock()

def _traffic_db():
    """Open the traffic DB with a generous busy timeout. WAL mode (set once at
    init) lets the 0.5 s sampler write while admin/user reads run concurrently
    without hitting 'database is locked'."""
    db = sqlite3.connect(TRAFFIC_DB, timeout=30)
    db.execute('PRAGMA busy_timeout=30000')
    return db

def _init_traffic_db():
    with _traffic_db() as db:
        try:
            db.execute('PRAGMA journal_mode=WAL')
        except sqlite3.DatabaseError:
            pass
        db.execute('''
            CREATE TABLE IF NOT EXISTS traffic_daily (
                key_id TEXT NOT NULL,
                day TEXT NOT NULL,
                down_bytes INTEGER NOT NULL DEFAULT 0,
                up_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key_id, day)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS traffic_hourly (
                key_id TEXT NOT NULL,
                hour TEXT NOT NULL,
                down_bytes INTEGER NOT NULL DEFAULT 0,
                up_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key_id, hour)
            )
        ''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_traffic_hourly_hour ON traffic_hourly(hour)')
    try:
        os.chmod(TRAFFIC_DB, 0o600)
    except OSError:
        pass

def _traffic_now():
    """Wall-clock time in the operator's timezone, used for day/hour bucketing."""
    return datetime.utcnow() + timedelta(hours=TRAFFIC_TZ_OFFSET_HOURS)

def _local_hour(dt=None):
    dt = dt or _traffic_now()
    return dt.replace(minute=0, second=0, microsecond=0).isoformat()

# In-memory accrual of byte deltas keyed by key id. The sampler adds to this
# every 0.5 s; a flusher writes it to SQLite in one transaction every few
# seconds. This is the single source of truth for billing — it is fed only by
# socket byte counters (see _monitor_loop), never by parsing connection logs.
_pending_traffic = {}

def _accrue_traffic(kid, down_bytes, up_bytes):
    down_bytes = int(down_bytes or 0)
    up_bytes = int(up_bytes or 0)
    if not kid or (down_bytes <= 0 and up_bytes <= 0):
        return
    # Caller already holds _mon_lock.
    slot = _pending_traffic.setdefault(kid, [0, 0])
    slot[0] += max(0, down_bytes)
    slot[1] += max(0, up_bytes)

def _flush_pending_traffic():
    global _pending_traffic
    with _mon_lock:
        pending, _pending_traffic = _pending_traffic, {}
    pending = {k: v for k, v in pending.items() if v[0] > 0 or v[1] > 0}
    if not pending:
        return
    now = _traffic_now()
    day = now.date().isoformat()
    hour = _local_hour(now)
    with _traffic_write_lock, _traffic_db() as db:
        for kid, (down, up) in pending.items():
            # CentOS 7 may ship an older SQLite without UPSERT support.
            db.execute('INSERT OR IGNORE INTO traffic_daily(key_id, day, down_bytes, up_bytes) VALUES (?, ?, 0, 0)',
                       (kid, day))
            db.execute('UPDATE traffic_daily SET down_bytes = down_bytes + ?, up_bytes = up_bytes + ? WHERE key_id = ? AND day = ?',
                       (down, up, kid, day))
            db.execute('INSERT OR IGNORE INTO traffic_hourly(key_id, hour, down_bytes, up_bytes) VALUES (?, ?, 0, 0)',
                       (kid, hour))
            db.execute('UPDATE traffic_hourly SET down_bytes = down_bytes + ?, up_bytes = up_bytes + ? WHERE key_id = ? AND hour = ?',
                       (down, up, kid, hour))

def _traffic_7d(kid):
    today = _traffic_now().date()
    days = [(today.fromordinal(today.toordinal() - i)).isoformat() for i in range(6, -1, -1)]
    rows = {}
    with _traffic_db() as db:
        for day, down, up in db.execute(
                'SELECT day, down_bytes, up_bytes FROM traffic_daily WHERE key_id = ? AND day >= ?',
                (kid, days[0])):
            rows[day] = {'down': down, 'up': up}
    return [{'day': day, 'down': rows.get(day, {}).get('down', 0), 'up': rows.get(day, {}).get('up', 0)}
            for day in days]

def _admin_hourly_traffic(hours=168):
    end = _traffic_now().replace(minute=0, second=0, microsecond=0)
    slots = []
    for i in range(hours - 1, -1, -1):
        dt = end - timedelta(hours=i)
        slots.append(dt.isoformat())
    rows = {hour: {'hour': hour, 'down': 0, 'up': 0, 'total': 0} for hour in slots}
    with _traffic_db() as db:
        for hour, down, up in db.execute(
                'SELECT hour, SUM(down_bytes), SUM(up_bytes) FROM traffic_hourly WHERE hour >= ? GROUP BY hour',
                (slots[0],)):
            if hour in rows:
                down = int(down or 0)
                up = int(up or 0)
                rows[hour] = {'hour': hour, 'down': down, 'up': up, 'total': down + up}
    series = [rows[hour] for hour in slots]
    peak = max(series, key=lambda r: r['total']) if series else {'hour': '', 'down': 0, 'up': 0, 'total': 0}
    return {
        'hours': series,
        'peak': peak,
        'total_down': sum(r['down'] for r in series),
        'total_up': sum(r['up'] for r in series),
        'total': sum(r['total'] for r in series),
    }

_init_traffic_db()

def _create_verify_key(label, device=None, mode=None):
    kid = '-'.join(secrets.token_hex(2).upper() for _ in range(4))
    _keygen(kid)
    _auth_add(kid)
    device = _norm_device(device)
    DATA['verify_keys'][kid] = {
        'label':        label,
        'device':       device,
        'mode':         mode or ('ios_shadowrocket' if device == 'iphone'
                                 else ('android_clash' if device == 'android'
                                       else ('desktop_clash' if device in ('mac', 'windows') else 'ssh_runner'))),
        'profile_token': secrets.token_urlsafe(24),
        'created_at':   datetime.utcnow().isoformat(),
        'activated':    False,
        'activated_at': None,
        'activated_ip': None,
        'last_ip':      None,
        'ip_history':   [],
    }
    return kid

def _record_key_ip(entry, client_ip, activate=False):
    if not client_ip:
        return False
    changed = False
    if activate and not entry.get('activated'):
        entry['activated'] = True
        entry['activated_at'] = datetime.utcnow().isoformat()
        changed = True
    if _is_loopback_ip(client_ip):
        age = _iso_age_seconds(entry.get('last_seen_at'))
        if age is None or age > 60:
            entry['last_seen_at'] = _now_iso()
            changed = True
        return changed
    if not entry.get('activated_ip'):
        entry['activated_ip'] = client_ip
        changed = True
    if entry.get('last_ip') != client_ip:
        entry['last_ip'] = client_ip
        changed = True
    hist = entry.setdefault('ip_history', [])
    if client_ip not in hist:
        hist.append(client_ip)
        del hist[:-20]
        changed = True
    age = _iso_age_seconds(entry.get('last_seen_at'))
    if age is None or age > 60:
        entry['last_seen_at'] = _now_iso()
        changed = True
    return changed

def _mark_key_seen(entry, client_ip=None):
    changed = False
    if client_ip:
        changed = _record_key_ip(entry, client_ip) or changed
    else:
        age = _iso_age_seconds(entry.get('last_seen_at'))
        if age is None or age > 60:
            entry['last_seen_at'] = _now_iso()
            changed = True
    return changed

def _mark_ios_key_active(kid, req):
    entry = DATA.get('verify_keys', {}).get(kid)
    if not entry:
        return False
    device = _norm_device(req.get('device', 'iphone'))
    if device == 'android':
        mode = 'android_clash'
    elif device in ('mac', 'windows'):
        mode = 'desktop_clash'
    else:
        mode = 'ios_shadowrocket'
    changed = False
    for key, val in (
        ('mode', mode),
        ('device', device),
        ('activated', True),
    ):
        if entry.get(key) != val and val is not None:
            entry[key] = val
            changed = True
    if not entry.get('activated_at'):
        entry['activated_at'] = req.get('approved_at') or datetime.utcnow().isoformat()
        changed = True
    if not entry.get('profile_token'):
        entry['profile_token'] = secrets.token_urlsafe(24)
        changed = True
    changed = _record_key_ip(entry, req.get('client_ip'), activate=True) or changed
    return changed

def _repair_approved_ios_keys():
    changed = False
    for req in DATA.get('requests', {}).values():
        if (req.get('status') == 'approved'
                and req.get('kind') in ('ios_shadowrocket', 'android_clash', 'desktop_clash')
                and req.get('key')):
            changed = _mark_ios_key_active(req['key'], req) or changed
    if changed:
        _save(DATA)

def _shadowsocks_service_up():
    try:
        r = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', MOBILE_PROXY_CONTAINER],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=2,
        )
        return (r.stdout or '').strip().lower() == 'true'
    except Exception:
        return False

def _shadowsocks_port():
    try:
        with open(SS_CONFIG) as f:
            return str(int(json.load(f).get('server_port', 8388)))
    except Exception:
        return '8388'

def _ss_password():
    # Shadowsocks 2022 ciphers require a base64 key of the right length.
    return base64.b64encode(os.urandom(16)).decode()

def _used_ss_ports():
    ports = set()
    try:
        ports.add(int(_shadowsocks_port()))
    except Exception:
        ports.add(8388)
    for entry in DATA.get('verify_keys', {}).values():
        if entry.get('ss_port'):
            ports.add(int(entry['ss_port']))
    return ports

def _allocate_ss_port():
    used = _used_ss_ports()
    for port in range(SS_USER_PORT_START, SS_USER_PORT_END + 1):
        if port not in used:
            return port
    raise RuntimeError('No free Shadowsocks per-user ports available')

def _ss_config_name(kid, port):
    safe_key = ''.join(c if c.isalnum() else '-' for c in kid)
    return ('user-%s-%s.json' % (int(port), safe_key))[:90]

def _ss_log_name(kid, port):
    return _ss_config_name(kid, port).rsplit('.', 1)[0] + '.log'

def _write_ssserver_config(path, port, password, method, cfg_path=SS_CONFIG):
    try:
        with open(cfg_path) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    out = {
        'server': '0.0.0.0',
        'server_port': int(port),
        'password': password,
        'method': method,
        'timeout': int(cfg.get('timeout', 300)),
        'mode': cfg.get('mode', 'tcp_and_udp'),
    }
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(out, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def _ensure_ss_process(kid, entry):
    if not _shadowsocks_service_up():
        return False
    port = entry.get('ss_port')
    if not port:
        return False
    name = _ss_config_name(kid, port)
    host_path = os.path.join(SS_CONFIG_DIR, name)
    container_path = '/app/state/ssserver.d/' + name
    container_log = '/app/state/logs/' + _ss_log_name(kid, port)
    _write_ssserver_config(host_path, port, entry.get('ss_password'), entry.get('ss_method') or _ss_method())
    try:
        check = subprocess.run(
            ['docker', 'exec', MOBILE_PROXY_CONTAINER, 'sh', '-lc',
             "ps -ef | grep -F 'ssserver' | grep -F %s | grep -v grep" % sh_quote(container_path)],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=4,
        )
        if check.returncode == 0:
            return True
        subprocess.run(
            ['docker', 'exec', '-d', MOBILE_PROXY_CONTAINER, 'sh', '-lc',
             "while true; do ssserver -vv -c %s 2>&1 | awk '/tcp tunnel .* closed|udp relay .* with [0-9]+ bytes/ { print; fflush(); }' >> %s; echo \"$(date -u +%%FT%%TZ) ssserver exited for %s; restarting in 1s\" >> %s; sleep 1; done"
             % (sh_quote(container_path), sh_quote(container_log), sh_quote(container_path), sh_quote(container_log))],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=6,
        )
        return True
    except Exception:
        return False

def sh_quote(s):
    return "'" + str(s).replace("'", "'\"'\"'") + "'"

def _monitored_ports():
    ports = {str(SSH_PORT), str(_shadowsocks_port())}
    for entry in DATA.get('verify_keys', {}).values():
        if entry.get('ss_port'):
            ports.add(str(entry['ss_port']))
        if entry.get('private_vpn_port'):
            ports.add(str(entry['private_vpn_port']))
    return tuple(sorted(ports))

def _sync_ss_users(restart=False):
    users = []
    for kid, entry in DATA.get('verify_keys', {}).items():
        if entry.get('mode') not in ('ios_shadowrocket', 'android_clash', 'desktop_clash'):
            continue
        if not entry.get('ss_port') or not entry.get('ss_password'):
            continue
        users.append({
            'key': kid,
            'label': entry.get('label', ''),
            'port': int(entry['ss_port']),
            'password': entry['ss_password'],
            'method': entry.get('ss_method') or _ss_method(),
            'enabled': True,
        })
    os.makedirs(os.path.dirname(SS_USERS), mode=0o700, exist_ok=True)
    with open(SS_USERS, 'w') as f:
        json.dump({'users': users, 'updated_at': _now_iso()}, f, indent=2)
    try:
        os.chmod(SS_USERS, 0o600)
    except OSError:
        pass
    for item in users:
        _write_ssserver_config(
            os.path.join(SS_CONFIG_DIR, _ss_config_name(item['key'], item['port'])),
            item['port'], item['password'], item['method'])
    if restart:
        try:
            subprocess.run(['docker', 'restart', MOBILE_PROXY_CONTAINER],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=15)
        except Exception:
            pass

def _ss_method():
    try:
        with open(SS_CONFIG) as f:
            return json.load(f).get('method', '2022-blake3-aes-128-gcm')
    except Exception:
        return '2022-blake3-aes-128-gcm'

def _preferred_ss_method(entry):
    if (entry or {}).get('mode') == 'ios_shadowrocket':
        return 'chacha20-ietf-poly1305'
    return _ss_method()

def _private_vpn_cfg():
    cfg = {
        'enabled': False,
        'server_host': SERVER_HOST,
        'server_port': PRIVATE_VPN_PORT_START,
        'method': 'chacha20-ietf-poly1305',
        'timeout': 300,
        'mode': 'tcp_and_udp',
        'keys': [],
    }
    try:
        with open(PRIVATE_VPN_CONFIG) as f:
            raw = json.load(f)
        cfg.update(raw or {})
    except Exception:
        pass
    return cfg

def _private_vpn_enabled_for(kid, entry):
    cfg = _private_vpn_cfg()
    keys = set(str(k).strip() for k in (cfg.get('keys') or []) if str(k).strip())
    return bool(cfg.get('enabled') and not entry.get('private_vpn_disabled') and
                (kid in keys or entry.get('private_vpn')))

def _used_private_vpn_ports():
    ports = set()
    for entry in DATA.get('verify_keys', {}).values():
        if entry.get('private_vpn_port'):
            ports.add(int(entry['private_vpn_port']))
    return ports

def _allocate_private_vpn_port():
    used = _used_private_vpn_ports()
    for port in range(PRIVATE_VPN_PORT_START, PRIVATE_VPN_PORT_END + 1):
        if port not in used:
            return port
    raise RuntimeError('No free MyNetwork ports available')

def _sync_private_vpn_users(restart=False):
    cfg = _private_vpn_cfg()
    users = []
    if cfg.get('enabled'):
        for kid, entry in DATA.get('verify_keys', {}).items():
            if not _private_vpn_enabled_for(kid, entry):
                continue
            if not entry.get('private_vpn_port') or not entry.get('private_vpn_password'):
                continue
            users.append({
                'key': kid,
                'label': entry.get('label', ''),
                'port': int(entry['private_vpn_port']),
                'password': entry['private_vpn_password'],
                'method': entry.get('private_vpn_method') or cfg.get('method') or 'chacha20-ietf-poly1305',
                'enabled': True,
            })
    os.makedirs(os.path.dirname(PRIVATE_VPN_USERS), mode=0o700, exist_ok=True)
    os.makedirs(PRIVATE_VPN_CONFIG_DIR, mode=0o700, exist_ok=True)
    with open(PRIVATE_VPN_USERS, 'w') as f:
        json.dump({'users': users, 'updated_at': _now_iso()}, f, indent=2)
    try:
        os.chmod(PRIVATE_VPN_USERS, 0o600)
    except OSError:
        pass
    for item in users:
        _write_ssserver_config(
            os.path.join(PRIVATE_VPN_CONFIG_DIR, _ss_config_name(item['key'], item['port'])),
            item['port'], item['password'], item['method'], cfg_path=PRIVATE_VPN_CONFIG)
    if restart:
        try:
            subprocess.Popen(['docker', 'restart', PRIVATE_VPN_PROXY_CONTAINER],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

def _ensure_private_vpn_user(kid, entry, restart=False):
    if not _private_vpn_enabled_for(kid, entry):
        return False
    cfg = _private_vpn_cfg()
    changed = False
    if not entry.get('private_vpn_port'):
        entry['private_vpn_port'] = _allocate_private_vpn_port()
        changed = True
    if not entry.get('private_vpn_password'):
        entry['private_vpn_password'] = _ss_password()
        changed = True
    method = cfg.get('method') or 'chacha20-ietf-poly1305'
    if entry.get('private_vpn_method') != method:
        entry['private_vpn_method'] = method
        changed = True
    if changed:
        _save(DATA)
    _sync_private_vpn_users(restart=bool(restart and changed))
    return changed

def _ensure_ss_user(kid, entry, restart=False):
    if entry.get('mode') not in ('ios_shadowrocket', 'android_clash', 'desktop_clash'):
        return False
    changed = False
    if not entry.get('ss_port'):
        entry['ss_port'] = _allocate_ss_port()
        changed = True
    if not entry.get('ss_password'):
        entry['ss_password'] = _ss_password()
        changed = True
    preferred_method = _preferred_ss_method(entry)
    if entry.get('ss_method') != preferred_method:
        entry['ss_method'] = preferred_method
        changed = True
    if changed:
        _save(DATA)
    _sync_ss_users(restart=bool(changed and restart))
    if changed:
        _ensure_ss_process(kid, entry)
    elif restart:
        _ensure_ss_process(kid, entry)
    return changed

def _shadowsocks_net_stats():
    """Return approximate container network stats for iOS Shadowsocks mode."""
    now = time.time()
    try:
        r = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Pid}}', MOBILE_PROXY_CONTAINER],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=2,
        )
        pid = (r.stdout or '').strip()
        if not pid or pid == '0':
            raise RuntimeError('container pid unavailable')
        rx = tx = 0
        with open(f'/proc/{pid}/net/dev') as f:
            for line in f:
                if ':' not in line:
                    continue
                iface, rest = line.split(':', 1)
                iface = iface.strip()
                if iface == 'lo':
                    continue
                cols = rest.split()
                if len(cols) >= 16:
                    rx += int(cols[0])
                    tx += int(cols[8])
    except Exception:
        return {'rx_bps': 0, 'tx_bps': 0, 'sess_rx': 0, 'sess_tx': 0, 'delta_rx': 0, 'delta_tx': 0}

    if _IOS_NET['base_rx'] is None:
        _IOS_NET['base_rx'] = rx
        _IOS_NET['base_tx'] = tx
    delta_rx = 0
    delta_tx = 0
    if _IOS_NET['rx'] is not None and _IOS_NET['t'] is not None and now > _IOS_NET['t']:
        dt = max(now - _IOS_NET['t'], 0.001)
        delta_rx = max(0, rx - _IOS_NET['rx'])
        delta_tx = max(0, tx - _IOS_NET['tx'])
        _IOS_NET['rx_bps'] = max(0, int(delta_rx / dt))
        _IOS_NET['tx_bps'] = max(0, int(delta_tx / dt))
    _IOS_NET['rx'] = rx
    _IOS_NET['tx'] = tx
    _IOS_NET['t'] = now
    return {
        'rx_bps': _IOS_NET['rx_bps'],
        'tx_bps': _IOS_NET['tx_bps'],
        'sess_rx': max(0, rx - _IOS_NET['base_rx']),
        'sess_tx': max(0, tx - _IOS_NET['base_tx']),
        'delta_rx': delta_rx,
        'delta_tx': delta_tx,
    }

def _shadowrocket_url(host=None, kid=None):
    if not os.path.exists(SS_CONFIG):
        raise RuntimeError('Shadowsocks iOS plugin is not configured')
    with open(SS_CONFIG) as f:
        cfg = json.load(f)
    entry = DATA.get('verify_keys', {}).get(kid) if kid else None
    if kid and entry and _private_vpn_enabled_for(kid, entry):
        return _shadowrocket_import_link(kid)
    if entry:
        _ensure_ss_user(kid, entry, restart=True)
    server_host = host or cfg.get('server_host') or SERVER_HOST
    method = (entry or {}).get('ss_method') or cfg['method']
    password = (entry or {}).get('ss_password') or cfg['password']
    port = int((entry or {}).get('ss_port') or cfg['server_port'])
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip('=')
    name = quote((entry or {}).get('label') or cfg.get('profile_name', 'MyNetwork iOS'), safe='')
    return f"ss://{userinfo}@{server_host}:{port}#{name}"

def _shadowrocket_profile_url(kid):
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    token = entry.get('profile_token')
    if not token:
        token = secrets.token_urlsafe(24)
        entry['profile_token'] = token
    sub_url = request.url_root.rstrip('/') + '/api/profile/shadowrocket/' + quote(token)
    return 'shadowrocket://add/' + quote(sub_url, safe='')

def _shadowrocket_import_link(kid):
    # Deep link that imports the full Shadowrocket .conf (proxy-all-except-LAN +
    # UDP relay, rules baked in) instead of a bare node. A bare node leaves
    # routing to Shadowrocket's default ruleset, which sends China/Tencent
    # traffic DIRECT — broken on a network that blocks direct egress (QQ dies,
    # WeChat images crawl). Importing the config makes routing correct out of
    # the box, so users no longer need to flip global routing to Proxy.
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    token = entry.get('profile_token')
    if not token:
        token = secrets.token_urlsafe(24)
        entry['profile_token'] = token
        if entry:
            _save(DATA)  # token is the only handle to the conf endpoint; persist it now
    conf_url = request.url_root.rstrip('/') + '/api/profile/shadowrocket-conf/' + quote(token)
    return 'shadowrocket://config/add/' + quote(conf_url, safe='')

def _shadowrocket_subscription(kid, host=None):
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    if not _private_vpn_enabled_for(kid, entry):
        node = _shadowrocket_url(host, kid) + '\n'
        return base64.b64encode(node.encode()).decode() + '\n'
    private_cfg = _private_vpn_cfg()
    _ensure_private_vpn_user(kid, entry, restart=True)
    server_host = host or private_cfg.get('server_host') or SERVER_HOST
    port = int(entry.get('private_vpn_port') or private_cfg.get('server_port') or PRIVATE_VPN_PORT_START)
    password = entry.get('private_vpn_password') or private_cfg.get('password') or ''
    pwd_q = quote(password, safe='')
    nodes = []
    for route_id, route_name in PRIVATE_VPN_ROUTES:
        user = quote(f'{kid}__{route_id}', safe='')
        nodes.append(f"socks5://{user}:{pwd_q}@{server_host}:{port}#{quote(route_name, safe='')}")

    if not os.path.exists(SS_CONFIG):
        raise RuntimeError('Shadowsocks iOS plugin is not configured')
    with open(SS_CONFIG) as f:
        cfg = json.load(f)
    _ensure_ss_user(kid, entry, restart=True)
    direct_host = host or cfg.get('server_host') or SERVER_HOST
    direct_port = int(entry.get('ss_port') or cfg['server_port'])
    direct_method = entry.get('ss_method') or cfg['method']
    direct_password = entry.get('ss_password') or cfg['password']
    direct_userinfo = base64.urlsafe_b64encode(
        f"{direct_method}:{direct_password}".encode()).decode().rstrip('=')
    nodes.append(f"ss://{direct_userinfo}@{direct_host}:{direct_port}#MyNetwork%20Direct")
    return base64.b64encode(('\n'.join(nodes) + '\n').encode()).decode() + '\n'

# LAN / private networks stay off the tunnel (SSH + campus intranet keep working).
_SR_LAN_DIRECT = '''IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
IP-CIDR,169.254.0.0/16,DIRECT,no-resolve'''

def _shadowrocket_conf(kid, host=None):
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    if not _private_vpn_enabled_for(kid, entry):
        # Full .conf for the standard Shadowsocks outlet. A bare ss:// node would
        # fall back to Shadowrocket's default ruleset, which routes China/Tencent
        # traffic DIRECT — broken on a network that blocks direct egress (QQ dies,
        # WeChat images crawl, while proxied apps like Douyin are fine). So we
        # proxy everything except LAN and relay UDP (QQ and others need it).
        if not os.path.exists(SS_CONFIG):
            raise RuntimeError('Shadowsocks iOS plugin is not configured')
        with open(SS_CONFIG) as f:
            cfg = json.load(f)
        if entry:
            _ensure_ss_user(kid, entry, restart=True)
        server_host = host or cfg.get('server_host') or SERVER_HOST
        method = entry.get('ss_method') or cfg['method']
        password = entry.get('ss_password') or cfg['password']
        port = int(entry.get('ss_port') or cfg['server_port'])
        return f'''# MyNetwork - Shadowrocket
# Generated by MyNetwork. Re-import this URL after admin changes permissions.

[General]
bypass-system = true
# No local dns-server: the campus blocks direct egress (incl. DNS to public
# resolvers), so domains must be resolved remotely by the proxy. Pinning an
# external resolver here makes Shadowrocket query it directly and fail, breaking
# every domain-based app (web/Douyin/Bilibili) while IP-based ones (QQ) survive.

[Proxy]
MyNetwork = ss, {server_host}, {port}, encrypt-method={method}, password={password}, udp-relay=true

[Rule]
{_SR_LAN_DIRECT}
FINAL,MyNetwork
'''
    private_cfg = _private_vpn_cfg()
    _ensure_private_vpn_user(kid, entry, restart=True)
    if not os.path.exists(SS_CONFIG):
        raise RuntimeError('Shadowsocks iOS plugin is not configured')
    with open(SS_CONFIG) as f:
        cfg = json.load(f)
    _ensure_ss_user(kid, entry, restart=True)
    server_host = host or private_cfg.get('server_host') or SERVER_HOST
    port = int(entry.get('private_vpn_port') or private_cfg.get('server_port') or PRIVATE_VPN_PORT_START)
    password = entry.get('private_vpn_password') or private_cfg.get('password') or ''
    private_nodes = '\n'.join(
        f'{route_name} = socks5, {server_host}, {port}, {kid}__{route_id}, {password}, udp-relay=true'
        for route_id, route_name in PRIVATE_VPN_ROUTES
    )
    direct_name = 'MyNetwork Direct'
    direct_host = host or cfg.get('server_host') or SERVER_HOST
    direct_port = int(entry.get('ss_port') or cfg['server_port'])
    direct_method = entry.get('ss_method') or cfg['method']
    direct_password = entry.get('ss_password') or cfg['password']
    group_nodes = ', '.join(route_name for _route_id, route_name in PRIVATE_VPN_ROUTES)
    return f'''# MyNetwork - Shadowrocket
# Generated by MyNetwork. Re-import this URL after admin changes permissions.

[General]
bypass-system = true
# No local dns-server: the campus blocks direct egress (incl. DNS to public
# resolvers), so domains must be resolved remotely by the proxy. Pinning an
# external resolver here makes Shadowrocket query it directly and fail, breaking
# every domain-based app (web/Douyin/Bilibili) while IP-based ones (QQ) survive.

[Proxy]
{private_nodes}
{direct_name} = ss, {direct_host}, {direct_port}, encrypt-method={direct_method}, password={direct_password}, udp-relay=true

[Proxy Group]
MyNetwork = select, {group_nodes}, {direct_name}

[Rule]
{_SR_LAN_DIRECT}
DOMAIN,gpu1.bucea.edu.cn,{direct_name}
DOMAIN-SUFFIX,qq.com,{direct_name}
DOMAIN-SUFFIX,weixin.qq.com,{direct_name}
DOMAIN-SUFFIX,wechat.com,{direct_name}
DOMAIN-SUFFIX,gtimg.com,{direct_name}
DOMAIN-SUFFIX,qpic.cn,{direct_name}
DOMAIN-SUFFIX,idqqimg.com,{direct_name}
DOMAIN-SUFFIX,myqcloud.com,{direct_name}
DOMAIN-SUFFIX,tencent.com,{direct_name}
DOMAIN-SUFFIX,tencent-cloud.net,{direct_name}
DOMAIN-SUFFIX,qqmusic.qq.com,{direct_name}
DOMAIN-SUFFIX,music.qq.com,{direct_name}
GEOIP,CN,{direct_name}
FINAL,MyNetwork
'''

def _clash_profile_urls(kid):
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    token = entry.get('profile_token')
    if not token:
        token = secrets.token_urlsafe(24)
        entry['profile_token'] = token
    config_url = request.url_root.rstrip('/') + '/api/profile/clash/' + quote(token)
    device = _norm_device(entry.get('device'))
    profile_name = 'MyNetwork Android' if device == 'android' else 'MyNetwork Clash'
    import_url = 'clash://install-config?url=' + quote(config_url, safe='') + '&name=' + quote(profile_name, safe='')
    return config_url, import_url

def _clash_yaml(kid, host=None):
    if not os.path.exists(SS_CONFIG):
        raise RuntimeError('Shadowsocks plugin is not configured')
    with open(SS_CONFIG) as f:
        cfg = json.load(f)
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    device = _norm_device(entry.get('device'))
    mode = entry.get('mode', 'ssh_runner')
    private_vpn = _private_vpn_enabled_for(kid, entry)
    if private_vpn:
        private_cfg = _private_vpn_cfg()
        _ensure_private_vpn_user(kid, entry, restart=True)
        _ensure_ss_user(kid, entry, restart=True)
        proxy_host = host or private_cfg.get('server_host') or SERVER_HOST
        proxy_port = int(entry.get('private_vpn_port') or private_cfg.get('server_port') or PRIVATE_VPN_PORT_START)
        proxy_password = entry.get('private_vpn_password') or private_cfg.get('password') or cfg['password']
        direct_name = 'MyNetwork Direct'
        direct_host = host or cfg.get('server_host') or SERVER_HOST
        direct_port = int(entry.get('ss_port') or cfg['server_port'])
        direct_method = entry.get('ss_method') or cfg['method']
        direct_password = entry.get('ss_password') or cfg['password']
        private_proxy_blocks = []
        for route_id, route_name in PRIVATE_VPN_ROUTES:
            private_proxy_blocks.append(f'''  - name: {route_name}
    type: socks5
    server: {proxy_host}
    port: {proxy_port}
    username: "{kid}__{route_id}"
    password: "{proxy_password}"
    udp: true''')
        proxy_block = '\n'.join(private_proxy_blocks) + f'''
  - name: {direct_name}
    type: ss
    server: {direct_host}
    port: {direct_port}
    cipher: {direct_method}
    password: "{direct_password}"
    udp: true'''
        group_proxy_names = '\n'.join(f'      - {route_name}' for _route_id, route_name in PRIVATE_VPN_ROUTES)
        group_proxy_names += f'\n      - {direct_name}'
    else:
        _ensure_ss_user(kid, entry, restart=True)
        name = 'MyNetwork Android' if device == 'android' else 'MyNetwork Clash'
        proxy_host = host or cfg.get('server_host') or SERVER_HOST
        proxy_port = int(entry.get('ss_port') or cfg['server_port'])
        proxy_method = entry.get('ss_method') or cfg['method']
        proxy_password = entry.get('ss_password') or cfg['password']
        proxy_block = f'''  - name: {name}
    type: ss
    server: {proxy_host}
    port: {proxy_port}
    cipher: {proxy_method}
    password: "{proxy_password}"
    udp: true'''
        group_proxy_names = f'''      - {name}'''
    comment = 'MyNetwork outlet for this key only.' if private_vpn else 'Standard MyNetwork outlet.'
    if private_vpn:
        rule_block = f'''  - DOMAIN,gpu1.bucea.edu.cn,{direct_name}
  - DOMAIN-SUFFIX,qq.com,{direct_name}
  - DOMAIN-SUFFIX,weixin.qq.com,{direct_name}
  - DOMAIN-SUFFIX,wechat.com,{direct_name}
  - DOMAIN-SUFFIX,gtimg.com,{direct_name}
  - DOMAIN-SUFFIX,qpic.cn,{direct_name}
  - DOMAIN-SUFFIX,idqqimg.com,{direct_name}
  - DOMAIN-SUFFIX,myqcloud.com,{direct_name}
  - DOMAIN-SUFFIX,tencent.com,{direct_name}
  - DOMAIN-SUFFIX,tencent-cloud.net,{direct_name}
  - DOMAIN-SUFFIX,qqmusic.qq.com,{direct_name}
  - DOMAIN-SUFFIX,music.qq.com,{direct_name}
  - GEOIP,CN,{direct_name}
  - MATCH,PROXY'''
    else:
        rule_block = '  - MATCH,PROXY'
    # Always keep LAN / private-network traffic (incl. the server's own IP, used
    # for SSH and the admin portal) OFF the tunnel. Without this, TUN/auto-route
    # swallows connections to 10.x/192.168.x/etc. and SSH to the server breaks.
    rule_block = '''  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
''' + rule_block
    tun_block = ''
    if mode == 'desktop_clash' or device in ('mac', 'windows'):
        tun_block = '''
tun:
  enable: true
  stack: mixed
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
'''
    return f'''# MyNetwork - Clash Meta / Mihomo
# Generated by MyNetwork. Revoking the user's key invalidates this subscription.
# {comment}

mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false

dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
{tun_block}

proxies:
{proxy_block}

proxy-groups:
  - name: PROXY
    type: select
    proxies:
{group_proxy_names}

rules:
{rule_block}
'''

# ── SSH keypair helpers ──────────────────────────────────────────────────────

def _ssh_home(user):
    try:
        return pwd.getpwnam(user).pw_dir
    except KeyError:
        return os.path.expanduser('~')

def _auth_keys_path():
    if AUTH_KEYS:
        return os.path.abspath(os.path.expanduser(AUTH_KEYS))
    return os.path.join(_ssh_home(SSH_USER), '.ssh', 'authorized_keys')

def _ensure_auth_keys():
    path = _auth_keys_path()
    ssh_dir = os.path.dirname(path)
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(ssh_dir, 0o700)
    except OSError:
        pass
    if not os.path.exists(path):
        open(path, 'a').close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path

def _pubkey_for(kid):
    pub = os.path.join(KEYS_DIR, f'{kid}.pub')
    if os.path.exists(pub):
        with open(pub) as f:
            return f.read().strip()

    priv = os.path.join(KEYS_DIR, f'{kid}.priv')
    if not os.path.exists(priv):
        return None

    # Recover the public key if keys.json/private keys survived but .pub or
    # authorized_keys was lost during a redeploy or server cleanup.
    r = subprocess.run(['ssh-keygen', '-y', '-f', priv],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, check=True)
    pubkey = (r.stdout or '').strip()
    if pubkey:
        with open(pub, 'w') as f:
            f.write(pubkey + f' labvpn-{kid}\n')
    return pubkey or None

def _auth_line(kid, pubkey):
    return f'restrict,port-forwarding {pubkey} labvpn-{kid}\n'

def _keygen(kid):
    priv = os.path.join(KEYS_DIR, f'{kid}.priv')
    pub  = os.path.join(KEYS_DIR, f'{kid}.pub')
    subprocess.run(
        ['ssh-keygen', '-t', 'ed25519', '-f', priv, '-N', '', '-C', f'labvpn-{kid}'],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    os.rename(priv + '.pub', pub)
    os.chmod(priv, 0o600)
    os.chmod(pub, 0o644)

def _auth_add(kid):
    pubkey = _pubkey_for(kid)
    if not pubkey:
        raise RuntimeError(f'SSH public key missing for {kid}')
    path = _ensure_auth_keys()
    marker = f'labvpn-{kid}'
    existing = open(path).read() if os.path.exists(path) else ''
    if marker not in existing:
        with open(path, 'a') as f:
            f.write(_auth_line(kid, pubkey))

def _auth_remove(kid):
    marker = f'labvpn-{kid}'
    path = _auth_keys_path()
    if not os.path.exists(path):
        return
    with open(path) as f:
        lines = f.readlines()
    with open(path, 'w') as f:
        for ln in lines:
            if marker not in ln:
                f.write(ln)

def _auth_sync():
    """Make SSH authorization match keys.json on every start.

    A verify-key is only useful if the runner's embedded SSH key is present in
    the SSH user's authorized_keys. This reconciles stale/missing entries after
    restarts, redeploys, user changes, or manual authorized_keys edits.
    """
    path = _ensure_auth_keys()
    with open(path) as f:
        lines = [ln for ln in f.readlines() if ' labvpn-' not in ln]

    missing = []
    for kid in sorted(DATA.get('verify_keys', {})):
        pubkey = _pubkey_for(kid)
        if pubkey:
            lines.append(_auth_line(kid, pubkey))
        else:
            missing.append(kid)

    with open(path, 'w') as f:
        f.writelines(lines)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    print(f'[auth] synced {len(DATA.get("verify_keys", {})) - len(missing)} key(s) '
          f'to {path} for SSH user {SSH_USER}')
    if missing:
        print('[auth] WARNING: missing private/public key files for: ' + ', '.join(missing))

def _kick_ssh_sessions():
    """Terminate current SSH sessions for SSH_USER after a revoke.

    Removing an authorized_keys line only blocks future logins; existing SSH
    tunnels keep running. This broad kill is disabled by default because sshd
    does not expose the accepted key to this Flask process, so killing by user
    can disconnect still-valid runners too.
    """
    if not KICK_SSH_ON_REVOKE:
        return 0
    try:
        r = subprocess.run(['pgrep', '-u', SSH_USER, '-f', f'^sshd: {SSH_USER}'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=3)
    except Exception:
        return 0
    pids = [p for p in (r.stdout or '').split() if p.isdigit()]
    for pid in pids:
        try:
            os.kill(int(pid), 15)
        except OSError:
            pass
    return len(pids)

# ── Throughput monitor & traffic accounting ──────────────────────────────────
#
# Single source of truth: TCP socket byte counters. Every proxy port (each
# user's Shadowsocks port, each user's MyNetwork port, the shared port, and
# the legacy SSH port) terminates on this machine, so `ss -i` exposes the real
# per-socket cumulative byte counters. We sample twice a second, diff each
# socket against its previous reading, attribute the delta to a key by the
# *listening port* it terminates on, and both (a) update live speed/session
# stats and (b) accrue it for periodic persistence to SQLite.
#
# Why counters and not the ssserver connection log: the log only emits totals
# when a connection *closes*, so it loses every connection that closes on error
# (RST) and lags badly on long-lived connections, while a close burst divided by
# the sampling interval produces absurd instantaneous speeds. Counters are
# continuous, survive errors, and measure the bytes the access link actually
# carried. From the server's point of view: bytes it *sends* to the client =
# the user's download; bytes it *receives* = the user's upload.

_mon_lock  = threading.Lock()
_ip_stats  = {}   # ip -> live stats dict
_ip_logs   = {}   # ip -> deque[{t, event}]
_key_stats = {}   # key id -> live proxy stats dict
_sock_prev = {}   # socket key -> (sent, recv) from the previous sample
_log_offsets = {} # log path -> byte offset already consumed
_key_tick  = {}   # key id -> [down, up] bytes seen in the current sample window

# bytes_acked counts only data the peer has acknowledged, so unlike bytes_sent
# it excludes TCP retransmissions — the more honest figure for billing. We fall
# back to bytes_sent only on kernels that don't report bytes_acked. These are
# used for the SSH transport, whose sockets live in the host network namespace
# and so are visible to `ss -i`.
_RE_SENT  = re.compile(r'bytes_sent:(\d+)')
_RE_ACKED = re.compile(r'bytes_acked:(\d+)')
_RE_RECV  = re.compile(r'bytes_received:(\d+)')
# Per-connection close lines emitted by ssserver (Shadowsocks) and by our
# private SOCKS proxy. L2R = local→remote = the user's upload; R2L = the
# download. Both proxies run inside containers, so their own logs — not host
# socket counters — are the authoritative byte source for these transports.
_RE_TCP_CLOSED = re.compile(
    r'tcp tunnel (?P<client>\[[^\]]+\]|[^:\s]+):\d+\s+<->\s+.+?\s+closed,\s+L2R\s+(?P<up>\d+)\s+bytes,\s+R2L\s+(?P<down>\d+)\s+bytes'
)
_RE_UDP_RELAY = re.compile(
    r'udp relay (?P<client>\[[^\]]+\]|[^:\s]+):\d+\s+(?P<dir>->|<-)\s+.+?\s+with\s+(?P<bytes>\d+)\s+bytes'
)
# Used only by the destination-audit feature (which reads `docker logs`), not by
# traffic accounting.
_RE_MOBILE_TARGET = re.compile(
    r'(?P<t>\d{4}-\d\d-\d\dT[^\s]+Z).*?\btunnel\s+'
    r'(?P<client>\[[^\]]+\]|[^:\s]+):\d+\s+->\s+'
    r'(?P<target>\[[^\]]+\]|[^:\s]+):(?P<port>\d+)\s*(?P<msg>.*)$'
)
_SUSPICIOUS_HINTS = (
    'porn', 'adult', 'casino', 'gamble', 'bet365', 'torrent', 'tracker',
    'bitcomet', 'utorrent', 'xunlei', 'sex', 'onlyfans',
)

# `ss` lives in /usr/sbin, which is often missing from a daemon's PATH.
_SS = (shutil.which('ss') or next(
    (p for p in ('/usr/sbin/ss', '/sbin/ss', '/bin/ss') if os.path.exists(p)), None))

def _new_stat():
    return {'connected': False, 'down_bps': 0, 'up_bps': 0,
            'sess_down': 0, 'sess_up': 0, 'since': None}

def _keys_for_ip(ip, mode=None):
    out = []
    for kid, entry in DATA.get('verify_keys', {}).items():
        known_ips = set(entry.get('ip_history') or [])
        if entry.get('activated_ip'):
            known_ips.add(entry.get('activated_ip'))
        if entry.get('last_ip'):
            known_ips.add(entry.get('last_ip'))
        if ip not in known_ips:
            continue
        if mode and entry.get('mode', 'ssh_runner') != mode:
            continue
        out.append(kid)
    return out

def _key_for_client_ip(ip):
    matches = _keys_for_ip(ip)
    if not matches:
        return None, None
    kid = matches[0]
    return kid, DATA.get('verify_keys', {}).get(kid, {})

def _best_key_for_ip(ip, modes):
    candidates = []
    for kid, entry in DATA.get('verify_keys', {}).items():
        if entry.get('mode', 'ssh_runner') not in modes:
            continue
        known_ips = set(entry.get('ip_history') or [])
        if entry.get('activated_ip'):
            known_ips.add(entry.get('activated_ip'))
        if entry.get('last_ip'):
            known_ips.add(entry.get('last_ip'))
        if ip not in known_ips:
            continue
        recency = (entry.get('last_seen_at') or entry.get('last_profile_at')
                   or entry.get('last_download') or entry.get('activated_at')
                   or entry.get('created_at') or '')
        candidates.append((recency, kid, entry))
    if not candidates:
        return None, None
    candidates.sort(reverse=True)
    return candidates[0][1], candidates[0][2]

def _key_for_ss_port(port):
    """Map a monitored listening port back to the key that owns it. Each key has
    a dedicated Shadowsocks port and (optionally) a dedicated MyNetwork port;
    both belong to the same user, so traffic on either counts to that key."""
    try:
        port = int(port)
    except Exception:
        return None, None
    for kid, entry in DATA.get('verify_keys', {}).items():
        if int(entry.get('ss_port') or -1) == port or int(entry.get('private_vpn_port') or -1) == port:
            return kid, entry
    return None, None

def _traffic_admin_summary():
    today = _traffic_now().date()
    days = [(today.fromordinal(today.toordinal() - i)).isoformat() for i in range(6, -1, -1)]
    per_key = {}
    per_day = {day: {'day': day, 'down': 0, 'up': 0} for day in days}
    with _traffic_db() as db:
        for kid, day, down, up in db.execute(
                'SELECT key_id, day, down_bytes, up_bytes FROM traffic_daily WHERE day >= ?',
                (days[0],)):
            down = int(down or 0)
            up = int(up or 0)
            if day in per_day:
                per_day[day]['down'] += down
                per_day[day]['up'] += up
            row = per_key.setdefault(kid, {'key': kid, 'down': 0, 'up': 0})
            row['down'] += down
            row['up'] += up

    users = []
    for kid, totals in per_key.items():
        entry = DATA.get('verify_keys', {}).get(kid, {})
        is_shared = kid == SHARED_TRAFFIC_KEY
        total = totals['down'] + totals['up']
        users.append({
            'key': kid,
            'label': entry.get('label', '') or ('共享端口（未归属）' if is_shared else ''),
            'device': entry.get('device', ''),
            'mode': entry.get('mode', '') or ('shared' if is_shared else ''),
            'down': totals['down'],
            'up': totals['up'],
            'total': total,
            'last_ip': entry.get('last_ip') or entry.get('activated_ip'),
            'ip_count': len(entry.get('ip_history') or []),
        })
    users.sort(key=lambda x: x['total'], reverse=True)
    total_down = sum(row['down'] for row in per_day.values())
    total_up = sum(row['up'] for row in per_day.values())
    return {
        'days': [per_day[day] for day in days],
        'top_users': users,
        'hourly_7d': _admin_hourly_traffic(168),
        'total_down': total_down,
        'total_up': total_up,
        'total': total_down + total_up,
    }

def _traffic_by_key():
    rows = _traffic_admin_summary().get('top_users', [])
    return {row['key']: row for row in rows}

def _admin_profile_links(kid, entry):
    mode = entry.get('mode', 'ssh_runner')
    device = entry.get('device', '')
    out = {'config_url': '', 'import_url': '', 'shadowrocket_url': ''}
    try:
        if mode in ('android_clash', 'desktop_clash') or (mode == 'ssh_runner' and device in ('mac', 'windows')):
            out['config_url'], out['import_url'] = _clash_profile_urls(kid)
        elif mode == 'ios_shadowrocket':
            out['shadowrocket_url'] = _shadowrocket_import_link(kid)
    except Exception as e:
        out['error'] = str(e)
    return out

def _admin_users():
    traffic = _traffic_by_key()
    users = []
    changed = False
    for kid, entry in DATA.get('verify_keys', {}).items():
        mode = entry.get('mode', 'ssh_runner')
        device = entry.get('device', 'windows')
        if mode == 'ssh_runner' and device in ('mac', 'windows'):
            entry['mode'] = 'desktop_clash'
            mode = 'desktop_clash'
            changed = True
        if mode in ('ios_shadowrocket', 'android_clash', 'desktop_clash'):
            _ensure_ss_user(kid, entry)
        if _private_vpn_enabled_for(kid, entry):
            _ensure_private_vpn_user(kid, entry)
        had_profile_token = bool(entry.get('profile_token'))
        links = _admin_profile_links(kid, entry)
        if links.get('config_url') and not had_profile_token:
            changed = True
        totals = traffic.get(kid, {})
        users.append({
            'key': kid,
            'label': entry.get('label', ''),
            'device': device,
            'mode': mode,
            'activated': bool(entry.get('activated')),
            'created_at': entry.get('created_at'),
            'activated_at': entry.get('activated_at'),
            'last_seen_at': entry.get('last_seen_at') or entry.get('last_download') or entry.get('activated_at'),
            'last_download': entry.get('last_download'),
            'activated_ip': entry.get('activated_ip'),
            'last_ip': entry.get('last_ip') or entry.get('activated_ip'),
            'ip_count': len(entry.get('ip_history') or []),
            'download_count': entry.get('download_count', 0),
            'down': int(totals.get('down') or 0),
            'up': int(totals.get('up') or 0),
            'total': int(totals.get('total') or 0),
            'config_url': links.get('config_url', ''),
            'import_url': links.get('import_url', ''),
            'shadowrocket_url': links.get('shadowrocket_url', ''),
            'profile_error': links.get('error', ''),
            'ss_port': entry.get('ss_port'),
            'private_vpn': bool(_private_vpn_enabled_for(kid, entry)),
            'private_vpn_manual': bool(entry.get('private_vpn')),
            'private_vpn_locked_off': bool(entry.get('private_vpn_disabled')),
            'private_vpn_port': entry.get('private_vpn_port'),
        })
    if changed:
        _save(DATA)
    users.sort(key=lambda row: (row.get('last_seen_at') or row.get('created_at') or ''), reverse=True)
    return users

def _mobile_destination_audit():
    try:
        r = subprocess.run(
            ['docker', 'logs', '--tail=800', MOBILE_PROXY_CONTAINER],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True, timeout=4,
        )
        lines = (r.stdout or '').splitlines()
    except Exception as e:
        return {'events': [], 'top_targets': [], 'flagged': [],
                'error': str(e), 'source': MOBILE_PROXY_CONTAINER}

    targets = {}
    events = []
    flagged = []
    for ln in lines:
        m = _RE_MOBILE_TARGET.search(ln)
        if not m:
            continue
        client = m.group('client').strip('[]')
        target = m.group('target').strip('[]')
        port = int(m.group('port'))
        kid, entry = _key_for_client_ip(client)
        event = {
            'time': m.group('t'),
            'client_ip': client,
            'target': target,
            'port': port,
            'message': (m.group('msg') or '').strip()[:160],
            'key': kid or '',
            'label': (entry or {}).get('label', ''),
            'device': (entry or {}).get('device', ''),
        }
        events.append(event)
        item = targets.setdefault(target, {'target': target, 'count': 0, 'ports': {}, 'labels': {}})
        item['count'] += 1
        item['ports'][str(port)] = item['ports'].get(str(port), 0) + 1
        if event['label']:
            item['labels'][event['label']] = item['labels'].get(event['label'], 0) + 1
        low = target.lower()
        if any(h in low for h in _SUSPICIOUS_HINTS):
            flagged.append(event)

    top = sorted(targets.values(), key=lambda x: x['count'], reverse=True)[:20]
    for item in top:
        item['ports'] = sorted(item['ports'].items(), key=lambda kv: kv[1], reverse=True)[:4]
        item['labels'] = sorted(item['labels'].items(), key=lambda kv: kv[1], reverse=True)[:4]
    return {
        'events': events[-60:][::-1],
        'top_targets': top,
        'flagged': flagged[-30:][::-1],
        'source': MOBILE_PROXY_CONTAINER,
    }

def _run_diag(cmd, timeout=3):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout)
        return (r.stdout or '').strip()
    except Exception as e:
        return str(e)

def _admin_diagnostics():
    docker_line = _run_diag(['docker', 'ps', '--filter', 'name=^/' + MOBILE_PROXY_CONTAINER + '$',
                             '--format', '{{.Names}}\t{{.Status}}\t{{.Ports}}'])
    listen = _run_diag([_SS, '-ltnH'] if _SS else ['netstat', '-ltn'])
    recent_profile = ''
    for entry in DATA.get('verify_keys', {}).values():
        ts = entry.get('last_profile_at')
        if ts and ts > recent_profile:
            recent_profile = ts
    pending = [r for r in DATA.get('requests', {}).values() if (r.get('status') or 'pending') == 'pending']
    recent_clients = []
    seen_ips = set()
    for ev in list(_HTTP_EVENTS):
        ip = ev.get('ip')
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            recent_clients.append(ev)
        if len(recent_clients) >= 5:
            break
    recent_errors = [ev for ev in list(_HTTP_EVENTS) if int(ev.get('status') or 0) >= 400][:8]
    return {
        'server_time': _now_iso(),
        'flask_online': True,
        'flask_listening_5000': ':5000' in listen,
        'shadowsocks_running': _shadowsocks_service_up(),
        'container': MOBILE_PROXY_CONTAINER,
        'container_status': docker_line,
        'ss_config_exists': os.path.exists(SS_CONFIG),
        'tcp_udp_8388_exposed': '8388/tcp' in docker_line and '8388/udp' in docker_line,
        'traffic_accounting': 'proxy_logs_by_user_port + ssh_socket_bytes_by_ip',
        'per_user_ss_ports': len([e for e in DATA.get('verify_keys', {}).values() if e.get('ss_port')]),
        'profile_last_request_at': recent_profile,
        'pending_requests': len(pending),
        'key_count': len(DATA.get('verify_keys', {})),
        'recent_clients': recent_clients,
        'recent_errors': recent_errors,
    }

def _admin_analytics():
    return {
        'traffic': _traffic_admin_summary(),
        'mobile_audit': _mobile_destination_audit(),
        'diagnostics': _admin_diagnostics(),
        'visibility': {
            'ssh_runner_destinations': False,
            'mobile_proxy_destinations': True,
        },
    }

def _log_event(ip, event):
    _ip_logs.setdefault(ip, deque(maxlen=50)).appendleft(
        {'t': datetime.utcnow().isoformat(), 'event': event})

def _key_for_log_file(name):
    """Map a proxy log filename to the key it bills. ssserver and the private
    proxy both name their per-port logs `user-<port>-<...>.log`; the shared
    Shadowsocks port logs to `shared-<port>...log`. Attribution is purely by
    listening port — the client/target inside each line is for audit only."""
    m = re.match(r'(user|shared)-(\d+)', name)
    if not m:
        return None
    if m.group(1) == 'shared':
        return SHARED_TRAFFIC_KEY
    kid, _entry = _key_for_ss_port(m.group(2))
    return kid

def _process_proxy_logs():
    """Tail every Shadowsocks and private-MyNetwork per-port log, summing the bytes of
    connections that closed since the last pass. This is the authoritative byte
    source for the containerized proxies (their sockets are invisible to the
    host's `ss`). Feeds DB accrual, live session totals, and the rate window."""
    agg = {}
    for log_dir in (SS_LOG_DIR, PRIVATE_VPN_LOG_DIR):
        if not os.path.isdir(log_dir):
            continue
        for name in os.listdir(log_dir):
            if not name.endswith('.log'):
                continue
            kid = _key_for_log_file(name)
            if not kid:
                continue
            path = os.path.join(log_dir, name)
            try:
                size = os.path.getsize(path)
                pos = _log_offsets.get(path, 0)
                if pos > size:                # rotated/truncated → re-read
                    pos = 0
                with open(path, 'r', errors='ignore') as f:
                    f.seek(pos)
                    for ln in f:
                        m = _RE_TCP_CLOSED.search(ln)
                        if m:
                            slot = agg.setdefault(kid, [0, 0])
                            slot[0] += int(m.group('down'))
                            slot[1] += int(m.group('up'))
                            continue
                        m = _RE_UDP_RELAY.search(ln)
                        if m:
                            n = int(m.group('bytes'))
                            slot = agg.setdefault(kid, [0, 0])
                            if m.group('dir') == '->':
                                slot[1] += n          # client→target = upload
                            else:
                                slot[0] += n          # download
                    _log_offsets[path] = f.tell()
            except Exception:
                continue
    if not agg:
        return
    now_iso = datetime.utcnow().isoformat()
    with _mon_lock:
        for kid, (down, up) in agg.items():
            if down <= 0 and up <= 0:
                continue
            _accrue_traffic(kid, down, up)
            tick = _key_tick.setdefault(kid, [0, 0])
            tick[0] += down
            tick[1] += up
            ks = _key_stats.setdefault(kid, _new_stat())
            if not ks.get('connected'):
                ks['connected'] = True
                ks['since'] = now_iso
            ks['sess_down'] += down
            ks['sess_up'] += up
            ks['last_at'] = now_iso
            ks['rate_at'] = now_iso

def _ss_sockets_for_ports(ports):
    """Established TCP sockets terminating on monitored ports.

    `ss -i` prints each socket as a header line (state / local / peer) followed
    by an indented info line carrying the byte counters. We pair the two lines
    manually. For the "sent" figure we prefer bytes_acked (excludes
    retransmissions) and fall back to bytes_sent on kernels that omit it."""
    if not _SS:
        return None
    ports = set(str(p) for p in ports if p)
    try:
        r = subprocess.run([_SS, '-tinH', 'state', 'established'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=3)   # 3.6-compatible
    except Exception:
        return None
    out, cur = [], None
    for ln in r.stdout.splitlines():
        if not ln:
            continue
        if ln[0].isspace():                       # info line for the pending socket
            if cur:
                ms = _RE_ACKED.search(ln) or _RE_SENT.search(ln)
                mr = _RE_RECV.search(ln)
                out.append((cur[0], cur[1], cur[2],
                            int(ms.group(1)) if ms else 0,
                            int(mr.group(1)) if mr else 0))
                cur = None
        else:                                      # socket header line
            # Local/Peer are the last two columns (the State column may be
            # absent when filtering by state), so index from the end.
            parts = ln.split()
            cur = None
            if len(parts) >= 4:
                local, peer = parts[-2], parts[-1]
                if ':' in local and ':' in peer:
                    port = local.rsplit(':', 1)[-1]
                    if port in ports:
                        cur = (port + '|' + local + '|' + peer, port,
                               peer.rsplit(':', 1)[0].strip('[]'))
    return out

SAMPLE_SEC = 0.5   # how often we read socket counters (finer = snappier graph)

FLUSH_EVERY = 10   # flush accrued bytes to SQLite every FLUSH_EVERY samples (~5s)

def _monitor_loop():
    global _sock_prev
    prev_t = time.time()
    flush_tick = 0
    while True:
        time.sleep(SAMPLE_SEC)
        # Shadowsocks + MyNetwork bytes come from the proxies' own logs (their
        # sockets live inside containers, invisible to the host's `ss`). This
        # accrues to the DB and fills _key_tick for the rate window below.
        _process_proxy_logs()
        # SSH bytes come from host-namespace socket counters, by client IP.
        socks = _ss_sockets_for_ports(_monitored_ports())
        now = time.time()
        dt  = now - prev_t
        prev_t = now
        if dt <= 0:
            dt = SAMPLE_SEC
        cur, delta, present = {}, {}, set()
        for key, port, ip, sent, recv in (socks or []):
            cur[key] = (sent, recv)
            present.add((port, ip))
            prev = _sock_prev.get(key)
            if prev:
                # Counters are monotonic per socket, so a decrease means the
                # 4-tuple was reused by a brand-new connection (or the daemon
                # restarted) — count the new socket's bytes from zero rather
                # than dropping them.
                ds = sent - prev[0]
                if ds < 0:
                    ds = sent
                dr = recv - prev[1]
                if dr < 0:
                    dr = recv
            else:
                # First time we see this socket: its counter already holds the
                # bytes transferred before we started watching, so seed without
                # counting them.
                ds = dr = 0
            d = delta.setdefault((port, ip), [0, 0])
            d[0] += ds; d[1] += dr
        if socks is not None:
            _sock_prev = cur

        now_iso = datetime.utcnow().isoformat()
        with _mon_lock:
            # Live speed for log-based keys (SS / MyNetwork): the bytes that
            # landed in the logs during this sample window, divided by the real
            # elapsed time. Bounded by wall-clock dt, so no close-burst spikes.
            for kid in set(_key_stats) | set(_key_tick):
                ks = _key_stats.setdefault(kid, _new_stat())
                tick = _key_tick.get(kid)
                if tick and (tick[0] or tick[1]):
                    ks['down_bps'] = tick[0] / dt
                    ks['up_bps'] = tick[1] / dt
                else:
                    ks['down_bps'] = ks['up_bps'] = 0
            _key_tick.clear()

            present_ips = set(ip for _port, ip in present)
            for ip in set(_ip_stats) | present_ips:
                st = _ip_stats.setdefault(ip, _new_stat())
                was, now_c = st['connected'], ip in present_ips
                d = [0, 0]
                for (_port, peer_ip), vals in delta.items():
                    if peer_ip == ip:
                        d[0] += vals[0]
                        d[1] += vals[1]
                if now_c:
                    if not was:                       # new session
                        st['sess_down'] = st['sess_up'] = 0
                        st['since'] = now_iso
                        _log_event(ip, 'up')
                    # accurate per-second rate; session totals get the raw bytes
                    st['down_bps'] = d[0] / dt
                    st['up_bps']   = d[1] / dt
                    st['sess_down'] += d[0]
                    st['sess_up']   += d[1]
                    if delta.get((SSH_PORT, ip)):
                        kid, _entry = _best_key_for_ip(ip, ('ssh_runner',))
                        if kid:
                            _accrue_traffic(kid, delta[(SSH_PORT, ip)][0], delta[(SSH_PORT, ip)][1])
                else:
                    if was:
                        _log_event(ip, 'down')
                    st['down_bps'] = st['up_bps'] = 0
                st['connected'] = now_c

        flush_tick += 1
        if flush_tick >= FLUSH_EVERY:
            flush_tick = 0
            try:
                _flush_pending_traffic()
            except Exception:
                pass

def _init_log_offsets():
    """Start tailing each proxy log from its current end. Without this, a server
    restart would re-read the whole file from offset 0 and double-count every
    connection already persisted to the DB."""
    for log_dir in (SS_LOG_DIR, PRIVATE_VPN_LOG_DIR):
        if not os.path.isdir(log_dir):
            continue
        for name in os.listdir(log_dir):
            if not name.endswith('.log'):
                continue
            path = os.path.join(log_dir, name)
            try:
                _log_offsets[path] = os.path.getsize(path)
            except OSError:
                pass

_init_log_offsets()
threading.Thread(target=_monitor_loop, daemon=True).start()

# ── Admin endpoints ──────────────────────────────────────────────────────────

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    if not _ok_root((request.json or {}).get('root_key', '')):
        return jsonify({'ok': False, 'error': 'Invalid root key'}), 401
    return jsonify({'ok': True})

@app.route('/api/admin/keys', methods=['GET'])
def admin_list():
    if not _ok_root(request.headers.get('X-Root-Key', '')):
        return jsonify({'ok': False}), 401
    _repair_approved_ios_keys()
    return jsonify({'ok': True, 'keys': DATA['verify_keys'],
                    'users': _admin_users(),
                    'requests': DATA.get('requests', {}),
                    'analytics': _admin_analytics()})

@app.route('/api/admin/keys', methods=['POST'])
def admin_create():
    body = request.json or {}
    if not _ok_root(body.get('root_key', '')):
        return jsonify({'ok': False, 'error': 'Invalid root key'}), 401
    label = body.get('label', '').strip()
    device = _norm_device(body.get('device', 'windows'))
    try:
        kid = _create_verify_key(label, device=device)
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Approval failed: ' + str(e)}), 500
    _save(DATA)
    return jsonify({'ok': True, 'key': kid})

@app.route('/api/admin/requests/<rid>/approve', methods=['POST'])
def admin_approve_request(rid):
    if not _ok_root(request.headers.get('X-Root-Key', '')):
        return jsonify({'ok': False}), 401
    reqs = DATA.setdefault('requests', {})
    req = reqs.get(rid)
    if not req:
        return jsonify({'ok': False, 'error': 'Request not found'}), 404
    if req.get('status') == 'approved' and req.get('key'):
        out = {'ok': True, 'key': req['key']}
        if req.get('link'):
            out['link'] = req['link']
        if req.get('config_url'):
            out['config_url'] = req['config_url']
        return jsonify(out)
    try:
        body = request.json or {}
        if body.get('device'):
            req['device'] = _norm_device(body.get('device'))
            req['kind'] = _device_kind(req['device'])
        device = _norm_device(req.get('device'))
        label = req.get('name') or device or rid
        if req.get('kind') in ('ios_shadowrocket', 'android_clash', 'desktop_clash'):
            mode = req.get('kind')
            if mode == 'android_clash':
                kid = req.get('key') or _create_verify_key(label + ' Android', device='android', mode='android_clash')
            elif mode == 'desktop_clash':
                kid = req.get('key') or _create_verify_key(label, device=device, mode='desktop_clash')
            else:
                kid = req.get('key') or _create_verify_key(label + ' iOS', device='iphone', mode='ios_shadowrocket')
            req['status'] = 'approved'
            req['key'] = kid
            _ensure_ss_user(kid, DATA['verify_keys'][kid], restart=True)
            if mode == 'ios_shadowrocket':
                req['link'] = req.get('link') or _shadowrocket_import_link(kid)
            else:
                req['config_url'], req['link'] = _clash_profile_urls(kid)
            req['approved_at'] = datetime.utcnow().isoformat()
            _mark_ios_key_active(kid, req)
            _save(DATA)
            out = {'ok': True, 'key': kid, 'link': req.get('link')}
            if req.get('config_url'):
                out['config_url'] = req['config_url']
            return jsonify(out)
        kid = _create_verify_key(label, device=device, mode='ssh_runner')
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Key generation failed: ' + str(e)}), 500
    req['status'] = 'approved'
    req['key'] = kid
    req['approved_at'] = datetime.utcnow().isoformat()
    _save(DATA)
    return jsonify({'ok': True, 'key': kid})

@app.route('/api/admin/requests/<rid>', methods=['PATCH'])
def admin_update_request(rid):
    if not _ok_root(request.headers.get('X-Root-Key', '')):
        return jsonify({'ok': False}), 401
    req = DATA.setdefault('requests', {}).get(rid)
    if not req:
        return jsonify({'ok': False, 'error': 'Request not found'}), 404
    if (req.get('status') or 'pending') != 'pending':
        return jsonify({'ok': False, 'error': 'Only pending requests can be edited'}), 400
    body = request.json or {}
    if body.get('device'):
        req['device'] = _norm_device(body.get('device'))
        req['kind'] = _device_kind(req['device'])
    if body.get('name'):
        req['name'] = body.get('name', '').strip()[:80]
    _save(DATA)
    return jsonify({'ok': True, 'request': req})

@app.route('/api/admin/requests/<rid>', methods=['DELETE'])
def admin_reject_request(rid):
    if not _ok_root(request.headers.get('X-Root-Key', '')):
        return jsonify({'ok': False}), 401
    reqs = DATA.setdefault('requests', {})
    if rid in reqs:
        reqs[rid]['status'] = 'rejected'
        reqs[rid]['rejected_at'] = datetime.utcnow().isoformat()
        _save(DATA)
    return jsonify({'ok': True})

@app.route('/api/admin/keys/<kid>', methods=['PATCH'])
def admin_update_key(kid):
    if not _ok_root(request.headers.get('X-Root-Key', '')):
        return jsonify({'ok': False}), 401
    entry = DATA.get('verify_keys', {}).get(kid)
    if not entry:
        return jsonify({'ok': False, 'error': 'Key not found'}), 404
    body = request.json or {}
    changed = False
    if 'private_vpn' in body:
        enabled = bool(body.get('private_vpn'))
        mode = entry.get('mode', 'ssh_runner')
        device = _norm_device(entry.get('device'))
        if enabled and mode == 'ssh_runner' and device in ('mac', 'windows'):
            entry['mode'] = 'desktop_clash'
            mode = 'desktop_clash'
            changed = True
        if enabled and mode not in ('ios_shadowrocket', 'android_clash', 'desktop_clash'):
            return jsonify({'ok': False, 'error': 'MyNetwork can only be enabled for Shadowrocket or Clash/Mihomo users.'}), 400
        if enabled:
            if not entry.get('private_vpn'):
                entry['private_vpn'] = True
                changed = True
            if entry.pop('private_vpn_disabled', None) is not None:
                changed = True
            if mode in ('android_clash', 'desktop_clash'):
                _ensure_ss_user(kid, entry, restart=True)
            _ensure_private_vpn_user(kid, entry, restart=True)
        else:
            if entry.pop('private_vpn', None) is not None:
                changed = True
            if not entry.get('private_vpn_disabled'):
                entry['private_vpn_disabled'] = True
                changed = True
            _sync_private_vpn_users(restart=True)
    if changed:
        _save(DATA)
    return jsonify({
        'ok': True,
        'private_vpn': bool(_private_vpn_enabled_for(kid, entry)),
        'private_vpn_port': entry.get('private_vpn_port'),
    })

@app.route('/api/admin/keys/<kid>/recovery-link', methods=['POST'])
def admin_recovery_link(kid):
    if not _ok_root(request.headers.get('X-Root-Key', '')):
        return jsonify({'ok': False}), 401
    entry = DATA.get('verify_keys', {}).get(kid)
    if not entry:
        return jsonify({'ok': False, 'error': 'Key not found'}), 404
    token = _ensure_dashboard_token(entry, rotate=True)
    _save(DATA)
    link = request.url_root.rstrip('/') + '/#recover=' + quote(token, safe='')
    return jsonify({'ok': True, 'recovery_link': link})

@app.route('/api/admin/keys/<kid>', methods=['DELETE'])
def admin_revoke(kid):
    if not _ok_root(request.headers.get('X-Root-Key', '')):
        return jsonify({'ok': False}), 401
    kicked = 0
    if kid in DATA['verify_keys']:
        del DATA['verify_keys'][kid]
        _save(DATA)
        _auth_remove(kid)
        for ext in ('.priv', '.pub'):
            p = os.path.join(KEYS_DIR, kid + ext)
            if os.path.exists(p):
                os.remove(p)
        _sync_ss_users(restart=True)
        _sync_private_vpn_users(restart=True)
        kicked = _kick_ssh_sessions()
    return jsonify({'ok': True, 'kicked_sessions': kicked})

# ── User endpoints ───────────────────────────────────────────────────────────

def _entry_for(kid, client_ip):
    """Resolve a verify-key. Returns (entry, error_response).

    IP addresses are audit data only. Campus Wi-Fi may move users between
    routers/NAT exits, so we do not reject a valid hidden key solely because
    the source IP changed.
    """
    if kid not in DATA['verify_keys']:
        return None, (jsonify({'ok': False, 'error': 'Invalid key'}), 401)
    entry = DATA['verify_keys'][kid]
    return entry, None

def _verify_key_from_request():
    return (request.headers.get('X-Verify-Key')
            or request.cookies.get(COOKIE_NAME, '')
            or request.args.get('key', '')).strip().upper()

@app.route('/api/session/recover', methods=['POST'])
def recover_session():
    token = (request.json or {}).get('token', '')
    kid, entry, _source = _entry_for_recovery_token(token)
    if not kid:
        return jsonify({'ok': False, 'error': 'Recovery link is invalid or expired'}), 401
    next_token = _ensure_dashboard_token(entry, rotate=True)
    _record_key_ip(entry, request.remote_addr, activate=True)
    _save(DATA)
    resp = jsonify({'ok': True, 'recovery_token': next_token})
    return _set_user_cookie(resp, kid)

@app.route('/api/request-key', methods=['POST'])
def request_key():
    body = request.json or {}
    name = body.get('name', '').strip()
    device = _norm_device(body.get('device', ''))
    kind = _device_kind(device)
    if not name:
        return jsonify({'ok': False, 'error': 'Enter your name'}), 400
    rid = secrets.token_urlsafe(12)
    DATA.setdefault('requests', {})[rid] = {
        'name': name[:80],
        'device': device,
        'kind': kind,
        'client_ip': request.remote_addr,
        'created_at': datetime.utcnow().isoformat(),
        'status': 'pending',
        'key': None,
    }
    _save(DATA)
    return jsonify({'ok': True, 'request_id': rid})

@app.route('/api/request-key/<rid>')
def request_key_status(rid):
    req = DATA.setdefault('requests', {}).get(rid)
    if not req:
        return jsonify({'ok': False, 'error': 'Request not found'}), 404
    if (req.get('status') == 'approved' and req.get('key')
            and req.get('key') not in DATA.get('verify_keys', {})):
        return jsonify({'ok': False, 'status': 'revoked', 'error': 'Access was revoked'}), 410
    if (req.get('status') == 'approved'
            and req.get('kind') in ('ios_shadowrocket', 'android_clash', 'desktop_clash')
            and not req.get('key')):
        try:
            label = req.get('name') or req.get('device') or rid
            if req.get('kind') == 'android_clash':
                req['key'] = _create_verify_key(label + ' Android', device='android', mode='android_clash')
                req['config_url'], req['link'] = _clash_profile_urls(req['key'])
            elif req.get('kind') == 'desktop_clash':
                req['key'] = _create_verify_key(label, device=req.get('device'), mode='desktop_clash')
                req['config_url'], req['link'] = _clash_profile_urls(req['key'])
            else:
                req['key'] = _create_verify_key(label + ' iOS', device='iphone', mode='ios_shadowrocket')
                req['link'] = req.get('link') or _shadowrocket_url(_request_host(), req['key'])
            _ensure_ss_user(req['key'], DATA['verify_keys'][req['key']], restart=True)
            _mark_ios_key_active(req['key'], req)
            _save(DATA)
        except Exception as e:
            return jsonify({'ok': False, 'error': 'Key generation failed: ' + str(e)}), 500
    elif (req.get('status') == 'approved'
            and req.get('kind') in ('ios_shadowrocket', 'android_clash', 'desktop_clash')
            and req.get('key')):
        changed = False
        if req.get('kind') in ('android_clash', 'desktop_clash') and not req.get('config_url'):
            req['config_url'], req['link'] = _clash_profile_urls(req['key'])
            changed = True
        elif req.get('kind') == 'ios_shadowrocket':
            req['link'] = _shadowrocket_url(_request_host(), req['key'])
        if _mark_ios_key_active(req['key'], req):
            changed = True
        if changed:
            _save(DATA)
    out = {
        'ok': True,
        'status': req.get('status', 'pending'),
        'name': req.get('name', ''),
        'device': req.get('device', ''),
    }
    if req.get('status') == 'approved' and req.get('key'):
        out['approved'] = True
        if req.get('kind') in ('android_clash', 'desktop_clash'):
            req['config_url'], req['link'] = _clash_profile_urls(req['key'])
        elif req.get('kind') == 'ios_shadowrocket':
            req['link'] = _shadowrocket_url(_request_host(), req['key'])
        entry = DATA['verify_keys'][req['key']]
        had_dashboard_token = bool(entry.get('dashboard_token'))
        out['recovery_token'] = _ensure_dashboard_token(entry)
        if not had_dashboard_token:
            _save(DATA)
    if req.get('status') == 'approved' and req.get('link'):
        out['link'] = req['link']
    if req.get('status') == 'approved' and req.get('config_url'):
        out['config_url'] = req['config_url']
    resp = jsonify(out)
    if req.get('status') == 'approved' and req.get('key'):
        _set_user_cookie(resp, req['key'])
    return resp

@app.route('/api/logout', methods=['POST'])
def user_logout():
    resp = jsonify({'ok': True})
    resp.delete_cookie(COOKIE_NAME)
    return resp

@app.route('/api/validate-key')
def validate_key():
    kid = _verify_key_from_request()
    entry, err = _entry_for(kid, request.remote_addr)
    if err:
        return err
    if _record_key_ip(entry, request.remote_addr):
        _save(DATA)
    had_dashboard_token = bool(entry.get('dashboard_token'))
    recovery_token = _ensure_dashboard_token(entry)
    if not had_dashboard_token:
        _save(DATA)
    resp = jsonify({'ok': True, 'recovery_token': recovery_token})
    return _set_user_cookie(resp, kid)

@app.route('/api/user/status')
def user_status():
    """Everything the dashboard polls: identity, live speed, session data flow,
    and the connect/disconnect log."""
    kid = _verify_key_from_request()
    entry, err = _entry_for(kid, request.remote_addr)
    if err:
        return err
    changed = _record_key_ip(entry, request.remote_addr)
    had_dashboard_token = bool(entry.get('dashboard_token'))
    recovery_token = _ensure_dashboard_token(entry)
    if changed or not had_dashboard_token:
        _save(DATA)
    ip = request.remote_addr
    with _mon_lock:
        st  = dict(_ip_stats.get(ip) or _new_stat())
        log = list(_ip_logs.get(ip, []))
    mode = entry.get('mode', 'ssh_runner')
    device = entry.get('device', 'windows')
    if mode == 'ssh_runner' and device in ('mac', 'windows'):
        entry['mode'] = 'desktop_clash'
        mode = 'desktop_clash'
        _save(DATA)
    if mode in ('ios_shadowrocket', 'android_clash', 'desktop_clash'):
        service_up = _shadowsocks_service_up()
        with _mon_lock:
            key_st = dict(_key_stats.get(kid) or {})
        recent_proxy = (_iso_age_seconds(key_st.get('last_at')) or 10 ** 9) < 90
        recent_rate = (_iso_age_seconds(key_st.get('rate_at')) or 10 ** 9) < 7
        if key_st:
            st.update(key_st)
            st['connected'] = bool(service_up and recent_proxy)
            if not recent_rate:
                st['down_bps'] = 0
                st['up_bps'] = 0
        if not service_up:
            st.update({'connected': False, 'down_bps': 0, 'up_bps': 0})
        log = []
    clash_config_url = clash_import_url = None
    shadowrocket_url = None
    if mode in ('android_clash', 'desktop_clash') or (mode == 'ssh_runner' and device in ('mac', 'windows')):
        had_profile_token = bool(entry.get('profile_token'))
        clash_config_url, clash_import_url = _clash_profile_urls(kid)
        if (not had_profile_token) or _record_key_ip(entry, request.remote_addr, activate=True):
            _save(DATA)
    elif mode == 'ios_shadowrocket':
        try:
            shadowrocket_url = _shadowrocket_import_link(kid)
        except Exception:
            shadowrocket_url = None
    resp = jsonify({
        'ok':             True,
        'label':          entry.get('label', ''),
        'mode':           mode,
        'device':         device,
        'config_url':     clash_config_url,
        'link':           shadowrocket_url or clash_import_url,
        'shadowrocket_url': shadowrocket_url,
        'activated':      entry['activated'],
        'activated_at':   entry.get('activated_at'),
        'activated_ip':   entry.get('activated_ip'),
        'last_ip':        entry.get('last_ip') or ip,
        'current_ip':     ip,
        'ip_count':       len(entry.get('ip_history') or []),
        'download_count': entry.get('download_count', 0),
        'last_download':  entry.get('last_download'),
        'connected':      st['connected'],
        'since':          st['since'],
        'down_bps':       st['down_bps'],
        'up_bps':         st['up_bps'],
        'sess_down':      st['sess_down'],
        'sess_up':        st['sess_up'],
        'traffic_7d':     _traffic_7d(kid),
        'log':            log,
        'recovery_token': recovery_token,
    })
    return _set_user_cookie(resp, kid)

@app.route('/api/profile/clash/<token>')
def clash_profile(token):
    token = (token or '').strip()
    kid = None
    profile_entry = None
    for key_id, entry in DATA.get('verify_keys', {}).items():
        if (entry.get('mode') in ('android_clash', 'desktop_clash', 'ssh_runner')
                and secrets.compare_digest(entry.get('profile_token') or '', token)):
            kid = key_id
            profile_entry = entry
            break
    if not kid:
        abort(404)
    if profile_entry is not None:
        profile_entry['last_profile_at'] = _now_iso()
        _mark_key_seen(profile_entry, request.remote_addr)
        _save(DATA)
    try:
        yaml = _clash_yaml(kid, _request_host())
    except Exception as e:
        return str(e), 500
    return Response(yaml, mimetype='text/yaml',
                    headers={'Cache-Control': 'no-store',
                             'Content-Disposition': 'inline; filename="schoolvpn-clash.yaml"'})

@app.route('/api/profile/shadowrocket/<token>')
def shadowrocket_profile(token):
    kid, profile_entry = _shadowrocket_profile_entry(token)
    if not kid:
        abort(404)
    if profile_entry is not None:
        profile_entry['last_profile_at'] = _now_iso()
        _mark_key_seen(profile_entry, request.remote_addr)
        _save(DATA)
    try:
        sub = _shadowrocket_subscription(kid, _request_host())
    except Exception as e:
        return str(e), 500
    return Response(sub, mimetype='text/plain',
                    headers={'Cache-Control': 'no-store',
                             'Content-Disposition': 'inline; filename="schoolvpn-shadowrocket.txt"'})

@app.route('/api/profile/shadowrocket-conf/<token>')
def shadowrocket_conf_profile(token):
    kid, profile_entry = _shadowrocket_profile_entry(token)
    if not kid:
        abort(404)
    if profile_entry is not None:
        profile_entry['last_profile_at'] = _now_iso()
        _mark_key_seen(profile_entry, request.remote_addr)
        _save(DATA)
    try:
        conf = _shadowrocket_conf(kid, _request_host())
    except Exception as e:
        return str(e), 500
    return Response(conf, mimetype='text/plain',
                    headers={'Cache-Control': 'no-store',
                             'Content-Disposition': 'inline; filename="schoolvpn-shadowrocket.conf"'})

def _shadowrocket_profile_entry(token):
    token = (token or '').strip()
    kid = None
    profile_entry = None
    for key_id, entry in DATA.get('verify_keys', {}).items():
        if (entry.get('mode') == 'ios_shadowrocket'
                and secrets.compare_digest(entry.get('profile_token') or '', token)):
            kid = key_id
            profile_entry = entry
            break
    return kid, profile_entry

# ── Runner download (activates the key on first download) ─────────────────────

@app.route('/api/runner/<platform>')
def runner(platform):
    if platform not in ('mac', 'win', 'ios'):
        abort(404)
    kid = _verify_key_from_request()
    entry, err = _entry_for(kid, request.remote_addr)
    if err:
        return err

    priv_file = os.path.join(KEYS_DIR, f'{kid}.priv')
    if not os.path.exists(priv_file):
        return 'SSH key missing — contact admin', 500
    with open(priv_file) as f:
        private_key = f.read()

    _record_key_ip(entry, request.remote_addr, activate=True)
    entry['download_count'] = entry.get('download_count', 0) + 1
    entry['last_download']  = datetime.utcnow().isoformat()
    _save(DATA)

    connect_host = _request_host()
    if platform == 'mac':
        return _mac_runner(kid, private_key, connect_host)
    if platform == 'win':
        return _win_runner(kid, private_key, connect_host)
    return _ios_shadowrocket_kit(kid, private_key, connect_host)

def _attach(script, kid, ext):
    return Response(script, mimetype='text/plain',
                    headers={'Content-Disposition':
                             f'attachment; filename="schoolvpn-{kid[:4]}.{ext}"',
                             'Cache-Control': 'no-store',
                             'Pragma': 'no-cache'})

def _mac_runner(kid, private_key, connect_host):
    script = f'''#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  MyNetwork Runner — macOS
#  Key  : {kid}
#  Host : {SSH_USER}@{connect_host}
#
#  Usage: chmod +x mynetwork.sh && ./mynetwork.sh
#  Press Ctrl+C to disconnect.
# ─────────────────────────────────────────────────────────────
SERVER_USER="{SSH_USER}"
SERVER_HOST="{connect_host}"
SERVER_PORT="{SSH_PORT}"
SOCKS_PORT=1080
WEB_PORT=5000
VERIFY_KEY="{kid}"
SSH_PID=""
PROXY_ON=""
SHARE_HOST=""
# A site the lab server can reach — used to confirm real internet works.
TEST_URL="http://www.baidu.com"

KEY_FILE=$(mktemp /tmp/schoolvpn_XXXXXX)
chmod 600 "$KEY_FILE"
cat > "$KEY_FILE" <<'SSHKEY'
{private_key}
SSHKEY

# Pick the network service that actually carries your traffic (the one behind
# the default route) — NOT just the first one in the list.
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{{print $2}}')
SERVICE=$(networksetup -listnetworkserviceorder 2>/dev/null | awk -v dev=" $IFACE)" '
  /^\\([0-9]+\\)/ {{ name=$0; sub(/^\\([0-9]+\\) /,"",name) }}
  index($0, "Device:" dev) {{ print name; exit }}')
[ -z "$SERVICE" ] && SERVICE=$(networksetup -listallnetworkservices 2>/dev/null | grep -v "^An" | grep -E "Wi-Fi|Ethernet" | head -1)
[ -z "$SERVICE" ] && SERVICE="Wi-Fi"

# Hotspot / LAN sharing: bind a second SOCKS listener to a private LAN address
# so phones connected to this computer's hotspot can use it manually.
for ip in $(ifconfig 2>/dev/null | awk '/inet /{{print $2}}'); do
  case "$ip" in
    127.*) ;;
    10.*|172.16.*|172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|172.23.*|172.24.*|172.25.*|172.26.*|172.27.*|172.28.*|172.29.*|172.30.*|172.31.*|192.168.*)
      SHARE_HOST="$ip"
      break
      ;;
  esac
done

# Remember your existing proxy so we can put it back EXACTLY on exit.
_orig=$(networksetup -getsocksfirewallproxy "$SERVICE" 2>/dev/null)
ORIG_ENABLED=$(echo "$_orig" | awk '/^Enabled/{{print $2}}')
ORIG_SERVER=$(echo  "$_orig" | awk '/^Server/{{print $2}}')
ORIG_PORT=$(echo    "$_orig" | awk '/^Port/{{print $2}}')

restore_proxy() {{
  if [ "$ORIG_ENABLED" = "Yes" ] && [ -n "$ORIG_SERVER" ]; then
    networksetup -setsocksfirewallproxy      "$SERVICE" "$ORIG_SERVER" "$ORIG_PORT" 2>/dev/null
    networksetup -setsocksfirewallproxystate "$SERVICE" on  2>/dev/null
  else
    networksetup -setsocksfirewallproxystate "$SERVICE" off 2>/dev/null
  fi
}}

_done=""
cleanup() {{
  [ -n "$_done" ] && return    # run once even if several signals arrive
  _done=1
  echo ""
  echo "Disconnecting..."
  [ -n "$PROXY_ON" ] && restore_proxy
  # stop the tunnel — by PID, then by key file as a safety net, then hard kill
  [ -n "$SSH_PID" ] && kill "$SSH_PID" 2>/dev/null
  pkill -f "$KEY_FILE" 2>/dev/null
  sleep 1
  [ -n "$SSH_PID" ] && kill -9 "$SSH_PID" 2>/dev/null
  rm -f "$KEY_FILE"
  echo "Done — MyNetwork stopped and your previous network settings are restored."
}}
# EXIT covers normal end / Ctrl-C; HUP covers closing the Terminal window.
trap cleanup EXIT HUP INT TERM

echo "Active network service : $SERVICE"
echo "Connecting to lab network ($SERVER_HOST)..."
SSH_D="-D 127.0.0.1:$SOCKS_PORT"
if [ -n "$SHARE_HOST" ]; then
  SSH_D="$SSH_D -D $SHARE_HOST:$SOCKS_PORT"
fi
ssh -N $SSH_D \\
    -p "$SERVER_PORT" \\
    -o StrictHostKeyChecking=no \\
    -o ConnectTimeout=10 \\
    -o ExitOnForwardFailure=yes \\
    -o ServerAliveInterval=30 \\
    -o ServerAliveCountMax=3 \\
    -o BatchMode=yes \\
    -o PreferredAuthentications=publickey \\
    -o PubkeyAuthentication=yes \\
    -o PasswordAuthentication=no \\
    -o KbdInteractiveAuthentication=no \\
    -o NumberOfPasswordPrompts=0 \\
    -i "$KEY_FILE" \\
    "$SERVER_USER@$SERVER_HOST" &
SSH_PID=$!

# Confirm REAL internet works through the tunnel BEFORE touching your proxy.
# This guarantees we never hand your browser a dead/blocked tunnel.
echo "Verifying internet through the lab (a few seconds)..."
NET=""
for _ in $(seq 1 15); do
  if ! kill -0 "$SSH_PID" 2>/dev/null; then
    echo "ERROR: SSH closed — you may not have access to $SERVER_HOST."
    echo "Your network was NOT changed."
    exit 1
  fi
  if curl -s --socks5-hostname 127.0.0.1:$SOCKS_PORT --max-time 8 \\
       -o /dev/null "$TEST_URL" 2>/dev/null; then
    NET=1; break
  fi
  sleep 1
done

if [ -z "$NET" ]; then
  echo "ERROR: The tunnel is up but could not load $TEST_URL through it."
  echo "The lab server may have no usable internet right now."
  echo "Your system proxy was NOT changed; normal browsing is unaffected."
  exit 1
fi

networksetup -setsocksfirewallproxy      "$SERVICE" 127.0.0.1 $SOCKS_PORT
networksetup -setsocksfirewallproxystate "$SERVICE" on
PROXY_ON=1

echo ""
echo "  ============================================"
echo "   ✅  CONNECTED — your browser now uses the lab"
echo "   Service : $SERVICE"
echo "   Proxy   : 127.0.0.1:$SOCKS_PORT (SOCKS5)"
echo "   Internet check passed ($TEST_URL)"
echo "  ============================================"
echo ""
if [ -n "$SHARE_HOST" ]; then
  echo "  Hotspot sharing:"
  echo "   On your phone Wi-Fi settings, set SOCKS/Proxy server to:"
  echo "   Host $SHARE_HOST   Port $SOCKS_PORT"
  echo ""
fi
echo "  Live status below. Press Ctrl+C to disconnect."
echo ""

# Heartbeat so you always know whether you're still connected. Checks the
# tunnel every 2s (so a dropped tunnel restores your network promptly) and
# prints a live status line about every 10s.
SECS=0
KEY_FAILS=0
while kill -0 "$SSH_PID" 2>/dev/null; do
  sleep 2
  SECS=$((SECS + 2))
  [ $((SECS % 10)) -ne 0 ] && continue
  if curl -fsS --noproxy "*" -H "X-Verify-Key: $VERIFY_KEY" --max-time 6 \
       "http://$SERVER_HOST:$WEB_PORT/api/validate-key" >/dev/null 2>&1; then
    KEY_FAILS=0
  else
    KEY_FAILS=$((KEY_FAILS + 1))
    echo "  WARNING: key check failed ($KEY_FAILS/3)"
    if [ "$KEY_FAILS" -ge 3 ]; then
      echo "  Key revoked or unreachable — disconnecting now."
      break
    fi
  fi
  if curl -s --socks5-hostname 127.0.0.1:$SOCKS_PORT --max-time 8 -o /dev/null "$TEST_URL" 2>/dev/null; then
    echo "  ● $(date +%H:%M:%S)  connected — internet OK"
  else
    echo "  ○ $(date +%H:%M:%S)  WARNING: tunnel up but internet check failed"
  fi
done
echo "Connection lost — restoring your network..."
'''
    return _attach(script, kid, 'sh')

def _win_runner(kid, private_key, connect_host):
    key_b64 = base64.b64encode(private_key.encode()).decode()
    script = f'''@echo off
:: -------------------------------------------------------------
::  MyNetwork Runner - Windows
::  Key  : {kid}
::  Host : {SSH_USER}@{connect_host}
::
::  Double-click to connect. Press any key to disconnect.
:: -------------------------------------------------------------
title MyNetwork - Connecting...
setlocal enabledelayedexpansion

set "SERVER_USER={SSH_USER}"
set "SERVER_HOST={connect_host}"
set "SERVER_PORT={SSH_PORT}"
set "SOCKS_PORT=1080"
set "WEB_PORT=5000"
set "VERIFY_KEY={kid}"
set "TEST_URL=http://www.baidu.com"
set "KEY_FILE=%TEMP%\\schoolvpn_{kid[:8]}.key"
set "REGK=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
set "KEY_FAILS=0"
set "SHARE_HOST="

where ssh.exe >nul 2>&1
if errorlevel 1 (
  echo Windows OpenSSH Client was not found.
  echo Trying to install it automatically. Windows may ask for administrator permission.
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Start-Process PowerShell -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0'" 2>nul
  where ssh.exe >nul 2>&1
  if errorlevel 1 (
    echo ERROR: ssh.exe is still missing.
    echo Please enable: Settings - Apps - Optional features - OpenSSH Client.
    pause & exit /b 1
  )
)

echo Writing credentials...
powershell -NoProfile -Command ^
  "[System.IO.File]::WriteAllText('%KEY_FILE%', [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{key_b64}')), [System.Text.UTF8Encoding]::new($false))" 2>nul

if not exist "%KEY_FILE%" (
  echo ERROR: Could not write key file. Requires PowerShell and Windows 10+.
  pause & exit /b 1
)

echo Securing key file...
powershell -NoProfile -Command ^
  "$p=$env:KEY_FILE; $acl=Get-Acl -LiteralPath $p; $acl.SetAccessRuleProtection($true,$false); $me=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($me,'FullControl','Allow'); $acl.SetAccessRule($rule); Set-Acl -LiteralPath $p -AclObject $acl" 2>nul

if errorlevel 1 (
  echo ERROR: Could not secure the private key file permissions.
  del "%KEY_FILE%" 2>nul
  pause & exit /b 1
)

:: Remember your existing proxy so we can put it back exactly on exit.
set "ORIG_ENABLE=0"
set "ORIG_SERVER="
for /f "tokens=3" %%a in ('reg query "%REGK%" /v ProxyEnable 2^>nul ^| find "ProxyEnable"') do set "ORIG_ENABLE=%%a"
for /f "tokens=2*" %%a in ('reg query "%REGK%" /v ProxyServer 2^>nul ^| find "ProxyServer"') do set "ORIG_SERVER=%%b"

for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /R /C:"IPv4.*192\\.168\\." /C:"IPv4.*10\\." /C:"IPv4.*172\\.1[6-9]\\." /C:"IPv4.*172\\.2[0-9]\\." /C:"IPv4.*172\\.3[0-1]\\."') do (
  if not defined SHARE_HOST (
    set "SHARE_HOST=%%a"
    set "SHARE_HOST=!SHARE_HOST: =!"
  )
)

echo Connecting...
if defined SHARE_HOST (
  start "MyNetwork-SSH" /b ssh -N -D 127.0.0.1:%SOCKS_PORT% -D !SHARE_HOST!:%SOCKS_PORT% ^
  -p %SERVER_PORT% ^
  -o StrictHostKeyChecking=no ^
  -o ConnectTimeout=10 ^
  -o ExitOnForwardFailure=yes ^
  -o ServerAliveInterval=30 ^
  -o ServerAliveCountMax=3 ^
  -o BatchMode=yes ^
  -o PreferredAuthentications=publickey ^
  -o PubkeyAuthentication=yes ^
  -o IdentitiesOnly=yes ^
  -o PasswordAuthentication=no ^
  -o KbdInteractiveAuthentication=no ^
  -o NumberOfPasswordPrompts=0 ^
  -i "%KEY_FILE%" ^
  %SERVER_USER%@%SERVER_HOST%
) else (
  start "MyNetwork-SSH" /b ssh -N -D 127.0.0.1:%SOCKS_PORT% ^
  -p %SERVER_PORT% ^
  -o StrictHostKeyChecking=no ^
  -o ConnectTimeout=10 ^
  -o ExitOnForwardFailure=yes ^
  -o ServerAliveInterval=30 ^
  -o ServerAliveCountMax=3 ^
  -o BatchMode=yes ^
  -o PreferredAuthentications=publickey ^
  -o PubkeyAuthentication=yes ^
  -o IdentitiesOnly=yes ^
  -o PasswordAuthentication=no ^
  -o KbdInteractiveAuthentication=no ^
  -o NumberOfPasswordPrompts=0 ^
  -i "%KEY_FILE%" ^
  %SERVER_USER%@%SERVER_HOST%
)

:: Confirm REAL internet works through the tunnel BEFORE enabling the proxy.
echo Verifying internet through the lab (a few seconds)...
set "OK="
for /L %%i in (1,1,15) do (
  if not defined OK (
    curl.exe -s --socks5-hostname 127.0.0.1:%SOCKS_PORT% --max-time 8 -o nul "%TEST_URL%" && set "OK=1"
    if not defined OK timeout /t 1 /nobreak >nul
  )
)

if not defined OK (
  echo ERROR: Could not load %TEST_URL% through the tunnel.
  echo Your system proxy was NOT changed; normal browsing is unaffected.
  taskkill /f /im ssh.exe >nul 2>&1
  del "%KEY_FILE%" 2>nul
  pause & exit /b 1
)

reg add "%REGK%" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "%REGK%" /v ProxyServer /t REG_SZ /d "socks=127.0.0.1:%SOCKS_PORT%" /f >nul
reg add "%REGK%" /v ProxyOverride /t REG_SZ /d "localhost;127.*;10.*;192.168.*" /f >nul

title MyNetwork - Connected
echo.
echo   ============================================
echo    CONNECTED - your browser now uses the lab
echo    Proxy   : 127.0.0.1:%SOCKS_PORT% (SOCKS5)
echo    Internet check passed (%TEST_URL%)
echo   ============================================
echo.
if defined SHARE_HOST (
  echo   Hotspot sharing:
  echo    On your phone Wi-Fi settings, set SOCKS/Proxy server to:
  echo    Host !SHARE_HOST!   Port %SOCKS_PORT%
  echo.
)
echo   Press D to disconnect. Revoked keys disconnect automatically.

:CONNECTED_LOOP
choice /c DN /n /t 10 /d N /m "Press D to disconnect..." >nul
if errorlevel 2 goto CHECK_STATUS
goto DISCONNECT

:CHECK_STATUS
curl.exe -fsS --noproxy "*" -H "X-Verify-Key: %VERIFY_KEY%" --max-time 6 "http://%SERVER_HOST%:%WEB_PORT%/api/validate-key" >nul 2>&1
if errorlevel 1 (
  set /a KEY_FAILS+=1
  echo WARNING: key check failed (!KEY_FAILS!/3)
  if !KEY_FAILS! GEQ 3 (
    echo Key revoked or unreachable - disconnecting now.
    goto DISCONNECT
  )
) else (
  set "KEY_FAILS=0"
)
curl.exe -s --socks5-hostname 127.0.0.1:%SOCKS_PORT% --max-time 8 -o nul "%TEST_URL%"
if errorlevel 1 echo WARNING: tunnel is up but internet check failed.
goto CONNECTED_LOOP

:DISCONNECT
title MyNetwork - Disconnecting...
taskkill /f /im ssh.exe >nul 2>&1
:: restore your previous proxy exactly
if "%ORIG_ENABLE%"=="0x1" (
  if defined ORIG_SERVER reg add "%REGK%" /v ProxyServer /t REG_SZ /d "%ORIG_SERVER%" /f >nul
  reg add "%REGK%" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
) else (
  reg add "%REGK%" /v ProxyEnable /t REG_DWORD /d 0 /f >nul
)
del "%KEY_FILE%" >nul 2>&1
echo Disconnected - your previous network settings are restored.
timeout /t 2 /nobreak >nul
'''
    return _attach(script, kid, 'bat')

def _ios_shadowrocket_kit(kid, private_key, connect_host):
    text = f'''MyNetwork - Shadowrocket setup for iOS

Key
  {kid}

Server
  Type: SSH / SSH Tunnel
  Host: {connect_host}
  Port: {SSH_PORT}
  User: {SSH_USER}
  Authentication: Private Key
  Dynamic forwarding / SOCKS5: enabled

Setup
  1. Install Shadowrocket from the App Store.
  2. Add a new SSH / SSH Tunnel server.
  3. Fill Host, Port, User with the values above.
  4. Choose private-key authentication.
  5. Import or paste the private key below.
  6. Save, select the node, then turn on Shadowrocket.

Notes
  - This verify-key is bound to the first IP that downloaded this kit.
  - Do not share this file. It contains the private key.
  - If the key is revoked, this profile will stop working.
  - If Shadowrocket shows many active connections, it is usually iOS background
    traffic such as iCloud, App Store, push services, or app refresh.
  - For lower traffic, avoid Global/Proxy-All mode. Prefer Rule/Config mode and
    let Apple, iCloud, App Store, LAN, and China traffic go Direct.
  - After setup, close the MyNetwork dashboard page and pause large iCloud Photos
    or App Store downloads if the tunnel feels busy.

Private key
{private_key}
'''
    return _attach(text, kid, 'shadowrocket.txt')

# ── Static / health ──────────────────────────────────────────────────────────

@app.route('/api/ping')
def ping():
    return jsonify({'ok': True})

@app.route('/')
def index():
    return send_file('index.html')

if __name__ == '__main__':
    _auth_sync()
    app.run(host='0.0.0.0', port=5000)
