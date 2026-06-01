#!/usr/bin/env python3
"""ServerFetch School VPN — server.py

Runs on the lab machine. Generates a per-user SSH key, serves a tiny runner
that opens an SSH SOCKS5 tunnel, and — because every tunnel terminates here —
measures each user's live throughput / data-flow / connect history server-side.
That means the runner needs nothing but a built-in `ssh` (no Python on the
client), and the dashboard still shows real stats for every user.
"""
import os, re, json, time, shutil, secrets, threading, subprocess, base64, pwd, sqlite3
from collections import deque
from datetime import datetime
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
TRAFFIC_DB  = os.path.join(BASE_DIR, 'traffic.sqlite3')
SSH_USER    = os.environ.get('SSH_USER',    'user1')
SERVER_HOST = os.environ.get('SERVER_HOST', '10.1.4.43')
DISPLAY_HOST = os.environ.get('DISPLAY_HOST', 'labvpn')
SSH_PORT    = str(os.environ.get('SSH_PORT', '22'))
AUTH_KEYS   = os.environ.get('AUTH_KEYS',   '')
LOCK_TO_FIRST_IP = False
KICK_SSH_ON_REVOKE = False
COOKIE_NAME = 'labvpn_key'
MOBILE_PROXY_CONTAINER = 'Network'
VALID_DEVICES = ('iphone', 'android', 'mac', 'windows')
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

def _ok_root(key):
    return secrets.compare_digest(key or '', DATA['root_key'])

def _request_host(default=SERVER_HOST):
    host = (request.host or '').split(':', 1)[0].strip()
    if not host or host in ('127.0.0.1', 'localhost'):
        return default
    return host

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

def _init_traffic_db():
    with sqlite3.connect(TRAFFIC_DB) as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS traffic_daily (
                key_id TEXT NOT NULL,
                day TEXT NOT NULL,
                down_bytes INTEGER NOT NULL DEFAULT 0,
                up_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key_id, day)
            )
        ''')
    try:
        os.chmod(TRAFFIC_DB, 0o600)
    except OSError:
        pass

def _add_traffic(kid, down_bytes, up_bytes):
    down_bytes = int(max(0, down_bytes or 0))
    up_bytes = int(max(0, up_bytes or 0))
    if not kid or (down_bytes == 0 and up_bytes == 0):
        return
    day = datetime.utcnow().date().isoformat()
    try:
        with sqlite3.connect(TRAFFIC_DB) as db:
            db.execute('''
                INSERT INTO traffic_daily(key_id, day, down_bytes, up_bytes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key_id, day) DO UPDATE SET
                    down_bytes = down_bytes + excluded.down_bytes,
                    up_bytes = up_bytes + excluded.up_bytes
            ''', (kid, day, down_bytes, up_bytes))
    except sqlite3.OperationalError:
        # CentOS 7 may ship an older SQLite without UPSERT support.
        with sqlite3.connect(TRAFFIC_DB) as db:
            db.execute('INSERT OR IGNORE INTO traffic_daily(key_id, day, down_bytes, up_bytes) VALUES (?, ?, 0, 0)',
                       (kid, day))
            db.execute('UPDATE traffic_daily SET down_bytes = down_bytes + ?, up_bytes = up_bytes + ? WHERE key_id = ? AND day = ?',
                       (down_bytes, up_bytes, kid, day))

def _traffic_7d(kid):
    today = datetime.utcnow().date()
    days = [(today.fromordinal(today.toordinal() - i)).isoformat() for i in range(6, -1, -1)]
    rows = {}
    with sqlite3.connect(TRAFFIC_DB) as db:
        for day, down, up in db.execute(
                'SELECT day, down_bytes, up_bytes FROM traffic_daily WHERE key_id = ? AND day >= ?',
                (kid, days[0])):
            rows[day] = {'down': down, 'up': up}
    return [{'day': day, 'down': rows.get(day, {}).get('down', 0), 'up': rows.get(day, {}).get('up', 0)}
            for day in days]

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

def _shadowrocket_url(host=None):
    if not os.path.exists(SS_CONFIG):
        raise RuntimeError('Shadowsocks iOS plugin is not configured')
    with open(SS_CONFIG) as f:
        cfg = json.load(f)
    server_host = host or cfg.get('server_host') or SERVER_HOST
    userinfo = f"{cfg['method']}:{cfg['password']}@{server_host}:{int(cfg['server_port'])}"
    encoded = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip('=')
    name = cfg.get('profile_name', 'SchoolVPN-iOS')
    return f"ss://{encoded}#{name}"

def _clash_profile_urls(kid):
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    token = entry.get('profile_token')
    if not token:
        token = secrets.token_urlsafe(24)
        entry['profile_token'] = token
    config_url = request.url_root.rstrip('/') + '/api/profile/clash/' + quote(token)
    device = _norm_device(entry.get('device'))
    profile_name = 'SchoolVPN-Android' if device == 'android' else 'SchoolVPN-ClashVerge'
    import_url = 'clash://install-config?url=' + quote(config_url, safe='') + '&name=' + quote(profile_name, safe='')
    return config_url, import_url

def _clash_yaml(kid, host=None):
    if not os.path.exists(SS_CONFIG):
        raise RuntimeError('Shadowsocks plugin is not configured')
    with open(SS_CONFIG) as f:
        cfg = json.load(f)
    entry = DATA.get('verify_keys', {}).get(kid) or {}
    device = _norm_device(entry.get('device'))
    name = 'SchoolVPN-Android' if device == 'android' else 'SchoolVPN-ClashVerge'
    return f'''# School VPN - Clash Meta / Mihomo
# Generated by School VPN. Revoking the user's key invalidates this subscription.

mixed-port: 7890
allow-lan: false
mode: global
log-level: info
ipv6: false

dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

proxies:
  - name: {name}
    type: ss
    server: {host or cfg.get('server_host') or SERVER_HOST}
    port: {int(cfg['server_port'])}
    cipher: {cfg['method']}
    password: "{cfg['password']}"
    udp: true

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - {name}

rules:
  - MATCH,PROXY
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

# ── Throughput monitor ───────────────────────────────────────────────────────
#
# Every SSH tunnel ends on this machine, so `ss -i` gives us the real per-socket
# byte counters. We sample once a second, aggregate by client IP, and expose
# live speed, cumulative session totals, and a connect/disconnect log. From the
# server's point of view: bytes it *sends* to the client = the user's download;
# bytes it *receives* = the user's upload.

_mon_lock  = threading.Lock()
_ip_stats  = {}   # ip -> live stats dict
_ip_logs   = {}   # ip -> deque[{t, event}]
_sock_prev = {}   # socket key -> (sent, recv) from the previous sample

_RE_SENT  = re.compile(r'bytes_sent:(\d+)')
_RE_ACKED = re.compile(r'bytes_acked:(\d+)')
_RE_RECV  = re.compile(r'bytes_received:(\d+)')
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

def _traffic_admin_summary():
    today = datetime.utcnow().date()
    days = [(today.fromordinal(today.toordinal() - i)).isoformat() for i in range(6, -1, -1)]
    per_key = {}
    per_day = {day: {'day': day, 'down': 0, 'up': 0} for day in days}
    with sqlite3.connect(TRAFFIC_DB) as db:
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
        total = totals['down'] + totals['up']
        users.append({
            'key': kid,
            'label': entry.get('label', ''),
            'device': entry.get('device', ''),
            'mode': entry.get('mode', ''),
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
            out['shadowrocket_url'] = _shadowrocket_url(_request_host())
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

def _ss_sockets():
    """Established SSH sockets terminating on our port: (key, peer_ip, sent, recv).

    `ss -i` prints each socket as a header line (state / local / peer) followed
    by an indented info line carrying the byte counters. Older iproute2 has no
    -O (oneline) flag and reports bytes_acked rather than bytes_sent, so we pair
    the two lines manually and fall back to bytes_acked for "sent"."""
    if not _SS:
        return None
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
                ms = _RE_SENT.search(ln) or _RE_ACKED.search(ln)
                mr = _RE_RECV.search(ln)
                out.append((cur[0], cur[1],
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
                if ':' in local and ':' in peer and local.rsplit(':', 1)[-1] == SSH_PORT:
                    cur = (local + '|' + peer, peer.rsplit(':', 1)[0].strip('[]'))
    return out

SAMPLE_SEC = 0.5   # how often we read socket counters (finer = snappier graph)

def _monitor_loop():
    global _sock_prev
    prev_t = time.time()
    while True:
        time.sleep(SAMPLE_SEC)
        socks = _ss_sockets()
        if socks is None:
            continue
        now = time.time()
        dt  = now - prev_t
        prev_t = now
        if dt <= 0:
            dt = SAMPLE_SEC
        cur, delta, present = {}, {}, set()
        for key, ip, sent, recv in socks:
            cur[key] = (sent, recv)
            present.add(ip)
            prev = _sock_prev.get(key)
            ds = max(0, sent - prev[0]) if prev else 0
            dr = max(0, recv - prev[1]) if prev else 0
            d = delta.setdefault(ip, [0, 0])
            d[0] += ds; d[1] += dr
        _sock_prev = cur

        with _mon_lock:
            for ip in set(_ip_stats) | present:
                st = _ip_stats.setdefault(ip, _new_stat())
                was, now_c = st['connected'], ip in present
                d = delta.get(ip, [0, 0])
                if now_c:
                    if not was:                       # new session
                        st['sess_down'] = st['sess_up'] = 0
                        st['since'] = datetime.utcnow().isoformat()
                        _log_event(ip, 'up')
                    # accurate per-second rate; session totals get the raw bytes
                    st['down_bps'] = d[0] / dt
                    st['up_bps']   = d[1] / dt
                    st['sess_down'] += d[0]
                    st['sess_up']   += d[1]
                    for kid in _keys_for_ip(ip, 'ssh_runner'):
                        _add_traffic(kid, d[0], d[1])
                else:
                    if was:
                        _log_event(ip, 'down')
                    st['down_bps'] = st['up_bps'] = 0
                st['connected'] = now_c

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
            if mode == 'ios_shadowrocket':
                req['link'] = req.get('link') or _shadowrocket_url(_request_host())
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
                req['link'] = req.get('link') or _shadowrocket_url(_request_host())
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
            req['link'] = _shadowrocket_url(_request_host())
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
            req['link'] = _shadowrocket_url(_request_host())
    if req.get('status') == 'approved' and req.get('link'):
        out['link'] = req['link']
    if req.get('status') == 'approved' and req.get('config_url'):
        out['config_url'] = req['config_url']
    resp = jsonify(out)
    if req.get('status') == 'approved' and req.get('key'):
        resp.set_cookie(COOKIE_NAME, req['key'], max_age=60 * 60 * 24 * 90,
                        httponly=True, samesite='Lax')
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
    resp = jsonify({'ok': True})
    resp.set_cookie(COOKIE_NAME, kid, max_age=60 * 60 * 24 * 90,
                    httponly=True, samesite='Lax')
    return resp

@app.route('/api/user/status')
def user_status():
    """Everything the dashboard polls: identity, live speed, session data flow,
    and the connect/disconnect log."""
    kid = _verify_key_from_request()
    entry, err = _entry_for(kid, request.remote_addr)
    if err:
        return err
    if _record_key_ip(entry, request.remote_addr):
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
        net = _shadowsocks_net_stats() if service_up else {
            'rx_bps': 0, 'tx_bps': 0, 'sess_rx': 0, 'sess_tx': 0, 'delta_rx': 0, 'delta_tx': 0,
        }
        _add_traffic(kid, net['delta_tx'], net['delta_rx'])
        st.update({
            'connected': service_up,
            'since': entry.get('activated_at') if service_up else None,
            'down_bps': net['tx_bps'],
            'up_bps': net['rx_bps'],
            'sess_down': net['sess_tx'],
            'sess_up': net['sess_rx'],
        })
        log = []
    clash_config_url = clash_import_url = None
    if mode in ('android_clash', 'desktop_clash') or (mode == 'ssh_runner' and device in ('mac', 'windows')):
        had_profile_token = bool(entry.get('profile_token'))
        clash_config_url, clash_import_url = _clash_profile_urls(kid)
        if (not had_profile_token) or _record_key_ip(entry, request.remote_addr, activate=True):
            _save(DATA)
    return jsonify({
        'ok':             True,
        'label':          entry.get('label', ''),
        'mode':           mode,
        'device':         device,
        'config_url':     clash_config_url,
        'link':           clash_import_url,
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
    })

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
#  School VPN Runner — macOS
#  Key  : {kid}
#  Host : {SSH_USER}@{connect_host}
#
#  Usage: chmod +x schoolvpn.sh && ./schoolvpn.sh
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
  echo "Done — VPN stopped and your previous network settings are restored."
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
::  School VPN Runner - Windows
::  Key  : {kid}
::  Host : {SSH_USER}@{connect_host}
::
::  Double-click to connect. Press any key to disconnect.
:: -------------------------------------------------------------
title School VPN - Connecting...
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
  start "SchoolVPN-SSH" /b ssh -N -D 127.0.0.1:%SOCKS_PORT% -D !SHARE_HOST!:%SOCKS_PORT% ^
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
  start "SchoolVPN-SSH" /b ssh -N -D 127.0.0.1:%SOCKS_PORT% ^
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

title School VPN - Connected
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
title School VPN - Disconnecting...
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
    text = f'''School VPN - Shadowrocket setup for iOS

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
  - After setup, close the School VPN dashboard page and pause large iCloud Photos
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
