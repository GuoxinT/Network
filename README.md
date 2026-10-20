# MyNetwork

Self-hosted access portal for using the school/lab server network from approved
devices. The web app runs on the server, users request access from the page, and
admin approval creates a hidden per-user key.

User-facing keys are intentionally hidden. The browser receives an HttpOnly
cookie, Clash-based clients receive app-specific subscription links, and desktop
SSH runners remain available as a fallback.

## Current Architecture

```text
server.py
  Flask UI, admin panel, key approval, runner generation, usage analytics

index.html
  Single-page UI for user request/dashboard and admin management

keys.json
  Root key, verify keys, request records and device metadata (no IP history)

traffic.sqlite3
  Persistent per-key daily and hourly traffic totals for charts and analysis

keys/
  Per-user ed25519 SSH keypairs for mac/windows SSH runner mode

Plugins/shadowsocks-ios-mode/
  Dockerized Shadowsocks service for iPhone/Android mobile proxy mode
  Runtime container name: Network
```

## Devices

| Device | Mode | Client-facing output |
|---|---|---|
| iPhone | `ios_shadowrocket` | Shadowrocket `ss://` import link |
| Android | `android_clash` | Clash Meta/Mihomo subscription URL and import link |
| mac | `desktop_clash` | Clash Verge subscription URL; optional `mynetwork.sh` fallback |
| windows | `desktop_clash` | Clash Verge subscription URL; optional `mynetwork.bat` fallback |

The request form asks for:

- `name`: entered by the user
- `device`: selected from `iPhone`, `Android`, `mac`, `windows`

Admin approval decides the mode from `device`; users do not see the generated
verify key.

## Network Names

The page brand is `MyNetwork`.

`labvpn` may still be used as a hostname if the school/router DNS resolves it.
This is separate from the brand name. If a user opens the page through
`http://labvpn:5000`, generated mobile profiles and desktop runners prefer
`labvpn` as the server address. If a user opens the old IP URL, generated
profiles continue to use that IP so old access still works.

## Mobile Docker

The mobile proxy Docker service is required for iPhone and Android access.

```bash
cd ~/serverfetch/Plugins/shadowsocks-ios-mode
docker compose up -d --build
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Expected container:

```text
Network
```

Do not delete this container unless mobile access is intentionally disabled.
mac/windows SSH runner access does not depend on this container.

## Admin Analytics

Admin `/api/admin/keys` returns an `analytics` object used by the admin panel:

- health diagnostics for Flask, the `Network` container, 8388 exposure, profile
  pulls and pending requests
- consolidated user management data with status, device, mode, 7-day traffic,
  last active time and subscription links
- 7-day total traffic
- recent 168-hour total traffic series, including peak hour metadata
- top users by traffic

Destination auditing, keyword classification, client IP history and HTTP request
history have been removed. See [PRIVACY.md](PRIVACY.md) for the exact data retained
and the separate encrypted-exit design.

### Traffic accounting framework

Accounting is **hybrid**: each transport is measured at the only place its bytes
are actually visible, then everything funnels through one persistence path. The
key insight is that the proxies run inside Docker containers, so their sockets
live in a separate network namespace and are **invisible to the host's `ss`** —
only the proxy itself can see and attribute their bytes. (An earlier design that
read host socket counters for Shadowsocks recorded nothing for those users; do
not reintroduce it.)

| Transport | Where it runs | Authoritative byte source | Attribution |
|-----------|---------------|---------------------------|-------------|
| Shadowsocks (`ios_shadowrocket`, `android_clash`, `desktop_clash`) | `Network` container, one `ssserver` per user on ports `8400-8599` | `ssserver -vv` output passes through `traffic_filter.py` in a pipe; only numeric upload/download counts reach `state/traffic/user-<port>.log` | **By listening port** (one port = one key) |
| MyNetwork outlet | `PrivateVPNProxy` container, custom SOCKS5 on ports `8600-8699` | `private_socks.py` writes numeric counts to `state/traffic/user-<port>.log`, on every TCP close (clean **and** error) | **By listening port** |
| Shared `8388` port | `Network` container | `shared-8388.log` | Bucketed to the synthetic key `__shared__` — one port with one shared password cannot be split per user |
| SSH runner (legacy fallback) | host `sshd`, port 22 | host `ss -i` socket byte counters (`bytes_acked`/`bytes_received`) | Transient heartbeat IP → key mapping; expires after 120 seconds |

Pipeline (see `server.py`):

1. `_monitor_loop` runs every `SAMPLE_SEC` (0.5 s). It calls `_process_proxy_logs()`
   to tail all per-port proxy logs (`SS_LOG_DIR`, `PRIVATE_VPN_LOG_DIR`) and reads
   host SSH socket counters.
2. Parsed bytes go to `_accrue_traffic(kid, down, up)`, an in-memory accumulator.
3. Every `FLUSH_EVERY` samples (~5 s) `_flush_pending_traffic()` writes the
   accumulator to SQLite in **one transaction**. The DB is opened in **WAL** mode
   with a 30 s `busy_timeout`, so the sampler never collides with admin/user reads
   (`_traffic_db()`).
4. `traffic_daily` / `traffic_hourly` use **local-time** day/hour buckets
   (`_traffic_now()`, offset `TRAFFIC_TZ_OFFSET_HOURS`, default `+8`) so the
   dashboard's "today" matches the operator's wall clock.
5. Live speed for log-based modes is computed from the bytes seen in each 0.5 s
   sample window (`_key_tick`), bounded by real elapsed time — no false spikes
   from large connections closing.

On startup `_init_log_offsets()` seeds each log's read offset to EOF, so a server
restart tails only new lines and never re-counts history already in the DB.

Known limitations (intentional, documented):

- **Error-closed connections** (`closed with error: ...`, ~0.8% of connections)
  carry no byte totals in `ssserver` logs, so those bytes are not counted for
  Shadowsocks. The private proxy does not have this gap (it logs on every close).
- **Long-lived connections** only contribute to live speed / totals when they
  close. Abrupt process termination can lose counts; totals are best-effort.
- **SSH runner** bytes are attributed by client IP; multiple keys behind one NAT
  IP collapse onto the most-recent heartbeat key. Without recent authenticated
  heartbeats, SSH bytes cannot be attributed.
- **UDP** is metered for Shadowsocks (per-packet relay lines) but not yet for the
  private SOCKS proxy.
- Proxy log files grow append-only. They are rotated by `ops/proxy-logs.logrotate`
  (see that file's header for the rationale): `copytruncate` so the in-container
  writers keep their fd, immediate `compress`, `rotate 3`, `daily` plus a
  `maxsize 50M` cap. It runs from the **service user's** crontab (no root) with
  its own state file:

  ```cron
  17 * * * * /usr/sbin/logrotate -s /home/user1/serverfetch/ops/logrotate.state \
             /home/user1/serverfetch/ops/proxy-logs.logrotate >> \
             /home/user1/serverfetch/ops/logrotate.cron.log 2>&1
  ```

  Truncation is safe: both writers append with `O_APPEND`, so post-truncate
  writes land at offset 0 (no sparse file), and server.py's tailer detects
  `size < offset` and resumes from 0. The log *content* is disposable — every
  consumed line is folded into `traffic.sqlite3` — so retention is short.
  `copytruncate` can lose unread counts during rotation. Startup skips existing
  lines, so counts accumulated while the Web process is down are also lost.

Pending requests can be corrected before approval by changing the device in the
admin table. Revoke is the destructive access-removal action and is confirmed in
the UI before deleting the verify key.

## Privacy and IP policy

The project does not retain client IP history, connection history or destinations.
Existing `activated_ip`, `last_ip`, `ip_history` and request `client_ip` fields are
removed at startup. Legacy SSH accounting uses only a short-lived in-memory map.
Do not introduce IP locks: campus Wi-Fi can move users between routers/NAT exits.

Sharing control should rely on hidden cookies, embedded runner keys, mobile
profile tokens, and admin revoke.

This change does **not** hide destinations from the campus operating system:
Shadowsocks and SSH currently terminate there. The private outlet also accepts
plain SOCKS/HTTP proxy traffic on the campus leg. Project logging is disabled,
but external packet capture, system logs and privileged inspection are outside
the application. The LAN-only client design in [PRIVACY.md](PRIVACY.md) moves
decryption to an independent exit while retaining the campus server as a
ciphertext relay. That architecture is not implemented in this update.

## Dashboard Exit Behavior

Refreshing or reopening the page works while the HttpOnly cookie exists. Each
authenticated dashboard response renews that cookie for 400 days, so active
devices do not age out on a fixed approval-date deadline.

The browser also stores a separate opaque dashboard recovery token. If its
HttpOnly cookie is missing or expired, the page exchanges that token for a new
cookie and rotates the recovery token. Existing Clash/Shadowrocket profile
tokens are accepted as a migration fallback so devices approved before this
recovery mechanism can repair themselves without a new application.

If all browser storage was cleared, an administrator can use `Recovery link` in
the user table and send the generated link to that user. The token is carried in
the URL fragment (not the HTTP request URL), exchanged through
`POST /api/session/recover`, and immediately rotated. Revoking the user's key
invalidates cookies, profile tokens, saved recovery tokens, and recovery links.

The user dashboard shows `Back`, which returns to the user page without deleting
the cookie. Users do not see verify keys, so the UI should not offer a casual
logout action that makes re-entry impossible without reapproval.

If local device removal is needed later, add a separate explicit `Forget this
device` action. That action may call `/api/logout`, but it must warn that
reapproval may be required.

Admin `Revoke` remains the authoritative way to disable access.

## Deployment

Use Docker on the CentOS 7 server where possible. Do not introduce command-line
args for app configuration; use config files or environment variables.

Privacy migration requires a maintenance window; a source upload alone does not
change running services or erase historical data.

1. Transfer explicit source files using `rsync`/`scp`. Exclude runtime `state/`,
   real `config.json`, `.env`, keys and SQLite data. Compare deployed templates
   first; preserve server-only node settings.
2. Stop the identified Web process and the three proxy containers. Do not remove
   authorization data or traffic totals.
3. With all old writers stopped, run `python3 ops/privacy_cleanup.py` from the
   deployed project. This irreversibly deletes only recognized legacy project
   proxy logs, clears project `server.log`, and removes IP history from keys.
   It does not remove system logs, Docker archives or third-party copies.
4. Rebuild `Network` to install `run-user.sh` and `traffic_filter.py`, rebuild
   `PrivateVPNProxy`, regenerate the private Mihomo config, and recreate all
   three proxy containers to apply Docker `logging.driver: none`.
5. Start the Web process only after the new proxy scripts are available. Update
   `ops/proxy-logs.logrotate`, verify health, and test approval, subscription
   refresh, revoke, and numeric traffic accounting.

Use the existing server Docker runtime for service workloads. Do not introduce
encoded-code deployment or dynamic execution. See [HANDOFF.md](HANDOFF.md).

## API Summary

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/admin/login` | body `root_key` | Verify root key |
| `GET` | `/api/admin/keys` | `X-Root-Key` | Keys, requests, analytics |
| `POST` | `/api/admin/keys` | body `root_key` | Manual key creation |
| `DELETE` | `/api/admin/keys/<kid>` | `X-Root-Key` | Revoke key |
| `POST` | `/api/admin/requests/<rid>/approve` | `X-Root-Key` | Approve request |
| `DELETE` | `/api/admin/requests/<rid>` | `X-Root-Key` | Reject request |
| `POST` | `/api/request-key` | none | Submit `{name, device}` |
| `GET` | `/api/request-key/<rid>` | none | Poll approval; sets hidden cookie |
| `POST` | `/api/logout` | cookie | Delete local browser cookie |
| `GET` | `/api/validate-key` | hidden key/header | Compatibility; migrates old localStorage key to cookie |
| `GET` | `/api/user/status` | cookie/header | Dashboard status and 7-day traffic |
| `POST` | `/api/session/recover` | recovery/profile token | Restore a browser session and rotate its recovery token |
| `POST` | `/api/admin/keys/<kid>/recovery-link` | `X-Root-Key` | Create a new dashboard recovery link |
| `GET` | `/api/profile/clash/<token>` | token URL | Clash YAML for Android/mac/windows |
| `GET` | `/api/runner/mac` | cookie/header | Download mac runner |
| `GET` | `/api/runner/win` | cookie/header | Download windows runner |
| `GET` | `/api/ping` | none | Health check |

## Local Checks

```bash
python3 -m py_compile server.py
python3 -m unittest discover -s tests -v
sed -n '/<script>/,/<\/script>/p' index.html | sed '1d;$d' | node --check
```

## Notes For Future Developers

- Preserve hidden-key UX. Do not reintroduce visible verify-key entry for normal
  users unless the whole auth model is changed.
- Keep client IP history and destination auditing disabled. Do not restore hard
  first-IP locking for campus use.
- Internal names like `labvpn_key` and `labvpn-*` SSH authorized-key markers are
  compatibility details. They can be renamed later with a migration, but do not
  casually change them.
- Persist only numeric proxy counters; never pass raw diagnostic streams to
  files or Docker logs. Keep deployment secrets out of Git.
