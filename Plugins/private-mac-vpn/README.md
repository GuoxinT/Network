# MyNetwork Outlet

This plugin creates a separate subscription-backed outlet for selected
MyNetwork keys.
It is intended for one MacBook using Clash Verge while every other MyNetwork
user continues to use the normal `Network` container.

## Design

- `MyNetworkCore` runs Mihomo and loads the private subscription provider.
- `MyNetworkProxy` exposes authenticated SOCKS5 TCP and UDP Associate ports
  and chains outbound traffic through `MyNetworkCore` on the Docker network.
- Only ports `8600-8699` are exposed for this private outlet.
- `server.py` switches a Clash profile to this outlet only when
  `config.json.enabled` is true and either the user's verify key is listed in
  `config.json.keys` or admin enables the user's MyNetwork toggle.
- Admin can manually turn MyNetwork on or off per Clash/Mihomo user from the
  user management table. Turning it off overrides the legacy `config.json.keys`
  allowlist for that key. Clash Verge users receive a `MyNetwork`
  node with UDP enabled, so TUN mode and UDP-heavy apps can use the private
  outlet.
- Allowlisted Clash profiles also include `MyNetwork Direct`, which uses the
  normal per-user MyNetwork Shadowsocks port and does not chain through the
  private subscription.

Normal MyNetwork users keep using the existing `Network` container and ports
`8400-8699`.

### Traffic accounting

`private_socks.py` counts the bytes of every relayed TCP connection and appends a
close line — `... tcp tunnel <client>:<port> <-> <host>:<port> closed, L2R <up>
bytes, R2L <down> bytes` — to `state/logs/user-<port>-<key>.log` (one file per
listening port). This mirrors `ssserver`'s grammar, so `server.py`'s
`_process_proxy_logs()` tails it with the same parser and bills the bytes to the
key that owns the port. Lines are written on **every** close, including errors, so
no bytes are lost. UDP relay is not yet metered. See the root `README.md`
"Traffic accounting framework" section for the full pipeline.

## Setup

1. Copy `.env.example` to `.env` and fill in the private subscription URL.
2. Copy `config.example.json` to `config.json`.
3. Set `enabled` to `true`.
4. Put only the MacBook verify key in `keys`.
5. Run `scripts/start.sh`.
6. Refresh the MacBook Clash subscription from the dashboard.
7. Select either `MyNetwork` or `MyNetwork Direct` in Clash Verge.

Do not put other users' keys in `config.json.keys`; that is the allowlist.
