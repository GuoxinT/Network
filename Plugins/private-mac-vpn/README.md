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

`private_socks.py` counts relayed TCP bytes and appends only `<up> <down>` to
`state/traffic/user-<port>.log` (one file per listening port). No client address,
destination, timestamp or credential is written. `server.py` attributes these
counts to the key that owns the port. Lines are written on clean and error
closes; abrupt process termination can still lose counts. UDP relay is not yet
metered. Mihomo uses silent logging and both containers disable Docker log
storage. See the root `README.md`
"Traffic accounting framework" section for the full pipeline.

The campus-facing SOCKS/HTTP connection is not an encrypted client-to-exit tunnel.
Removing project logs does not prevent privileged observation of its traffic.
See the root `PRIVACY.md` for the proposed independent-exit architecture.

## Setup

1. Copy `.env.example` to `.env` and fill in the private subscription URL.
2. Copy `config.example.json` to `config.json`.
3. Set `enabled` to `true`.
4. Put only the MacBook verify key in `keys`.
5. Run `scripts/start.sh`.
6. Refresh the MacBook Clash subscription from the dashboard.
7. Select either `MyNetwork` or `MyNetwork Direct` in Clash Verge.

Do not put other users' keys in `config.json.keys`; that is the allowlist.
