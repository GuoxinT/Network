# Private Mac VPN Outlet

This plugin creates a separate subscription-backed outlet for selected
School-VPN keys.
It is intended for one MacBook using Clash Verge while every other School-VPN
user continues to use the normal `Network` container.

## Design

- `PrivateVPN` runs Mihomo and loads the private subscription provider.
- `PrivateVPNProxy` exposes authenticated SOCKS5 ports and chains outbound
  traffic through `PrivateVPN` on the Docker network.
- Only ports `8600-8699` are exposed for this private outlet.
- `server.py` switches a Clash profile to this outlet only when
  `config.json.enabled` is true and the user's verify key is listed in
  `config.json.keys`.
- Allowlisted Clash profiles also include `SchoolVPN-Direct`, which uses the
  normal per-user School-VPN Shadowsocks port and does not chain through the
  private subscription.

Normal School-VPN users keep using the existing `Network` container and ports
`8400-8599`.

## Setup

1. Copy `.env.example` to `.env` and fill in the private subscription URL.
2. Copy `config.example.json` to `config.json`.
3. Set `enabled` to `true`.
4. Put only the MacBook verify key in `keys`.
5. Run `scripts/start.sh`.
6. Refresh the MacBook Clash subscription from the dashboard.
7. Select either `SchoolVPN-PrivateVPN` or `SchoolVPN-Direct` in Clash Verge.

Do not put other users' keys in `config.json.keys`; that is the allowlist.
