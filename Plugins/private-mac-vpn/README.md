# Private Mac VPN Outlet

This plugin creates a separate subscription-backed outlet for selected
School-VPN keys.
It is intended for one MacBook using Clash Verge while every other School-VPN
user continues to use the normal `Network` container.

## Design

- `PrivateVPN` runs Mihomo and loads the private subscription provider.
- `PrivateVPNProxy` exposes authenticated SOCKS5 TCP and UDP Associate ports
  and chains outbound traffic through `PrivateVPN` on the Docker network.
- Only ports `8600-8699` are exposed for this private outlet.
- `server.py` switches a Clash profile to this outlet only when
  `config.json.enabled` is true and either the user's verify key is listed in
  `config.json.keys` or admin enables the user's Private VPN toggle.
- Admin can manually turn Private VPN on or off per Clash/Mihomo user from the
  user management table. Turning it off overrides the legacy `config.json.keys`
  allowlist for that key. Clash Verge users receive a `SchoolVPN-PrivateVPN`
  node with UDP enabled, so TUN mode and UDP-heavy apps can use the private
  outlet.
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
