# Shadowsocks iOS Mode

Docker-based Shadowsocks server for iOS Shadowrocket. This is intended as the
faster iOS path compared with SSH Tunnel: iPhone -> Shadowrocket -> Shadowsocks
-> lab server network -> internet.

## Files

- `config.json` - all settings. No command-line arguments are required.
- `docker-compose.yml` - Docker service exposing TCP/UDP `8388`.
- `scripts/start.sh` - generate password if needed, build, and start.
- `scripts/stop.sh` - stop the service.
- `scripts/status.sh` - show service status and logs.
- `scripts/show-shadowrocket.sh` - print the `ss://` import link.

## Start On Server

```bash
cd ~/serverfetch/Plugins/shadowsocks-ios-mode
./scripts/start.sh
./scripts/show-shadowrocket.sh
```

Copy the `ss://` link into Shadowrocket:

1. Open Shadowrocket on iPhone.
2. Tap `+`.
3. Choose import from clipboard / add from URL.
4. Select `SchoolVPN-iOS`.
5. Use Rule/Config mode when possible, not Global, to reduce iOS background noise.

## Notes

- The `ss://` link contains the password. Do not share it publicly.
- Open TCP and UDP `8388` if a firewall blocks clients.
- This plugin is separate from the verify-key SSH runner system.
