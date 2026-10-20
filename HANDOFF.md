# MyNetwork operational handoff

- Pre-privacy GitHub snapshot: `2c98ceb` on `origin/main`, 2026-10-20.
- Privacy implementation changes the accounting input to numeric upload/download
  lines in `state/traffic/`; old destination logs are not read.
- Preserve `keys.json`, both real plugin `config.json` files, private `.env`,
  SSH keys and SQLite totals. Never commit those or deployment backups.
- Rebuild `Network` so `run-user.sh` and `traffic_filter.py` exist before the new
  Web process can approve users. Rebuild `PrivateVPNProxy`; recreate `PrivateVPN`
  for Compose logging changes and load its regenerated configuration.
- The deployed Mihomo template historically differs at ROUTE-us06. Compare and
  merge only requested changes; do not overwrite the server's node customization.
- Stop Web and proxy writers before running `ops/privacy_cleanup.py`. It only
  removes project legacy logs and IP metadata, not system/security logs.
- Privacy logs use `ops/proxy-logs.logrotate`; update the deployed copy.
- Validate with `python3 -m unittest discover -s tests -v`, shell syntax checks,
  Compose config checks, Mihomo config validation and service health checks.
- Local verification on 2026-10-20: 26 unit tests passed; changed Python, shell
  and inline JavaScript passed syntax checks. Docker is unavailable locally, so
  container build/config validation and real-device checks remain deployment
  requirements. This update has not restarted or migrated the live server;
  historical data has not been deleted.
- `PRIVACY.md` describes the separate, not-yet-implemented encrypted-exit design
  for devices with LAN-only connectivity. No independent exit is provisioned.
