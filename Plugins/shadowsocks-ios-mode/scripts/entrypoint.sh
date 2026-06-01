#!/usr/bin/env bash
set -euo pipefail

CONFIG=/app/config.json
STATE=/app/state
SS_CONFIG="$STATE/ssserver.json"

mkdir -p "$STATE"
chmod 700 "$STATE"

python3 - "$CONFIG" "$SS_CONFIG" <<'PY'
import json
import sys

config_path, out_path = sys.argv[1:]
with open(config_path) as f:
    cfg = json.load(f)

password = cfg["password"]
if password == "CHANGE_ME_TO_A_RANDOM_16_BYTE_BASE64_KEY":
    raise SystemExit("Set a real password in config.json before starting.")

out = {
    "server": "0.0.0.0",
    "server_port": int(cfg["server_port"]),
    "password": password,
    "method": cfg["method"],
    "timeout": int(cfg.get("timeout", 300)),
    "mode": cfg.get("mode", "tcp_and_udp"),
}
with open(out_path, "w") as f:
    json.dump(out, f, indent=2)
PY

exec ssserver -vv -c "$SS_CONFIG"
