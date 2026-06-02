#!/usr/bin/env bash
set -euo pipefail

CONFIG=/app/config.json
STATE=/app/state
USER_CONFIG="$STATE/users.json"
SS_CONFIG_DIR="$STATE/ssserver.d"
LOG_DIR="$STATE/logs"

mkdir -p "$STATE"
chmod 700 "$STATE"
rm -rf "$SS_CONFIG_DIR"
mkdir -p "$SS_CONFIG_DIR"
mkdir -p "$LOG_DIR"

python3 - "$CONFIG" "$USER_CONFIG" "$SS_CONFIG_DIR" <<'PY'
import json
import os
import sys

config_path, users_path, out_dir = sys.argv[1:]
with open(config_path) as f:
    cfg = json.load(f)

password = cfg["password"]
if password == "CHANGE_ME_TO_A_RANDOM_16_BYTE_BASE64_KEY":
    raise SystemExit("Set a real password in config.json before starting.")

def write_config(name, server_port, user_password, method=None):
    out = {
        "server": "0.0.0.0",
        "server_port": int(server_port),
        "password": user_password,
        "method": method or cfg["method"],
        "timeout": int(cfg.get("timeout", 300)),
        "mode": cfg.get("mode", "tcp_and_udp"),
    }
    path = os.path.join(out_dir, name + ".json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)

write_config("shared-{}".format(int(cfg["server_port"])), int(cfg["server_port"]), password)

try:
    with open(users_path) as f:
        users = json.load(f).get("users", [])
except FileNotFoundError:
    users = []

seen_ports = {int(cfg["server_port"])}
for item in users:
    if not item.get("enabled", True):
        continue
    port = int(item["port"])
    if port in seen_ports:
        continue
    seen_ports.add(port)
    safe_name = "user-{}-{}".format(port, "".join(c if c.isalnum() else "-" for c in item.get("key", "")))
    write_config(safe_name[:80], port, item["password"], item.get("method") or cfg["method"])
PY

pids=()
start_server() {
  local config="$1"
  local log="$2"
  while true; do
    ssserver -vv -c "$config" 2>&1 \
      | awk '/tcp tunnel .* closed|udp relay .* with [0-9]+ bytes/ { print; fflush(); }' >> "$log" || true
    echo "$(date -u +%FT%TZ) ssserver exited for $config; restarting in 1s" >> "$log"
    sleep 1
  done
}

for f in "$SS_CONFIG_DIR"/*.json; do
  echo "starting ssserver with $f"
  base="$(basename "$f" .json)"
  log="$LOG_DIR/$base.log"
  touch "$log"
  start_server "$f" "$log" &
  pids+=("$!")
done

trap 'kill "${pids[@]}" 2>/dev/null || true' TERM INT
wait "${pids[@]}"
