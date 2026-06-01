#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import base64
import json
import urllib.parse

with open("config.json") as f:
    cfg = json.load(f)

userinfo = f"{cfg['method']}:{cfg['password']}@{cfg['server_host']}:{int(cfg['server_port'])}"
encoded = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip("=")
name = urllib.parse.quote(cfg.get("profile_name", "SchoolVPN-iOS"))
print(f"ss://{encoded}#{name}")
print()
print("Shadowrocket:")
print("1. Copy the ss:// link above.")
print("2. Open Shadowrocket.")
print("3. Tap +, then Import from Clipboard / Add from URL.")
print("4. Select the SchoolVPN-iOS node and turn on Shadowrocket.")
print()
print("Do not share this URL. It contains the server password.")
PY
