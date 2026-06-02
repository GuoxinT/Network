#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Missing .env. Copy .env.example to .env and fill in your VPN provider settings." >&2
  exit 1
fi

if [ ! -f config.json ]; then
  cp config.example.json config.json
  python3 - <<'PY'
import base64
import json
import os

path = "config.json"
with open(path) as f:
    cfg = json.load(f)
cfg["password"] = base64.b64encode(os.urandom(18)).decode()
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
PY
  chmod 600 config.json
  echo "Created config.json. Edit enabled=true and keys before starting again." >&2
  exit 1
fi

mkdir -p state/mihomo
chmod 700 state state/mihomo
python3 - <<'PY'
from pathlib import Path

env = {}
for line in Path(".env").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    env[k.strip()] = v.strip().strip('"').strip("'")

url = env.get("PRIVATE_PROXY_PROVIDER_URL", "")
if not url:
    raise SystemExit("PRIVATE_PROXY_PROVIDER_URL is missing in .env")

tmpl = Path("mihomo.template.yaml").read_text(encoding="utf-8")
Path("state/mihomo/config.yaml").write_text(
    tmpl.replace("__PRIVATE_PROXY_PROVIDER_URL__", url)
    , encoding="utf-8"
)
PY
chmod 600 state/mihomo/config.yaml
export PUID="${PUID:-$(id -u)}"
export PGID="${PGID:-$(id -g)}"
docker compose up -d --build
docker compose ps
