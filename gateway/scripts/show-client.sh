#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

name="$(python3 - <<'PY'
import json
with open("config.json") as f:
    print(json.load(f).get("export_client", "phone"))
PY
)"
conf="state/clients/$name.ovpn"

if [ ! -f "$conf" ]; then
  echo "Client not found: $name" >&2
  echo "Available clients:" >&2
  find state/clients -mindepth 1 -maxdepth 1 -type f -name '*.ovpn' -exec basename {} .ovpn \; 2>/dev/null >&2 || true
  exit 1
fi

cat "$conf"
echo
echo "Import this .ovpn file into the OpenVPN Connect app."
