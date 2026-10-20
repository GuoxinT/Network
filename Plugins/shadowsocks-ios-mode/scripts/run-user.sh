#!/usr/bin/env bash
# Both container startup and newly approved users use this same private filter.
set -euo pipefail
config="$1"
log="$2"
while true; do
  ssserver -vv -c "$config" 2>&1 \
    | python3 /app/scripts/traffic_filter.py >> "$log" || true
  sleep 1
done
