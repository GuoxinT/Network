#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose ps
echo "Docker logs are disabled; numeric traffic counters are in state/traffic/."
