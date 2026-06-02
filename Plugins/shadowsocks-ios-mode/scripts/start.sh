#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/ensure-password.py
mkdir -p state
chmod 700 state
export PUID="${PUID:-$(id -u)}"
export PGID="${PGID:-$(id -g)}"
docker compose up -d --build
docker compose ps
