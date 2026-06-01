#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/ensure-password.py
docker compose up -d --build
docker compose ps
