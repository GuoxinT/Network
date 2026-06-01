#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose ps
docker compose logs --tail=40 shadowsocks-ios
