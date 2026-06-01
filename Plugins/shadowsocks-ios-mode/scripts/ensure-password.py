#!/usr/bin/env python3
import base64
import json
import os
import secrets

CONFIG = "config.json"
PLACEHOLDER = "CHANGE_ME_TO_A_RANDOM_16_BYTE_BASE64_KEY"

with open(CONFIG) as f:
    cfg = json.load(f)

if cfg.get("password") != PLACEHOLDER:
    raise SystemExit(0)

cfg["password"] = base64.b64encode(secrets.token_bytes(16)).decode()

tmp = CONFIG + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, CONFIG)
os.chmod(CONFIG, 0o600)
print("Generated Shadowsocks password in config.json")
