#!/usr/bin/env bash
# Selkies Forge action "Doctor": check Node.js, cloudflared and Docker, and
# fetch what is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
exec bin/aegis doctor --fix
