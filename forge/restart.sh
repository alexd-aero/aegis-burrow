#!/usr/bin/env bash
# Selkies Forge action "Restart".
set -euo pipefail
cd "$(dirname "$0")/.."
exec bin/aegis restart
