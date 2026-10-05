#!/usr/bin/env bash
# Selkies Forge action "Burrow on/off": flip the tunnel engine. Tunnels are
# kept while it is off; their addresses just stop answering.
set -euo pipefail
cd "$(dirname "$0")/.."
if bin/aegis status --json | grep -q '"burrow":true'; then
  echo "::phase Switching Burrow off"
  bin/aegis burrow off
  echo "Your tunnels are kept. Switch it back on here, or under Settings → Modules."
else
  echo "::phase Switching Burrow on"
  bin/aegis burrow on
  bin/aegis burrow list
fi
