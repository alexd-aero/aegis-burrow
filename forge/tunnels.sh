#!/usr/bin/env bash
# Selkies Forge action "Show tunnels": Burrow's tunnels, one per line.
set -euo pipefail
cd "$(dirname "$0")/.."
bin/aegis burrow status
echo
bin/aegis burrow list
