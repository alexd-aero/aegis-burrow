#!/usr/bin/env bash
# Selkies Forge action "Open the dashboard": the first-run link until the
# login exists, the dashboard after.
set -euo pipefail
cd "$(dirname "$0")/.."
link="$(bin/aegis setup-link)"
case "$link" in
  http*) echo "Create your login: $link"; echo "::open $link" ;;
  *) url="$(bin/aegis url)"; echo "$link"; echo "::open $url" ;;
esac
