#!/usr/bin/env bash
# Selkies Forge: remove Aegis × Burrow. FORGE_ADDON_KEEP_DATA=1 (the default) keeps the
# login, tunnels and Cloudflare credentials so a reinstall picks them up.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${FORGE_ADDON_KEEP_DATA:-1}" = 1 ]; then exec bin/aegis uninstall; else exec bin/aegis uninstall --purge; fi
